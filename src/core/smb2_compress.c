// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   SMB2/3 Compression Transform Support
 *
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   Implements message-level compression and decompression for SMB 3.1.1
 *   per MS-SMB2 section 2.2.42 and MS-XCA.
 *
 *   Supported algorithms:
 *     - Pattern_V1 (0x0004): Repeated-byte pattern detection
 *     - LZ4 (0x0005): LZ4 block compression via kernel API
 *     - LZNT1 (0x0001): Stub (declines to compress)
 *     - LZ77 (0x0002): Stub (declines to compress)
 *     - LZ77+Huffman (0x0003): Stub (declines to compress)
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/lz4.h>

#include "glob.h"
#include "smb2pdu.h"
#include "smb_common.h"
#include "connection.h"
#include "ksmbd_work.h"
#include "server.h"

/*
 * Pattern_V1 compression (MS-XCA 2.3)
 *
 * Pattern_V1 is the simplest compression algorithm in the SMB3 spec.
 * It detects repeated byte patterns. The compressed format is:
 *   - 1 byte: the repeated byte value
 *   - The rest of the original data (or nothing if entire buffer is a pattern)
 *
 * For Pattern_V1, the compressed payload consists of:
 *   Byte 0: The pattern byte
 *   Bytes 1..N: Reserved (zero)
 *
 * Per MS-SMB2, Pattern_V1 is only used in chained compression mode as
 * a pre-scan. For our non-chained implementation we implement it as a
 * simple run-length check: if the entire buffer is a single repeated byte,
 * we compress it down to 8 bytes (1 byte pattern + 3 bytes reserved +
 * 4 bytes repetition count).
 */

/* Pattern_V1 compressed payload */
struct pattern_v1_payload {
	__u8  Pattern;
	__u8  Reserved1;
	__le16 Reserved2;
	__le32 Repetitions;
} __packed;

#define PATTERN_V1_COMPRESSED_SIZE sizeof(struct pattern_v1_payload)

/**
 * smb2_pattern_v1_compress - Compress data using Pattern_V1 algorithm
 * @src:      Source data buffer
 * @src_len:  Length of source data
 * @dst:      Destination buffer (must be at least PATTERN_V1_COMPRESSED_SIZE)
 * @dst_len:  Available space in destination buffer
 *
 * Returns compressed size on success, 0 if data is not compressible
 * with Pattern_V1 (i.e., not a single repeated byte), or negative
 * errno on error.
 */
static int smb2_pattern_v1_compress(const void *src, unsigned int src_len,
				    void *dst, unsigned int dst_len)
{
	const unsigned char *data = src;
	struct pattern_v1_payload *payload = dst;
	unsigned char pattern;
	unsigned int i;

	if (src_len == 0)
		return 0;

	if (dst_len < PATTERN_V1_COMPRESSED_SIZE)
		return 0;

	/* Check if entire buffer is a single repeated byte */
	pattern = data[0];
	for (i = 1; i < src_len; i++) {
		if (data[i] != pattern)
			return 0; /* Not a pattern - cannot compress */
	}

	/* Only compress if we actually save space */
	if (PATTERN_V1_COMPRESSED_SIZE >= src_len)
		return 0;

	payload->Pattern = pattern;
	payload->Reserved1 = 0;
	payload->Reserved2 = 0;
	payload->Repetitions = cpu_to_le32(src_len);

	return PATTERN_V1_COMPRESSED_SIZE;
}

/**
 * smb2_pattern_v1_decompress - Decompress Pattern_V1 compressed data
 * @src:          Compressed data buffer
 * @src_len:      Length of compressed data
 * @dst:          Destination buffer for decompressed data
 * @dst_len:      Size of destination buffer
 * @original_size: Expected original (decompressed) size
 *
 * Returns 0 on success, negative errno on failure.
 */
static int smb2_pattern_v1_decompress(const void *src, unsigned int src_len,
				      void *dst, unsigned int dst_len,
				      unsigned int original_size)
{
	const struct pattern_v1_payload *payload = src;
	unsigned int repetitions;

	if (src_len < PATTERN_V1_COMPRESSED_SIZE)
		return -EINVAL;

	repetitions = le32_to_cpu(payload->Repetitions);
	if (repetitions != original_size)
		return -EINVAL;

	if (original_size > dst_len)
		return -ENOSPC;

	memset(dst, payload->Pattern, original_size);
	return 0;
}

/*
 * LZ4 compression using the kernel's built-in LZ4 API.
 *
 * The kernel provides lz4_compress() and lz4_decompress_unknownoutputsize()
 * from <linux/lz4.h>.
 */

/**
 * smb2_lz4_compress - Compress data using LZ4 algorithm
 * @src:      Source data buffer
 * @src_len:  Length of source data
 * @dst:      Destination buffer
 * @dst_len:  Available space in destination buffer
 * @wrkmem:   LZ4 working memory (LZ4_MEM_COMPRESS bytes)
 *
 * Returns compressed size on success, 0 if compression does not save
 * space, or negative errno on error.
 */
static int smb2_lz4_compress(const void *src, unsigned int src_len,
			     void *dst, unsigned int dst_len, void *wrkmem)
{
	int compressed_size;

	compressed_size = LZ4_compress_default(src, dst, src_len,
					       dst_len, wrkmem);
	if (compressed_size <= 0)
		return 0; /* Compression failed or didn't save space */

	/* Only use compression if we actually save space */
	if ((unsigned int)compressed_size >= src_len)
		return 0;

	return compressed_size;
}

/**
 * smb2_lz4_decompress - Decompress LZ4 compressed data
 * @src:          Compressed data buffer
 * @src_len:      Length of compressed data
 * @dst:          Destination buffer for decompressed data
 * @dst_len:      Size of destination buffer
 * @original_size: Expected original (decompressed) size
 *
 * Returns 0 on success, negative errno on failure.
 */
static int smb2_lz4_decompress(const void *src, unsigned int src_len,
			       void *dst, unsigned int dst_len,
			       unsigned int original_size)
{
	int ret;

	if (original_size > dst_len)
		return -ENOSPC;

	ret = LZ4_decompress_safe(src, dst, src_len, dst_len);
	if (ret < 0) {
		pr_err("LZ4 decompression failed: %d\n", ret);
		return -EIO;
	}

	if ((unsigned int)ret != original_size) {
		pr_err("LZ4 decompression size mismatch: got %d, expected %u\n",
		       ret, original_size);
		return -EIO;
	}

	return 0;
}

/**
 * smb2_compress_data - Compress data using the specified algorithm
 * @algorithm:  Compression algorithm to use (le16 wire value)
 * @src:        Source data buffer
 * @src_len:    Length of source data
 * @dst:        Destination buffer for compressed data
 * @dst_len:    Available space in destination buffer
 *
 * Returns compressed size on success, 0 if data is not compressible
 * or algorithm is not supported, or negative errno on error.
 */
static int smb2_compress_data(__le16 algorithm, const void *src,
			      unsigned int src_len, void *dst,
			      unsigned int dst_len)
{
	if (algorithm == SMB3_COMPRESS_PATTERN_V1)
		return smb2_pattern_v1_compress(src, src_len, dst, dst_len);

	if (algorithm == SMB3_COMPRESS_LZ4) {
		void *wrkmem;
		int ret;

		wrkmem = kvmalloc(LZ4_MEM_COMPRESS, KSMBD_DEFAULT_GFP);
		if (!wrkmem)
			return -ENOMEM;

		ret = smb2_lz4_compress(src, src_len, dst, dst_len, wrkmem);
		kvfree(wrkmem);
		return ret;
	}

	/* LZNT1, LZ77, LZ77+Huffman: stubs - decline to compress */
	if (algorithm == SMB3_COMPRESS_LZNT1 ||
	    algorithm == SMB3_COMPRESS_LZ77 ||
	    algorithm == SMB3_COMPRESS_LZ77_HUFF)
		return 0;

	return 0; /* Unknown algorithm */
}

/**
 * smb2_decompress_data - Decompress data using the specified algorithm
 * @algorithm:      Compression algorithm used (le16 wire value)
 * @src:            Compressed data buffer
 * @src_len:        Length of compressed data
 * @dst:            Destination buffer for decompressed data
 * @dst_len:        Size of destination buffer
 * @original_size:  Expected original (decompressed) size
 *
 * Returns 0 on success, negative errno on failure.
 */
static int smb2_decompress_data(__le16 algorithm, const void *src,
				unsigned int src_len, void *dst,
				unsigned int dst_len,
				unsigned int original_size)
{
	if (algorithm == SMB3_COMPRESS_PATTERN_V1)
		return smb2_pattern_v1_decompress(src, src_len, dst, dst_len,
						  original_size);

	if (algorithm == SMB3_COMPRESS_LZ4)
		return smb2_lz4_decompress(src, src_len, dst, dst_len,
					   original_size);

	/* LZNT1, LZ77, LZ77+Huffman: not implemented for decompression */
	pr_err("Unsupported compression algorithm: 0x%04x\n",
	       le16_to_cpu(algorithm));
	return -EOPNOTSUPP;
}

/**
 * smb2_is_compression_transform_hdr - Check if buffer starts with a
 *                                     compression transform header
 * @buf:  Buffer to check (raw request including RFC1002 4-byte length)
 *
 * Returns true if the protocol ID matches SMB2_COMPRESSION_TRANSFORM_ID.
 */
bool smb2_is_compression_transform_hdr(void *buf)
{
	struct smb2_compression_transform_hdr *hdr = smb2_get_msg(buf);

	return hdr->ProtocolId == SMB2_COMPRESSION_TRANSFORM_ID;
}

/**
 * smb2_decompress_req - Decompress a compressed SMB2 request in place
 * @work:  ksmbd_work containing the request buffer
 *
 * If the incoming request has a compression transform header, decompress
 * the payload and replace the request buffer with the decompressed version.
 * The decompressed buffer will have standard RFC1002 framing with the
 * original SMB2 header.
 *
 * Returns 0 on success, negative errno on failure.
 */
int smb2_decompress_req(struct ksmbd_work *work)
{
	char *buf = work->request_buf;
	unsigned int pdu_length = get_rfc1002_len(buf);
	struct smb2_compression_transform_hdr *hdr;
	unsigned int original_size, offset, compressed_offset;
	unsigned int compressed_len, total_decompressed_len;
	__le16 algorithm;
	char *decompressed_buf;
	char *uncompressed_part;
	char *compressed_part;
	int rc;

	if (pdu_length < sizeof(struct smb2_compression_transform_hdr)) {
		pr_err("Compression transform message too small (%u)\n",
		       pdu_length);
		return -ECONNABORTED;
	}

	hdr = (struct smb2_compression_transform_hdr *)smb2_get_msg(buf);

	/* Only support non-chained (Flags == 0) for now */
	if (le16_to_cpu(hdr->Flags) & SMB2_COMPRESSION_FLAG_CHAINED) {
		pr_err("Chained compression not supported\n");
		return -EOPNOTSUPP;
	}

	algorithm = hdr->CompressionAlgorithm;
	original_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);
	offset = le32_to_cpu(hdr->Offset);

	/*
	 * Sanity check: original_size should be reasonable.
	 * Limit to 16MB to prevent memory abuse.
	 */
	if (original_size > (16 * 1024 * 1024)) {
		pr_err("Decompressed size too large: %u\n", original_size);
		return -ECONNABORTED;
	}

	/*
	 * The compression transform header layout (non-chained):
	 *
	 * [RFC1002 4 bytes][CompressionTransformHeader]
	 * [Uncompressed data: 'offset' bytes]
	 * [Compressed data]
	 *
	 * The Offset field indicates how many bytes of uncompressed data
	 * follow the header before the compressed region starts.
	 */
	compressed_offset = sizeof(struct smb2_compression_transform_hdr) +
			    offset;

	if (compressed_offset > pdu_length) {
		pr_err("Invalid compression offset: %u > PDU length %u\n",
		       compressed_offset, pdu_length);
		return -ECONNABORTED;
	}

	compressed_len = pdu_length - compressed_offset;
	uncompressed_part = (char *)hdr +
			    sizeof(struct smb2_compression_transform_hdr);
	compressed_part = (char *)hdr + compressed_offset;

	/*
	 * Total decompressed output: the uncompressed prefix (offset bytes)
	 * plus the decompressed data (original_size bytes from the
	 * OriginalCompressedSegmentSize field, which is the total original
	 * size of the entire segment including the uncompressed prefix).
	 *
	 * Per MS-SMB2, OriginalCompressedSegmentSize is the original
	 * uncompressed size of the data. The Offset bytes are sent
	 * uncompressed, and the compressed region, when decompressed,
	 * gives (original_size - offset) bytes.
	 */
	if (original_size < offset) {
		pr_err("Invalid: original size %u < offset %u\n",
		       original_size, offset);
		return -ECONNABORTED;
	}

	total_decompressed_len = original_size;

	/* Allocate buffer: 4 bytes RFC1002 + decompressed payload */
	decompressed_buf = kvmalloc(total_decompressed_len + 5,
				    KSMBD_DEFAULT_GFP);
	if (!decompressed_buf)
		return -ENOMEM;

	/* Set RFC1002 length header */
	*(__be32 *)decompressed_buf =
		cpu_to_be32(total_decompressed_len);

	/* Copy uncompressed prefix (the 'offset' bytes) */
	if (offset > 0)
		memcpy(decompressed_buf + 4, uncompressed_part, offset);

	/* Decompress the compressed region */
	if (compressed_len > 0 && (original_size - offset) > 0) {
		rc = smb2_decompress_data(algorithm, compressed_part,
					  compressed_len,
					  decompressed_buf + 4 + offset,
					  total_decompressed_len - offset,
					  original_size - offset);
		if (rc) {
			pr_err("Decompression failed: %d\n", rc);
			kvfree(decompressed_buf);
			return rc;
		}
	}

	/* Replace the request buffer with the decompressed version */
	kvfree(work->request_buf);
	work->request_buf = decompressed_buf;

	ksmbd_debug(SMB, "Decompressed request: %u -> %u bytes (algo=0x%04x)\n",
		    pdu_length, total_decompressed_len,
		    le16_to_cpu(algorithm));

	return 0;
}

/**
 * smb2_compress_resp - Compress an SMB2 response if beneficial
 * @work:  ksmbd_work containing the response buffer
 *
 * Attempts to compress the SMB2 response payload. If compression
 * is negotiated and the message exceeds the compression threshold,
 * the response is replaced with a compression transform header
 * followed by the compressed payload.
 *
 * Compression is skipped if:
 *   - No compression algorithm was negotiated
 *   - The message is already encrypted
 *   - The message is too small (below threshold)
 *   - Compression does not reduce the message size
 *
 * Returns 0 on success (including when compression is skipped),
 * negative errno on failure.
 */
int smb2_compress_resp(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct kvec *iov;
	struct smb2_hdr *rsp_hdr;
	struct smb2_compression_transform_hdr *comp_hdr;
	void *rsp_body;
	unsigned int rsp_body_len;
	unsigned int total_rsp_len;
	void *compressed_buf = NULL;
	void *comp_transform_buf;
	int compressed_size;
	unsigned int comp_transform_len;
	__le16 algorithm;

	/* Skip if no compression negotiated */
	if (conn->compress_algorithm == SMB3_COMPRESS_NONE)
		return 0;

	/* Skip if the response is encrypted - don't compress encrypted data */
	if (work->encrypted)
		return 0;

	/* We need iov to be set up */
	if (!work->iov_idx || !work->iov)
		return 0;

	/*
	 * Skip compression for multi-iov responses (e.g., SMB2 READ with
	 * aux data in iov[2]). Collapsing to iov_cnt=1 would silently
	 * discard the extra iov data. iov[0] is the RFC1002 header and
	 * iov[1] is the SMB2 response, so iov_cnt > 2 means extra payload.
	 */
	if (work->iov_cnt > 2)
		return 0;

	iov = work->iov;
	algorithm = conn->compress_algorithm;

	/*
	 * The response is in iov[]:
	 *   iov[0]: RFC1002 header + SMB2 header (if encrypted, it's
	 *           transform header)
	 *   iov[1..n]: response body parts
	 *
	 * For simplicity, we compress the entire SMB2 response body
	 * after the RFC1002 header, using the SMB2 header as the
	 * uncompressed prefix (Offset).
	 */
	rsp_body = iov[0].iov_base;
	total_rsp_len = get_rfc1002_len(rsp_body);

	/* Check minimum size threshold */
	if (total_rsp_len < SMB2_COMPRESSION_THRESHOLD)
		return 0;

	/*
	 * For non-chained compression, we use the SMB2 header as the
	 * uncompressed prefix. The offset field tells the client how
	 * many bytes of uncompressed data precede the compressed data.
	 *
	 * Layout: [RFC1002 4B][CompTransformHdr][SMB2Hdr uncompressed][Compressed body]
	 *
	 * The SMB2 header size is sizeof(struct smb2_hdr).
	 * The body starts after the SMB2 header.
	 */
	rsp_hdr = iov[1].iov_base;
	rsp_body_len = total_rsp_len - sizeof(struct smb2_hdr);

	if (rsp_body_len == 0)
		return 0;

	/* Allocate buffer for compressed output */
	compressed_buf = kvmalloc(rsp_body_len, KSMBD_DEFAULT_GFP);
	if (!compressed_buf)
		return 0; /* Fail silently - just send uncompressed */

	compressed_size = smb2_compress_data(algorithm,
					     (char *)rsp_hdr +
					     sizeof(struct smb2_hdr),
					     rsp_body_len,
					     compressed_buf,
					     rsp_body_len);

	if (compressed_size <= 0) {
		kvfree(compressed_buf);
		return 0; /* Cannot compress, send uncompressed */
	}

	/*
	 * Build the compression transform buffer:
	 *   [RFC1002 4B][CompTransformHdr][SMB2Hdr][Compressed body]
	 */
	comp_transform_len = 4 +
			     sizeof(struct smb2_compression_transform_hdr) +
			     sizeof(struct smb2_hdr) +
			     compressed_size;

	comp_transform_buf = kvmalloc(comp_transform_len, KSMBD_DEFAULT_GFP);
	if (!comp_transform_buf) {
		kvfree(compressed_buf);
		return 0; /* Fail silently */
	}

	/* Only use compression if it actually saves space */
	if (comp_transform_len >= total_rsp_len + 4) {
		kvfree(compressed_buf);
		kvfree(comp_transform_buf);
		return 0;
	}

	/* Set RFC1002 length */
	*(__be32 *)comp_transform_buf = cpu_to_be32(
		comp_transform_len - 4);

	/* Fill compression transform header */
	comp_hdr = (struct smb2_compression_transform_hdr *)
		   (comp_transform_buf + 4);
	comp_hdr->ProtocolId = SMB2_COMPRESSION_TRANSFORM_ID;
	comp_hdr->OriginalCompressedSegmentSize = cpu_to_le32(total_rsp_len);
	comp_hdr->CompressionAlgorithm = algorithm;
	comp_hdr->Flags = cpu_to_le16(SMB2_COMPRESSION_FLAG_NONE);
	comp_hdr->Offset = cpu_to_le32(sizeof(struct smb2_hdr));

	/* Copy the uncompressed SMB2 header */
	memcpy(comp_transform_buf + 4 +
	       sizeof(struct smb2_compression_transform_hdr),
	       rsp_hdr, sizeof(struct smb2_hdr));

	/* Copy the compressed body */
	memcpy(comp_transform_buf + 4 +
	       sizeof(struct smb2_compression_transform_hdr) +
	       sizeof(struct smb2_hdr),
	       compressed_buf, compressed_size);

	kvfree(compressed_buf);

	/* Replace iov[0] with the compressed buffer */
	iov[0].iov_base = comp_transform_buf;
	iov[0].iov_len = comp_transform_len;

	/* Mark that we need to free this buffer and clear extra iovs */
	work->tr_buf = comp_transform_buf;
	work->iov_cnt = 1;
	work->iov_idx = 1;

	ksmbd_debug(SMB,
		    "Compressed response: %u -> %u bytes (algo=0x%04x)\n",
		    total_rsp_len, comp_transform_len - 4,
		    le16_to_cpu(algorithm));

	return 0;
}
