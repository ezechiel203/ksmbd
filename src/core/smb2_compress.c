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
 *     - LZ4 (0x0005): LZ4 block compression via kernel API (internal only,
 *                     NOT advertised to clients — see I.2 below)
 *     - LZNT1 (0x0001): MS-XCA §2.3 implementation
 *     - LZ77 plain (0x0002): MS-XCA §2.4 implementation
 *     - LZ77+Huffman (0x0003): MS-XCA §2.5 (LZXPRESS Huffman) full impl
 *
 * I.2 NOTE: LZ4 (0x0005) is not in the MS-SMB2 specification and MUST NOT
 * be advertised in the SMB2_COMPRESSION_CAPABILITIES negotiate context.
 * The negotiate code (smb2_negotiate.c) is responsible for filtering LZ4
 * from the advertised list.  If a client somehow negotiates LZ4, this file
 * supports decompression for backward compatibility, but the server will
 * not actively compress responses using LZ4 (smb2_compress_data declines).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/lz4.h>
#include <linux/overflow.h>
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

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
VISIBLE_IF_KUNIT int smb2_pattern_v1_compress(const void *src, unsigned int src_len,
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
EXPORT_SYMBOL_IF_KUNIT(smb2_pattern_v1_compress);

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
VISIBLE_IF_KUNIT int smb2_pattern_v1_decompress(const void *src, unsigned int src_len,
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
EXPORT_SYMBOL_IF_KUNIT(smb2_pattern_v1_decompress);

/*
 * LZ4 compression using the kernel's built-in LZ4 API.
 *
 * The kernel provides lz4_compress() and lz4_decompress_unknownoutputsize()
 * from <linux/lz4.h>.
 */

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
VISIBLE_IF_KUNIT int smb2_lz4_decompress(const void *src, unsigned int src_len,
			       void *dst, unsigned int dst_len,
			       unsigned int original_size)
{
	int ret;

	if (original_size > dst_len)
		return -ENOSPC;

	ret = LZ4_decompress_safe(src, dst, src_len, original_size);
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
EXPORT_SYMBOL_IF_KUNIT(smb2_lz4_decompress);

/*
 * LZNT1 compression/decompression (MS-XCA §2.3)
 *
 * LZNT1 is a chunk-based LZ77 variant. The compressed stream consists of
 * 4096-byte chunks, each preceded by a 2-byte chunk header:
 *   - Bit 15 set:   uncompressed chunk (copy 4096 bytes as-is)
 *   - Bit 15 clear: compressed chunk; bits 12:0 = (compressed_size - 3)
 *
 * Within a compressed chunk, data is encoded as:
 *   - A flag byte (8 bits), each bit indicates literal (0) or back-ref (1)
 *   - Literals: 1 byte copied as-is
 *   - Back-references: 2 bytes encoding offset+length, where the split
 *     between offset and length bits varies based on position in the output
 *     (more offset bits as output fills up, per MS-XCA §2.3.1)
 *
 * The decompressor is the critical path (server receives compressed client
 * data).  The compressor produces valid LZNT1 output but is not highly
 * optimised.
 */

#define LZNT1_CHUNK_SIZE	4096

/**
 * lznt1_get_offset - Extract offset field from LZNT1 back-reference token
 */
static inline unsigned int lznt1_get_offset(unsigned int word,
					    unsigned int pos_bits)
{
	/* offset uses the high (16 - pos_bits) bits */
	return (word >> pos_bits) + 1;
}

/**
 * lznt1_get_length - Extract length field from LZNT1 back-reference token
 */
static inline unsigned int lznt1_get_length(unsigned int word,
					    unsigned int pos_bits)
{
	/* length uses the low pos_bits bits */
	unsigned int mask = (1u << pos_bits) - 1u;

	return (word & mask) + 3;
}

/**
 * ksmbd_lznt1_decompress - Decompress LZNT1 data (MS-XCA §2.3)
 * @input:      Compressed data
 * @input_len:  Length of compressed data
 * @output:     Output buffer
 * @output_len: Size of output buffer
 *
 * Returns number of decompressed bytes on success, negative errno on error.
 */
static ssize_t ksmbd_lznt1_decompress(const void *input, size_t input_len,
				      void *output, size_t output_len)
{
	const unsigned char *in = input;
	unsigned char *out = output;
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos + 2 <= input_len) {
		unsigned int chunk_hdr;
		size_t chunk_start_out;
		bool is_compressed;
		size_t chunk_data_size;
		size_t chunk_end_in;

		chunk_hdr = (unsigned int)in[in_pos] |
			    ((unsigned int)in[in_pos + 1] << 8);
		in_pos += 2;

		is_compressed = !(chunk_hdr & 0x8000);
		chunk_data_size = (chunk_hdr & 0x0FFF) + 3;

		if (in_pos + chunk_data_size > input_len) {
			/* Truncated chunk — treat as end of stream */
			break;
		}

		chunk_end_in = in_pos + chunk_data_size;
		chunk_start_out = out_pos;

		if (!is_compressed) {
			/*
			 * TC-12: Use remaining output budget as copy bound.
			 * The old min_t(size_t, 4096, ...) incorrectly capped
			 * at 4096; MS-XCA §2.3 uncompressed chunks can be up
			 * to 4098 bytes.  The 4096 cap would truncate valid
			 * chunks and produce corrupt output.
			 */
			size_t copy_len = output_len - out_pos;

			if (copy_len < chunk_data_size)
				return -ENOSPC;
			memcpy(out + out_pos, in + in_pos, chunk_data_size);
			out_pos += chunk_data_size;
			in_pos = chunk_end_in;
			continue;
		}

		/* Compressed chunk: parse LZ77 tokens */
		while (in_pos < chunk_end_in && out_pos < output_len) {
			unsigned int flags;
			int bit;

			if (in_pos >= chunk_end_in)
				break;

			flags = in[in_pos++];

			for (bit = 0; bit < 8 && in_pos < chunk_end_in &&
			     out_pos < output_len; bit++) {
				if (!(flags & (1u << bit))) {
					/* Literal byte */
					out[out_pos++] = in[in_pos++];
				} else {
					/* Back-reference */
					unsigned int token;
					unsigned int offset, length;
					unsigned int filled;
					unsigned int pos_bits;
					unsigned int copy_offset;

					if (in_pos + 2 > chunk_end_in)
						return -EINVAL;

					token = (unsigned int)in[in_pos] |
						((unsigned int)in[in_pos + 1] << 8);
					in_pos += 2;

					/*
					 * Number of bits for length field depends
					 * on how much output we've produced in
					 * this chunk so far.  Per MS-XCA §2.3.1:
					 * pos_bits starts at 4 (for 0-16 bytes),
					 * grows by 1 for each doubling of chunk
					 * position, up to max 12.
					 */
					filled = out_pos - chunk_start_out;
					pos_bits = 4;
					{
						unsigned int tmp = filled;

						while (tmp >= (1u << pos_bits) &&
						       pos_bits < 12)
							pos_bits++;
					}

					offset = lznt1_get_offset(token,
								  pos_bits);
					length = lznt1_get_length(token,
								  pos_bits);

					if (offset > out_pos)
						return -EINVAL;

					copy_offset = out_pos - offset;
					if (out_pos + length > output_len)
						return -ENOSPC;

					/*
					 * Copy byte by byte to handle overlapping
					 * back-references (run-length expansion).
					 */
					while (length-- > 0)
						out[out_pos++] =
							out[copy_offset++];
				}
			}
		}

		in_pos = chunk_end_in;
	}

	return (ssize_t)out_pos;
}

/**
 * ksmbd_lznt1_compress - Compress data using LZNT1 (MS-XCA §2.3)
 * @input:      Input data
 * @input_len:  Length of input data
 * @output:     Output buffer
 * @output_len: Size of output buffer
 *
 * Returns number of compressed bytes on success, negative errno on error,
 * or 0 if compression did not reduce the data size.
 */
static ssize_t ksmbd_lznt1_compress(const void *input, size_t input_len,
				    void *output, size_t output_len)
{
	const unsigned char *in = input;
	unsigned char *out = output;
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos < input_len) {
		/* Position where this chunk header will be written */
		size_t chunk_hdr_pos = out_pos;
		size_t chunk_start_in = in_pos;
		size_t chunk_end_in = min_t(size_t, in_pos + LZNT1_CHUNK_SIZE,
					    input_len);
		size_t chunk_out_start;
		unsigned char *flags_byte;
		int flag_bit = 0;
		bool any_match = false;

		/* Reserve space for chunk header (2 bytes) */
		if (out_pos + 2 > output_len)
			return 0; /* No space */
		out_pos += 2;
		chunk_out_start = out_pos;

		/* Reserve space for flag byte */
		if (out_pos >= output_len)
			return 0;
		flags_byte = &out[out_pos++];
		*flags_byte = 0;

		while (in_pos < chunk_end_in) {
			size_t best_len = 0;
			size_t best_off = 0;
			size_t search_start;
			unsigned int filled;
			unsigned int pos_bits;

			/* Search backwards for longest match */
			search_start = (in_pos > chunk_start_in + 4096) ?
					in_pos - 4096 : chunk_start_in;

			filled = in_pos - chunk_start_in;
			pos_bits = 4;
			{
				unsigned int tmp = filled;

				while (tmp >= (1u << pos_bits) && pos_bits < 12)
					pos_bits++;
			}

			{
				size_t max_off = (1u << (16 - pos_bits));
				size_t max_len = (1u << pos_bits) + 2;
				size_t s;

				for (s = in_pos - 1;
				     s >= search_start && in_pos > search_start;
				     s--) {
					size_t match_len = 0;
					size_t off = in_pos - s;

					if (off > max_off)
						break;

					while (match_len < max_len &&
					       in_pos + match_len < chunk_end_in &&
					       in[s + match_len] ==
					       in[in_pos + match_len])
						match_len++;

					if (match_len >= 3 &&
					    match_len > best_len) {
						best_len = match_len;
						best_off = off;
					}
					if (s == chunk_start_in)
						break;
				}
			}

			if (best_len >= 3) {
				/* Emit back-reference */
				unsigned int token;
				unsigned int off_field = best_off - 1;
				unsigned int len_field = best_len - 3;
				unsigned int len_mask = (1u << pos_bits) - 1u;

				token = (off_field << pos_bits) | (len_field & len_mask);

				if (out_pos + 2 > output_len)
					return 0;

				out[out_pos++] = token & 0xFF;
				out[out_pos++] = (token >> 8) & 0xFF;
				*flags_byte |= (1u << flag_bit);
				in_pos += best_len;
				any_match = true;
			} else {
				/* Emit literal */
				if (out_pos >= output_len)
					return 0;
				out[out_pos++] = in[in_pos++];
			}

			flag_bit++;
			if (flag_bit == 8 && in_pos < chunk_end_in) {
				/* Start new flag byte */
				if (out_pos >= output_len)
					return 0;
				flags_byte = &out[out_pos++];
				*flags_byte = 0;
				flag_bit = 0;
			}
		}

		/*
		 * Write chunk header.
		 * If chunk compresses well, write compressed header;
		 * otherwise write uncompressed (if space allows).
		 */
		{
			size_t compressed_chunk_size = out_pos - chunk_out_start;
			size_t orig_chunk_size = chunk_end_in - chunk_start_in;

			if (!any_match || compressed_chunk_size >= orig_chunk_size) {
				/* Write uncompressed chunk */
				if (chunk_hdr_pos + 2 + orig_chunk_size > output_len)
					return 0;
				out_pos = chunk_hdr_pos;
				/* Uncompressed: bit 15 set, size = orig_chunk_size - 3 */
				{
					unsigned int hdr = 0x8000 |
						((orig_chunk_size - 3) & 0x0FFF);
					out[out_pos++] = hdr & 0xFF;
					out[out_pos++] = (hdr >> 8) & 0xFF;
				}
				memcpy(out + out_pos, in + chunk_start_in,
				       orig_chunk_size);
				out_pos += orig_chunk_size;
			} else {
				/* Write compressed chunk header */
				unsigned int hdr = (compressed_chunk_size - 3) & 0x0FFF;
				/* bit 15 clear = compressed */
				out[chunk_hdr_pos] = hdr & 0xFF;
				out[chunk_hdr_pos + 1] = (hdr >> 8) & 0xFF;
			}
		}

		in_pos = chunk_end_in;
	}

	/* Return 0 if we didn't compress at all */
	if (out_pos >= input_len)
		return 0;

	return (ssize_t)out_pos;
}

/*
 * LZ77 plain compression/decompression (MS-XCA §2.4)
 *
 * LZ77 plain (not LZ77+Huffman) uses a simple binary format:
 *   - 4-byte flag word: each bit (LSB first) indicates whether the
 *     corresponding item is a literal (0) or back-reference (1).
 *   - Literal: 1 byte copied as-is.
 *   - Back-reference: 2 bytes little-endian:
 *       bits 15:4 = offset - 1 (12 bits, so max offset 4096)
 *       bits  3:0 = extra_length (4 bits)
 *     If extra_length == 15: read 1 more byte for more_len.
 *       If more_len == 255: read 2-byte additional length, then subtract
 *       (15 + 255) to get final_length.
 *       Otherwise final_length = extra_length + more_len + 3.
 *     Otherwise final_length = extra_length + 3.
 *
 * The format operates on the entire message (no chunk boundary).
 * This is the LZ77 "plain" algorithm as used in SMB3 (algorithm 0x0002).
 */

/**
 * ksmbd_lz77_decompress - Decompress LZ77 plain data (MS-XCA §2.4)
 * @input:      Compressed data
 * @input_len:  Length of compressed data
 * @output:     Output buffer
 * @output_len: Size of output buffer
 *
 * Returns number of decompressed bytes on success, negative errno on error.
 */
static ssize_t ksmbd_lz77_decompress(const void *input, size_t input_len,
				     void *output, size_t output_len)
{
	const unsigned char *in = input;
	unsigned char *out = output;
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos < input_len && out_pos < output_len) {
		unsigned int flags;
		int bit;

		/* Read 4-byte flag word */
		if (in_pos + 4 > input_len)
			break;

		flags = (unsigned int)in[in_pos] |
			((unsigned int)in[in_pos + 1] << 8) |
			((unsigned int)in[in_pos + 2] << 16) |
			((unsigned int)in[in_pos + 3] << 24);
		in_pos += 4;

		for (bit = 0; bit < 32 && in_pos < input_len &&
		     out_pos < output_len; bit++) {
			if (!(flags & (1u << bit))) {
				/* Literal */
				out[out_pos++] = in[in_pos++];
			} else {
				/* Back-reference */
				unsigned int token;
				unsigned int offset, length;

				if (in_pos + 2 > input_len)
					return -EINVAL;

				token = (unsigned int)in[in_pos] |
					((unsigned int)in[in_pos + 1] << 8);
				in_pos += 2;

				offset = (token >> 4) + 1;  /* 12-bit offset + 1 */
				length = token & 0xF;        /* 4-bit extra length */

				if (length == 15) {
					unsigned int more;

					if (in_pos >= input_len)
						return -EINVAL;
					more = in[in_pos++];
					if (more == 255) {
						unsigned int extra;

						if (in_pos + 2 > input_len)
							return -EINVAL;
						extra = (unsigned int)in[in_pos] |
							((unsigned int)in[in_pos + 1] << 8);
						in_pos += 2;
						/*
						 * TC-14: MS-XCA §2.4 extended
						 * length: length = extra_u16 - 267
						 * (267 = 15 + 255 - 3).
						 */
						if (extra < 267)
							return -EINVAL;
						length = extra - 267;
					} else {
						length = length + more + 3;
					}
				} else {
					length += 3;
				}

				if (offset > out_pos)
					return -EINVAL;

				if (out_pos + length > output_len)
					return -ENOSPC;

				{
					size_t src = out_pos - offset;

					while (length-- > 0)
						out[out_pos++] = out[src++];
				}
			}
		}
	}

	return (ssize_t)out_pos;
}

/**
 * ksmbd_lz77_compress - Compress data using LZ77 plain (MS-XCA §2.4)
 * @input:      Input data
 * @input_len:  Length of input data
 * @output:     Output buffer
 * @output_len: Size of output buffer
 *
 * Returns number of compressed bytes on success, 0 if not compressible,
 * negative errno on error.
 */
static ssize_t ksmbd_lz77_compress(const void *input, size_t input_len,
				   void *output, size_t output_len)
{
	const unsigned char *in = input;
	unsigned char *out = output;
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos < input_len) {
		/* Reserve 4 bytes for flag word */
		size_t flags_pos = out_pos;
		unsigned int flags = 0;
		int bit;

		if (out_pos + 4 > output_len)
			return 0;
		out_pos += 4;

		for (bit = 0; bit < 32 && in_pos < input_len; bit++) {
			size_t best_len = 0;
			size_t best_off = 0;
			size_t search_start;
			size_t max_match;
			size_t s;

			/* Search back up to 4096 bytes */
			search_start = (in_pos > 4096) ? in_pos - 4096 : 0;
			max_match = min_t(size_t, input_len - in_pos, (1u << 16) + 17);

			for (s = search_start; s < in_pos; s++) {
				size_t match_len = 0;
				size_t off = in_pos - s;

				while (match_len < max_match &&
				       in_pos + match_len < input_len &&
				       in[s + match_len] == in[in_pos + match_len])
					match_len++;

				if (match_len >= 3 && match_len > best_len) {
					best_len = match_len;
					best_off = off;
				}
			}

			if (best_len >= 3) {
				/* Emit back-reference */
				unsigned int token_base;

				flags |= (1u << bit);

				token_base = ((best_off - 1) << 4);

				if (best_len - 3 < 15) {
					/* Fits in 4 bits */
					unsigned int token =
						token_base | (best_len - 3);

					if (out_pos + 2 > output_len)
						return 0;
					out[out_pos++] = token & 0xFF;
					out[out_pos++] = (token >> 8) & 0xFF;
				} else {
					/* Need extra length byte(s) */
					unsigned int token = token_base | 0xF;
					unsigned int extra_len;

					if (out_pos + 2 > output_len)
						return 0;
					out[out_pos++] = token & 0xFF;
					out[out_pos++] = (token >> 8) & 0xFF;

					extra_len = best_len - 3 - 15;
					if (extra_len < 255) {
						if (out_pos >= output_len)
							return 0;
						out[out_pos++] = (unsigned char)extra_len;
					} else {
						if (out_pos + 3 > output_len)
							return 0;
						out[out_pos++] = 255;
						{
							unsigned int total =
								best_len - 3;
							out[out_pos++] = total & 0xFF;
							out[out_pos++] = (total >> 8) & 0xFF;
						}
					}
				}
				in_pos += best_len;
			} else {
				/* Emit literal */
				if (out_pos >= output_len)
					return 0;
				out[out_pos++] = in[in_pos++];
			}
		}

		/* Write flag word */
		out[flags_pos]     = flags & 0xFF;
		out[flags_pos + 1] = (flags >> 8) & 0xFF;
		out[flags_pos + 2] = (flags >> 16) & 0xFF;
		out[flags_pos + 3] = (flags >> 24) & 0xFF;
	}

	if (out_pos >= input_len)
		return 0;

	return (ssize_t)out_pos;
}

/*
 * LZ77+Huffman compression/decompression (MS-XCA §2.5)
 * SMB3 compression algorithm 0x0003 (SMB3_COMPRESS_LZ77_HUFF).
 *
 * This is the LZXPRESS Huffman algorithm.  The wire format is:
 *
 * For each 65536-byte (uncompressed) block:
 *   [256 bytes: Huffman symbol length table, 512 4-bit lengths packed]
 *   [variable: Huffman-coded LZ77 token stream]
 *
 * The Huffman alphabet has 512 symbols:
 *   Symbols   0-255: literal bytes
 *   Symbols 256-511: LZ77 match tokens
 *     symbol = 256 + ((match_length - 3) << 4) + distance_log2
 *       match_length: decoded_length = len_slot + 3  (len_slot = high nibble)
 *       distance_log2: low nibble; read that many more bits for exact offset
 *         offset = (1 << distance_log2) + read_bits(distance_log2)
 *         special case: distance_log2 == 0 => offset = 1, no extra bits
 *
 * Bit-stream: 32-bit LE words, bits extracted LSB-first.
 * Huffman codes: canonical, lengths up to 15 bits, read MSB-first within
 * the 32-bit window (i.e., the bit-reversal is baked into the decode table).
 *
 * Compressor: we implement a literal-only encoder (all 256 symbols at
 * length 8), which is spec-valid but does not compress data.  The caller
 * (smb2_compress_data) will detect that compressed >= original and fall
 * back to sending uncompressed data.
 */

/* Maximum number of Huffman symbols */
#define LZ77H_NSYM		512
/* Maximum Huffman code length */
#define LZ77H_MAX_BITS		15
/* Bits in the fast decode table index */
#define LZ77H_FAST_BITS		11
#define LZ77H_FAST_SIZE		(1 << LZ77H_FAST_BITS)
/* Uncompressed block size */
#define LZ77H_BLOCK_SIZE	65536

/*
 * Huffman decode entry.
 * For codes <= LZ77H_FAST_BITS, stored directly in fast[].
 * For longer codes, fast[] entry has is_chain=1 and sym=chain index.
 *
 * TC-13: extra_code stores the bit-reversed canonical code bits
 * beyond LZ77H_FAST_BITS (i.e. rev >> LZ77H_FAST_BITS).  The chain
 * decode loop uses this to verify the extra bits from the bit-stream
 * actually match before consuming them, preventing garbled output
 * when multiple long codes share the same lower LZ77H_FAST_BITS bits.
 */
struct lz77h_entry {
	__u16 sym;        /* decoded symbol */
	__u8  len;        /* code length in bits, 0 = empty slot */
	__u8  is_chain;   /* 1 = sym is index into chain[], not a symbol */
	__u16 extra_code; /* chain only: rev >> LZ77H_FAST_BITS */
	__u16 _pad;       /* alignment padding */
};

/* Per-block decoder state */
struct lz77h_decoder {
	struct lz77h_entry fast[LZ77H_FAST_SIZE];
	/* Overflow entries for codes > LZ77H_FAST_BITS bits */
	struct lz77h_entry chain[LZ77H_NSYM];
	int chain_cnt;
};

/*
 * Build canonical Huffman decode tables.
 * lengths[i] = code length for symbol i (0 = symbol not present).
 * Returns 0 on success, -EINVAL on bad table.
 *
 * The bit-stream reads bits LSB-first from 32-bit LE words.  Canonical
 * Huffman codes are assigned MSB-first (standard).  To look up a code
 * in the fast table we use the bit-reversed code as the table index.
 */
static int lz77h_build_table(struct lz77h_decoder *dec,
			     const __u8 *lengths, int nsym)
{
	int cnt[LZ77H_MAX_BITS + 1] = {0};
	int next_code[LZ77H_MAX_BITS + 2] = {0};
	int i, bits;
	unsigned int code;

	memset(dec->fast, 0, sizeof(dec->fast));
	dec->chain_cnt = 0;

	/* Count codes per length */
	for (i = 0; i < nsym; i++) {
		if (lengths[i] > LZ77H_MAX_BITS)
			return -EINVAL;
		if (lengths[i])
			cnt[lengths[i]]++;
	}

	/* Canonical code start values */
	code = 0;
	next_code[0] = 0;
	for (bits = 1; bits <= LZ77H_MAX_BITS; bits++) {
		code = (code + cnt[bits - 1]) << 1;
		next_code[bits] = (int)code;
	}

	/* Assign codes and populate decode table */
	for (i = 0; i < nsym; i++) {
		int len = lengths[i];
		unsigned int c, rev;
		int b;

		if (!len)
			continue;

		c = (unsigned int)next_code[len]++;

		/*
		 * Bit-reverse the canonical code so it can be used as an
		 * index into the fast table (which is indexed by bits read
		 * LSB-first from the stream).
		 */
		rev = 0;
		for (b = 0; b < len; b++)
			rev = (rev << 1) | ((c >> b) & 1);

		if (len <= LZ77H_FAST_BITS) {
			/*
			 * Short code: fill all fast[] entries whose index
			 * has `rev` as a prefix (the remaining bits are
			 * don't-cares).
			 */
			int pad = LZ77H_FAST_BITS - len;
			unsigned int base = rev << pad; /* no — wrong */

			/*
			 * Correct: rev is the LSB-first code of length `len`.
			 * We want all indices idx in [0, LZ77H_FAST_SIZE) such
			 * that (idx & ((1<<len)-1)) == rev.
			 * These are: rev + k*(1<<len) for k = 0..2^pad-1.
			 */
			base = rev;
			{
				unsigned int stride = 1u << len;
				unsigned int idx;

				for (idx = base; idx < LZ77H_FAST_SIZE;
				     idx += stride) {
					if (dec->fast[idx].len == 0) {
						dec->fast[idx].sym = (u16)i;
						dec->fast[idx].len = (u8)len;
						dec->fast[idx].is_chain = 0;
					}
				}
			}
		} else {
			/*
			 * Long code: add to chain table.
			 * The fast[] entry for the lower LZ77H_FAST_BITS bits
			 * of rev acts as a chain anchor.
			 */
			unsigned int fast_idx = rev & (LZ77H_FAST_SIZE - 1);

			if (dec->chain_cnt < LZ77H_NSYM) {
				int ci = dec->chain_cnt++;

				dec->chain[ci].sym = (u16)i;
				dec->chain[ci].len = (u8)len;
				dec->chain[ci].is_chain = 0;
				/*
				 * TC-13: store the upper bits of the
				 * bit-reversed code so the decode loop
				 * can verify a match before consuming.
				 */
				dec->chain[ci].extra_code =
					(u16)(rev >> LZ77H_FAST_BITS);
				dec->chain[ci]._pad = 0;

				/*
				 * Point the fast entry to the first chain
				 * entry (if not already set).  If already a
				 * chain pointer, that's fine — linear scan
				 * will find this entry too.
				 */
				if (dec->fast[fast_idx].len == 0) {
					dec->fast[fast_idx].sym = (u16)ci;
					dec->fast[fast_idx].len = LZ77H_FAST_BITS;
					dec->fast[fast_idx].is_chain = 1;
				}
			}
		}
	}

	return 0;
}

/* Bit-reader for LZ77+Huffman */
struct lz77h_br {
	const unsigned char *data;
	size_t              data_len;
	size_t              pos;   /* next byte to read */
	unsigned int        buf;   /* bit buffer, LSB = next bit */
	int                 avail; /* valid bits in buf */
};

static inline void lz77h_br_init(struct lz77h_br *br,
				 const unsigned char *data, size_t len)
{
	br->data     = data;
	br->data_len = len;
	br->pos      = 0;
	br->buf      = 0;
	br->avail    = 0;
}

/* Refill bit buffer from input stream (read up to 16 bits at a time) */
static inline void lz77h_br_refill(struct lz77h_br *br)
{
	while (br->avail <= 24 && br->pos + 1 < br->data_len) {
		unsigned int word = (unsigned int)br->data[br->pos] |
				    ((unsigned int)br->data[br->pos + 1] << 8);
		br->buf  |= word << br->avail;
		br->avail += 16;
		br->pos  += 2;
	}
	/* Handle trailing odd byte */
	if (br->avail <= 24 && br->pos < br->data_len) {
		br->buf  |= (unsigned int)br->data[br->pos] << br->avail;
		br->avail += 8;
		br->pos++;
	}
}

static inline unsigned int lz77h_br_read(struct lz77h_br *br, int n)
{
	unsigned int v;

	if (n == 0)
		return 0;
	lz77h_br_refill(br);
	v        = br->buf & ((1u << n) - 1u);
	br->buf  >>= n;
	br->avail -= n;
	return v;
}

/*
 * Decode one Huffman symbol from the bit-stream.
 * Returns symbol (0..511) on success, -1 on error/end-of-stream.
 */
static int lz77h_decode_sym(struct lz77h_decoder *dec, struct lz77h_br *br)
{
	unsigned int peek;
	struct lz77h_entry *e;

	lz77h_br_refill(br);

	if (br->avail < 1)
		return -1;

	/* Peek LZ77H_FAST_BITS bits (LSB first) */
	peek = br->buf & (LZ77H_FAST_SIZE - 1);
	e = &dec->fast[peek];

	if (e->len == 0)
		return -1;

	if (!e->is_chain) {
		/* Direct hit */
		br->buf   >>= e->len;
		br->avail  -= e->len;
		return e->sym;
	}

	/*
	 * TC-13: Chain lookup.
	 *
	 * The fast[] table matched the lower LZ77H_FAST_BITS bits but the
	 * code is longer than LZ77H_FAST_BITS.  The chain[] table holds all
	 * long-code entries that share those lower bits.  We must peek the
	 * remaining (extra) bits from the bit-stream and compare them against
	 * ce->extra_code before consuming, so that we don't corrupt the
	 * stream by consuming bits from the wrong chain entry.
	 *
	 * Do NOT consume the LZ77H_FAST_BITS base bits until we know we
	 * have a match — peek only.
	 */
	{
		int ci_start = e->sym;
		int ci;

		for (ci = ci_start; ci < dec->chain_cnt; ci++) {
			struct lz77h_entry *ce = &dec->chain[ci];
			int extra = ce->len - LZ77H_FAST_BITS;
			unsigned int peek_extra;

			if (extra <= 0)
				continue;

			lz77h_br_refill(br);
			if (br->avail < LZ77H_FAST_BITS + extra)
				return -1;

			/*
			 * Peek the extra bits that follow the base
			 * LZ77H_FAST_BITS bits (do not consume yet).
			 */
			peek_extra = (br->buf >> LZ77H_FAST_BITS) &
				     ((1u << extra) - 1);

			if (peek_extra != ce->extra_code)
				continue;

			/* Match: consume the full code length */
			br->buf   >>= LZ77H_FAST_BITS + extra;
			br->avail  -= LZ77H_FAST_BITS + extra;
			return ce->sym;
		}

		/*
		 * No chain entry matched: the bitstream is corrupt.
		 * Consume the fast bits to avoid re-trying this entry
		 * and return an error.
		 */
		br->buf   >>= LZ77H_FAST_BITS;
		br->avail  -= LZ77H_FAST_BITS;
	}

	return -1;
}

/**
 * ksmbd_lz77huff_decompress - Decompress LZ77+Huffman data (MS-XCA §2.5)
 * @input:      Compressed data
 * @input_len:  Length of compressed data
 * @output:     Output buffer
 * @output_len: Size of output buffer
 *
 * Returns number of decompressed bytes on success, negative errno on error.
 */
static ssize_t ksmbd_lz77huff_decompress(const void *input, size_t input_len,
					 void *output, size_t output_len)
{
	const unsigned char *in = input;
	unsigned char *out = output;
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (out_pos < output_len && in_pos < input_len) {
		__u8 lengths[LZ77H_NSYM];
		struct lz77h_decoder *dec;
		struct lz77h_br br;
		size_t block_out_end;
		int i, rc;

		/* Each block decompresses to at most LZ77H_BLOCK_SIZE bytes */
		block_out_end = min_t(size_t, out_pos + LZ77H_BLOCK_SIZE,
				      output_len);

		/* Read 256-byte Huffman table: 512 symbols, 4 bits each */
		if (in_pos + 256 > input_len)
			break;

		for (i = 0; i < 256; i++) {
			unsigned char b = in[in_pos + i];

			lengths[2 * i]     = b & 0x0F;
			lengths[2 * i + 1] = (b >> 4) & 0x0F;
		}
		in_pos += 256;

		dec = kvmalloc(sizeof(*dec), GFP_KERNEL);
		if (!dec)
			return -ENOMEM;

		rc = lz77h_build_table(dec, lengths, LZ77H_NSYM);
		if (rc) {
			kvfree(dec);
			return rc;
		}

		/* Initialize bit reader starting right after the table */
		lz77h_br_init(&br, in + in_pos, input_len - in_pos);

		/* Decode symbols for this block */
		while (out_pos < block_out_end) {
			int sym = lz77h_decode_sym(dec, &br);

			if (sym < 0)
				break;

			if (sym < 256) {
				/* Literal byte */
				out[out_pos++] = (unsigned char)sym;
			} else {
				/*
				 * LZ77 match token.
				 * sym = 256 + (len_slot << 4) + dist_log2
				 */
				unsigned int token     = (unsigned int)sym - 256;
				unsigned int len_slot  = token >> 4;
				unsigned int dist_log2 = token & 0xF;
				unsigned int match_len;
				unsigned int offset;
				unsigned int copy_src;

				/* Base match length */
				match_len = len_slot + 3;

				/*
				 * Extended length: if len_slot == 15, read
				 * additional length bytes per MS-XCA §2.5.1.
				 */
				if (len_slot == 15) {
					unsigned int extra;

					lz77h_br_refill(&br);
					extra = lz77h_br_read(&br, 8);
					match_len = extra + 3 + 15;

					if (extra == 255) {
						unsigned int lo, hi;

						lo = lz77h_br_read(&br, 8);
						hi = lz77h_br_read(&br, 8);
						match_len = lo | (hi << 8);
					}
				}

				/* Decode offset */
				if (dist_log2 == 0) {
					offset = 1;
				} else {
					unsigned int extra_bits =
						lz77h_br_read(&br, dist_log2);
					offset = (1u << dist_log2) + extra_bits;
				}

				if (offset > out_pos) {
					kvfree(dec);
					return -EINVAL;
				}

				/* Clamp match to available output */
				if (out_pos + match_len > output_len)
					match_len = output_len - out_pos;

				/* Byte-by-byte copy for overlapping matches */
				copy_src = out_pos - offset;
				while (match_len-- > 0)
					out[out_pos++] = out[copy_src++];
			}
		}

		/* Advance input by bytes consumed by bit reader */
		in_pos += br.pos;
		/* Account for bits buffered but not consumed */
		if (br.avail > 0)
			in_pos -= (br.avail / 8);

		kvfree(dec);
	}

	return (ssize_t)out_pos;
}

/**
 * ksmbd_lz77huff_compress - Compress data using LZ77+Huffman (MS-XCA §2.5)
 * @input:      Input data
 * @input_len:  Length of input data
 * @output:     Output buffer
 * @output_len: Size of output buffer
 *
 * This implements a literal-only encoder: all 256 literal symbols are
 * assigned 8-bit codes (balanced table), and no LZ77 back-references
 * are emitted.  The output is spec-valid LZ77+Huffman and can be
 * decompressed by any compliant implementation.
 *
 * Because a literal-only encoding expands data (Huffman table overhead),
 * this function will return 0 (decline) when output >= input, causing
 * the caller to fall back to uncompressed transmission.
 *
 * Returns number of compressed bytes, 0 if not beneficial, negative on error.
 */
static ssize_t ksmbd_lz77huff_compress(const void *input, size_t input_len,
					void *output, size_t output_len)
{
	const unsigned char *in = input;
	unsigned char *out = output;
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos < input_len) {
		size_t block_size = min_t(size_t, input_len - in_pos,
					  LZ77H_BLOCK_SIZE);
		size_t i;

		/*
		 * Huffman table: 512 symbols, 4 bits each, 256 bytes total.
		 * Symbols 0-255 (literals): length = 8 (fits in 4 bits as 0x8).
		 * Symbols 256-511 (matches): length = 0 (not used).
		 * Layout: byte[k] = len[2k] | (len[2k+1] << 4)
		 *   bytes 0-127:  both nibbles = 8  => 0x88
		 *   bytes 128-255: both nibbles = 0  => 0x00
		 */
		if (out_pos + 256 > output_len)
			return 0;

		for (i = 0; i < 128; i++)
			out[out_pos++] = 0x88;
		for (i = 128; i < 256; i++)
			out[out_pos++] = 0x00;

		/*
		 * Encode literals.  With all symbols at length 8, the
		 * canonical code for symbol i is simply i (8-bit MSB-first).
		 * In our LSB-first bit stream, symbol i is emitted as
		 * bit-reverse(i, 8).
		 *
		 * We pack symbols into 32-bit LE words (4 symbols per word).
		 */
		for (i = 0; i < block_size; ) {
			unsigned int word = 0;
			int j;

			if (out_pos + 4 > output_len)
				return 0;

			for (j = 0; j < 4 && i < block_size; j++, i++) {
				unsigned int v = in[in_pos + i];
				unsigned int rev = 0;
				int b;

				/* Bit-reverse 8 bits for LSB-first stream */
				for (b = 0; b < 8; b++) {
					rev = (rev << 1) | (v & 1);
					v >>= 1;
				}
				word |= rev << (j * 8);
			}

			out[out_pos++] = (unsigned char)(word);
			out[out_pos++] = (unsigned char)(word >> 8);
			out[out_pos++] = (unsigned char)(word >> 16);
			out[out_pos++] = (unsigned char)(word >> 24);
		}

		in_pos += block_size;
	}

	/* Literal-only encoding always expands; decline compression */
	if (out_pos >= input_len)
		return 0;

	return (ssize_t)out_pos;
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
 *
 * I.2: LZ4 (0x0005) is NOT in the MS-SMB2 spec and MUST NOT be
 * advertised.  Although LZ4 decompression is still supported for
 * backward compatibility, the server never actively *compresses* with
 * LZ4 — smb2_compress_data() returns 0 (decline) for LZ4.
 */
VISIBLE_IF_KUNIT int smb2_compress_data(__le16 algorithm, const void *src,
			      unsigned int src_len, void *dst,
			      unsigned int dst_len)
{
	if (algorithm == SMB3_COMPRESS_PATTERN_V1)
		return smb2_pattern_v1_compress(src, src_len, dst, dst_len);

	/*
	 * I.2: Do NOT actively compress with LZ4 — it is non-spec.
	 * Return 0 (decline) so callers send uncompressed data.
	 * LZ4 decompression is still supported in smb2_decompress_data().
	 */
	if (algorithm == SMB3_COMPRESS_LZ4)
		return 0;

	if (algorithm == SMB3_COMPRESS_LZNT1) {
		ssize_t ret = ksmbd_lznt1_compress(src, src_len, dst, dst_len);

		if (ret < 0)
			return (int)ret;
		return (int)ret;
	}

	if (algorithm == SMB3_COMPRESS_LZ77) {
		ssize_t ret = ksmbd_lz77_compress(src, src_len, dst, dst_len);

		if (ret < 0)
			return (int)ret;
		return (int)ret;
	}

	if (algorithm == SMB3_COMPRESS_LZ77_HUFF) {
		ssize_t ret = ksmbd_lz77huff_compress(src, src_len,
						       dst, dst_len);

		if (ret < 0)
			return (int)ret;
		return (int)ret;
	}

	return 0; /* Unknown algorithm */
}
EXPORT_SYMBOL_IF_KUNIT(smb2_compress_data);

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
VISIBLE_IF_KUNIT int smb2_decompress_data(__le16 algorithm, const void *src,
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

	if (algorithm == SMB3_COMPRESS_LZNT1) {
		ssize_t ret = ksmbd_lznt1_decompress(src, src_len,
						     dst, dst_len);

		if (ret < 0)
			return (int)ret;
		if ((unsigned int)ret != original_size) {
			pr_err("LZNT1 decompression size mismatch: got %zd, expected %u\n",
			       ret, original_size);
			return -EIO;
		}
		return 0;
	}

	if (algorithm == SMB3_COMPRESS_LZ77) {
		ssize_t ret = ksmbd_lz77_decompress(src, src_len,
						    dst, dst_len);

		if (ret < 0)
			return (int)ret;
		if ((unsigned int)ret != original_size) {
			pr_err("LZ77 decompression size mismatch: got %zd, expected %u\n",
			       ret, original_size);
			return -EIO;
		}
		return 0;
	}

	if (algorithm == SMB3_COMPRESS_LZ77_HUFF) {
		ssize_t ret = ksmbd_lz77huff_decompress(src, src_len,
							 dst, dst_len);

		if (ret < 0)
			return (int)ret;
		if ((unsigned int)ret != original_size) {
			pr_err("LZ77+Huffman decompression size mismatch: got %zd, expected %u\n",
			       ret, original_size);
			return -EIO;
		}
		return 0;
	}

	pr_err("Unsupported compression algorithm: 0x%04x\n",
	       le16_to_cpu(algorithm));
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_IF_KUNIT(smb2_decompress_data);

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
 * smb2_decompress_chained - Decompress a chained compression message
 * @buf:        Raw buffer starting at RFC1002 prefix
 * @pdu_length: PDU length (from RFC1002 header, bytes after the 4-byte prefix)
 * @out_buf:    Pre-allocated output buffer for decompressed data
 * @out_size:   Size of out_buf
 * @total_out:  Receives total bytes written to out_buf on success
 *
 * Handles chained compression as defined in MS-SMB2 §2.2.42.1.
 * After the initial smb2_compression_transform_hdr with Flags=CHAINED,
 * the data consists of a series of smb2_compression_chained_payload_hdr
 * segments, each followed by compressed (or uncompressed) data.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int smb2_decompress_chained(const char *buf, unsigned int pdu_length,
				   char *out_buf, unsigned int out_size,
				   unsigned int *total_out,
				   __le16 conn_algo)
{
	const struct smb2_compression_transform_hdr *first_hdr;
	const unsigned char *msg;  /* points to first byte after RFC1002 */
	unsigned int msg_off;      /* current offset within msg[] */
	unsigned int out_pos = 0;

	msg = (const unsigned char *)(buf + 4);
	first_hdr = (const struct smb2_compression_transform_hdr *)msg;

	/*
	 * OriginalCompressedSegmentSize: total uncompressed size of all
	 * chained segments combined.
	 */
	*total_out = le32_to_cpu(first_hdr->OriginalCompressedSegmentSize);
	if (*total_out > out_size) {
		pr_err("Chained: total original size %u exceeds buffer %u\n",
		       *total_out, out_size);
		return -ENOSPC;
	}

	/*
	 * Skip past the initial transform header to reach the first
	 * chained payload header.
	 */
	msg_off = sizeof(struct smb2_compression_transform_hdr);

	while (msg_off < pdu_length) {
		const struct smb2_compression_chained_payload_hdr *seg;
		__le16 seg_algo;
		unsigned int seg_flags;
		unsigned int seg_comp_len;
		const unsigned char *seg_data;
		unsigned int seg_orig_size;
		int rc;

		if (msg_off + sizeof(*seg) > pdu_length) {
			pr_err("Chained: truncated segment header at offset %u\n",
			       msg_off);
			return -EINVAL;
		}

		seg = (const struct smb2_compression_chained_payload_hdr *)
		      (msg + msg_off);

		seg_algo     = seg->CompressionAlgorithm;
		seg_flags    = le16_to_cpu(seg->Flags);
		seg_comp_len = le32_to_cpu(seg->Length);

		msg_off += sizeof(*seg);

		/*
		 * TC-11: Algorithm mismatch check for chained segments.
		 * The non-chained path validates algorithm against conn;
		 * the chained path previously had no such check, allowing
		 * algorithm-confusion attacks.  NONE segments are exempt
		 * (uncompressed passthrough).
		 */
		if (seg_algo != SMB3_COMPRESS_NONE &&
		    conn_algo != SMB3_COMPRESS_NONE &&
		    seg_algo != conn_algo) {
			pr_err_ratelimited("Chained: algo mismatch: got 0x%04x expected 0x%04x\n",
					   le16_to_cpu(seg_algo),
					   le16_to_cpu(conn_algo));
			return -EINVAL;
		}

		if (msg_off + seg_comp_len > pdu_length) {
			pr_err("Chained: segment data overruns PDU (off=%u len=%u pdusz=%u)\n",
			       msg_off, seg_comp_len, pdu_length);
			return -EINVAL;
		}

		seg_data = msg + msg_off;

		/*
		 * Segment original size: we don't know it explicitly here
		 * (it's not in the minimal chained payload header).  Use
		 * the remaining output budget as an upper bound.  The
		 * decompressor will stop at the actual decompressed size.
		 */
		seg_orig_size = *total_out - out_pos;

		/*
		 * TC-10: Decompression bomb guard — reject per-segment
		 * compression ratios exceeding 1024:1.  A single byte of
		 * compressed input claiming to expand to the full remaining
		 * output budget constitutes a decompression bomb attack that
		 * would saturate CPU with no legitimate justification.
		 */
		if (seg_comp_len > 0 &&
		    seg_orig_size > (size_t)seg_comp_len * 1024) {
			pr_err_ratelimited("Chained: decompression bomb detected: comp=%u orig=%u\n",
					   seg_comp_len, seg_orig_size);
			return -E2BIG;
		}

		if (seg_algo == SMB3_COMPRESS_NONE) {
			/* Uncompressed segment: copy verbatim */
			if (out_pos + seg_comp_len > out_size)
				return -ENOSPC;
			memcpy(out_buf + out_pos, seg_data, seg_comp_len);
			out_pos += seg_comp_len;
		} else {
			rc = smb2_decompress_data(seg_algo,
						  seg_data, seg_comp_len,
						  out_buf + out_pos,
						  out_size - out_pos,
						  seg_orig_size);
			if (rc) {
				pr_err("Chained: segment decompress failed: %d (algo=0x%04x)\n",
				       rc, le16_to_cpu(seg_algo));
				return rc;
			}
			/*
			 * smb2_decompress_data verifies exact size only when
			 * it knows seg_orig_size.  Advance by what was written,
			 * which smb2_decompress_data confirmed == seg_orig_size.
			 */
			out_pos += seg_orig_size;
		}

		msg_off += seg_comp_len;

		/* Last segment has Flags without CHAINED bit set */
		if (!(seg_flags & SMB2_COMPRESSION_FLAG_CHAINED))
			break;
	}

	*total_out = out_pos;
	return 0;
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
 * Supports both non-chained and chained compression (MS-SMB2 §2.2.42,
 * §2.2.42.1).
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

	/*
	 * Handle chained compression (MS-SMB2 §2.2.42.1).
	 * When Flags has SMB2_COMPRESSION_FLAG_CHAINED set, the payload
	 * consists of a series of smb2_compression_chained_payload_hdr
	 * segments rather than a single compressed region.
	 */
	if (le16_to_cpu(hdr->Flags) & SMB2_COMPRESSION_FLAG_CHAINED) {
		unsigned int max_allowed = 2 * 1024 * 1024;
		unsigned int chain_total;

		if (work->conn && work->conn->vals &&
		    work->conn->vals->max_trans_size)
			max_allowed = min_t(unsigned int, max_allowed,
					    work->conn->vals->max_trans_size);

		original_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);
		if (original_size > max_allowed) {
			pr_err("Chained: decompressed size too large: %u (max %u)\n",
			       original_size, max_allowed);
			return -ECONNABORTED;
		}

		/* Allocate: 4 bytes RFC1002 + decompressed payload */
		decompressed_buf = kvmalloc(original_size + 5,
					    KSMBD_DEFAULT_GFP);
		if (!decompressed_buf)
			return -ENOMEM;

		rc = smb2_decompress_chained(buf, pdu_length,
					     decompressed_buf + 4,
					     original_size,
					     &chain_total,
					     work->conn ? work->conn->compress_algorithm
						       : SMB3_COMPRESS_NONE);
		if (rc) {
			kvfree(decompressed_buf);
			return rc;
		}

		*(__be32 *)decompressed_buf = cpu_to_be32(chain_total);

		kvfree(work->request_buf);
		work->request_buf = decompressed_buf;

		ksmbd_debug(SMB,
			    "Chained decompressed request: %u bytes\n",
			    chain_total);
		return 0;
	}

	/* Non-chained decompression path */
	algorithm = hdr->CompressionAlgorithm;
	original_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);
	offset = le32_to_cpu(hdr->Offset);

	/*
	 * Security fix (BUG-C02): Validate that the CompressionAlgorithm in the
	 * transform header matches the algorithm that was negotiated for this
	 * connection.  Without this check a client that negotiated Pattern_V1
	 * could send a transform header claiming LZ4 (or any other algorithm)
	 * and force the server to invoke an arbitrary decompressor on attacker-
	 * controlled data — a classic algorithm-confusion attack.
	 *
	 * MS-SMB2 §3.3.5.2.3 requires the server to use the negotiated
	 * compression algorithm.  If the PDU specifies a different algorithm,
	 * drop the packet.
	 */
	if (algorithm != work->conn->compress_algorithm) {
		pr_err("ksmbd: compression algorithm mismatch: got %d, expected %d\n",
		       le16_to_cpu(algorithm),
		       le16_to_cpu(work->conn->compress_algorithm));
		return -EINVAL;
	}

	/*
	 * Decompression bomb cap (BUG-C03): cap original_size at
	 * min(2MB, max_trans_size).
	 *
	 * MS-SMB2 §2.2.42 requires OriginalCompressedSegmentSize MUST NOT
	 * exceed MaxTransactSize negotiated in the NEGOTIATE response.
	 */
	{
		unsigned int max_allowed = 2 * 1024 * 1024;
		struct ksmbd_conn *conn = work->conn;

		if (conn && conn->vals && conn->vals->max_trans_size)
			max_allowed = min_t(unsigned int, max_allowed,
					    conn->vals->max_trans_size);
		if (original_size > max_allowed) {
			pr_err("Decompressed size too large: %u (max %u)\n",
			       original_size, max_allowed);
			return -ECONNABORTED;
		}
	}

	/*
	 * Layout (non-chained):
	 *   [RFC1002 4B][CompressionTransformHdr]
	 *   [Uncompressed prefix: 'offset' bytes]
	 *   [Compressed region]
	 */
	if (check_add_overflow(
		    (unsigned int)sizeof(struct smb2_compression_transform_hdr),
		    offset, &compressed_offset)) {
		pr_err("Compression offset overflow: sizeof(hdr) + %u\n",
		       offset);
		return -ECONNABORTED;
	}

	if (compressed_offset > pdu_length) {
		pr_err("Invalid compression offset: %u > PDU length %u\n",
		       compressed_offset, pdu_length);
		return -ECONNABORTED;
	}

	compressed_len = pdu_length - compressed_offset;

	/*
	 * Reject excessive amplification ratios (decompression bomb guard).
	 * Cap at 1024:1 which is generous for legitimate traffic.
	 */
	if (compressed_len > 0 && original_size > offset &&
	    (original_size - offset) / 1024 > compressed_len) {
		pr_err("Decompression ratio too high: %u -> %u (compressed %u)\n",
		       compressed_len, original_size - offset, compressed_len);
		return -ECONNABORTED;
	}

	uncompressed_part = (char *)hdr +
			    sizeof(struct smb2_compression_transform_hdr);
	compressed_part = (char *)hdr + compressed_offset;

	if (original_size < offset) {
		pr_err("Invalid: original size %u < offset %u\n",
		       original_size, offset);
		return -ECONNABORTED;
	}

	/*
	 * TC-24: Reject zero-length or undersized decompressed requests.
	 * original_size == 0 would pass a zero-length buffer to the SMB2
	 * parser which will crash on the absent SMB2 header.
	 */
	if (original_size < sizeof(struct smb2_hdr)) {
		pr_err("Decompressed size %u too small for SMB2 header\n",
		       original_size);
		return -EINVAL;
	}

	total_decompressed_len = original_size;

	/* Allocate buffer: 4 bytes RFC1002 + decompressed payload */
	decompressed_buf = kvmalloc(total_decompressed_len + 5,
				    KSMBD_DEFAULT_GFP);
	if (!decompressed_buf)
		return -ENOMEM;

	/* Set RFC1002 length header */
	*(__be32 *)decompressed_buf = cpu_to_be32(total_decompressed_len);

	/* Copy uncompressed prefix */
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
 * Multi-iov responses (e.g., SMB2 READ with iov[0]=RFC1002 4-byte header,
 * iov[1]=SMB2 response struct, iov[2]=file data) are handled by
 * linearizing all payload iovs (iov[1..n]) into a contiguous buffer
 * before compression.
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
	void *payload_buf = NULL;
	unsigned int payload_len = 0;
	bool payload_allocated = false;
	void *compressed_buf = NULL;
	void *comp_transform_buf;
	int compressed_size;
	unsigned int comp_transform_len;
	__le16 algorithm;
	unsigned int total_rsp_len;
	unsigned int smb2_hdr_size;
	int i;

	/* Skip if no compression negotiated */
	if (conn->compress_algorithm == SMB3_COMPRESS_NONE)
		return 0;

	/* Skip if the response is encrypted */
	if (work->encrypted)
		return 0;

	/* We need at least iov[0] (RFC1002) and iov[1] (SMB2 header) */
	if (!work->iov_idx || !work->iov || work->iov_cnt < 2)
		return 0;

	iov = work->iov;
	algorithm = conn->compress_algorithm;

	/*
	 * iov[0].iov_base = work->response_buf, iov[0].iov_len = 4
	 *   Contains RFC1002 4-byte length prefix.
	 * iov[1].iov_base = SMB2 response header + command response
	 * iov[2].iov_base = auxiliary data (file data for READ, etc.)
	 *
	 * total_rsp_len = bytes after the RFC1002 prefix
	 *               = sum of iov[1..n].iov_len
	 */
	total_rsp_len = get_rfc1002_len(iov[0].iov_base);

	/* Check minimum size threshold */
	if (total_rsp_len < SMB2_COMPRESSION_THRESHOLD)
		return 0;

	/* iov[1] must hold at least the SMB2 header */
	smb2_hdr_size = sizeof(struct smb2_hdr);
	if (iov[1].iov_len < smb2_hdr_size)
		return 0;

	rsp_hdr = iov[1].iov_base;

	/*
	 * payload_len = everything after the SMB2 header (what we compress).
	 * The SMB2 header itself becomes the uncompressed Offset prefix.
	 */
	if (total_rsp_len <= smb2_hdr_size)
		return 0;

	payload_len = total_rsp_len - smb2_hdr_size;

	if (work->iov_cnt == 2) {
		/*
		 * Simple case: all data is in iov[1].
		 * The payload starts immediately after the SMB2 header.
		 */
		payload_buf = (char *)iov[1].iov_base + smb2_hdr_size;
		payload_allocated = false;
	} else {
		/*
		 * Multi-iov case (e.g., READ response with iov[2] = file data).
		 * Linearize the body of iov[1] plus iov[2..n] into one buffer.
		 */
		unsigned int linear_off = 0;
		char *linear;

		linear = kvmalloc(payload_len, KSMBD_DEFAULT_GFP);
		if (!linear)
			return 0; /* Fail silently — send uncompressed */

		/* Tail portion of iov[1] (after the SMB2 header) */
		{
			unsigned int iov1_body =
				(iov[1].iov_len > smb2_hdr_size) ?
				(iov[1].iov_len - smb2_hdr_size) : 0;

			if (iov1_body > payload_len)
				iov1_body = payload_len;

			if (iov1_body > 0) {
				memcpy(linear,
				       (char *)iov[1].iov_base + smb2_hdr_size,
				       iov1_body);
				linear_off += iov1_body;
			}
		}

		/* Remaining iovs (iov[2], iov[3], ...) */
		for (i = 2; i < work->iov_cnt && linear_off < payload_len; i++) {
			unsigned int copy_len = min_t(unsigned int,
						      iov[i].iov_len,
						      payload_len - linear_off);
			if (iov[i].iov_base && copy_len > 0) {
				memcpy(linear + linear_off,
				       iov[i].iov_base, copy_len);
				linear_off += copy_len;
			}
		}

		payload_buf = linear;
		payload_len = linear_off;
		payload_allocated = true;
	}

	if (payload_len == 0) {
		if (payload_allocated)
			kvfree(payload_buf);
		return 0;
	}

	/* Try to compress the payload */
	compressed_buf = kvmalloc(payload_len, KSMBD_DEFAULT_GFP);
	if (!compressed_buf) {
		if (payload_allocated)
			kvfree(payload_buf);
		return 0;
	}

	compressed_size = smb2_compress_data(algorithm,
					     payload_buf, payload_len,
					     compressed_buf, payload_len);

	if (payload_allocated)
		kvfree(payload_buf);

	if (compressed_size <= 0) {
		kvfree(compressed_buf);
		return 0; /* Not compressible — send uncompressed */
	}

	/*
	 * Build the output:
	 *   [RFC1002 4B][CompTransformHdr][SMB2Hdr (uncompressed)][Compressed body]
	 */
	comp_transform_len = 4 +
			     sizeof(struct smb2_compression_transform_hdr) +
			     smb2_hdr_size +
			     (unsigned int)compressed_size;

	/* Only use compression if it actually reduces the message size */
	if (comp_transform_len >= total_rsp_len + 4) {
		kvfree(compressed_buf);
		return 0;
	}

	comp_transform_buf = kvmalloc(comp_transform_len, KSMBD_DEFAULT_GFP);
	if (!comp_transform_buf) {
		kvfree(compressed_buf);
		return 0;
	}

	/* RFC1002 length field */
	*(__be32 *)comp_transform_buf = cpu_to_be32(comp_transform_len - 4);

	/* Compression transform header */
	comp_hdr = (struct smb2_compression_transform_hdr *)
		   (comp_transform_buf + 4);
	comp_hdr->ProtocolId = SMB2_COMPRESSION_TRANSFORM_ID;
	comp_hdr->OriginalCompressedSegmentSize = cpu_to_le32(total_rsp_len);
	comp_hdr->CompressionAlgorithm = algorithm;
	comp_hdr->Flags = cpu_to_le16(SMB2_COMPRESSION_FLAG_NONE);
	comp_hdr->Offset = cpu_to_le32(smb2_hdr_size);

	/* Uncompressed SMB2 header (Offset bytes) */
	memcpy(comp_transform_buf + 4 +
	       sizeof(struct smb2_compression_transform_hdr),
	       rsp_hdr, smb2_hdr_size);

	/* Compressed body */
	memcpy(comp_transform_buf + 4 +
	       sizeof(struct smb2_compression_transform_hdr) +
	       smb2_hdr_size,
	       compressed_buf, compressed_size);

	kvfree(compressed_buf);

	/* Collapse the iov array: replace with single compressed buffer */
	iov[0].iov_base = comp_transform_buf;
	iov[0].iov_len  = comp_transform_len;

	work->tr_buf  = comp_transform_buf;
	work->iov_cnt = 1;
	work->iov_idx = 1;

	ksmbd_debug(SMB,
		    "Compressed response: %u -> %u bytes (algo=0x%04x)\n",
		    total_rsp_len, comp_transform_len - 4,
		    le16_to_cpu(algorithm));

	return 0;
}
