// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB3 compression/decompression
 *
 *   This module exercises the LZNT1, LZ77 plain, and LZ77+Huffman
 *   decompression paths used in ksmbd when processing compressed SMB3
 *   messages. Decompression of attacker-controlled data is a critical
 *   attack surface: decompression bombs, out-of-bounds writes, and
 *   integer overflows are all potential issues.
 *
 *   Targets:
 *     - LZNT1 decompression (MS-XCA section 2.3): chunk headers, flag bytes,
 *       back-reference tokens with variable-width offset/length bit splitting
 *     - LZ77 plain decompression (MS-XCA section 2.4): 4-byte flag words,
 *       literal/match decisions, extended length encoding
 *     - LZ77+Huffman decompression (MS-XCA section 2.5): 256-byte Huffman
 *       table, canonical tree build, bitstream decode, LZ77 match tokens
 *     - SMB3 compression transform header: ProtocolId, algorithm,
 *       OriginalCompressedSegmentSize, chained/unchained
 *
 *   Corpus seed hints:
 *     - LZNT1: 2-byte chunk header 0x03B0 (compressed, 4 bytes data) +
 *       flag byte + literals
 *     - LZ77: 4-byte flags word (all zeros = all literals) + literal bytes
 *     - LZ77+Huffman: 256-byte Huffman table (all 4-bit code lengths) +
 *       compressed bitstream
 *     - Compression header: 0xFC534D42 ProtocolId + fields
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_*() entry points accept raw byte
 *     buffers and lengths.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- LZNT1 inline decompressor (mirrors smb2_compress.c) ---- */

#define LZNT1_CHUNK_SIZE	4096
#define FUZZ_MAX_OUTPUT		(64 * 1024)  /* cap output to prevent bomb */

static inline unsigned int lznt1_get_offset(unsigned int word,
					    unsigned int pos_bits)
{
	return (word >> pos_bits) + 1;
}

static inline unsigned int lznt1_get_length(unsigned int word,
					    unsigned int pos_bits)
{
	unsigned int mask = (1u << pos_bits) - 1u;

	return (word & mask) + 3;
}

/*
 * fuzz_lznt1_decompress - Fuzz LZNT1 decompression
 * @data:	raw compressed input
 * @len:	length of input
 *
 * Exercises the LZNT1 chunk-based decompression logic. This is the
 * critical path for attacker-controlled compressed data.
 *
 * Return: decompressed size on success, negative on error
 */
static ssize_t fuzz_lznt1_decompress(const u8 *data, size_t len)
{
	const unsigned char *in = data;
	unsigned char *out;
	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t output_len = FUZZ_MAX_OUTPUT;
	ssize_t result;

	if (len == 0)
		return 0;

	/* Cap input to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	out = kzalloc(output_len, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	while (in_pos + 2 <= len) {
		unsigned int chunk_hdr;
		size_t chunk_start_out;
		bool is_compressed;
		size_t chunk_data_size;
		size_t chunk_end_in;

		chunk_hdr = (unsigned int)in[in_pos] |
			    ((unsigned int)in[in_pos + 1] << 8);
		in_pos += 2;

		/* Signature check: bits 14:12 should be non-zero for
		 * a valid chunk. A zero chunk header means end of stream.
		 */
		if (chunk_hdr == 0)
			break;

		is_compressed = !(chunk_hdr & 0x8000);
		chunk_data_size = (chunk_hdr & 0x0FFF) + 3;

		if (in_pos + chunk_data_size > len) {
			pr_debug("fuzz_lznt1: truncated chunk at %zu\n",
				 in_pos);
			break;
		}

		chunk_end_in = in_pos + chunk_data_size;
		chunk_start_out = out_pos;

		if (!is_compressed) {
			/* Uncompressed chunk */
			size_t copy_len = min_t(size_t, chunk_data_size,
						output_len - out_pos);

			if (copy_len < chunk_data_size) {
				pr_debug("fuzz_lznt1: output full at uncompressed chunk\n");
				result = -ENOSPC;
				goto out_free;
			}
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
					out[out_pos++] = in[in_pos++];
				} else {
					unsigned int token;
					unsigned int offset, length;
					unsigned int filled;
					unsigned int pos_bits;
					unsigned int copy_offset;

					if (in_pos + 2 > chunk_end_in) {
						result = -EINVAL;
						goto out_free;
					}

					token = (unsigned int)in[in_pos] |
						((unsigned int)in[in_pos + 1] << 8);
					in_pos += 2;

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

					if (offset > out_pos) {
						result = -EINVAL;
						goto out_free;
					}

					copy_offset = out_pos - offset;
					if (out_pos + length > output_len) {
						result = -ENOSPC;
						goto out_free;
					}

					while (length-- > 0)
						out[out_pos++] =
							out[copy_offset++];
				}
			}
		}

		in_pos = chunk_end_in;
	}

	result = (ssize_t)out_pos;
	pr_debug("fuzz_lznt1: decompressed %zu -> %zd\n", len, result);

out_free:
	kfree(out);
	return result;
}

/* ---- LZ77 plain inline decompressor ---- */

/*
 * fuzz_lz77_decompress - Fuzz LZ77 plain decompression
 * @data:	raw compressed input
 * @len:	length of input
 *
 * Exercises the LZ77 plain decompression: 4-byte flag words, literal/match
 * decisions, extended length encoding with extra bytes.
 *
 * Return: decompressed size on success, negative on error
 */
static ssize_t fuzz_lz77_decompress(const u8 *data, size_t len)
{
	const unsigned char *in = data;
	unsigned char *out;
	size_t in_pos = 0;
	size_t out_pos = 0;
	size_t output_len = FUZZ_MAX_OUTPUT;
	ssize_t result;

	if (len == 0)
		return 0;

	if (len > 65536)
		len = 65536;

	out = kzalloc(output_len, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	while (in_pos < len && out_pos < output_len) {
		unsigned int flags;
		int bit;

		/* Read 4-byte flag word */
		if (in_pos + 4 > len)
			break;

		flags = (unsigned int)in[in_pos] |
			((unsigned int)in[in_pos + 1] << 8) |
			((unsigned int)in[in_pos + 2] << 16) |
			((unsigned int)in[in_pos + 3] << 24);
		in_pos += 4;

		for (bit = 0; bit < 32 && in_pos < len &&
		     out_pos < output_len; bit++) {
			if (!(flags & (1u << bit))) {
				/* Literal */
				out[out_pos++] = in[in_pos++];
			} else {
				/* Back-reference */
				unsigned int token;
				unsigned int offset, length;

				if (in_pos + 2 > len) {
					result = -EINVAL;
					goto out_free;
				}

				token = (unsigned int)in[in_pos] |
					((unsigned int)in[in_pos + 1] << 8);
				in_pos += 2;

				offset = (token >> 4) + 1;
				length = token & 0xF;

				if (length == 15) {
					unsigned int more;

					if (in_pos >= len) {
						result = -EINVAL;
						goto out_free;
					}
					more = in[in_pos++];
					if (more == 255) {
						unsigned int extra;

						if (in_pos + 2 > len) {
							result = -EINVAL;
							goto out_free;
						}
						extra = (unsigned int)in[in_pos] |
							((unsigned int)in[in_pos + 1] << 8);
						in_pos += 2;
						length = extra;
					} else {
						length = length + more + 3;
					}
				} else {
					length += 3;
				}

				if (offset > out_pos) {
					result = -EINVAL;
					goto out_free;
				}

				if (out_pos + length > output_len) {
					result = -ENOSPC;
					goto out_free;
				}

				{
					size_t src = out_pos - offset;

					while (length-- > 0)
						out[out_pos++] = out[src++];
				}
			}
		}
	}

	result = (ssize_t)out_pos;
	pr_debug("fuzz_lz77: decompressed %zu -> %zd\n", len, result);

out_free:
	kfree(out);
	return result;
}

/* ---- LZ77+Huffman inline decompressor ---- */

#define LZ77H_HUFFMAN_TABLE_SIZE	256   /* 256 bytes = 512 4-bit entries */
#define LZ77H_NUM_SYMBOLS		512
#define LZ77H_MAX_CODE_LEN		15

/*
 * fuzz_lz77h_decompress - Fuzz LZ77+Huffman decompression
 * @data:	raw compressed input (256-byte table + bitstream)
 * @len:	length of input
 *
 * Exercises the Huffman table build + canonical decode + LZ77 match
 * expansion. The 256-byte Huffman table contains 512 4-bit code lengths.
 *
 * Return: decompressed size on success, negative on error
 */
static ssize_t fuzz_lz77h_decompress(const u8 *data, size_t len)
{
	unsigned char *out;
	size_t output_len = FUZZ_MAX_OUTPUT;
	ssize_t result;
	u8 code_lengths[LZ77H_NUM_SYMBOLS];
	u16 decode_table[1 << LZ77H_MAX_CODE_LEN];
	unsigned int i;
	unsigned int bl_count[LZ77H_MAX_CODE_LEN + 1];
	unsigned int next_code[LZ77H_MAX_CODE_LEN + 1];
	unsigned int bit_buf;
	unsigned int bits_avail;
	size_t in_pos;
	size_t out_pos = 0;

	if (len < LZ77H_HUFFMAN_TABLE_SIZE) {
		pr_debug("fuzz_lz77h: input too small for Huffman table\n");
		return -EINVAL;
	}

	if (len > 65536)
		len = 65536;

	/* Extract 4-bit code lengths from the 256-byte table */
	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++) {
		u8 byte = data[i / 2];

		if (i & 1)
			code_lengths[i] = (byte >> 4) & 0x0F;
		else
			code_lengths[i] = byte & 0x0F;
	}

	/* Validate code lengths */
	{
		bool any_nonzero = false;

		for (i = 0; i < LZ77H_NUM_SYMBOLS; i++) {
			if (code_lengths[i] > LZ77H_MAX_CODE_LEN) {
				pr_debug("fuzz_lz77h: code length %u > max %u\n",
					 code_lengths[i], LZ77H_MAX_CODE_LEN);
				return -EINVAL;
			}
			if (code_lengths[i] > 0)
				any_nonzero = true;
		}
		if (!any_nonzero) {
			pr_debug("fuzz_lz77h: all code lengths zero\n");
			return -EINVAL;
		}
	}

	/* Build canonical Huffman decode table */
	memset(bl_count, 0, sizeof(bl_count));
	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++)
		bl_count[code_lengths[i]]++;
	bl_count[0] = 0;

	next_code[0] = 0;
	for (i = 1; i <= LZ77H_MAX_CODE_LEN; i++)
		next_code[i] = (next_code[i - 1] + bl_count[i - 1]) << 1;

	/* Fill decode table with sentinel */
	memset(decode_table, 0xFF, sizeof(decode_table));

	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++) {
		unsigned int cl = code_lengths[i];
		unsigned int code;
		unsigned int fill_start, fill_count, j;

		if (cl == 0)
			continue;

		code = next_code[cl]++;
		/* Fill all entries that match this prefix */
		fill_start = code << (LZ77H_MAX_CODE_LEN - cl);
		fill_count = 1u << (LZ77H_MAX_CODE_LEN - cl);

		for (j = 0; j < fill_count; j++) {
			unsigned int idx = fill_start + j;

			if (idx < ARRAY_SIZE(decode_table))
				decode_table[idx] = (u16)i;
		}
	}

	/* Now decode the bitstream */
	out = kzalloc(output_len, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	in_pos = LZ77H_HUFFMAN_TABLE_SIZE;
	bit_buf = 0;
	bits_avail = 0;

	while (out_pos < output_len && in_pos < len) {
		unsigned int symbol;
		unsigned int code_val;
		unsigned int safety = 0;

		/* Fill bit buffer */
		while (bits_avail < LZ77H_MAX_CODE_LEN && in_pos < len) {
			bit_buf |= ((unsigned int)data[in_pos++]) << bits_avail;
			bits_avail += 8;
		}

		if (bits_avail < 1)
			break;

		/* Look up symbol using max-length prefix */
		code_val = bit_buf & ((1u << LZ77H_MAX_CODE_LEN) - 1);
		symbol = decode_table[code_val];

		if (symbol == 0xFFFF) {
			pr_debug("fuzz_lz77h: invalid Huffman code\n");
			result = -EINVAL;
			goto out_free;
		}

		/* Consume the appropriate number of bits */
		{
			unsigned int cl = code_lengths[symbol];

			if (cl == 0 || cl > bits_avail) {
				result = -EINVAL;
				goto out_free;
			}
			bit_buf >>= cl;
			bits_avail -= cl;
		}

		if (symbol < 256) {
			/* Literal byte */
			out[out_pos++] = (unsigned char)symbol;
		} else {
			/* LZ77 match: symbol 256-511 */
			unsigned int match_len;
			unsigned int match_off;
			unsigned int off_bits;
			unsigned int len_bits;

			/* Extra length from symbol */
			match_len = (symbol - 256) & 0xF;
			off_bits = ((symbol - 256) >> 4) & 0xF;

			/* Read offset */
			while (bits_avail < off_bits && in_pos < len) {
				bit_buf |= ((unsigned int)data[in_pos++]) << bits_avail;
				bits_avail += 8;
			}

			if (bits_avail < off_bits) {
				result = -EINVAL;
				goto out_free;
			}

			match_off = (bit_buf & ((1u << off_bits) - 1)) + 1;
			bit_buf >>= off_bits;
			bits_avail -= off_bits;

			/* Extended length */
			if (match_len == 15) {
				while (bits_avail < 8 && in_pos < len) {
					bit_buf |= ((unsigned int)data[in_pos++]) << bits_avail;
					bits_avail += 8;
				}
				if (bits_avail >= 8) {
					unsigned int extra = bit_buf & 0xFF;

					bit_buf >>= 8;
					bits_avail -= 8;
					if (extra == 255) {
						while (bits_avail < 16 && in_pos < len) {
							bit_buf |= ((unsigned int)data[in_pos++]) << bits_avail;
							bits_avail += 8;
						}
						if (bits_avail >= 16) {
							match_len = (bit_buf & 0xFFFF);
							bit_buf >>= 16;
							bits_avail -= 16;
						}
					} else {
						match_len = match_len + extra + 3;
					}
				}
			} else {
				match_len += 3;
			}

			if (match_off > out_pos) {
				result = -EINVAL;
				goto out_free;
			}

			if (out_pos + match_len > output_len) {
				result = -ENOSPC;
				goto out_free;
			}

			{
				size_t src = out_pos - match_off;

				while (match_len-- > 0)
					out[out_pos++] = out[src++];
			}
		}

		/* Safety valve: limit total iterations */
		if (++safety > 4 * FUZZ_MAX_OUTPUT)
			break;
	}

	result = (ssize_t)out_pos;
	pr_debug("fuzz_lz77h: decompressed %zu -> %zd\n", len, result);

out_free:
	kfree(out);
	return result;
}

/* ---- SMB3 compression transform header ---- */

struct smb3_compress_hdr {
	__le32 ProtocolId;            /* 0xFC 'S' 'M' 'B' */
	__le32 OriginalCompressedSegmentSize;
	__le16 CompressionAlgorithm;
	__le16 Flags;
	__le32 Offset;                /* For unchained: offset to compressed data */
} __packed;

#define SMB3_COMPRESS_PROTO_NUM		cpu_to_le32(0x424d53FC)
#define SMB2_COMPRESSION_FLAG_NONE	0x0000
#define SMB2_COMPRESSION_FLAG_CHAINED	0x0001

/*
 * fuzz_compression_header - Fuzz SMB3 compression transform header
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Validates the compression transform header fields.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_compression_header(const u8 *data, size_t len)
{
	const struct smb3_compress_hdr *hdr;
	u32 orig_size;
	u16 algorithm;
	u16 flags;
	u32 offset;

	if (len < sizeof(struct smb3_compress_hdr)) {
		pr_debug("fuzz_comphdr: input too small (%zu)\n", len);
		return -EINVAL;
	}

	hdr = (const struct smb3_compress_hdr *)data;

	/* Validate ProtocolId */
	if (hdr->ProtocolId != SMB3_COMPRESS_PROTO_NUM) {
		pr_debug("fuzz_comphdr: bad protocol id 0x%08x\n",
			 le32_to_cpu(hdr->ProtocolId));
		return -EINVAL;
	}

	orig_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);
	algorithm = le16_to_cpu(hdr->CompressionAlgorithm);
	flags = le16_to_cpu(hdr->Flags);
	offset = le32_to_cpu(hdr->Offset);

	/* Validate algorithm (0=NONE, 1=LZNT1, 2=LZ77, 3=LZ77+Huffman, 4=PATTERN_V1) */
	if (algorithm > 4) {
		pr_debug("fuzz_comphdr: unknown algorithm %u\n", algorithm);
		return -EINVAL;
	}

	/* Validate flags */
	if (flags != SMB2_COMPRESSION_FLAG_NONE &&
	    flags != SMB2_COMPRESSION_FLAG_CHAINED) {
		pr_debug("fuzz_comphdr: invalid flags 0x%04x\n", flags);
		return -EINVAL;
	}

	/* Validate OriginalCompressedSegmentSize */
	if (orig_size == 0) {
		pr_debug("fuzz_comphdr: zero OriginalCompressedSegmentSize\n");
		return -EINVAL;
	}

	if (orig_size > 16 * 1024 * 1024) {
		pr_debug("fuzz_comphdr: OriginalCompressedSegmentSize %u too large\n",
			 orig_size);
		return -EINVAL;
	}

	/* Unchained: Offset must point within remaining buffer */
	if (flags == SMB2_COMPRESSION_FLAG_NONE) {
		if (sizeof(struct smb3_compress_hdr) + offset > len) {
			pr_debug("fuzz_comphdr: Offset %u out of bounds\n", offset);
			return -EINVAL;
		}
	}

	pr_debug("fuzz_comphdr: algo=%u flags=0x%04x orig_size=%u offset=%u\n",
		 algorithm, flags, orig_size, offset);

	return 0;
}

static int __init compression_fuzz_init(void)
{
	u8 *test_buf;
	ssize_t ret;

	pr_info("compression_fuzz: module loaded\n");

	test_buf = kzalloc(1024, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: LZNT1 - uncompressed chunk */
	{
		/* Chunk header: bit 15 set (uncompressed), size = 5-3=2 */
		test_buf[0] = 0x02;
		test_buf[1] = 0x80;
		test_buf[2] = 'H'; test_buf[3] = 'i'; test_buf[4] = '!';
		test_buf[5] = 0; test_buf[6] = 0; /* end marker */
		ret = fuzz_lznt1_decompress(test_buf, 7);
		pr_info("compression_fuzz: lznt1 uncompressed test returned %zd\n", ret);
	}

	/* Self-test 2: LZNT1 - empty input */
	ret = fuzz_lznt1_decompress(test_buf, 0);
	pr_info("compression_fuzz: lznt1 empty test returned %zd\n", ret);

	/* Self-test 3: LZNT1 - truncated chunk */
	test_buf[0] = 0xFF;
	test_buf[1] = 0x0F;
	ret = fuzz_lznt1_decompress(test_buf, 2);
	pr_info("compression_fuzz: lznt1 truncated test returned %zd\n", ret);

	/* Self-test 4: LZ77 - all literals */
	memset(test_buf, 0, 1024);
	/* flags word = 0 means 32 literals */
	test_buf[0] = 0; test_buf[1] = 0; test_buf[2] = 0; test_buf[3] = 0;
	test_buf[4] = 'A'; test_buf[5] = 'B'; test_buf[6] = 'C';
	ret = fuzz_lz77_decompress(test_buf, 7);
	pr_info("compression_fuzz: lz77 literals test returned %zd\n", ret);

	/* Self-test 5: LZ77 - empty input */
	ret = fuzz_lz77_decompress(test_buf, 0);
	pr_info("compression_fuzz: lz77 empty test returned %zd\n", ret);

	/* Self-test 6: LZ77+Huffman - table too small */
	ret = fuzz_lz77h_decompress(test_buf, 100);
	pr_info("compression_fuzz: lz77h small table test returned %zd\n", ret);

	/* Self-test 7: LZ77+Huffman - all-zero table */
	memset(test_buf, 0, 1024);
	ret = fuzz_lz77h_decompress(test_buf, 300);
	pr_info("compression_fuzz: lz77h zero table test returned %zd\n", ret);

	/* Self-test 8: Compression header - valid */
	{
		struct smb3_compress_hdr *chdr =
			(struct smb3_compress_hdr *)test_buf;

		memset(test_buf, 0, 1024);
		chdr->ProtocolId = SMB3_COMPRESS_PROTO_NUM;
		chdr->OriginalCompressedSegmentSize = cpu_to_le32(4096);
		chdr->CompressionAlgorithm = cpu_to_le16(1); /* LZNT1 */
		chdr->Flags = cpu_to_le16(0);
		chdr->Offset = cpu_to_le32(0);
		ret = fuzz_compression_header(test_buf, sizeof(*chdr));
		pr_info("compression_fuzz: comp hdr valid test returned %zd\n", ret);
	}

	/* Self-test 9: Compression header - wrong protocol */
	{
		struct smb3_compress_hdr *chdr =
			(struct smb3_compress_hdr *)test_buf;

		chdr->ProtocolId = cpu_to_le32(0x424d53FE); /* SMB2, not compress */
		ret = fuzz_compression_header(test_buf, sizeof(*chdr));
		pr_info("compression_fuzz: comp hdr wrong proto test returned %zd\n", ret);
	}

	/* Self-test 10: Garbage data through all decompressors */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_lznt1_decompress(test_buf, 512);
	pr_info("compression_fuzz: lznt1 garbage test returned %zd\n", ret);
	ret = fuzz_lz77_decompress(test_buf, 512);
	pr_info("compression_fuzz: lz77 garbage test returned %zd\n", ret);
	ret = fuzz_lz77h_decompress(test_buf, 300);
	pr_info("compression_fuzz: lz77h garbage test returned %zd\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit compression_fuzz_exit(void)
{
	pr_info("compression_fuzz: module unloaded\n");
}

module_init(compression_fuzz_init);
module_exit(compression_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB3 compression (LZNT1/LZ77/LZ77+Huffman)");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
