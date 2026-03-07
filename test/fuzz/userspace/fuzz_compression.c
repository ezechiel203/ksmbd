// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace libFuzzer target for SMB3 compression/decompression.
 *
 * Exercises the decompression paths that ksmbd uses when processing
 * compressed SMB3 messages (MS-XCA):
 *   - LZNT1 decompression (MS-XCA 2.3): chunk headers, flag bytes,
 *     back-reference tokens with variable-width offset/length splitting
 *   - LZ77 plain decompression (MS-XCA 2.4): 4-byte flag words,
 *     literal/match decisions, extended length encoding
 *   - LZ77+Huffman decompression (MS-XCA 2.5): 256-byte Huffman table,
 *     canonical tree build, bitstream decode, LZ77 match tokens
 *   - SMB3 compression transform header validation
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *        -I. fuzz_compression.c -o fuzz_compression
 */

#include "ksmbd_compat.h"

#define LZNT1_CHUNK_SIZE	4096
#define FUZZ_MAX_OUTPUT		(64 * 1024)

/* ---- LZNT1 decompressor ---- */

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

static ssize_t decompress_lznt1(const u8 *in, size_t in_len,
				u8 *out, size_t out_len)
{
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos + 2 <= in_len) {
		unsigned int chunk_hdr;
		bool is_compressed;
		size_t chunk_data_size;
		size_t chunk_end_in;
		size_t chunk_start_out;

		chunk_hdr = (unsigned int)in[in_pos] |
			    ((unsigned int)in[in_pos + 1] << 8);
		in_pos += 2;

		if (chunk_hdr == 0)
			break;

		is_compressed = !!(chunk_hdr & 0x8000);
		chunk_data_size = (chunk_hdr & 0x0FFF) + 1;

		if (in_pos + chunk_data_size > in_len)
			break;

		chunk_end_in = in_pos + chunk_data_size;
		chunk_start_out = out_pos;

		if (!is_compressed) {
			size_t copy_len = min_t(size_t, chunk_data_size,
						out_len - out_pos);
			if (copy_len < chunk_data_size)
				return -ENOSPC;

			memcpy(out + out_pos, in + in_pos, chunk_data_size);
			out_pos += chunk_data_size;
			in_pos = chunk_end_in;
			continue;
		}

		/* Compressed chunk */
		while (in_pos < chunk_end_in && out_pos < out_len) {
			unsigned int flags;
			int bit;

			if (in_pos >= chunk_end_in)
				break;

			flags = in[in_pos++];

			for (bit = 0; bit < 8 && in_pos < chunk_end_in &&
			     out_pos < out_len; bit++) {
				if (!(flags & (1u << bit))) {
					out[out_pos++] = in[in_pos++];
				} else {
					unsigned int token, offset, length;
					unsigned int filled, pos_bits;
					unsigned int copy_src;

					if (in_pos + 2 > chunk_end_in)
						return -EINVAL;

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

					offset = lznt1_get_offset(token, pos_bits);
					length = lznt1_get_length(token, pos_bits);

					if (offset > out_pos)
						return -EINVAL;

					copy_src = out_pos - offset;
					if (out_pos + length > out_len)
						return -ENOSPC;

					while (length-- > 0)
						out[out_pos++] = out[copy_src++];
				}
			}
		}

		in_pos = chunk_end_in;
	}

	return (ssize_t)out_pos;
}

/* ---- LZ77 plain decompressor ---- */

static ssize_t decompress_lz77(const u8 *in, size_t in_len,
			       u8 *out, size_t out_len)
{
	size_t in_pos = 0;
	size_t out_pos = 0;

	while (in_pos < in_len && out_pos < out_len) {
		unsigned int flags;
		int bit;

		if (in_pos + 4 > in_len)
			break;

		flags = (unsigned int)in[in_pos] |
			((unsigned int)in[in_pos + 1] << 8) |
			((unsigned int)in[in_pos + 2] << 16) |
			((unsigned int)in[in_pos + 3] << 24);
		in_pos += 4;

		for (bit = 0; bit < 32 && in_pos < in_len &&
		     out_pos < out_len; bit++) {
			if (!(flags & (1u << bit))) {
				out[out_pos++] = in[in_pos++];
			} else {
				unsigned int token, offset, length;

				if (in_pos + 2 > in_len)
					return -EINVAL;

				token = (unsigned int)in[in_pos] |
					((unsigned int)in[in_pos + 1] << 8);
				in_pos += 2;

				offset = (token >> 4) + 1;
				length = token & 0xF;

				if (length == 15) {
					unsigned int more;

					if (in_pos >= in_len)
						return -EINVAL;
					more = in[in_pos++];
					if (more == 255) {
						unsigned int extra;

						if (in_pos + 2 > in_len)
							return -EINVAL;
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

				if (offset > out_pos)
					return -EINVAL;

				if (out_pos + length > out_len)
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

/* ---- LZ77+Huffman decompressor ---- */

#define LZ77H_TABLE_SIZE	256
#define LZ77H_NUM_SYMBOLS	512
#define LZ77H_MAX_CODE_LEN	15

static ssize_t decompress_lz77h(const u8 *in, size_t in_len,
				u8 *out, size_t out_len)
{
	u8 code_lengths[LZ77H_NUM_SYMBOLS];
	u16 decode_table[1 << LZ77H_MAX_CODE_LEN];
	unsigned int bl_count[LZ77H_MAX_CODE_LEN + 1];
	unsigned int next_code[LZ77H_MAX_CODE_LEN + 1];
	unsigned int i;
	unsigned int bit_buf;
	unsigned int bits_avail;
	size_t in_pos;
	size_t out_pos = 0;
	unsigned int safety = 0;
	bool any_nonzero = false;

	if (in_len < LZ77H_TABLE_SIZE)
		return -EINVAL;

	/* Extract 4-bit code lengths */
	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++) {
		u8 byte = in[i / 2];
		if (i & 1)
			code_lengths[i] = (byte >> 4) & 0x0F;
		else
			code_lengths[i] = byte & 0x0F;
	}

	/* Validate code lengths */
	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++) {
		if (code_lengths[i] > LZ77H_MAX_CODE_LEN)
			return -EINVAL;
		if (code_lengths[i] > 0)
			any_nonzero = true;
	}
	if (!any_nonzero)
		return -EINVAL;

	/* Build canonical Huffman table */
	memset(bl_count, 0, sizeof(bl_count));
	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++)
		bl_count[code_lengths[i]]++;
	bl_count[0] = 0;

	next_code[0] = 0;
	for (i = 1; i <= LZ77H_MAX_CODE_LEN; i++)
		next_code[i] = (next_code[i - 1] + bl_count[i - 1]) << 1;

	memset(decode_table, 0xFF, sizeof(decode_table));

	for (i = 0; i < LZ77H_NUM_SYMBOLS; i++) {
		unsigned int cl = code_lengths[i];
		unsigned int code, fill_start, fill_count, j;

		if (cl == 0)
			continue;

		code = next_code[cl]++;
		fill_start = code << (LZ77H_MAX_CODE_LEN - cl);
		fill_count = 1u << (LZ77H_MAX_CODE_LEN - cl);

		for (j = 0; j < fill_count; j++) {
			unsigned int idx = fill_start + j;
			if (idx < (1u << LZ77H_MAX_CODE_LEN))
				decode_table[idx] = (u16)i;
		}
	}

	/* Decode bitstream */
	in_pos = LZ77H_TABLE_SIZE;
	bit_buf = 0;
	bits_avail = 0;

	while (out_pos < out_len && in_pos < in_len) {
		unsigned int symbol, code_val;

		/* Fill bit buffer */
		while (bits_avail < LZ77H_MAX_CODE_LEN && in_pos < in_len) {
			bit_buf |= ((unsigned int)in[in_pos++]) << bits_avail;
			bits_avail += 8;
		}

		if (bits_avail < 1)
			break;

		code_val = bit_buf & ((1u << LZ77H_MAX_CODE_LEN) - 1);
		symbol = decode_table[code_val];

		if (symbol == 0xFFFF)
			return -EINVAL;

		{
			unsigned int cl = code_lengths[symbol];
			if (cl == 0 || cl > bits_avail)
				return -EINVAL;
			bit_buf >>= cl;
			bits_avail -= cl;
		}

		if (symbol < 256) {
			out[out_pos++] = (u8)symbol;
		} else {
			unsigned int match_len, match_off, off_bits;

			match_len = (symbol - 256) & 0xF;
			off_bits = ((symbol - 256) >> 4) & 0xF;

			/* Read offset bits */
			while (bits_avail < off_bits && in_pos < in_len) {
				bit_buf |= ((unsigned int)in[in_pos++]) << bits_avail;
				bits_avail += 8;
			}
			if (bits_avail < off_bits)
				return -EINVAL;

			match_off = (bit_buf & ((1u << off_bits) - 1)) + 1;
			bit_buf >>= off_bits;
			bits_avail -= off_bits;

			/* Extended length */
			if (match_len == 15) {
				while (bits_avail < 8 && in_pos < in_len) {
					bit_buf |= ((unsigned int)in[in_pos++]) << bits_avail;
					bits_avail += 8;
				}
				if (bits_avail >= 8) {
					unsigned int extra = bit_buf & 0xFF;
					bit_buf >>= 8;
					bits_avail -= 8;
					if (extra == 255) {
						while (bits_avail < 16 && in_pos < in_len) {
							bit_buf |= ((unsigned int)in[in_pos++]) << bits_avail;
							bits_avail += 8;
						}
						if (bits_avail >= 16) {
							match_len = bit_buf & 0xFFFF;
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

			if (match_off > out_pos)
				return -EINVAL;
			if (out_pos + match_len > out_len)
				return -ENOSPC;

			{
				size_t src = out_pos - match_off;
				while (match_len-- > 0)
					out[out_pos++] = out[src++];
			}
		}

		if (++safety > 4 * FUZZ_MAX_OUTPUT)
			break;
	}

	return (ssize_t)out_pos;
}

/* ---- Compression transform header ---- */

struct smb3_compress_hdr {
	__le32 ProtocolId;
	__le32 OriginalCompressedSegmentSize;
	__le16 CompressionAlgorithm;
	__le16 Flags;
	__le32 Offset;
} __packed;

#define SMB3_COMPRESS_PROTO_ID	0x424d53FC

static void validate_compression_header(const u8 *data, size_t len)
{
	const struct smb3_compress_hdr *hdr;
	u32 orig_size, proto;
	u16 algorithm, flags, offset;

	if (len < sizeof(struct smb3_compress_hdr))
		return;

	hdr = (const struct smb3_compress_hdr *)data;
	proto = le32_to_cpu(hdr->ProtocolId);

	if (proto != SMB3_COMPRESS_PROTO_ID)
		return;

	orig_size = le32_to_cpu(hdr->OriginalCompressedSegmentSize);
	algorithm = le16_to_cpu(hdr->CompressionAlgorithm);
	flags = le16_to_cpu(hdr->Flags);
	offset = le32_to_cpu(hdr->Offset);

	if (algorithm > 4)
		return;

	if (flags > 1)
		return;

	if (orig_size == 0 || orig_size > 16 * 1024 * 1024)
		return;

	if (flags == 0 && sizeof(struct smb3_compress_hdr) + offset > len)
		return;

	/* Access check */
	(void)orig_size;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	u8 *out;

	if (size < 2)
		return 0;

	/* Cap input */
	if (size > 65536)
		size = 65536;

	out = (u8 *)malloc(FUZZ_MAX_OUTPUT);
	if (!out)
		return 0;

	/*
	 * Use first byte to select algorithm:
	 * 0: LZNT1
	 * 1: LZ77 plain
	 * 2: LZ77+Huffman
	 * 3: Compression header + route to decompressor
	 */
	u8 algo = data[0] % 4;
	const u8 *payload = data + 1;
	size_t payload_len = size - 1;

	switch (algo) {
	case 0:
		decompress_lznt1(payload, payload_len, out, FUZZ_MAX_OUTPUT);
		break;
	case 1:
		decompress_lz77(payload, payload_len, out, FUZZ_MAX_OUTPUT);
		break;
	case 2:
		decompress_lz77h(payload, payload_len, out, FUZZ_MAX_OUTPUT);
		break;
	case 3:
		validate_compression_header(payload, payload_len);
		if (payload_len >= sizeof(struct smb3_compress_hdr)) {
			const struct smb3_compress_hdr *hdr =
				(const struct smb3_compress_hdr *)payload;
			u16 calgo = le16_to_cpu(hdr->CompressionAlgorithm);
			u32 offset = le32_to_cpu(hdr->Offset);
			const u8 *comp_data;
			size_t comp_len;

			if (sizeof(struct smb3_compress_hdr) + offset <= payload_len) {
				comp_data = payload + sizeof(struct smb3_compress_hdr) + offset;
				comp_len = payload_len - sizeof(struct smb3_compress_hdr) - offset;

				switch (calgo) {
				case 1:
					decompress_lznt1(comp_data, comp_len,
							 out, FUZZ_MAX_OUTPUT);
					break;
				case 2:
					decompress_lz77(comp_data, comp_len,
							out, FUZZ_MAX_OUTPUT);
					break;
				case 3:
					decompress_lz77h(comp_data, comp_len,
							 out, FUZZ_MAX_OUTPUT);
					break;
				}
			}
		}
		break;
	}

	free(out);
	return 0;
}
