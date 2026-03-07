// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for QUIC packet parsing
 *
 *   This module exercises the QUIC Initial packet parsing and variable-length
 *   integer decoding used in ksmbd's QUIC transport. QUIC Initial packets
 *   are the first bytes received on the UDP wire from unauthenticated clients,
 *   making this a critical attack surface.
 *
 *   Targets:
 *     - QUIC variable-length integer decode (RFC 9000 section 16)
 *     - QUIC variable-length integer encode (round-trip)
 *     - QUIC Initial packet header parsing: first-byte flags, Version,
 *       DCID/SCID length+data, token varint, payload varint
 *     - Header protection removal: sample/mask logic
 *
 *   Corpus seed hints:
 *     - First byte 0xC0 or 0xC1 (long header, Initial)
 *     - Version 0x00000001 (QUIC v1)
 *     - DCID length 0-20, SCID length 0-20
 *     - Token length as varint (typically 0)
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <asm/unaligned.h>

/* QUIC constants (from transport_quic.c) */
#define QUIC_HDR_FORM_LONG		0x80
#define QUIC_HDR_FIXED_BIT		0x40
#define QUIC_LONG_TYPE_INITIAL		0x00
#define QUIC_LONG_TYPE_HANDSHAKE	0x20
#define QUIC_LONG_TYPE_RETRY		0x30
#define QUIC_MAX_CID_LEN		20
#define QUIC_VERSION_1			0x00000001U
#define QUIC_MAX_PKT_SIZE		1500

/*
 * fuzz_quic_get_varint - Decode a QUIC variable-length integer
 * @buf:	source buffer
 * @len:	available bytes
 * @val_out:	decoded value
 * @consumed:	bytes consumed
 *
 * Return: 0 on success, -EINVAL on error
 */
static int fuzz_quic_get_varint(const u8 *buf, size_t len,
				u64 *val_out, int *consumed)
{
	u8 first;

	if (!len)
		return -EINVAL;

	first = buf[0];
	switch (first >> 6) {
	case 0:
		*val_out = first & 0x3f;
		*consumed = 1;
		return 0;
	case 1:
		if (len < 2)
			return -EINVAL;
		*val_out = ((u64)(first & 0x3f) << 8) | buf[1];
		*consumed = 2;
		return 0;
	case 2:
		if (len < 4)
			return -EINVAL;
		*val_out = ((u64)(first & 0x3f) << 24) |
			   ((u64)buf[1] << 16) |
			   ((u64)buf[2] << 8) |
			    (u64)buf[3];
		*consumed = 4;
		return 0;
	case 3:
		if (len < 8)
			return -EINVAL;
		*val_out = ((u64)(first & 0x3f) << 56) |
			   ((u64)buf[1] << 48) |
			   ((u64)buf[2] << 40) |
			   ((u64)buf[3] << 32) |
			   ((u64)buf[4] << 24) |
			   ((u64)buf[5] << 16) |
			   ((u64)buf[6] << 8) |
			    (u64)buf[7];
		*consumed = 8;
		return 0;
	}
	return -EINVAL;
}

/*
 * fuzz_quic_put_varint - Encode a QUIC variable-length integer
 * @buf:	destination buffer (at least 8 bytes)
 * @val:	value to encode
 * @len_out:	bytes written
 *
 * Return: 0 on success, -ERANGE if too large
 */
static int fuzz_quic_put_varint(u8 *buf, u64 val, int *len_out)
{
	if (val < 64) {
		buf[0] = (u8)val;
		*len_out = 1;
	} else if (val < 16384) {
		buf[0] = 0x40 | (u8)(val >> 8);
		buf[1] = (u8)val;
		*len_out = 2;
	} else if (val < 1073741824ULL) {
		put_unaligned_be32((u32)(0x80000000UL | val), buf);
		*len_out = 4;
	} else if (val < (1ULL << 62)) {
		put_unaligned_be64(0xC000000000000000ULL | val, buf);
		*len_out = 8;
	} else {
		return -ERANGE;
	}
	return 0;
}

/*
 * fuzz_quic_varint - Fuzz QUIC varint encode/decode
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Decodes a varint from the input, then re-encodes and verifies round-trip.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_quic_varint(const u8 *data, size_t len)
{
	u64 val;
	int consumed;
	int ret;
	u8 re_enc[8];
	int re_len;

	ret = fuzz_quic_get_varint(data, len, &val, &consumed);
	if (ret < 0) {
		pr_debug("fuzz_quic: varint decode failed\n");
		return ret;
	}

	pr_debug("fuzz_quic: varint decoded val=%llu consumed=%d\n",
		 val, consumed);

	/* Round-trip test */
	ret = fuzz_quic_put_varint(re_enc, val, &re_len);
	if (ret < 0) {
		pr_debug("fuzz_quic: varint re-encode failed\n");
		return ret;
	}

	/* Re-decode and verify */
	{
		u64 val2;
		int consumed2;

		ret = fuzz_quic_get_varint(re_enc, re_len, &val2, &consumed2);
		if (ret < 0 || val2 != val)
			pr_debug("fuzz_quic: varint round-trip mismatch\n");
	}

	return 0;
}

/*
 * fuzz_quic_initial_parse - Fuzz QUIC Initial packet header parsing
 * @data:	raw packet bytes
 * @len:	length of packet
 *
 * Parses the QUIC long-header Initial packet format: first byte, Version,
 * DCID length + data, SCID length + data, token varint length + data,
 * payload varint length.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_quic_initial_parse(const u8 *data, size_t len)
{
	size_t pos = 0;
	u8 first_byte;
	u8 pkt_type;
	u32 version;
	u8 dcid_len, scid_len;
	u64 token_len, payload_len;
	int consumed;
	int ret;

	if (len < 7) {
		pr_debug("fuzz_quic: packet too short (%zu)\n", len);
		return -EINVAL;
	}

	if (len > QUIC_MAX_PKT_SIZE)
		len = QUIC_MAX_PKT_SIZE;

	/* First byte */
	first_byte = data[pos++];

	/* Must be long header (Form bit = 1) */
	if (!(first_byte & QUIC_HDR_FORM_LONG)) {
		pr_debug("fuzz_quic: not a long header (first=0x%02x)\n",
			 first_byte);
		return -EINVAL;
	}

	/* Fixed bit must be 1 */
	if (!(first_byte & QUIC_HDR_FIXED_BIT)) {
		pr_debug("fuzz_quic: fixed bit not set\n");
		return -EINVAL;
	}

	/* Packet type (bits 5:4) */
	pkt_type = first_byte & 0x30;
	if (pkt_type != QUIC_LONG_TYPE_INITIAL &&
	    pkt_type != QUIC_LONG_TYPE_HANDSHAKE &&
	    pkt_type != QUIC_LONG_TYPE_RETRY) {
		pr_debug("fuzz_quic: packet type 0x%02x (0-RTT or unknown)\n",
			 pkt_type);
		/* Not an error per se, but we focus on Initial */
	}

	/* Version (4 bytes, big-endian) */
	if (pos + 4 > len)
		return -EINVAL;
	version = ((u32)data[pos] << 24) | ((u32)data[pos + 1] << 16) |
		  ((u32)data[pos + 2] << 8) | (u32)data[pos + 3];
	pos += 4;

	pr_debug("fuzz_quic: version=0x%08x type=0x%02x\n", version, pkt_type);

	/* Version 0 = Version Negotiation (special) */
	if (version == 0) {
		pr_debug("fuzz_quic: version negotiation packet\n");
		return 0;
	}

	/* DCID length (1 byte) + DCID */
	if (pos >= len)
		return -EINVAL;
	dcid_len = data[pos++];
	if (dcid_len > QUIC_MAX_CID_LEN) {
		pr_debug("fuzz_quic: DCID len %u > max %u\n",
			 dcid_len, QUIC_MAX_CID_LEN);
		return -EINVAL;
	}
	if (pos + dcid_len > len) {
		pr_debug("fuzz_quic: DCID truncated\n");
		return -EINVAL;
	}
	pos += dcid_len;

	/* SCID length (1 byte) + SCID */
	if (pos >= len)
		return -EINVAL;
	scid_len = data[pos++];
	if (scid_len > QUIC_MAX_CID_LEN) {
		pr_debug("fuzz_quic: SCID len %u > max %u\n",
			 scid_len, QUIC_MAX_CID_LEN);
		return -EINVAL;
	}
	if (pos + scid_len > len) {
		pr_debug("fuzz_quic: SCID truncated\n");
		return -EINVAL;
	}
	pos += scid_len;

	/* Token length (varint) - only for Initial packets */
	if (pkt_type == QUIC_LONG_TYPE_INITIAL) {
		ret = fuzz_quic_get_varint(data + pos, len - pos,
					   &token_len, &consumed);
		if (ret < 0) {
			pr_debug("fuzz_quic: token length decode failed\n");
			return ret;
		}
		pos += consumed;

		if (token_len > len - pos) {
			pr_debug("fuzz_quic: token truncated (%llu > %zu)\n",
				 token_len, len - pos);
			return -EINVAL;
		}
		pos += (size_t)token_len;
	}

	/* Payload length (varint) */
	ret = fuzz_quic_get_varint(data + pos, len - pos,
				   &payload_len, &consumed);
	if (ret < 0) {
		pr_debug("fuzz_quic: payload length decode failed\n");
		return ret;
	}
	pos += consumed;

	pr_debug("fuzz_quic: dcid_len=%u scid_len=%u payload_len=%llu\n",
		 dcid_len, scid_len, payload_len);

	/* Remaining bytes = encrypted payload + packet number */
	if (pos + payload_len > len) {
		pr_debug("fuzz_quic: payload exceeds packet (%llu > %zu)\n",
			 payload_len, len - pos);
		/* Not fatal for fuzzing: just note the mismatch */
	}

	return 0;
}

/*
 * fuzz_quic_header_protection - Fuzz QUIC header protection removal
 * @data:	raw bytes (first byte + sample bytes for mask)
 * @len:	length of input
 *
 * Simulates the header protection unmasking: the first byte is XORed
 * with a mask derived from sample bytes.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_quic_header_protection(const u8 *data, size_t len)
{
	u8 first_byte, mask;
	u8 pkt_num_bytes[4];
	int pkt_num_len;
	int i;

	/* Need at least 1 byte (first) + 4 bytes (sample) */
	if (len < 5) {
		pr_debug("fuzz_quic: hp input too short\n");
		return -EINVAL;
	}

	first_byte = data[0];
	/* Mask is first byte of the HP-encrypted sample (simplified) */
	mask = data[1];

	if (first_byte & QUIC_HDR_FORM_LONG)
		first_byte ^= (mask & 0x0F); /* Long header: mask lower 4 bits */
	else
		first_byte ^= (mask & 0x1F); /* Short header: mask lower 5 bits */

	/* Packet number length from unmasked first byte */
	pkt_num_len = (first_byte & 0x03) + 1;

	if (5 + pkt_num_len > (int)len)
		return -EINVAL;

	/* Unmask packet number bytes */
	for (i = 0; i < pkt_num_len; i++)
		pkt_num_bytes[i] = data[5 + i] ^ data[2 + i];

	pr_debug("fuzz_quic: hp unmasked first=0x%02x pn_len=%d\n",
		 first_byte, pkt_num_len);

	(void)pkt_num_bytes;
	return 0;
}

static int __init quic_packet_fuzz_init(void)
{
	u8 *test_buf;
	int ret;

	pr_info("quic_packet_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: varint decode - 1 byte */
	test_buf[0] = 0x25; /* value = 37 */
	ret = fuzz_quic_varint(test_buf, 1);
	pr_info("quic_packet_fuzz: varint 1-byte test returned %d\n", ret);

	/* Self-test 2: varint decode - 2 bytes */
	test_buf[0] = 0x7B; test_buf[1] = 0xBD; /* 0x40|... */
	ret = fuzz_quic_varint(test_buf, 2);
	pr_info("quic_packet_fuzz: varint 2-byte test returned %d\n", ret);

	/* Self-test 3: varint decode - truncated */
	test_buf[0] = 0xC0;
	ret = fuzz_quic_varint(test_buf, 1); /* needs 8 bytes */
	pr_info("quic_packet_fuzz: varint truncated test returned %d\n", ret);

	/* Self-test 4: minimal valid Initial packet */
	{
		size_t pos = 0;

		memset(test_buf, 0, 256);
		test_buf[pos++] = 0xC0; /* long header, Initial, fixed bit */
		/* Version 1 */
		test_buf[pos++] = 0x00;
		test_buf[pos++] = 0x00;
		test_buf[pos++] = 0x00;
		test_buf[pos++] = 0x01;
		/* DCID length = 8 */
		test_buf[pos++] = 8;
		memset(test_buf + pos, 0xAA, 8); pos += 8;
		/* SCID length = 0 */
		test_buf[pos++] = 0;
		/* Token length = 0 (varint) */
		test_buf[pos++] = 0;
		/* Payload length = 10 (varint) */
		test_buf[pos++] = 10;
		/* Payload bytes */
		memset(test_buf + pos, 0xBB, 10); pos += 10;

		ret = fuzz_quic_initial_parse(test_buf, pos);
		pr_info("quic_packet_fuzz: valid Initial test returned %d\n", ret);
	}

	/* Self-test 5: oversized DCID */
	{
		memset(test_buf, 0, 256);
		test_buf[0] = 0xC0;
		test_buf[1] = 0; test_buf[2] = 0; test_buf[3] = 0; test_buf[4] = 1;
		test_buf[5] = 0xFF; /* DCID len = 255, way over max */
		ret = fuzz_quic_initial_parse(test_buf, 10);
		pr_info("quic_packet_fuzz: oversized DCID test returned %d\n", ret);
	}

	/* Self-test 6: header protection */
	memset(test_buf, 0x55, 20);
	ret = fuzz_quic_header_protection(test_buf, 20);
	pr_info("quic_packet_fuzz: header protection test returned %d\n", ret);

	/* Self-test 7: garbage data */
	memset(test_buf, 0xFF, 256);
	ret = fuzz_quic_initial_parse(test_buf, 256);
	pr_info("quic_packet_fuzz: garbage test returned %d\n", ret);

	/* Self-test 8: version negotiation (version = 0) */
	{
		memset(test_buf, 0, 256);
		test_buf[0] = 0xC0;
		/* version = 0 */
		ret = fuzz_quic_initial_parse(test_buf, 7);
		pr_info("quic_packet_fuzz: version negotiation test returned %d\n", ret);
	}

	kfree(test_buf);
	return 0;
}

static void __exit quic_packet_fuzz_exit(void)
{
	pr_info("quic_packet_fuzz: module unloaded\n");
}

module_init(quic_packet_fuzz_init);
module_exit(quic_packet_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for QUIC packet parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
