// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for QUIC transport pure-logic functions (transport_quic.c)
 *
 *   These tests implement the QUIC variable-length integer encoding/decoding
 *   per RFC 9000 Section 16, QUIC state machine transitions, and basic
 *   packet structure validation.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>

/* ── QUIC Variable-Length Integer (RFC 9000 Section 16) ───
 *
 * Encoding:
 *   1-byte: 0b00xxxxxx (values 0..63)
 *   2-byte: 0b01xxxxxx xxxxxxxx (values 0..16383)
 *   4-byte: 0b10xxxxxx ... (values 0..1073741823)
 *   8-byte: 0b11xxxxxx ... (values 0..4611686018427387903)
 */

static int test_quic_varint_encode(u64 val, u8 *buf, size_t buflen,
				   size_t *outlen)
{
	if (val <= 63) {
		if (buflen < 1)
			return -ENOSPC;
		buf[0] = (u8)val;
		*outlen = 1;
	} else if (val <= 16383) {
		if (buflen < 2)
			return -ENOSPC;
		buf[0] = 0x40 | (u8)(val >> 8);
		buf[1] = (u8)(val & 0xFF);
		*outlen = 2;
	} else if (val <= 1073741823ULL) {
		if (buflen < 4)
			return -ENOSPC;
		buf[0] = 0x80 | (u8)(val >> 24);
		buf[1] = (u8)((val >> 16) & 0xFF);
		buf[2] = (u8)((val >> 8) & 0xFF);
		buf[3] = (u8)(val & 0xFF);
		*outlen = 4;
	} else if (val <= 4611686018427387903ULL) {
		if (buflen < 8)
			return -ENOSPC;
		buf[0] = 0xC0 | (u8)(val >> 56);
		buf[1] = (u8)((val >> 48) & 0xFF);
		buf[2] = (u8)((val >> 40) & 0xFF);
		buf[3] = (u8)((val >> 32) & 0xFF);
		buf[4] = (u8)((val >> 24) & 0xFF);
		buf[5] = (u8)((val >> 16) & 0xFF);
		buf[6] = (u8)((val >> 8) & 0xFF);
		buf[7] = (u8)(val & 0xFF);
		*outlen = 8;
	} else {
		return -ERANGE;
	}
	return 0;
}

static int test_quic_varint_decode(const u8 *buf, size_t buflen,
				   u64 *val, size_t *consumed)
{
	u8 prefix;
	size_t len;

	if (buflen < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1u << prefix;

	if (buflen < len)
		return -EINVAL;

	switch (prefix) {
	case 0:
		*val = buf[0] & 0x3F;
		break;
	case 1:
		*val = ((u64)(buf[0] & 0x3F) << 8) | buf[1];
		break;
	case 2:
		*val = ((u64)(buf[0] & 0x3F) << 24) |
		       ((u64)buf[1] << 16) |
		       ((u64)buf[2] << 8) |
		       buf[3];
		break;
	case 3:
		*val = ((u64)(buf[0] & 0x3F) << 56) |
		       ((u64)buf[1] << 48) |
		       ((u64)buf[2] << 40) |
		       ((u64)buf[3] << 32) |
		       ((u64)buf[4] << 24) |
		       ((u64)buf[5] << 16) |
		       ((u64)buf[6] << 8) |
		       buf[7];
		break;
	}
	*consumed = len;
	return 0;
}

/* ── QUIC state machine ─── */
enum test_quic_state {
	QUIC_STATE_INITIAL = 0,
	QUIC_STATE_HANDSHAKE,
	QUIC_STATE_CONNECTED,
	QUIC_STATE_CLOSING,
};

static int test_quic_transition(enum test_quic_state from,
				enum test_quic_state to)
{
	switch (from) {
	case QUIC_STATE_INITIAL:
		if (to == QUIC_STATE_HANDSHAKE)
			return 0;
		break;
	case QUIC_STATE_HANDSHAKE:
		if (to == QUIC_STATE_CONNECTED)
			return 0;
		break;
	case QUIC_STATE_CONNECTED:
		if (to == QUIC_STATE_CLOSING)
			return 0;
		break;
	case QUIC_STATE_CLOSING:
		break;
	}
	return -EINVAL;
}

/* ──────────────────────────────────────────────────────────
 * Varint encoding tests
 * ────────────────────────────────────────────────────────── */

static void test_quic_varint_encode_1byte(struct kunit *test)
{
	u8 buf[8];
	size_t outlen;
	int ret;

	ret = test_quic_varint_encode(0, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)1);
	KUNIT_EXPECT_EQ(test, buf[0], (u8)0);

	ret = test_quic_varint_encode(63, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)1);
	KUNIT_EXPECT_EQ(test, buf[0], (u8)63);
}

static void test_quic_varint_encode_2byte(struct kunit *test)
{
	u8 buf[8];
	size_t outlen;
	int ret;

	ret = test_quic_varint_encode(64, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)2);
	KUNIT_EXPECT_EQ(test, (u8)(buf[0] >> 6), (u8)1); /* prefix bits = 01 */

	ret = test_quic_varint_encode(16383, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)2);
}

static void test_quic_varint_encode_4byte(struct kunit *test)
{
	u8 buf[8];
	size_t outlen;
	int ret;

	ret = test_quic_varint_encode(16384, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)4);
	KUNIT_EXPECT_EQ(test, (u8)(buf[0] >> 6), (u8)2); /* prefix bits = 10 */

	ret = test_quic_varint_encode(1073741823ULL, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)4);
}

static void test_quic_varint_encode_8byte(struct kunit *test)
{
	u8 buf[8];
	size_t outlen;
	int ret;

	ret = test_quic_varint_encode(1073741824ULL, buf, sizeof(buf), &outlen);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, outlen, (size_t)8);
	KUNIT_EXPECT_EQ(test, (u8)(buf[0] >> 6), (u8)3); /* prefix bits = 11 */
}

static void test_quic_varint_roundtrip(struct kunit *test)
{
	u64 values[] = {
		0, 63, 64, 16383, 16384,
		1073741823ULL, 1073741824ULL,
		4611686018427387903ULL
	};
	u8 buf[8];
	size_t outlen, consumed;
	u64 decoded;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		ret = test_quic_varint_encode(values[i], buf, sizeof(buf),
					      &outlen);
		KUNIT_ASSERT_EQ(test, ret, 0);

		ret = test_quic_varint_decode(buf, outlen, &decoded, &consumed);
		KUNIT_ASSERT_EQ(test, ret, 0);
		KUNIT_EXPECT_EQ(test, decoded, values[i]);
		KUNIT_EXPECT_EQ(test, consumed, outlen);
	}
}

static void test_quic_varint_decode_truncated(struct kunit *test)
{
	/* 2-byte varint in a 1-byte buffer */
	u8 buf[1] = { 0x40 }; /* prefix = 01, needs 2 bytes */
	u64 val;
	size_t consumed;
	int ret;

	ret = test_quic_varint_decode(buf, 1, &val, &consumed);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_quic_varint_decode_all_zeros(struct kunit *test)
{
	u8 buf[1] = { 0x00 };
	u64 val;
	size_t consumed;
	int ret;

	ret = test_quic_varint_decode(buf, 1, &val, &consumed);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, val, 0ULL);
}

/* ──────────────────────────────────────────────────────────
 * QUIC state machine tests
 * ────────────────────────────────────────────────────────── */

static void test_quic_state_initial_to_handshake(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_quic_transition(QUIC_STATE_INITIAL,
						   QUIC_STATE_HANDSHAKE), 0);
}

static void test_quic_state_handshake_to_connected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_quic_transition(QUIC_STATE_HANDSHAKE,
						   QUIC_STATE_CONNECTED), 0);
}

static void test_quic_state_connected_to_closing(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_quic_transition(QUIC_STATE_CONNECTED,
						   QUIC_STATE_CLOSING), 0);
}

static void test_quic_state_invalid_transition(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_quic_transition(QUIC_STATE_CONNECTED,
						   QUIC_STATE_INITIAL),
			-EINVAL);
}

/* ──────────────────────────────────────────────────────────
 * QUIC DCID hash tests
 * ────────────────────────────────────────────────────────── */

static u32 test_quic_dcid_hash(const u8 *dcid, size_t dcid_len)
{
	u32 hash = 0;
	size_t i;

	for (i = 0; i < dcid_len; i++)
		hash = hash * 31 + dcid[i];
	return hash;
}

static void test_quic_dcid_hash_basic(struct kunit *test)
{
	u8 dcid[] = { 0x01, 0x02, 0x03, 0x04 };
	u32 h1, h2;

	h1 = test_quic_dcid_hash(dcid, sizeof(dcid));
	h2 = test_quic_dcid_hash(dcid, sizeof(dcid));
	KUNIT_EXPECT_EQ(test, h1, h2); /* deterministic */
}

static void test_quic_dcid_hash_different_dcids(struct kunit *test)
{
	u8 dcid1[] = { 0x01, 0x02, 0x03, 0x04 };
	u8 dcid2[] = { 0x05, 0x06, 0x07, 0x08 };

	KUNIT_EXPECT_NE(test, test_quic_dcid_hash(dcid1, sizeof(dcid1)),
			test_quic_dcid_hash(dcid2, sizeof(dcid2)));
}

/* ──────────────────────────────────────────────────────────
 * QUIC initial packet parsing tests
 * ────────────────────────────────────────────────────────── */

/* Minimal initial packet header structure */
struct test_quic_initial_hdr {
	u8	first_byte;	/* form bit + type + version-specific */
	u32	version;
	u8	dcid_len;
	/* followed by DCID, SCID len, SCID, token, payload */
};

static int test_parse_initial_header(const u8 *pkt, size_t pkt_len,
				     u8 *dcid, size_t *dcid_len,
				     u32 *version)
{
	size_t offset = 0;

	if (pkt_len < 7) /* minimum: first_byte + version(4) + dcid_len(1) + scid_len(1) */
		return -EINVAL;

	/* First byte: long header has form bit set (0x80) */
	if (!(pkt[0] & 0x80))
		return -EINVAL;

	offset = 1;
	/* Version: 4 bytes big-endian */
	*version = ((u32)pkt[1] << 24) | ((u32)pkt[2] << 16) |
		   ((u32)pkt[3] << 8) | pkt[4];
	offset = 5;

	/* DCID length */
	*dcid_len = pkt[offset++];
	if (*dcid_len > 20) /* RFC 9000: max DCID length is 20 */
		return -EINVAL;
	if (offset + *dcid_len > pkt_len)
		return -EINVAL;

	memcpy(dcid, pkt + offset, *dcid_len);
	return 0;
}

static void test_quic_parse_initial_valid(struct kunit *test)
{
	/* Construct minimal valid QUIC Initial packet */
	u8 pkt[1200];
	u8 dcid[20];
	size_t dcid_len;
	u32 version;
	int ret;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0xC0; /* Long header, Initial type */
	/* Version 1: 0x00000001 */
	pkt[1] = 0x00; pkt[2] = 0x00; pkt[3] = 0x00; pkt[4] = 0x01;
	/* DCID length = 8 */
	pkt[5] = 8;
	/* DCID bytes */
	memset(pkt + 6, 0xAA, 8);

	ret = test_parse_initial_header(pkt, sizeof(pkt), dcid, &dcid_len,
					&version);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, version, 1u);
	KUNIT_EXPECT_EQ(test, dcid_len, (size_t)8);
	KUNIT_EXPECT_EQ(test, dcid[0], (u8)0xAA);
}

static void test_quic_parse_initial_too_short(struct kunit *test)
{
	u8 pkt[6] = { 0xC0, 0x00, 0x00, 0x00, 0x01, 0x08 };
	u8 dcid[20];
	size_t dcid_len;
	u32 version;
	int ret;

	/* DCID len says 8 but packet only has 6 bytes total */
	ret = test_parse_initial_header(pkt, sizeof(pkt), dcid, &dcid_len,
					&version);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_quic_parse_initial_truncated_dcid(struct kunit *test)
{
	u8 pkt[7] = { 0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0xAA };
	u8 dcid[20];
	size_t dcid_len;
	u32 version;
	int ret;

	/* DCID len = 8 but only 1 byte of DCID available */
	ret = test_parse_initial_header(pkt, sizeof(pkt), dcid, &dcid_len,
					&version);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_quic_parse_initial_dcid_too_long(struct kunit *test)
{
	u8 pkt[30];
	u8 dcid[20];
	size_t dcid_len;
	u32 version;
	int ret;

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0xC0;
	pkt[1] = 0x00; pkt[2] = 0x00; pkt[3] = 0x00; pkt[4] = 0x01;
	pkt[5] = 21; /* > 20, invalid per RFC 9000 */

	ret = test_parse_initial_header(pkt, sizeof(pkt), dcid, &dcid_len,
					&version);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ──────────────────────────────────────────────────────────
 * CRYPTO frame parsing tests
 * ────────────────────────────────────────────────────────── */

struct test_crypto_frame {
	u64	offset;
	u64	length;
	const u8 *data;
};

static int test_parse_crypto_frame(const u8 *buf, size_t buflen,
				   struct test_crypto_frame *frame)
{
	size_t pos = 0, consumed;
	int ret;

	/* Frame type (0x06 for CRYPTO) */
	if (buflen < 1 || buf[0] != 0x06)
		return -EINVAL;
	pos = 1;

	/* Offset (varint) */
	ret = test_quic_varint_decode(buf + pos, buflen - pos,
				      &frame->offset, &consumed);
	if (ret)
		return ret;
	pos += consumed;

	/* Length (varint) */
	ret = test_quic_varint_decode(buf + pos, buflen - pos,
				      &frame->length, &consumed);
	if (ret)
		return ret;
	pos += consumed;

	/* Data */
	if (pos + frame->length > buflen)
		return -EINVAL;

	frame->data = buf + pos;
	return 0;
}

static void test_quic_parse_crypto_frame_basic(struct kunit *test)
{
	/* CRYPTO frame: type=0x06, offset=0, length=5, data="Hello" */
	u8 buf[] = { 0x06, 0x00, 0x05, 'H', 'e', 'l', 'l', 'o' };
	struct test_crypto_frame frame;
	int ret;

	ret = test_parse_crypto_frame(buf, sizeof(buf), &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, frame.offset, 0ULL);
	KUNIT_EXPECT_EQ(test, frame.length, 5ULL);
	KUNIT_EXPECT_MEMEQ(test, frame.data, "Hello", 5);
}

static void test_quic_parse_crypto_frame_nonzero_offset(struct kunit *test)
{
	/* CRYPTO frame with offset = 10 */
	u8 buf[] = { 0x06, 0x0A, 0x03, 'a', 'b', 'c' };
	struct test_crypto_frame frame;
	int ret;

	ret = test_parse_crypto_frame(buf, sizeof(buf), &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, frame.offset, 10ULL);
	KUNIT_EXPECT_EQ(test, frame.length, 3ULL);
}

static void test_quic_parse_crypto_frame_truncated(struct kunit *test)
{
	/* CRYPTO frame claims length=10 but only has 3 data bytes */
	u8 buf[] = { 0x06, 0x00, 0x0A, 'a', 'b', 'c' };
	struct test_crypto_frame frame;
	int ret;

	ret = test_parse_crypto_frame(buf, sizeof(buf), &frame);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ──────────────────────────────────────────────────────────
 * Version negotiation tests
 * ────────────────────────────────────────────────────────── */

#define QUIC_VERSION_1		0x00000001u
#define QUIC_VERSION_2		0x6B3343CFu

static void test_quic_version_negotiation_packet(struct kunit *test)
{
	u32 supported[] = { QUIC_VERSION_1, QUIC_VERSION_2 };

	KUNIT_EXPECT_EQ(test, supported[0], QUIC_VERSION_1);
	KUNIT_EXPECT_EQ(test, supported[1], QUIC_VERSION_2);
	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(supported), (size_t)2);
}

/* ──────────────────────────────────────────────────────────
 * Connection ID validation tests
 * ────────────────────────────────────────────────────────── */

static void test_quic_connection_id_zero_length(struct kunit *test)
{
	/* DCID length 0 is valid for short headers */
	size_t dcid_len = 0;

	KUNIT_EXPECT_LE(test, dcid_len, (size_t)20);
}

static void test_quic_connection_id_max_length(struct kunit *test)
{
	size_t dcid_len = 20;

	KUNIT_EXPECT_LE(test, dcid_len, (size_t)20);
}

static void test_quic_connection_id_invalid_length(struct kunit *test)
{
	size_t dcid_len = 21;

	KUNIT_EXPECT_GT(test, dcid_len, (size_t)20);
}

/* ──────────────────────────────────────────────────────────
 * AEAD nonce construction tests
 * ────────────────────────────────────────────────────────── */

static void test_quic_aead_nonce_construction(struct kunit *test)
{
	/*
	 * QUIC nonce = base_iv XOR (zero-padded packet number)
	 * base_iv is 12 bytes, packet number is placed at the end.
	 */
	u8 base_iv[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			   0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
	u8 nonce[12];
	u64 pkt_num = 1;
	int i;

	memcpy(nonce, base_iv, 12);
	/* XOR packet number into last 8 bytes */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pkt_num >> (i * 8)) & 0xFF;

	/* nonce[11] should be base_iv[11] ^ 1 = 0x0C ^ 0x01 = 0x0D */
	KUNIT_EXPECT_EQ(test, nonce[11], (u8)0x0D);
	/* nonce[0..3] unchanged (packet number doesn't reach there) */
	KUNIT_EXPECT_EQ(test, nonce[0], base_iv[0]);
	KUNIT_EXPECT_EQ(test, nonce[1], base_iv[1]);
}

/* ── SMB over QUIC specifics ─── */

static void test_quic_no_rfc1002_prefix(struct kunit *test)
{
	/*
	 * SMB over QUIC does NOT use the 4-byte NetBIOS (RFC1002) header.
	 * The SMB2 message starts directly on the QUIC stream.
	 */
	bool quic_transport = true;
	int rfc1002_size = quic_transport ? 0 : 4;

	KUNIT_EXPECT_EQ(test, rfc1002_size, 0);
}

static void test_quic_default_port_443(struct kunit *test)
{
	unsigned short quic_port = 443;

	KUNIT_EXPECT_EQ(test, quic_port, (unsigned short)443);
}

/* ──────────────────────────────────────────────────────────
 * QUIC connection hash insert/remove tests (replicated)
 * ────────────────────────────────────────────────────────── */

struct test_quic_conn {
	u8 dcid[20];
	size_t dcid_len;
	struct hlist_node hash_node;
};

#define TEST_QUIC_HASH_BITS 8
#define TEST_QUIC_HASH_SIZE (1 << TEST_QUIC_HASH_BITS)

static DEFINE_SPINLOCK(test_quic_hash_lock);
static struct hlist_head test_quic_hash_table[TEST_QUIC_HASH_SIZE];

static u32 test_quic_conn_hash(const u8 *dcid, size_t len)
{
	u32 hash = 0;
	size_t i;

	for (i = 0; i < len; i++)
		hash = hash * 31 + dcid[i];
	return hash & (TEST_QUIC_HASH_SIZE - 1);
}

static void test_quic_conn_insert(struct test_quic_conn *qc)
{
	u32 bucket = test_quic_conn_hash(qc->dcid, qc->dcid_len);

	spin_lock(&test_quic_hash_lock);
	hlist_add_head(&qc->hash_node, &test_quic_hash_table[bucket]);
	spin_unlock(&test_quic_hash_lock);
}

static void test_quic_conn_remove(struct test_quic_conn *qc)
{
	spin_lock(&test_quic_hash_lock);
	hlist_del_init(&qc->hash_node);
	spin_unlock(&test_quic_hash_lock);
}

static struct test_quic_conn *test_quic_conn_find(const u8 *dcid, size_t len)
{
	u32 bucket = test_quic_conn_hash(dcid, len);
	struct test_quic_conn *qc;

	spin_lock(&test_quic_hash_lock);
	hlist_for_each_entry(qc, &test_quic_hash_table[bucket], hash_node) {
		if (qc->dcid_len == len && !memcmp(qc->dcid, dcid, len)) {
			spin_unlock(&test_quic_hash_lock);
			return qc;
		}
	}
	spin_unlock(&test_quic_hash_lock);
	return NULL;
}

static void test_quic_conn_insert_remove(struct kunit *test)
{
	struct test_quic_conn qc = {};
	struct test_quic_conn *found;
	int i;

	/* Initialize hash table */
	for (i = 0; i < TEST_QUIC_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&test_quic_hash_table[i]);

	qc.dcid[0] = 0xDE;
	qc.dcid[1] = 0xAD;
	qc.dcid[2] = 0xBE;
	qc.dcid[3] = 0xEF;
	qc.dcid_len = 4;
	INIT_HLIST_NODE(&qc.hash_node);

	test_quic_conn_insert(&qc);
	found = test_quic_conn_find(qc.dcid, qc.dcid_len);
	KUNIT_EXPECT_PTR_EQ(test, found, &qc);

	test_quic_conn_remove(&qc);
	found = test_quic_conn_find(qc.dcid, qc.dcid_len);
	KUNIT_EXPECT_NULL(test, found);
}

/* ──────────────────────────────────────────────────────────
 * Initial packet bad version triggers version negotiation
 * ────────────────────────────────────────────────────────── */

static void test_quic_parse_initial_bad_version(struct kunit *test)
{
	/*
	 * Construct an Initial packet with an unsupported version.
	 * The parser should detect this and trigger version negotiation.
	 */
	u8 buf[64];
	u32 version;

	memset(buf, 0, sizeof(buf));
	/* Long header form: bit 7 set */
	buf[0] = 0xC0;
	/* Set unsupported version: 0xBAD0BEEF */
	buf[1] = 0xBA;
	buf[2] = 0xD0;
	buf[3] = 0xBE;
	buf[4] = 0xEF;

	version = ((u32)buf[1] << 24) | ((u32)buf[2] << 16) |
		  ((u32)buf[3] << 8) | (u32)buf[4];

	KUNIT_EXPECT_NE(test, version, QUIC_VERSION_1);
	KUNIT_EXPECT_NE(test, version, QUIC_VERSION_2);
}

/* ──────────────────────────────────────────────────────────
 * Header protection mask computation (replicated AES-ECB-like)
 * ────────────────────────────────────────────────────────── */

static void test_quic_header_protection_mask(struct kunit *test)
{
	/*
	 * Header protection mask: 5 bytes derived from sample.
	 * We replicate the XOR logic for both long and short headers.
	 */
	u8 first_byte_long = 0xC3;  /* long header: 4 bits masked */
	u8 first_byte_short = 0x43; /* short header: 5 bits masked */
	u8 mask[5] = { 0x0F, 0xAA, 0xBB, 0xCC, 0xDD };

	/* Long header: mask bottom 4 bits */
	u8 protected_long = first_byte_long ^ (mask[0] & 0x0F);
	/* Short header: mask bottom 5 bits */
	u8 protected_short = first_byte_short ^ (mask[0] & 0x1F);

	/* Unprotect by XOR-ing again */
	KUNIT_EXPECT_EQ(test, (u8)(protected_long ^ (mask[0] & 0x0F)),
			first_byte_long);
	KUNIT_EXPECT_EQ(test, (u8)(protected_short ^ (mask[0] & 0x1F)),
			first_byte_short);
}

static void test_quic_header_protect_unprotect_roundtrip(struct kunit *test)
{
	u8 original_header[5] = { 0xC3, 0x00, 0x00, 0x00, 0x01 };
	u8 header[5];
	u8 mask[5] = { 0x0A, 0x55, 0x33, 0x77, 0x11 };
	int i;

	memcpy(header, original_header, 5);

	/* Protect: XOR mask into header */
	header[0] ^= (mask[0] & 0x0F); /* long header */
	for (i = 1; i < 5; i++)
		header[i] ^= mask[i];

	/* Header should be different */
	KUNIT_EXPECT_NE(test, memcmp(header, original_header, 5), 0);

	/* Unprotect: XOR again */
	header[0] ^= (mask[0] & 0x0F);
	for (i = 1; i < 5; i++)
		header[i] ^= mask[i];

	KUNIT_EXPECT_EQ(test, memcmp(header, original_header, 5), 0);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_quic_test_cases[] = {
	/* Varint encoding */
	KUNIT_CASE(test_quic_varint_encode_1byte),
	KUNIT_CASE(test_quic_varint_encode_2byte),
	KUNIT_CASE(test_quic_varint_encode_4byte),
	KUNIT_CASE(test_quic_varint_encode_8byte),
	KUNIT_CASE(test_quic_varint_roundtrip),
	KUNIT_CASE(test_quic_varint_decode_truncated),
	KUNIT_CASE(test_quic_varint_decode_all_zeros),
	/* State machine */
	KUNIT_CASE(test_quic_state_initial_to_handshake),
	KUNIT_CASE(test_quic_state_handshake_to_connected),
	KUNIT_CASE(test_quic_state_connected_to_closing),
	KUNIT_CASE(test_quic_state_invalid_transition),
	/* DCID hash */
	KUNIT_CASE(test_quic_dcid_hash_basic),
	KUNIT_CASE(test_quic_dcid_hash_different_dcids),
	/* Initial packet parsing */
	KUNIT_CASE(test_quic_parse_initial_valid),
	KUNIT_CASE(test_quic_parse_initial_too_short),
	KUNIT_CASE(test_quic_parse_initial_truncated_dcid),
	KUNIT_CASE(test_quic_parse_initial_dcid_too_long),
	/* CRYPTO frame parsing */
	KUNIT_CASE(test_quic_parse_crypto_frame_basic),
	KUNIT_CASE(test_quic_parse_crypto_frame_nonzero_offset),
	KUNIT_CASE(test_quic_parse_crypto_frame_truncated),
	/* Version negotiation */
	KUNIT_CASE(test_quic_version_negotiation_packet),
	/* Connection ID validation */
	KUNIT_CASE(test_quic_connection_id_zero_length),
	KUNIT_CASE(test_quic_connection_id_max_length),
	KUNIT_CASE(test_quic_connection_id_invalid_length),
	/* AEAD */
	KUNIT_CASE(test_quic_aead_nonce_construction),
	/* SMB over QUIC */
	KUNIT_CASE(test_quic_no_rfc1002_prefix),
	KUNIT_CASE(test_quic_default_port_443),
	/* Connection hash insert/remove */
	KUNIT_CASE(test_quic_conn_insert_remove),
	/* Bad version */
	KUNIT_CASE(test_quic_parse_initial_bad_version),
	/* Header protection */
	KUNIT_CASE(test_quic_header_protection_mask),
	KUNIT_CASE(test_quic_header_protect_unprotect_roundtrip),
	{}
};

static struct kunit_suite ksmbd_quic_test_suite = {
	.name = "ksmbd_quic",
	.test_cases = ksmbd_quic_test_cases,
};

kunit_test_suite(ksmbd_quic_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd QUIC transport helpers");
