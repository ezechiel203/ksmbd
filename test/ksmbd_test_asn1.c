// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ASN.1/SPNEGO parsing and construction (asn1.c)
 *
 *   These tests replicate the pure-logic portions of asn1.c (OID decoding,
 *   ASN header length computation, tag encoding) inline, since the functions
 *   are static in the production code.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ── Well-known OID constants (replicated from asn1.c) ─── */

#define SPNEGO_OID_LEN		7
#define NTLMSSP_OID_LEN	10
#define KRB5_OID_LEN		7
#define KRB5U2U_OID_LEN	8
#define MSKRB5_OID_LEN		7

static unsigned long TEST_SPNEGO_OID[7] = { 1, 3, 6, 1, 5, 5, 2 };
static unsigned long TEST_NTLMSSP_OID[10] = { 1, 3, 6, 1, 4, 1, 311, 2, 2, 10 };
static unsigned long TEST_KRB5_OID[7] = { 1, 2, 840, 113554, 1, 2, 2 };
static unsigned long TEST_KRB5U2U_OID[8] = { 1, 2, 840, 113554, 1, 2, 2, 3 };
static unsigned long TEST_MSKRB5_OID[7] = { 1, 2, 840, 48018, 1, 2, 2 };

static char TEST_NTLMSSP_OID_STR[NTLMSSP_OID_LEN] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
};

/* ── Replicated asn1_subid_decode() ─── */

static bool test_asn1_subid_decode(const unsigned char **begin,
				   const unsigned char *end,
				   unsigned long *subid)
{
	const unsigned char *ptr = *begin;
	unsigned char ch;

	*subid = 0;

	do {
		if (ptr >= end)
			return false;

		ch = *ptr++;

		if (*subid >> (sizeof(unsigned long) * 8 - 7))
			return false;

		*subid <<= 7;
		*subid |= ch & 0x7F;
	} while ((ch & 0x80) == 0x80);

	*begin = ptr;
	return true;
}

/* ── Replicated asn1_oid_decode() ─── */

static bool test_asn1_oid_decode(const unsigned char *value, size_t vlen,
				 unsigned long **oid, size_t *oidlen)
{
	const unsigned char *iptr = value, *end = value + vlen;
	unsigned long *optr;
	unsigned long subid;

	vlen += 1;
	if (vlen < 2 || vlen > UINT_MAX / sizeof(unsigned long))
		goto fail_nullify;

	*oid = kmalloc(vlen * sizeof(unsigned long), GFP_KERNEL);
	if (!*oid)
		return false;

	optr = *oid;

	if (!test_asn1_subid_decode(&iptr, end, &subid))
		goto fail;

	if (subid < 40) {
		optr[0] = 0;
		optr[1] = subid;
	} else if (subid < 80) {
		optr[0] = 1;
		optr[1] = subid - 40;
	} else {
		optr[0] = 2;
		optr[1] = subid - 80;
	}

	*oidlen = 2;
	optr += 2;

	while (iptr < end) {
		if (++(*oidlen) > vlen)
			goto fail;

		if (!test_asn1_subid_decode(&iptr, end, optr++))
			goto fail;
	}
	return true;

fail:
	kfree(*oid);
fail_nullify:
	*oid = NULL;
	return false;
}

/* ── Replicated oid_eq() ─── */

static bool test_oid_eq(unsigned long *oid1, unsigned int oid1len,
			unsigned long *oid2, unsigned int oid2len)
{
	if (oid1len != oid2len)
		return false;

	return memcmp(oid1, oid2, oid1len * sizeof(unsigned long)) == 0;
}

/* ── Replicated compute_asn_hdr_len_bytes() ─── */

static int test_compute_asn_hdr_len_bytes(int len)
{
	if (len > 0xFFFFFF)
		return 4;
	else if (len > 0xFFFF)
		return 3;
	else if (len > 0xFF)
		return 2;
	else if (len > 0x7F)
		return 1;
	else
		return 0;
}

/* ── Replicated encode_asn_tag() ─── */

static int test_encode_asn_tag(char *buf, unsigned int *ofs,
			       unsigned int bufsize,
			       char tag, char seq, int length)
{
	int i;
	int index = *ofs;
	char hdr_len = test_compute_asn_hdr_len_bytes(length);
	int len = length + 2 + hdr_len;
	int max_write = 2 + (hdr_len ? 1 + hdr_len : 1) * 2;

	if (index + max_write > bufsize)
		return -EINVAL;

	buf[index++] = tag;

	if (!hdr_len) {
		buf[index++] = len;
	} else {
		buf[index++] = 0x80 | hdr_len;
		for (i = hdr_len - 1; i >= 0; i--)
			buf[index++] = (len >> (i * 8)) & 0xFF;
	}

	len = len - (index - *ofs);
	buf[index++] = seq;

	if (!hdr_len) {
		buf[index++] = len;
	} else {
		buf[index++] = 0x80 | hdr_len;
		for (i = hdr_len - 1; i >= 0; i--)
			buf[index++] = (len >> (i * 8)) & 0xFF;
	}

	*ofs += (index - *ofs);
	return 0;
}

/* ──────────────────────────────────────────────────────────
 * asn1_subid_decode tests
 * ────────────────────────────────────────────────────────── */

static void test_asn1_subid_decode_single_byte(struct kunit *test)
{
	unsigned char data[] = { 0x06 };
	const unsigned char *ptr = data;
	unsigned long subid = 0;

	KUNIT_EXPECT_TRUE(test, test_asn1_subid_decode(&ptr, data + 1, &subid));
	KUNIT_EXPECT_EQ(test, subid, 6UL);
	KUNIT_EXPECT_PTR_EQ(test, ptr, data + 1);
}

static void test_asn1_subid_decode_multi_byte(struct kunit *test)
{
	/* 0x86 0x48 encodes 840: (0x06 << 7) | 0x48 = 6*128 + 72 = 840 */
	unsigned char data[] = { 0x86, 0x48 };
	const unsigned char *ptr = data;
	unsigned long subid = 0;

	KUNIT_EXPECT_TRUE(test, test_asn1_subid_decode(&ptr, data + 2, &subid));
	KUNIT_EXPECT_EQ(test, subid, 840UL);
	KUNIT_EXPECT_PTR_EQ(test, ptr, data + 2);
}

static void test_asn1_subid_decode_overflow(struct kunit *test)
{
	/* Feed many continuation bytes to trigger overflow */
	unsigned char data[20];
	const unsigned char *ptr = data;
	unsigned long subid = 0;
	int i;

	for (i = 0; i < 19; i++)
		data[i] = 0xFF; /* continuation + all bits set */
	data[19] = 0x00; /* terminator */

	KUNIT_EXPECT_FALSE(test, test_asn1_subid_decode(&ptr, data + 20, &subid));
}

static void test_asn1_subid_decode_empty(struct kunit *test)
{
	unsigned char data[] = { 0x00 };
	const unsigned char *ptr = data;
	unsigned long subid = 0;

	/* begin == end -> should fail */
	KUNIT_EXPECT_FALSE(test, test_asn1_subid_decode(&ptr, data, &subid));
}

/* ──────────────────────────────────────────────────────────
 * asn1_oid_decode tests
 * ────────────────────────────────────────────────────────── */

static void test_asn1_oid_decode_spnego(struct kunit *test)
{
	/*
	 * SPNEGO OID 1.3.6.1.5.5.2 encoded in BER:
	 * First two arcs: 1*40+3=43 = 0x2b
	 * Then: 6, 1, 5, 5, 2
	 */
	unsigned char encoded[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
	unsigned long *oid = NULL;
	size_t oidlen = 0;

	KUNIT_ASSERT_TRUE(test, test_asn1_oid_decode(encoded, sizeof(encoded),
						     &oid, &oidlen));
	KUNIT_EXPECT_EQ(test, oidlen, (size_t)SPNEGO_OID_LEN);
	KUNIT_EXPECT_TRUE(test, test_oid_eq(oid, oidlen,
					    TEST_SPNEGO_OID, SPNEGO_OID_LEN));
	kfree(oid);
}

static void test_asn1_oid_decode_ntlmssp(struct kunit *test)
{
	unsigned char encoded[] = {
		0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
	};
	unsigned long *oid = NULL;
	size_t oidlen = 0;

	KUNIT_ASSERT_TRUE(test, test_asn1_oid_decode(encoded, sizeof(encoded),
						     &oid, &oidlen));
	KUNIT_EXPECT_EQ(test, oidlen, (size_t)NTLMSSP_OID_LEN);
	KUNIT_EXPECT_TRUE(test, test_oid_eq(oid, oidlen,
					    TEST_NTLMSSP_OID, NTLMSSP_OID_LEN));
	kfree(oid);
}

static void test_asn1_oid_decode_krb5(struct kunit *test)
{
	/*
	 * KRB5 OID 1.2.840.113554.1.2.2
	 * First two arcs: 1*40+2=42 = 0x2a
	 * 840 = 0x86 0x48
	 * 113554 = 0x86 0xF7 0x12
	 * Then: 1, 2, 2
	 */
	unsigned char encoded[] = {
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
	};
	unsigned long *oid = NULL;
	size_t oidlen = 0;

	KUNIT_ASSERT_TRUE(test, test_asn1_oid_decode(encoded, sizeof(encoded),
						     &oid, &oidlen));
	KUNIT_EXPECT_EQ(test, oidlen, (size_t)KRB5_OID_LEN);
	KUNIT_EXPECT_TRUE(test, test_oid_eq(oid, oidlen,
					    TEST_KRB5_OID, KRB5_OID_LEN));
	kfree(oid);
}

static void test_asn1_oid_decode_empty(struct kunit *test)
{
	unsigned long *oid = NULL;
	size_t oidlen = 0;

	KUNIT_EXPECT_FALSE(test, test_asn1_oid_decode(NULL, 0, &oid, &oidlen));
	KUNIT_EXPECT_NULL(test, oid);
}

static void test_asn1_oid_decode_single_byte(struct kunit *test)
{
	/* Single byte OID encodes two arcs: e.g. 0x2b = 1.3 */
	unsigned char encoded[] = { 0x2b };
	unsigned long *oid = NULL;
	size_t oidlen = 0;

	KUNIT_ASSERT_TRUE(test, test_asn1_oid_decode(encoded, 1, &oid, &oidlen));
	KUNIT_EXPECT_EQ(test, oidlen, (size_t)2);
	KUNIT_EXPECT_EQ(test, oid[0], 1UL);
	KUNIT_EXPECT_EQ(test, oid[1], 3UL);
	kfree(oid);
}

static void test_asn1_oid_decode_too_large(struct kunit *test)
{
	unsigned long *oid = NULL;
	size_t oidlen = 0;
	/* vlen > UINT_MAX / sizeof(unsigned long) should fail */
	size_t huge = UINT_MAX / sizeof(unsigned long) + 1;

	/*
	 * We cannot actually allocate a huge buffer, but the function should
	 * reject it before trying. Pass a valid pointer with huge vlen.
	 */
	unsigned char dummy = 0x2b;

	KUNIT_EXPECT_FALSE(test, test_asn1_oid_decode(&dummy, huge,
						      &oid, &oidlen));
	KUNIT_EXPECT_NULL(test, oid);
}

/* ──────────────────────────────────────────────────────────
 * oid_eq tests
 * ────────────────────────────────────────────────────────── */

static void test_oid_eq_same(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_oid_eq(TEST_SPNEGO_OID, SPNEGO_OID_LEN,
					    TEST_SPNEGO_OID, SPNEGO_OID_LEN));
}

static void test_oid_eq_different_length(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_oid_eq(TEST_SPNEGO_OID, SPNEGO_OID_LEN,
					     TEST_NTLMSSP_OID, NTLMSSP_OID_LEN));
}

static void test_oid_eq_same_length_different_values(struct kunit *test)
{
	/* SPNEGO and KRB5 are both length 7 but different values */
	KUNIT_EXPECT_FALSE(test, test_oid_eq(TEST_SPNEGO_OID, SPNEGO_OID_LEN,
					     TEST_KRB5_OID, KRB5_OID_LEN));
}

/* ──────────────────────────────────────────────────────────
 * compute_asn_hdr_len_bytes tests
 * ────────────────────────────────────────────────────────── */

static void test_asn_hdr_len_short_form(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0), 0);
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(1), 0);
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0x7F), 0);
}

static void test_asn_hdr_len_1byte(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0x80), 1);
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0xFF), 1);
}

static void test_asn_hdr_len_2byte(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0x100), 2);
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0xFFFF), 2);
}

static void test_asn_hdr_len_3byte(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0x10000), 3);
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0xFFFFFF), 3);
}

static void test_asn_hdr_len_4byte(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_compute_asn_hdr_len_bytes(0x1000000), 4);
}

/* ──────────────────────────────────────────────────────────
 * encode_asn_tag tests
 * ────────────────────────────────────────────────────────── */

static void test_encode_asn_tag_short_length(struct kunit *test)
{
	char buf[64];
	unsigned int ofs = 0;
	int ret;

	memset(buf, 0, sizeof(buf));
	ret = test_encode_asn_tag(buf, &ofs, sizeof(buf), 0xa1, 0x30, 10);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, ofs, 0u);
	/* First byte should be the tag */
	KUNIT_EXPECT_EQ(test, (unsigned char)buf[0], (unsigned char)0xa1);
}

static void test_encode_asn_tag_long_length(struct kunit *test)
{
	char buf[256];
	unsigned int ofs = 0;
	int ret;

	memset(buf, 0, sizeof(buf));
	/* Use a length > 0x7F to trigger multi-byte length encoding */
	ret = test_encode_asn_tag(buf, &ofs, sizeof(buf), 0xa1, 0x30, 200);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, ofs, 0u);
	/* Tag byte */
	KUNIT_EXPECT_EQ(test, (unsigned char)buf[0], (unsigned char)0xa1);
	/* Second byte should have high bit set (long form) */
	KUNIT_EXPECT_TRUE(test, (buf[1] & 0x80) != 0);
}

static void test_encode_asn_tag_buffer_overflow(struct kunit *test)
{
	char buf[4]; /* Too small */
	unsigned int ofs = 0;
	int ret;

	ret = test_encode_asn_tag(buf, &ofs, sizeof(buf), 0xa1, 0x30, 100);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ──────────────────────────────────────────────────────────
 * SPNEGO blob construction tests (replicated logic)
 * ────────────────────────────────────────────────────────── */

static int test_build_spnego_ntlmssp_neg_blob(unsigned char **pbuffer,
					      u16 *buflen,
					      char *ntlm_blob,
					      int ntlm_blob_len)
{
	char *buf;
	unsigned int ofs = 0;
	int neg_result_len, oid_len, ntlmssp_len, total_len;

	if (ntlm_blob_len < 0 || ntlm_blob_len > U16_MAX)
		return -EINVAL;

	neg_result_len = 4 + test_compute_asn_hdr_len_bytes(1) * 2 + 1;
	oid_len = 4 + test_compute_asn_hdr_len_bytes(NTLMSSP_OID_LEN) * 2 +
		  NTLMSSP_OID_LEN;
	ntlmssp_len = 4 + test_compute_asn_hdr_len_bytes(ntlm_blob_len) * 2 +
		      ntlm_blob_len;
	total_len = 4 + test_compute_asn_hdr_len_bytes(neg_result_len +
			oid_len + ntlmssp_len) * 2 +
		    neg_result_len + oid_len + ntlmssp_len;

	if (total_len > U16_MAX || total_len < 0)
		return -EINVAL;

	buf = kmalloc(total_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (test_encode_asn_tag(buf, &ofs, total_len, 0xa1, 0x30,
				neg_result_len + oid_len + ntlmssp_len))
		goto err_out;

	if (test_encode_asn_tag(buf, &ofs, total_len, 0xa0, 0x0a, 1))
		goto err_out;
	if (ofs >= total_len)
		goto err_out;
	buf[ofs++] = 1;

	if (test_encode_asn_tag(buf, &ofs, total_len, 0xa1, 0x06,
				NTLMSSP_OID_LEN))
		goto err_out;
	if (ofs + NTLMSSP_OID_LEN > total_len)
		goto err_out;
	memcpy(buf + ofs, TEST_NTLMSSP_OID_STR, NTLMSSP_OID_LEN);
	ofs += NTLMSSP_OID_LEN;

	if (test_encode_asn_tag(buf, &ofs, total_len, 0xa2, 0x04,
				ntlm_blob_len))
		goto err_out;
	if (ofs + ntlm_blob_len > total_len)
		goto err_out;
	memcpy(buf + ofs, ntlm_blob, ntlm_blob_len);
	ofs += ntlm_blob_len;

	*pbuffer = buf;
	*buflen = total_len;
	return 0;

err_out:
	kfree(buf);
	return -EINVAL;
}

static int test_build_spnego_ntlmssp_auth_blob(unsigned char **pbuffer,
					       u16 *buflen, int neg_result)
{
	char *buf;
	unsigned int ofs = 0;
	int neg_result_len = 4 + test_compute_asn_hdr_len_bytes(1) * 2 + 1;
	int total_len = 4 + test_compute_asn_hdr_len_bytes(neg_result_len) * 2 +
		neg_result_len;

	buf = kmalloc(total_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (test_encode_asn_tag(buf, &ofs, total_len, 0xa1, 0x30,
				neg_result_len))
		goto err_free;

	if (test_encode_asn_tag(buf, &ofs, total_len, 0xa0, 0x0a, 1))
		goto err_free;
	if (ofs >= total_len)
		goto err_free;
	if (neg_result)
		buf[ofs++] = 2;
	else
		buf[ofs++] = 0;

	*pbuffer = buf;
	*buflen = total_len;
	return 0;

err_free:
	kfree(buf);
	return -EINVAL;
}

static void test_build_spnego_ntlmssp_neg_blob_basic(struct kunit *test)
{
	unsigned char *buf = NULL;
	u16 buflen = 0;
	char ntlm_blob[] = "NTLMSSP_TEST_DATA";
	int ret;

	ret = test_build_spnego_ntlmssp_neg_blob(&buf, &buflen,
						 ntlm_blob,
						 sizeof(ntlm_blob) - 1);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, buf);
	KUNIT_EXPECT_GT(test, (int)buflen, 0);
	kfree(buf);
}

static void test_build_spnego_ntlmssp_neg_blob_empty_ntlm(struct kunit *test)
{
	unsigned char *buf = NULL;
	u16 buflen = 0;
	int ret;

	ret = test_build_spnego_ntlmssp_neg_blob(&buf, &buflen, "", 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, buf);
	KUNIT_EXPECT_GT(test, (int)buflen, 0);
	kfree(buf);
}

static void test_build_spnego_ntlmssp_neg_blob_negative_len(struct kunit *test)
{
	unsigned char *buf = NULL;
	u16 buflen = 0;
	int ret;

	ret = test_build_spnego_ntlmssp_neg_blob(&buf, &buflen, NULL, -1);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_build_spnego_ntlmssp_neg_blob_max_size(struct kunit *test)
{
	unsigned char *buf = NULL;
	u16 buflen = 0;
	int ret;

	/* U16_MAX+1 should be rejected */
	ret = test_build_spnego_ntlmssp_neg_blob(&buf, &buflen, NULL,
						 U16_MAX + 1);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_build_spnego_ntlmssp_auth_blob_accept(struct kunit *test)
{
	unsigned char *buf = NULL;
	u16 buflen = 0;
	int ret;

	ret = test_build_spnego_ntlmssp_auth_blob(&buf, &buflen, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, buf);
	/* Last byte should be 0 (accept) */
	KUNIT_EXPECT_EQ(test, buf[buflen - 1], (unsigned char)0);
	kfree(buf);
}

static void test_build_spnego_ntlmssp_auth_blob_reject(struct kunit *test)
{
	unsigned char *buf = NULL;
	u16 buflen = 0;
	int ret;

	ret = test_build_spnego_ntlmssp_auth_blob(&buf, &buflen, 1);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, buf);
	/* Last byte should be 2 (reject) */
	KUNIT_EXPECT_EQ(test, buf[buflen - 1], (unsigned char)2);
	kfree(buf);
}

/* ──────────────────────────────────────────────────────────
 * SPNEGO token parsing (mock-based) tests
 *
 * We replicate the logic of ksmbd_neg_token_init_mech_type and
 * ksmbd_neg_token_alloc using a minimal mock conn struct.
 * ────────────────────────────────────────────────────────── */

/* Replicate auth mechanism flags from auth.h */
#define TEST_KSMBD_AUTH_NTLMSSP		0x0001
#define TEST_KSMBD_AUTH_KRB5		0x0002
#define TEST_KSMBD_AUTH_MSKRB5		0x0004
#define TEST_KSMBD_AUTH_KRB5U2U		0x0008

struct test_mock_conn {
	unsigned int	auth_mechs;
	unsigned int	preferred_auth_mech;
	char		*mechToken;
	unsigned int	mechTokenLen;
};

static int test_neg_token_init_mech_type(struct test_mock_conn *conn,
					 const void *value, size_t vlen)
{
	unsigned long *oid;
	size_t oidlen;
	int mech_type;

	if (!test_asn1_oid_decode(value, vlen, &oid, &oidlen))
		goto fail;

	if (test_oid_eq(oid, oidlen, TEST_NTLMSSP_OID, NTLMSSP_OID_LEN))
		mech_type = TEST_KSMBD_AUTH_NTLMSSP;
	else if (test_oid_eq(oid, oidlen, TEST_MSKRB5_OID, MSKRB5_OID_LEN))
		mech_type = TEST_KSMBD_AUTH_MSKRB5;
	else if (test_oid_eq(oid, oidlen, TEST_KRB5_OID, KRB5_OID_LEN))
		mech_type = TEST_KSMBD_AUTH_KRB5;
	else if (test_oid_eq(oid, oidlen, TEST_KRB5U2U_OID, KRB5U2U_OID_LEN))
		mech_type = TEST_KSMBD_AUTH_KRB5U2U;
	else
		goto fail;

	conn->auth_mechs |= mech_type;
	if (conn->preferred_auth_mech == 0)
		conn->preferred_auth_mech = mech_type;

	kfree(oid);
	return 0;

fail:
	kfree(oid);
	return -EBADMSG;
}

static void test_ksmbd_neg_token_init_mech_type_ntlmssp(struct kunit *test)
{
	struct test_mock_conn conn = {};
	unsigned char encoded[] = {
		0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
	};
	int ret;

	ret = test_neg_token_init_mech_type(&conn, encoded, sizeof(encoded));
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, (conn.auth_mechs & TEST_KSMBD_AUTH_NTLMSSP) != 0);
	KUNIT_EXPECT_EQ(test, conn.preferred_auth_mech,
			(unsigned int)TEST_KSMBD_AUTH_NTLMSSP);
}

static void test_ksmbd_neg_token_init_mech_type_krb5(struct kunit *test)
{
	struct test_mock_conn conn = {};
	unsigned char encoded[] = {
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
	};
	int ret;

	ret = test_neg_token_init_mech_type(&conn, encoded, sizeof(encoded));
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, (conn.auth_mechs & TEST_KSMBD_AUTH_KRB5) != 0);
}

static void test_ksmbd_neg_token_init_mech_type_mskrb5(struct kunit *test)
{
	struct test_mock_conn conn = {};
	/*
	 * MSKRB5 OID 1.2.840.48018.1.2.2
	 * First two arcs: 1*40+2=42 = 0x2a
	 * 840 = 0x86 0x48
	 * 48018 = 0x82 0xF7 0x12 -> actually 48018 encoded differently
	 * Let's use the actual encoded bytes from production:
	 * 48018 in base-128: 48018 / 128 = 375 rem 18
	 * 375 / 128 = 2 rem 119
	 * So: 0x82, 0xF7, 0x12 -- wait, that's 113554 not 48018
	 * 48018: 48018 / 128 = 375.14 -> 375 rem 18
	 *   375 / 128 = 2 rem 119
	 *   So: 0x82 (2|0x80), 0xF7 (119|0x80)... no, 119 < 128 so no cont
	 * Actually: 48018 in base-128: 48018 = 2*128^2 + 119*128 + 18
	 *   = 0x82 0x77 0x12 -> but 119 = 0x77 and no high bit needed?
	 * Wait: high byte: 2 -> 0x82 (continuation), mid: 119 -> 0xF7 (cont), low: 18 -> 0x12
	 * Let me recalculate: 48018 in 7-bit chunks:
	 *   48018 & 0x7F = 18 = 0x12
	 *   48018 >> 7 = 375; 375 & 0x7F = 119 = 0x77
	 *   375 >> 7 = 2; 2 & 0x7F = 2
	 * So encoded: 0x82, 0xF7, 0x12 (0x82 = 2|0x80, 0xF7 = 119|0x80, 0x12)
	 * Hmm that gives: (2 << 14) | (119 << 7) | 18 = 32768 + 15232 + 18 = 48018 - correct!
	 */
	unsigned char encoded[] = {
		0x2a, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02
	};
	int ret;

	ret = test_neg_token_init_mech_type(&conn, encoded, sizeof(encoded));
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, (conn.auth_mechs & TEST_KSMBD_AUTH_MSKRB5) != 0);
}

static void test_ksmbd_neg_token_init_mech_type_unknown(struct kunit *test)
{
	struct test_mock_conn conn = {};
	/* Some random OID that doesn't match any known auth mech */
	unsigned char encoded[] = { 0x55, 0x04, 0x03 }; /* 2.5.4.3 */
	int ret;

	ret = test_neg_token_init_mech_type(&conn, encoded, sizeof(encoded));
	KUNIT_EXPECT_EQ(test, ret, -EBADMSG);
	KUNIT_EXPECT_EQ(test, conn.auth_mechs, 0u);
}

/* ── mechToken allocation tests ─── */

static int test_neg_token_alloc(struct test_mock_conn *conn,
				const void *value, size_t vlen)
{
	if (!vlen)
		return -EINVAL;

	kfree(conn->mechToken);
	conn->mechToken = kmemdup_nul(value, vlen, GFP_KERNEL);
	if (!conn->mechToken)
		return -ENOMEM;

	conn->mechTokenLen = (unsigned int)vlen;
	return 0;
}

static void test_ksmbd_neg_token_init_mech_token_alloc(struct kunit *test)
{
	struct test_mock_conn conn = {};
	char token[] = "test_token_data";
	int ret;

	ret = test_neg_token_alloc(&conn, token, sizeof(token) - 1);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, conn.mechToken);
	KUNIT_EXPECT_EQ(test, conn.mechTokenLen,
			(unsigned int)(sizeof(token) - 1));
	KUNIT_EXPECT_MEMEQ(test, conn.mechToken, token, sizeof(token) - 1);
	kfree(conn.mechToken);
}

static void test_ksmbd_neg_token_init_mech_token_empty(struct kunit *test)
{
	struct test_mock_conn conn = {};
	int ret;

	ret = test_neg_token_alloc(&conn, "", 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_ksmbd_neg_token_init_mech_token_replaces(struct kunit *test)
{
	struct test_mock_conn conn = {};
	char token1[] = "first_token";
	char token2[] = "second_token_longer";
	int ret;

	ret = test_neg_token_alloc(&conn, token1, sizeof(token1) - 1);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = test_neg_token_alloc(&conn, token2, sizeof(token2) - 1);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, conn.mechTokenLen,
			(unsigned int)(sizeof(token2) - 1));
	KUNIT_EXPECT_MEMEQ(test, conn.mechToken, token2, sizeof(token2) - 1);
	kfree(conn.mechToken);
}

/* ── gssapi_this_mech tests ─── */

static int test_gssapi_this_mech(const void *value, size_t vlen)
{
	unsigned long *oid;
	size_t oidlen;
	int err = 0;

	if (!test_asn1_oid_decode(value, vlen, &oid, &oidlen)) {
		err = -EBADMSG;
		goto out;
	}

	if (!test_oid_eq(oid, oidlen, TEST_SPNEGO_OID, SPNEGO_OID_LEN))
		err = -EBADMSG;
	kfree(oid);
out:
	return err;
}

static void test_ksmbd_gssapi_this_mech_valid(struct kunit *test)
{
	unsigned char encoded[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

	KUNIT_EXPECT_EQ(test, test_gssapi_this_mech(encoded, sizeof(encoded)), 0);
}

static void test_ksmbd_gssapi_this_mech_invalid(struct kunit *test)
{
	/* KRB5 OID - not SPNEGO */
	unsigned char encoded[] = {
		0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
	};

	KUNIT_EXPECT_EQ(test, test_gssapi_this_mech(encoded, sizeof(encoded)),
			-EBADMSG);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_asn1_test_cases[] = {
	/* asn1_subid_decode */
	KUNIT_CASE(test_asn1_subid_decode_single_byte),
	KUNIT_CASE(test_asn1_subid_decode_multi_byte),
	KUNIT_CASE(test_asn1_subid_decode_overflow),
	KUNIT_CASE(test_asn1_subid_decode_empty),
	/* asn1_oid_decode */
	KUNIT_CASE(test_asn1_oid_decode_spnego),
	KUNIT_CASE(test_asn1_oid_decode_ntlmssp),
	KUNIT_CASE(test_asn1_oid_decode_krb5),
	KUNIT_CASE(test_asn1_oid_decode_empty),
	KUNIT_CASE(test_asn1_oid_decode_single_byte),
	KUNIT_CASE(test_asn1_oid_decode_too_large),
	/* oid_eq */
	KUNIT_CASE(test_oid_eq_same),
	KUNIT_CASE(test_oid_eq_different_length),
	KUNIT_CASE(test_oid_eq_same_length_different_values),
	/* compute_asn_hdr_len_bytes */
	KUNIT_CASE(test_asn_hdr_len_short_form),
	KUNIT_CASE(test_asn_hdr_len_1byte),
	KUNIT_CASE(test_asn_hdr_len_2byte),
	KUNIT_CASE(test_asn_hdr_len_3byte),
	KUNIT_CASE(test_asn_hdr_len_4byte),
	/* encode_asn_tag */
	KUNIT_CASE(test_encode_asn_tag_short_length),
	KUNIT_CASE(test_encode_asn_tag_long_length),
	KUNIT_CASE(test_encode_asn_tag_buffer_overflow),
	/* SPNEGO blob construction */
	KUNIT_CASE(test_build_spnego_ntlmssp_neg_blob_basic),
	KUNIT_CASE(test_build_spnego_ntlmssp_neg_blob_empty_ntlm),
	KUNIT_CASE(test_build_spnego_ntlmssp_neg_blob_negative_len),
	KUNIT_CASE(test_build_spnego_ntlmssp_neg_blob_max_size),
	KUNIT_CASE(test_build_spnego_ntlmssp_auth_blob_accept),
	KUNIT_CASE(test_build_spnego_ntlmssp_auth_blob_reject),
	/* SPNEGO token parsing */
	KUNIT_CASE(test_ksmbd_gssapi_this_mech_valid),
	KUNIT_CASE(test_ksmbd_gssapi_this_mech_invalid),
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_type_ntlmssp),
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_type_krb5),
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_type_mskrb5),
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_type_unknown),
	/* mechToken allocation */
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_token_alloc),
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_token_empty),
	KUNIT_CASE(test_ksmbd_neg_token_init_mech_token_replaces),
	{}
};

static struct kunit_suite ksmbd_asn1_test_suite = {
	.name = "ksmbd_asn1",
	.test_cases = ksmbd_asn1_test_cases,
};

kunit_test_suite(ksmbd_asn1_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd ASN.1/SPNEGO parsing");
