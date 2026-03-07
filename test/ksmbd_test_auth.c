// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for authentication helpers (auth.c)
 *
 *   These tests call real production functions exported via
 *   VISIBLE_IF_KUNIT: cifs_arc4_setkey(), cifs_arc4_crypt(),
 *   and ksmbd_copy_gss_neg_header(), as well as public API
 *   functions for NTLMSSP blob parsing, PDU signing, and
 *   key derivation.
 */

#include <kunit/test.h>
#include <kunit/visibility.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "auth.h"
#include "ntlmssp.h"
#include "connection.h"
#include "smb2pdu.h"
#include "smb_common.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/* ====================================================================
 * Helper: build a minimal ksmbd_conn for NTLMSSP tests
 * ====================================================================
 */
static struct ksmbd_conn *alloc_test_conn(struct kunit *test)
{
	struct ksmbd_conn *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);
	conn->local_nls = load_nls("utf8");
	if (!conn->local_nls)
		conn->local_nls = load_nls_default();
	return conn;
}

static void free_test_conn(struct ksmbd_conn *conn)
{
	if (conn->local_nls)
		unload_nls(conn->local_nls);
}

/* ====================================================================
 * Section 1: ksmbd_copy_gss_neg_header() tests (existing 4 tests)
 * ====================================================================
 */

static void test_gss_header_copy_matches(struct kunit *test)
{
	static const char expected[AUTH_GSS_LENGTH] = {
		0x60, 0x5e, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x02, 0xa0, 0x54, 0x30, 0x52, 0xa0, 0x24,
		0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2a,
		0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
		0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28,
		0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f,
		0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,
		0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31,
		0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,
		0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65
	};
	char *buf;

	buf = kzalloc(AUTH_GSS_LENGTH, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	ksmbd_copy_gss_neg_header(buf);
	KUNIT_EXPECT_EQ(test, memcmp(buf, expected, AUTH_GSS_LENGTH), 0);

	kfree(buf);
}

static void test_gss_header_starts_with_asn1_sequence(struct kunit *test)
{
	char buf[AUTH_GSS_LENGTH];

	ksmbd_copy_gss_neg_header(buf);
	KUNIT_EXPECT_EQ(test, (unsigned char)buf[0], (unsigned char)0x60);
}

static void test_gss_header_contains_spnego_oid(struct kunit *test)
{
	char buf[AUTH_GSS_LENGTH];
	static const unsigned char spnego_oid[] = {
		0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02
	};

	ksmbd_copy_gss_neg_header(buf);
	KUNIT_EXPECT_EQ(test, memcmp(buf + 2, spnego_oid, sizeof(spnego_oid)), 0);
}

static void test_gss_header_length(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, AUTH_GSS_LENGTH, 96);
}

/* ====================================================================
 * Section 2: ARC4 cipher tests (existing 4 tests)
 * ====================================================================
 */

static void test_arc4_roundtrip(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
	u8 plain[32];
	u8 cipher[32];
	u8 decrypt[32];
	int i, rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	for (i = 0; i < 32; i++)
		plain[i] = (u8)i;

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher, plain, sizeof(plain));

	KUNIT_EXPECT_NE(test, memcmp(plain, cipher, sizeof(plain)), 0);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, decrypt, cipher, sizeof(cipher));

	KUNIT_EXPECT_EQ(test, memcmp(plain, decrypt, sizeof(plain)), 0);
}

static void test_arc4_zero_length(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
	u8 out[1] = { 0x42 };
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);

	cifs_arc4_crypt(ctx, out, out, 0);
	KUNIT_EXPECT_EQ(test, out[0], (u8)0x42);
}

static void test_arc4_deterministic(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[8] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	u8 plain[16] = { 0 };
	u8 cipher1[16], cipher2[16];
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher1, plain, sizeof(plain));

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher2, plain, sizeof(plain));

	KUNIT_EXPECT_EQ(test, memcmp(cipher1, cipher2, sizeof(cipher1)), 0);
}

static void test_arc4_min_key_size(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key = 0xFF;
	u8 plain[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	u8 cipher[8];
	u8 decrypt[8];
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = cifs_arc4_setkey(ctx, &key, 1);
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher, plain, sizeof(plain));

	rc = cifs_arc4_setkey(ctx, &key, 1);
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, decrypt, cipher, sizeof(cipher));

	KUNIT_EXPECT_EQ(test, memcmp(plain, decrypt, sizeof(plain)), 0);
}

/* ====================================================================
 * Section 3: ARC4 additional coverage
 * ====================================================================
 */

/*
 * test_arc4_rfc6229_key_40bit - Verify ARC4 against known test vector.
 *
 * RFC 6229 provides test vectors for RC4/ARC4. Using key = {0x01..0x05}
 * (40-bit key) and encrypting 8 zero bytes, verify the first 8 bytes of
 * the keystream match the RFC 6229 expected output.
 */
static void test_arc4_rfc6229_key_40bit(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
	u8 plain[16] = { 0 };
	u8 cipher[16];
	/*
	 * RFC 6229 Section 2 - Key = 01 02 03 04 05 (40-bit):
	 * First 16 output bytes:
	 * b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8
	 */
	static const u8 expected[16] = {
		0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27,
		0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8
	};
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher, plain, sizeof(plain));

	KUNIT_EXPECT_EQ(test, memcmp(cipher, expected, sizeof(expected)), 0);
}

/*
 * test_arc4_max_key_size - ARC4 with 256-byte key should roundtrip.
 */
static void test_arc4_max_key_size(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[ARC4_MAX_KEY_SIZE];
	u8 plain[64];
	u8 cipher[64];
	u8 decrypt[64];
	int i, rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	for (i = 0; i < 256; i++)
		key[i] = (u8)i;
	for (i = 0; i < 64; i++)
		plain[i] = (u8)(i ^ 0xAA);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher, plain, sizeof(plain));

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, decrypt, cipher, sizeof(cipher));

	KUNIT_EXPECT_EQ(test, memcmp(plain, decrypt, sizeof(plain)), 0);
}

/*
 * test_arc4_in_place - ARC4 with src == dst (in-place encryption).
 */
static void test_arc4_in_place(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
	u8 data[16];
	u8 original[16];
	int i, rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	for (i = 0; i < 16; i++) {
		data[i] = (u8)i;
		original[i] = (u8)i;
	}

	/* Encrypt in place */
	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, data, data, sizeof(data));
	KUNIT_EXPECT_NE(test, memcmp(data, original, sizeof(data)), 0);

	/* Decrypt in place */
	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, data, data, sizeof(data));
	KUNIT_EXPECT_EQ(test, memcmp(data, original, sizeof(data)), 0);
}

/* ====================================================================
 * Section 4: NTLMSSP negotiate blob parsing
 * ====================================================================
 */

/*
 * test_ntlmssp_neg_valid - A well-formed NEGOTIATE_MESSAGE is accepted.
 */
static void test_ntlmssp_neg_valid(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	int rc;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, "NTLMSSP", 8);
	neg.MessageType = NtLmNegotiate;
	neg.NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_UNICODE |
					 NTLMSSP_NEGOTIATE_NTLM |
					 NTLMSSP_NEGOTIATE_SIGN);

	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, sizeof(neg), conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Verify flags were stored on the connection */
	KUNIT_EXPECT_TRUE(test, (conn->ntlmssp.client_flags &
				 NTLMSSP_NEGOTIATE_UNICODE) != 0);
	KUNIT_EXPECT_TRUE(test, (conn->ntlmssp.client_flags &
				 NTLMSSP_NEGOTIATE_NTLM) != 0);
	KUNIT_EXPECT_TRUE(test, (conn->ntlmssp.client_flags &
				 NTLMSSP_NEGOTIATE_SIGN) != 0);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_neg_too_short - Blob smaller than negotiate_message is rejected.
 */
static void test_ntlmssp_neg_too_short(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	int rc;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, "NTLMSSP", 8);
	neg.MessageType = NtLmNegotiate;

	/* Pass blob_len too small */
	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, sizeof(neg) - 1, conn);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_neg_zero_length - Zero-length blob is rejected.
 */
static void test_ntlmssp_neg_zero_length(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	int rc;

	memset(&neg, 0, sizeof(neg));
	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, 0, conn);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_neg_wrong_signature - Non-NTLMSSP signature is rejected.
 */
static void test_ntlmssp_neg_wrong_signature(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	int rc;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, "BADSIGGX", 8);
	neg.MessageType = NtLmNegotiate;
	neg.NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_UNICODE);

	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, sizeof(neg), conn);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_neg_all_flags - All negotiate flags are preserved.
 */
static void test_ntlmssp_neg_all_flags(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	__u32 flags;
	int rc;

	flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL |
		NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56 |
		NTLMSSP_NEGOTIATE_KEY_XCH | NTLMSSP_NEGOTIATE_EXTENDED_SEC |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_REQUEST_TARGET;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, "NTLMSSP", 8);
	neg.MessageType = NtLmNegotiate;
	neg.NegotiateFlags = cpu_to_le32(flags);

	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, sizeof(neg), conn);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, conn->ntlmssp.client_flags, flags);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_neg_exact_minimum_size - Blob exactly at minimum is accepted.
 */
static void test_ntlmssp_neg_exact_minimum_size(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	int rc;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, "NTLMSSP", 8);
	neg.MessageType = NtLmNegotiate;
	neg.NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);

	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, sizeof(neg), conn);
	KUNIT_EXPECT_EQ(test, rc, 0);

	free_test_conn(conn);
}

/* ====================================================================
 * Section 5: NTLMSSP authenticate blob parsing
 * ====================================================================
 */

/*
 * test_ntlmssp_auth_too_short - Auth blob smaller than header is rejected.
 */
static void test_ntlmssp_auth_too_short(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "NTLMSSP", 8);
	auth.MessageType = NtLmAuthenticate;

	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth) - 1,
					     conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_wrong_signature - Bad signature in auth blob is rejected.
 */
static void test_ntlmssp_auth_wrong_signature(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "XXXXXXXX", 8);
	auth.MessageType = NtLmAuthenticate;

	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_anonymous - Anonymous auth (zero-length NtChallengeResponse
 * + NTLMSSP_ANONYMOUS flag) succeeds with rc=0.
 */
static void test_ntlmssp_auth_anonymous(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "NTLMSSP", 8);
	auth.MessageType = NtLmAuthenticate;

	/* NtChallengeResponse length = 0, offset can be anything valid */
	auth.NtChallengeResponse.Length = cpu_to_le16(0);
	auth.NtChallengeResponse.MaximumLength = cpu_to_le16(0);
	auth.NtChallengeResponse.BufferOffset = cpu_to_le32(sizeof(auth));

	/* DomainName length = 0 */
	auth.DomainName.Length = cpu_to_le16(0);
	auth.DomainName.MaximumLength = cpu_to_le16(0);
	auth.DomainName.BufferOffset = cpu_to_le32(sizeof(auth));

	/* Set NTLMSSP_ANONYMOUS flag */
	auth.NegotiateFlags = cpu_to_le32(NTLMSSP_ANONYMOUS);

	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, 0);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_anonymous_without_flag - Zero-length NtChallengeResponse
 * without NTLMSSP_ANONYMOUS flag set should not be treated as anonymous
 * (nt_len < CIFS_ENCPWD_SIZE check catches it).
 */
static void test_ntlmssp_auth_anonymous_without_flag(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "NTLMSSP", 8);
	auth.MessageType = NtLmAuthenticate;

	auth.NtChallengeResponse.Length = cpu_to_le16(0);
	auth.NtChallengeResponse.MaximumLength = cpu_to_le16(0);
	auth.NtChallengeResponse.BufferOffset = cpu_to_le32(sizeof(auth));
	auth.DomainName.Length = cpu_to_le16(0);
	auth.DomainName.MaximumLength = cpu_to_le16(0);
	auth.DomainName.BufferOffset = cpu_to_le32(sizeof(auth));

	/* No NTLMSSP_ANONYMOUS flag: nt_len=0 < CIFS_ENCPWD_SIZE -> EINVAL */
	auth.NegotiateFlags = cpu_to_le32(0);

	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_nt_offset_overflow - NtChallengeResponse offset + length
 * exceeding blob_len is rejected.
 */
static void test_ntlmssp_auth_nt_offset_overflow(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "NTLMSSP", 8);
	auth.MessageType = NtLmAuthenticate;

	/* Set NtChallengeResponse offset to point beyond blob */
	auth.NtChallengeResponse.Length = cpu_to_le16(24);
	auth.NtChallengeResponse.MaximumLength = cpu_to_le16(24);
	auth.NtChallengeResponse.BufferOffset = cpu_to_le32(sizeof(auth));

	auth.DomainName.Length = cpu_to_le16(0);
	auth.DomainName.MaximumLength = cpu_to_le16(0);
	auth.DomainName.BufferOffset = cpu_to_le32(sizeof(auth));

	/* blob_len = sizeof(auth), so offset(sizeof(auth)) + len(24) > sizeof(auth) */
	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_domain_offset_overflow - DomainName offset + length
 * exceeding blob_len is rejected.
 */
static void test_ntlmssp_auth_domain_offset_overflow(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	/*
	 * Use a larger buffer so we can place NtChallengeResponse inside
	 * but have DomainName point outside.
	 */
	u8 buf[256];
	struct authenticate_message *auth = (struct authenticate_message *)buf;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(buf, 0, sizeof(buf));
	memcpy(auth->Signature, "NTLMSSP", 8);
	auth->MessageType = NtLmAuthenticate;

	/* NtChallengeResponse: small valid region but still needs ENCPWD_SIZE */
	auth->NtChallengeResponse.Length = cpu_to_le16(0);
	auth->NtChallengeResponse.MaximumLength = cpu_to_le16(0);
	auth->NtChallengeResponse.BufferOffset = cpu_to_le32(sizeof(*auth));

	/* DomainName: offset + length overflow */
	auth->DomainName.Length = cpu_to_le16(200);
	auth->DomainName.MaximumLength = cpu_to_le16(200);
	auth->DomainName.BufferOffset = cpu_to_le32(200);

	/* NTLMSSP_ANONYMOUS with nt_len=0 would succeed before checking domain,
	 * so omit the flag to force domain offset check path
	 */
	auth->NegotiateFlags = cpu_to_le32(0);

	/* nt_len=0 without anonymous => EINVAL (from nt_len < CIFS_ENCPWD_SIZE) */
	rc = ksmbd_decode_ntlmssp_auth_blob(auth, sizeof(buf), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_nt_len_too_small - NtChallengeResponse length smaller
 * than CIFS_ENCPWD_SIZE (16 bytes) is rejected (unless anonymous).
 */
static void test_ntlmssp_auth_nt_len_too_small(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	u8 buf[256];
	struct authenticate_message *auth = (struct authenticate_message *)buf;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(buf, 0, sizeof(buf));
	memcpy(auth->Signature, "NTLMSSP", 8);
	auth->MessageType = NtLmAuthenticate;

	/* NtChallengeResponse length = 8 (less than CIFS_ENCPWD_SIZE = 16) */
	auth->NtChallengeResponse.Length = cpu_to_le16(8);
	auth->NtChallengeResponse.MaximumLength = cpu_to_le16(8);
	auth->NtChallengeResponse.BufferOffset = cpu_to_le32(sizeof(*auth));

	auth->DomainName.Length = cpu_to_le16(0);
	auth->DomainName.MaximumLength = cpu_to_le16(0);
	auth->DomainName.BufferOffset = cpu_to_le32(sizeof(*auth));

	auth->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);

	rc = ksmbd_decode_ntlmssp_auth_blob(auth, sizeof(buf), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/* ====================================================================
 * Section 6: GSS header additional validation
 * ====================================================================
 */

/*
 * test_gss_header_contains_kerberos_oid - The GSS header includes
 * the Kerberos 5 OID (1.2.840.113554.1.2.2).
 */
static void test_gss_header_contains_kerberos_oid(struct kunit *test)
{
	char buf[AUTH_GSS_LENGTH];
	/* OID 1.2.840.113554.1.2.2 encoded as: 06 09 2a 86 48 86 f7 12 01 02 02 */
	static const u8 krb5_oid[] = {
		0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x12, 0x01, 0x02, 0x02
	};
	bool found = false;
	int i;

	ksmbd_copy_gss_neg_header(buf);

	for (i = 0; i <= AUTH_GSS_LENGTH - (int)sizeof(krb5_oid); i++) {
		if (memcmp(buf + i, krb5_oid, sizeof(krb5_oid)) == 0) {
			found = true;
			break;
		}
	}
	KUNIT_EXPECT_TRUE(test, found);
}

/*
 * test_gss_header_contains_ntlmssp_oid - The GSS header includes
 * the NTLMSSP OID (1.3.6.1.4.1.311.2.2.10).
 */
static void test_gss_header_contains_ntlmssp_oid(struct kunit *test)
{
	char buf[AUTH_GSS_LENGTH];
	/* OID 1.3.6.1.4.1.311.2.2.10 => 06 0a 2b 06 01 04 01 82 37 02 02 0a */
	static const u8 ntlmssp_oid[] = {
		0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
	};
	bool found = false;
	int i;

	ksmbd_copy_gss_neg_header(buf);

	for (i = 0; i <= AUTH_GSS_LENGTH - (int)sizeof(ntlmssp_oid); i++) {
		if (memcmp(buf + i, ntlmssp_oid, sizeof(ntlmssp_oid)) == 0) {
			found = true;
			break;
		}
	}
	KUNIT_EXPECT_TRUE(test, found);
}

/*
 * test_gss_header_idempotent - Calling ksmbd_copy_gss_neg_header twice
 * into different buffers yields identical output.
 */
static void test_gss_header_idempotent(struct kunit *test)
{
	char buf1[AUTH_GSS_LENGTH];
	char buf2[AUTH_GSS_LENGTH];

	ksmbd_copy_gss_neg_header(buf1);
	ksmbd_copy_gss_neg_header(buf2);

	KUNIT_EXPECT_EQ(test, memcmp(buf1, buf2, AUTH_GSS_LENGTH), 0);
}

/*
 * test_gss_header_contains_hint_string - The GSS header includes
 * "not_defined_in_RFC4178@please_ignore" (36 bytes at offset 60).
 */
static void test_gss_header_contains_hint_string(struct kunit *test)
{
	char buf[AUTH_GSS_LENGTH];
	static const char hint[] = "not_defined_in_RFC4178@please_ignore";

	ksmbd_copy_gss_neg_header(buf);

	/*
	 * The hint string is at offset 60 (0x3c) in the GSS header,
	 * spanning to the end (offset 96 = 60 + 36).
	 */
	KUNIT_EXPECT_EQ(test,
			memcmp(buf + 60, hint, sizeof(hint) - 1), 0);
}

/* ====================================================================
 * Section 7: NTLMSSP structure size constants validation
 * ====================================================================
 */

/*
 * test_ntlmssp_constants - Verify NTLMSSP-related size constants.
 */
static void test_ntlmssp_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, CIFS_CRYPTO_KEY_SIZE, 8);
	KUNIT_EXPECT_EQ(test, CIFS_ENCPWD_SIZE, 16);
	KUNIT_EXPECT_EQ(test, CIFS_KEY_SIZE, 40);
	KUNIT_EXPECT_EQ(test, CIFS_AUTH_RESP_SIZE, 24);
	KUNIT_EXPECT_EQ(test, CIFS_HMAC_MD5_HASH_SIZE, 16);
	KUNIT_EXPECT_EQ(test, CIFS_NTHASH_SIZE, 16);
	KUNIT_EXPECT_EQ(test, CIFS_SMB1_SIGNATURE_SIZE, 8);
	KUNIT_EXPECT_EQ(test, CIFS_SMB1_SESSKEY_SIZE, 16);
	KUNIT_EXPECT_EQ(test, AUTH_GSS_PADDING, 0);
}

/*
 * test_smb2_key_size_constants - Verify SMB2/3 key size constants.
 */
static void test_smb2_key_size_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_NTLMV2_SESSKEY_SIZE, 16);
	KUNIT_EXPECT_EQ(test, SMB2_SIGNATURE_SIZE, 16);
	KUNIT_EXPECT_EQ(test, SMB2_HMACSHA256_SIZE, 32);
	KUNIT_EXPECT_EQ(test, SMB2_CMACAES_SIZE, 16);
	KUNIT_EXPECT_EQ(test, SMB3_SIGN_KEY_SIZE, 16);
	KUNIT_EXPECT_EQ(test, SMB3_ENC_DEC_KEY_SIZE, 32);
}

/* ====================================================================
 * Section 8: NTLMSSP message type constants
 * ====================================================================
 */

/*
 * test_ntlmssp_message_types - Verify NTLMSSP message type encodings.
 */
static void test_ntlmssp_message_types(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(NtLmNegotiate), (u32)1);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(NtLmChallenge), (u32)2);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(NtLmAuthenticate), (u32)3);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(UnknownMessage), (u32)8);
}

/*
 * test_ntlmssp_signature_string - Verify the NTLMSSP signature constant.
 */
static void test_ntlmssp_signature_string(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, strlen(NTLMSSP_SIGNATURE), (size_t)7);
	KUNIT_EXPECT_EQ(test, memcmp(NTLMSSP_SIGNATURE, "NTLMSSP", 7), 0);
	/* The signature is 8 bytes including NUL terminator */
	KUNIT_EXPECT_EQ(test, sizeof(NTLMSSP_SIGNATURE), (size_t)8);
}

/* ====================================================================
 * Section 9: NTLMSSP negotiate flag bit positions
 * ====================================================================
 */

/*
 * test_ntlmssp_flag_bits - Verify flag bit positions match MS-NLMP spec.
 */
static void test_ntlmssp_flag_bits(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_UNICODE, (u32)0x01);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_OEM, (u32)0x02);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_REQUEST_TARGET, (u32)0x04);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_SIGN, (u32)0x0010);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_SEAL, (u32)0x0020);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_LM_KEY, (u32)0x0080);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_NTLM, (u32)0x0200);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_ANONYMOUS, (u32)0x0800);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_EXTENDED_SEC, (u32)0x80000);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_128, (u32)0x20000000);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_KEY_XCH, (u32)0x40000000);
	KUNIT_EXPECT_EQ(test, (u32)NTLMSSP_NEGOTIATE_56, (u32)0x80000000);
}

/* ====================================================================
 * Section 10: NTLMSSP structure layout validation
 * ====================================================================
 */

/*
 * test_negotiate_message_struct_size - negotiate_message is packed correctly.
 */
static void test_negotiate_message_struct_size(struct kunit *test)
{
	/*
	 * negotiate_message has:
	 *   Signature[8] + MessageType(4) + NegotiateFlags(4) +
	 *   DomainName(security_buffer=8) + WorkstationName(security_buffer=8)
	 *   = 32 bytes (plus flexible array DomainString[])
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct negotiate_message), 32);
}

/*
 * test_authenticate_message_struct_size - authenticate_message is packed correctly.
 */
static void test_authenticate_message_struct_size(struct kunit *test)
{
	/*
	 * authenticate_message has:
	 *   Signature[8] + MessageType(4) +
	 *   LmChallengeResponse(8) + NtChallengeResponse(8) +
	 *   DomainName(8) + UserName(8) + WorkstationName(8) +
	 *   SessionKey(8) + NegotiateFlags(4)
	 *   = 8 + 4 + 6*8 + 4 = 64 bytes (plus flexible array UserString[])
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct authenticate_message), 64);
}

/*
 * test_challenge_message_struct_size - challenge_message is packed correctly.
 */
static void test_challenge_message_struct_size(struct kunit *test)
{
	/*
	 * challenge_message has:
	 *   Signature[8] + MessageType(4) + TargetName(8) +
	 *   NegotiateFlags(4) + Challenge[8] + Reserved[8] +
	 *   TargetInfoArray(8)
	 *   = 48 bytes
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct challenge_message), 48);
}

/*
 * test_security_buffer_struct_size - security_buffer is 8 bytes (packed).
 */
static void test_security_buffer_struct_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct security_buffer), 8);
}

/*
 * test_ntlmv2_resp_struct_size - ntlmv2_resp is packed correctly.
 */
static void test_ntlmv2_resp_struct_size(struct kunit *test)
{
	/*
	 * ntlmv2_resp has:
	 *   ntlmv2_hash[16] + blob_signature(4) + reserved(4) +
	 *   time(8) + client_chal(8) + reserved2(4)
	 *   = 44 bytes
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct ntlmv2_resp), 44);
}

/*
 * test_ntlmssp_auth_struct_size - ntlmssp_auth is packed correctly.
 */
static void test_ntlmssp_auth_struct_size(struct kunit *test)
{
	/*
	 * ntlmssp_auth has:
	 *   sesskey_per_smbsess(bool) + 3 padding + client_flags(4) +
	 *   conn_flags(4) + ciphertext[16] + cryptkey[8]
	 *   The exact size depends on alignment and packing.
	 */
	KUNIT_EXPECT_TRUE(test, sizeof(struct ntlmssp_auth) >= 33);
}

/* ====================================================================
 * Section 11: ARC4 context structure
 * ====================================================================
 */

/*
 * test_arc4_ctx_struct - Verify arc4_ctx has expected layout.
 */
static void test_arc4_ctx_struct(struct kunit *test)
{
	struct arc4_ctx ctx;

	/* S-box is 256 u32 entries */
	KUNIT_EXPECT_EQ(test, (int)sizeof(ctx.S), (int)(256 * sizeof(u32)));
	/* x and y are u32 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(ctx.x), (int)sizeof(u32));
	KUNIT_EXPECT_EQ(test, (int)sizeof(ctx.y), (int)sizeof(u32));
}

/*
 * test_arc4_key_size_constants - Verify ARC4 key size constants.
 */
static void test_arc4_key_size_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ARC4_MIN_KEY_SIZE, 1);
	KUNIT_EXPECT_EQ(test, ARC4_MAX_KEY_SIZE, 256);
	KUNIT_EXPECT_EQ(test, ARC4_BLOCK_SIZE, 1);
}

/* ====================================================================
 * Section 12: ARC4 keystream behavior
 * ====================================================================
 */

/*
 * test_arc4_different_keys_different_output - Different keys produce
 * different ciphertexts for the same plaintext.
 */
static void test_arc4_different_keys_different_output(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key1[16], key2[16];
	u8 plain[32] = { 0 };
	u8 cipher1[32], cipher2[32];
	int i, rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	for (i = 0; i < 16; i++) {
		key1[i] = (u8)i;
		key2[i] = (u8)(i + 0x80);
	}

	rc = cifs_arc4_setkey(ctx, key1, sizeof(key1));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher1, plain, sizeof(plain));

	rc = cifs_arc4_setkey(ctx, key2, sizeof(key2));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, cipher2, plain, sizeof(plain));

	KUNIT_EXPECT_NE(test, memcmp(cipher1, cipher2, sizeof(cipher1)), 0);
}

/*
 * test_arc4_single_byte - ARC4 encrypts/decrypts a single byte correctly.
 */
static void test_arc4_single_byte(struct kunit *test)
{
	struct arc4_ctx *ctx;
	u8 key[4] = { 0x12, 0x34, 0x56, 0x78 };
	u8 plain = 0xAA;
	u8 cipher, decrypt;
	int rc;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, &cipher, &plain, 1);

	rc = cifs_arc4_setkey(ctx, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, rc, 0);
	cifs_arc4_crypt(ctx, &decrypt, &cipher, 1);

	KUNIT_EXPECT_EQ(test, decrypt, plain);
}

/* ====================================================================
 * Section 13: NTLMSSP auth blob with malformed NTLMv2 blob
 * ====================================================================
 */

/*
 * test_ntlmssp_auth_ntlmv2_blob_no_avpair_eol - NTLMv2 auth blob with
 * NtChallengeResponse that has a CLIENT_CHALLENGE but missing MsvAvEOL
 * terminator in the AvPairs list should be rejected.
 */
static void test_ntlmssp_auth_ntlmv2_blob_no_avpair_eol(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	int rc;

	/*
	 * Build a buffer large enough for authenticate_message header +
	 * NtChallengeResponse containing ntlmv2_resp + some AvPairs without EOL.
	 *
	 * ntlmv2_resp is 44 bytes. The total NtChallengeResponse includes:
	 *   16 bytes NTProofStr (the ntlmv2_hash field) +
	 *   28 bytes CLIENT_CHALLENGE header (rest of ntlmv2_resp) +
	 *   AvPair data (with no MsvAvEOL)
	 *
	 * CIFS_ENCPWD_SIZE = 16, so nt_len must be >= 16.
	 * The blen (nt_len - 16) must have room for CLIENT_CHALLENGE + AvPairs.
	 */
	int nt_off = sizeof(struct authenticate_message);
	int nt_len = sizeof(struct ntlmv2_resp) + 8; /* 44 + 8 = 52 bytes */
	int total_buf = nt_off + nt_len;
	u8 *buf;
	struct authenticate_message *auth;
	u8 *nt_data;

	buf = kunit_kzalloc(test, total_buf, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	memset(&sess, 0, sizeof(sess));
	auth = (struct authenticate_message *)buf;
	memcpy(auth->Signature, "NTLMSSP", 8);
	auth->MessageType = NtLmAuthenticate;
	auth->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);

	auth->NtChallengeResponse.Length = cpu_to_le16(nt_len);
	auth->NtChallengeResponse.MaximumLength = cpu_to_le16(nt_len);
	auth->NtChallengeResponse.BufferOffset = cpu_to_le32(nt_off);

	auth->DomainName.Length = cpu_to_le16(0);
	auth->DomainName.MaximumLength = cpu_to_le16(0);
	auth->DomainName.BufferOffset = cpu_to_le32(nt_off);

	/*
	 * Fill the NtChallengeResponse data with non-zero values.
	 * The AvPairs area (after ntlmv2_resp - CIFS_ENCPWD_SIZE offset)
	 * has non-zero bytes that don't form a valid MsvAvEOL terminator.
	 */
	nt_data = buf + nt_off;
	memset(nt_data, 0x41, nt_len);

	/* Put avpair_off area with garbage (no EOL) */
	/* avpair_off = sizeof(ntlmv2_resp) - CIFS_ENCPWD_SIZE = 44 - 16 = 28 */
	/* At position 28 in bstart we need AvPairs but no MsvAvEOL */
	/* Write a non-zero AvId at the AvPairs start position */
	{
		__le16 av_id = cpu_to_le16(0x0001); /* non-EOL */
		__le16 av_len = cpu_to_le16(4);
		int avpair_pos = CIFS_ENCPWD_SIZE + (sizeof(struct ntlmv2_resp) -
						     CIFS_ENCPWD_SIZE);

		if (avpair_pos + 8 <= nt_len) {
			memcpy(nt_data + avpair_pos, &av_id, 2);
			memcpy(nt_data + avpair_pos + 2, &av_len, 2);
			/* av_len=4 means 4 bytes of content follow, but
			 * pos would advance to avpair_pos + 8, then no
			 * more room for another 4-byte header = no EOL found
			 */
		}
	}

	rc = ksmbd_decode_ntlmssp_auth_blob(auth, total_buf, conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_ntlmv2_blob_too_small_for_avpairs - NTLMv2 blob
 * that is exactly CIFS_ENCPWD_SIZE + avpair_off but too small for any
 * AvPair header (4 bytes minimum) should be rejected.
 */
static void test_ntlmssp_auth_ntlmv2_blob_too_small_for_avpairs(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	int rc;

	/*
	 * nt_len must be >= CIFS_ENCPWD_SIZE (16) to pass initial check.
	 * blen = nt_len - 16. avpair_off = sizeof(ntlmv2_resp) - 16 = 28.
	 * If blen < avpair_off + 4 = 32, we get "too small for AvPairs".
	 * So nt_len = 16 + 31 = 47 should trigger this.
	 */
	int nt_off = sizeof(struct authenticate_message);
	int nt_len = CIFS_ENCPWD_SIZE + 31; /* 47: blen=31 < 32 */
	int total_buf = nt_off + nt_len;
	u8 *buf;
	struct authenticate_message *auth;

	buf = kunit_kzalloc(test, total_buf, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	memset(&sess, 0, sizeof(sess));
	auth = (struct authenticate_message *)buf;
	memcpy(auth->Signature, "NTLMSSP", 8);
	auth->MessageType = NtLmAuthenticate;
	auth->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);

	auth->NtChallengeResponse.Length = cpu_to_le16(nt_len);
	auth->NtChallengeResponse.MaximumLength = cpu_to_le16(nt_len);
	auth->NtChallengeResponse.BufferOffset = cpu_to_le32(nt_off);

	auth->DomainName.Length = cpu_to_le16(0);
	auth->DomainName.MaximumLength = cpu_to_le16(0);
	auth->DomainName.BufferOffset = cpu_to_le32(nt_off);

	memset(buf + nt_off, 0, nt_len);

	rc = ksmbd_decode_ntlmssp_auth_blob(auth, total_buf, conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/* ====================================================================
 * Section 14: AV pair field type enum validation
 * ====================================================================
 */

/*
 * test_av_field_types - Verify AvPair field type enum values match MS-NLMP.
 */
static void test_av_field_types(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_EOL, 0);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_NB_COMPUTER_NAME, 1);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_NB_DOMAIN_NAME, 2);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_DNS_COMPUTER_NAME, 3);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_DNS_DOMAIN_NAME, 4);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_DNS_TREE_NAME, 5);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_FLAGS, 6);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_TIMESTAMP, 7);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_RESTRICTION, 8);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_TARGET_NAME, 9);
	KUNIT_EXPECT_EQ(test, (int)NTLMSSP_AV_CHANNEL_BINDINGS, 10);
}

/* ====================================================================
 * Section 15: Auth mechanism type flags
 * ====================================================================
 */

/*
 * test_auth_mechanism_flags - Verify KSMBD_AUTH_* flag bit values.
 */
static void test_auth_mechanism_flags(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_AUTH_NTLMSSP, 0x0001);
	KUNIT_EXPECT_EQ(test, KSMBD_AUTH_KRB5, 0x0002);
	KUNIT_EXPECT_EQ(test, KSMBD_AUTH_MSKRB5, 0x0004);
	KUNIT_EXPECT_EQ(test, KSMBD_AUTH_KRB5U2U, 0x0008);

	/* Flags should be non-overlapping */
	KUNIT_EXPECT_EQ(test,
			KSMBD_AUTH_NTLMSSP & KSMBD_AUTH_KRB5, 0);
	KUNIT_EXPECT_EQ(test,
			KSMBD_AUTH_KRB5 & KSMBD_AUTH_MSKRB5, 0);
	KUNIT_EXPECT_EQ(test,
			KSMBD_AUTH_MSKRB5 & KSMBD_AUTH_KRB5U2U, 0);
}

/* ====================================================================
 * Section 16: NTLMSSP negotiate with domain/workstation supplied flags
 * ====================================================================
 */

/*
 * test_ntlmssp_neg_domain_supplied - DOMAIN_SUPPLIED flag is stored.
 */
static void test_ntlmssp_neg_domain_supplied(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct negotiate_message neg;
	int rc;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, "NTLMSSP", 8);
	neg.MessageType = NtLmNegotiate;
	neg.NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_UNICODE |
					 NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED |
					 NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED);

	rc = ksmbd_decode_ntlmssp_neg_blob(&neg, sizeof(neg), conn);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_TRUE(test,
			  (conn->ntlmssp.client_flags &
			   NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED) != 0);
	KUNIT_EXPECT_TRUE(test,
			  (conn->ntlmssp.client_flags &
			   NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED) != 0);

	free_test_conn(conn);
}

/* ====================================================================
 * Section 17: NTLMSSP auth integer overflow in offset/length
 * ====================================================================
 */

/*
 * test_ntlmssp_auth_u32_overflow_nt - When NtChallengeResponse offset
 * and length are large u32 values that overflow when added, the function
 * rejects the blob via the (u64)cast check.
 */
static void test_ntlmssp_auth_u32_overflow_nt(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "NTLMSSP", 8);
	auth.MessageType = NtLmAuthenticate;

	/* offset = 0xFFFFFFF0, length = 0x20: sum > u32 max */
	auth.NtChallengeResponse.Length = cpu_to_le16(0x0020);
	auth.NtChallengeResponse.MaximumLength = cpu_to_le16(0x0020);
	auth.NtChallengeResponse.BufferOffset = cpu_to_le32(0xFFFFFFF0);

	auth.DomainName.Length = cpu_to_le16(0);
	auth.DomainName.MaximumLength = cpu_to_le16(0);
	auth.DomainName.BufferOffset = cpu_to_le32(sizeof(auth));

	auth.NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);

	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/*
 * test_ntlmssp_auth_u32_overflow_dn - When DomainName offset and length
 * are large values that overflow, the function rejects the blob.
 */
static void test_ntlmssp_auth_u32_overflow_dn(struct kunit *test)
{
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct ksmbd_session sess;
	struct authenticate_message auth;
	int rc;

	memset(&sess, 0, sizeof(sess));
	memset(&auth, 0, sizeof(auth));
	memcpy(auth.Signature, "NTLMSSP", 8);
	auth.MessageType = NtLmAuthenticate;

	auth.NtChallengeResponse.Length = cpu_to_le16(0);
	auth.NtChallengeResponse.MaximumLength = cpu_to_le16(0);
	auth.NtChallengeResponse.BufferOffset = cpu_to_le32(sizeof(auth));

	/* DomainName: large offset that overflows with any length */
	auth.DomainName.Length = cpu_to_le16(0x0010);
	auth.DomainName.MaximumLength = cpu_to_le16(0x0010);
	auth.DomainName.BufferOffset = cpu_to_le32(0xFFFFFFFF);

	auth.NegotiateFlags = cpu_to_le32(0);

	rc = ksmbd_decode_ntlmssp_auth_blob(&auth, sizeof(auth), conn, &sess);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);

	free_test_conn(conn);
}

/* ====================================================================
 * Test suite registration
 * ====================================================================
 */

static struct kunit_case ksmbd_auth_test_cases[] = {
	/* Existing GSS header tests */
	KUNIT_CASE(test_gss_header_copy_matches),
	KUNIT_CASE(test_gss_header_starts_with_asn1_sequence),
	KUNIT_CASE(test_gss_header_contains_spnego_oid),
	KUNIT_CASE(test_gss_header_length),
	/* Existing ARC4 tests */
	KUNIT_CASE(test_arc4_roundtrip),
	KUNIT_CASE(test_arc4_zero_length),
	KUNIT_CASE(test_arc4_deterministic),
	KUNIT_CASE(test_arc4_min_key_size),
	/* New ARC4 tests */
	KUNIT_CASE(test_arc4_rfc6229_key_40bit),
	KUNIT_CASE(test_arc4_max_key_size),
	KUNIT_CASE(test_arc4_in_place),
	KUNIT_CASE(test_arc4_different_keys_different_output),
	KUNIT_CASE(test_arc4_single_byte),
	/* New GSS header tests */
	KUNIT_CASE(test_gss_header_contains_kerberos_oid),
	KUNIT_CASE(test_gss_header_contains_ntlmssp_oid),
	KUNIT_CASE(test_gss_header_idempotent),
	KUNIT_CASE(test_gss_header_contains_hint_string),
	/* NTLMSSP negotiate blob parsing */
	KUNIT_CASE(test_ntlmssp_neg_valid),
	KUNIT_CASE(test_ntlmssp_neg_too_short),
	KUNIT_CASE(test_ntlmssp_neg_zero_length),
	KUNIT_CASE(test_ntlmssp_neg_wrong_signature),
	KUNIT_CASE(test_ntlmssp_neg_all_flags),
	KUNIT_CASE(test_ntlmssp_neg_exact_minimum_size),
	KUNIT_CASE(test_ntlmssp_neg_domain_supplied),
	/* NTLMSSP authenticate blob parsing */
	KUNIT_CASE(test_ntlmssp_auth_too_short),
	KUNIT_CASE(test_ntlmssp_auth_wrong_signature),
	KUNIT_CASE(test_ntlmssp_auth_anonymous),
	KUNIT_CASE(test_ntlmssp_auth_anonymous_without_flag),
	KUNIT_CASE(test_ntlmssp_auth_nt_offset_overflow),
	KUNIT_CASE(test_ntlmssp_auth_domain_offset_overflow),
	KUNIT_CASE(test_ntlmssp_auth_nt_len_too_small),
	KUNIT_CASE(test_ntlmssp_auth_ntlmv2_blob_no_avpair_eol),
	KUNIT_CASE(test_ntlmssp_auth_ntlmv2_blob_too_small_for_avpairs),
	KUNIT_CASE(test_ntlmssp_auth_u32_overflow_nt),
	KUNIT_CASE(test_ntlmssp_auth_u32_overflow_dn),
	/* Constants and structure validation */
	KUNIT_CASE(test_ntlmssp_constants),
	KUNIT_CASE(test_smb2_key_size_constants),
	KUNIT_CASE(test_ntlmssp_message_types),
	KUNIT_CASE(test_ntlmssp_signature_string),
	KUNIT_CASE(test_ntlmssp_flag_bits),
	KUNIT_CASE(test_negotiate_message_struct_size),
	KUNIT_CASE(test_authenticate_message_struct_size),
	KUNIT_CASE(test_challenge_message_struct_size),
	KUNIT_CASE(test_security_buffer_struct_size),
	KUNIT_CASE(test_ntlmv2_resp_struct_size),
	KUNIT_CASE(test_ntlmssp_auth_struct_size),
	KUNIT_CASE(test_arc4_ctx_struct),
	KUNIT_CASE(test_arc4_key_size_constants),
	KUNIT_CASE(test_av_field_types),
	KUNIT_CASE(test_auth_mechanism_flags),
	{}
};

static struct kunit_suite ksmbd_auth_test_suite = {
	.name = "ksmbd_auth",
	.test_cases = ksmbd_auth_test_cases,
};

kunit_test_suite(ksmbd_auth_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd authentication helpers");
