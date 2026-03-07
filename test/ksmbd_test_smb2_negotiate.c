// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB2 negotiate context helpers (smb2_negotiate.c)
 *
 *   Tests call real decode_preauth_ctxt(), decode_encrypt_ctxt(),
 *   decode_compress_ctxt(), decode_sign_cap_ctxt() via VISIBLE_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "connection.h"
#include "server.h"
#include "auth.h"

/* --- decode_preauth_ctxt() tests --- */

/*
 * test_preauth_sha512 - SHA-512 is accepted
 */
static void test_preauth_sha512(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;
	int ctxt_len;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.HashAlgorithmCount = cpu_to_le16(1);
	ctxt.HashAlgorithms = SMB2_PREAUTH_INTEGRITY_SHA512;
	ctxt_len = sizeof(ctxt);

	status = decode_preauth_ctxt(&conn, &ctxt, ctxt_len);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, conn.preauth_info->Preauth_HashId,
			SMB2_PREAUTH_INTEGRITY_SHA512);
}

/*
 * test_preauth_hash_count_zero - HashAlgorithmCount=0 is rejected
 */
static void test_preauth_hash_count_zero(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.HashAlgorithmCount = cpu_to_le16(0);
	ctxt.HashAlgorithms = SMB2_PREAUTH_INTEGRITY_SHA512;

	status = decode_preauth_ctxt(&conn, &ctxt, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/*
 * test_preauth_unknown_hash - unknown hash algorithm has no overlap
 */
static void test_preauth_unknown_hash(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	ctxt.ContextType = SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.HashAlgorithmCount = cpu_to_le16(1);
	ctxt.HashAlgorithms = cpu_to_le16(0xFFFF); /* unknown */

	status = decode_preauth_ctxt(&conn, &ctxt, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_NO_PREAUTH_INTEGRITY_HASH_OVERLAP);
}

/*
 * test_preauth_truncated - short context rejected
 */
static void test_preauth_truncated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_preauth_integrity_info preauth;
	struct smb2_preauth_neg_context ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&preauth, 0, sizeof(preauth));
	conn.preauth_info = &preauth;

	memset(&ctxt, 0, sizeof(ctxt));
	/* Provide a very short context length */
	status = decode_preauth_ctxt(&conn, &ctxt, 4);
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/* --- decode_sign_cap_ctxt() tests --- */

/*
 * test_sign_cap_aes_cmac - AES-CMAC is selected
 */
static void test_sign_cap_aes_cmac(struct kunit *test)
{
	struct ksmbd_conn conn;
	/* Need room for 1 algorithm entry after the struct */
	struct {
		struct smb2_signing_capabilities cap;
		__le16 alg;
	} __packed ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.cap.ContextType = SMB2_SIGNING_CAPABILITIES;
	ctxt.cap.DataLength = cpu_to_le16(sizeof(__le16) + sizeof(__le16));
	ctxt.cap.SigningAlgorithmCount = cpu_to_le16(1);
	ctxt.cap.SigningAlgorithms[0] = SIGNING_ALG_AES_CMAC;

	status = decode_sign_cap_ctxt(&conn, &ctxt.cap, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_TRUE(test, conn.signing_negotiated);
	KUNIT_EXPECT_EQ(test, conn.signing_algorithm, SIGNING_ALG_AES_CMAC);
}

/*
 * test_sign_cap_count_zero - SigningAlgorithmCount=0 is rejected
 */
static void test_sign_cap_count_zero(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_signing_capabilities cap;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&cap, 0, sizeof(cap));

	cap.ContextType = SMB2_SIGNING_CAPABILITIES;
	cap.DataLength = cpu_to_le16(sizeof(__le16));
	cap.SigningAlgorithmCount = cpu_to_le16(0);

	status = decode_sign_cap_ctxt(&conn, &cap, sizeof(cap));
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/*
 * test_sign_cap_no_overlap_fallback - no overlap falls back to AES-CMAC
 */
static void test_sign_cap_no_overlap_fallback(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct {
		struct smb2_signing_capabilities cap;
		__le16 alg;
	} __packed ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.cap.ContextType = SMB2_SIGNING_CAPABILITIES;
	ctxt.cap.DataLength = cpu_to_le16(sizeof(__le16) + sizeof(__le16));
	ctxt.cap.SigningAlgorithmCount = cpu_to_le16(1);
	ctxt.cap.SigningAlgorithms[0] = cpu_to_le16(0xFFFF); /* unknown */

	status = decode_sign_cap_ctxt(&conn, &ctxt.cap, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
	KUNIT_EXPECT_TRUE(test, conn.signing_negotiated);
	/* Falls back to AES-CMAC */
	KUNIT_EXPECT_EQ(test, conn.signing_algorithm, SIGNING_ALG_AES_CMAC);
}

/* --- decode_compress_ctxt() tests --- */

/*
 * test_compress_count_zero - CompressionAlgorithmCount=0 is rejected
 */
static void test_compress_count_zero(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_compression_ctx ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	ctxt.ContextType = SMB2_COMPRESSION_CAPABILITIES;
	ctxt.DataLength = cpu_to_le16(sizeof(ctxt) - sizeof(struct smb2_neg_context));
	ctxt.CompressionAlgorithmCount = cpu_to_le16(0);

	status = decode_compress_ctxt(&conn, &ctxt, sizeof(ctxt));
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/*
 * test_compress_truncated - truncated context is rejected
 */
static void test_compress_truncated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_compression_ctx ctxt;
	__le32 status;

	memset(&conn, 0, sizeof(conn));
	memset(&ctxt, 0, sizeof(ctxt));

	/* Too small context */
	status = decode_compress_ctxt(&conn, &ctxt, 2);
	KUNIT_EXPECT_EQ(test, status, STATUS_INVALID_PARAMETER);
}

/* --- decode_encrypt_ctxt() tests --- */

/*
 * test_encrypt_truncated - truncated context handled gracefully
 */
static void test_encrypt_truncated(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_encryption_neg_context ctxt;

	memset(&conn, 0, sizeof(conn));
	conn.cipher_type = 0x1234; /* Set to detect if cleared */
	memset(&ctxt, 0, sizeof(ctxt));

	/* Too-short context: function should return without setting cipher */
	decode_encrypt_ctxt(&conn, &ctxt, 2);
	/* cipher_type was not set to any valid cipher (function returns early) */
	KUNIT_EXPECT_EQ(test, conn.cipher_type, (__le16)0x1234);
}

static struct kunit_case ksmbd_smb2_negotiate_test_cases[] = {
	KUNIT_CASE(test_preauth_sha512),
	KUNIT_CASE(test_preauth_hash_count_zero),
	KUNIT_CASE(test_preauth_unknown_hash),
	KUNIT_CASE(test_preauth_truncated),
	KUNIT_CASE(test_sign_cap_aes_cmac),
	KUNIT_CASE(test_sign_cap_count_zero),
	KUNIT_CASE(test_sign_cap_no_overlap_fallback),
	KUNIT_CASE(test_compress_count_zero),
	KUNIT_CASE(test_compress_truncated),
	KUNIT_CASE(test_encrypt_truncated),
	{}
};

static struct kunit_suite ksmbd_smb2_negotiate_test_suite = {
	.name = "ksmbd_smb2_negotiate",
	.test_cases = ksmbd_smb2_negotiate_test_cases,
};

kunit_test_suite(ksmbd_smb2_negotiate_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 negotiate context helpers");
