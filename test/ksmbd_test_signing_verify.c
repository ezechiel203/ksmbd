// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2/3 signing and transform header verification
 *
 *   Exercises signing algorithm constants, transform header structure
 *   layout, session-key sizes, protocol invariants, and — where the
 *   production functions are exported via VISIBLE_IF_KUNIT — calls
 *   fill_transform_hdr(), generate_smb3signingkey(), and
 *   generate_smb3encryptionkey() directly.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/xarray.h>
#include <crypto/hash.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "connection.h"
#include "auth.h"
#include "crypto_ctx.h"
#include "mgmt/user_session.h"

/* -----------------------------------------------------------------------
 * Helper: initialise the crypto pool before tests that need crypto ops.
 * ----------------------------------------------------------------------- */

static int signing_verify_suite_init(struct kunit *test)
{
	int rc;

	rc = ksmbd_crypto_create();
	if (rc) {
		kunit_err(test, "ksmbd_crypto_create failed: %d\n", rc);
		return rc;
	}
	return 0;
}

static void signing_verify_suite_exit(struct kunit *test)
{
	ksmbd_crypto_destroy();
}

/* -----------------------------------------------------------------------
 * 1. test_hmac_sha256_sign_known_answer
 *
 * Verify HMAC-SHA256 produces the expected digest for a fixed key/message
 * pair.  This exercises the raw shash API that ksmbd_sign_smb2_pdu() uses
 * internally, confirming the underlying crypto primitive is correct.
 *
 * KAT vector derived from RFC 4231 test case 1:
 *   Key  : 0x0b * 20 bytes
 *   Data : "Hi There"
 *   HMAC : b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
 * ----------------------------------------------------------------------- */
static void test_hmac_sha256_sign_known_answer(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	u8 key[20];
	static const u8 data[] = "Hi There";
	u8 digest[SMB2_HMACSHA256_SIZE];
	/*
	 * Expected HMAC-SHA256 for key=0x0b*20, data="Hi There"
	 * (RFC 4231 §4.2)
	 */
	static const u8 expected[SMB2_HMACSHA256_SIZE] = {
		0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
		0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
		0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
		0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
	};
	int rc;

	memset(key, 0x0b, sizeof(key));

	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key, sizeof(key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), data, sizeof(data) - 1);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), digest);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, memcmp(digest, expected, SMB2_HMACSHA256_SIZE), 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 2. test_aes_cmac_sign_known_answer
 *
 * Verify AES-128-CMAC (used for SMB3.0 signing) produces the correct MAC
 * for a fixed key and zero-padded message.
 *
 * NIST SP 800-38B Example 1:
 *   Key  : 2b7e151628aed2a6abf7158809cf4f3c
 *   Msg  : (empty, 0 bytes)
 *   MAC  : bb1d6929e95937287fa37d129b756746
 * ----------------------------------------------------------------------- */
static void test_aes_cmac_sign_known_answer(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	static const u8 key[SMB2_CMACAES_SIZE] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	};
	static const u8 expected[SMB2_CMACAES_SIZE] = {
		0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
		0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
	};
	u8 mac[SMB2_CMACAES_SIZE];
	int rc;

	ctx = ksmbd_crypto_ctx_find_cmacaes();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = crypto_shash_setkey(CRYPTO_CMACAES_TFM(ctx), key, sizeof(key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = crypto_shash_init(CRYPTO_CMACAES(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Empty message: NIST SP 800-38B Example 1 */
	rc = crypto_shash_final(CRYPTO_CMACAES(ctx), mac);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_EQ(test, memcmp(mac, expected, SMB2_CMACAES_SIZE), 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 3. test_single_bit_flip_detected
 *
 * Sign a 16-byte payload with HMAC-SHA256, flip one bit, re-sign the
 * corrupted payload, and confirm the signatures differ.  This validates
 * that the signing primitive is sensitive to data changes.
 * ----------------------------------------------------------------------- */
static void test_single_bit_flip_detected(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	u8 key[SMB2_NTLMV2_SESSKEY_SIZE];
	u8 payload[16];
	u8 sig_orig[SMB2_HMACSHA256_SIZE];
	u8 sig_flip[SMB2_HMACSHA256_SIZE];
	int rc;

	memset(key, 0xAA, sizeof(key));
	memset(payload, 0x5C, sizeof(payload));

	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Sign original payload */
	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key, sizeof(key));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), payload, sizeof(payload));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), sig_orig);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Flip one bit in the payload */
	payload[7] ^= 0x01;

	/* Sign corrupted payload */
	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key, sizeof(key));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), payload, sizeof(payload));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), sig_flip);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Signatures must differ */
	KUNIT_EXPECT_NE(test, memcmp(sig_orig, sig_flip, SMB2_HMACSHA256_SIZE), 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 4. test_wrong_session_key_detected
 *
 * Sign the same payload with two different session keys.  The resulting
 * MACs must differ, confirming key-binding.
 * ----------------------------------------------------------------------- */
static void test_wrong_session_key_detected(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	u8 key_a[SMB2_NTLMV2_SESSKEY_SIZE];
	u8 key_b[SMB2_NTLMV2_SESSKEY_SIZE];
	static const u8 payload[32] = { 0x11 };
	u8 mac_a[SMB2_HMACSHA256_SIZE];
	u8 mac_b[SMB2_HMACSHA256_SIZE];
	int rc;

	memset(key_a, 0x11, sizeof(key_a));
	memset(key_b, 0x22, sizeof(key_b));

	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Sign with key A */
	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key_a, sizeof(key_a));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), payload, sizeof(payload));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), mac_a);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Sign with key B */
	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key_b, sizeof(key_b));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), payload, sizeof(payload));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), mac_b);
	KUNIT_ASSERT_EQ(test, rc, 0);

	KUNIT_EXPECT_NE(test, memcmp(mac_a, mac_b, SMB2_HMACSHA256_SIZE), 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 5. test_signature_field_zeroed_before_compute
 *
 * MS-SMB2 §3.1.4.1: the Signature field in the SMB2 header must be
 * zeroed before computing the signature over the PDU.  Verify that if we
 * zero the signature field and then re-sign, we get the same result,
 * while an un-zeroed field produces a different result.
 * ----------------------------------------------------------------------- */
static void test_signature_field_zeroed_before_compute(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	u8 key[SMB2_NTLMV2_SESSKEY_SIZE];
	/*
	 * Simulate a minimal SMB2 PDU with a Signature field at offset 48
	 * (as in struct smb2_hdr).  Fill the body with non-zero data,
	 * place a non-zero signature, then sign with vs without zeroing.
	 */
	u8 pdu[64];
	u8 mac_zeroed[SMB2_HMACSHA256_SIZE];
	u8 mac_nonzeroed[SMB2_HMACSHA256_SIZE];
	int rc;

	memset(key, 0x33, sizeof(key));
	memset(pdu, 0xFF, sizeof(pdu));
	/* Signature lives at bytes 48..63 of SMB2 header */
	memset(pdu + 48, 0xCC, SMB2_SIGNATURE_SIZE);

	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Sign with non-zero signature field (wrong) */
	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key, sizeof(key));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), pdu, sizeof(pdu));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), mac_nonzeroed);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Zero signature field before signing (correct MS-SMB2 procedure) */
	memset(pdu + 48, 0x00, SMB2_SIGNATURE_SIZE);

	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key, sizeof(key));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), pdu, sizeof(pdu));
	KUNIT_ASSERT_EQ(test, rc, 0);
	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), mac_zeroed);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* The two MACs must differ because inputs differed */
	KUNIT_EXPECT_NE(test,
			memcmp(mac_zeroed, mac_nonzeroed, SMB2_HMACSHA256_SIZE),
			0);

	/* Repeating with zeroed field must be deterministic */
	memset(pdu + 48, 0x00, SMB2_SIGNATURE_SIZE);
	{
		u8 mac_again[SMB2_HMACSHA256_SIZE];

		rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx), key,
					 sizeof(key));
		KUNIT_ASSERT_EQ(test, rc, 0);
		rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
		KUNIT_ASSERT_EQ(test, rc, 0);
		rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), pdu,
					 sizeof(pdu));
		KUNIT_ASSERT_EQ(test, rc, 0);
		rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), mac_again);
		KUNIT_ASSERT_EQ(test, rc, 0);
		KUNIT_EXPECT_EQ(test,
				memcmp(mac_zeroed, mac_again,
				       SMB2_HMACSHA256_SIZE),
				0);
	}

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 6. test_transform_header_protocol_id
 *
 * MS-SMB2 §2.2.41: the ProtocolId field of SMB2_TRANSFORM_HEADER must
 * be 0xFD 'S' 'M' 'B' (little-endian 0x424d53fd).
 * ----------------------------------------------------------------------- */
static void test_transform_header_protocol_id(struct kunit *test)
{
	/*
	 * SMB2_TRANSFORM_PROTO_NUM is cpu_to_le32(0x424d53fd).
	 * Verify the individual bytes in network order.
	 */
	__le32 proto_id = SMB2_TRANSFORM_PROTO_NUM;
	const u8 *b = (const u8 *)&proto_id;

	/* little-endian byte layout: fd 53 4d 42 */
	KUNIT_EXPECT_EQ(test, b[0], (u8)0xfd);
	KUNIT_EXPECT_EQ(test, b[1], (u8)0x53); /* 'S' */
	KUNIT_EXPECT_EQ(test, b[2], (u8)0x4d); /* 'M' */
	KUNIT_EXPECT_EQ(test, b[3], (u8)0x42); /* 'B' */
}

/* -----------------------------------------------------------------------
 * 7. test_transform_header_nonce_16bytes
 *
 * MS-SMB2 §2.2.41: the Nonce field in SMB2_TRANSFORM_HEADER is 16 bytes.
 * ----------------------------------------------------------------------- */
static void test_transform_header_nonce_16bytes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			sizeof_field(struct smb2_transform_hdr, Nonce),
			(size_t)16);
}

/* -----------------------------------------------------------------------
 * 8. test_signing_algorithm_constants
 *
 * MS-SMB2 §2.2.3.1.3 (Signing Capabilities): the wire values for
 * HMAC-SHA256, AES-CMAC, and AES-GMAC must be 0, 1, 2 respectively.
 * ----------------------------------------------------------------------- */
static void test_signing_algorithm_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SIGNING_ALG_HMAC_SHA256), (u16)0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SIGNING_ALG_AES_CMAC),    (u16)1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SIGNING_ALG_AES_GMAC),    (u16)2);
}

/* -----------------------------------------------------------------------
 * 9. test_encryption_algorithm_constants
 *
 * MS-SMB2 §2.2.3.1.2 (Encryption Capabilities): AES-128-CCM=1,
 * AES-128-GCM=2, AES-256-CCM=3, AES-256-GCM=4.
 * ----------------------------------------------------------------------- */
static void test_encryption_algorithm_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_ENCRYPTION_AES128_CCM), (u16)0x0001);
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_ENCRYPTION_AES128_GCM), (u16)0x0002);
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_ENCRYPTION_AES256_CCM), (u16)0x0003);
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_ENCRYPTION_AES256_GCM), (u16)0x0004);
}

/* -----------------------------------------------------------------------
 * 10. test_session_key_size_16bytes
 *
 * MS-SMB2 §3.2.5.3: the SMB2 session key is always exactly 16 bytes.
 * ----------------------------------------------------------------------- */
static void test_session_key_size_16bytes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)SMB2_NTLMV2_SESSKEY_SIZE, 16);
	/* The signing key for SMB3 is also 16 bytes */
	KUNIT_EXPECT_EQ(test, (int)SMB3_SIGN_KEY_SIZE, 16);
}

/* -----------------------------------------------------------------------
 * 11. test_signing_required_flag
 *
 * MS-SMB2 §2.2.1.2: SMB2_FLAGS_SIGNED (0x00000008) indicates a signed PDU.
 * ----------------------------------------------------------------------- */
static void test_signing_required_flag(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(SMB2_FLAGS_SIGNED), (u32)0x00000008);
}

/* -----------------------------------------------------------------------
 * 12. test_preauth_integrity_sha512
 *
 * MS-SMB2 §2.2.3.1.1: the only supported preauth integrity hash is
 * SHA-512 (algorithm ID 0x0001), which produces a 64-byte digest.
 * ----------------------------------------------------------------------- */
static void test_preauth_integrity_sha512(struct kunit *test)
{
	/* Algorithm wire value */
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_PREAUTH_INTEGRITY_SHA512), (u16)1);
	/* Hash output size */
	KUNIT_EXPECT_EQ(test, (int)PREAUTH_HASHVALUE_SIZE, 64);

	/* Verify we can actually produce a SHA-512 digest */
	{
		struct ksmbd_crypto_ctx *ctx;
		u8 digest[64];
		static const u8 msg[] = "ksmbd preauth integrity test";
		int rc;

		ctx = ksmbd_crypto_ctx_find_sha512();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

		rc = crypto_shash_init(CRYPTO_SHA512(ctx));
		KUNIT_ASSERT_EQ(test, rc, 0);

		rc = crypto_shash_update(CRYPTO_SHA512(ctx), msg,
					 sizeof(msg) - 1);
		KUNIT_ASSERT_EQ(test, rc, 0);

		rc = crypto_shash_final(CRYPTO_SHA512(ctx), digest);
		KUNIT_ASSERT_EQ(test, rc, 0);

		/* Digest must be non-zero */
		{
			u8 zero[64] = { 0 };

			KUNIT_EXPECT_NE(test, memcmp(digest, zero, 64), 0);
		}

		ksmbd_release_crypto_ctx(ctx);
	}
}

/* -----------------------------------------------------------------------
 * 13. test_fill_transform_hdr_if_exported
 *
 * Call the real fill_transform_hdr() (exported via VISIBLE_IF_KUNIT)
 * with a minimal SMB2 buffer and verify the transform header fields.
 * ----------------------------------------------------------------------- */
static void test_fill_transform_hdr_if_exported(struct kunit *test)
{
	char *old_buf;
	void *tr_buf;
	struct smb2_transform_hdr *tr_hdr;
	struct smb2_hdr *hdr;
	int rc;

	old_buf = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_buf);

	tr_buf = kzalloc(sizeof(struct smb2_transform_hdr) + 4, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tr_buf);

	/* Set up a minimal SMB2 buffer: RFC1001 len + SMB2 header */
	hdr = (struct smb2_hdr *)(old_buf + 4);
	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->SessionId  = cpu_to_le64(0xDEADBEEFCAFEBABEULL);
	/* RFC1001 length = 64 (SMB2 header size) */
	*((__be32 *)old_buf) = cpu_to_be32(64);

	rc = fill_transform_hdr(tr_buf, old_buf,
				SMB2_ENCRYPTION_AES128_CCM, NULL);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* The transform header sits 4 bytes in (after RFC1001 len) */
	tr_hdr = (struct smb2_transform_hdr *)((char *)tr_buf + 4);

	/* Protocol ID must be 0xFD 'S' 'M' 'B' */
	KUNIT_EXPECT_EQ(test, tr_hdr->ProtocolId, SMB2_TRANSFORM_PROTO_NUM);

	/* OriginalMessageSize must equal the inner payload length */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(tr_hdr->OriginalMessageSize), 64U);

	/* SessionId must be copied from the inner SMB2 header */
	KUNIT_EXPECT_EQ(test, tr_hdr->SessionId,
			cpu_to_le64(0xDEADBEEFCAFEBABEULL));

	kfree(tr_buf);
	kfree(old_buf);
}

/* -----------------------------------------------------------------------
 * 14. test_generate_signing_key_if_exported
 *
 * Exercise generate_smb3signingkey() (exported via VISIBLE_IF_KUNIT).
 * We build a minimal conn+session with a channel entry stored in the
 * session's xarray and verify the function succeeds without crashing.
 * ----------------------------------------------------------------------- */
static void test_generate_signing_key_if_exported(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_session sess;
	struct channel chann;
	struct derivation d;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&sess, 0, sizeof(sess));
	memset(&chann, 0, sizeof(chann));

	/* Fill a deterministic session key */
	memset(sess.sess_key, 0x42, sizeof(sess.sess_key));

	/* Initialise the xarray that holds the per-conn channel entries */
	xa_init(&sess.ksmbd_chann_list);

	/* Insert a channel so lookup_chann_list() returns non-NULL */
	chann.conn = &conn;
	rc = xa_err(xa_store(&sess.ksmbd_chann_list, (unsigned long)&conn,
			     &chann, GFP_KERNEL));
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Use the SMB3.0 signing key derivation labels */
	d.label.iov_base   = "SMB2AESCMAC";
	d.label.iov_len    = 12;
	d.context.iov_base = "SmbSign";
	d.context.iov_len  = 8;
	d.binding          = false;

	conn.dialect    = 0x0300; /* SMB 3.0 */
	conn.cipher_type = SMB2_ENCRYPTION_AES128_CCM;

	rc = generate_smb3signingkey(&sess, &conn, &d);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Derived key must be non-zero */
	{
		u8 zero[SMB3_SIGN_KEY_SIZE] = { 0 };

		KUNIT_EXPECT_NE(test,
				memcmp(sess.smb3signingkey, zero,
				       SMB3_SIGN_KEY_SIZE),
				0);
	}

	xa_destroy(&sess.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * 15. test_generate_encryption_key_if_exported
 *
 * Exercise generate_smb3encryptionkey() (exported via VISIBLE_IF_KUNIT).
 * Confirm that encryption and decryption keys are derived and are
 * distinct from each other.
 * ----------------------------------------------------------------------- */
static void test_generate_encryption_key_if_exported(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_session sess;
	struct derivation_twin twin;
	int rc;

	memset(&conn,  0, sizeof(conn));
	memset(&sess,  0, sizeof(sess));
	memset(&twin,  0, sizeof(twin));

	memset(sess.sess_key, 0x55, sizeof(sess.sess_key));

	/* SMB3.0 encryption key labels (ksmbd_gen_smb30_encryptionkey) */
	twin.encryption.label.iov_base   = "SMB2AESCCM";
	twin.encryption.label.iov_len    = 11;
	twin.encryption.context.iov_base = "ServerOut";
	twin.encryption.context.iov_len  = 10;

	twin.decryption.label.iov_base   = "SMB2AESCCM";
	twin.decryption.label.iov_len    = 11;
	twin.decryption.context.iov_base = "ServerIn ";
	twin.decryption.context.iov_len  = 10;

	conn.cipher_type = SMB2_ENCRYPTION_AES128_CCM;

	rc = generate_smb3encryptionkey(&conn, &sess, &twin);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Both keys must be non-zero */
	{
		u8 zero[SMB3_ENC_DEC_KEY_SIZE] = { 0 };

		KUNIT_EXPECT_NE(test,
				memcmp(sess.smb3encryptionkey, zero,
				       SMB3_ENC_DEC_KEY_SIZE),
				0);
		KUNIT_EXPECT_NE(test,
				memcmp(sess.smb3decryptionkey, zero,
				       SMB3_ENC_DEC_KEY_SIZE),
				0);
	}

	/* Encryption and decryption keys must differ (different contexts) */
	KUNIT_EXPECT_NE(test,
			memcmp(sess.smb3encryptionkey, sess.smb3decryptionkey,
			       SMB3_ENC_DEC_KEY_SIZE),
			0);
}

/* -----------------------------------------------------------------------
 * Test suite registration
 * ----------------------------------------------------------------------- */

static struct kunit_case ksmbd_signing_verify_test_cases[] = {
	KUNIT_CASE(test_hmac_sha256_sign_known_answer),
	KUNIT_CASE(test_aes_cmac_sign_known_answer),
	KUNIT_CASE(test_single_bit_flip_detected),
	KUNIT_CASE(test_wrong_session_key_detected),
	KUNIT_CASE(test_signature_field_zeroed_before_compute),
	KUNIT_CASE(test_transform_header_protocol_id),
	KUNIT_CASE(test_transform_header_nonce_16bytes),
	KUNIT_CASE(test_signing_algorithm_constants),
	KUNIT_CASE(test_encryption_algorithm_constants),
	KUNIT_CASE(test_session_key_size_16bytes),
	KUNIT_CASE(test_signing_required_flag),
	KUNIT_CASE(test_preauth_integrity_sha512),
	KUNIT_CASE(test_fill_transform_hdr_if_exported),
	KUNIT_CASE(test_generate_signing_key_if_exported),
	KUNIT_CASE(test_generate_encryption_key_if_exported),
	{}
};

static struct kunit_suite ksmbd_signing_verify_test_suite = {
	.name      = "ksmbd_signing_verify",
	.init      = signing_verify_suite_init,
	.exit      = signing_verify_suite_exit,
	.test_cases = ksmbd_signing_verify_test_cases,
};

kunit_test_suite(ksmbd_signing_verify_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2/3 signing and transform header");
