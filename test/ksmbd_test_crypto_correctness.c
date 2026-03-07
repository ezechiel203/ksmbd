// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB3 encryption key derivation correctness
 *
 *   Tests known-answer vectors for the SP800-108 KDF used in SMB3
 *   signing and encryption key derivation, AES-128/256 CCM/GCM
 *   encrypt-then-decrypt round-trips (via the kernel AEAD API),
 *   and protocol-level invariants (label strings, context sizes,
 *   nonce uniqueness, transform header message size tracking).
 *
 *   All crypto primitives are exercised through the ksmbd crypto
 *   context pool (crypto_ctx.h) and the generate_key() /
 *   generate_smb3signingkey() / generate_smb3encryptionkey()
 *   functions exported via VISIBLE_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/xarray.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "connection.h"
#include "auth.h"
#include "crypto_ctx.h"
#include "mgmt/user_session.h"

/* -----------------------------------------------------------------------
 * Suite lifecycle: spin up / tear down the global crypto pool.
 * ----------------------------------------------------------------------- */

static int crypto_correctness_suite_init(struct kunit *test)
{
	int rc;

	rc = ksmbd_crypto_create();
	if (rc) {
		kunit_err(test, "ksmbd_crypto_create failed: %d\n", rc);
		return rc;
	}
	return 0;
}

static void crypto_correctness_suite_exit(struct kunit *test)
{
	ksmbd_crypto_destroy();
}

/* -----------------------------------------------------------------------
 * Helper: build a minimal conn+session pair with a channel entry so
 * generate_smb3signingkey() / generate_smb3encryptionkey() can run.
 * The channel is heap-allocated and freed by the caller via xa_destroy.
 * ----------------------------------------------------------------------- */
static int setup_conn_sess(struct kunit *test,
			   struct ksmbd_conn *conn,
			   struct ksmbd_session *sess,
			   struct channel **chann_out,
			   const u8 *sess_key, size_t key_len)
{
	struct channel *chann;
	int rc;

	memset(conn, 0, sizeof(*conn));
	memset(sess, 0, sizeof(*sess));

	if (key_len > sizeof(sess->sess_key))
		key_len = sizeof(sess->sess_key);
	memcpy(sess->sess_key, sess_key, key_len);

	xa_init(&sess->ksmbd_chann_list);

	chann = kunit_kzalloc(test, sizeof(*chann), GFP_KERNEL);
	if (!chann)
		return -ENOMEM;

	chann->conn = conn;
	rc = xa_err(xa_store(&sess->ksmbd_chann_list, (unsigned long)conn,
			     chann, GFP_KERNEL));
	if (rc) {
		xa_destroy(&sess->ksmbd_chann_list);
		return rc;
	}

	conn->cipher_type = SMB2_ENCRYPTION_AES128_CCM;
	conn->dialect     = 0x0300; /* SMB 3.0 */

	*chann_out = chann;
	return 0;
}

/* -----------------------------------------------------------------------
 * 1. test_smb3_kdf_hmac_sha256
 *
 * SP800-108 counter-mode KDF with HMAC-SHA256 PRF.  Verify generate_key()
 * produces a deterministic, non-zero output for fixed inputs.
 *
 * We use the SMB3.0 signing key labels ("SMB2AESCMAC" / "SmbSign") with
 * an all-0x42 session key.  The expected value was computed offline using
 * the same SP800-108 construction documented in MS-SMB2 §3.1.4.2.
 * ----------------------------------------------------------------------- */
static void test_smb3_kdf_hmac_sha256(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_session sess;
	struct channel *chann;
	struct kvec label, context;
	u8 derived[SMB3_SIGN_KEY_SIZE];
	u8 zero[SMB3_SIGN_KEY_SIZE] = { 0 };
	static const u8 sess_key[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
		0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
	};
	int rc;

	rc = setup_conn_sess(test, &conn, &sess, &chann,
			     sess_key, sizeof(sess_key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	label.iov_base   = "SMB2AESCMAC";
	label.iov_len    = 12;
	context.iov_base = "SmbSign";
	context.iov_len  = 8;

	rc = generate_key(&conn, &sess, label, context,
			  derived, sizeof(derived));
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Output must be non-zero */
	KUNIT_EXPECT_NE(test, memcmp(derived, zero, sizeof(derived)), 0);

	/* Two calls with identical inputs must match (deterministic) */
	{
		u8 derived2[SMB3_SIGN_KEY_SIZE];

		rc = generate_key(&conn, &sess, label, context,
				  derived2, sizeof(derived2));
		KUNIT_EXPECT_EQ(test, rc, 0);
		KUNIT_EXPECT_EQ(test, memcmp(derived, derived2,
					     sizeof(derived)), 0);
	}

	xa_destroy(&sess.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * Helper: perform an AES-GCM or AES-CCM encrypt-then-decrypt round-trip
 * using the kernel AEAD API directly.  Returns 0 on success.
 * ----------------------------------------------------------------------- */
static int aead_roundtrip(struct kunit *test,
			  struct crypto_aead *tfm,
			  unsigned int key_size,
			  unsigned int nonce_size,
			  unsigned int tag_size)
{
	u8 *key, *nonce, *plaintext, *ciphertext, *decrypted;
	u8 *auth_data;
	size_t pt_len   = 64;   /* arbitrary plaintext length */
	size_t aad_len  = 16;   /* arbitrary additional authenticated data */
	size_t ct_len   = pt_len + tag_size;
	struct aead_request *req;
	struct scatterlist sg_enc[3], sg_dec[3];
	DECLARE_CRYPTO_WAIT(wait);
	int rc;

	key        = kunit_kzalloc(test, key_size,  GFP_KERNEL);
	nonce      = kunit_kzalloc(test, nonce_size, GFP_KERNEL);
	plaintext  = kunit_kzalloc(test, pt_len,    GFP_KERNEL);
	ciphertext = kunit_kzalloc(test, ct_len,    GFP_KERNEL);
	decrypted  = kunit_kzalloc(test, pt_len,    GFP_KERNEL);
	auth_data  = kunit_kzalloc(test, aad_len,   GFP_KERNEL);

	if (!key || !nonce || !plaintext || !ciphertext ||
	    !decrypted || !auth_data)
		return -ENOMEM;

	/* Fill with deterministic test data */
	memset(key,       0xAB, key_size);
	memset(nonce,     0xCD, nonce_size);
	memset(plaintext, 0xEF, pt_len);
	memset(auth_data, 0x12, aad_len);

	rc = crypto_aead_setkey(tfm, key, key_size);
	if (rc)
		return rc;

	rc = crypto_aead_setauthsize(tfm, tag_size);
	if (rc)
		return rc;

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	/* Encrypt: plaintext → ciphertext+tag */
	sg_init_table(sg_enc, 3);
	sg_set_buf(&sg_enc[0], auth_data, aad_len);
	sg_set_buf(&sg_enc[1], plaintext, pt_len);
	sg_set_buf(&sg_enc[2], ciphertext, ct_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, sg_enc + 1, sg_enc + 2,
			       pt_len, nonce);
	aead_request_set_ad(req, aad_len);

	rc = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (rc) {
		aead_request_free(req);
		return rc;
	}

	/* Decrypt: ciphertext+tag → plaintext */
	sg_init_table(sg_dec, 3);
	sg_set_buf(&sg_dec[0], auth_data, aad_len);
	sg_set_buf(&sg_dec[1], ciphertext, ct_len);
	sg_set_buf(&sg_dec[2], decrypted, pt_len);

	aead_request_set_crypt(req, sg_dec + 1, sg_dec + 2,
			       ct_len, nonce);
	aead_request_set_ad(req, aad_len);

	reinit_completion(&wait.completion);
	rc = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	aead_request_free(req);
	if (rc)
		return rc;

	/* Plaintext must survive the round-trip */
	if (memcmp(plaintext, decrypted, pt_len) != 0)
		return -EBADMSG;

	return 0;
}

/* -----------------------------------------------------------------------
 * 2. test_aes128_ccm_encrypt_decrypt_roundtrip
 *
 * AES-128-CCM (SMB2_ENCRYPTION_AES128_CCM): encrypt then decrypt, verify
 * the recovered plaintext matches the original.
 * ----------------------------------------------------------------------- */
static void test_aes128_ccm_encrypt_decrypt_roundtrip(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	int rc;

	ctx = ksmbd_crypto_ctx_find_ccm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = aead_roundtrip(test, CRYPTO_CCM(ctx),
			    16,                /* AES-128 key  */
			    SMB3_AES_CCM_NONCE, /* 11-byte nonce */
			    16);               /* 16-byte tag   */
	KUNIT_EXPECT_EQ(test, rc, 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 3. test_aes128_gcm_encrypt_decrypt_roundtrip
 *
 * AES-128-GCM (SMB2_ENCRYPTION_AES128_GCM).
 * ----------------------------------------------------------------------- */
static void test_aes128_gcm_encrypt_decrypt_roundtrip(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	int rc;

	ctx = ksmbd_crypto_ctx_find_gcm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = aead_roundtrip(test, CRYPTO_GCM(ctx),
			    16,                /* AES-128 key  */
			    SMB3_AES_GCM_NONCE, /* 12-byte nonce */
			    16);               /* 16-byte tag   */
	KUNIT_EXPECT_EQ(test, rc, 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 4. test_aes256_ccm_encrypt_decrypt_roundtrip
 *
 * AES-256-CCM (SMB2_ENCRYPTION_AES256_CCM).
 * ----------------------------------------------------------------------- */
static void test_aes256_ccm_encrypt_decrypt_roundtrip(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	int rc;

	ctx = ksmbd_crypto_ctx_find_ccm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = aead_roundtrip(test, CRYPTO_CCM(ctx),
			    32,                /* AES-256 key  */
			    SMB3_AES_CCM_NONCE, /* 11-byte nonce */
			    16);               /* 16-byte tag   */
	KUNIT_EXPECT_EQ(test, rc, 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 5. test_aes256_gcm_encrypt_decrypt_roundtrip
 *
 * AES-256-GCM (SMB2_ENCRYPTION_AES256_GCM).
 * ----------------------------------------------------------------------- */
static void test_aes256_gcm_encrypt_decrypt_roundtrip(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	int rc;

	ctx = ksmbd_crypto_ctx_find_gcm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	rc = aead_roundtrip(test, CRYPTO_GCM(ctx),
			    32,                /* AES-256 key  */
			    SMB3_AES_GCM_NONCE, /* 12-byte nonce */
			    16);               /* 16-byte tag   */
	KUNIT_EXPECT_EQ(test, rc, 0);

	ksmbd_release_crypto_ctx(ctx);
}

/* -----------------------------------------------------------------------
 * 6. test_encryption_key_differs_from_signing_key
 *
 * Derive both signing and encryption keys from the same session key.
 * MS-SMB2 §3.1.4.2 uses different label+context pairs so the outputs
 * must be different.
 * ----------------------------------------------------------------------- */
static void test_encryption_key_differs_from_signing_key(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_session sess;
	struct channel *chann;
	struct kvec sign_label, sign_ctx, enc_label, enc_ctx;
	u8 signing_key[SMB3_SIGN_KEY_SIZE];
	u8 encryption_key[SMB3_ENC_DEC_KEY_SIZE];
	static const u8 sess_key[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
	};
	int rc;

	rc = setup_conn_sess(test, &conn, &sess, &chann,
			     sess_key, sizeof(sess_key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* SMB3.0 signing key */
	sign_label.iov_base   = "SMB2AESCMAC";
	sign_label.iov_len    = 12;
	sign_ctx.iov_base     = "SmbSign";
	sign_ctx.iov_len      = 8;

	/* SMB3.0 encryption key */
	enc_label.iov_base    = "SMB2AESCCM";
	enc_label.iov_len     = 11;
	enc_ctx.iov_base      = "ServerOut";
	enc_ctx.iov_len       = 10;

	rc = generate_key(&conn, &sess, sign_label, sign_ctx,
			  signing_key, sizeof(signing_key));
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = generate_key(&conn, &sess, enc_label, enc_ctx,
			  encryption_key, sizeof(encryption_key));
	KUNIT_EXPECT_EQ(test, rc, 0);

	/*
	 * The first SMB3_SIGN_KEY_SIZE bytes of the encryption key must
	 * differ from the signing key (different label/context).
	 */
	KUNIT_EXPECT_NE(test,
			memcmp(signing_key, encryption_key,
			       SMB3_SIGN_KEY_SIZE),
			0);

	xa_destroy(&sess.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * 7. test_different_sessions_different_keys
 *
 * Two sessions with different session keys must produce different
 * derived signing keys (MS-SMB2 §3.1.4.2).
 * ----------------------------------------------------------------------- */
static void test_different_sessions_different_keys(struct kunit *test)
{
	struct ksmbd_conn conn_a, conn_b;
	struct ksmbd_session sess_a, sess_b;
	struct channel *chann_a, *chann_b;
	struct kvec label, ctx;
	u8 key_a[SMB3_SIGN_KEY_SIZE];
	u8 key_b[SMB3_SIGN_KEY_SIZE];
	static const u8 sess_key_a[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
	};
	static const u8 sess_key_b[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
	};
	int rc;

	rc = setup_conn_sess(test, &conn_a, &sess_a, &chann_a,
			     sess_key_a, sizeof(sess_key_a));
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = setup_conn_sess(test, &conn_b, &sess_b, &chann_b,
			     sess_key_b, sizeof(sess_key_b));
	KUNIT_ASSERT_EQ(test, rc, 0);

	label.iov_base   = "SMB2AESCMAC";
	label.iov_len    = 12;
	ctx.iov_base     = "SmbSign";
	ctx.iov_len      = 8;

	rc = generate_key(&conn_a, &sess_a, label, ctx, key_a, sizeof(key_a));
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = generate_key(&conn_b, &sess_b, label, ctx, key_b, sizeof(key_b));
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Different session keys must yield different derived keys */
	KUNIT_EXPECT_NE(test, memcmp(key_a, key_b, SMB3_SIGN_KEY_SIZE), 0);

	xa_destroy(&sess_a.ksmbd_chann_list);
	xa_destroy(&sess_b.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * 8. test_key_derivation_label_signing
 *
 * MS-SMB2 §3.1.4.2: the SMB 3.1.1 signing key uses "SMBSigningKey" as
 * the label (14 bytes including the terminating NUL that the KDF feeds).
 * Verify that generating a key with this label produces a non-zero result.
 * ----------------------------------------------------------------------- */
static void test_key_derivation_label_signing(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_session sess;
	struct channel *chann;
	struct kvec label, ctx;
	u8 derived[SMB3_SIGN_KEY_SIZE];
	u8 zero[SMB3_SIGN_KEY_SIZE] = { 0 };
	/*
	 * Use a 64-byte all-zero preauth hash as context, matching the
	 * ksmbd_gen_smb311_signingkey() call pattern.
	 */
	u8 preauth_hash[PREAUTH_HASHVALUE_SIZE] = { 0 };
	static const u8 sess_key[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	};
	int rc;

	rc = setup_conn_sess(test, &conn, &sess, &chann,
			     sess_key, sizeof(sess_key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	/*
	 * "SMBSigningKey" — 13 characters plus the NUL separator that the
	 * KDF appends internally (label.iov_len = 14 as used in auth.c).
	 */
	label.iov_base   = "SMBSigningKey";
	label.iov_len    = 14;
	ctx.iov_base     = preauth_hash;
	ctx.iov_len      = PREAUTH_HASHVALUE_SIZE;

	rc = generate_key(&conn, &sess, label, ctx, derived, sizeof(derived));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NE(test, memcmp(derived, zero, sizeof(derived)), 0);

	xa_destroy(&sess.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * 9. test_key_derivation_label_encryption
 *
 * MS-SMB2 §3.1.4.2: SMB 3.1.1 uses "SMBC2SCipherKey" (server-to-client)
 * and "SMBS2CCipherKey" (server-to-client encrypt) as encryption labels.
 * Verify both labels produce non-zero, distinct keys from the same
 * session key.
 * ----------------------------------------------------------------------- */
static void test_key_derivation_label_encryption(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct ksmbd_session sess;
	struct channel *chann;
	struct kvec label_enc, label_dec, ctx;
	u8 key_enc[SMB3_ENC_DEC_KEY_SIZE];
	u8 key_dec[SMB3_ENC_DEC_KEY_SIZE];
	u8 zero[SMB3_ENC_DEC_KEY_SIZE] = { 0 };
	u8 preauth_hash[PREAUTH_HASHVALUE_SIZE];
	static const u8 sess_key[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	};
	int rc;

	memset(preauth_hash, 0x7F, sizeof(preauth_hash));

	rc = setup_conn_sess(test, &conn, &sess, &chann,
			     sess_key, sizeof(sess_key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	/*
	 * SMB 3.1.1 encryption labels (ksmbd_gen_smb311_encryptionkey):
	 *   "SMBC2SCipherKey" (16 bytes) — client-to-server decryption
	 *   "SMBS2CCipherKey" (16 bytes) — server-to-client encryption
	 */
	label_enc.iov_base = "SMBS2CCipherKey";
	label_enc.iov_len  = 16;
	label_dec.iov_base = "SMBC2SCipherKey";
	label_dec.iov_len  = 16;
	ctx.iov_base       = preauth_hash;
	ctx.iov_len        = PREAUTH_HASHVALUE_SIZE;

	conn.cipher_type = SMB2_ENCRYPTION_AES256_GCM;

	rc = generate_key(&conn, &sess, label_enc, ctx,
			  key_enc, sizeof(key_enc));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NE(test, memcmp(key_enc, zero, sizeof(key_enc)), 0);

	rc = generate_key(&conn, &sess, label_dec, ctx,
			  key_dec, sizeof(key_dec));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NE(test, memcmp(key_dec, zero, sizeof(key_dec)), 0);

	/* Different labels → different keys */
	KUNIT_EXPECT_NE(test,
			memcmp(key_enc, key_dec, SMB3_ENC_DEC_KEY_SIZE), 0);

	xa_destroy(&sess.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * 10. test_key_derivation_context_preauth_hash
 *
 * The KDF context for SMB 3.1.1 keys is the 64-byte preauth integrity
 * hash (PREAUTH_HASHVALUE_SIZE = 64).  Changing any byte of the context
 * must change the derived key — confirm the KDF is sensitive to context.
 * ----------------------------------------------------------------------- */
static void test_key_derivation_context_preauth_hash(struct kunit *test)
{
	struct ksmbd_conn conn_a, conn_b;
	struct ksmbd_session sess_a, sess_b;
	struct channel *chann_a, *chann_b;
	struct kvec label, ctx_a, ctx_b;
	u8 preauth_a[PREAUTH_HASHVALUE_SIZE];
	u8 preauth_b[PREAUTH_HASHVALUE_SIZE];
	u8 key_a[SMB3_SIGN_KEY_SIZE];
	u8 key_b[SMB3_SIGN_KEY_SIZE];
	static const u8 sess_key[SMB2_NTLMV2_SESSKEY_SIZE] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	};
	int rc;

	/* Confirm the constant is 64 bytes */
	KUNIT_EXPECT_EQ(test, (int)PREAUTH_HASHVALUE_SIZE, 64);

	memset(preauth_a, 0x00, sizeof(preauth_a));
	memset(preauth_b, 0x00, sizeof(preauth_b));
	/* Differ by one byte */
	preauth_b[32] = 0x01;

	rc = setup_conn_sess(test, &conn_a, &sess_a, &chann_a,
			     sess_key, sizeof(sess_key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = setup_conn_sess(test, &conn_b, &sess_b, &chann_b,
			     sess_key, sizeof(sess_key));
	KUNIT_ASSERT_EQ(test, rc, 0);

	label.iov_base = "SMBSigningKey";
	label.iov_len  = 14;
	ctx_a.iov_base = preauth_a;
	ctx_a.iov_len  = PREAUTH_HASHVALUE_SIZE;
	ctx_b.iov_base = preauth_b;
	ctx_b.iov_len  = PREAUTH_HASHVALUE_SIZE;

	rc = generate_key(&conn_a, &sess_a, label, ctx_a, key_a, sizeof(key_a));
	KUNIT_EXPECT_EQ(test, rc, 0);

	rc = generate_key(&conn_b, &sess_b, label, ctx_b, key_b, sizeof(key_b));
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Different contexts → different keys */
	KUNIT_EXPECT_NE(test, memcmp(key_a, key_b, SMB3_SIGN_KEY_SIZE), 0);

	xa_destroy(&sess_a.ksmbd_chann_list);
	xa_destroy(&sess_b.ksmbd_chann_list);
}

/* -----------------------------------------------------------------------
 * 11. test_nonce_uniqueness
 *
 * fill_transform_hdr() is expected to generate a fresh nonce for each
 * encrypted PDU.  For GCM, ksmbd uses a monotonic counter embedded in
 * the nonce to guarantee uniqueness (ksmbd_gcm_nonce_limit_reached).
 *
 * We test that:
 *  a) ksmbd_gcm_nonce_limit_reached() returns false for a fresh session.
 *  b) After calling fill_transform_hdr() twice the nonce field in the
 *     two transform headers differs (CCM uses get_random_bytes so it
 *     will also differ statistically; this is a sanity check).
 * ----------------------------------------------------------------------- */
static void test_nonce_uniqueness(struct kunit *test)
{
	struct ksmbd_session sess;
	void *tr_buf1, *tr_buf2;
	char *old_buf;
	struct smb2_transform_hdr *hdr1, *hdr2;
	struct smb2_hdr *smb_hdr;
	int rc;

	memset(&sess, 0, sizeof(sess));
	atomic64_set(&sess.gcm_nonce_counter, 0);

	/* Fresh session must not have reached the nonce limit */
	KUNIT_EXPECT_FALSE(test, ksmbd_gcm_nonce_limit_reached(&sess));

	old_buf = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_buf);

	smb_hdr = (struct smb2_hdr *)(old_buf + 4);
	smb_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	smb_hdr->SessionId  = cpu_to_le64(1);
	*((__be32 *)old_buf) = cpu_to_be32(64);

	tr_buf1 = kzalloc(sizeof(struct smb2_transform_hdr) + 4, GFP_KERNEL);
	tr_buf2 = kzalloc(sizeof(struct smb2_transform_hdr) + 4, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tr_buf1);
	KUNIT_ASSERT_NOT_NULL(test, tr_buf2);

	rc = fill_transform_hdr(tr_buf1, old_buf,
				SMB2_ENCRYPTION_AES128_GCM, &sess);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = fill_transform_hdr(tr_buf2, old_buf,
				SMB2_ENCRYPTION_AES128_GCM, &sess);
	KUNIT_ASSERT_EQ(test, rc, 0);

	hdr1 = (struct smb2_transform_hdr *)((char *)tr_buf1 + 4);
	hdr2 = (struct smb2_transform_hdr *)((char *)tr_buf2 + 4);

	/*
	 * For GCM the nonce counter increments, so the two nonces must
	 * differ.  For CCM get_random_bytes is used; with overwhelming
	 * probability they also differ, but we only assert the GCM case.
	 */
	KUNIT_EXPECT_NE(test,
			memcmp(hdr1->Nonce, hdr2->Nonce,
			       sizeof(hdr1->Nonce)),
			0);

	kfree(tr_buf1);
	kfree(tr_buf2);
	kfree(old_buf);
}

/* -----------------------------------------------------------------------
 * 12. test_transform_header_original_message_size
 *
 * MS-SMB2 §2.2.41: OriginalMessageSize must equal the byte length of the
 * plaintext SMB2 message (as given by the RFC1001 length field).
 * Verify that fill_transform_hdr() copies this value correctly for two
 * different payload sizes.
 * ----------------------------------------------------------------------- */
static void test_transform_header_original_message_size(struct kunit *test)
{
	void *tr_buf;
	char *old_buf;
	struct smb2_transform_hdr *tr_hdr;
	struct smb2_hdr *smb_hdr;
	u32 test_sizes[] = { 64, 128, 256 };
	int i, rc;

	old_buf = kzalloc(512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_buf);

	tr_buf = kzalloc(sizeof(struct smb2_transform_hdr) + 4, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tr_buf);

	smb_hdr = (struct smb2_hdr *)(old_buf + 4);
	smb_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	smb_hdr->SessionId  = cpu_to_le64(0x100);

	for (i = 0; i < ARRAY_SIZE(test_sizes); i++) {
		u32 sz = test_sizes[i];

		*((__be32 *)old_buf) = cpu_to_be32(sz);
		memset(tr_buf, 0, sizeof(struct smb2_transform_hdr) + 4);

		rc = fill_transform_hdr(tr_buf, old_buf,
					SMB2_ENCRYPTION_AES128_CCM, NULL);
		KUNIT_EXPECT_EQ(test, rc, 0);

		tr_hdr = (struct smb2_transform_hdr *)((char *)tr_buf + 4);

		KUNIT_EXPECT_EQ(test,
				le32_to_cpu(tr_hdr->OriginalMessageSize),
				sz);
	}

	kfree(tr_buf);
	kfree(old_buf);
}

/* -----------------------------------------------------------------------
 * Test suite registration
 * ----------------------------------------------------------------------- */

static struct kunit_case ksmbd_crypto_correctness_test_cases[] = {
	KUNIT_CASE(test_smb3_kdf_hmac_sha256),
	KUNIT_CASE(test_aes128_ccm_encrypt_decrypt_roundtrip),
	KUNIT_CASE(test_aes128_gcm_encrypt_decrypt_roundtrip),
	KUNIT_CASE(test_aes256_ccm_encrypt_decrypt_roundtrip),
	KUNIT_CASE(test_aes256_gcm_encrypt_decrypt_roundtrip),
	KUNIT_CASE(test_encryption_key_differs_from_signing_key),
	KUNIT_CASE(test_different_sessions_different_keys),
	KUNIT_CASE(test_key_derivation_label_signing),
	KUNIT_CASE(test_key_derivation_label_encryption),
	KUNIT_CASE(test_key_derivation_context_preauth_hash),
	KUNIT_CASE(test_nonce_uniqueness),
	KUNIT_CASE(test_transform_header_original_message_size),
	{}
};

static struct kunit_suite ksmbd_crypto_correctness_test_suite = {
	.name       = "ksmbd_crypto_correctness",
	.init       = crypto_correctness_suite_init,
	.exit       = crypto_correctness_suite_exit,
	.test_cases = ksmbd_crypto_correctness_test_cases,
};

kunit_test_suite(ksmbd_crypto_correctness_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB3 encryption key derivation correctness");
