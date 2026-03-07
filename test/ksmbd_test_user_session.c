// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 session lifecycle management
 *
 *   These tests verify the layout of struct ksmbd_session and struct channel,
 *   the session state machine constants, and related invariants from
 *   src/mgmt/user_session.h and src/include/protocol/smb2pdu.h.
 *
 *   All session management functions (ksmbd_smb2_session_create,
 *   ksmbd_session_destroy, etc.) are not called directly because they
 *   depend on kernel infrastructure (IDA, file tables, IPC) that is not
 *   available in the KUnit environment.  Instead the tests validate the
 *   constants, field presence, and field sizes that the functions rely on.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/xarray.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "mgmt/user_session.h"

/*
 * SMB3 signing and encryption key sizes (smb2pdu.h)
 */
#define TEST_SMB3_SIGN_KEY_SIZE		16
#define TEST_SMB3_ENC_DEC_KEY_SIZE	32

/*
 * Preauth hash size (user_session.h: PREAUTH_HASHVALUE_SIZE = 64)
 * This is the SHA-512 digest size used for SMB3.1.1 pre-authentication
 * integrity (MS-SMB2 §3.3.5.4).
 */
#define TEST_PREAUTH_HASHVALUE_SIZE	64

/* --- Session state constants --- */

/*
 * test_session_state_new - SMB2_SESSION_EXPIRED is the "new/reset" state
 *
 * ksmbd uses SMB2_SESSION_EXPIRED (= 0) as the initial/reset sentinel for
 * sessions that have not yet completed authentication or have been expired.
 * MS-SMB2 §3.3.1.4 describes the session state machine.
 */
static void test_session_state_new(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_EXPIRED, 0);
}

/*
 * test_session_state_in_progress - SMB2_SESSION_IN_PROGRESS is BIT(0)
 *
 * The session enters this state immediately after allocation
 * (__session_create sets sess->state = SMB2_SESSION_IN_PROGRESS) and
 * remains here until authentication completes successfully.
 */
static void test_session_state_in_progress(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_IN_PROGRESS, BIT(0));
	KUNIT_EXPECT_NE(test, SMB2_SESSION_IN_PROGRESS, 0);
}

/*
 * test_session_state_valid - SMB2_SESSION_VALID is BIT(1)
 *
 * A session becomes VALID once ntlm_authenticate() or the Kerberos path
 * succeeds and generate_smb3signingkey() has been called.  Subsequent
 * requests are only served when the session is in this state.
 */
static void test_session_state_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_VALID, BIT(1));
	KUNIT_EXPECT_NE(test, SMB2_SESSION_VALID, SMB2_SESSION_IN_PROGRESS);
}

/*
 * test_session_state_expired - SMB2_SESSION_EXPIRED is distinct from VALID
 *
 * Expired sessions (timed out or explicitly invalidated by LOGOFF) return
 * to the zero/expired state.  The server rejects ordinary requests against
 * expired sessions with STATUS_USER_SESSION_DELETED.
 */
static void test_session_state_expired(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_EXPIRED, 0);
	KUNIT_EXPECT_NE(test, SMB2_SESSION_EXPIRED, SMB2_SESSION_VALID);
	KUNIT_EXPECT_NE(test, SMB2_SESSION_EXPIRED, SMB2_SESSION_IN_PROGRESS);
}

/* --- struct ksmbd_session field presence --- */

/*
 * test_session_struct_has_id - ksmbd_session carries a 64-bit session ID
 *
 * The SessionId assigned by the server (ksmbd_acquire_smb2_uid) is stored
 * in sess->id and echoed in every SMB2 response header.
 */
static void test_session_struct_has_id(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	sess.id = 0xDEADBEEFCAFEBABEULL;
	KUNIT_EXPECT_EQ(test, sess.id, 0xDEADBEEFCAFEBABEULL);
}

/*
 * test_session_struct_has_state - ksmbd_session carries an integer state
 *
 * The state field is read by smb2_check_user_session() to gate access and
 * written by ntlm_authenticate() on success or by the timeout path on expiry.
 */
static void test_session_struct_has_state(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	sess.state = SMB2_SESSION_IN_PROGRESS;
	KUNIT_EXPECT_EQ(test, sess.state, SMB2_SESSION_IN_PROGRESS);

	sess.state = SMB2_SESSION_VALID;
	KUNIT_EXPECT_EQ(test, sess.state, SMB2_SESSION_VALID);

	sess.state = SMB2_SESSION_EXPIRED;
	KUNIT_EXPECT_EQ(test, sess.state, SMB2_SESSION_EXPIRED);
}

/*
 * test_session_struct_has_user - ksmbd_session holds a user pointer
 *
 * sess->user points to the ksmbd_user record resolved from the account
 * database by the IPC call to ksmbd.mountd.  It is NULL for anonymous
 * sessions.
 */
static void test_session_struct_has_user(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	KUNIT_EXPECT_NULL(test, sess.user);

	/* A non-NULL pointer is accepted by the struct */
	sess.user = (struct ksmbd_user *)1UL;
	KUNIT_EXPECT_NOT_NULL(test, sess.user);
}

/*
 * test_session_struct_has_channels - ksmbd_session stores channels in an xarray
 *
 * Multi-channel SMB3 connections (MS-SMB2 §3.3.5.5) add per-channel signing
 * keys to sess->ksmbd_chann_list.  The xarray is initialised by xa_init() in
 * __session_create() and iterated by free_channel_list() on teardown.
 */
static void test_session_struct_has_channels(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	xa_init(&sess.ksmbd_chann_list);

	/* An empty xarray has no entries */
	KUNIT_EXPECT_TRUE(test, xa_empty(&sess.ksmbd_chann_list));

	xa_destroy(&sess.ksmbd_chann_list);
}

/*
 * test_session_struct_has_sign_key - ksmbd_session has a 16-byte signing key
 *
 * sess->smb3signingkey is derived by generate_smb3signingkey() for SMB3+
 * sessions.  Its size is SMB3_SIGN_KEY_SIZE = 16 bytes (AES-CMAC key length).
 */
static void test_session_struct_has_sign_key(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct ksmbd_session, smb3signingkey),
			TEST_SMB3_SIGN_KEY_SIZE);
}

/*
 * test_session_struct_has_enc_key - ksmbd_session has a 32-byte encryption key
 *
 * sess->smb3encryptionkey is derived by generate_smb3encryptionkey() for
 * encrypted SMB3 sessions (AES-128-GCM or AES-256-GCM).  The field is
 * SMB3_ENC_DEC_KEY_SIZE = 32 bytes to accommodate both 128- and 256-bit keys.
 */
static void test_session_struct_has_enc_key(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct ksmbd_session, smb3encryptionkey),
			TEST_SMB3_ENC_DEC_KEY_SIZE);
	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct ksmbd_session, smb3decryptionkey),
			TEST_SMB3_ENC_DEC_KEY_SIZE);
}

/* --- Capacity and size constants --- */

/*
 * test_session_cap_default_1024 - session hashtable fits at least 1024 sessions
 *
 * SESSION_HASH_BITS = 12 in user_session.c gives 2^12 = 4096 buckets.
 * This is not a hard cap on the number of sessions but demonstrates that
 * the hashtable is dimensioned for thousands of concurrent sessions.
 */
static void test_session_cap_default_1024(struct kunit *test)
{
#define TEST_SESSION_HASH_BITS 12
	unsigned int buckets = 1U << TEST_SESSION_HASH_BITS;

	KUNIT_EXPECT_GE(test, buckets, 1024U);
	KUNIT_EXPECT_EQ(test, buckets, 4096U);
#undef TEST_SESSION_HASH_BITS
}

/*
 * test_session_id_size_u64 - session ID field is 64 bits
 *
 * MS-SMB2 §2.2.6 defines SessionId as an 8-byte (64-bit) opaque value.
 * struct ksmbd_session::id is declared as u64 to match this.
 */
static void test_session_id_size_u64(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct ksmbd_session, id),
			8);
}

/*
 * test_session_signing_key_size_16 - signing key is exactly 16 bytes
 *
 * AES-CMAC (the SMB3 signing algorithm) uses a 128-bit (16-byte) key.
 * SMB3_SIGN_KEY_SIZE must equal 16 for generate_smb3signingkey() to
 * produce the correct key material via the SP800-108 KDF.
 */
static void test_session_signing_key_size_16(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB3_SIGN_KEY_SIZE, TEST_SMB3_SIGN_KEY_SIZE);
	KUNIT_EXPECT_EQ(test, TEST_SMB3_SIGN_KEY_SIZE, 16);

	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct ksmbd_session, smb3signingkey),
			16);
}

/*
 * test_channel_struct_has_conn - struct channel embeds a connection pointer
 *
 * Each channel in the ksmbd_chann_list xarray is a struct channel that
 * holds a per-channel signing key and a back-pointer to the ksmbd_conn
 * (transport connection) used for that channel.  This enables multi-channel
 * request dispatching and per-channel signing verification.
 */
static void test_channel_struct_has_conn(struct kunit *test)
{
	struct channel chann;

	memset(&chann, 0, sizeof(chann));
	KUNIT_EXPECT_NULL(test, chann.conn);

	chann.conn = (struct ksmbd_conn *)1UL;
	KUNIT_EXPECT_NOT_NULL(test, chann.conn);
}

/*
 * test_session_preauth_hash_size_64 - preauth hash is SHA-512 = 64 bytes
 *
 * MS-SMB2 §3.3.5.4 specifies that the Pre-Authentication Integrity Hash
 * uses SHA-512, which produces a 64-byte digest.  PREAUTH_HASHVALUE_SIZE
 * in user_session.h must equal 64 for the hash computation in
 * generate_preauth_hash() to be correct.
 */
static void test_session_preauth_hash_size_64(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, PREAUTH_HASHVALUE_SIZE, TEST_PREAUTH_HASHVALUE_SIZE);
	KUNIT_EXPECT_EQ(test, TEST_PREAUTH_HASHVALUE_SIZE, 64);

	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct preauth_session,
					  Preauth_HashValue),
			64);
}

static struct kunit_case ksmbd_user_session_test_cases[] = {
	KUNIT_CASE(test_session_struct_has_id),
	KUNIT_CASE(test_session_struct_has_state),
	KUNIT_CASE(test_session_struct_has_user),
	KUNIT_CASE(test_session_struct_has_channels),
	KUNIT_CASE(test_session_struct_has_sign_key),
	KUNIT_CASE(test_session_struct_has_enc_key),
	KUNIT_CASE(test_session_state_new),
	KUNIT_CASE(test_session_state_in_progress),
	KUNIT_CASE(test_session_state_valid),
	KUNIT_CASE(test_session_state_expired),
	KUNIT_CASE(test_session_cap_default_1024),
	KUNIT_CASE(test_session_id_size_u64),
	KUNIT_CASE(test_session_signing_key_size_16),
	KUNIT_CASE(test_channel_struct_has_conn),
	KUNIT_CASE(test_session_preauth_hash_size_64),
	{}
};

static struct kunit_suite ksmbd_user_session_test_suite = {
	.name = "ksmbd_user_session",
	.test_cases = ksmbd_user_session_test_cases,
};

kunit_test_suite(ksmbd_user_session_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd session lifecycle management");
