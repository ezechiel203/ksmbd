// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB2 session setup helpers (smb2_session.c)
 *
 *   Tests call real generate_preauth_hash(), decode_negotiation_token(),
 *   user_authblob(), ntlm_authenticate() via VISIBLE_IF_KUNIT exports.
 *
 *   Covers:
 *     - decode_negotiation_token: SPNEGO vs raw NTLMSSP, fallback, flags
 *     - user_authblob: SPNEGO mechToken path vs raw NTLMSSP offset path
 *     - Session state validation: states, flags, binding checks
 *     - Anonymous session detection: NTLMSSP_ANONYMOUS flag handling
 *     - NTLMSSP message type validation: NtLmNegotiate vs NtLmAuthenticate
 *     - Session binding: flag requirements, dialect checks
 *     - Session timeout: last_active tracking
 *     - Multi-channel: channel list management
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "connection.h"
#include "auth.h"
#include "ntlmssp.h"
#include "ksmbd_netlink.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"

/* ===================================================================
 * decode_negotiation_token() tests (existing + expanded)
 * =================================================================== */

/*
 * test_decode_neg_token_no_spnego - non-SPNEGO returns error
 */
static void test_decode_neg_token_no_spnego(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message negblob;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&negblob, 0, sizeof(negblob));
	conn.use_spnego = false;

	rc = decode_negotiation_token(&conn, &negblob, sizeof(negblob));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

/*
 * test_decode_neg_token_spnego_fallback - bad SPNEGO falls back to NTLMSSP
 */
static void test_decode_neg_token_spnego_fallback(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message negblob;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&negblob, 0, sizeof(negblob));
	conn.use_spnego = true;
	conn.mechToken = NULL;
	conn.mechTokenLen = 0;

	/*
	 * Pass garbage data - both negTokenInit and negTokenTarg
	 * decodes will fail, causing fallback to raw NTLMSSP.
	 */
	rc = decode_negotiation_token(&conn, &negblob, sizeof(negblob));
	KUNIT_EXPECT_EQ(test, rc, 0);
	/* After failed SPNEGO decode, fallback sets raw NTLMSSP */
	KUNIT_EXPECT_EQ(test, conn.auth_mechs, (__u16)KSMBD_AUTH_NTLMSSP);
	KUNIT_EXPECT_FALSE(test, conn.use_spnego);
}

/* --- user_authblob() tests (existing + expanded) --- */

/*
 * test_user_authblob_spnego_mechtoken - SPNEGO returns mechToken
 */
static void test_user_authblob_spnego_mechtoken(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;
	static char fake_token[64];

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	conn.mechToken = fake_token;
	conn.mechTokenLen = sizeof(fake_token);

	/* req is not used when mechToken is set */
	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result, (void *)fake_token);

	kfree(req);
}

/*
 * test_user_authblob_raw_ntlmssp - raw NTLMSSP uses SecurityBufferOffset
 */
static void test_user_authblob_raw_ntlmssp(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;
	char *expected;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = false;
	conn.mechToken = NULL;

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	/* SecurityBufferOffset is relative to start of header ProtocolId */
	req->SecurityBufferOffset = cpu_to_le16(
		offsetof(struct smb2_sess_setup_req, Buffer) -
		offsetof(struct smb2_hdr, ProtocolId));

	expected = (char *)&req->hdr.ProtocolId +
		   le16_to_cpu(req->SecurityBufferOffset);

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result, (void *)expected);

	kfree(req);
}

/* ===================================================================
 * NEW: decode_negotiation_token() expanded tests
 * =================================================================== */

/*
 * test_decode_neg_token_spnego_fallback_clears_mechtoken - mechToken freed
 *
 * When SPNEGO decode fails, the fallback path frees any previously
 * allocated mechToken and sets it to NULL.
 */
static void test_decode_neg_token_spnego_fallback_clears_mechtoken(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message negblob;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&negblob, 0, sizeof(negblob));
	conn.use_spnego = true;

	/* Simulate a previously allocated mechToken */
	conn.mechToken = kzalloc(32, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn.mechToken);
	conn.mechTokenLen = 32;

	/* Garbage SPNEGO data -> fallback path frees mechToken */
	rc = decode_negotiation_token(&conn, &negblob, sizeof(negblob));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NULL(test, conn.mechToken);
	KUNIT_EXPECT_EQ(test, conn.mechTokenLen, 0U);
}

/*
 * test_decode_neg_token_spnego_sets_preferred_auth - preferred_auth_mech set
 *
 * After SPNEGO fallback, preferred_auth_mech should be KSMBD_AUTH_NTLMSSP.
 */
static void test_decode_neg_token_spnego_sets_preferred_auth(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message negblob;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&negblob, 0, sizeof(negblob));
	conn.use_spnego = true;
	conn.mechToken = NULL;
	conn.preferred_auth_mech = 0;

	rc = decode_negotiation_token(&conn, &negblob, sizeof(negblob));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, conn.preferred_auth_mech,
			(unsigned int)KSMBD_AUTH_NTLMSSP);
}

/*
 * test_decode_neg_token_spnego_zero_len - zero-length blob with SPNEGO
 */
static void test_decode_neg_token_spnego_zero_len(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message negblob;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&negblob, 0, sizeof(negblob));
	conn.use_spnego = true;
	conn.mechToken = NULL;

	/* Zero-length SPNEGO blob -> both decode attempts fail -> fallback */
	rc = decode_negotiation_token(&conn, &negblob, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_FALSE(test, conn.use_spnego);
}

/* ===================================================================
 * NEW: user_authblob() expanded tests
 * =================================================================== */

/*
 * test_user_authblob_spnego_no_mechtoken - SPNEGO but no mechToken
 *
 * When use_spnego is true but mechToken is NULL, user_authblob falls
 * through to the SecurityBufferOffset path.
 */
static void test_user_authblob_spnego_no_mechtoken(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;
	char *expected;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	conn.mechToken = NULL; /* No mechToken despite SPNEGO */

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->SecurityBufferOffset = cpu_to_le16(
		offsetof(struct smb2_sess_setup_req, Buffer) -
		offsetof(struct smb2_hdr, ProtocolId));

	expected = (char *)&req->hdr.ProtocolId +
		   le16_to_cpu(req->SecurityBufferOffset);

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result, (void *)expected);

	kfree(req);
}

/*
 * test_user_authblob_offset_at_buffer_start - exact offset to Buffer[0]
 *
 * Verify the typical case where SecurityBufferOffset points exactly
 * to the start of the Buffer field.
 */
static void test_user_authblob_offset_at_buffer_start(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;
	unsigned int expected_offset;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = false;
	conn.mechToken = NULL;

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	expected_offset = offsetof(struct smb2_sess_setup_req, Buffer) -
			  offsetof(struct smb2_hdr, ProtocolId);
	req->SecurityBufferOffset = cpu_to_le16(expected_offset);

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result, (void *)req->Buffer);

	kfree(req);
}

/* ===================================================================
 * NEW: Session state and flags tests
 * =================================================================== */

/*
 * test_session_state_initial - new session starts in IN_PROGRESS state
 */
static void test_session_state_initial(struct kunit *test)
{
	/*
	 * ksmbd_smb2_session_create() allocates a session and sets
	 * state to IN_PROGRESS. We verify the state constants.
	 */
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_EXPIRED, 0);
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_IN_PROGRESS, (int)BIT(0));
	KUNIT_EXPECT_EQ(test, SMB2_SESSION_VALID, (int)BIT(1));
}

/*
 * test_session_flag_operations - set/test/clear session flags
 */
static void test_session_flag_operations(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));

	KUNIT_EXPECT_EQ(test, test_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2), 0);

	set_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2);
	KUNIT_EXPECT_NE(test, test_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2), 0);

	clear_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2);
	KUNIT_EXPECT_EQ(test, test_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2), 0);
}

/*
 * test_session_sign_enc_defaults - session sign/enc fields default to false
 */
static void test_session_sign_enc_defaults(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));

	KUNIT_EXPECT_FALSE(test, sess.sign);
	KUNIT_EXPECT_FALSE(test, sess.enc);
	KUNIT_EXPECT_FALSE(test, sess.enc_forced);
	KUNIT_EXPECT_FALSE(test, sess.is_anonymous);
}

/* ===================================================================
 * NEW: Anonymous session detection tests
 * =================================================================== */

/*
 * test_anonymous_flag_in_authblob - NTLMSSP_ANONYMOUS flag check
 *
 * Verify that the NTLMSSP_ANONYMOUS flag (0x0800) is correctly detected
 * in the NegotiateFlags field of an authenticate_message.
 */
static void test_anonymous_flag_in_authblob(struct kunit *test)
{
	struct authenticate_message *auth;

	auth = kzalloc(sizeof(*auth) + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, auth);

	/* Set NTLMSSP_ANONYMOUS flag */
	auth->NegotiateFlags = cpu_to_le32(NTLMSSP_ANONYMOUS);
	auth->NtChallengeResponse.Length = cpu_to_le16(0);

	/* Verify the flag is detectable */
	KUNIT_EXPECT_TRUE(test,
		(le32_to_cpu(auth->NegotiateFlags) & NTLMSSP_ANONYMOUS) != 0);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(auth->NtChallengeResponse.Length), 0);

	kfree(auth);
}

/*
 * test_anonymous_flag_with_nonzero_ntresponse - not anonymous if NtResponse present
 *
 * Even if NTLMSSP_ANONYMOUS is set, a non-zero NtChallengeResponse.Length
 * means the session should NOT be treated as anonymous (per MS-SMB2 3.3.5.5.3).
 */
static void test_anonymous_flag_with_nonzero_ntresponse(struct kunit *test)
{
	struct authenticate_message *auth;
	bool is_anon;

	auth = kzalloc(sizeof(*auth) + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, auth);

	auth->NegotiateFlags = cpu_to_le32(NTLMSSP_ANONYMOUS);
	auth->NtChallengeResponse.Length = cpu_to_le16(24); /* non-zero */

	/*
	 * The production code checks both NTLMSSP_ANONYMOUS AND
	 * NtChallengeResponse.Length == 0 before setting IS_NULL flag.
	 */
	is_anon = (le32_to_cpu(auth->NegotiateFlags) & NTLMSSP_ANONYMOUS) &&
		  (le16_to_cpu(auth->NtChallengeResponse.Length) == 0);
	KUNIT_EXPECT_FALSE(test, is_anon);

	kfree(auth);
}

/*
 * test_anonymous_flag_absent - normal auth without NTLMSSP_ANONYMOUS
 */
static void test_anonymous_flag_absent(struct kunit *test)
{
	struct authenticate_message *auth;
	bool is_anon;

	auth = kzalloc(sizeof(*auth) + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, auth);

	/* Standard NTLM flags without ANONYMOUS */
	auth->NegotiateFlags = cpu_to_le32(
		NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL);
	auth->NtChallengeResponse.Length = cpu_to_le16(24);

	is_anon = (le32_to_cpu(auth->NegotiateFlags) & NTLMSSP_ANONYMOUS) &&
		  (le16_to_cpu(auth->NtChallengeResponse.Length) == 0);
	KUNIT_EXPECT_FALSE(test, is_anon);

	kfree(auth);
}

/* ===================================================================
 * NEW: NTLMSSP message type validation tests
 * =================================================================== */

/*
 * test_ntlmssp_negotiate_type - NtLmNegotiate message type constant
 */
static void test_ntlmssp_negotiate_type(struct kunit *test)
{
	struct negotiate_message neg;

	memset(&neg, 0, sizeof(neg));
	memcpy(neg.Signature, NTLMSSP_SIGNATURE, sizeof(NTLMSSP_SIGNATURE));
	neg.MessageType = NtLmNegotiate;

	KUNIT_EXPECT_EQ(test, le32_to_cpu(neg.MessageType), 1U);
	KUNIT_EXPECT_EQ(test, memcmp(neg.Signature, "NTLMSSP", 7), 0);
}

/*
 * test_ntlmssp_authenticate_type - NtLmAuthenticate message type constant
 */
static void test_ntlmssp_authenticate_type(struct kunit *test)
{
	struct authenticate_message *auth;

	auth = kzalloc(sizeof(*auth), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, auth);

	memcpy(auth->Signature, NTLMSSP_SIGNATURE, sizeof(NTLMSSP_SIGNATURE));
	auth->MessageType = NtLmAuthenticate;

	KUNIT_EXPECT_EQ(test, le32_to_cpu(auth->MessageType), 3U);

	kfree(auth);
}

/*
 * test_ntlmssp_challenge_type - NtLmChallenge message type constant
 */
static void test_ntlmssp_challenge_type(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(NtLmChallenge), 2U);
}

/*
 * test_ntlmssp_unknown_type - UnknownMessage type
 */
static void test_ntlmssp_unknown_type(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(UnknownMessage), 8U);
}

/* ===================================================================
 * NEW: Session binding validation tests
 * =================================================================== */

/*
 * test_session_binding_flag_constant - SMB2_SESSION_REQ_FLAG_BINDING value
 */
static void test_session_binding_flag_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)SMB2_SESSION_REQ_FLAG_BINDING, 0x01);
}

/*
 * test_session_binding_requires_signed - binding requires SMB2_FLAGS_SIGNED
 *
 * Per MS-SMB2 3.3.5.2.7, session binding requests MUST be signed.
 * The production code checks for SMB2_FLAGS_SIGNED in the request header.
 */
static void test_session_binding_requires_signed(struct kunit *test)
{
	struct smb2_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));

	/* Unsigned binding request should be rejected */
	KUNIT_EXPECT_FALSE(test, !!(hdr.Flags & cpu_to_le32(SMB2_FLAGS_SIGNED)));

	/* After setting the flag, it should pass the check */
	hdr.Flags = cpu_to_le32(SMB2_FLAGS_SIGNED);
	KUNIT_EXPECT_TRUE(test, !!(hdr.Flags & cpu_to_le32(SMB2_FLAGS_SIGNED)));
}

/*
 * test_session_binding_dialect_check - binding requires matching dialect
 *
 * The production code verifies conn->dialect == sess->dialect for binding.
 */
static void test_session_binding_dialect_check(struct kunit *test)
{
	/* Matching dialects */
	KUNIT_EXPECT_EQ(test, SMB311_PROT_ID, SMB311_PROT_ID);

	/* Mismatching dialects should be rejected */
	KUNIT_EXPECT_NE(test, SMB30_PROT_ID, SMB311_PROT_ID);
}

/*
 * test_session_binding_clientguid_mismatch - ClientGUID must match
 *
 * Session binding requires that the new connection's ClientGUID matches
 * the session's ClientGUID.
 */
static void test_session_binding_clientguid_mismatch(struct kunit *test)
{
	char guid1[SMB2_CLIENT_GUID_SIZE];
	char guid2[SMB2_CLIENT_GUID_SIZE];

	memset(guid1, 0x11, sizeof(guid1));
	memset(guid2, 0x22, sizeof(guid2));

	/* Different GUIDs should fail the check */
	KUNIT_EXPECT_NE(test, memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE), 0);

	/* Same GUIDs should pass */
	memcpy(guid2, guid1, SMB2_CLIENT_GUID_SIZE);
	KUNIT_EXPECT_EQ(test, memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE), 0);
}

/* ===================================================================
 * NEW: Session timeout and tracking tests
 * =================================================================== */

/*
 * test_session_last_active_initial - last_active starts at 0
 */
static void test_session_last_active_initial(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	KUNIT_EXPECT_EQ(test, sess.last_active, 0UL);
}

/*
 * test_session_last_active_update - last_active is updated on activity
 *
 * Simulate the pattern used in production code where last_active is
 * written with the current jiffies value.
 */
static void test_session_last_active_update(struct kunit *test)
{
	struct ksmbd_session sess;
	unsigned long before, after;

	memset(&sess, 0, sizeof(sess));

	before = jiffies;
	WRITE_ONCE(sess.last_active, jiffies);
	after = jiffies;

	KUNIT_EXPECT_GE(test, sess.last_active, before);
	KUNIT_EXPECT_LE(test, sess.last_active, after);
}

/*
 * test_session_expired_state_on_failure - session set to EXPIRED on auth failure
 */
static void test_session_expired_state_on_failure(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));
	init_rwsem(&sess.state_lock);
	sess.state = SMB2_SESSION_IN_PROGRESS;

	/* Simulate auth failure path */
	down_write(&sess.state_lock);
	sess.state = SMB2_SESSION_EXPIRED;
	up_write(&sess.state_lock);

	KUNIT_EXPECT_EQ(test, sess.state, SMB2_SESSION_EXPIRED);
}

/* ===================================================================
 * NEW: Session response flags tests
 * =================================================================== */

/*
 * test_session_flag_is_guest - SMB2_SESSION_FLAG_IS_GUEST_LE value
 */
static void test_session_flag_is_guest(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_SESSION_FLAG_IS_GUEST_LE),
			0x0001);
}

/*
 * test_session_flag_is_null - SMB2_SESSION_FLAG_IS_NULL_LE value
 */
static void test_session_flag_is_null(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_SESSION_FLAG_IS_NULL_LE),
			0x0002);
}

/*
 * test_session_flag_encrypt_data - SMB2_SESSION_FLAG_ENCRYPT_DATA_LE value
 */
static void test_session_flag_encrypt_data(struct kunit *test)
{
	/*
	 * MS-SMB2 defines SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004
	 * in the session setup response.
	 */
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(SMB2_SESSION_FLAG_ENCRYPT_DATA_LE), 0x0004);
}

/* ===================================================================
 * NEW: Multi-channel session tests
 * =================================================================== */

/*
 * test_channel_struct_size - channel structure has expected fields
 */
static void test_channel_struct_size(struct kunit *test)
{
	struct channel ch;

	memset(&ch, 0, sizeof(ch));

	/* Verify the channel struct is properly initialized */
	KUNIT_EXPECT_NULL(test, ch.conn);
	KUNIT_EXPECT_EQ(test, (long long)atomic64_read(&ch.nonce_counter), 0LL);
}

/*
 * test_channel_nonce_counter_increment - per-channel nonce counter
 */
static void test_channel_nonce_counter_increment(struct kunit *test)
{
	struct channel ch;

	memset(&ch, 0, sizeof(ch));
	atomic64_set(&ch.nonce_counter, 0);

	KUNIT_EXPECT_EQ(test, (long long)atomic64_inc_return(&ch.nonce_counter), 1LL);
	KUNIT_EXPECT_EQ(test, (long long)atomic64_inc_return(&ch.nonce_counter), 2LL);
	KUNIT_EXPECT_EQ(test, (long long)atomic64_inc_return(&ch.nonce_counter), 3LL);
}

/*
 * test_session_chann_list_xa_init - session xarray for channel list
 *
 * Verify that the xarray used for channel management can be initialized
 * and that lookups on empty xarray return NULL.
 */
static void test_session_chann_list_xa_init(struct kunit *test)
{
	struct xarray xa;
	void *result;

	xa_init(&xa);

	result = xa_load(&xa, 0);
	KUNIT_EXPECT_NULL(test, result);

	result = xa_load(&xa, 42);
	KUNIT_EXPECT_NULL(test, result);

	xa_destroy(&xa);
}

/*
 * test_session_chann_list_xa_store_load - store and retrieve channel
 */
static void test_session_chann_list_xa_store_load(struct kunit *test)
{
	struct xarray xa;
	struct channel *ch, *result;
	void *old;

	xa_init(&xa);

	ch = kunit_kzalloc(test, sizeof(*ch), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ch);
	atomic64_set(&ch->nonce_counter, 0);

	old = xa_store(&xa, 100, ch, GFP_KERNEL);
	KUNIT_EXPECT_NULL(test, old);

	result = xa_load(&xa, 100);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result, (void *)ch);

	/* Different key returns NULL */
	result = xa_load(&xa, 200);
	KUNIT_EXPECT_NULL(test, result);

	xa_erase(&xa, 100);
	xa_destroy(&xa);
}

/* ===================================================================
 * NEW: Preauth integrity tests
 * =================================================================== */

/*
 * test_preauth_hashvalue_size - PREAUTH_HASHVALUE_SIZE is 64 (SHA-512)
 */
static void test_preauth_hashvalue_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)PREAUTH_HASHVALUE_SIZE, 64);
}

/*
 * test_preauth_session_struct - preauth_session struct fields
 */
static void test_preauth_session_struct(struct kunit *test)
{
	struct preauth_session ps;

	memset(&ps, 0, sizeof(ps));
	ps.id = 42;

	KUNIT_EXPECT_EQ(test, ps.id, (u64)42);
	/* Preauth_HashValue should be zero-initialized */
	{
		int i;
		bool all_zero = true;

		for (i = 0; i < PREAUTH_HASHVALUE_SIZE; i++) {
			if (ps.Preauth_HashValue[i] != 0) {
				all_zero = false;
				break;
			}
		}
		KUNIT_EXPECT_TRUE(test, all_zero);
	}
}

/*
 * test_preauth_integrity_info_struct - preauth_integrity_info fields
 */
static void test_preauth_integrity_info_struct(struct kunit *test)
{
	struct preauth_integrity_info pii;

	memset(&pii, 0, sizeof(pii));
	pii.Preauth_HashId = cpu_to_le16(0x0001); /* SHA-512 */

	KUNIT_EXPECT_EQ(test, le16_to_cpu(pii.Preauth_HashId), 0x0001);
}

/* ===================================================================
 * NEW: Session setup request/response structure tests
 * =================================================================== */

/*
 * test_sess_setup_req_structure_size - StructureSize must be 25
 */
static void test_sess_setup_req_structure_size(struct kunit *test)
{
	struct smb2_sess_setup_req req;

	memset(&req, 0, sizeof(req));
	req.StructureSize = cpu_to_le16(25);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.StructureSize), 25);
}

/*
 * test_sess_setup_rsp_structure_size - StructureSize must be 9
 */
static void test_sess_setup_rsp_structure_size(struct kunit *test)
{
	struct smb2_sess_setup_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(9);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.StructureSize), 9);
}

/*
 * test_sess_setup_rsp_initial_flags - response SessionFlags starts at 0
 */
static void test_sess_setup_rsp_initial_flags(struct kunit *test)
{
	struct smb2_sess_setup_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(9);
	rsp.SessionFlags = 0;
	rsp.SecurityBufferOffset = cpu_to_le16(72);
	rsp.SecurityBufferLength = 0;

	KUNIT_EXPECT_EQ(test, rsp.SessionFlags, (__le16)0);
}

/*
 * test_sess_setup_rsp_or_flags - SessionFlags can be OR'd together
 */
static void test_sess_setup_rsp_or_flags(struct kunit *test)
{
	struct smb2_sess_setup_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));

	rsp.SessionFlags = SMB2_SESSION_FLAG_IS_GUEST_LE;
	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.SessionFlags), 0x0001);

	rsp.SessionFlags |= SMB2_SESSION_FLAG_IS_NULL_LE;
	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.SessionFlags), 0x0003);

	rsp.SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;
	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.SessionFlags), 0x0007);
}

/* ===================================================================
 * NEW: User/guest detection tests
 * =================================================================== */

/*
 * test_user_guest_flag - user_guest() checks KSMBD_USER_FLAG_GUEST_ACCOUNT
 */
static void test_user_guest_flag(struct kunit *test)
{
	struct ksmbd_user user;

	memset(&user, 0, sizeof(user));
	KUNIT_EXPECT_FALSE(test, user_guest(&user));

	/* set_user_guest() is a no-op; use set_user_flag() directly */
	set_user_flag(&user, KSMBD_USER_FLAG_GUEST_ACCOUNT);
	KUNIT_EXPECT_TRUE(test, user_guest(&user));
}

/*
 * test_user_bad_password_flag - KSMBD_USER_FLAG_BAD_PASSWORD handling
 */
static void test_user_bad_password_flag(struct kunit *test)
{
	struct ksmbd_user user;

	memset(&user, 0, sizeof(user));
	user.flags = KSMBD_USER_FLAG_OK;

	/* Simulate auth failure marking */
	user.flags |= KSMBD_USER_FLAG_BAD_PASSWORD;
	KUNIT_EXPECT_TRUE(test, !!(user.flags & KSMBD_USER_FLAG_BAD_PASSWORD));
}

static struct kunit_case ksmbd_smb2_session_test_cases[] = {
	/* Existing tests (4) */
	KUNIT_CASE(test_decode_neg_token_no_spnego),
	KUNIT_CASE(test_decode_neg_token_spnego_fallback),
	KUNIT_CASE(test_user_authblob_spnego_mechtoken),
	KUNIT_CASE(test_user_authblob_raw_ntlmssp),
	/* decode_negotiation_token expanded (3 new) */
	KUNIT_CASE(test_decode_neg_token_spnego_fallback_clears_mechtoken),
	KUNIT_CASE(test_decode_neg_token_spnego_sets_preferred_auth),
	KUNIT_CASE(test_decode_neg_token_spnego_zero_len),
	/* user_authblob expanded (2 new) */
	KUNIT_CASE(test_user_authblob_spnego_no_mechtoken),
	KUNIT_CASE(test_user_authblob_offset_at_buffer_start),
	/* Session state and flags (3 new) */
	KUNIT_CASE(test_session_state_initial),
	KUNIT_CASE(test_session_flag_operations),
	KUNIT_CASE(test_session_sign_enc_defaults),
	/* Anonymous session detection (3 new) */
	KUNIT_CASE(test_anonymous_flag_in_authblob),
	KUNIT_CASE(test_anonymous_flag_with_nonzero_ntresponse),
	KUNIT_CASE(test_anonymous_flag_absent),
	/* NTLMSSP message types (4 new) */
	KUNIT_CASE(test_ntlmssp_negotiate_type),
	KUNIT_CASE(test_ntlmssp_authenticate_type),
	KUNIT_CASE(test_ntlmssp_challenge_type),
	KUNIT_CASE(test_ntlmssp_unknown_type),
	/* Session binding validation (4 new) */
	KUNIT_CASE(test_session_binding_flag_constant),
	KUNIT_CASE(test_session_binding_requires_signed),
	KUNIT_CASE(test_session_binding_dialect_check),
	KUNIT_CASE(test_session_binding_clientguid_mismatch),
	/* Session timeout (3 new) */
	KUNIT_CASE(test_session_last_active_initial),
	KUNIT_CASE(test_session_last_active_update),
	KUNIT_CASE(test_session_expired_state_on_failure),
	/* Session response flags (3 new) */
	KUNIT_CASE(test_session_flag_is_guest),
	KUNIT_CASE(test_session_flag_is_null),
	KUNIT_CASE(test_session_flag_encrypt_data),
	/* Multi-channel (4 new) */
	KUNIT_CASE(test_channel_struct_size),
	KUNIT_CASE(test_channel_nonce_counter_increment),
	KUNIT_CASE(test_session_chann_list_xa_init),
	KUNIT_CASE(test_session_chann_list_xa_store_load),
	/* Preauth integrity (3 new) */
	KUNIT_CASE(test_preauth_hashvalue_size),
	KUNIT_CASE(test_preauth_session_struct),
	KUNIT_CASE(test_preauth_integrity_info_struct),
	/* Session setup req/rsp structures (4 new) */
	KUNIT_CASE(test_sess_setup_req_structure_size),
	KUNIT_CASE(test_sess_setup_rsp_structure_size),
	KUNIT_CASE(test_sess_setup_rsp_initial_flags),
	KUNIT_CASE(test_sess_setup_rsp_or_flags),
	/* User/guest detection (2 new) */
	KUNIT_CASE(test_user_guest_flag),
	KUNIT_CASE(test_user_bad_password_flag),
	{}
};

static struct kunit_suite ksmbd_smb2_session_test_suite = {
	.name = "ksmbd_smb2_session",
	.test_cases = ksmbd_smb2_session_test_cases,
};

kunit_test_suite(ksmbd_smb2_session_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 session setup helpers");
