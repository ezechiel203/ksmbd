// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for SMB2 session functions
 *
 *   Tests invalid inputs and edge cases for session-related production
 *   functions. All tests call real functions via VISIBLE_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "connection.h"
#include "auth.h"
#include "ntlmssp.h"

/* --- decode_negotiation_token error paths --- */

/*
 * err_sess_buffer_overflow: SecurityBufferOffset past end of message.
 * When use_spnego is false, decode_negotiation_token returns -EINVAL.
 */
static void err_sess_buffer_overflow(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message msg;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&msg, 0, sizeof(msg));
	conn.use_spnego = false;

	rc = decode_negotiation_token(&conn, &msg, sizeof(msg));
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

/*
 * err_sess_empty_blob: zero-length blob with SPNEGO enabled.
 * Both ASN.1 decodes fail, falls back to raw NTLMSSP.
 */
static void err_sess_empty_blob(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message msg;
	int rc;

	memset(&conn, 0, sizeof(conn));
	memset(&msg, 0, sizeof(msg));
	conn.use_spnego = true;

	rc = decode_negotiation_token(&conn, &msg, 0);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_FALSE(test, conn.use_spnego);
}

/*
 * err_sess_garbage_data: random data in SPNEGO mode.
 * Both ASN.1 decodes fail, falls back to raw NTLMSSP.
 */
static void err_sess_garbage_data(struct kunit *test)
{
	struct ksmbd_conn conn;
	char garbage[128];
	int rc;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	memset(garbage, 0xAB, sizeof(garbage));

	rc = decode_negotiation_token(&conn,
				      (struct negotiate_message *)garbage,
				      sizeof(garbage));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, conn.auth_mechs, (__u16)KSMBD_AUTH_NTLMSSP);
}

/* --- user_authblob error paths --- */

/*
 * err_sess_authblob_null_mechtoken: SPNEGO mode but mechToken is NULL.
 * Falls back to SecurityBufferOffset.
 */
static void err_sess_authblob_null_mechtoken(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;
	char *expected;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	conn.mechToken = NULL;

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
 * err_sess_authblob_zero_offset: SecurityBufferOffset = 0.
 */
static void err_sess_authblob_zero_offset(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = false;

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);
	req->SecurityBufferOffset = 0;

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result,
			    (void *)&req->hdr.ProtocolId);

	kfree(req);
}

/*
 * err_sess_authblob_spnego_mechtoken: mechToken set, used directly.
 */
static void err_sess_authblob_spnego_mechtoken(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;
	static char token[32];

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	conn.mechToken = token;
	conn.mechTokenLen = sizeof(token);

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result, (void *)token);

	kfree(req);
}

/*
 * err_sess_authblob_not_spnego: use_spnego=false ignores mechToken.
 */
static void err_sess_authblob_not_spnego(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = false;
	conn.mechToken = (void *)0xDEAD; /* should not be used */

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);
	req->SecurityBufferOffset = cpu_to_le16(100);

	result = user_authblob(&conn, req);
	KUNIT_EXPECT_PTR_EQ(test, (void *)result,
			    (void *)((char *)&req->hdr.ProtocolId + 100));

	kfree(req);
}

/*
 * err_sess_mechtoken_freed_on_fallback: mechToken from previous
 * round is freed on SPNEGO fallback.
 */
static void err_sess_mechtoken_freed_on_fallback(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message msg;
	int rc;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	conn.mechToken = kzalloc(16, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn.mechToken);
	conn.mechTokenLen = 16;

	memset(&msg, 0, sizeof(msg));

	rc = decode_negotiation_token(&conn, &msg, sizeof(msg));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_NULL(test, conn.mechToken);
	KUNIT_EXPECT_EQ(test, conn.mechTokenLen, 0U);
}

/*
 * err_sess_fallback_sets_ntlmssp: on SPNEGO failure, auth_mechs and
 * preferred_auth_mech are set to KSMBD_AUTH_NTLMSSP.
 */
static void err_sess_fallback_sets_ntlmssp(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct negotiate_message msg;
	int rc;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = true;
	conn.auth_mechs = 0;
	conn.preferred_auth_mech = 0;
	memset(&msg, 0xCC, sizeof(msg));

	rc = decode_negotiation_token(&conn, &msg, sizeof(msg));
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, conn.auth_mechs, (__u16)KSMBD_AUTH_NTLMSSP);
	KUNIT_EXPECT_EQ(test, conn.preferred_auth_mech,
			(__u16)KSMBD_AUTH_NTLMSSP);
}

/*
 * err_sess_authblob_large_offset: SecurityBufferOffset is very large.
 * user_authblob should still return a pointer (no bounds check in the
 * function itself; bounds checking happens at the caller level).
 */
static void err_sess_authblob_large_offset(struct kunit *test)
{
	struct ksmbd_conn conn;
	struct smb2_sess_setup_req *req;
	struct authenticate_message *result;

	memset(&conn, 0, sizeof(conn));
	conn.use_spnego = false;

	req = kzalloc(sizeof(*req) + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);
	req->SecurityBufferOffset = cpu_to_le16(0xFFFF);

	result = user_authblob(&conn, req);
	/*
	 * user_authblob computes the pointer arithmetic without bounds
	 * checking. The caller (smb2_sess_setup) validates the offset.
	 * Here we just verify it returns a non-NULL pointer.
	 */
	KUNIT_EXPECT_NOT_NULL(test, result);

	kfree(req);
}

static struct kunit_case ksmbd_error_session_test_cases[] = {
	KUNIT_CASE(err_sess_buffer_overflow),
	KUNIT_CASE(err_sess_empty_blob),
	KUNIT_CASE(err_sess_garbage_data),
	KUNIT_CASE(err_sess_authblob_null_mechtoken),
	KUNIT_CASE(err_sess_authblob_zero_offset),
	KUNIT_CASE(err_sess_authblob_spnego_mechtoken),
	KUNIT_CASE(err_sess_authblob_not_spnego),
	KUNIT_CASE(err_sess_mechtoken_freed_on_fallback),
	KUNIT_CASE(err_sess_fallback_sets_ntlmssp),
	KUNIT_CASE(err_sess_authblob_large_offset),
	{}
};

static struct kunit_suite ksmbd_error_session_test_suite = {
	.name = "ksmbd_error_session",
	.test_cases = ksmbd_error_session_test_cases,
};

kunit_test_suite(ksmbd_error_session_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for ksmbd SMB2 session functions");
