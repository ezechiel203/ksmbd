// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit tests for ntlm_negotiate() in smb2_session.c
 *
 *   ntlm_negotiate() processes the NTLMSSP_NEGOTIATE message and
 *   generates a challenge blob. These tests exercise the non-SPNEGO
 *   path (use_spnego=false) with minimal mock infrastructure.
 */

#include <kunit/test.h>
#include <kunit/visibility.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/nls.h>

#include "auth.h"
#include "ntlmssp.h"
#include "connection.h"
#include "smb2pdu.h"
#include "smb_common.h"
#include "ksmbd_work.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"
#include "server.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/*
 * Helper: allocate a minimal ksmbd_conn for negotiate tests.
 * Sets use_spnego=false so ntlm_negotiate takes the simple path
 * (build challenge blob directly into rsp->Buffer).
 */
static struct ksmbd_conn *alloc_negotiate_conn(struct kunit *test)
{
	struct ksmbd_conn *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);
	conn->local_nls = load_nls("utf8");
	if (!conn->local_nls)
		conn->local_nls = load_nls_default();
	refcount_set(&conn->refcnt, 1);

	/* Non-SPNEGO path: ntlm_negotiate builds challenge directly */
	conn->use_spnego = false;

	return conn;
}

static void free_negotiate_conn(struct ksmbd_conn *conn)
{
	if (conn->local_nls)
		unload_nls(conn->local_nls);
}

/*
 * Build a valid NTLMSSP_NEGOTIATE message.
 * MS-NLMP section 2.2.1.1: negotiate message format.
 */
static struct negotiate_message *build_neg_blob(struct kunit *test,
						size_t *out_len)
{
	struct negotiate_message *neg;
	size_t sz = sizeof(struct negotiate_message);

	neg = kunit_kzalloc(test, sz, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, neg);

	memcpy(neg->Signature, "NTLMSSP", 8);
	neg->MessageType = NtLmNegotiate;
	neg->NegotiateFlags = cpu_to_le32(
		NTLMSSP_NEGOTIATE_UNICODE |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_REQUEST_TARGET);

	*out_len = sz;
	return neg;
}

/*
 * test_ntlm_negotiate_non_spnego - basic negotiate produces challenge
 *
 * Exercises the non-SPNEGO path of ntlm_negotiate(). The function should:
 *   1. Decode the negotiate blob successfully
 *   2. Build a challenge blob into rsp->Buffer
 *   3. Set rsp->SecurityBufferLength > 0
 *   4. Return 0
 */
static void test_ntlm_negotiate_non_spnego(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct ksmbd_work *work;
	struct negotiate_message *negblob;
	size_t negblob_len;
	int rc;

	/*
	 * Allocate a response buffer large enough for the SMB2 header
	 * + session setup response + challenge blob.
	 */
	size_t rsp_buf_sz = 4096;
	char *rsp_buf;
	struct smb2_sess_setup_rsp *rsp;

	conn = alloc_negotiate_conn(test);

	work = kunit_kzalloc(test, sizeof(*work), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, work);

	rsp_buf = kunit_kzalloc(test, rsp_buf_sz, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, rsp_buf);

	work->conn = conn;
	work->response_buf = rsp_buf;
	work->response_sz = rsp_buf_sz;

	/*
	 * Set up rsp pointing into the response buffer.
	 * In the real code, rsp is obtained via WORK_BUFFERS macro.
	 * Here we place it at the start of response_buf for simplicity.
	 */
	rsp = (struct smb2_sess_setup_rsp *)rsp_buf;
	rsp->SecurityBufferOffset = cpu_to_le16(
		offsetof(struct smb2_sess_setup_rsp, Buffer));
	rsp->SecurityBufferLength = 0;

	negblob = build_neg_blob(test, &negblob_len);

	rc = ntlm_negotiate(work, negblob, negblob_len, rsp);
	KUNIT_EXPECT_EQ(test, rc, 0);
	/* Challenge blob should have been written */
	KUNIT_EXPECT_GT(test, le16_to_cpu(rsp->SecurityBufferLength), (u16)0);

	/*
	 * Verify the challenge blob has the NTLMSSP signature.
	 * The challenge is written at rsp->Buffer.
	 */
	{
		struct challenge_message *chg =
			(struct challenge_message *)rsp->Buffer;
		KUNIT_EXPECT_EQ(test,
				memcmp(chg->Signature, "NTLMSSP", 7), 0);
		KUNIT_EXPECT_EQ(test, chg->MessageType,
				(__le32)NtLmChallenge);
	}

	free_negotiate_conn(conn);
}

/*
 * test_ntlm_negotiate_too_small_blob - blob smaller than negotiate_message
 *
 * ksmbd_decode_ntlmssp_neg_blob should reject undersized blobs.
 */
static void test_ntlm_negotiate_too_small_blob(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct ksmbd_work *work;
	struct negotiate_message negblob;
	int rc;

	size_t rsp_buf_sz = 4096;
	char *rsp_buf;
	struct smb2_sess_setup_rsp *rsp;

	conn = alloc_negotiate_conn(test);

	work = kunit_kzalloc(test, sizeof(*work), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, work);

	rsp_buf = kunit_kzalloc(test, rsp_buf_sz, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, rsp_buf);

	work->conn = conn;
	work->response_buf = rsp_buf;
	work->response_sz = rsp_buf_sz;

	rsp = (struct smb2_sess_setup_rsp *)rsp_buf;
	rsp->SecurityBufferOffset = cpu_to_le16(
		offsetof(struct smb2_sess_setup_rsp, Buffer));
	rsp->SecurityBufferLength = 0;

	/* Valid signature but truncated to 4 bytes */
	memset(&negblob, 0, sizeof(negblob));
	memcpy(negblob.Signature, "NTLMSSP", 8);
	negblob.MessageType = NtLmNegotiate;

	rc = ntlm_negotiate(work, &negblob, 4, rsp);
	/* Should fail: blob too small for decode */
	KUNIT_EXPECT_NE(test, rc, 0);

	free_negotiate_conn(conn);
}

static struct kunit_case ksmbd_session_negotiate_test_cases[] = {
	KUNIT_CASE(test_ntlm_negotiate_non_spnego),
	KUNIT_CASE(test_ntlm_negotiate_too_small_blob),
	{}
};

static struct kunit_suite ksmbd_session_negotiate_test_suite = {
	.name = "ksmbd_session_negotiate",
	.test_cases = ksmbd_session_negotiate_test_cases,
};

kunit_test_suite(ksmbd_session_negotiate_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd NTLM negotiate phase (smb2_session.c)");
