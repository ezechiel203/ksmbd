// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB1 protocol state machine (MS-SMB 3.3.5)
 *
 *   These tests verify the SMB1 protocol state machine transitions
 *   as defined in [MS-SMB] sections 3.3.1 through 3.3.6, and the
 *   SMB1-to-SMB2 upgrade path described in [MS-SMB2] section 3.3.5.4.
 *   We replicate the state enum and transition checks in a
 *   self-contained manner since the full server stack cannot be
 *   instantiated in KUnit.
 *
 *   Spec references:
 *     [MS-SMB] 3.3.1   - Server Abstract Data Model
 *     [MS-SMB] 3.3.3   - Initialization
 *     [MS-SMB] 3.3.5.1 - Receiving Any Message (session validation)
 *     [MS-SMB] 3.3.5.2 - Receiving SMB_COM_NEGOTIATE
 *     [MS-SMB] 3.3.5.3 - Receiving SMB_COM_SESSION_SETUP_ANDX
 *     [MS-SMB] 3.3.5.4 - Receiving SMB_COM_TREE_CONNECT_ANDX
 *     [MS-SMB] 3.3.5.5 - Receiving SMB_COM_NT_CREATE_ANDX
 *     [MS-SMB] 3.3.6.1 - Authentication Expiration Timer Event
 *     [MS-SMB2] 3.3.5.4 - SMB1->SMB2 upgrade via wildcard dialect
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "connection.h"

/* ================================================================
 * Connection states: use the real KSMBD_SESS_* constants from
 * connection.h via aliased names for readability.
 * ================================================================
 */

enum smb1_conn_status {
	SMB1_CONN_NEW = KSMBD_SESS_NEW,
	SMB1_CONN_GOOD = KSMBD_SESS_GOOD,
	SMB1_CONN_EXITING = KSMBD_SESS_EXITING,
	SMB1_CONN_NEED_RECONNECT = KSMBD_SESS_NEED_RECONNECT,
	SMB1_CONN_NEED_NEGOTIATE = KSMBD_SESS_NEED_NEGOTIATE,
	SMB1_CONN_NEED_SETUP = KSMBD_SESS_NEED_SETUP,
	SMB1_CONN_RELEASING = KSMBD_SESS_RELEASING,
};

/*
 * SMB1 session states (from [MS-SMB] 3.3.1.5):
 *   InProgress     - session setup exchange in progress for the first time
 *   Valid          - session is valid, session key and UID available
 *   Expired        - Kerberos ticket expired, needs re-establishment
 *   ReauthInProgress - re-authentication in progress for expired/valid session
 */
enum smb1_session_state {
	SMB1_SESSION_NONE = 0,		/* No session allocated */
	SMB1_SESSION_IN_PROGRESS,	/* Authentication in progress */
	SMB1_SESSION_VALID,		/* Fully authenticated */
	SMB1_SESSION_EXPIRED,		/* Session expired */
	SMB1_SESSION_REAUTH_IN_PROGRESS, /* Re-authentication in progress */
};

/* SMB1 command codes (from smb1pdu.h) */
#define SMB_COM_CREATE_DIRECTORY	0x00
#define SMB_COM_DELETE_DIRECTORY	0x01
#define SMB_COM_CLOSE			0x04
#define SMB_COM_FLUSH			0x05
#define SMB_COM_DELETE			0x06
#define SMB_COM_RENAME			0x07
#define SMB_COM_READ_ANDX		0x2E
#define SMB_COM_WRITE_ANDX		0x2F
#define SMB_COM_LOCKING_ANDX		0x24
#define SMB_COM_TREE_DISCONNECT		0x71
#define SMB_COM_NEGOTIATE		0x72
#define SMB_COM_SESSION_SETUP_ANDX	0x73
#define SMB_COM_LOGOFF_ANDX		0x74
#define SMB_COM_TREE_CONNECT_ANDX	0x75
#define SMB_COM_NT_CREATE_ANDX		0xA2
#define SMB_COM_NT_CANCEL		0xA4
#define SMB_COM_NT_TRANSACT		0xA0
#define SMB_COM_ECHO			0x2B
#define SMB_COM_OPEN_ANDX		0x2D
#define SMB_COM_TRANSACTION2		0x32

/* SMB2 dialect IDs for upgrade testing */
#define SMB20_PROT_ID		0x0202
#define SMB21_PROT_ID		0x0210
#define SMB2X_PROT_ID		0x02FF	/* wildcard for multi-protocol negotiate */
#define SMB30_PROT_ID		0x0300
#define SMB311_PROT_ID		0x0311
#define SMB1_PROT_ID		0x0001	/* NT LM 0.12 */
#define BAD_PROT_ID_SMB1	0xFFFF

/* NTSTATUS codes */
#define STATUS_SUCCESS			0x00000000
#define STATUS_MORE_PROCESSING_REQUIRED	0xC0000016
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_SMB_BAD_UID		0x005B0002
#define STATUS_NETWORK_SESSION_EXPIRED	0xC000035C
#define STATUS_NETWORK_NAME_DELETED	0xC00000C9
#define STATUS_FILE_CLOSED		0xC0000128
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_NOT_SUPPORTED		0xC00000BB
#define STATUS_SMB_BAD_TID		0xC00000C9

/* ================================================================
 * Test state machine structures
 * ================================================================
 */

#define TEST_MAX_TREE_CONNECTS	8
#define TEST_MAX_OPEN_FILES	16

struct smb1_test_open_file {
	u16	fid;		/* 0 = unused slot */
	u16	tid;
	bool	closed;
};

struct smb1_test_tree_connect {
	u16	tid;		/* 0 = unused slot */
	bool	disconnected;
};

struct smb1_test_session {
	u16				uid;
	enum smb1_session_state		state;
	struct smb1_test_tree_connect	trees[TEST_MAX_TREE_CONNECTS];
	struct smb1_test_open_file	opens[TEST_MAX_OPEN_FILES];
};

struct smb1_test_conn {
	enum smb1_conn_status		status;
	bool				need_neg;
	bool				smb1_conn;	/* true for pure SMB1 */
	u16				dialect;
	struct smb1_test_session	*session;
	bool				upgraded_to_smb2; /* SMB1->SMB2 upgrade */
};

/* ================================================================
 * State machine helpers (replicate ksmbd SMB1 logic)
 * ================================================================
 */

static bool smb1_conn_good(struct smb1_test_conn *conn)
{
	return conn->status == SMB1_CONN_GOOD;
}

static bool smb1_conn_need_negotiate(struct smb1_test_conn *conn)
{
	return conn->status == SMB1_CONN_NEED_NEGOTIATE;
}

static bool smb1_conn_need_setup(struct smb1_test_conn *conn)
{
	return conn->status == SMB1_CONN_NEED_SETUP;
}

static bool smb1_conn_exiting(struct smb1_test_conn *conn)
{
	return conn->status == SMB1_CONN_EXITING;
}

/*
 * [MS-SMB] 3.3.5.1 "Receiving Any Message" - Session Validation
 *
 * If SMB_Header.UID is not zero, the server MUST check the session state:
 *   - If AuthenticationState is Expired or ReauthInProgress:
 *       Allow: SMB_COM_CLOSE, SMB_COM_LOGOFF_ANDX, SMB_COM_FLUSH,
 *              SMB_COM_LOCKING_ANDX, SMB_COM_TREE_DISCONNECT
 *       Otherwise: STATUS_NETWORK_SESSION_EXPIRED
 *   - If SessionTable is not empty, UID not found, and not SESSION_SETUP:
 *       STATUS_SMB_BAD_UID
 *   - If AuthenticationState is InProgress and not SESSION_SETUP:
 *       STATUS_INVALID_HANDLE
 *   - If AuthenticationState is Valid: allow all operations
 */
static u32 smb1_check_session_state(struct smb1_test_session *sess, u8 cmd)
{
	if (!sess)
		return STATUS_SMB_BAD_UID;

	switch (sess->state) {
	case SMB1_SESSION_VALID:
		return STATUS_SUCCESS;

	case SMB1_SESSION_EXPIRED:
	case SMB1_SESSION_REAUTH_IN_PROGRESS:
		/* Only limited commands allowed per [MS-SMB] 3.3.5.1 */
		if (cmd == SMB_COM_CLOSE ||
		    cmd == SMB_COM_LOGOFF_ANDX ||
		    cmd == SMB_COM_FLUSH ||
		    cmd == SMB_COM_LOCKING_ANDX ||
		    cmd == SMB_COM_TREE_DISCONNECT)
			return STATUS_SUCCESS;
		/* Re-auth allowed via SESSION_SETUP */
		if (cmd == SMB_COM_SESSION_SETUP_ANDX)
			return STATUS_SUCCESS;
		return STATUS_NETWORK_SESSION_EXPIRED;

	case SMB1_SESSION_IN_PROGRESS:
		/* Only SESSION_SETUP is allowed to continue auth */
		if (cmd == SMB_COM_SESSION_SETUP_ANDX)
			return STATUS_SUCCESS;
		return STATUS_INVALID_HANDLE;

	case SMB1_SESSION_NONE:
	default:
		return STATUS_SMB_BAD_UID;
	}
}

/*
 * Check connection state for an SMB1 command.
 * [MS-CIFS] requires NEGOTIATE before any other command.
 * SMB_COM_NEGOTIATE itself is only valid before dialect is established.
 */
static u32 smb1_check_conn_state_for_command(struct smb1_test_conn *conn,
					     u8 cmd)
{
	/* Connection exiting - reject everything */
	if (smb1_conn_exiting(conn))
		return STATUS_NETWORK_SESSION_EXPIRED;

	/*
	 * If upgraded to SMB2, all SMB1 commands (except NEGOTIATE
	 * which triggered the upgrade) must be rejected.
	 */
	if (conn->upgraded_to_smb2 && cmd != SMB_COM_NEGOTIATE)
		return STATUS_NOT_SUPPORTED;

	/*
	 * NEGOTIATE must not be repeated after dialect is established.
	 * [MS-SMB] 3.3.5.2 / Figure 4: "the SMB_COM_NEGOTIATE exchange
	 * MUST NOT be repeated over the same SMB connection"
	 */
	if (cmd == SMB_COM_NEGOTIATE && !conn->need_neg)
		return STATUS_INVALID_PARAMETER;

	/*
	 * Non-NEGOTIATE commands before NEGOTIATE is complete are rejected.
	 */
	if (cmd != SMB_COM_NEGOTIATE && conn->need_neg)
		return STATUS_INVALID_PARAMETER;

	/*
	 * SESSION_SETUP requires at least NEED_SETUP or GOOD state.
	 */
	if (cmd == SMB_COM_SESSION_SETUP_ANDX) {
		if (!smb1_conn_need_setup(conn) && !smb1_conn_good(conn))
			return STATUS_INVALID_PARAMETER;
	}

	/*
	 * Commands requiring a session (everything except NEGOTIATE,
	 * SESSION_SETUP, ECHO, NT_CANCEL) need GOOD state.
	 */
	if (cmd != SMB_COM_NEGOTIATE &&
	    cmd != SMB_COM_SESSION_SETUP_ANDX &&
	    cmd != SMB_COM_ECHO &&
	    cmd != SMB_COM_NT_CANCEL) {
		if (!smb1_conn_good(conn))
			return STATUS_SMB_BAD_UID;
	}

	return STATUS_SUCCESS;
}

/*
 * Simulate SMB1 NEGOTIATE: transitions conn from NEED_NEGOTIATE to
 * NEED_SETUP. If SMB2 dialect is detected, trigger upgrade.
 */
static u32 smb1_do_negotiate(struct smb1_test_conn *conn, u16 dialect,
			     bool has_smb2_dialect)
{
	u32 status;

	status = smb1_check_conn_state_for_command(conn, SMB_COM_NEGOTIATE);
	if (status != STATUS_SUCCESS)
		return status;

	conn->need_neg = false;

	if (has_smb2_dialect) {
		/*
		 * SMB1 NEGOTIATE with SMB2 dialect(s): upgrade to SMB2.
		 * Force wildcard dialect 0x02FF (MS-SMB2 3.3.5.4).
		 * After this, SMB1 commands are no longer accepted.
		 */
		conn->dialect = SMB2X_PROT_ID;
		conn->smb1_conn = false;
		conn->upgraded_to_smb2 = true;
		conn->status = SMB1_CONN_NEED_NEGOTIATE;
		conn->need_neg = true;
		return STATUS_SUCCESS;
	}

	/* Pure SMB1 negotiation: NT LM 0.12 */
	conn->dialect = dialect;
	conn->smb1_conn = true;
	conn->status = SMB1_CONN_NEED_SETUP;
	return STATUS_SUCCESS;
}

/*
 * Simulate SMB1 SESSION_SETUP_ANDX success.
 * [MS-SMB] 3.3.5.3: On success, AuthenticationState -> Valid.
 */
static u32 smb1_do_session_setup(struct smb1_test_conn *conn, u16 uid)
{
	u32 status;

	status = smb1_check_conn_state_for_command(conn,
						   SMB_COM_SESSION_SETUP_ANDX);
	if (status != STATUS_SUCCESS)
		return status;

	if (!conn->session) {
		conn->session = kzalloc(sizeof(*conn->session), GFP_KERNEL);
		if (!conn->session)
			return STATUS_INVALID_PARAMETER;
		conn->session->uid = uid;
		conn->session->state = SMB1_SESSION_IN_PROGRESS;
	}

	/* Simulate successful auth completion */
	conn->session->state = SMB1_SESSION_VALID;
	conn->status = SMB1_CONN_GOOD;
	return STATUS_SUCCESS;
}

/*
 * Simulate SMB1 TREE_CONNECT_ANDX.
 */
static u32 smb1_do_tree_connect(struct smb1_test_conn *conn, u16 tid)
{
	int i;
	u32 status;

	status = smb1_check_conn_state_for_command(conn,
						   SMB_COM_TREE_CONNECT_ANDX);
	if (status != STATUS_SUCCESS)
		return status;

	status = smb1_check_session_state(conn->session,
					  SMB_COM_TREE_CONNECT_ANDX);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_TREE_CONNECTS; i++) {
		if (conn->session->trees[i].tid == 0) {
			conn->session->trees[i].tid = tid;
			conn->session->trees[i].disconnected = false;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_PARAMETER;
}

/*
 * Check tree connect validity.
 */
static u32 smb1_check_tree(struct smb1_test_session *sess, u16 tid)
{
	int i;

	if (!sess || sess->state != SMB1_SESSION_VALID)
		return STATUS_SMB_BAD_UID;

	for (i = 0; i < TEST_MAX_TREE_CONNECTS; i++) {
		if (sess->trees[i].tid == tid && tid != 0) {
			if (sess->trees[i].disconnected)
				return STATUS_SMB_BAD_TID;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_SMB_BAD_TID;
}

/*
 * Simulate SMB1 NT_CREATE_ANDX (open file).
 */
static u32 smb1_do_create(struct smb1_test_conn *conn, u16 tid, u16 fid)
{
	int i;
	u32 status;

	status = smb1_check_conn_state_for_command(conn,
						   SMB_COM_NT_CREATE_ANDX);
	if (status != STATUS_SUCCESS)
		return status;

	status = smb1_check_session_state(conn->session,
					  SMB_COM_NT_CREATE_ANDX);
	if (status != STATUS_SUCCESS)
		return status;

	status = smb1_check_tree(conn->session, tid);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_OPEN_FILES; i++) {
		if (conn->session->opens[i].fid == 0) {
			conn->session->opens[i].fid = fid;
			conn->session->opens[i].tid = tid;
			conn->session->opens[i].closed = false;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_PARAMETER;
}

/*
 * Simulate SMB_COM_CLOSE.
 */
static u32 smb1_do_close(struct smb1_test_conn *conn, u16 fid)
{
	int i;
	u32 status;

	status = smb1_check_conn_state_for_command(conn, SMB_COM_CLOSE);
	if (status != STATUS_SUCCESS)
		return status;

	if (!conn->session)
		return STATUS_SMB_BAD_UID;

	for (i = 0; i < TEST_MAX_OPEN_FILES; i++) {
		if (conn->session->opens[i].fid == fid && fid != 0) {
			if (conn->session->opens[i].closed)
				return STATUS_FILE_CLOSED;
			conn->session->opens[i].closed = true;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_HANDLE;
}

/*
 * Simulate SMB_COM_TREE_DISCONNECT.
 */
static u32 smb1_do_tree_disconnect(struct smb1_test_conn *conn, u16 tid)
{
	int i;
	u32 status;

	status = smb1_check_conn_state_for_command(conn,
						   SMB_COM_TREE_DISCONNECT);
	if (status != STATUS_SUCCESS)
		return status;

	status = smb1_check_tree(conn->session, tid);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_TREE_CONNECTS; i++) {
		if (conn->session->trees[i].tid == tid) {
			conn->session->trees[i].disconnected = true;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_SMB_BAD_TID;
}

/*
 * Simulate SMB_COM_LOGOFF_ANDX.
 */
static u32 smb1_do_logoff(struct smb1_test_conn *conn)
{
	u32 status;

	status = smb1_check_conn_state_for_command(conn, SMB_COM_LOGOFF_ANDX);
	if (status != STATUS_SUCCESS)
		return status;

	if (!conn->session || conn->session->state == SMB1_SESSION_NONE)
		return STATUS_SMB_BAD_UID;

	conn->session->state = SMB1_SESSION_EXPIRED;
	conn->status = SMB1_CONN_NEED_SETUP;
	return STATUS_SUCCESS;
}

/* ================================================================
 * Test setup / teardown
 * ================================================================
 */

struct smb1_state_test_ctx {
	struct smb1_test_conn conn;
};

static int smb1_state_test_init(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Initial state: new connection, negotiation needed */
	ctx->conn.status = SMB1_CONN_NEW;
	ctx->conn.need_neg = true;
	ctx->conn.smb1_conn = false;
	ctx->conn.dialect = BAD_PROT_ID_SMB1;
	ctx->conn.session = NULL;
	ctx->conn.upgraded_to_smb2 = false;

	test->priv = ctx;
	return 0;
}

static void smb1_state_test_exit(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	if (ctx) {
		kfree(ctx->conn.session);
		kfree(ctx);
	}
}

/* Helper: bring connection through pure SMB1 negotiate + session_setup */
static void smb1_setup_good_connection(struct smb1_test_conn *conn)
{
	conn->status = SMB1_CONN_NEED_NEGOTIATE;
	smb1_do_negotiate(conn, SMB1_PROT_ID, false);
	smb1_do_session_setup(conn, 0x0802);
}

/* Helper: bring connection to GOOD with a tree connect */
static void smb1_setup_tree_connected(struct smb1_test_conn *conn, u16 tid)
{
	smb1_setup_good_connection(conn);
	smb1_do_tree_connect(conn, tid);
}

/* Helper: bring connection to GOOD with tree and open file */
static void smb1_setup_file_opened(struct smb1_test_conn *conn, u16 tid,
				   u16 fid)
{
	smb1_setup_tree_connected(conn, tid);
	smb1_do_create(conn, tid, fid);
}

/* ================================================================
 * TEST CATEGORY 1: SMB1 NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT
 *                   ordering (MS-SMB 3.3.5.2, 3.3.5.3, 3.3.5.4)
 * ================================================================
 */

/*
 * SMB1 NEGOTIATE in NEED_NEGOTIATE state should succeed and
 * transition to NEED_SETUP.
 */
static void test_smb1_negotiate_success(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_EQ(test,
			smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, false),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status,
			(int)SMB1_CONN_NEED_SETUP);
	KUNIT_EXPECT_TRUE(test, ctx->conn.smb1_conn);
	KUNIT_EXPECT_FALSE(test, ctx->conn.need_neg);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.dialect, (int)SMB1_PROT_ID);
}

/*
 * SESSION_SETUP before NEGOTIATE must be rejected.
 */
static void test_smb1_session_setup_before_negotiate(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_NE(test,
			smb1_do_session_setup(&ctx->conn, 0x0802),
			STATUS_SUCCESS);
}

/*
 * TREE_CONNECT before SESSION_SETUP must be rejected.
 */
static void test_smb1_tree_connect_before_session(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, false);
	KUNIT_EXPECT_NE(test,
			smb1_do_tree_connect(&ctx->conn, 1),
			STATUS_SUCCESS);
}

/*
 * Full valid SMB1 lifecycle: NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT
 * -> NT_CREATE_ANDX -> CLOSE -> TREE_DISCONNECT -> LOGOFF
 */
static void test_smb1_valid_full_lifecycle(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;

	KUNIT_EXPECT_EQ(test,
			smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, false),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_do_session_setup(&ctx->conn, 0x0802),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_do_tree_connect(&ctx->conn, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_do_create(&ctx->conn, 1, 100),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_do_close(&ctx->conn, 100),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_do_tree_disconnect(&ctx->conn, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_do_logoff(&ctx->conn),
			STATUS_SUCCESS);
}

/*
 * SESSION_SETUP transitions conn from NEED_SETUP to GOOD,
 * and session from IN_PROGRESS to VALID.
 */
static void test_smb1_session_setup_transitions(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, false);

	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status,
			(int)SMB1_CONN_NEED_SETUP);

	KUNIT_EXPECT_EQ(test,
			smb1_do_session_setup(&ctx->conn, 0x0802),
			STATUS_SUCCESS);

	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status,
			(int)SMB1_CONN_GOOD);
	KUNIT_ASSERT_NOT_NULL(test, ctx->conn.session);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.session->state,
			(int)SMB1_SESSION_VALID);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.session->uid, 0x0802);
}

/*
 * Second NEGOTIATE after dialect is established must be rejected.
 * [MS-SMB] 3.3.5.2 / Figure 4: "MUST NOT be repeated"
 */
static void test_smb1_second_negotiate_rejected(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_NE(test,
			smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, false),
			STATUS_SUCCESS);
}

/*
 * Commands before NEGOTIATE must be rejected.
 */
static void test_smb1_cmd_before_negotiate_rejected(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;

	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_TREE_CONNECT_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_READ_ANDX),
			STATUS_SUCCESS);
}

/*
 * Commands on exiting connection must be rejected.
 */
static void test_smb1_cmd_on_exiting_conn(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_EXITING;
	ctx->conn.need_neg = false;

	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_NEGOTIATE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 2: SMB1->SMB2 Upgrade State Transitions
 *                   (MS-SMB2 3.3.5.4, ksmbd smb_common.c)
 * ================================================================
 */

/*
 * SMB1 NEGOTIATE with SMB2 dialect present triggers upgrade.
 * Connection should set dialect to 0x02FF (wildcard), set
 * upgraded_to_smb2 = true, and need_neg back to true so the
 * client sends a full SMB2 NEGOTIATE.
 */
static void test_smb1_to_smb2_upgrade_negotiate(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_EQ(test,
			smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, true),
			STATUS_SUCCESS);

	/* Should have wildcard dialect for multi-protocol negotiate */
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.dialect, (int)SMB2X_PROT_ID);
	KUNIT_EXPECT_TRUE(test, ctx->conn.upgraded_to_smb2);
	KUNIT_EXPECT_FALSE(test, ctx->conn.smb1_conn);
	/* need_neg should be true again for the SMB2 NEGOTIATE phase */
	KUNIT_EXPECT_TRUE(test, ctx->conn.need_neg);
}

/*
 * After SMB1->SMB2 upgrade, SMB1 commands must be rejected.
 */
static void test_smb1_cmd_after_upgrade_rejected(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, true);

	/* SMB1 SESSION_SETUP_ANDX should be rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);

	/* SMB1 TREE_CONNECT_ANDX should be rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_TREE_CONNECT_ANDX),
			STATUS_SUCCESS);

	/* SMB1 NT_CREATE_ANDX should be rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);

	/* SMB1 READ_ANDX should be rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_READ_ANDX),
			STATUS_SUCCESS);

	/* SMB1 WRITE_ANDX should be rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_WRITE_ANDX),
			STATUS_SUCCESS);
}

/*
 * SMB1 NEGOTIATE without SMB2 dialects stays as pure SMB1.
 */
static void test_smb1_negotiate_no_upgrade(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	ctx->conn.status = SMB1_CONN_NEED_NEGOTIATE;
	smb1_do_negotiate(&ctx->conn, SMB1_PROT_ID, false);

	KUNIT_EXPECT_FALSE(test, ctx->conn.upgraded_to_smb2);
	KUNIT_EXPECT_TRUE(test, ctx->conn.smb1_conn);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.dialect, (int)SMB1_PROT_ID);
}

/*
 * Wildcard dialect 0x02FF is correctly set during upgrade.
 */
static void test_smb1_upgrade_wildcard_dialect(struct kunit *test)
{
	struct smb1_test_conn conn = {
		.status = SMB1_CONN_NEED_NEGOTIATE,
		.need_neg = true,
		.dialect = BAD_PROT_ID_SMB1,
	};

	smb1_do_negotiate(&conn, SMB1_PROT_ID, true);
	KUNIT_EXPECT_EQ(test, (int)conn.dialect, 0x02FF);
}

/*
 * After upgrade, smb1_conn flag should be false.
 */
static void test_smb1_upgrade_clears_smb1_flag(struct kunit *test)
{
	struct smb1_test_conn conn = {
		.status = SMB1_CONN_NEED_NEGOTIATE,
		.need_neg = true,
		.smb1_conn = true,
		.dialect = BAD_PROT_ID_SMB1,
	};

	smb1_do_negotiate(&conn, SMB1_PROT_ID, true);
	KUNIT_EXPECT_FALSE(test, conn.smb1_conn);
}

/* ================================================================
 * TEST CATEGORY 3: SMB1 Session State Machine
 *                   (MS-SMB 3.3.1.5, 3.3.5.1, 3.3.5.3, 3.3.6.1)
 * ================================================================
 */

/*
 * Session in IN_PROGRESS state only allows SESSION_SETUP_ANDX.
 * [MS-SMB] 3.3.5.1: AuthenticationState InProgress + not SESSION_SETUP
 * -> STATUS_INVALID_HANDLE
 */
static void test_smb1_session_in_progress_limits(struct kunit *test)
{
	struct smb1_test_session sess = {
		.uid = 0x0802,
		.state = SMB1_SESSION_IN_PROGRESS,
	};

	/* SESSION_SETUP allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);

	/* NT_CREATE_ANDX rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);

	/* READ_ANDX rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess, SMB_COM_READ_ANDX),
			STATUS_SUCCESS);

	/* TREE_CONNECT rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess,
				SMB_COM_TREE_CONNECT_ANDX),
			STATUS_SUCCESS);
}

/*
 * Session in EXPIRED state allows limited commands per [MS-SMB] 3.3.5.1:
 *   SMB_COM_CLOSE, SMB_COM_LOGOFF_ANDX, SMB_COM_FLUSH,
 *   SMB_COM_LOCKING_ANDX, SMB_COM_TREE_DISCONNECT, SMB_COM_SESSION_SETUP_ANDX
 */
static void test_smb1_session_expired_allows_limited(struct kunit *test)
{
	struct smb1_test_session sess = {
		.uid = 0x0802,
		.state = SMB1_SESSION_EXPIRED,
	};

	/* CLOSE allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_CLOSE),
			STATUS_SUCCESS);
	/* LOGOFF allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_LOGOFF_ANDX),
			STATUS_SUCCESS);
	/* FLUSH allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_FLUSH),
			STATUS_SUCCESS);
	/* LOCKING_ANDX allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_LOCKING_ANDX),
			STATUS_SUCCESS);
	/* TREE_DISCONNECT allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess,
				SMB_COM_TREE_DISCONNECT),
			STATUS_SUCCESS);
	/* SESSION_SETUP_ANDX allowed (re-auth) */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);

	/* NT_CREATE_ANDX rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);
	/* READ_ANDX rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess, SMB_COM_READ_ANDX),
			STATUS_SUCCESS);
	/* WRITE_ANDX rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess, SMB_COM_WRITE_ANDX),
			STATUS_SUCCESS);
}

/*
 * Session in REAUTH_IN_PROGRESS state allows same commands as EXPIRED.
 * [MS-SMB] 3.3.5.1: Expired or ReauthInProgress are handled the same.
 */
static void test_smb1_session_reauth_in_progress(struct kunit *test)
{
	struct smb1_test_session sess = {
		.uid = 0x0802,
		.state = SMB1_SESSION_REAUTH_IN_PROGRESS,
	};

	/* CLOSE allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_CLOSE),
			STATUS_SUCCESS);
	/* SESSION_SETUP allowed (continue re-auth) */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);
	/* NT_CREATE_ANDX rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);
}

/*
 * Valid session allows all commands.
 */
static void test_smb1_session_valid_allows_all(struct kunit *test)
{
	struct smb1_test_session sess = {
		.uid = 0x0802,
		.state = SMB1_SESSION_VALID,
	};

	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_READ_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_WRITE_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_CLOSE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_LOGOFF_ANDX),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess,
				SMB_COM_TREE_CONNECT_ANDX),
			STATUS_SUCCESS);
}

/*
 * NULL session (no UID) must be rejected.
 */
static void test_smb1_null_session_rejected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(NULL, SMB_COM_READ_ANDX),
			STATUS_SMB_BAD_UID);
}

/*
 * LOGOFF transitions session to EXPIRED and conn to NEED_SETUP.
 */
static void test_smb1_logoff_transitions(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);

	KUNIT_EXPECT_EQ(test, smb1_do_logoff(&ctx->conn), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.session->state,
			(int)SMB1_SESSION_EXPIRED);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status,
			(int)SMB1_CONN_NEED_SETUP);
}

/*
 * Double LOGOFF must be rejected.
 */
static void test_smb1_double_logoff(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_EQ(test, smb1_do_logoff(&ctx->conn), STATUS_SUCCESS);

	/* Second logoff: session is expired, conn is NEED_SETUP */
	KUNIT_EXPECT_NE(test, smb1_do_logoff(&ctx->conn), STATUS_SUCCESS);
}

/*
 * Operations after LOGOFF must fail.
 */
static void test_smb1_operations_after_logoff(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	smb1_do_logoff(&ctx->conn);

	KUNIT_EXPECT_NE(test,
			smb1_do_tree_connect(&ctx->conn, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			smb1_do_create(&ctx->conn, 1, 100),
			STATUS_SUCCESS);
}

/*
 * Authentication expiration timer: valid session transitions to expired.
 * [MS-SMB] 3.3.6.1: Timer scans all sessions and sets AuthenticationState
 * to Expired for those whose AuthenticationExpirationTime has passed.
 */
static void test_smb1_auth_expiration_timer(struct kunit *test)
{
	struct smb1_test_session sess = {
		.uid = 0x0802,
		.state = SMB1_SESSION_VALID,
	};

	/* Simulate timer expiration */
	sess.state = SMB1_SESSION_EXPIRED;

	/* CLOSE should still be allowed */
	KUNIT_EXPECT_EQ(test,
			smb1_check_session_state(&sess, SMB_COM_CLOSE),
			STATUS_SUCCESS);
	/* NT_CREATE_ANDX should be rejected */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(&sess,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 4: SMB1 Tree Connect and File Operations
 *                   (MS-SMB 3.3.5.4, 3.3.5.5)
 * ================================================================
 */

/*
 * TREE_DISCONNECT on non-existent tree is rejected.
 */
static void test_smb1_tree_disconnect_nonexistent(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_NE(test,
			smb1_do_tree_disconnect(&ctx->conn, 99),
			STATUS_SUCCESS);
}

/*
 * Double TREE_DISCONNECT is rejected.
 */
static void test_smb1_double_tree_disconnect(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			smb1_do_tree_disconnect(&ctx->conn, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			smb1_do_tree_disconnect(&ctx->conn, 1),
			STATUS_SUCCESS);
}

/*
 * NT_CREATE_ANDX before TREE_CONNECT is rejected.
 */
static void test_smb1_create_before_tree_connect(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_NE(test,
			smb1_do_create(&ctx->conn, 1, 100),
			STATUS_SUCCESS);
}

/*
 * NT_CREATE_ANDX on disconnected tree is rejected.
 */
static void test_smb1_create_on_disconnected_tree(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_tree_connected(&ctx->conn, 1);
	smb1_do_tree_disconnect(&ctx->conn, 1);

	KUNIT_EXPECT_NE(test,
			smb1_do_create(&ctx->conn, 1, 100),
			STATUS_SUCCESS);
}

/*
 * CLOSE with invalid FID is rejected.
 */
static void test_smb1_close_invalid_fid(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_NE(test,
			smb1_do_close(&ctx->conn, 999),
			STATUS_SUCCESS);
}

/*
 * Double CLOSE on same FID is rejected.
 */
static void test_smb1_double_close(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_file_opened(&ctx->conn, 1, 100);
	KUNIT_EXPECT_EQ(test, smb1_do_close(&ctx->conn, 100),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test, smb1_do_close(&ctx->conn, 100),
			STATUS_SUCCESS);
}

/*
 * Multiple tree connects and multiple file opens.
 */
static void test_smb1_multi_tree_multi_file(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);

	/* Two tree connects */
	KUNIT_EXPECT_EQ(test, smb1_do_tree_connect(&ctx->conn, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, smb1_do_tree_connect(&ctx->conn, 2),
			STATUS_SUCCESS);

	/* Files on tree 1 */
	KUNIT_EXPECT_EQ(test, smb1_do_create(&ctx->conn, 1, 10),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, smb1_do_create(&ctx->conn, 1, 11),
			STATUS_SUCCESS);

	/* File on tree 2 */
	KUNIT_EXPECT_EQ(test, smb1_do_create(&ctx->conn, 2, 20),
			STATUS_SUCCESS);

	/* Close one file, others remain accessible */
	KUNIT_EXPECT_EQ(test, smb1_do_close(&ctx->conn, 10),
			STATUS_SUCCESS);

	/* Tree 2 still works */
	KUNIT_EXPECT_EQ(test, smb1_check_tree(ctx->conn.session, 2),
			STATUS_SUCCESS);

	/* Tree 1 still works */
	KUNIT_EXPECT_EQ(test, smb1_check_tree(ctx->conn.session, 1),
			STATUS_SUCCESS);
}

/*
 * Tree connect with tid 0 is invalid.
 */
static void test_smb1_tree_connect_tid_zero(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_NE(test, smb1_check_tree(ctx->conn.session, 0),
			STATUS_SUCCESS);
}

/*
 * Logoff invalidates all trees and files at session level.
 */
static void test_smb1_logoff_invalidates_trees_files(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);
	smb1_do_tree_connect(&ctx->conn, 1);
	smb1_do_create(&ctx->conn, 1, 100);

	/* Everything works */
	KUNIT_EXPECT_EQ(test, smb1_check_tree(ctx->conn.session, 1),
			STATUS_SUCCESS);

	/* Logoff */
	smb1_do_logoff(&ctx->conn);

	/* Session is expired, operations on trees fail at session level */
	KUNIT_EXPECT_NE(test,
			smb1_check_session_state(ctx->conn.session,
				SMB_COM_NT_CREATE_ANDX),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 5: Connection State Enumeration and Edge Cases
 * ================================================================
 */

/*
 * Verify all SMB1 connection state check helpers are mutually exclusive.
 */
static void test_smb1_conn_states_mutually_exclusive(struct kunit *test)
{
	struct smb1_test_conn conn = {};

	conn.status = SMB1_CONN_NEW;
	KUNIT_EXPECT_FALSE(test, smb1_conn_good(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_need_negotiate(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_need_setup(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_exiting(&conn));

	conn.status = SMB1_CONN_GOOD;
	KUNIT_EXPECT_TRUE(test, smb1_conn_good(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_need_negotiate(&conn));

	conn.status = SMB1_CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_TRUE(test, smb1_conn_need_negotiate(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_good(&conn));

	conn.status = SMB1_CONN_NEED_SETUP;
	KUNIT_EXPECT_TRUE(test, smb1_conn_need_setup(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_good(&conn));

	conn.status = SMB1_CONN_EXITING;
	KUNIT_EXPECT_TRUE(test, smb1_conn_exiting(&conn));
	KUNIT_EXPECT_FALSE(test, smb1_conn_good(&conn));
}

/*
 * Verify the test enum aliases match the production KSMBD_SESS_*
 * constants from connection.h.  This is now guaranteed by the enum
 * initializers, but we verify at runtime for documentation.
 */
static void test_smb1_state_transition_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_NEW, (int)KSMBD_SESS_NEW);
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_GOOD, (int)KSMBD_SESS_GOOD);
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_EXITING, (int)KSMBD_SESS_EXITING);
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_NEED_RECONNECT, (int)KSMBD_SESS_NEED_RECONNECT);
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_NEED_NEGOTIATE, (int)KSMBD_SESS_NEED_NEGOTIATE);
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_NEED_SETUP, (int)KSMBD_SESS_NEED_SETUP);
	KUNIT_EXPECT_EQ(test, (int)SMB1_CONN_RELEASING, (int)KSMBD_SESS_RELEASING);
}

/*
 * SMB1 session state enumeration covers all four states.
 */
static void test_smb1_session_state_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)SMB1_SESSION_NONE, 0);
	KUNIT_EXPECT_EQ(test, (int)SMB1_SESSION_IN_PROGRESS, 1);
	KUNIT_EXPECT_EQ(test, (int)SMB1_SESSION_VALID, 2);
	KUNIT_EXPECT_EQ(test, (int)SMB1_SESSION_EXPIRED, 3);
	KUNIT_EXPECT_EQ(test, (int)SMB1_SESSION_REAUTH_IN_PROGRESS, 4);
}

/*
 * Verify that SESSION_SETUP re-auth in GOOD state is allowed
 * (additional session setups for reauthentication).
 */
static void test_smb1_session_setup_reauth(struct kunit *test)
{
	struct smb1_state_test_ctx *ctx = test->priv;

	smb1_setup_good_connection(&ctx->conn);

	/* Re-authentication should be accepted */
	KUNIT_EXPECT_EQ(test,
			smb1_check_conn_state_for_command(&ctx->conn,
				SMB_COM_SESSION_SETUP_ANDX),
			STATUS_SUCCESS);
}

/* ================================================================
 * Test case table and suite
 * ================================================================
 */

static struct kunit_case ksmbd_smb1_state_machine_test_cases[] = {
	/* Category 1: SMB1 NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT */
	KUNIT_CASE(test_smb1_negotiate_success),
	KUNIT_CASE(test_smb1_session_setup_before_negotiate),
	KUNIT_CASE(test_smb1_tree_connect_before_session),
	KUNIT_CASE(test_smb1_valid_full_lifecycle),
	KUNIT_CASE(test_smb1_session_setup_transitions),
	KUNIT_CASE(test_smb1_second_negotiate_rejected),
	KUNIT_CASE(test_smb1_cmd_before_negotiate_rejected),
	KUNIT_CASE(test_smb1_cmd_on_exiting_conn),

	/* Category 2: SMB1->SMB2 upgrade state transitions */
	KUNIT_CASE(test_smb1_to_smb2_upgrade_negotiate),
	KUNIT_CASE(test_smb1_cmd_after_upgrade_rejected),
	KUNIT_CASE(test_smb1_negotiate_no_upgrade),
	KUNIT_CASE(test_smb1_upgrade_wildcard_dialect),
	KUNIT_CASE(test_smb1_upgrade_clears_smb1_flag),

	/* Category 3: SMB1 session state machine */
	KUNIT_CASE(test_smb1_session_in_progress_limits),
	KUNIT_CASE(test_smb1_session_expired_allows_limited),
	KUNIT_CASE(test_smb1_session_reauth_in_progress),
	KUNIT_CASE(test_smb1_session_valid_allows_all),
	KUNIT_CASE(test_smb1_null_session_rejected),
	KUNIT_CASE(test_smb1_logoff_transitions),
	KUNIT_CASE(test_smb1_double_logoff),
	KUNIT_CASE(test_smb1_operations_after_logoff),
	KUNIT_CASE(test_smb1_auth_expiration_timer),

	/* Category 4: Tree connect and file operations */
	KUNIT_CASE(test_smb1_tree_disconnect_nonexistent),
	KUNIT_CASE(test_smb1_double_tree_disconnect),
	KUNIT_CASE(test_smb1_create_before_tree_connect),
	KUNIT_CASE(test_smb1_create_on_disconnected_tree),
	KUNIT_CASE(test_smb1_close_invalid_fid),
	KUNIT_CASE(test_smb1_double_close),
	KUNIT_CASE(test_smb1_multi_tree_multi_file),
	KUNIT_CASE(test_smb1_tree_connect_tid_zero),
	KUNIT_CASE(test_smb1_logoff_invalidates_trees_files),

	/* Category 5: Connection state enumeration and edge cases */
	KUNIT_CASE(test_smb1_conn_states_mutually_exclusive),
	KUNIT_CASE(test_smb1_state_transition_values),
	KUNIT_CASE(test_smb1_session_state_values),
	KUNIT_CASE(test_smb1_session_setup_reauth),
	{}
};

static struct kunit_suite ksmbd_smb1_state_machine_test_suite = {
	.name = "ksmbd_smb1_state_machine",
	.init = smb1_state_test_init,
	.exit = smb1_state_test_exit,
	.test_cases = ksmbd_smb1_state_machine_test_cases,
};

kunit_test_suite(ksmbd_smb1_state_machine_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB1 protocol state machine (MS-SMB 3.3.5)");
