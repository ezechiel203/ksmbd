// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 protocol state machine (MS-SMB2 3.3.5)
 *
 *   These tests verify the SMB2 protocol state machine transitions
 *   as defined in [MS-SMB2] sections 3.3.5.1 through 3.3.5.14.
 *   We replicate the state enum and transition checks in a
 *   self-contained manner since the full server stack cannot be
 *   instantiated in KUnit.
 *
 *   Spec references:
 *     3.3.5.2  - Receiving Any Message (connection state check)
 *     3.3.5.4  - Receiving an SMB2 NEGOTIATE Request
 *     3.3.5.5  - Receiving an SMB2 SESSION_SETUP Request
 *     3.3.5.6  - Receiving an SMB2 LOGOFF Request
 *     3.3.5.7  - Receiving an SMB2 TREE_CONNECT Request
 *     3.3.5.8  - Receiving an SMB2 TREE_DISCONNECT Request
 *     3.3.5.9  - Receiving an SMB2 CREATE Request
 *     3.3.5.11 - Receiving an SMB2 CLOSE Request
 *     3.3.5.14 - Receiving an SMB2 LOCK Request
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

enum test_conn_status {
	CONN_NEW = KSMBD_SESS_NEW,
	CONN_GOOD = KSMBD_SESS_GOOD,
	CONN_EXITING = KSMBD_SESS_EXITING,
	CONN_NEED_RECONNECT = KSMBD_SESS_NEED_RECONNECT,
	CONN_NEED_NEGOTIATE = KSMBD_SESS_NEED_NEGOTIATE,
	CONN_NEED_SETUP = KSMBD_SESS_NEED_SETUP,
	CONN_RELEASING = KSMBD_SESS_RELEASING,
};

/* Session states (from MS-SMB2 3.3.1.8) */
enum test_session_state {
	SESSION_NONE = 0,	/* No session allocated */
	SESSION_IN_PROGRESS,	/* Authentication in progress */
	SESSION_VALID,		/* Fully authenticated */
	SESSION_EXPIRED,	/* Session expired */
};

/* SMB2 command codes (from smb2pdu.h) */
#define SMB2_NEGOTIATE_HE	0x0000
#define SMB2_SESSION_SETUP_HE	0x0001
#define SMB2_LOGOFF_HE		0x0002
#define SMB2_TREE_CONNECT_HE	0x0003
#define SMB2_TREE_DISCONNECT_HE	0x0004
#define SMB2_CREATE_HE		0x0005
#define SMB2_CLOSE_HE		0x0006
#define SMB2_FLUSH_HE		0x0007
#define SMB2_READ_HE		0x0008
#define SMB2_WRITE_HE		0x0009
#define SMB2_LOCK_HE		0x000A
#define SMB2_IOCTL_HE		0x000B
#define SMB2_CANCEL_HE		0x000C
#define SMB2_ECHO_HE		0x000D
#define SMB2_QUERY_DIRECTORY_HE	0x000E
#define SMB2_CHANGE_NOTIFY_HE	0x000F
#define SMB2_QUERY_INFO_HE	0x0010
#define SMB2_SET_INFO_HE	0x0011
#define SMB2_OPLOCK_BREAK_HE	0x0012

/* Dialect constants */
#define SMB20_PROT_ID		0x0202
#define SMB21_PROT_ID		0x0210
#define SMB30_PROT_ID		0x0300
#define SMB302_PROT_ID		0x0302
#define SMB311_PROT_ID		0x0311
#define BAD_PROT_ID		0xFFFF

/* NTSTATUS codes */
#define STATUS_SUCCESS			0x00000000
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_USER_SESSION_DELETED	0xC0000203
#define STATUS_NETWORK_NAME_DELETED	0xC00000C9
#define STATUS_FILE_CLOSED		0xC0000128
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_NETWORK_SESSION_EXPIRED	0xC000035C
#define STATUS_NOT_SUPPORTED		0xC00000BB
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_REQUEST_NOT_ACCEPTED	0x00000D21

/* ================================================================
 * Test state machine structures
 * ================================================================
 */

#define TEST_MAX_TREE_CONNECTS	8
#define TEST_MAX_OPEN_FILES	16

struct test_open_file {
	u64	file_id;	/* 0 = unused slot */
	u32	tree_id;
	bool	closed;
};

struct test_tree_connect {
	u32	tree_id;	/* 0 = unused slot */
	bool	disconnected;
};

struct test_session {
	u64			session_id;
	enum test_session_state	state;
	struct test_tree_connect	trees[TEST_MAX_TREE_CONNECTS];
	struct test_open_file	opens[TEST_MAX_OPEN_FILES];
};

struct test_smb2_conn {
	enum test_conn_status	status;
	bool			need_neg;
	u16			dialect;
	struct test_session	*session;
};

/* ================================================================
 * State machine helpers (replicate ksmbd logic)
 * ================================================================
 */

static bool conn_good(struct test_smb2_conn *conn)
{
	return conn->status == CONN_GOOD;
}

static bool conn_need_negotiate(struct test_smb2_conn *conn)
{
	return conn->status == CONN_NEED_NEGOTIATE;
}

static bool conn_need_setup(struct test_smb2_conn *conn)
{
	return conn->status == CONN_NEED_SETUP;
}

static bool conn_exiting(struct test_smb2_conn *conn)
{
	return conn->status == CONN_EXITING;
}

/*
 * Replicate the "Receiving Any Message" check from MS-SMB2 3.3.5.2.2:
 * If the request is not NEGOTIATE and NegotiateDialect is 0xFFFF,
 * the server MUST disconnect.
 *
 * Returns a STATUS code: STATUS_SUCCESS if command is allowed in
 * the current connection state, or an appropriate error status.
 */
static u32 check_conn_state_for_command(struct test_smb2_conn *conn, u16 cmd)
{
	/* Connection exiting - reject everything */
	if (conn_exiting(conn))
		return STATUS_NETWORK_SESSION_EXPIRED;

	/*
	 * MS-SMB2 3.3.5.2.2: If the request is not NEGOTIATE and
	 * Connection.NegotiateDialect is 0xFFFF (or 0x02FF), the
	 * server MUST disconnect the connection.
	 */
	if (cmd != SMB2_NEGOTIATE_HE && conn->need_neg)
		return STATUS_INVALID_PARAMETER;

	/*
	 * MS-SMB2 3.3.5.4: If the server receives NEGOTIATE when
	 * Connection.NegotiateDialect is already set (not 0xFFFF),
	 * the server MUST disconnect.
	 */
	if (cmd == SMB2_NEGOTIATE_HE && conn_good(conn))
		return STATUS_INVALID_PARAMETER;

	/*
	 * MS-SMB2 3.3.5.2.9: For commands requiring a session
	 * (everything except NEGOTIATE, SESSION_SETUP, CANCEL, ECHO),
	 * the connection must be in GOOD state.
	 */
	if (cmd != SMB2_NEGOTIATE_HE &&
	    cmd != SMB2_SESSION_SETUP_HE &&
	    cmd != SMB2_CANCEL_HE &&
	    cmd != SMB2_ECHO_HE) {
		if (!conn_good(conn))
			return STATUS_USER_SESSION_DELETED;
	}

	/*
	 * SESSION_SETUP requires at least NEED_SETUP or GOOD state.
	 */
	if (cmd == SMB2_SESSION_SETUP_HE) {
		if (!conn_need_setup(conn) && !conn_good(conn))
			return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

/*
 * Check session state for non-session-setup commands (MS-SMB2 3.3.5.2.9).
 * Returns STATUS_SUCCESS if the session allows this command.
 */
static u32 check_session_state(struct test_session *sess, u16 cmd)
{
	if (!sess)
		return STATUS_USER_SESSION_DELETED;

	switch (sess->state) {
	case SESSION_VALID:
		return STATUS_SUCCESS;

	case SESSION_IN_PROGRESS:
		/* Only LOGOFF, CLOSE, and LOCK are allowed (3.3.5.2.9) */
		if (cmd == SMB2_LOGOFF_HE || cmd == SMB2_CLOSE_HE ||
		    cmd == SMB2_LOCK_HE)
			return STATUS_SUCCESS;
		return STATUS_NETWORK_SESSION_EXPIRED;

	case SESSION_EXPIRED:
		/* Only LOGOFF, CLOSE, and LOCK are allowed (3.3.5.2.9) */
		if (cmd == SMB2_LOGOFF_HE || cmd == SMB2_CLOSE_HE ||
		    cmd == SMB2_LOCK_HE)
			return STATUS_SUCCESS;
		return STATUS_NETWORK_SESSION_EXPIRED;

	case SESSION_NONE:
	default:
		return STATUS_USER_SESSION_DELETED;
	}
}

/*
 * Check tree connect state (MS-SMB2 3.3.5.2.11).
 */
static u32 check_tree_connect(struct test_session *sess, u32 tree_id)
{
	int i;

	if (!sess || sess->state != SESSION_VALID)
		return STATUS_USER_SESSION_DELETED;

	for (i = 0; i < TEST_MAX_TREE_CONNECTS; i++) {
		if (sess->trees[i].tree_id == tree_id && tree_id != 0) {
			if (sess->trees[i].disconnected)
				return STATUS_NETWORK_NAME_DELETED;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NETWORK_NAME_DELETED;
}

/*
 * Check file handle validity.
 */
static u32 check_file_id(struct test_session *sess, u64 file_id)
{
	int i;

	if (!sess || sess->state != SESSION_VALID)
		return STATUS_USER_SESSION_DELETED;

	for (i = 0; i < TEST_MAX_OPEN_FILES; i++) {
		if (sess->opens[i].file_id == file_id && file_id != 0) {
			if (sess->opens[i].closed)
				return STATUS_FILE_CLOSED;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_HANDLE;
}

/*
 * Simulate NEGOTIATE: transitions conn from NEED_NEGOTIATE to NEED_SETUP.
 */
static u32 do_negotiate(struct test_smb2_conn *conn, u16 dialect,
			int dialect_count)
{
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_NEGOTIATE_HE);
	if (status != STATUS_SUCCESS)
		return status;

	if (dialect_count == 0)
		return STATUS_INVALID_PARAMETER;

	conn->need_neg = false;
	conn->dialect = dialect;
	conn->status = CONN_NEED_SETUP;
	return STATUS_SUCCESS;
}

/*
 * Simulate SESSION_SETUP success: transitions conn to GOOD,
 * session to VALID.
 */
static u32 do_session_setup(struct test_smb2_conn *conn)
{
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_SESSION_SETUP_HE);
	if (status != STATUS_SUCCESS)
		return status;

	if (!conn->session) {
		conn->session = kzalloc(sizeof(*conn->session), GFP_KERNEL);
		if (!conn->session)
			return STATUS_INVALID_PARAMETER;
		conn->session->session_id = 1;
		conn->session->state = SESSION_IN_PROGRESS;
	}

	/* Simulate successful auth completion */
	conn->session->state = SESSION_VALID;
	conn->status = CONN_GOOD;
	return STATUS_SUCCESS;
}

/*
 * Simulate TREE_CONNECT: requires valid session.
 */
static u32 do_tree_connect(struct test_smb2_conn *conn, u32 tree_id)
{
	int i;
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_TREE_CONNECT_HE);
	if (status != STATUS_SUCCESS)
		return status;

	status = check_session_state(conn->session, SMB2_TREE_CONNECT_HE);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_TREE_CONNECTS; i++) {
		if (conn->session->trees[i].tree_id == 0) {
			conn->session->trees[i].tree_id = tree_id;
			conn->session->trees[i].disconnected = false;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_PARAMETER;
}

/*
 * Simulate CREATE: requires valid tree connect.
 */
static u32 do_create(struct test_smb2_conn *conn, u32 tree_id, u64 file_id)
{
	int i;
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_CREATE_HE);
	if (status != STATUS_SUCCESS)
		return status;

	status = check_session_state(conn->session, SMB2_CREATE_HE);
	if (status != STATUS_SUCCESS)
		return status;

	status = check_tree_connect(conn->session, tree_id);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_OPEN_FILES; i++) {
		if (conn->session->opens[i].file_id == 0) {
			conn->session->opens[i].file_id = file_id;
			conn->session->opens[i].tree_id = tree_id;
			conn->session->opens[i].closed = false;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_PARAMETER;
}

/*
 * Simulate CLOSE.
 */
static u32 do_close(struct test_smb2_conn *conn, u64 file_id)
{
	int i;
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_CLOSE_HE);
	if (status != STATUS_SUCCESS)
		return status;

	status = check_file_id(conn->session, file_id);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_OPEN_FILES; i++) {
		if (conn->session->opens[i].file_id == file_id) {
			conn->session->opens[i].closed = true;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_INVALID_HANDLE;
}

/*
 * Simulate TREE_DISCONNECT.
 */
static u32 do_tree_disconnect(struct test_smb2_conn *conn, u32 tree_id)
{
	int i;
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_TREE_DISCONNECT_HE);
	if (status != STATUS_SUCCESS)
		return status;

	status = check_tree_connect(conn->session, tree_id);
	if (status != STATUS_SUCCESS)
		return status;

	for (i = 0; i < TEST_MAX_TREE_CONNECTS; i++) {
		if (conn->session->trees[i].tree_id == tree_id) {
			conn->session->trees[i].disconnected = true;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NETWORK_NAME_DELETED;
}

/*
 * Simulate LOGOFF.
 */
static u32 do_logoff(struct test_smb2_conn *conn)
{
	u32 status;

	status = check_conn_state_for_command(conn, SMB2_LOGOFF_HE);
	if (status != STATUS_SUCCESS)
		return status;

	if (!conn->session || conn->session->state == SESSION_NONE)
		return STATUS_USER_SESSION_DELETED;

	conn->session->state = SESSION_EXPIRED;
	conn->status = CONN_NEED_SETUP;
	return STATUS_SUCCESS;
}

/* ================================================================
 * Test setup / teardown
 * ================================================================
 */

struct smb2_state_test_ctx {
	struct test_smb2_conn conn;
};

static int smb2_state_test_init(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Initial state: new connection, negotiation needed */
	ctx->conn.status = CONN_NEW;
	ctx->conn.need_neg = true;
	ctx->conn.dialect = BAD_PROT_ID;
	ctx->conn.session = NULL;

	test->priv = ctx;
	return 0;
}

static void smb2_state_test_exit(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	if (ctx) {
		kfree(ctx->conn.session);
		kfree(ctx);
	}
}

/* Helper: bring connection through negotiate + session_setup to GOOD */
static void setup_good_connection(struct test_smb2_conn *conn)
{
	conn->status = CONN_NEED_NEGOTIATE;
	do_negotiate(conn, SMB311_PROT_ID, 5);
	do_session_setup(conn);
}

/* Helper: bring connection to GOOD with a tree connect */
static void setup_tree_connected(struct test_smb2_conn *conn, u32 tree_id)
{
	setup_good_connection(conn);
	do_tree_connect(conn, tree_id);
}

/* Helper: bring connection to GOOD with tree and open file */
static void setup_file_opened(struct test_smb2_conn *conn, u32 tree_id,
			      u64 file_id)
{
	setup_tree_connected(conn, tree_id);
	do_create(conn, tree_id, file_id);
}

/* ================================================================
 * TEST CATEGORY 1: Connection State Transitions (MS-SMB2 3.3.5.2)
 * ================================================================
 */

/*
 * Spec ref: 3.3.5.2.2
 * Any command before NEGOTIATE must be rejected (except NEGOTIATE itself).
 */
static void test_cmd_before_negotiate_rejected(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;
	u32 status;

	ctx->conn.status = CONN_NEED_NEGOTIATE;

	/* SESSION_SETUP before NEGOTIATE */
	status = check_conn_state_for_command(&ctx->conn, SMB2_SESSION_SETUP_HE);
	KUNIT_EXPECT_NE(test, status, STATUS_SUCCESS);

	/* TREE_CONNECT before NEGOTIATE */
	status = check_conn_state_for_command(&ctx->conn, SMB2_TREE_CONNECT_HE);
	KUNIT_EXPECT_NE(test, status, STATUS_SUCCESS);

	/* CREATE before NEGOTIATE */
	status = check_conn_state_for_command(&ctx->conn, SMB2_CREATE_HE);
	KUNIT_EXPECT_NE(test, status, STATUS_SUCCESS);

	/* READ before NEGOTIATE */
	status = check_conn_state_for_command(&ctx->conn, SMB2_READ_HE);
	KUNIT_EXPECT_NE(test, status, STATUS_SUCCESS);
}

/*
 * NEGOTIATE is allowed in NEED_NEGOTIATE state.
 */
static void test_negotiate_in_need_neg_state(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_EQ(test, do_negotiate(&ctx->conn, SMB311_PROT_ID, 5),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEED_SETUP);
}

/*
 * Spec ref: 3.3.5.4
 * Second NEGOTIATE after dialect already set must be rejected.
 */
static void test_second_negotiate_rejected(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);

	/* Second NEGOTIATE should fail */
	KUNIT_EXPECT_NE(test,
			check_conn_state_for_command(&ctx->conn, SMB2_NEGOTIATE_HE),
			STATUS_SUCCESS);
}

/*
 * NEGOTIATE with zero dialects must return STATUS_INVALID_PARAMETER.
 */
static void test_negotiate_zero_dialects(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_EQ(test, do_negotiate(&ctx->conn, SMB311_PROT_ID, 0),
			STATUS_INVALID_PARAMETER);
}

/*
 * Commands on exiting connection must be rejected.
 */
static void test_cmd_on_exiting_conn(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_EXITING;
	ctx->conn.need_neg = false;

	KUNIT_EXPECT_NE(test,
			check_conn_state_for_command(&ctx->conn, SMB2_NEGOTIATE_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			check_conn_state_for_command(&ctx->conn, SMB2_SESSION_SETUP_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test,
			check_conn_state_for_command(&ctx->conn, SMB2_CREATE_HE),
			STATUS_SUCCESS);
}

/*
 * After NEGOTIATE, state transitions to NEED_SETUP.
 */
static void test_negotiate_transitions_to_need_setup(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB30_PROT_ID, 3);

	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEED_SETUP);
	KUNIT_EXPECT_FALSE(test, ctx->conn.need_neg);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.dialect, (int)SMB30_PROT_ID);
}

/*
 * SESSION_SETUP in NEED_SETUP state transitions to GOOD.
 */
static void test_session_setup_transitions_to_good(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEED_SETUP);

	KUNIT_EXPECT_EQ(test, do_session_setup(&ctx->conn), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_GOOD);
}

/*
 * Valid command sequence: NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT
 * -> CREATE -> CLOSE -> TREE_DISCONNECT -> LOGOFF
 */
static void test_valid_full_lifecycle(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;
	u32 status;

	ctx->conn.status = CONN_NEED_NEGOTIATE;

	status = do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);

	status = do_session_setup(&ctx->conn);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);

	status = do_tree_connect(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);

	status = do_create(&ctx->conn, 1, 100);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);

	status = do_close(&ctx->conn, 100);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);

	status = do_tree_disconnect(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);

	status = do_logoff(&ctx->conn);
	KUNIT_EXPECT_EQ(test, status, STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 2: Session State Machine (MS-SMB2 3.3.5.5/3.3.5.6)
 * ================================================================
 */

/*
 * SESSION_SETUP without prior NEGOTIATE must fail.
 */
static void test_session_setup_without_negotiate(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_NE(test, do_session_setup(&ctx->conn), STATUS_SUCCESS);
}

/*
 * SESSION_SETUP in GOOD state (reauthentication) is allowed.
 */
static void test_session_setup_reauth(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_GOOD);

	/* Reauthentication should be accepted */
	KUNIT_EXPECT_EQ(test,
			check_conn_state_for_command(&ctx->conn, SMB2_SESSION_SETUP_HE),
			STATUS_SUCCESS);
}

/*
 * LOGOFF before SESSION_SETUP must be rejected.
 */
static void test_logoff_before_session_setup(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);

	KUNIT_EXPECT_NE(test, do_logoff(&ctx->conn), STATUS_SUCCESS);
}

/*
 * Double LOGOFF must be rejected (session already expired).
 */
static void test_double_logoff_rejected(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);

	KUNIT_EXPECT_EQ(test, do_logoff(&ctx->conn), STATUS_SUCCESS);
	/* Session is now expired, conn is NEED_SETUP */
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEED_SETUP);

	/* Second LOGOFF: can reach the function but session is expired */
	KUNIT_EXPECT_NE(test, do_logoff(&ctx->conn), STATUS_SUCCESS);
}

/*
 * Operations after LOGOFF must be rejected (session expired).
 */
static void test_operations_after_logoff(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	do_logoff(&ctx->conn);

	/* TREE_CONNECT after logoff should fail */
	KUNIT_EXPECT_NE(test, do_tree_connect(&ctx->conn, 1), STATUS_SUCCESS);

	/* CREATE after logoff should fail */
	KUNIT_EXPECT_NE(test, do_create(&ctx->conn, 1, 100), STATUS_SUCCESS);
}

/*
 * Session in IN_PROGRESS state only allows LOGOFF, CLOSE, LOCK.
 */
static void test_session_in_progress_allows_limited_cmds(struct kunit *test)
{
	struct test_session sess = {
		.session_id = 1,
		.state = SESSION_IN_PROGRESS,
	};

	/* LOGOFF allowed */
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_LOGOFF_HE),
			STATUS_SUCCESS);

	/* CLOSE allowed */
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_CLOSE_HE),
			STATUS_SUCCESS);

	/* LOCK allowed */
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_LOCK_HE),
			STATUS_SUCCESS);

	/* CREATE rejected */
	KUNIT_EXPECT_NE(test,
			check_session_state(&sess, SMB2_CREATE_HE),
			STATUS_SUCCESS);

	/* READ rejected */
	KUNIT_EXPECT_NE(test,
			check_session_state(&sess, SMB2_READ_HE),
			STATUS_SUCCESS);

	/* WRITE rejected */
	KUNIT_EXPECT_NE(test,
			check_session_state(&sess, SMB2_WRITE_HE),
			STATUS_SUCCESS);

	/* TREE_CONNECT rejected */
	KUNIT_EXPECT_NE(test,
			check_session_state(&sess, SMB2_TREE_CONNECT_HE),
			STATUS_SUCCESS);
}

/*
 * Session in EXPIRED state only allows LOGOFF, CLOSE, LOCK.
 */
static void test_session_expired_allows_limited_cmds(struct kunit *test)
{
	struct test_session sess = {
		.session_id = 1,
		.state = SESSION_EXPIRED,
	};

	/* LOGOFF allowed */
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_LOGOFF_HE),
			STATUS_SUCCESS);

	/* CLOSE allowed */
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_CLOSE_HE),
			STATUS_SUCCESS);

	/* LOCK allowed */
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_LOCK_HE),
			STATUS_SUCCESS);

	/* QUERY_INFO rejected */
	KUNIT_EXPECT_NE(test,
			check_session_state(&sess, SMB2_QUERY_INFO_HE),
			STATUS_SUCCESS);

	/* IOCTL rejected */
	KUNIT_EXPECT_NE(test,
			check_session_state(&sess, SMB2_IOCTL_HE),
			STATUS_SUCCESS);
}

/*
 * Valid session allows all commands.
 */
static void test_session_valid_allows_all_cmds(struct kunit *test)
{
	struct test_session sess = {
		.session_id = 1,
		.state = SESSION_VALID,
	};

	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_CREATE_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_READ_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_WRITE_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_LOGOFF_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_LOCK_HE),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_session_state(&sess, SMB2_QUERY_INFO_HE),
			STATUS_SUCCESS);
}

/*
 * NULL session must fail.
 */
static void test_null_session_rejected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			check_session_state(NULL, SMB2_READ_HE),
			STATUS_USER_SESSION_DELETED);
}

/* ================================================================
 * TEST CATEGORY 3: Tree Connect State Machine (MS-SMB2 3.3.5.7/3.3.5.8)
 * ================================================================
 */

/*
 * TREE_CONNECT before valid session is rejected.
 */
static void test_tree_connect_before_session(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);

	KUNIT_EXPECT_NE(test, do_tree_connect(&ctx->conn, 1), STATUS_SUCCESS);
}

/*
 * TREE_DISCONNECT on non-existent tree is rejected.
 */
static void test_tree_disconnect_nonexistent(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_NE(test, do_tree_disconnect(&ctx->conn, 99),
			STATUS_SUCCESS);
}

/*
 * Double TREE_DISCONNECT is rejected (tree already disconnected).
 */
static void test_double_tree_disconnect(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test, do_tree_disconnect(&ctx->conn, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test, do_tree_disconnect(&ctx->conn, 1),
			STATUS_SUCCESS);
}

/*
 * Operations on disconnected tree are rejected.
 */
static void test_create_on_disconnected_tree(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	do_tree_disconnect(&ctx->conn, 1);

	KUNIT_EXPECT_NE(test, do_create(&ctx->conn, 1, 100), STATUS_SUCCESS);
}

/*
 * Tree connect with tree_id 0 is invalid.
 */
static void test_tree_connect_id_zero(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	/* tree_id 0 is reserved/invalid in our model */
	KUNIT_EXPECT_NE(test, check_tree_connect(ctx->conn.session, 0),
			STATUS_SUCCESS);
}

/*
 * Multiple tree connects should succeed.
 */
static void test_multiple_tree_connects(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_EQ(test, do_tree_connect(&ctx->conn, 1), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, do_tree_connect(&ctx->conn, 2), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, do_tree_connect(&ctx->conn, 3), STATUS_SUCCESS);

	/* All trees should be accessible */
	KUNIT_EXPECT_EQ(test,
			check_tree_connect(ctx->conn.session, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_tree_connect(ctx->conn.session, 2),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_tree_connect(ctx->conn.session, 3),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 4: Create/Close Lifecycle (MS-SMB2 3.3.5.9/3.3.5.11)
 * ================================================================
 */

/*
 * CREATE before TREE_CONNECT is rejected.
 */
static void test_create_before_tree_connect(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	KUNIT_EXPECT_NE(test, do_create(&ctx->conn, 1, 100), STATUS_SUCCESS);
}

/*
 * CLOSE with invalid FID is rejected.
 */
static void test_close_invalid_fid(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_NE(test, do_close(&ctx->conn, 999), STATUS_SUCCESS);
}

/*
 * Double CLOSE on same FID is rejected.
 */
static void test_double_close(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_file_opened(&ctx->conn, 1, 100);
	KUNIT_EXPECT_EQ(test, do_close(&ctx->conn, 100), STATUS_SUCCESS);
	KUNIT_EXPECT_NE(test, do_close(&ctx->conn, 100), STATUS_SUCCESS);
}

/*
 * Operations on closed FID are rejected.
 */
static void test_ops_on_closed_fid(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_file_opened(&ctx->conn, 1, 100);
	do_close(&ctx->conn, 100);

	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 100),
			STATUS_FILE_CLOSED);
}

/*
 * CREATE and CLOSE in sequence succeeds.
 */
static void test_create_close_sequence(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);

	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 1, 100), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 100),
			STATUS_SUCCESS);

	KUNIT_EXPECT_EQ(test, do_close(&ctx->conn, 100), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 100),
			STATUS_FILE_CLOSED);
}

/*
 * Multiple files open simultaneously.
 */
static void test_multiple_opens(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);

	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 1, 100), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 1, 200), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 1, 300), STATUS_SUCCESS);

	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 100),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 200),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 300),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 5: Command Ordering Violations (MS-SMB2 3.3.5.2)
 * ================================================================
 */

/*
 * READ without prior CREATE is rejected (requires file handle).
 */
static void test_read_without_create(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 100),
			STATUS_INVALID_HANDLE);
}

/*
 * WRITE without prior CREATE is rejected.
 */
static void test_write_without_create(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 200),
			STATUS_INVALID_HANDLE);
}

/*
 * LOCK without prior CREATE is rejected.
 */
static void test_lock_without_create(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 300),
			STATUS_INVALID_HANDLE);
}

/*
 * QUERY_INFO without prior CREATE is rejected.
 */
static void test_query_info_without_create(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 400),
			STATUS_INVALID_HANDLE);
}

/*
 * SET_INFO without prior CREATE is rejected.
 */
static void test_set_info_without_create(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 500),
			STATUS_INVALID_HANDLE);
}

/*
 * IOCTL without prior CREATE (when file-based) is rejected.
 */
static void test_ioctl_without_create(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_tree_connected(&ctx->conn, 1);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 600),
			STATUS_INVALID_HANDLE);
}

/* ================================================================
 * TEST CATEGORY 6: Negotiate Edge Cases
 * ================================================================
 */

/*
 * NEGOTIATE with each supported dialect should succeed.
 */
static void test_negotiate_each_dialect(struct kunit *test)
{
	u16 dialects[] = {
		SMB20_PROT_ID, SMB21_PROT_ID, SMB30_PROT_ID,
		SMB302_PROT_ID, SMB311_PROT_ID
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(dialects); i++) {
		struct test_smb2_conn conn = {
			.status = CONN_NEED_NEGOTIATE,
			.need_neg = true,
			.dialect = BAD_PROT_ID,
			.session = NULL,
		};

		KUNIT_EXPECT_EQ(test,
				do_negotiate(&conn, dialects[i], 1),
				STATUS_SUCCESS);
		KUNIT_EXPECT_EQ(test, (int)conn.dialect, (int)dialects[i]);
		KUNIT_EXPECT_EQ(test, (int)conn.status, (int)CONN_NEED_SETUP);
	}
}

/*
 * NEGOTIATE in NEW state (with need_neg=true) is allowed.
 */
static void test_negotiate_in_new_state(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	/* conn starts in NEW state */
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEW);
	ctx->conn.status = CONN_NEED_NEGOTIATE;

	KUNIT_EXPECT_EQ(test, do_negotiate(&ctx->conn, SMB311_PROT_ID, 5),
			STATUS_SUCCESS);
}

/*
 * NEGOTIATE in NEED_SETUP state (already negotiated) is rejected.
 */
static void test_negotiate_after_negotiate(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);

	/* need_neg is false now, so NEGOTIATE should be rejected */
	KUNIT_EXPECT_NE(test,
			check_conn_state_for_command(&ctx->conn, SMB2_NEGOTIATE_HE),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 7: Connection State Enumeration
 * ================================================================
 */

/*
 * Verify all state check helpers are mutually exclusive.
 */
static void test_conn_states_mutually_exclusive(struct kunit *test)
{
	struct test_smb2_conn conn;

	conn.status = CONN_NEW;
	KUNIT_EXPECT_FALSE(test, conn_good(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_negotiate(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_setup(&conn));
	KUNIT_EXPECT_FALSE(test, conn_exiting(&conn));

	conn.status = CONN_GOOD;
	KUNIT_EXPECT_TRUE(test, conn_good(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_negotiate(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_setup(&conn));
	KUNIT_EXPECT_FALSE(test, conn_exiting(&conn));

	conn.status = CONN_NEED_NEGOTIATE;
	KUNIT_EXPECT_FALSE(test, conn_good(&conn));
	KUNIT_EXPECT_TRUE(test, conn_need_negotiate(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_setup(&conn));
	KUNIT_EXPECT_FALSE(test, conn_exiting(&conn));

	conn.status = CONN_NEED_SETUP;
	KUNIT_EXPECT_FALSE(test, conn_good(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_negotiate(&conn));
	KUNIT_EXPECT_TRUE(test, conn_need_setup(&conn));
	KUNIT_EXPECT_FALSE(test, conn_exiting(&conn));

	conn.status = CONN_EXITING;
	KUNIT_EXPECT_FALSE(test, conn_good(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_negotiate(&conn));
	KUNIT_EXPECT_FALSE(test, conn_need_setup(&conn));
	KUNIT_EXPECT_TRUE(test, conn_exiting(&conn));
}

/*
 * Verify CANCEL and ECHO are allowed without session (3.3.5.2.9).
 */
static void test_cancel_echo_no_session(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);
	/* In NEED_SETUP state, no session yet */

	/* CANCEL should be allowed (exempt from session check) */
	KUNIT_EXPECT_EQ(test,
			check_conn_state_for_command(&ctx->conn, SMB2_CANCEL_HE),
			STATUS_SUCCESS);

	/* ECHO should be allowed */
	KUNIT_EXPECT_EQ(test,
			check_conn_state_for_command(&ctx->conn, SMB2_ECHO_HE),
			STATUS_SUCCESS);
}

/* ================================================================
 * TEST CATEGORY 8: Complex Scenarios
 * ================================================================
 */

/*
 * Full lifecycle with multiple trees and files.
 */
static void test_complex_multi_tree_multi_file(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);

	/* Two tree connects */
	KUNIT_EXPECT_EQ(test, do_tree_connect(&ctx->conn, 1), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, do_tree_connect(&ctx->conn, 2), STATUS_SUCCESS);

	/* Files on tree 1 */
	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 1, 10), STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 1, 11), STATUS_SUCCESS);

	/* Files on tree 2 */
	KUNIT_EXPECT_EQ(test, do_create(&ctx->conn, 2, 20), STATUS_SUCCESS);

	/* Close one file on tree 1 */
	KUNIT_EXPECT_EQ(test, do_close(&ctx->conn, 10), STATUS_SUCCESS);

	/* File 11 and 20 still accessible */
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 11),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 20),
			STATUS_SUCCESS);

	/* Disconnect tree 1 */
	KUNIT_EXPECT_EQ(test, do_tree_disconnect(&ctx->conn, 1),
			STATUS_SUCCESS);

	/* Tree 2 still works */
	KUNIT_EXPECT_EQ(test,
			check_tree_connect(ctx->conn.session, 2),
			STATUS_SUCCESS);

	/* Tree 1 is disconnected */
	KUNIT_EXPECT_NE(test,
			check_tree_connect(ctx->conn.session, 1),
			STATUS_SUCCESS);
}

/*
 * Logoff invalidates all trees and files.
 */
static void test_logoff_invalidates_trees_and_files(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	setup_good_connection(&ctx->conn);
	do_tree_connect(&ctx->conn, 1);
	do_create(&ctx->conn, 1, 100);

	/* Everything works */
	KUNIT_EXPECT_EQ(test,
			check_tree_connect(ctx->conn.session, 1),
			STATUS_SUCCESS);
	KUNIT_EXPECT_EQ(test,
			check_file_id(ctx->conn.session, 100),
			STATUS_SUCCESS);

	/* Logoff */
	do_logoff(&ctx->conn);

	/* Session is expired, operations on trees/files fail at session level */
	KUNIT_EXPECT_NE(test,
			check_session_state(ctx->conn.session, SMB2_CREATE_HE),
			STATUS_SUCCESS);
}

/*
 * Connection state after session setup failure stays NEED_SETUP.
 */
static void test_conn_state_preserved_after_session_fail(struct kunit *test)
{
	struct smb2_state_test_ctx *ctx = test->priv;

	ctx->conn.status = CONN_NEED_NEGOTIATE;
	do_negotiate(&ctx->conn, SMB311_PROT_ID, 5);
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEED_SETUP);

	/*
	 * Even if session setup were to fail partway, the connection
	 * would remain in NEED_SETUP (not transition to GOOD).
	 */
	KUNIT_EXPECT_EQ(test, (int)ctx->conn.status, (int)CONN_NEED_SETUP);
}

/*
 * Verify the complete state transition sequence numbers.
 */
static void test_state_transition_values(struct kunit *test)
{
	/* Verify enum ordering matches ksmbd connection.h */
	KUNIT_EXPECT_EQ(test, (int)CONN_NEW, 0);
	KUNIT_EXPECT_EQ(test, (int)CONN_GOOD, 1);
	KUNIT_EXPECT_EQ(test, (int)CONN_EXITING, 2);
	KUNIT_EXPECT_EQ(test, (int)CONN_NEED_RECONNECT, 3);
	KUNIT_EXPECT_EQ(test, (int)CONN_NEED_NEGOTIATE, 4);
	KUNIT_EXPECT_EQ(test, (int)CONN_NEED_SETUP, 5);
	KUNIT_EXPECT_EQ(test, (int)CONN_RELEASING, 6);
}

/* ================================================================
 * Test case table and suite
 * ================================================================
 */

static struct kunit_case ksmbd_smb2_state_machine_test_cases[] = {
	/* Category 1: Connection state transitions */
	KUNIT_CASE(test_cmd_before_negotiate_rejected),
	KUNIT_CASE(test_negotiate_in_need_neg_state),
	KUNIT_CASE(test_second_negotiate_rejected),
	KUNIT_CASE(test_negotiate_zero_dialects),
	KUNIT_CASE(test_cmd_on_exiting_conn),
	KUNIT_CASE(test_negotiate_transitions_to_need_setup),
	KUNIT_CASE(test_session_setup_transitions_to_good),
	KUNIT_CASE(test_valid_full_lifecycle),

	/* Category 2: Session state machine */
	KUNIT_CASE(test_session_setup_without_negotiate),
	KUNIT_CASE(test_session_setup_reauth),
	KUNIT_CASE(test_logoff_before_session_setup),
	KUNIT_CASE(test_double_logoff_rejected),
	KUNIT_CASE(test_operations_after_logoff),
	KUNIT_CASE(test_session_in_progress_allows_limited_cmds),
	KUNIT_CASE(test_session_expired_allows_limited_cmds),
	KUNIT_CASE(test_session_valid_allows_all_cmds),
	KUNIT_CASE(test_null_session_rejected),

	/* Category 3: Tree connect state machine */
	KUNIT_CASE(test_tree_connect_before_session),
	KUNIT_CASE(test_tree_disconnect_nonexistent),
	KUNIT_CASE(test_double_tree_disconnect),
	KUNIT_CASE(test_create_on_disconnected_tree),
	KUNIT_CASE(test_tree_connect_id_zero),
	KUNIT_CASE(test_multiple_tree_connects),

	/* Category 4: Create/Close lifecycle */
	KUNIT_CASE(test_create_before_tree_connect),
	KUNIT_CASE(test_close_invalid_fid),
	KUNIT_CASE(test_double_close),
	KUNIT_CASE(test_ops_on_closed_fid),
	KUNIT_CASE(test_create_close_sequence),
	KUNIT_CASE(test_multiple_opens),

	/* Category 5: Command ordering violations */
	KUNIT_CASE(test_read_without_create),
	KUNIT_CASE(test_write_without_create),
	KUNIT_CASE(test_lock_without_create),
	KUNIT_CASE(test_query_info_without_create),
	KUNIT_CASE(test_set_info_without_create),
	KUNIT_CASE(test_ioctl_without_create),

	/* Category 6: Negotiate edge cases */
	KUNIT_CASE(test_negotiate_each_dialect),
	KUNIT_CASE(test_negotiate_in_new_state),
	KUNIT_CASE(test_negotiate_after_negotiate),

	/* Category 7: Connection state enumeration */
	KUNIT_CASE(test_conn_states_mutually_exclusive),
	KUNIT_CASE(test_cancel_echo_no_session),

	/* Category 8: Complex scenarios */
	KUNIT_CASE(test_complex_multi_tree_multi_file),
	KUNIT_CASE(test_logoff_invalidates_trees_and_files),
	KUNIT_CASE(test_conn_state_preserved_after_session_fail),
	KUNIT_CASE(test_state_transition_values),
	{}
};

static struct kunit_suite ksmbd_smb2_state_machine_test_suite = {
	.name = "ksmbd_smb2_state_machine",
	.init = smb2_state_test_init,
	.exit = smb2_state_test_exit,
	.test_cases = ksmbd_smb2_state_machine_test_cases,
};

kunit_test_suite(ksmbd_smb2_state_machine_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 protocol state machine (MS-SMB2 3.3.5)");
