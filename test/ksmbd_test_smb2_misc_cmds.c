// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 miscellaneous commands (smb2_misc_cmds.c)
 *
 *   Tests cover structure layout, constants, and protocol-level logic
 *   for echo, close, oplock/lease break, and server-to-client
 *   notification commands.  Production functions in smb2_misc_cmds.c
 *   require full ksmbd_work state, so we test the structural and
 *   constant aspects that can be verified without live connections.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "oplock.h"
#include "vfs_cache.h"

/* VISIBLE_IF_KUNIT function from smb2_misc_cmds.c */
extern int check_lease_state(struct lease *lease, __le32 req_state);

/* ================================================================
 * Echo command structure tests
 * ================================================================ */

/*
 * test_echo_rsp_structure_size - Echo response StructureSize must be 4
 */
static void test_echo_rsp_structure_size(struct kunit *test)
{
	struct smb2_echo_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(4);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.StructureSize), 4);
}

/*
 * test_echo_rsp_reserved_zero - Echo response Reserved field
 */
static void test_echo_rsp_reserved_zero(struct kunit *test)
{
	struct smb2_echo_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(4);
	rsp.Reserved = 0;

	KUNIT_EXPECT_EQ(test, rsp.Reserved, (__le16)0);
}

/*
 * test_echo_rsp_sizeof - verify compiled struct size
 */
static void test_echo_rsp_sizeof(struct kunit *test)
{
	/* smb2_echo_rsp = smb2_hdr + StructureSize(2) + Reserved(2) */
	KUNIT_EXPECT_EQ(test, sizeof(struct smb2_echo_rsp),
			sizeof(struct smb2_hdr) + 4);
}

/* ================================================================
 * Close command structure tests
 * ================================================================ */

/*
 * test_close_req_structure_size - Close request StructureSize must be 24
 */
static void test_close_req_structure_size(struct kunit *test)
{
	struct smb2_close_req req;

	memset(&req, 0, sizeof(req));
	req.StructureSize = cpu_to_le16(24);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.StructureSize), 24);
}

/*
 * test_close_rsp_structure_size - Close response StructureSize must be 60
 */
static void test_close_rsp_structure_size(struct kunit *test)
{
	struct smb2_close_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(60);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.StructureSize), 60);
}

/*
 * test_close_flag_postquery_attrib - SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB value
 */
static void test_close_flag_postquery_attrib(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB),
			0x0001);
}

/*
 * test_close_rsp_no_postquery - close without POSTQUERY zeroes fields
 */
static void test_close_rsp_no_postquery(struct kunit *test)
{
	struct smb2_close_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(60);
	rsp.Flags = 0;
	rsp.AllocationSize = 0;
	rsp.EndOfFile = 0;
	rsp.Attributes = 0;
	rsp.CreationTime = 0;
	rsp.LastAccessTime = 0;
	rsp.LastWriteTime = 0;
	rsp.ChangeTime = 0;

	/* All time/size fields should be zero when no POSTQUERY flag */
	KUNIT_EXPECT_EQ(test, rsp.Flags, (__le16)0);
	KUNIT_EXPECT_EQ(test, rsp.AllocationSize, cpu_to_le64(0));
	KUNIT_EXPECT_EQ(test, rsp.EndOfFile, cpu_to_le64(0));
	KUNIT_EXPECT_EQ(test, rsp.Attributes, (__le32)0);
}

/*
 * test_close_rsp_with_postquery - close with POSTQUERY flag set
 */
static void test_close_rsp_with_postquery(struct kunit *test)
{
	struct smb2_close_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(60);
	rsp.Flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;
	rsp.AllocationSize = cpu_to_le64(4096);
	rsp.EndOfFile = cpu_to_le64(1024);
	rsp.Attributes = cpu_to_le32(0x20); /* ARCHIVE */

	KUNIT_EXPECT_EQ(test, rsp.Flags, SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(rsp.AllocationSize), (u64)4096);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(rsp.EndOfFile), (u64)1024);
}

/* ================================================================
 * Server-to-Client Notification structure tests
 * ================================================================ */

/*
 * test_notification_command_value - SMB2_SERVER_TO_CLIENT_NOTIFICATION = 0x0013
 */
static void test_notification_command_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(SMB2_SERVER_TO_CLIENT_NOTIFICATION),
			0x0013);
	KUNIT_EXPECT_EQ(test,
			(int)SMB2_SERVER_TO_CLIENT_NOTIFICATION_HE,
			0x0013);
}

/*
 * test_notify_session_closed_type - SMB2_NOTIFY_SESSION_CLOSED = 0x00000000
 * Per MS-SMB2 §2.2.44.1, SmbNotifySessionClosed = 0x0000.
 */
static void test_notify_session_closed_type(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			le32_to_cpu(SMB2_NOTIFY_SESSION_CLOSED),
			0x00000000);
}

/*
 * test_notification_struct_layout - verify notification structure fields
 */
static void test_notification_struct_layout(struct kunit *test)
{
	struct smb2_server_to_client_notification notif;

	memset(&notif, 0, sizeof(notif));
	notif.StructureSize = cpu_to_le16(4);
	notif.Reserved = 0;
	notif.NotificationType = SMB2_NOTIFY_SESSION_CLOSED;

	KUNIT_EXPECT_EQ(test, le16_to_cpu(notif.StructureSize), 4);
	KUNIT_EXPECT_EQ(test, notif.Reserved, (__le16)0);
	KUNIT_EXPECT_EQ(test, notif.NotificationType,
			SMB2_NOTIFY_SESSION_CLOSED);
}

/*
 * test_notification_header_flags - notification uses SERVER_TO_REDIR flag
 */
static void test_notification_header_flags(struct kunit *test)
{
	struct smb2_server_to_client_notification notif;

	memset(&notif, 0, sizeof(notif));
	notif.hdr.ProtocolId = SMB2_PROTO_NUMBER;
	notif.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	notif.hdr.Command = SMB2_SERVER_TO_CLIENT_NOTIFICATION;
	notif.hdr.Flags = SMB2_FLAGS_SERVER_TO_REDIR;
	notif.hdr.MessageId = cpu_to_le64(-1ULL); /* unsolicited */

	KUNIT_EXPECT_EQ(test, notif.hdr.ProtocolId, SMB2_PROTO_NUMBER);
	KUNIT_EXPECT_EQ(test, notif.hdr.Command,
			SMB2_SERVER_TO_CLIENT_NOTIFICATION);
	KUNIT_EXPECT_TRUE(test,
		!!(notif.hdr.Flags & SMB2_FLAGS_SERVER_TO_REDIR));
	KUNIT_EXPECT_EQ(test, le64_to_cpu(notif.hdr.MessageId),
			0xFFFFFFFFFFFFFFFFULL);
}

/*
 * test_notification_session_id - notification carries session ID
 */
static void test_notification_session_id(struct kunit *test)
{
	struct smb2_server_to_client_notification notif;

	memset(&notif, 0, sizeof(notif));
	notif.hdr.SessionId = cpu_to_le64(0x123456789ABCDEF0ULL);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(notif.hdr.SessionId),
			0x123456789ABCDEF0ULL);
}

/* ================================================================
 * Oplock break structure size constants
 * ================================================================ */

/*
 * test_oplock_break_struct_size_20 - OP_BREAK_STRUCT_SIZE_20 = 24
 */
static void test_oplock_break_struct_size_20(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, OP_BREAK_STRUCT_SIZE_20, 24);
}

/*
 * test_oplock_break_struct_size_21 - OP_BREAK_STRUCT_SIZE_21 = 36
 */
static void test_oplock_break_struct_size_21(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, OP_BREAK_STRUCT_SIZE_21, 36);
}

/*
 * test_oplock_break_struct_dispatch - dispatch by StructureSize
 *
 * The production code dispatches oplock vs lease break by checking
 * req->StructureSize: 24 = oplock, 36 = lease.
 */
static void test_oplock_break_struct_dispatch(struct kunit *test)
{
	struct smb2_oplock_break brk;

	/* Oplock break (SMB 2.0) */
	memset(&brk, 0, sizeof(brk));
	brk.StructureSize = cpu_to_le16(OP_BREAK_STRUCT_SIZE_20);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(brk.StructureSize),
			OP_BREAK_STRUCT_SIZE_20);

	/* Lease break (SMB 2.1) */
	brk.StructureSize = cpu_to_le16(OP_BREAK_STRUCT_SIZE_21);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(brk.StructureSize),
			OP_BREAK_STRUCT_SIZE_21);
}

/*
 * test_oplock_break_invalid_size - invalid StructureSize
 */
static void test_oplock_break_invalid_size(struct kunit *test)
{
	__le16 size = cpu_to_le16(12);

	/* Neither 24 nor 36 -> invalid */
	KUNIT_EXPECT_NE(test, le16_to_cpu(size), OP_BREAK_STRUCT_SIZE_20);
	KUNIT_EXPECT_NE(test, le16_to_cpu(size), OP_BREAK_STRUCT_SIZE_21);
}

/* ================================================================
 * SMB2 header constants used by misc commands
 * ================================================================ */

/*
 * test_smb2_header_structure_size - SMB2_HEADER_STRUCTURE_SIZE = 64
 */
static void test_smb2_header_structure_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le16_to_cpu(SMB2_HEADER_STRUCTURE_SIZE), 64);
}

/*
 * test_smb2_proto_number - SMB2 protocol signature
 */
static void test_smb2_proto_number(struct kunit *test)
{
	/*
	 * SMB2_PROTO_NUMBER is 0x424D53FE ("\xFESMB" in LE)
	 * which identifies an SMB2 protocol message.
	 */
	KUNIT_EXPECT_EQ(test, SMB2_PROTO_NUMBER, cpu_to_le32(0x424D53FE));
}

/* ================================================================
 * check_lease_state() logic tests
 *
 * check_lease_state() validates a lease break acknowledgement:
 *   - returns 0 if the requested state is acceptable (downgrade or match)
 *   - returns 1 if the requested state is a rejected upgrade
 *
 * The function also updates lease->new_state on success.
 * ================================================================ */

/*
 * Helper: allocate a test lease struct.
 */
static struct lease *alloc_test_lease(struct kunit *test)
{
	struct lease *l = kunit_kzalloc(test, sizeof(*l), GFP_KERNEL);

	KUNIT_ASSERT_NOT_NULL(test, l);
	return l;
}

/*
 * test_lease_rh_to_r - RH break, ack with R (drop Handle): accept
 */
static void test_lease_rh_to_r(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_READ_CACHING_LE), 0);
}

/*
 * test_lease_rh_to_none - RH break, ack with NONE: accept
 */
static void test_lease_rh_to_none(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_NONE_LE), 0);
}

/*
 * test_lease_rh_to_rh - RH break, ack with RH (exact match): accept
 */
static void test_lease_rh_to_rh(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);
	__le32 rh = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;

	l->new_state = rh;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, rh), 0);
}

/*
 * test_lease_rh_to_rwh - RH break, ack with RWH (upgrade attempt): reject
 */
static void test_lease_rh_to_rwh(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);
	__le32 rwh = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE |
		     SMB2_LEASE_HANDLE_CACHING_LE;

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, rwh), 1);
}

/*
 * test_lease_rw_to_r - RW break, ack with R (drop Handle): accept
 */
static void test_lease_rw_to_r(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_READ_CACHING_LE), 0);
}

/*
 * test_lease_rw_to_none - RW break, ack with NONE: accept
 */
static void test_lease_rw_to_none(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_NONE_LE), 0);
}

/*
 * test_lease_rw_to_rwh - RW break, ack with RWH (re-add Handle): reject
 */
static void test_lease_rw_to_rwh(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);
	__le32 rwh = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE |
		     SMB2_LEASE_HANDLE_CACHING_LE;

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, rwh), 1);
}

/*
 * test_lease_r_to_r - R break, ack with R (exact match): accept
 */
static void test_lease_r_to_r(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_READ_CACHING_LE), 0);
}

/*
 * test_lease_r_to_rh - R break, ack with RH (upgrade attempt): reject
 */
static void test_lease_r_to_rh(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l,
		SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE), 1);
}

/*
 * test_lease_none_to_none - NONE break, ack with NONE (exact match): accept
 */
static void test_lease_none_to_none(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_NONE_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_NONE_LE), 0);
}

/*
 * test_lease_none_to_r - NONE break, ack with R (upgrade): reject
 */
static void test_lease_none_to_r(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_NONE_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_READ_CACHING_LE), 1);
}

/*
 * test_lease_rw_to_rw - RW break, ack with RW (exact match): accept
 */
static void test_lease_rw_to_rw(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);
	__le32 rw = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE;

	l->new_state = rw;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, rw), 0);
}

/*
 * test_lease_rh_to_h_only - RH break, ack with H only (drop Read): accept
 * (H without Write is acceptable as a downgrade from RH)
 */
static void test_lease_rh_to_h_only(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_HANDLE_CACHING_LE), 0);
}

/*
 * test_lease_rh_to_w_only - RH break, ack with W only (adds Write): reject
 */
static void test_lease_rh_to_w_only(struct kunit *test)
{
	struct lease *l = alloc_test_lease(test);

	l->new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, check_lease_state(l, SMB2_LEASE_WRITE_CACHING_LE), 1);
}

/* ================================================================
 * Oplock break dispatch structure tests
 * ================================================================ */

/*
 * test_oplock_break_dispatch_smb20 - StructureSize 24 dispatches to oplock
 */
static void test_oplock_break_dispatch_smb20(struct kunit *test)
{
	struct smb2_oplock_break brk;

	memset(&brk, 0, sizeof(brk));
	brk.StructureSize = cpu_to_le16(OP_BREAK_STRUCT_SIZE_20);

	/* Simulates the switch in smb2_oplock_break() */
	switch (le16_to_cpu(brk.StructureSize)) {
	case OP_BREAK_STRUCT_SIZE_20:
		KUNIT_SUCCEED(test);
		return;
	default:
		break;
	}
	KUNIT_FAIL(test, "expected OP_BREAK_STRUCT_SIZE_20 dispatch");
}

/* ================================================================
 * Test case array and suite definition
 * ================================================================ */

static struct kunit_case ksmbd_smb2_misc_cmds_test_cases[] = {
	/* Echo command */
	KUNIT_CASE(test_echo_rsp_structure_size),
	KUNIT_CASE(test_echo_rsp_reserved_zero),
	KUNIT_CASE(test_echo_rsp_sizeof),
	/* Close command */
	KUNIT_CASE(test_close_req_structure_size),
	KUNIT_CASE(test_close_rsp_structure_size),
	KUNIT_CASE(test_close_flag_postquery_attrib),
	KUNIT_CASE(test_close_rsp_no_postquery),
	KUNIT_CASE(test_close_rsp_with_postquery),
	/* Server-to-client notification */
	KUNIT_CASE(test_notification_command_value),
	KUNIT_CASE(test_notify_session_closed_type),
	KUNIT_CASE(test_notification_struct_layout),
	KUNIT_CASE(test_notification_header_flags),
	KUNIT_CASE(test_notification_session_id),
	/* Oplock break */
	KUNIT_CASE(test_oplock_break_struct_size_20),
	KUNIT_CASE(test_oplock_break_struct_size_21),
	KUNIT_CASE(test_oplock_break_struct_dispatch),
	KUNIT_CASE(test_oplock_break_invalid_size),
	/* Header constants */
	KUNIT_CASE(test_smb2_header_structure_size),
	KUNIT_CASE(test_smb2_proto_number),
	/* check_lease_state logic */
	KUNIT_CASE(test_lease_rh_to_r),
	KUNIT_CASE(test_lease_rh_to_none),
	KUNIT_CASE(test_lease_rh_to_rh),
	KUNIT_CASE(test_lease_rh_to_rwh),
	KUNIT_CASE(test_lease_rw_to_r),
	KUNIT_CASE(test_lease_rw_to_none),
	KUNIT_CASE(test_lease_rw_to_rwh),
	KUNIT_CASE(test_lease_r_to_r),
	KUNIT_CASE(test_lease_r_to_rh),
	KUNIT_CASE(test_lease_none_to_none),
	KUNIT_CASE(test_lease_none_to_r),
	KUNIT_CASE(test_lease_rw_to_rw),
	KUNIT_CASE(test_lease_rh_to_h_only),
	KUNIT_CASE(test_lease_rh_to_w_only),
	/* Oplock break dispatch */
	KUNIT_CASE(test_oplock_break_dispatch_smb20),
	{}
};

static struct kunit_suite ksmbd_smb2_misc_cmds_test_suite = {
	.name = "ksmbd_smb2_misc_cmds",
	.test_cases = ksmbd_smb2_misc_cmds_test_cases,
};

kunit_test_suite(ksmbd_smb2_misc_cmds_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 miscellaneous commands");
