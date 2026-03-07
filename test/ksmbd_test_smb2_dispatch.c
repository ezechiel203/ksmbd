// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 command dispatch, header validation,
 *   message size calculation, and signing checks (server.c, smb2misc.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

#define TEST_SMB2_PROTO_NUMBER		0x424d53fe
#define TEST_SMB2_TRANSFORM_PROTO_NUM	0x424d53fd
#define TEST_SMB2_COMPRESSION_PROTO_NUM	0x424d53fc

#define TEST_SMB2_HEADER_STRUCT_SIZE	64
#define TEST_NUMBER_OF_SMB2_COMMANDS	0x0013

/* Commands */
#define TEST_SMB2_NEGOTIATE_HE		0x0000
#define TEST_SMB2_SESSION_SETUP_HE	0x0001
#define TEST_SMB2_LOGOFF_HE		0x0002
#define TEST_SMB2_TREE_CONNECT_HE	0x0003
#define TEST_SMB2_TREE_DISCONNECT_HE	0x0004
#define TEST_SMB2_CREATE_HE		0x0005
#define TEST_SMB2_CLOSE_HE		0x0006
#define TEST_SMB2_FLUSH_HE		0x0007
#define TEST_SMB2_READ_HE		0x0008
#define TEST_SMB2_WRITE_HE		0x0009
#define TEST_SMB2_LOCK_HE		0x000A
#define TEST_SMB2_IOCTL_HE		0x000B
#define TEST_SMB2_CANCEL_HE		0x000C
#define TEST_SMB2_ECHO_HE		0x000D
#define TEST_SMB2_QUERY_DIRECTORY_HE	0x000E
#define TEST_SMB2_CHANGE_NOTIFY_HE	0x000F
#define TEST_SMB2_QUERY_INFO_HE		0x0010
#define TEST_SMB2_SET_INFO_HE		0x0011
#define TEST_SMB2_OPLOCK_BREAK_HE	0x0012

/* Flags */
#define TEST_SMB2_FLAGS_SERVER_TO_REDIR	0x00000001
#define TEST_SMB2_FLAGS_ASYNC		0x00000002
#define TEST_SMB2_FLAGS_RELATED		0x00000004
#define TEST_SMB2_FLAGS_SIGNED		0x00000008

/* ---- Replicated logic ---- */

/*
 * Validate SMB2 protocol ID
 */
static bool test_is_smb2_protocol(u32 protocol_id)
{
	return protocol_id == TEST_SMB2_PROTO_NUMBER;
}

/*
 * Check if this is a transform header
 */
static bool test_is_transform_hdr(u32 protocol_id)
{
	return protocol_id == TEST_SMB2_TRANSFORM_PROTO_NUM;
}

/*
 * Check if this is a compression transform header
 */
static bool test_is_compression_hdr(u32 protocol_id)
{
	return protocol_id == TEST_SMB2_COMPRESSION_PROTO_NUM;
}

/*
 * Validate command number is in range
 */
static bool test_validate_command(u16 command)
{
	return command < TEST_NUMBER_OF_SMB2_COMMANDS;
}

/*
 * Check if this is a negotiate command
 */
static bool test_is_neg_cmd(u16 command)
{
	return command == TEST_SMB2_NEGOTIATE_HE;
}

/*
 * Check if this is a response
 */
static bool test_is_response(u32 flags)
{
	return !!(flags & TEST_SMB2_FLAGS_SERVER_TO_REDIR);
}

/*
 * Check signing requirement (MS-SMB2 3.2.4.24)
 */
static bool test_is_sign_required(u16 command, bool session_valid,
				  bool signing_required)
{
	/* NEGOTIATE never signed */
	if (command == TEST_SMB2_NEGOTIATE_HE)
		return false;

	/* CANCEL never signed (MS-SMB2 3.2.4.24) */
	if (command == TEST_SMB2_CANCEL_HE)
		return false;

	/* SESSION_SETUP (first round) not signed */
	if (command == TEST_SMB2_SESSION_SETUP_HE && !session_valid)
		return false;

	return signing_required;
}

/*
 * Calculate minimum message size for a command
 */
static u32 test_min_msg_size(u16 command)
{
	/* Minimum: SMB2 header + StructureSize field (2 bytes) */
	u32 base = TEST_SMB2_HEADER_STRUCT_SIZE + 2;

	switch (command) {
	case TEST_SMB2_NEGOTIATE_HE:
		return base + 34; /* 36 total body */
	case TEST_SMB2_SESSION_SETUP_HE:
		return base + 23; /* 25 total body */
	case TEST_SMB2_LOGOFF_HE:
	case TEST_SMB2_TREE_DISCONNECT_HE:
	case TEST_SMB2_ECHO_HE:
	case TEST_SMB2_CANCEL_HE:
		return base + 2; /* 4 total body */
	case TEST_SMB2_TREE_CONNECT_HE:
		return base + 7; /* 9 total body */
	case TEST_SMB2_CREATE_HE:
		return base + 55; /* 57 total body */
	case TEST_SMB2_CLOSE_HE:
	case TEST_SMB2_FLUSH_HE:
		return base + 22; /* 24 total body */
	case TEST_SMB2_READ_HE:
	case TEST_SMB2_WRITE_HE:
		return base + 47; /* 49 total body */
	case TEST_SMB2_LOCK_HE:
		return base + 46; /* 48 total body */
	case TEST_SMB2_IOCTL_HE:
		return base + 55; /* 57 total body */
	case TEST_SMB2_QUERY_DIRECTORY_HE:
		return base + 31; /* 33 total body */
	case TEST_SMB2_CHANGE_NOTIFY_HE:
		return base + 30; /* 32 total body */
	case TEST_SMB2_QUERY_INFO_HE:
		return base + 39; /* 41 total body */
	case TEST_SMB2_SET_INFO_HE:
		return base + 31; /* 33 total body */
	case TEST_SMB2_OPLOCK_BREAK_HE:
		return base + 22; /* 24 total body */
	default:
		return base;
	}
}

/*
 * Validate header structure size is 64
 */
static bool test_validate_header_struct_size(u16 struct_size)
{
	return struct_size == TEST_SMB2_HEADER_STRUCT_SIZE;
}

/* ---- Test Cases: Protocol ID Validation ---- */

static void test_dispatch_smb2_proto_id(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_smb2_protocol(0x424d53fe));
	KUNIT_EXPECT_FALSE(test, test_is_smb2_protocol(0x424d53fd));
	KUNIT_EXPECT_FALSE(test, test_is_smb2_protocol(0x00000000));
}

static void test_dispatch_transform_proto_id(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_transform_hdr(0x424d53fd));
	KUNIT_EXPECT_FALSE(test, test_is_transform_hdr(0x424d53fe));
}

static void test_dispatch_compression_proto_id(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_compression_hdr(0x424d53fc));
	KUNIT_EXPECT_FALSE(test, test_is_compression_hdr(0x424d53fe));
}

/* ---- Test Cases: Command Validation ---- */

static void test_dispatch_valid_commands(struct kunit *test)
{
	u16 cmd;

	for (cmd = 0; cmd < TEST_NUMBER_OF_SMB2_COMMANDS; cmd++)
		KUNIT_EXPECT_TRUE(test, test_validate_command(cmd));
}

static void test_dispatch_invalid_command(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_validate_command(TEST_NUMBER_OF_SMB2_COMMANDS));
	KUNIT_EXPECT_FALSE(test, test_validate_command(0xFFFF));
}

static void test_dispatch_is_neg_cmd(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_neg_cmd(TEST_SMB2_NEGOTIATE_HE));
	KUNIT_EXPECT_FALSE(test, test_is_neg_cmd(TEST_SMB2_SESSION_SETUP_HE));
}

/* ---- Test Cases: Response Detection ---- */

static void test_dispatch_is_response(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_is_response(TEST_SMB2_FLAGS_SERVER_TO_REDIR));
	KUNIT_EXPECT_FALSE(test, test_is_response(0));
}

/* ---- Test Cases: Header Validation ---- */

static void test_dispatch_header_struct_size(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_validate_header_struct_size(64));
	KUNIT_EXPECT_FALSE(test, test_validate_header_struct_size(63));
	KUNIT_EXPECT_FALSE(test, test_validate_header_struct_size(65));
}

/* ---- Test Cases: Message Size Calculation ---- */

static void test_dispatch_min_msg_negotiate(struct kunit *test)
{
	u32 min = test_min_msg_size(TEST_SMB2_NEGOTIATE_HE);

	KUNIT_EXPECT_EQ(test, min, 64U + 2U + 34U);
}

static void test_dispatch_min_msg_session_setup(struct kunit *test)
{
	u32 min = test_min_msg_size(TEST_SMB2_SESSION_SETUP_HE);

	KUNIT_EXPECT_EQ(test, min, 64U + 2U + 23U);
}

static void test_dispatch_min_msg_create(struct kunit *test)
{
	u32 min = test_min_msg_size(TEST_SMB2_CREATE_HE);

	KUNIT_EXPECT_EQ(test, min, 64U + 2U + 55U);
}

static void test_dispatch_min_msg_echo(struct kunit *test)
{
	u32 min = test_min_msg_size(TEST_SMB2_ECHO_HE);

	KUNIT_EXPECT_EQ(test, min, 64U + 2U + 2U);
}

static void test_dispatch_min_msg_read_write(struct kunit *test)
{
	u32 read_min = test_min_msg_size(TEST_SMB2_READ_HE);
	u32 write_min = test_min_msg_size(TEST_SMB2_WRITE_HE);

	KUNIT_EXPECT_EQ(test, read_min, write_min);
	KUNIT_EXPECT_EQ(test, read_min, 64U + 2U + 47U);
}

/* ---- Test Cases: Signing Requirement ---- */

static void test_smb2_is_sign_req_negotiate_excluded(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test,
		test_is_sign_required(TEST_SMB2_NEGOTIATE_HE, true, true));
}

static void test_smb2_is_sign_req_cancel_excluded(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test,
		test_is_sign_required(TEST_SMB2_CANCEL_HE, true, true));
}

static void test_smb2_is_sign_req_session_setup_excluded(struct kunit *test)
{
	/* First round: session not yet valid */
	KUNIT_EXPECT_FALSE(test,
		test_is_sign_required(TEST_SMB2_SESSION_SETUP_HE, false, true));

	/* Subsequent round: session valid -> signing required */
	KUNIT_EXPECT_TRUE(test,
		test_is_sign_required(TEST_SMB2_SESSION_SETUP_HE, true, true));
}

static void test_smb2_sign_req_normal_command(struct kunit *test)
{
	/* Normal command with signing required */
	KUNIT_EXPECT_TRUE(test,
		test_is_sign_required(TEST_SMB2_READ_HE, true, true));
	KUNIT_EXPECT_FALSE(test,
		test_is_sign_required(TEST_SMB2_READ_HE, true, false));
}

/* ---- Test Cases: Transform Header Validation ---- */

static void test_smb3_is_transform_hdr_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_transform_hdr(TEST_SMB2_TRANSFORM_PROTO_NUM));
}

static void test_smb3_is_transform_hdr_invalid_protocol(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_is_transform_hdr(0x00000000));
	KUNIT_EXPECT_FALSE(test, test_is_transform_hdr(TEST_SMB2_PROTO_NUMBER));
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_dispatch_test_cases[] = {
	/* Protocol ID */
	KUNIT_CASE(test_dispatch_smb2_proto_id),
	KUNIT_CASE(test_dispatch_transform_proto_id),
	KUNIT_CASE(test_dispatch_compression_proto_id),
	/* Command Validation */
	KUNIT_CASE(test_dispatch_valid_commands),
	KUNIT_CASE(test_dispatch_invalid_command),
	KUNIT_CASE(test_dispatch_is_neg_cmd),
	/* Response Detection */
	KUNIT_CASE(test_dispatch_is_response),
	/* Header */
	KUNIT_CASE(test_dispatch_header_struct_size),
	/* Message Size */
	KUNIT_CASE(test_dispatch_min_msg_negotiate),
	KUNIT_CASE(test_dispatch_min_msg_session_setup),
	KUNIT_CASE(test_dispatch_min_msg_create),
	KUNIT_CASE(test_dispatch_min_msg_echo),
	KUNIT_CASE(test_dispatch_min_msg_read_write),
	/* Signing */
	KUNIT_CASE(test_smb2_is_sign_req_negotiate_excluded),
	KUNIT_CASE(test_smb2_is_sign_req_cancel_excluded),
	KUNIT_CASE(test_smb2_is_sign_req_session_setup_excluded),
	KUNIT_CASE(test_smb2_sign_req_normal_command),
	/* Transform Header */
	KUNIT_CASE(test_smb3_is_transform_hdr_valid),
	KUNIT_CASE(test_smb3_is_transform_hdr_invalid_protocol),
	{}
};

static struct kunit_suite ksmbd_smb2_dispatch_test_suite = {
	.name = "ksmbd_smb2_dispatch",
	.test_cases = ksmbd_smb2_dispatch_test_cases,
};

kunit_test_suite(ksmbd_smb2_dispatch_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 command dispatch and validation");
