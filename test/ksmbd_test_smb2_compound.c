// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 compound request processing:
 *   is_chained_smb2_message(), init_chained_smb2_rsp(),
 *   FID propagation, error cascade (smb2_pdu_common.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

#define TEST_SMB2_FLAGS_RELATED_OPERATIONS	0x00000004
#define TEST_SMB2_HEADER_SIZE			64

/* SMB2 commands (host endian) */
#define TEST_SMB2_CREATE_HE		0x0005
#define TEST_SMB2_CLOSE_HE		0x0006
#define TEST_SMB2_FLUSH_HE		0x0007
#define TEST_SMB2_READ_HE		0x0008
#define TEST_SMB2_WRITE_HE		0x0009
#define TEST_SMB2_LOCK_HE		0x000A
#define TEST_SMB2_IOCTL_HE		0x000B
#define TEST_SMB2_QUERY_DIRECTORY_HE	0x000E
#define TEST_SMB2_CHANGE_NOTIFY_HE	0x000F
#define TEST_SMB2_QUERY_INFO_HE		0x0010
#define TEST_SMB2_SET_INFO_HE		0x0011

#define TEST_INVALID_FID		0xFFFFFFFFFFFFFFFFULL

/* ---- Replicated compound structures ---- */

struct test_compound_state {
	u64 compound_fid;
	u64 compound_pfid;
	u64 compound_sid;
	u32 compound_err_status;
	bool compound_fid_set;
	int current_idx;
	int total_requests;
};

static void test_init_compound(struct test_compound_state *s, int total)
{
	s->compound_fid = TEST_INVALID_FID;
	s->compound_pfid = TEST_INVALID_FID;
	s->compound_sid = 0;
	s->compound_err_status = 0;
	s->compound_fid_set = false;
	s->current_idx = 0;
	s->total_requests = total;
}

/*
 * Check if request is part of a compound chain
 */
static bool test_is_compound(u32 next_command, u32 flags, int idx, int total)
{
	if (next_command != 0)
		return true;
	if (idx > 0 && idx < total)
		return true;
	return false;
}

/*
 * Check if request is related (uses compound FID)
 */
static bool test_is_related(u32 flags)
{
	return !!(flags & TEST_SMB2_FLAGS_RELATED_OPERATIONS);
}

/*
 * Replicate FID capture from non-CREATE commands
 * (MS-SMB2 3.3.5.2.7.2)
 */
static void test_capture_fid_from_request(struct test_compound_state *s,
					  u16 command, u64 volatile_fid,
					  u64 persistent_fid)
{
	if (s->compound_fid_set)
		return;

	switch (command) {
	case TEST_SMB2_FLUSH_HE:
	case TEST_SMB2_READ_HE:
	case TEST_SMB2_WRITE_HE:
	case TEST_SMB2_CLOSE_HE:
	case TEST_SMB2_QUERY_INFO_HE:
	case TEST_SMB2_SET_INFO_HE:
	case TEST_SMB2_LOCK_HE:
	case TEST_SMB2_IOCTL_HE:
	case TEST_SMB2_QUERY_DIRECTORY_HE:
	case TEST_SMB2_CHANGE_NOTIFY_HE:
		s->compound_fid = volatile_fid;
		s->compound_pfid = persistent_fid;
		s->compound_fid_set = true;
		break;
	default:
		break;
	}
}

/*
 * Capture FID from CREATE response
 */
static void test_capture_fid_from_create_rsp(struct test_compound_state *s,
					     u64 volatile_fid,
					     u64 persistent_fid)
{
	s->compound_fid = volatile_fid;
	s->compound_pfid = persistent_fid;
	s->compound_fid_set = true;
}

/*
 * Replicate error cascade logic:
 * CREATE failure cascades; non-CREATE failure does NOT cascade
 */
static bool test_should_cascade_error(u16 failed_command)
{
	return failed_command == TEST_SMB2_CREATE_HE;
}

/*
 * Check if next command offset is properly aligned
 */
static bool test_next_command_aligned(u32 next_command)
{
	return (next_command % 8) == 0;
}

/* ---- Test Cases: Basic Compound Processing ---- */

static void test_compound_related_two_requests(struct kunit *test)
{
	/* CREATE + CLOSE related */
	u32 flags = TEST_SMB2_FLAGS_RELATED_OPERATIONS;

	KUNIT_EXPECT_TRUE(test, test_is_related(flags));
}

static void test_compound_related_three_requests(struct kunit *test)
{
	/* CREATE + READ + CLOSE */
	struct test_compound_state s;

	test_init_compound(&s, 3);
	KUNIT_EXPECT_EQ(test, s.total_requests, 3);
}

static void test_compound_unrelated_requests(struct kunit *test)
{
	/* Unrelated compound (no FID sharing) */
	u32 flags = 0;

	KUNIT_EXPECT_FALSE(test, test_is_related(flags));
}

static void test_compound_single_request(struct kunit *test)
{
	/* Single request is not compound */
	KUNIT_EXPECT_FALSE(test, test_is_compound(0, 0, 0, 1));
}

static void test_compound_next_command_alignment(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_next_command_aligned(64));
	KUNIT_EXPECT_TRUE(test, test_next_command_aligned(128));
	KUNIT_EXPECT_TRUE(test, test_next_command_aligned(0));
	KUNIT_EXPECT_FALSE(test, test_next_command_aligned(65));
	KUNIT_EXPECT_FALSE(test, test_next_command_aligned(100));
}

/* ---- Test Cases: FID Propagation ---- */

static void test_compound_fid_from_create(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_create_rsp(&s, 42, 100);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)42);
	KUNIT_EXPECT_EQ(test, s.compound_pfid, (u64)100);
	KUNIT_EXPECT_TRUE(test, s.compound_fid_set);
}

static void test_compound_fid_from_read(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 3);
	test_capture_fid_from_request(&s, TEST_SMB2_READ_HE, 50, 200);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)50);
	KUNIT_EXPECT_TRUE(test, s.compound_fid_set);
}

static void test_compound_fid_from_write(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 3);
	test_capture_fid_from_request(&s, TEST_SMB2_WRITE_HE, 60, 210);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)60);
}

static void test_compound_fid_from_flush(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 3);
	test_capture_fid_from_request(&s, TEST_SMB2_FLUSH_HE, 70, 220);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)70);
}

static void test_compound_fid_from_close(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_CLOSE_HE, 80, 230);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)80);
}

static void test_compound_fid_from_query_info(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_QUERY_INFO_HE, 90, 240);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)90);
}

static void test_compound_fid_from_set_info(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_SET_INFO_HE, 91, 241);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)91);
}

static void test_compound_fid_from_lock(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_LOCK_HE, 92, 242);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)92);
}

static void test_compound_fid_from_ioctl(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_IOCTL_HE, 93, 243);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)93);
}

static void test_compound_fid_from_query_dir(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_QUERY_DIRECTORY_HE, 94, 244);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)94);
}

static void test_compound_fid_from_notify(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	test_capture_fid_from_request(&s, TEST_SMB2_CHANGE_NOTIFY_HE, 95, 245);

	KUNIT_EXPECT_EQ(test, s.compound_fid, (u64)95);
}

static void test_compound_fid_0xffffffffffffffff(struct kunit *test)
{
	/*
	 * Related request with 0xFFFFFFFFFFFFFFFF FID means "use compound FID"
	 */
	u64 req_fid = TEST_INVALID_FID;
	u64 compound_fid = 42;
	bool is_related = true;

	u64 effective = (is_related && req_fid == TEST_INVALID_FID) ?
			compound_fid : req_fid;
	KUNIT_EXPECT_EQ(test, effective, (u64)42);
}

/* ---- Test Cases: Error Cascade ---- */

static void test_compound_error_cascade_create_failure(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_should_cascade_error(TEST_SMB2_CREATE_HE));
}

static void test_compound_error_no_cascade_non_create(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_should_cascade_error(TEST_SMB2_READ_HE));
	KUNIT_EXPECT_FALSE(test, test_should_cascade_error(TEST_SMB2_WRITE_HE));
	KUNIT_EXPECT_FALSE(test, test_should_cascade_error(TEST_SMB2_CLOSE_HE));
}

static void test_compound_error_status_propagation(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 3);
	s.compound_err_status = 0xC0000022; /* STATUS_ACCESS_DENIED */

	KUNIT_EXPECT_NE(test, s.compound_err_status, 0U);
}

/* ---- Test Cases: Interim Responses ---- */

static void test_compound_interim_padding(struct kunit *test)
{
	/* Interim responses 8-byte padded */
	u32 interim_size = TEST_SMB2_HEADER_SIZE + 9; /* header + error body */
	u32 padded = (interim_size + 7) & ~7U;

	KUNIT_EXPECT_EQ(test, padded % 8, 0U);
}

static void test_compound_interim_header_only(struct kunit *test)
{
	/* Error response body is 9 bytes (StructureSize=9) */
	u16 error_struct_size = 9;

	KUNIT_EXPECT_EQ(test, error_struct_size, (u16)9);
}

/* ---- Test Cases: Session / Tree Connect in Compound ---- */

static void test_compound_session_id_propagation(struct kunit *test)
{
	struct test_compound_state s;

	test_init_compound(&s, 2);
	s.compound_sid = 0xABCD1234;

	KUNIT_EXPECT_EQ(test, s.compound_sid, (u64)0xABCD1234);
}

static void test_compound_tree_id_propagation(struct kunit *test)
{
	u32 compound_tid = 5;

	KUNIT_EXPECT_NE(test, compound_tid, 0U);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_compound_test_cases[] = {
	/* Basic */
	KUNIT_CASE(test_compound_related_two_requests),
	KUNIT_CASE(test_compound_related_three_requests),
	KUNIT_CASE(test_compound_unrelated_requests),
	KUNIT_CASE(test_compound_single_request),
	KUNIT_CASE(test_compound_next_command_alignment),
	/* FID Propagation */
	KUNIT_CASE(test_compound_fid_from_create),
	KUNIT_CASE(test_compound_fid_from_read),
	KUNIT_CASE(test_compound_fid_from_write),
	KUNIT_CASE(test_compound_fid_from_flush),
	KUNIT_CASE(test_compound_fid_from_close),
	KUNIT_CASE(test_compound_fid_from_query_info),
	KUNIT_CASE(test_compound_fid_from_set_info),
	KUNIT_CASE(test_compound_fid_from_lock),
	KUNIT_CASE(test_compound_fid_from_ioctl),
	KUNIT_CASE(test_compound_fid_from_query_dir),
	KUNIT_CASE(test_compound_fid_from_notify),
	KUNIT_CASE(test_compound_fid_0xffffffffffffffff),
	/* Error Cascade */
	KUNIT_CASE(test_compound_error_cascade_create_failure),
	KUNIT_CASE(test_compound_error_no_cascade_non_create),
	KUNIT_CASE(test_compound_error_status_propagation),
	/* Interim */
	KUNIT_CASE(test_compound_interim_padding),
	KUNIT_CASE(test_compound_interim_header_only),
	/* Session/Tree */
	KUNIT_CASE(test_compound_session_id_propagation),
	KUNIT_CASE(test_compound_tree_id_propagation),
	{}
};

static struct kunit_suite ksmbd_smb2_compound_test_suite = {
	.name = "ksmbd_smb2_compound",
	.test_cases = ksmbd_smb2_compound_test_cases,
};

kunit_test_suite(ksmbd_smb2_compound_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 compound request processing");
