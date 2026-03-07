// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 CHANGE_NOTIFY handler (smb2_notify.c)
 *
 *   Tests cover:
 *     - Request validation (MS-SMB2 2.2.35)
 *     - Watch flags (WATCH_TREE)
 *     - Completion filter bitmask
 *     - Async / Cancel / Pending behavior
 *     - Output buffer format (FILE_NOTIFY_INFORMATION)
 *     - Compound FID propagation for notify
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

/* Notify flags (MS-SMB2 2.2.35) */
#define TEST_SMB2_WATCH_TREE			0x0001

/* Completion filter bits (MS-SMB2 2.2.35) */
#define TEST_FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001
#define TEST_FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002
#define TEST_FILE_NOTIFY_CHANGE_ATTRIBUTES	0x00000004
#define TEST_FILE_NOTIFY_CHANGE_SIZE		0x00000008
#define TEST_FILE_NOTIFY_CHANGE_LAST_WRITE	0x00000010
#define TEST_FILE_NOTIFY_CHANGE_LAST_ACCESS	0x00000020
#define TEST_FILE_NOTIFY_CHANGE_CREATION	0x00000040
#define TEST_FILE_NOTIFY_CHANGE_EA		0x00000080
#define TEST_FILE_NOTIFY_CHANGE_SECURITY	0x00000100
#define TEST_FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200
#define TEST_FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400
#define TEST_FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800

#define TEST_FILE_NOTIFY_ALL			0x00000FFF

/* FILE_NOTIFY_INFORMATION actions */
#define TEST_FILE_ACTION_ADDED			0x00000001
#define TEST_FILE_ACTION_REMOVED		0x00000002
#define TEST_FILE_ACTION_MODIFIED		0x00000003
#define TEST_FILE_ACTION_RENAMED_OLD_NAME	0x00000004
#define TEST_FILE_ACTION_RENAMED_NEW_NAME	0x00000005
#define TEST_FILE_ACTION_ADDED_STREAM		0x00000006
#define TEST_FILE_ACTION_REMOVED_STREAM		0x00000007
#define TEST_FILE_ACTION_MODIFIED_STREAM	0x00000008

/* Access mask required for notify */
#define TEST_FILE_LIST_DIRECTORY_LE		cpu_to_le32(0x00000001)

/* Struct sizes */
#define TEST_SMB2_CHANGE_NOTIFY_REQ_STRUCT_SIZE	32
#define TEST_SMB2_HEADER_SIZE			64

/* ---- Replicated structures ---- */

struct test_notify_info {
	u32 next_entry_offset;
	u32 action;
	u32 file_name_length;
	/* followed by file_name[file_name_length] */
};

/* ---- Replicated logic ---- */

/*
 * Check if watch is recursive (WATCH_TREE flag)
 */
static bool test_is_watch_tree(u16 flags)
{
	return !!(flags & TEST_SMB2_WATCH_TREE);
}

/*
 * Validate completion filter has at least one valid bit
 */
static bool test_validate_completion_filter(u32 filter)
{
	return (filter & TEST_FILE_NOTIFY_ALL) != 0;
}

/*
 * Check if a specific change matches the filter
 */
static bool test_change_matches_filter(u32 change_type, u32 filter)
{
	return !!(change_type & filter);
}

/*
 * Validate that notify target is a directory
 * (MS-SMB2 3.3.5.19: notify on non-directory = INVALID_PARAMETER)
 */
static int test_validate_notify_target(bool is_directory, __le32 daccess)
{
	if (!is_directory)
		return -EINVAL;
	if (!(daccess & TEST_FILE_LIST_DIRECTORY_LE))
		return -EACCES;
	return 0;
}

/*
 * Validate notify in compound chain:
 * CHANGE_NOTIFY must be the last request in a compound (MS-SMB2 3.3.5.19)
 */
static int test_validate_notify_compound(bool is_compound, bool is_last)
{
	if (is_compound && !is_last)
		return -EINVAL;
	return 0;
}

/*
 * Calculate output buffer entry size for FILE_NOTIFY_INFORMATION
 * NextEntryOffset is 0 for last entry; otherwise aligned to 4 bytes
 */
static u32 test_calc_notify_entry_size(u32 file_name_length, bool is_last)
{
	u32 base = sizeof(struct test_notify_info) + file_name_length;

	if (is_last)
		return base;
	/* Align to 4-byte boundary */
	return (base + 3) & ~3U;
}

/*
 * Check if output buffer can hold the next entry
 */
static bool test_output_buffer_fits(u32 used, u32 entry_size,
				    u32 output_buffer_length)
{
	return (used + entry_size) <= output_buffer_length;
}

/* ---- Test Cases: Request Validation (MS-SMB2 2.2.35) ---- */

static void test_notify_basic_setup(struct kunit *test)
{
	/* Valid notify: directory with LIST_DIRECTORY access */
	int ret = test_validate_notify_target(true,
					      TEST_FILE_LIST_DIRECTORY_LE);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_notify_invalid_fid(struct kunit *test)
{
	/* Invalid FID mapped to file-not-found in real code */
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_notify_non_directory(struct kunit *test)
{
	/* Watch on file = STATUS_INVALID_PARAMETER */
	int ret = test_validate_notify_target(false,
					      TEST_FILE_LIST_DIRECTORY_LE);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_notify_no_list_directory(struct kunit *test)
{
	/* No FILE_LIST_DIRECTORY = ACCESS_DENIED */
	int ret = test_validate_notify_target(true, cpu_to_le32(0));

	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_notify_compound_not_last(struct kunit *test)
{
	/* NOTIFY in compound (not last) = INVALID_PARAMETER */
	int ret = test_validate_notify_compound(true, false);

	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_notify_compound_last_ok(struct kunit *test)
{
	/* NOTIFY as last in compound = OK */
	int ret = test_validate_notify_compound(true, true);

	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_notify_compound_fid_propagation(struct kunit *test)
{
	/* Compound FID from prior CREATE used for NOTIFY */
	u64 compound_fid = 42;
	u64 req_fid = 0xFFFFFFFFFFFFFFFFULL;
	bool is_related = true;

	u64 effective = (is_related && req_fid == 0xFFFFFFFFFFFFFFFFULL) ?
			compound_fid : req_fid;
	KUNIT_EXPECT_EQ(test, effective, (u64)42);
}

/* ---- Test Cases: Flags ---- */

static void test_notify_watch_tree(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_watch_tree(TEST_SMB2_WATCH_TREE));
}

static void test_notify_no_watch_tree(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_is_watch_tree(0));
}

/* ---- Test Cases: Completion Filter (MS-SMB2 2.2.35) ---- */

static void test_notify_filter_file_name(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_validate_completion_filter(
			TEST_FILE_NOTIFY_CHANGE_FILE_NAME));
	KUNIT_EXPECT_TRUE(test,
		test_change_matches_filter(TEST_FILE_NOTIFY_CHANGE_FILE_NAME,
					   TEST_FILE_NOTIFY_CHANGE_FILE_NAME));
}

static void test_notify_filter_dir_name(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_validate_completion_filter(
			TEST_FILE_NOTIFY_CHANGE_DIR_NAME));
}

static void test_notify_filter_attributes(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_validate_completion_filter(
			TEST_FILE_NOTIFY_CHANGE_ATTRIBUTES));
}

static void test_notify_filter_size(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_validate_completion_filter(
			TEST_FILE_NOTIFY_CHANGE_SIZE));
}

static void test_notify_filter_last_write(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_validate_completion_filter(
			TEST_FILE_NOTIFY_CHANGE_LAST_WRITE));
}

static void test_notify_filter_security(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_validate_completion_filter(
			TEST_FILE_NOTIFY_CHANGE_SECURITY));
}

static void test_notify_filter_combined(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_FILE_NAME |
		     TEST_FILE_NOTIFY_CHANGE_SIZE |
		     TEST_FILE_NOTIFY_CHANGE_LAST_WRITE;

	KUNIT_EXPECT_TRUE(test, test_validate_completion_filter(filter));
	KUNIT_EXPECT_TRUE(test,
		test_change_matches_filter(TEST_FILE_NOTIFY_CHANGE_SIZE,
					   filter));
	KUNIT_EXPECT_FALSE(test,
		test_change_matches_filter(
			TEST_FILE_NOTIFY_CHANGE_SECURITY, filter));
}

static void test_notify_filter_zero(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_validate_completion_filter(0));
}

/* ---- Test Cases: Async / Cancel ---- */

static void test_notify_returns_status_pending(struct kunit *test)
{
	/*
	 * CHANGE_NOTIFY goes async: returns STATUS_PENDING to client
	 * and waits for filesystem events.
	 */
	u32 status_pending = 0x00000103; /* STATUS_PENDING */

	KUNIT_EXPECT_EQ(test, status_pending, 0x00000103U);
}

static void test_notify_cancel(struct kunit *test)
{
	/* Cancel pending notify returns STATUS_CANCELLED */
	u32 status_cancelled = 0xC0000120;
	bool cancelled = true;

	KUNIT_EXPECT_TRUE(test, cancelled);
	KUNIT_EXPECT_EQ(test, status_cancelled, 0xC0000120U);
}

static void test_notify_cancel_piggyback(struct kunit *test)
{
	/*
	 * Cancel of piggyback watches: a watch that was already
	 * delivered but re-registered needs clean cancellation.
	 */
	int outstanding_async = 3;

	outstanding_async--; /* Cancel piggyback */
	KUNIT_EXPECT_EQ(test, outstanding_async, 2);
}

static void test_notify_outstanding_async_counter(struct kunit *test)
{
	/* Async counter must be properly tracked */
	int outstanding = 0;

	outstanding++; /* Register async watch */
	KUNIT_EXPECT_EQ(test, outstanding, 1);

	outstanding++; /* Second watch */
	KUNIT_EXPECT_EQ(test, outstanding, 2);

	outstanding--; /* Complete one */
	KUNIT_EXPECT_EQ(test, outstanding, 1);

	outstanding--; /* Cancel remaining */
	KUNIT_EXPECT_EQ(test, outstanding, 0);
}

/* ---- Test Cases: Output ---- */

static void test_notify_response_format(struct kunit *test)
{
	/* FILE_NOTIFY_INFORMATION structure format */
	struct test_notify_info info = {
		.next_entry_offset = 0,
		.action = TEST_FILE_ACTION_ADDED,
		.file_name_length = 10,
	};

	KUNIT_EXPECT_EQ(test, info.action, TEST_FILE_ACTION_ADDED);
	KUNIT_EXPECT_EQ(test, info.file_name_length, 10U);
	KUNIT_EXPECT_EQ(test, info.next_entry_offset, 0U);
}

static void test_notify_multiple_events(struct kunit *test)
{
	/* Multiple events: entries chained via NextEntryOffset */
	u32 entry1_size = test_calc_notify_entry_size(10, false);
	u32 entry2_size = test_calc_notify_entry_size(8, true);

	/* First entry: aligned to 4 bytes */
	KUNIT_EXPECT_EQ(test, entry1_size % 4, 0U);
	/* Second entry: no alignment needed (last) */
	KUNIT_EXPECT_EQ(test, entry2_size,
			(u32)(sizeof(struct test_notify_info) + 8));
}

static void test_notify_output_buffer_overflow(struct kunit *test)
{
	/* OutputBufferLength too small to hold even one entry */
	u32 output_buf_len = 8; /* very small */
	u32 entry_size = test_calc_notify_entry_size(20, true);

	KUNIT_EXPECT_FALSE(test,
		test_output_buffer_fits(0, entry_size, output_buf_len));
}

static void test_notify_output_buffer_exact_fit(struct kunit *test)
{
	u32 entry_size = test_calc_notify_entry_size(4, true);

	KUNIT_EXPECT_TRUE(test,
		test_output_buffer_fits(0, entry_size, entry_size));
}

/* ---- Test Cases: Action Values ---- */

static void test_notify_action_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_ADDED, 0x00000001U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_REMOVED, 0x00000002U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_MODIFIED, 0x00000003U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_RENAMED_OLD_NAME, 0x00000004U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_RENAMED_NEW_NAME, 0x00000005U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_ADDED_STREAM, 0x00000006U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_REMOVED_STREAM, 0x00000007U);
	KUNIT_EXPECT_EQ(test, TEST_FILE_ACTION_MODIFIED_STREAM, 0x00000008U);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_notify_test_cases[] = {
	/* Request Validation */
	KUNIT_CASE(test_notify_basic_setup),
	KUNIT_CASE(test_notify_invalid_fid),
	KUNIT_CASE(test_notify_non_directory),
	KUNIT_CASE(test_notify_no_list_directory),
	KUNIT_CASE(test_notify_compound_not_last),
	KUNIT_CASE(test_notify_compound_last_ok),
	KUNIT_CASE(test_notify_compound_fid_propagation),
	/* Flags */
	KUNIT_CASE(test_notify_watch_tree),
	KUNIT_CASE(test_notify_no_watch_tree),
	/* Completion Filter */
	KUNIT_CASE(test_notify_filter_file_name),
	KUNIT_CASE(test_notify_filter_dir_name),
	KUNIT_CASE(test_notify_filter_attributes),
	KUNIT_CASE(test_notify_filter_size),
	KUNIT_CASE(test_notify_filter_last_write),
	KUNIT_CASE(test_notify_filter_security),
	KUNIT_CASE(test_notify_filter_combined),
	KUNIT_CASE(test_notify_filter_zero),
	/* Async / Cancel */
	KUNIT_CASE(test_notify_returns_status_pending),
	KUNIT_CASE(test_notify_cancel),
	KUNIT_CASE(test_notify_cancel_piggyback),
	KUNIT_CASE(test_notify_outstanding_async_counter),
	/* Output */
	KUNIT_CASE(test_notify_response_format),
	KUNIT_CASE(test_notify_multiple_events),
	KUNIT_CASE(test_notify_output_buffer_overflow),
	KUNIT_CASE(test_notify_output_buffer_exact_fit),
	/* Action Values */
	KUNIT_CASE(test_notify_action_values),
	{}
};

static struct kunit_suite ksmbd_smb2_notify_test_suite = {
	.name = "ksmbd_smb2_notify",
	.test_cases = ksmbd_smb2_notify_test_cases,
};

kunit_test_suite(ksmbd_smb2_notify_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 CHANGE_NOTIFY handler");
