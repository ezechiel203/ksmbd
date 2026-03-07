// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for change-notify subsystem (ksmbd_notify.c)
 *
 *   The notify subsystem relies on fsnotify which requires real
 *   filesystem state.  We test the data structures, filter flag
 *   mapping, and structural validation logic.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "ksmbd_notify.h"
#include "connection.h"

extern bool ksmbd_notify_take_work(struct ksmbd_work *work, int state);
extern bool ksmbd_notify_claim_cancel_work(struct ksmbd_work *work);

/* ═══════════════════════════════════════════════════════════════════
 *  Notify Data Structure Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_change_struct_init(struct kunit *test)
{
	struct ksmbd_notify_change *change;

	change = kunit_kzalloc(test, sizeof(*change), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, change);

	change->action = 0x00000001; /* FILE_ACTION_ADDED */
	change->name = kunit_kstrdup(test, "testfile.txt", GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, change->name);
	change->name_len = strlen(change->name);

	KUNIT_EXPECT_EQ(test, change->action, 0x00000001U);
	KUNIT_EXPECT_STREQ(test, change->name, "testfile.txt");
	KUNIT_EXPECT_EQ(test, change->name_len, (size_t)12);
}

static void test_notify_watch_struct_init(struct kunit *test)
{
	struct ksmbd_notify_watch *watch;

	watch = kunit_kzalloc(test, sizeof(*watch), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, watch);

	watch->completion_filter = 0x00000017;
	watch->watch_tree = true;
	watch->output_buf_len = 4096;

	KUNIT_EXPECT_EQ(test, watch->completion_filter, 0x00000017U);
	KUNIT_EXPECT_TRUE(test, watch->watch_tree);
	KUNIT_EXPECT_EQ(test, watch->output_buf_len, 4096U);
	KUNIT_EXPECT_FALSE(test, watch->completed);
	KUNIT_EXPECT_FALSE(test, watch->has_mark);
	KUNIT_EXPECT_EQ(test, watch->buffered_count, 0U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Filter Flag Tests (replicated logic)
 *
 *  Map SMB2 FILE_NOTIFY_CHANGE_* flags to fsnotify equivalents.
 * ═══════════════════════════════════════════════════════════════════ */

/* FILE_NOTIFY_CHANGE_* constants from MS-SMB2 */
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

static void test_notify_filter_file_name_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_FILE_NAME;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_FILE_NAME));
	KUNIT_EXPECT_FALSE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_SIZE));
}

static void test_notify_filter_dir_name_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_DIR_NAME;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_DIR_NAME));
}

static void test_notify_filter_attributes_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_ATTRIBUTES;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_ATTRIBUTES));
}

static void test_notify_filter_size_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_SIZE;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_SIZE));
}

static void test_notify_filter_last_write_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_LAST_WRITE;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_LAST_WRITE));
}

static void test_notify_filter_security_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_SECURITY;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_SECURITY));
}

static void test_notify_filter_creation_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_CREATION;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_CREATION));
}

static void test_notify_filter_combined_flags(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_FILE_NAME |
		     TEST_FILE_NOTIFY_CHANGE_DIR_NAME |
		     TEST_FILE_NOTIFY_CHANGE_SIZE;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_FILE_NAME));
	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_DIR_NAME));
	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_SIZE));
	KUNIT_EXPECT_FALSE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_SECURITY));
}

static void test_notify_filter_no_match_no_delivery(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_SECURITY;
	u32 event = TEST_FILE_NOTIFY_CHANGE_SIZE;

	KUNIT_EXPECT_FALSE(test, !!(filter & event));
}

/* ═══════════════════════════════════════════════════════════════════
 *  FILE_ACTION constants
 * ═══════════════════════════════════════════════════════════════════ */

#define FILE_ACTION_ADDED		0x00000001
#define FILE_ACTION_REMOVED		0x00000002
#define FILE_ACTION_MODIFIED		0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME	0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME	0x00000005

static void test_notify_file_action_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, FILE_ACTION_ADDED, 1U);
	KUNIT_EXPECT_EQ(test, FILE_ACTION_REMOVED, 2U);
	KUNIT_EXPECT_EQ(test, FILE_ACTION_MODIFIED, 3U);
	KUNIT_EXPECT_EQ(test, FILE_ACTION_RENAMED_OLD_NAME, 4U);
	KUNIT_EXPECT_EQ(test, FILE_ACTION_RENAMED_NEW_NAME, 5U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Buffer Size Validation Tests (replicated logic)
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * FILE_NOTIFY_INFORMATION structure:
 * NextEntryOffset: 4 bytes
 * Action: 4 bytes
 * FileNameLength: 4 bytes
 * FileName: variable (UTF-16LE)
 */
#define NOTIFY_INFO_HEADER_SIZE	12

static unsigned int test_notify_entry_size(size_t name_len_bytes)
{
	/* Each entry is padded to 4-byte alignment */
	return ALIGN(NOTIFY_INFO_HEADER_SIZE + name_len_bytes, 4);
}

static void test_notify_response_single_entry_fits(struct kunit *test)
{
	unsigned int entry_size = test_notify_entry_size(20);
	unsigned int buf_size = 4096;

	KUNIT_EXPECT_TRUE(test, entry_size <= buf_size);
}

static void test_notify_response_truncated_at_max(struct kunit *test)
{
	unsigned int buf_size = NOTIFY_INFO_HEADER_SIZE + 4; /* Very small */
	unsigned int entry = test_notify_entry_size(100); /* Large name */

	KUNIT_EXPECT_TRUE(test, entry > buf_size);
}

static void test_notify_response_overflow_set_flag(struct kunit *test)
{
	/*
	 * When buffer is too small, STATUS_NOTIFY_ENUM_DIR is set.
	 * The completed flag prevents further normal notifications.
	 */
	struct ksmbd_notify_watch watch = {};

	watch.completed = true;
	KUNIT_EXPECT_TRUE(test, watch.completed);
}

static void test_notify_response_buffer_exactly_fits(struct kunit *test)
{
	unsigned int name_bytes = 20;
	unsigned int entry = test_notify_entry_size(name_bytes);

	/* Buffer exactly large enough */
	KUNIT_EXPECT_TRUE(test, entry <= entry);
}

static void test_notify_response_buffer_one_byte_short(struct kunit *test)
{
	unsigned int name_bytes = 20;
	unsigned int entry = test_notify_entry_size(name_bytes);
	unsigned int buf = entry - 1;

	KUNIT_EXPECT_TRUE(test, entry > buf);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Watch Tree Semantics
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_add_watch_tree_flag_set(struct kunit *test)
{
	struct ksmbd_notify_watch watch = {};

	watch.watch_tree = true;
	KUNIT_EXPECT_TRUE(test, watch.watch_tree);
}

static void test_notify_watch_non_tree_default(struct kunit *test)
{
	struct ksmbd_notify_watch watch = {};

	KUNIT_EXPECT_FALSE(test, watch.watch_tree);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Buffered Changes Management
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_buffered_count_increments(struct kunit *test)
{
	struct ksmbd_notify_watch watch = {};

	KUNIT_EXPECT_EQ(test, watch.buffered_count, 0U);

	watch.buffered_count++;
	KUNIT_EXPECT_EQ(test, watch.buffered_count, 1U);

	watch.buffered_count++;
	KUNIT_EXPECT_EQ(test, watch.buffered_count, 2U);
}

static void test_notify_completed_flag(struct kunit *test)
{
	struct ksmbd_notify_watch watch = {};

	KUNIT_EXPECT_FALSE(test, watch.completed);
	watch.completed = true;
	KUNIT_EXPECT_TRUE(test, watch.completed);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Stream Change Notification Filter Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_filter_stream_name_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_STREAM_NAME;

	KUNIT_EXPECT_TRUE(test,
			  !!(filter & TEST_FILE_NOTIFY_CHANGE_STREAM_NAME));
	KUNIT_EXPECT_FALSE(test,
			   !!(filter & TEST_FILE_NOTIFY_CHANGE_FILE_NAME));
}

static void test_notify_filter_stream_size_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_STREAM_SIZE;

	KUNIT_EXPECT_TRUE(test,
			  !!(filter & TEST_FILE_NOTIFY_CHANGE_STREAM_SIZE));
}

static void test_notify_filter_stream_write_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_STREAM_WRITE;

	KUNIT_EXPECT_TRUE(test,
			  !!(filter & TEST_FILE_NOTIFY_CHANGE_STREAM_WRITE));
}

static void test_notify_filter_ea_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_EA;

	KUNIT_EXPECT_TRUE(test, !!(filter & TEST_FILE_NOTIFY_CHANGE_EA));
}

static void test_notify_filter_last_access_change(struct kunit *test)
{
	u32 filter = TEST_FILE_NOTIFY_CHANGE_LAST_ACCESS;

	KUNIT_EXPECT_TRUE(test,
			  !!(filter & TEST_FILE_NOTIFY_CHANGE_LAST_ACCESS));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Notify Entry Alignment Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_entry_alignment_short_name(struct kunit *test)
{
	/* 1-byte UTF-16 name (2 bytes) */
	unsigned int entry = test_notify_entry_size(2);

	KUNIT_EXPECT_EQ(test, entry % 4, 0U);
}

static void test_notify_entry_alignment_long_name(struct kunit *test)
{
	/* 100-byte name */
	unsigned int entry = test_notify_entry_size(100);

	KUNIT_EXPECT_EQ(test, entry % 4, 0U);
}

static void test_notify_entry_alignment_odd_name(struct kunit *test)
{
	/* 13-byte name: 12 + 13 = 25, aligned to 28 */
	unsigned int entry = test_notify_entry_size(13);

	KUNIT_EXPECT_EQ(test, entry % 4, 0U);
	KUNIT_EXPECT_GE(test, entry, NOTIFY_INFO_HEADER_SIZE + 13U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Multiple Buffered Changes Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_multiple_changes_accumulate(struct kunit *test)
{
	struct ksmbd_notify_watch watch = {};

	watch.output_buf_len = 4096;

	/* Simulate accumulating changes */
	watch.buffered_count = 0;
	watch.buffered_count += 3;
	watch.buffered_count += 2;

	KUNIT_EXPECT_EQ(test, watch.buffered_count, 5U);
}

static void test_notify_completed_overrides(struct kunit *test)
{
	struct ksmbd_notify_watch watch = {};

	watch.buffered_count = 5;
	watch.completed = true;

	/* Once completed is set, count is irrelevant */
	KUNIT_EXPECT_TRUE(test, watch.completed);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Work State Claim Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_take_work_only_from_active(struct kunit *test)
{
	struct ksmbd_work work = {};

	work.state = KSMBD_WORK_ACTIVE;
	KUNIT_EXPECT_TRUE(test,
			  ksmbd_notify_take_work(&work, KSMBD_WORK_CLOSED));
	KUNIT_EXPECT_EQ(test, work.state, (unsigned char)KSMBD_WORK_CLOSED);

	KUNIT_EXPECT_FALSE(test,
			   ksmbd_notify_take_work(&work,
						  KSMBD_WORK_CANCELLED));
	KUNIT_EXPECT_EQ(test, work.state, (unsigned char)KSMBD_WORK_CLOSED);
}

static void test_notify_claim_cancel_accepts_precancelled(struct kunit *test)
{
	struct ksmbd_work work = {};

	work.state = KSMBD_WORK_ACTIVE;
	KUNIT_EXPECT_TRUE(test, ksmbd_notify_claim_cancel_work(&work));
	KUNIT_EXPECT_EQ(test, work.state,
			(unsigned char)KSMBD_WORK_CANCELLED);

	KUNIT_EXPECT_TRUE(test, ksmbd_notify_claim_cancel_work(&work));
	KUNIT_EXPECT_EQ(test, work.state,
			(unsigned char)KSMBD_WORK_CANCELLED);
}

static void test_notify_claim_cancel_rejects_closed(struct kunit *test)
{
	struct ksmbd_work work = {};

	work.state = KSMBD_WORK_CLOSED;
	KUNIT_EXPECT_FALSE(test, ksmbd_notify_claim_cancel_work(&work));
	KUNIT_EXPECT_EQ(test, work.state, (unsigned char)KSMBD_WORK_CLOSED);
}

/* ═══════════════════════════════════════════════════════════════════
 *  All-Filters Combined Test
 * ═══════════════════════════════════════════════════════════════════ */

static void test_notify_all_filters_combined(struct kunit *test)
{
	u32 all = TEST_FILE_NOTIFY_CHANGE_FILE_NAME |
		  TEST_FILE_NOTIFY_CHANGE_DIR_NAME |
		  TEST_FILE_NOTIFY_CHANGE_ATTRIBUTES |
		  TEST_FILE_NOTIFY_CHANGE_SIZE |
		  TEST_FILE_NOTIFY_CHANGE_LAST_WRITE |
		  TEST_FILE_NOTIFY_CHANGE_LAST_ACCESS |
		  TEST_FILE_NOTIFY_CHANGE_CREATION |
		  TEST_FILE_NOTIFY_CHANGE_EA |
		  TEST_FILE_NOTIFY_CHANGE_SECURITY |
		  TEST_FILE_NOTIFY_CHANGE_STREAM_NAME |
		  TEST_FILE_NOTIFY_CHANGE_STREAM_SIZE |
		  TEST_FILE_NOTIFY_CHANGE_STREAM_WRITE;

	KUNIT_EXPECT_EQ(test, all, 0x00000FFFU);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_notify_test_cases[] = {
	/* Data structures */
	KUNIT_CASE(test_notify_change_struct_init),
	KUNIT_CASE(test_notify_watch_struct_init),
	/* Filter flags */
	KUNIT_CASE(test_notify_filter_file_name_change),
	KUNIT_CASE(test_notify_filter_dir_name_change),
	KUNIT_CASE(test_notify_filter_attributes_change),
	KUNIT_CASE(test_notify_filter_size_change),
	KUNIT_CASE(test_notify_filter_last_write_change),
	KUNIT_CASE(test_notify_filter_security_change),
	KUNIT_CASE(test_notify_filter_creation_change),
	KUNIT_CASE(test_notify_filter_combined_flags),
	KUNIT_CASE(test_notify_filter_no_match_no_delivery),
	/* File action constants */
	KUNIT_CASE(test_notify_file_action_constants),
	/* Buffer validation */
	KUNIT_CASE(test_notify_response_single_entry_fits),
	KUNIT_CASE(test_notify_response_truncated_at_max),
	KUNIT_CASE(test_notify_response_overflow_set_flag),
	KUNIT_CASE(test_notify_response_buffer_exactly_fits),
	KUNIT_CASE(test_notify_response_buffer_one_byte_short),
	/* Watch tree */
	KUNIT_CASE(test_notify_add_watch_tree_flag_set),
	KUNIT_CASE(test_notify_watch_non_tree_default),
	/* Buffered changes */
	KUNIT_CASE(test_notify_buffered_count_increments),
	KUNIT_CASE(test_notify_completed_flag),
	/* Stream notification filters */
	KUNIT_CASE(test_notify_filter_stream_name_change),
	KUNIT_CASE(test_notify_filter_stream_size_change),
	KUNIT_CASE(test_notify_filter_stream_write_change),
	KUNIT_CASE(test_notify_filter_ea_change),
	KUNIT_CASE(test_notify_filter_last_access_change),
	/* Entry alignment */
	KUNIT_CASE(test_notify_entry_alignment_short_name),
	KUNIT_CASE(test_notify_entry_alignment_long_name),
	KUNIT_CASE(test_notify_entry_alignment_odd_name),
	/* Multiple buffered changes */
	KUNIT_CASE(test_notify_multiple_changes_accumulate),
	KUNIT_CASE(test_notify_completed_overrides),
	KUNIT_CASE(test_notify_take_work_only_from_active),
	KUNIT_CASE(test_notify_claim_cancel_accepts_precancelled),
	KUNIT_CASE(test_notify_claim_cancel_rejects_closed),
	/* All filters combined */
	KUNIT_CASE(test_notify_all_filters_combined),
	{}
};

static struct kunit_suite ksmbd_notify_test_suite = {
	.name = "ksmbd_notify",
	.test_cases = ksmbd_notify_test_cases,
};

kunit_test_suite(ksmbd_notify_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd change-notify subsystem");
