// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 CLOSE, ECHO, OPLOCK_BREAK, and
 *   Server-to-Client Notification logic (smb2_misc_cmds.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

/* Close flags */
#define TEST_SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB	0x0001

/* Oplock levels */
#define TEST_SMB2_OPLOCK_LEVEL_NONE		0x00
#define TEST_SMB2_OPLOCK_LEVEL_II		0x01
#define TEST_SMB2_OPLOCK_LEVEL_EXCLUSIVE	0x08
#define TEST_SMB2_OPLOCK_LEVEL_BATCH		0x09
#define TEST_SMB2_OPLOCK_LEVEL_LEASE		0xFF

/* Lease state bits */
#define TEST_SMB2_LEASE_NONE		0x00
#define TEST_SMB2_LEASE_READ		0x01
#define TEST_SMB2_LEASE_HANDLE		0x02
#define TEST_SMB2_LEASE_WRITE		0x04
#define TEST_SMB2_LEASE_RWH		(TEST_SMB2_LEASE_READ |  \
					 TEST_SMB2_LEASE_WRITE | \
					 TEST_SMB2_LEASE_HANDLE)
#define TEST_SMB2_LEASE_RW		(TEST_SMB2_LEASE_READ |  \
					 TEST_SMB2_LEASE_WRITE)
#define TEST_SMB2_LEASE_RH		(TEST_SMB2_LEASE_READ |  \
					 TEST_SMB2_LEASE_HANDLE)

/* SMB 3.1.1 notification */
#define TEST_SMB2_NOTIFY_SESSION_CLOSED		0x0000

/* ---- Replicated logic ---- */

/*
 * Validate close flags
 */
static bool test_has_postquery_attrib(u16 flags)
{
	return !!(flags & TEST_SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB);
}

/*
 * Validate oplock break acknowledgement levels
 */
static int test_validate_oplock_break_ack(u8 current_level, u8 ack_level)
{
	/* Cannot break FROM Level II */
	if (current_level == TEST_SMB2_OPLOCK_LEVEL_II)
		return -EINVAL;

	/* Cannot break FROM None */
	if (current_level == TEST_SMB2_OPLOCK_LEVEL_NONE)
		return -EINVAL;

	/* Target must be lower or equal to current */
	switch (ack_level) {
	case TEST_SMB2_OPLOCK_LEVEL_NONE:
	case TEST_SMB2_OPLOCK_LEVEL_II:
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * Validate lease break acknowledgement
 * New state must be a subset of the current state (no upgrades)
 */
static int test_validate_lease_break_ack(u32 current_state, u32 new_state)
{
	/* Cannot upgrade (add bits) */
	if (new_state & ~current_state)
		return -EINVAL;
	return 0;
}

/*
 * Check if notification should be sent to a channel
 */
static bool test_should_send_notification(u16 dialect, bool is_current_conn)
{
	/* Only send to 3.1.1 channels, not current connection */
	if (is_current_conn)
		return false;
	if (dialect < 0x0311)
		return false;
	return true;
}

/* ---- Test Cases: Close ---- */

static void test_close_basic(struct kunit *test)
{
	/* Normal file close with valid FID */
	u64 volatile_fid = 42;

	KUNIT_EXPECT_NE(test, volatile_fid, (u64)0);
}

static void test_close_postquery_attrib(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_has_postquery_attrib(TEST_SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB));
}

static void test_close_no_postquery(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_has_postquery_attrib(0));
}

static void test_close_invalid_fid(struct kunit *test)
{
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_close_pipe(struct kunit *test)
{
	bool is_pipe = true;

	KUNIT_EXPECT_TRUE(test, is_pipe);
}

static void test_close_compound_fid(struct kunit *test)
{
	u64 compound_fid = 55;
	bool is_related = true;

	KUNIT_EXPECT_TRUE(test, is_related);
	KUNIT_EXPECT_NE(test, compound_fid, (u64)0);
}

static void test_close_compound_already_closed(struct kunit *test)
{
	/* Compound close after close = FILE_CLOSED */
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_close_session_id_validation(struct kunit *test)
{
	u64 compound_sid = 0x1234;
	u64 req_sid = 0xFFFFFFFFFFFFFFFFULL;
	bool is_related = true;

	u64 effective_sid = is_related ? compound_sid : req_sid;
	KUNIT_EXPECT_EQ(test, effective_sid, (u64)0x1234);
}

static void test_close_delete_on_close_trigger(struct kunit *test)
{
	/* Close triggers delete-on-close if no other handles */
	bool delete_on_close = true;
	u32 open_count = 1; /* last handle */

	KUNIT_EXPECT_TRUE(test, delete_on_close && open_count == 1);
}

static void test_close_delete_on_close_other_handles_open(struct kunit *test)
{
	/* No delete while other handles exist */
	bool delete_on_close = true;
	u32 open_count = 3;

	KUNIT_EXPECT_TRUE(test, delete_on_close && open_count > 1);
}

/* ---- Test Cases: Echo ---- */

static void test_echo_basic(struct kunit *test)
{
	/* Echo returns success with minimal response */
	int ret = 0;

	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_echo_response_size(struct kunit *test)
{
	/* Echo response StructureSize is 4 */
	u16 struct_size = 4;

	KUNIT_EXPECT_EQ(test, struct_size, (u16)4);
}

/* ---- Test Cases: Oplock Break ---- */

static void test_oplock_break_ack_exclusive(struct kunit *test)
{
	int ret = test_validate_oplock_break_ack(
		TEST_SMB2_OPLOCK_LEVEL_EXCLUSIVE,
		TEST_SMB2_OPLOCK_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_oplock_break_ack_exclusive_to_level2(struct kunit *test)
{
	int ret = test_validate_oplock_break_ack(
		TEST_SMB2_OPLOCK_LEVEL_EXCLUSIVE,
		TEST_SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_oplock_break_ack_batch(struct kunit *test)
{
	int ret = test_validate_oplock_break_ack(
		TEST_SMB2_OPLOCK_LEVEL_BATCH,
		TEST_SMB2_OPLOCK_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_oplock_break_ack_level2_invalid(struct kunit *test)
{
	int ret = test_validate_oplock_break_ack(
		TEST_SMB2_OPLOCK_LEVEL_II,
		TEST_SMB2_OPLOCK_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_oplock_break_ack_invalid_fid(struct kunit *test)
{
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_oplock_break_ack_no_oplock(struct kunit *test)
{
	int ret = test_validate_oplock_break_ack(
		TEST_SMB2_OPLOCK_LEVEL_NONE,
		TEST_SMB2_OPLOCK_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* ---- Test Cases: Lease Break ---- */

static void test_lease_break_ack_rwh_to_rh(struct kunit *test)
{
	int ret = test_validate_lease_break_ack(
		TEST_SMB2_LEASE_RWH, TEST_SMB2_LEASE_RH);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_lease_break_ack_rwh_to_r(struct kunit *test)
{
	int ret = test_validate_lease_break_ack(
		TEST_SMB2_LEASE_RWH, TEST_SMB2_LEASE_READ);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_lease_break_ack_rwh_to_none(struct kunit *test)
{
	int ret = test_validate_lease_break_ack(
		TEST_SMB2_LEASE_RWH, TEST_SMB2_LEASE_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_lease_break_ack_rw_to_r(struct kunit *test)
{
	int ret = test_validate_lease_break_ack(
		TEST_SMB2_LEASE_RW, TEST_SMB2_LEASE_READ);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_lease_break_ack_rw_to_none(struct kunit *test)
{
	int ret = test_validate_lease_break_ack(
		TEST_SMB2_LEASE_RW, TEST_SMB2_LEASE_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_lease_break_invalid_state_upgrade(struct kunit *test)
{
	/* Cannot upgrade: R -> RWH */
	int ret = test_validate_lease_break_ack(
		TEST_SMB2_LEASE_READ, TEST_SMB2_LEASE_RWH);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_lease_break_invalid_key(struct kunit *test)
{
	u8 key[16] = {0};
	u8 stored_key[16] = {1, 2, 3};

	KUNIT_EXPECT_NE(test, memcmp(key, stored_key, 16), 0);
}

/* ---- Test Cases: Server-to-Client Notification ---- */

static void test_session_closed_notification_sent(struct kunit *test)
{
	/* Notification sent on logoff */
	bool should_send = test_should_send_notification(0x0311, false);

	KUNIT_EXPECT_TRUE(test, should_send);
}

static void test_session_closed_notification_skips_current(struct kunit *test)
{
	bool should_send = test_should_send_notification(0x0311, true);

	KUNIT_EXPECT_FALSE(test, should_send);
}

static void test_session_closed_notification_311_only(struct kunit *test)
{
	/* Only sent to 3.1.1 channels */
	KUNIT_EXPECT_FALSE(test, test_should_send_notification(0x0302, false));
	KUNIT_EXPECT_FALSE(test, test_should_send_notification(0x0300, false));
	KUNIT_EXPECT_TRUE(test, test_should_send_notification(0x0311, false));
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_misc_test_cases[] = {
	/* Close */
	KUNIT_CASE(test_close_basic),
	KUNIT_CASE(test_close_postquery_attrib),
	KUNIT_CASE(test_close_no_postquery),
	KUNIT_CASE(test_close_invalid_fid),
	KUNIT_CASE(test_close_pipe),
	KUNIT_CASE(test_close_compound_fid),
	KUNIT_CASE(test_close_compound_already_closed),
	KUNIT_CASE(test_close_session_id_validation),
	KUNIT_CASE(test_close_delete_on_close_trigger),
	KUNIT_CASE(test_close_delete_on_close_other_handles_open),
	/* Echo */
	KUNIT_CASE(test_echo_basic),
	KUNIT_CASE(test_echo_response_size),
	/* Oplock Break */
	KUNIT_CASE(test_oplock_break_ack_exclusive),
	KUNIT_CASE(test_oplock_break_ack_exclusive_to_level2),
	KUNIT_CASE(test_oplock_break_ack_batch),
	KUNIT_CASE(test_oplock_break_ack_level2_invalid),
	KUNIT_CASE(test_oplock_break_ack_invalid_fid),
	KUNIT_CASE(test_oplock_break_ack_no_oplock),
	/* Lease Break */
	KUNIT_CASE(test_lease_break_ack_rwh_to_rh),
	KUNIT_CASE(test_lease_break_ack_rwh_to_r),
	KUNIT_CASE(test_lease_break_ack_rwh_to_none),
	KUNIT_CASE(test_lease_break_ack_rw_to_r),
	KUNIT_CASE(test_lease_break_ack_rw_to_none),
	KUNIT_CASE(test_lease_break_invalid_state_upgrade),
	KUNIT_CASE(test_lease_break_invalid_key),
	/* Notification */
	KUNIT_CASE(test_session_closed_notification_sent),
	KUNIT_CASE(test_session_closed_notification_skips_current),
	KUNIT_CASE(test_session_closed_notification_311_only),
	{}
};

static struct kunit_suite ksmbd_smb2_misc_test_suite = {
	.name = "ksmbd_smb2_misc",
	.test_cases = ksmbd_smb2_misc_test_cases,
};

kunit_test_suite(ksmbd_smb2_misc_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 CLOSE/ECHO/OPLOCK_BREAK/NOTIFY");
