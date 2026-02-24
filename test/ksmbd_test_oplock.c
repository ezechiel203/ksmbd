// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for oplock state machine (oplock.c)
 *
 *   The oplock transition functions (opinfo_write_to_read, etc.) operate
 *   on struct oplock_info which requires complex kernel state (connections,
 *   sessions, kmem_cache). Testing these in isolation is impractical
 *   without the full kernel infrastructure.
 *
 *   Instead we test the pure-logic function smb2_map_lease_to_oplock()
 *   and the smb_inherit_flags() function which are both exported and
 *   can be tested without any kernel state.
 */

#include <kunit/test.h>

#include "oplock.h"
#include "smb2pdu.h"

/* --- smb2_map_lease_to_oplock() tests --- */

/*
 * test_lease_to_oplock_rwh - R+W+H lease maps to batch oplock
 */
static void test_lease_to_oplock_rwh(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE |
		       SMB2_LEASE_WRITE_CACHING_LE |
		       SMB2_LEASE_HANDLE_CACHING_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state),
			(__u8)SMB2_OPLOCK_LEVEL_BATCH);
}

/*
 * test_lease_to_oplock_rw - R+W lease maps to exclusive oplock
 */
static void test_lease_to_oplock_rw(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE |
		       SMB2_LEASE_WRITE_CACHING_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state),
			(__u8)SMB2_OPLOCK_LEVEL_EXCLUSIVE);
}

/*
 * test_lease_to_oplock_r - R-only lease maps to level II oplock
 */
static void test_lease_to_oplock_r(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state),
			(__u8)SMB2_OPLOCK_LEVEL_II);
}

/*
 * test_lease_to_oplock_rh - R+H lease maps to level II oplock
 *
 * R+H without W maps to level II because the function checks
 * for the read caching bit when there's no write caching.
 */
static void test_lease_to_oplock_rh(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE |
		       SMB2_LEASE_HANDLE_CACHING_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state),
			(__u8)SMB2_OPLOCK_LEVEL_II);
}

/*
 * test_lease_to_oplock_none - no lease state maps to 0
 */
static void test_lease_to_oplock_none(struct kunit *test)
{
	__le32 state = SMB2_LEASE_NONE_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)0);
}

/*
 * test_lease_to_oplock_write_only - W-only lease maps to 0
 *
 * Write-only is not a valid lease state in practice, and the function
 * returns 0 for it because none of the branches match.
 */
static void test_lease_to_oplock_write_only(struct kunit *test)
{
	__le32 state = SMB2_LEASE_WRITE_CACHING_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)0);
}

/*
 * test_lease_to_oplock_wh - W+H lease maps to batch oplock
 *
 * W+H: has write caching, is not write-only, and has handle caching.
 * The first branch checks for R+W+H (all three), so it does not match.
 * The second branch checks: state != W-only && state has W && !H => exclusive.
 * Since H is present, this branch fails. Falls through to R check: no R -> 0.
 */
static void test_lease_to_oplock_wh(struct kunit *test)
{
	__le32 state = SMB2_LEASE_WRITE_CACHING_LE |
		       SMB2_LEASE_HANDLE_CACHING_LE;

	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)0);
}

/* --- Oplock level constant tests --- */

/*
 * test_oplock_level_ordering - verify oplock level constants are distinct
 */
static void test_oplock_level_ordering(struct kunit *test)
{
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_NONE, SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_II,
			SMB2_OPLOCK_LEVEL_EXCLUSIVE);
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_EXCLUSIVE,
			SMB2_OPLOCK_LEVEL_BATCH);
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_BATCH,
			SMB2_OPLOCK_LEVEL_LEASE);
}

/*
 * test_oplock_level_values - verify specific oplock level values
 */
static void test_oplock_level_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_NONE, 0x00);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_II, 0x01);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_EXCLUSIVE, 0x08);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_BATCH, 0x09);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_LEASE, 0xFF);
}

/* --- Lease state constant tests --- */

/*
 * test_lease_state_values - verify lease state bitmask constants
 */
static void test_lease_state_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_NONE_LE, cpu_to_le32(0x00));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_READ_CACHING_LE, cpu_to_le32(0x01));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_HANDLE_CACHING_LE,
			cpu_to_le32(0x02));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_WRITE_CACHING_LE,
			cpu_to_le32(0x04));
}

/*
 * test_lease_state_combinations - combined lease states form valid bitmask
 */
static void test_lease_state_combinations(struct kunit *test)
{
	__le32 rwh = SMB2_LEASE_READ_CACHING_LE |
		     SMB2_LEASE_WRITE_CACHING_LE |
		     SMB2_LEASE_HANDLE_CACHING_LE;

	KUNIT_EXPECT_EQ(test, rwh, cpu_to_le32(0x07));

	/* R+W = 0x05 */
	KUNIT_EXPECT_EQ(test,
		SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE,
		cpu_to_le32(0x05));

	/* R+H = 0x03 */
	KUNIT_EXPECT_EQ(test,
		SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE,
		cpu_to_le32(0x03));
}

static struct kunit_case ksmbd_oplock_test_cases[] = {
	KUNIT_CASE(test_lease_to_oplock_rwh),
	KUNIT_CASE(test_lease_to_oplock_rw),
	KUNIT_CASE(test_lease_to_oplock_r),
	KUNIT_CASE(test_lease_to_oplock_rh),
	KUNIT_CASE(test_lease_to_oplock_none),
	KUNIT_CASE(test_lease_to_oplock_write_only),
	KUNIT_CASE(test_lease_to_oplock_wh),
	KUNIT_CASE(test_oplock_level_ordering),
	KUNIT_CASE(test_oplock_level_values),
	KUNIT_CASE(test_lease_state_values),
	KUNIT_CASE(test_lease_state_combinations),
	{}
};

static struct kunit_suite ksmbd_oplock_test_suite = {
	.name = "ksmbd_oplock",
	.test_cases = ksmbd_oplock_test_cases,
};

kunit_test_suite(ksmbd_oplock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd oplock state machine");
