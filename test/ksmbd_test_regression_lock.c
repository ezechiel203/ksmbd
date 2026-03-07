// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit regression tests for SMB2 lock fixes
 *
 *   Tests known-fixed bugs to prevent regressions.
 *   All tests call real production functions via VISIBLE_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif
#include <linux/fs.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "vfs_cache.h"

/*
 * REG-001: Lock fl_end off-by-one (inclusive end)
 *
 * Regression: fl_end was set to fl_start + length instead of
 * fl_start + length - 1. POSIX fl_end is inclusive.
 * This is tested indirectly through smb2_lock_init which stores
 * unclamped SMB range.
 */
static void test_reg001_lock_init_stores_smb_range(struct kunit *test)
{
	struct file_lock fl;
	struct ksmbd_lock *lock;
	LIST_HEAD(lock_list);

	memset(&fl, 0, sizeof(fl));

	/*
	 * SMB range [100, 200) means start=100, end=200.
	 * The smb2_lock_init stores the original unclamped SMB range.
	 */
	lock = smb2_lock_init(&fl, F_SETLKW, SMB2_LOCKFLAG_EXCLUSIVE,
			      100, 200, &lock_list);
	KUNIT_ASSERT_NOT_NULL(test, lock);

	KUNIT_EXPECT_EQ(test, lock->start, 100ULL);
	KUNIT_EXPECT_EQ(test, lock->end, 200ULL);

	list_del(&lock->llist);
	kfree(lock);
}

/*
 * REG-002: Lock OFFSET_MAX skip (ranges beyond OFFSET_MAX)
 *
 * Regression: Locks at offsets > OFFSET_MAX caused false VFS
 * conflicts because they were all clamped to the same POSIX value.
 * Fix: skip vfs_lock_file for those ranges.
 * Tested by verifying smb2_lock_init handles large offsets.
 */
static void test_reg002_lock_init_large_offset(struct kunit *test)
{
	struct file_lock fl;
	struct ksmbd_lock *lock;
	LIST_HEAD(lock_list);

	memset(&fl, 0, sizeof(fl));

	/* Offset beyond OFFSET_MAX */
	lock = smb2_lock_init(&fl, F_SETLK, SMB2_LOCKFLAG_EXCLUSIVE,
			      (unsigned long long)OFFSET_MAX + 100,
			      (unsigned long long)OFFSET_MAX + 200,
			      &lock_list);
	KUNIT_ASSERT_NOT_NULL(test, lock);

	KUNIT_EXPECT_EQ(test, lock->start, (unsigned long long)OFFSET_MAX + 100);
	KUNIT_EXPECT_EQ(test, lock->end, (unsigned long long)OFFSET_MAX + 200);

	list_del(&lock->llist);
	kfree(lock);
}

/*
 * REG-003: Lock overlap with wrap-around
 *
 * Regression: Overlap check did not handle wrap-around at 2^64
 * where end==0 means "wrapped past max". smb2_lock_init stores
 * the raw SMB range including end=0 for wrapped ranges.
 */
static void test_reg003_lock_init_wrap_around(struct kunit *test)
{
	struct file_lock fl;
	struct ksmbd_lock *lock;
	LIST_HEAD(lock_list);

	memset(&fl, 0, sizeof(fl));

	/* offset=~0, length=1 => end wraps to 0 */
	lock = smb2_lock_init(&fl, F_SETLK, SMB2_LOCKFLAG_EXCLUSIVE,
			      ~0ULL, 0ULL, &lock_list);
	KUNIT_ASSERT_NOT_NULL(test, lock);

	KUNIT_EXPECT_EQ(test, lock->start, ~0ULL);
	KUNIT_EXPECT_EQ(test, lock->end, 0ULL);

	list_del(&lock->llist);
	kfree(lock);
}

/*
 * REG-004: Lock same-handle blocking upgrade
 *
 * Regression: POSIX-style lock upgrades (shared->exclusive on same
 * handle) were attempted, but SMB/NT doesn't support them.
 * Tested by ensuring smb2_set_flock_flags returns correct cmd
 * for blocking locks (F_SETLKW with FL_SLEEP flag set).
 */
static void test_reg004_blocking_lock_sleep_flag(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl, SMB2_LOCKFLAG_EXCLUSIVE);
	KUNIT_EXPECT_EQ(test, cmd, F_SETLKW);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	KUNIT_EXPECT_TRUE(test, fl.c.flc_flags & FL_SLEEP);
#else
	KUNIT_EXPECT_TRUE(test, fl.fl_flags & FL_SLEEP);
#endif
}

/*
 * REG-005: Lock sequence bit extraction (was reversed)
 *
 * Regression: LockSequenceNumber was extracted as (val>>28)&0xF
 * and LockSequenceIndex as (val>>24)&0xF. Fixed to:
 *   seq_num = val & 0xF (low 4 bits)
 *   seq_idx = (val >> 4) & 0xFFFFFFF (upper 28 bits)
 *
 * Verify that encoding (idx << 4) | num stores and retrieves correctly.
 */
static void test_reg005_lock_seq_bit_extraction(struct kunit *test)
{
	struct ksmbd_file fp;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Store: index=5, seq_num=0xA */
	store_lock_sequence(&fp, cpu_to_le32((5 << 4) | 0xA));

	/* Verify stored value */
	KUNIT_EXPECT_EQ(test, fp.lock_seq[5], (u8)0xA);

	/* Check: same encoding should be replay */
	KUNIT_EXPECT_EQ(test, check_lock_sequence(&fp, cpu_to_le32((5 << 4) | 0xA)), 1);

	/* Different seq_num at same index: should NOT be replay */
	KUNIT_EXPECT_EQ(test, check_lock_sequence(&fp, cpu_to_le32((5 << 4) | 0xB)), 0);
}

/*
 * REG-006: Lock replay returns OK not EAGAIN
 *
 * Regression: Replay was returning -EAGAIN/STATUS_FILE_NOT_AVAILABLE
 * instead of STATUS_OK (return 1 from check_lock_sequence).
 */
static void test_reg006_lock_replay_returns_one(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_durable = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	store_lock_sequence(&fp, cpu_to_le32((10 << 4) | 7));
	rc = check_lock_sequence(&fp, cpu_to_le32((10 << 4) | 7));

	/* Must return 1 (replay detected), not negative error */
	KUNIT_EXPECT_EQ(test, rc, 1);
}

/*
 * REG-007: Lock seq array size 65 (indices 1-64)
 *
 * Regression: Array was lock_seq[16], too small. Now lock_seq[65]
 * supports indices 1-64.
 */
static void test_reg007_lock_seq_index_boundary(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_persistent = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Index 1 (minimum valid) */
	store_lock_sequence(&fp, cpu_to_le32((1 << 4) | 2));
	rc = check_lock_sequence(&fp, cpu_to_le32((1 << 4) | 2));
	KUNIT_EXPECT_EQ(test, rc, 1);

	/* Index 64 (maximum valid) */
	store_lock_sequence(&fp, cpu_to_le32((64 << 4) | 3));
	rc = check_lock_sequence(&fp, cpu_to_le32((64 << 4) | 3));
	KUNIT_EXPECT_EQ(test, rc, 1);

	/* Index 65 (out of range) - should be skipped */
	rc = check_lock_sequence(&fp, cpu_to_le32((65 << 4) | 1));
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Index 0 (reserved) - should be skipped */
	rc = check_lock_sequence(&fp, cpu_to_le32((0 << 4) | 1));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

/*
 * REG-008: Lock sequence stored AFTER success only
 *
 * Regression: Sequence was stored BEFORE lock processing, meaning
 * a failed lock would still register as "replayed" on retry.
 * Fixed: store_lock_sequence() is called only after success.
 *
 * Verify that check_lock_sequence does NOT find a replay if
 * store_lock_sequence was never called (simulating failure path).
 */
static void test_reg008_lock_seq_not_stored_until_success(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Do NOT call store_lock_sequence (simulating lock failure path) */

	/* Check should find 0xFF (sentinel = not valid), so NOT a replay */
	rc = check_lock_sequence(&fp, cpu_to_le32((3 << 4) | 5));
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* The entry at index 3 was invalidated (set to 0xFF) by check */
	KUNIT_EXPECT_EQ(test, fp.lock_seq[3], (u8)0xFF);
}

static struct kunit_case ksmbd_regression_lock_test_cases[] = {
	KUNIT_CASE(test_reg001_lock_init_stores_smb_range),
	KUNIT_CASE(test_reg002_lock_init_large_offset),
	KUNIT_CASE(test_reg003_lock_init_wrap_around),
	KUNIT_CASE(test_reg004_blocking_lock_sleep_flag),
	KUNIT_CASE(test_reg005_lock_seq_bit_extraction),
	KUNIT_CASE(test_reg006_lock_replay_returns_one),
	KUNIT_CASE(test_reg007_lock_seq_index_boundary),
	KUNIT_CASE(test_reg008_lock_seq_not_stored_until_success),
	{}
};

static struct kunit_suite ksmbd_regression_lock_test_suite = {
	.name = "ksmbd_regression_lock",
	.test_cases = ksmbd_regression_lock_test_cases,
};

kunit_test_suite(ksmbd_regression_lock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit regression tests for ksmbd SMB2 lock fixes");
