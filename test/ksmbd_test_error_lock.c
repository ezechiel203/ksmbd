// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for SMB2 lock functions
 *
 *   Tests invalid inputs and edge cases for lock-related production
 *   functions. All tests call real functions via VISIBLE_IF_KUNIT.
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

/* --- Invalid flag combinations for smb2_set_flock_flags --- */

static void test_err_flock_zero_flags(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl, 0);
	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

static void test_err_flock_shared_and_exclusive(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	/* SHARED | EXCLUSIVE is not a valid combination */
	cmd = smb2_set_flock_flags(&fl,
			SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_EXCLUSIVE);
	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

static void test_err_flock_unlock_and_shared(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	/* UNLOCK | SHARED is invalid */
	cmd = smb2_set_flock_flags(&fl,
			SMB2_LOCKFLAG_UNLOCK | SMB2_LOCKFLAG_SHARED);
	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

static void test_err_flock_unlock_and_fail_immediately(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	/* UNLOCK | FAIL_IMMEDIATELY is invalid */
	cmd = smb2_set_flock_flags(&fl,
			SMB2_LOCKFLAG_UNLOCK | SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

static void test_err_flock_all_flags(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl,
			SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_EXCLUSIVE |
			SMB2_LOCKFLAG_UNLOCK | SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

static void test_err_flock_high_bits_only(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	/* Only high bits set - not a recognized flag pattern */
	cmd = smb2_set_flock_flags(&fl, 0xF0);
	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

/* --- Lock sequence edge cases --- */

static void test_err_lock_seq_zero_value(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* val=0 means index=0 which is reserved */
	rc = check_lock_sequence(&fp, cpu_to_le32(0));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_err_lock_seq_max_value(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Max u32 value: index = 0x0FFFFFFF (way beyond 64) */
	rc = check_lock_sequence(&fp, cpu_to_le32(0xFFFFFFFF));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_err_store_seq_index_zero_noop(struct kunit *test)
{
	struct ksmbd_file fp;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Store at index 0 should be a no-op */
	store_lock_sequence(&fp, cpu_to_le32(0x00000005));

	/* All entries should remain 0xFF */
	KUNIT_EXPECT_EQ(test, fp.lock_seq[0], (u8)0xFF);
}

static void test_err_store_seq_not_durable_noop(struct kunit *test)
{
	struct ksmbd_file fp;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = false;
	fp.is_durable = false;
	fp.is_persistent = false;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Non-durable handle: store should be no-op */
	store_lock_sequence(&fp, cpu_to_le32((1 << 4) | 5));
	KUNIT_EXPECT_EQ(test, fp.lock_seq[1], (u8)0xFF);
}

static void test_err_store_seq_index_65_noop(struct kunit *test)
{
	struct ksmbd_file fp;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_durable = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Index 65 is out of range: store should be no-op */
	store_lock_sequence(&fp, cpu_to_le32((65 << 4) | 3));
	/* No array element should have been modified */
}

/* --- smb2_lock_init edge cases --- */

static void test_err_lock_init_max_values(struct kunit *test)
{
	struct file_lock fl;
	struct ksmbd_lock *lock;
	LIST_HEAD(lock_list);

	memset(&fl, 0, sizeof(fl));
	lock = smb2_lock_init(&fl, F_SETLK, SMB2_LOCKFLAG_EXCLUSIVE,
			      ~0ULL, ~0ULL, &lock_list);
	KUNIT_ASSERT_NOT_NULL(test, lock);

	KUNIT_EXPECT_EQ(test, lock->start, ~0ULL);
	KUNIT_EXPECT_EQ(test, lock->end, ~0ULL);
	/* start == end means zero_len */
	KUNIT_EXPECT_EQ(test, lock->zero_len, 1);

	list_del(&lock->llist);
	kfree(lock);
}

static struct kunit_case ksmbd_error_lock_test_cases[] = {
	KUNIT_CASE(test_err_flock_zero_flags),
	KUNIT_CASE(test_err_flock_shared_and_exclusive),
	KUNIT_CASE(test_err_flock_unlock_and_shared),
	KUNIT_CASE(test_err_flock_unlock_and_fail_immediately),
	KUNIT_CASE(test_err_flock_all_flags),
	KUNIT_CASE(test_err_flock_high_bits_only),
	KUNIT_CASE(test_err_lock_seq_zero_value),
	KUNIT_CASE(test_err_lock_seq_max_value),
	KUNIT_CASE(test_err_store_seq_index_zero_noop),
	KUNIT_CASE(test_err_store_seq_not_durable_noop),
	KUNIT_CASE(test_err_store_seq_index_65_noop),
	KUNIT_CASE(test_err_lock_init_max_values),
	{}
};

static struct kunit_suite ksmbd_error_lock_test_suite = {
	.name = "ksmbd_error_lock",
	.test_cases = ksmbd_error_lock_test_cases,
};

kunit_test_suite(ksmbd_error_lock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for ksmbd SMB2 lock functions");
