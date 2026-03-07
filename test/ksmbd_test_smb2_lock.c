// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB2 lock helpers (smb2_lock.c)
 *
 *   Tests call real smb2_set_flock_flags(), smb2_lock_init(),
 *   check_lock_sequence(), store_lock_sequence() via VISIBLE_IF_KUNIT.
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

/* --- smb2_set_flock_flags() tests --- */

static void test_set_flock_shared(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl, SMB2_LOCKFLAG_SHARED);

	KUNIT_EXPECT_EQ(test, cmd, F_SETLKW);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	KUNIT_EXPECT_EQ(test, (int)fl.c.flc_type, (int)F_RDLCK);
#else
	KUNIT_EXPECT_EQ(test, (int)fl.fl_type, (int)F_RDLCK);
#endif
}

static void test_set_flock_exclusive(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl, SMB2_LOCKFLAG_EXCLUSIVE);

	KUNIT_EXPECT_EQ(test, cmd, F_SETLKW);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	KUNIT_EXPECT_EQ(test, (int)fl.c.flc_type, (int)F_WRLCK);
#else
	KUNIT_EXPECT_EQ(test, (int)fl.fl_type, (int)F_WRLCK);
#endif
}

/* Implementation note: FAIL_IMMEDIATELY semantics per MS-SMB2 §3.3.5.14 */
static void test_set_flock_shared_fail_immediately(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl,
			SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY);

	KUNIT_EXPECT_EQ(test, cmd, F_SETLK);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	KUNIT_EXPECT_EQ(test, (int)fl.c.flc_type, (int)F_RDLCK);
#else
	KUNIT_EXPECT_EQ(test, (int)fl.fl_type, (int)F_RDLCK);
#endif
}

static void test_set_flock_exclusive_fail_immediately(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl,
			SMB2_LOCKFLAG_EXCLUSIVE | SMB2_LOCKFLAG_FAIL_IMMEDIATELY);

	KUNIT_EXPECT_EQ(test, cmd, F_SETLK);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	KUNIT_EXPECT_EQ(test, (int)fl.c.flc_type, (int)F_WRLCK);
#else
	KUNIT_EXPECT_EQ(test, (int)fl.fl_type, (int)F_WRLCK);
#endif
}

static void test_set_flock_unlock(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl, SMB2_LOCKFLAG_UNLOCK);

	KUNIT_EXPECT_EQ(test, cmd, F_SETLK);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	KUNIT_EXPECT_EQ(test, (int)fl.c.flc_type, (int)F_UNLCK);
#else
	KUNIT_EXPECT_EQ(test, (int)fl.fl_type, (int)F_UNLCK);
#endif
}

static void test_set_flock_invalid_flags(struct kunit *test)
{
	struct file_lock fl;
	int cmd;

	memset(&fl, 0, sizeof(fl));
	cmd = smb2_set_flock_flags(&fl, 0xFF);

	KUNIT_EXPECT_EQ(test, cmd, -EINVAL);
}

/* --- smb2_lock_init() tests --- */

static void test_lock_init_basic(struct kunit *test)
{
	struct file_lock fl;
	struct ksmbd_lock *lock;
	LIST_HEAD(lock_list);

	memset(&fl, 0, sizeof(fl));
	lock = smb2_lock_init(&fl, F_SETLKW, SMB2_LOCKFLAG_EXCLUSIVE,
			      100, 200, &lock_list);
	KUNIT_ASSERT_NOT_NULL(test, lock);

	KUNIT_EXPECT_EQ(test, lock->cmd, F_SETLKW);
	KUNIT_EXPECT_EQ(test, lock->start, 100ULL);
	KUNIT_EXPECT_EQ(test, lock->end, 200ULL);
	KUNIT_EXPECT_EQ(test, lock->flags, (unsigned int)SMB2_LOCKFLAG_EXCLUSIVE);
	KUNIT_EXPECT_EQ(test, lock->zero_len, 0);
	KUNIT_EXPECT_FALSE(test, list_empty(&lock_list));

	list_del(&lock->llist);
	kfree(lock);
}

static void test_lock_init_zero_len(struct kunit *test)
{
	struct file_lock fl;
	struct ksmbd_lock *lock;
	LIST_HEAD(lock_list);

	memset(&fl, 0, sizeof(fl));
	lock = smb2_lock_init(&fl, F_SETLK, SMB2_LOCKFLAG_SHARED,
			      500, 500, &lock_list);
	KUNIT_ASSERT_NOT_NULL(test, lock);

	KUNIT_EXPECT_EQ(test, lock->zero_len, 1);

	list_del(&lock->llist);
	kfree(lock);
}

/* --- check_lock_sequence() / store_lock_sequence() tests --- */

static void test_lock_seq_index_zero_skipped(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Index 0 means skip validation */
	rc = check_lock_sequence(&fp, cpu_to_le32(0x00000005));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_lock_seq_replay_detected(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* First: store sequence (index=1, seq_num=3) */
	/* Encode: low 4 bits = seq_num, upper bits = index */
	store_lock_sequence(&fp, cpu_to_le32((1 << 4) | 3));

	/* Replay: same index and seq_num should return 1 */
	rc = check_lock_sequence(&fp, cpu_to_le32((1 << 4) | 3));
	KUNIT_EXPECT_EQ(test, rc, 1);
}

static void test_lock_seq_different_seq_num(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	store_lock_sequence(&fp, cpu_to_le32((2 << 4) | 5));

	/* Different seq_num at same index: should proceed (invalidate) */
	rc = check_lock_sequence(&fp, cpu_to_le32((2 << 4) | 7));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_lock_seq_not_resilient_skipped(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = false;
	fp.is_durable = false;
	fp.is_persistent = false;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Non-resilient handle: always skip validation */
	rc = check_lock_sequence(&fp, cpu_to_le32((1 << 4) | 3));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_lock_seq_index_out_of_range(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Index > 64 is out of range, should skip */
	rc = check_lock_sequence(&fp, cpu_to_le32((65 << 4) | 1));
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_lock_seq_index_64_valid(struct kunit *test)
{
	struct ksmbd_file fp;
	int rc;

	memset(&fp, 0, sizeof(fp));
	spin_lock_init(&fp.lock_seq_lock);
	fp.is_resilient = true;
	memset(fp.lock_seq, 0xFF, sizeof(fp.lock_seq));

	/* Index 64 is the maximum valid index */
	store_lock_sequence(&fp, cpu_to_le32((64 << 4) | 9));
	rc = check_lock_sequence(&fp, cpu_to_le32((64 << 4) | 9));
	KUNIT_EXPECT_EQ(test, rc, 1);
}

static struct kunit_case ksmbd_smb2_lock_test_cases[] = {
	KUNIT_CASE(test_set_flock_shared),
	KUNIT_CASE(test_set_flock_exclusive),
	KUNIT_CASE(test_set_flock_shared_fail_immediately),
	KUNIT_CASE(test_set_flock_exclusive_fail_immediately),
	KUNIT_CASE(test_set_flock_unlock),
	KUNIT_CASE(test_set_flock_invalid_flags),
	KUNIT_CASE(test_lock_init_basic),
	KUNIT_CASE(test_lock_init_zero_len),
	KUNIT_CASE(test_lock_seq_index_zero_skipped),
	KUNIT_CASE(test_lock_seq_replay_detected),
	KUNIT_CASE(test_lock_seq_different_seq_num),
	KUNIT_CASE(test_lock_seq_not_resilient_skipped),
	KUNIT_CASE(test_lock_seq_index_out_of_range),
	KUNIT_CASE(test_lock_seq_index_64_valid),
	{}
};

static struct kunit_suite ksmbd_smb2_lock_test_suite = {
	.name = "ksmbd_smb2_lock",
	.test_cases = ksmbd_smb2_lock_test_cases,
};

kunit_test_suite(ksmbd_smb2_lock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 lock helpers");
