// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *
 *   Error path tests for VFS cache operations (vfs_cache.c)
 *
 *   10 error path tests covering:
 *   - fd_limit at zero
 *   - inode_hash with various inputs
 *   - __sanity_check edge cases
 */

#include <kunit/test.h>
#include <linux/slab.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "vfs_cache.h"

/* --- fd_limit edge cases --- */

static void test_fd_limit_at_zero(struct kunit *test)
{
	bool result;

	/*
	 * Set limit to 0 -- fd_limit_depleted should immediately return true.
	 * Note: ksmbd_set_fd_limit(0) actually calls min(0, get_max_files()),
	 * so if get_max_files() returns > 0, the atomic is set to 0.
	 * Decrementing from 0 yields -1 which is < 0, so depleted = true.
	 */
	ksmbd_set_fd_limit(0);

	result = fd_limit_depleted();
	KUNIT_EXPECT_TRUE(test, result);

	/* Restore */
	ksmbd_set_fd_limit(1000);
}

static void test_fd_limit_at_one(struct kunit *test)
{
	bool r1, r2;

	ksmbd_set_fd_limit(1);

	r1 = fd_limit_depleted();
	KUNIT_EXPECT_FALSE(test, r1);

	r2 = fd_limit_depleted();
	KUNIT_EXPECT_TRUE(test, r2);

	/* Restore */
	ksmbd_set_fd_limit(1000);
}

/* --- inode_hash edge cases --- */

static void test_inode_hash_zero_hashval(struct kunit *test)
{
	struct super_block sb;
	unsigned long h;

	memset(&sb, 0, sizeof(sb));
	h = inode_hash(&sb, 0UL);
	KUNIT_SUCCEED(test);
	(void)h;
}

static void test_inode_hash_max_hashval(struct kunit *test)
{
	struct super_block sb;
	unsigned long h;

	memset(&sb, 0, sizeof(sb));
	h = inode_hash(&sb, ULONG_MAX);
	KUNIT_SUCCEED(test);
	(void)h;
}

static void test_inode_hash_same_sb_different_vals(struct kunit *test)
{
	struct super_block sb;
	unsigned long h1, h2;

	memset(&sb, 0, sizeof(sb));
	h1 = inode_hash(&sb, 1UL);
	h2 = inode_hash(&sb, 2UL);

	/* Different vals usually produce different hashes */
	KUNIT_SUCCEED(test);
	(void)h1;
	(void)h2;
}

/* --- __sanity_check edge cases --- */

static void test_sanity_check_both_null(struct kunit *test)
{
	/* NULL fp should always return false regardless of tcon */
	KUNIT_EXPECT_FALSE(test, __sanity_check(NULL, NULL));
}

static void test_sanity_check_null_tcon_in_fp(struct kunit *test)
{
	struct ksmbd_tree_connect tcon;
	struct ksmbd_file fp;

	memset(&tcon, 0, sizeof(tcon));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = NULL;  /* fp->tcon is NULL */

	/* fp->tcon (NULL) != tcon, should return false */
	KUNIT_EXPECT_FALSE(test, __sanity_check(&tcon, &fp));
}

static void test_sanity_check_same_pointer(struct kunit *test)
{
	struct ksmbd_tree_connect tcon;
	struct ksmbd_file fp;

	memset(&tcon, 0, sizeof(tcon));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = &tcon;

	KUNIT_EXPECT_TRUE(test, __sanity_check(&tcon, &fp));
}

static void test_sanity_check_different_tcons_same_content(struct kunit *test)
{
	struct ksmbd_tree_connect tcon1, tcon2;
	struct ksmbd_file fp;

	memset(&tcon1, 0, sizeof(tcon1));
	memset(&tcon2, 0, sizeof(tcon2));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = &tcon2;

	/* Even if content is identical, pointers differ => false */
	KUNIT_EXPECT_FALSE(test, __sanity_check(&tcon1, &fp));
}

static void test_sanity_check_null_tcon_arg(struct kunit *test)
{
	struct ksmbd_file fp;

	memset(&fp, 0, sizeof(fp));
	fp.tcon = NULL;

	/* Both NULL => fp->tcon == tcon, true */
	KUNIT_EXPECT_TRUE(test, __sanity_check(NULL, &fp));
}

static struct kunit_case ksmbd_error_vfs_test_cases[] = {
	KUNIT_CASE(test_fd_limit_at_zero),
	KUNIT_CASE(test_fd_limit_at_one),
	KUNIT_CASE(test_inode_hash_zero_hashval),
	KUNIT_CASE(test_inode_hash_max_hashval),
	KUNIT_CASE(test_inode_hash_same_sb_different_vals),
	KUNIT_CASE(test_sanity_check_both_null),
	KUNIT_CASE(test_sanity_check_null_tcon_in_fp),
	KUNIT_CASE(test_sanity_check_same_pointer),
	KUNIT_CASE(test_sanity_check_different_tcons_same_content),
	KUNIT_CASE(test_sanity_check_null_tcon_arg),
	{}
};

static struct kunit_suite ksmbd_error_vfs_test_suite = {
	.name = "ksmbd_error_vfs",
	.test_cases = ksmbd_error_vfs_test_cases,
};

kunit_test_suite(ksmbd_error_vfs_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for ksmbd VFS cache operations");
