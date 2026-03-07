// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *
 *   Regression tests for VFS cache operations (vfs_cache.c)
 *
 *   REG-033: fd_limit_depleted atomic behavior
 *   REG-034: inode_hash stability (same inputs produce same output)
 *   REG-036: sanity_check with NULL fp/tcon
 */

#include <kunit/test.h>
#include <linux/slab.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "vfs_cache.h"

/*
 * REG-033: fd_limit_depleted should correctly handle the atomic counter.
 * After setting a limit of 2, the first two calls should return false.
 * The third call should return true (depleted).
 */
static void test_reg033_fd_limit_depleted_atomic(struct kunit *test)
{
	bool result;

	ksmbd_set_fd_limit(2);

	result = fd_limit_depleted();
	KUNIT_EXPECT_FALSE(test, result);

	result = fd_limit_depleted();
	KUNIT_EXPECT_FALSE(test, result);

	/* Third call: limit was 2, we took 2, now depleted */
	result = fd_limit_depleted();
	KUNIT_EXPECT_TRUE(test, result);

	/* Restore limit for other tests */
	ksmbd_set_fd_limit(1000);
}

/*
 * REG-034: inode_hash must be deterministic for the same inputs.
 */
static void test_reg034_inode_hash_stability(struct kunit *test)
{
	struct super_block sb;
	unsigned long h1, h2, h3;

	memset(&sb, 0, sizeof(sb));

	h1 = inode_hash(&sb, 42UL);
	h2 = inode_hash(&sb, 42UL);
	h3 = inode_hash(&sb, 42UL);

	KUNIT_EXPECT_EQ(test, h1, h2);
	KUNIT_EXPECT_EQ(test, h2, h3);
}

/*
 * REG-034b: Different hash inputs should produce different buckets
 *           (not guaranteed, but with high probability).
 */
static void test_reg034_inode_hash_distribution(struct kunit *test)
{
	struct super_block sb;
	unsigned long hashes[10];
	int i, collisions = 0;

	memset(&sb, 0, sizeof(sb));

	for (i = 0; i < 10; i++)
		hashes[i] = inode_hash(&sb, (unsigned long)(i * 1000 + 1));

	/* Count collisions */
	for (i = 0; i < 9; i++) {
		if (hashes[i] == hashes[i + 1])
			collisions++;
	}

	/* With 10 different inputs, having all collide is extremely unlikely */
	KUNIT_EXPECT_LT(test, collisions, 9);
}

/*
 * REG-036: __sanity_check with NULL fp returns false.
 */
static void test_reg036_sanity_check_null_fp(struct kunit *test)
{
	struct ksmbd_tree_connect tcon;

	memset(&tcon, 0, sizeof(tcon));
	KUNIT_EXPECT_FALSE(test, __sanity_check(&tcon, NULL));
}

/*
 * REG-036b: __sanity_check with matching tcon returns true.
 */
static void test_reg036_sanity_check_match(struct kunit *test)
{
	struct ksmbd_tree_connect tcon;
	struct ksmbd_file fp;

	memset(&tcon, 0, sizeof(tcon));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = &tcon;

	KUNIT_EXPECT_TRUE(test, __sanity_check(&tcon, &fp));
}

/*
 * REG-036c: __sanity_check with different tcon returns false.
 */
static void test_reg036_sanity_check_mismatch(struct kunit *test)
{
	struct ksmbd_tree_connect tcon1, tcon2;
	struct ksmbd_file fp;

	memset(&tcon1, 0, sizeof(tcon1));
	memset(&tcon2, 0, sizeof(tcon2));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = &tcon2;

	KUNIT_EXPECT_FALSE(test, __sanity_check(&tcon1, &fp));
}

static struct kunit_case ksmbd_regression_vfs_test_cases[] = {
	KUNIT_CASE(test_reg033_fd_limit_depleted_atomic),
	KUNIT_CASE(test_reg034_inode_hash_stability),
	KUNIT_CASE(test_reg034_inode_hash_distribution),
	KUNIT_CASE(test_reg036_sanity_check_null_fp),
	KUNIT_CASE(test_reg036_sanity_check_match),
	KUNIT_CASE(test_reg036_sanity_check_mismatch),
	{}
};

static struct kunit_suite ksmbd_regression_vfs_test_suite = {
	.name = "ksmbd_regression_vfs",
	.test_cases = ksmbd_regression_vfs_test_cases,
};

kunit_test_suite(ksmbd_regression_vfs_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit regression tests for ksmbd VFS cache operations");
