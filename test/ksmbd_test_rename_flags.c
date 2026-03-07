// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for rename flag constants (vfs.h)
 *
 *   Validates that ksmbd-internal rename flags occupy high bits
 *   that don't conflict with kernel RENAME_* flags, and that
 *   the mask correctly covers all defined flags.
 */

#include <kunit/test.h>
#include "vfs.h"

/* Test that POSIX flag bits don't overlap with kernel RENAME_* flags (low byte) */
static void test_rename_posix_flag_no_overlap(struct kunit *test)
{
	/* Linux kernel RENAME_NOREPLACE=1, RENAME_EXCHANGE=2, RENAME_WHITEOUT=4 */
	KUNIT_EXPECT_EQ(test, KSMBD_RENAME_POSIX_SEMANTICS & 0xFF, 0U);
}

static void test_rename_readonly_flag_no_overlap(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_RENAME_IGNORE_READONLY & 0xFF, 0U);
}

static void test_rename_flags_are_distinct(struct kunit *test)
{
	KUNIT_EXPECT_NE(test, KSMBD_RENAME_POSIX_SEMANTICS,
			KSMBD_RENAME_IGNORE_READONLY);
	KUNIT_EXPECT_EQ(test,
			KSMBD_RENAME_POSIX_SEMANTICS & KSMBD_RENAME_IGNORE_READONLY,
			0U);
}

static void test_rename_mask_covers_all_flags(struct kunit *test)
{
	unsigned int all_flags = KSMBD_RENAME_POSIX_SEMANTICS |
				 KSMBD_RENAME_IGNORE_READONLY;

	KUNIT_EXPECT_EQ(test, KSMBD_RENAME_FLAGS_MASK, all_flags);
}

static void test_rename_mask_strips_ksmbd_bits(struct kunit *test)
{
	unsigned int flags = KSMBD_RENAME_POSIX_SEMANTICS |
			     KSMBD_RENAME_IGNORE_READONLY |
			     0x02; /* RENAME_EXCHANGE */
	unsigned int kernel_only = flags & ~KSMBD_RENAME_FLAGS_MASK;

	KUNIT_EXPECT_EQ(test, kernel_only, 0x02U);
}

static void test_rename_posix_is_bit24(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_RENAME_POSIX_SEMANTICS, (unsigned int)BIT(24));
}

static void test_rename_readonly_is_bit25(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_RENAME_IGNORE_READONLY, (unsigned int)BIT(25));
}

static struct kunit_case ksmbd_rename_flags_test_cases[] = {
	KUNIT_CASE(test_rename_posix_flag_no_overlap),
	KUNIT_CASE(test_rename_readonly_flag_no_overlap),
	KUNIT_CASE(test_rename_flags_are_distinct),
	KUNIT_CASE(test_rename_mask_covers_all_flags),
	KUNIT_CASE(test_rename_mask_strips_ksmbd_bits),
	KUNIT_CASE(test_rename_posix_is_bit24),
	KUNIT_CASE(test_rename_readonly_is_bit25),
	{}
};

static struct kunit_suite ksmbd_rename_flags_test_suite = {
	.name = "ksmbd_rename_flags",
	.test_cases = ksmbd_rename_flags_test_cases,
};

kunit_test_suite(ksmbd_rename_flags_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd rename flag constants");
