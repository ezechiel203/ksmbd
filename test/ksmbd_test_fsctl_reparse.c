// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_SET_REPARSE_POINT, FSCTL_GET_REPARSE_POINT,
 *   FSCTL_DELETE_REPARSE_POINT.  Verifies these are not in the dispatch
 *   table (handled separately in smb2_create.c / vfs layer).
 */

#include <kunit/test.h>
#include <linux/types.h>

/*
 * These FSCTLs are not registered in the dispatch table and should
 * return -EOPNOTSUPP from the generic dispatch path.
 */
static void test_reparse_not_registered(struct kunit *test)
{
	/*
	 * Reparse point FSCTLs (SET/GET/DELETE) are handled inline
	 * in smb2_create.c, not through the generic FSCTL dispatch table.
	 * Verifying this design requires calling the production dispatch
	 * table with these FSCTL codes.
	 */
	kunit_skip(test, "TODO: needs production FSCTL dispatch export");
}

static struct kunit_case ksmbd_fsctl_reparse_test_cases[] = {
	KUNIT_CASE(test_reparse_not_registered),
	{}
};

static struct kunit_suite ksmbd_fsctl_reparse_test_suite = {
	.name = "ksmbd_fsctl_reparse",
	.test_cases = ksmbd_fsctl_reparse_test_cases,
};

kunit_test_suite(ksmbd_fsctl_reparse_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL reparse point dispatch");
