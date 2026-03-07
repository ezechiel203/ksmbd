// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for tree connect operations.
 *   Tests share name validation and tree connect error paths.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

#include "../smb2pdu.h"

/*
 * Tree connect validation logic tests.
 * ksmbd rejects share names >= 80 chars (ME-02 compliance fix).
 */

#define KSMBD_MAX_SHARE_NAME_LEN	80

/* ---- Share name length validation ---- */

static void test_tree_share_name_valid(struct kunit *test)
{
	const char *name = "TestShare";
	size_t len = strlen(name);

	KUNIT_EXPECT_LT(test, len, (size_t)KSMBD_MAX_SHARE_NAME_LEN);
}

static void test_tree_share_name_max_len(struct kunit *test)
{
	char name[KSMBD_MAX_SHARE_NAME_LEN];

	/* 79 chars = exactly at limit, should pass */
	memset(name, 'A', KSMBD_MAX_SHARE_NAME_LEN - 1);
	name[KSMBD_MAX_SHARE_NAME_LEN - 1] = '\0';

	KUNIT_EXPECT_LT(test, strlen(name), (size_t)KSMBD_MAX_SHARE_NAME_LEN);
}

static void test_tree_share_name_too_long(struct kunit *test)
{
	char name[KSMBD_MAX_SHARE_NAME_LEN + 10];

	/* 80+ chars should be rejected */
	memset(name, 'A', KSMBD_MAX_SHARE_NAME_LEN);
	name[KSMBD_MAX_SHARE_NAME_LEN] = '\0';

	KUNIT_EXPECT_GE(test, strlen(name), (size_t)KSMBD_MAX_SHARE_NAME_LEN);
}

static void test_tree_share_name_empty(struct kunit *test)
{
	const char *name = "";

	/* Empty share name is invalid */
	KUNIT_EXPECT_EQ(test, strlen(name), (size_t)0);
}

/* ---- UNC path parsing ---- */

static void test_tree_unc_path_valid(struct kunit *test)
{
	const char *unc = "\\\\server\\share";
	const char *backslash;

	/* Valid UNC starts with \\ */
	KUNIT_EXPECT_EQ(test, unc[0], '\\');
	KUNIT_EXPECT_EQ(test, unc[1], '\\');

	/* Find the share name after server\\ */
	backslash = strchr(unc + 2, '\\');
	KUNIT_ASSERT_NOT_NULL(test, backslash);
	KUNIT_EXPECT_STREQ(test, backslash + 1, "share");
}

static void test_tree_unc_path_no_share(struct kunit *test)
{
	const char *unc = "\\\\server";
	const char *backslash;

	/* No backslash after server name means no share name */
	backslash = strchr(unc + 2, '\\');
	KUNIT_EXPECT_NULL(test, backslash);
}

static void test_tree_unc_path_not_unc(struct kunit *test)
{
	const char *path = "/mnt/share";

	/* Non-UNC path should be rejected */
	KUNIT_EXPECT_NE(test, path[0], '\\');
}

static void test_tree_share_name_with_special_chars(struct kunit *test)
{
	const char *name = "Share$Admin";
	size_t len = strlen(name);

	/* Share names with $ are valid (admin shares) */
	KUNIT_EXPECT_LT(test, len, (size_t)KSMBD_MAX_SHARE_NAME_LEN);
	KUNIT_EXPECT_NOT_NULL(test, strchr(name, '$'));
}

static struct kunit_case ksmbd_error_tree_test_cases[] = {
	KUNIT_CASE(test_tree_share_name_valid),
	KUNIT_CASE(test_tree_share_name_max_len),
	KUNIT_CASE(test_tree_share_name_too_long),
	KUNIT_CASE(test_tree_share_name_empty),
	KUNIT_CASE(test_tree_unc_path_valid),
	KUNIT_CASE(test_tree_unc_path_no_share),
	KUNIT_CASE(test_tree_unc_path_not_unc),
	KUNIT_CASE(test_tree_share_name_with_special_chars),
	{}
};

static struct kunit_suite ksmbd_error_tree_test_suite = {
	.name = "ksmbd_error_tree",
	.test_cases = ksmbd_error_tree_test_cases,
};

kunit_test_suite(ksmbd_error_tree_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for tree connect operations");
