// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd reparse point helper functions (ksmbd_reparse.c)
 *
 *   Since KUnit tests cannot link against the ksmbd module directly,
 *   we replicate the pure-logic portions (slash conversion and NT prefix
 *   stripping) inline.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

/* ── Replicated logic from ksmbd_reparse.c ─── */

/**
 * test_convert_slashes() - Replicate ksmbd_convert_slashes()
 *
 * Converts all backslashes to forward slashes in-place.
 */
static void test_convert_slashes(char *path)
{
	char *p;

	for (p = path; *p; p++) {
		if (*p == '\\')
			*p = '/';
	}
}

/**
 * test_strip_nt_prefix() - Replicate ksmbd_strip_nt_prefix()
 *
 * Removes /??/ or //?/ prefixes from NT-style paths.
 * Note: The original operates on paths after slash conversion,
 * so backslash prefixes are already converted to forward slashes.
 */
static void test_strip_nt_prefix(char *path)
{
	int len = strlen(path);

	if (len > 4 &&
	    (strncmp(path, "/??/", 4) == 0 ||
	     strncmp(path, "//?/", 4) == 0)) {
		memmove(path, path + 4, len - 4 + 1);
	}
}

static bool test_is_safe_reparse_target(const char *target)
{
	const char *p;

	if (!target || !*target)
		return false;

	if (target[0] == '/')
		return false;

	p = target;
	while (*p) {
		const char *seg = p;
		size_t seglen;

		while (*p && *p != '/')
			p++;
		seglen = p - seg;

		if (seglen == 1 && seg[0] == '.')
			return false;
		if (seglen == 2 && seg[0] == '.' && seg[1] == '.')
			return false;

		if (*p == '/')
			p++;
	}

	return true;
}

/* ── ksmbd_convert_slashes() tests ─── */

static void test_convert_slashes_basic(struct kunit *test)
{
	char path[] = "a\\b\\c";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "a/b/c");
}

static void test_convert_slashes_no_backslashes(struct kunit *test)
{
	char path[] = "a/b/c";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "a/b/c");
}

static void test_convert_slashes_empty(struct kunit *test)
{
	char path[] = "";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "");
}

static void test_convert_slashes_mixed(struct kunit *test)
{
	char path[] = "a\\b/c\\d";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "a/b/c/d");
}

static void test_convert_slashes_all_backslash(struct kunit *test)
{
	char path[] = "\\\\\\\\";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "////");
}

static void test_convert_slashes_leading_trailing(struct kunit *test)
{
	char path[] = "\\folder\\file.txt\\";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "/folder/file.txt/");
}

static void test_convert_slashes_single_backslash(struct kunit *test)
{
	char path[] = "\\";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "/");
}

/* ── ksmbd_strip_nt_prefix() tests ─── */

static void test_strip_nt_prefix_question_marks(struct kunit *test)
{
	/*
	 * After slash conversion, \??\C:\path becomes /??/C:/path
	 */
	char path[] = "/??/C:/path";

	test_strip_nt_prefix(path);
	KUNIT_EXPECT_STREQ(test, path, "C:/path");
}

static void test_strip_nt_prefix_double_slash(struct kunit *test)
{
	/*
	 * After slash conversion, \\?\C:\path becomes //?/C:/path
	 */
	char path[] = "//?/C:/path";

	test_strip_nt_prefix(path);
	KUNIT_EXPECT_STREQ(test, path, "C:/path");
}

static void test_strip_nt_prefix_no_prefix(struct kunit *test)
{
	char path[] = "C:/path/to/file";

	test_strip_nt_prefix(path);
	/* Should remain unchanged */
	KUNIT_EXPECT_STREQ(test, path, "C:/path/to/file");
}

static void test_strip_nt_prefix_too_short(struct kunit *test)
{
	/* Path exactly 4 chars with prefix pattern but nothing after */
	char path[] = "/??/";

	test_strip_nt_prefix(path);
	/* len == 4, condition requires > 4, so no change */
	KUNIT_EXPECT_STREQ(test, path, "/??/");
}

static void test_strip_nt_prefix_just_prefix_plus_one(struct kunit *test)
{
	/* Path exactly 5 chars: prefix + "X" */
	char path[] = "/??/X";

	test_strip_nt_prefix(path);
	KUNIT_EXPECT_STREQ(test, path, "X");
}

/* ── Combined convert + strip workflow test ─── */

static void test_full_workflow(struct kunit *test)
{
	/*
	 * Simulate the full reparse target processing pipeline:
	 * Start: \??\C:\Users\test\file.txt
	 * After convert_slashes: /??/C:/Users/test/file.txt
	 * After strip_nt_prefix: C:/Users/test/file.txt
	 */
	char path[] = "\\??\\C:\\Users\\test\\file.txt";

	test_convert_slashes(path);
	KUNIT_EXPECT_STREQ(test, path, "/??/C:/Users/test/file.txt");

	test_strip_nt_prefix(path);
	KUNIT_EXPECT_STREQ(test, path, "C:/Users/test/file.txt");
}

/* ── reparse target safety checks ─── */

static void test_reparse_target_relative_ok(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_safe_reparse_target("dir/file.txt"));
}

static void test_reparse_target_reject_absolute(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_is_safe_reparse_target("/etc/passwd"));
}

static void test_reparse_target_reject_dotdot(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_is_safe_reparse_target("../escape"));
	KUNIT_EXPECT_FALSE(test, test_is_safe_reparse_target("a/../escape"));
}

static void test_reparse_target_reject_dot_component(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_is_safe_reparse_target("./file"));
	KUNIT_EXPECT_FALSE(test, test_is_safe_reparse_target("a/./file"));
}

static struct kunit_case ksmbd_reparse_test_cases[] = {
	KUNIT_CASE(test_convert_slashes_basic),
	KUNIT_CASE(test_convert_slashes_no_backslashes),
	KUNIT_CASE(test_convert_slashes_empty),
	KUNIT_CASE(test_convert_slashes_mixed),
	KUNIT_CASE(test_convert_slashes_all_backslash),
	KUNIT_CASE(test_convert_slashes_leading_trailing),
	KUNIT_CASE(test_convert_slashes_single_backslash),
	KUNIT_CASE(test_strip_nt_prefix_question_marks),
	KUNIT_CASE(test_strip_nt_prefix_double_slash),
	KUNIT_CASE(test_strip_nt_prefix_no_prefix),
	KUNIT_CASE(test_strip_nt_prefix_too_short),
	KUNIT_CASE(test_strip_nt_prefix_just_prefix_plus_one),
	KUNIT_CASE(test_full_workflow),
	KUNIT_CASE(test_reparse_target_relative_ok),
	KUNIT_CASE(test_reparse_target_reject_absolute),
	KUNIT_CASE(test_reparse_target_reject_dotdot),
	KUNIT_CASE(test_reparse_target_reject_dot_component),
	{}
};

static struct kunit_suite ksmbd_reparse_test_suite = {
	.name = "ksmbd_reparse",
	.test_cases = ksmbd_reparse_test_cases,
};

kunit_test_suite(ksmbd_reparse_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd reparse point helper functions");
