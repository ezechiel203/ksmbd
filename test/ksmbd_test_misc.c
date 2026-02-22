// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for miscellaneous helpers (misc.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time64.h>

#include "../misc.h"

/* --- match_pattern() tests --- */

/*
 * test_match_pattern_exact - exact string match with no wildcards
 */
static void test_match_pattern_exact(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, match_pattern("hello", 5, "hello"));
	KUNIT_EXPECT_FALSE(test, match_pattern("hello", 5, "world"));
}

/*
 * test_match_pattern_star - '*' wildcard matches any sequence
 */
static void test_match_pattern_star(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, match_pattern("hello.txt", 9, "*.txt"));
	KUNIT_EXPECT_TRUE(test, match_pattern("hello.txt", 9, "*"));
	KUNIT_EXPECT_TRUE(test, match_pattern("hello.txt", 9, "hello*"));
	KUNIT_EXPECT_TRUE(test, match_pattern("hello.txt", 9, "h*t"));
	KUNIT_EXPECT_FALSE(test, match_pattern("hello.txt", 9, "*.doc"));
}

/*
 * test_match_pattern_question - '?' wildcard matches single character
 */
static void test_match_pattern_question(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, match_pattern("cat", 3, "c?t"));
	KUNIT_EXPECT_TRUE(test, match_pattern("cot", 3, "c?t"));
	KUNIT_EXPECT_FALSE(test, match_pattern("cart", 4, "c?t"));
}

/*
 * test_match_pattern_combined - mixed wildcards
 */
static void test_match_pattern_combined(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, match_pattern("document.pdf", 12, "doc*.p?f"));
	KUNIT_EXPECT_TRUE(test, match_pattern("data123.csv", 11, "data*.c?v"));
	KUNIT_EXPECT_FALSE(test, match_pattern("data123.csv", 11, "data*.t?v"));
}

/*
 * test_match_pattern_empty - edge cases with empty strings
 */
static void test_match_pattern_empty(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, match_pattern("", 0, "*"));
	KUNIT_EXPECT_TRUE(test, match_pattern("", 0, ""));
	KUNIT_EXPECT_FALSE(test, match_pattern("", 0, "a"));
	KUNIT_EXPECT_FALSE(test, match_pattern("a", 1, ""));
}

/*
 * test_match_pattern_case_insensitive - matching is case-insensitive
 */
static void test_match_pattern_case_insensitive(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, match_pattern("Hello", 5, "hello"));
	KUNIT_EXPECT_TRUE(test, match_pattern("HELLO", 5, "hello"));
	KUNIT_EXPECT_TRUE(test, match_pattern("HeLLo.TXT", 9, "*.txt"));
}

/* --- ksmbd_validate_filename() tests --- */

/*
 * test_validate_filename_valid - normal filenames should pass
 */
static void test_validate_filename_valid(struct kunit *test)
{
	char name1[] = "document.txt";
	char name2[] = "my file (1).pdf";
	char name3[] = "folder";

	KUNIT_EXPECT_EQ(test, ksmbd_validate_filename(name1), 0);
	KUNIT_EXPECT_EQ(test, ksmbd_validate_filename(name2), 0);
	KUNIT_EXPECT_EQ(test, ksmbd_validate_filename(name3), 0);
}

/*
 * test_validate_filename_invalid_wildcards - wildcard chars are not allowed
 */
static void test_validate_filename_invalid_wildcards(struct kunit *test)
{
	char name_star[] = "file*.txt";
	char name_question[] = "file?.txt";

	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_star), 0);
	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_question), 0);
}

/*
 * test_validate_filename_invalid_special - special characters that are banned
 */
static void test_validate_filename_invalid_special(struct kunit *test)
{
	char name_lt[] = "file<name";
	char name_gt[] = "file>name";
	char name_pipe[] = "file|name";
	char name_quote[] = "file\"name";

	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_lt), 0);
	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_gt), 0);
	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_pipe), 0);
	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_quote), 0);
}

/*
 * test_validate_filename_control_char - control characters are not allowed
 */
static void test_validate_filename_control_char(struct kunit *test)
{
	char name_ctrl[] = "file\x01name";
	char name_null_mid[] = "file\x1fname";

	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_ctrl), 0);
	KUNIT_EXPECT_NE(test, ksmbd_validate_filename(name_null_mid), 0);
}

/*
 * test_validate_filename_empty - empty filename should pass
 *
 * ksmbd_validate_filename loops over characters; an empty string has no
 * invalid characters, so it returns 0.
 */
static void test_validate_filename_empty(struct kunit *test)
{
	char name[] = "";

	KUNIT_EXPECT_EQ(test, ksmbd_validate_filename(name), 0);
}

/* --- ksmbd_conv_path_to_unix() / ksmbd_conv_path_to_windows() tests --- */

/*
 * test_conv_path_to_unix - backslashes should be converted to forward slashes
 */
static void test_conv_path_to_unix(struct kunit *test)
{
	char path[] = "share\\folder\\file.txt";

	ksmbd_conv_path_to_unix(path);
	KUNIT_EXPECT_STREQ(test, path, "share/folder/file.txt");
}

/*
 * test_conv_path_to_windows - forward slashes become backslashes
 */
static void test_conv_path_to_windows(struct kunit *test)
{
	char path[] = "share/folder/file.txt";

	ksmbd_conv_path_to_windows(path);
	KUNIT_EXPECT_STREQ(test, path, "share\\folder\\file.txt");
}

/* --- ksmbd_strip_last_slash() tests --- */

/*
 * test_strip_last_slash - trailing slashes should be removed
 */
static void test_strip_last_slash(struct kunit *test)
{
	char path1[] = "/share/folder/";
	char path2[] = "/share/folder///";
	char path3[] = "/share/folder";
	char path4[] = "/";

	ksmbd_strip_last_slash(path1);
	KUNIT_EXPECT_STREQ(test, path1, "/share/folder");

	ksmbd_strip_last_slash(path2);
	KUNIT_EXPECT_STREQ(test, path2, "/share/folder");

	ksmbd_strip_last_slash(path3);
	KUNIT_EXPECT_STREQ(test, path3, "/share/folder");

	ksmbd_strip_last_slash(path4);
	KUNIT_EXPECT_STREQ(test, path4, "");
}

/* --- get_nlink() tests --- */

/*
 * test_get_nlink_file - regular files preserve nlink count
 */
static void test_get_nlink_file(struct kunit *test)
{
	struct kstat st = {};

	st.mode = S_IFREG | 0644;
	st.nlink = 3;

	KUNIT_EXPECT_EQ(test, get_nlink(&st), 3);
}

/*
 * test_get_nlink_directory - directories have nlink decremented by 1
 */
static void test_get_nlink_directory(struct kunit *test)
{
	struct kstat st = {};

	st.mode = S_IFDIR | 0755;
	st.nlink = 5;

	KUNIT_EXPECT_EQ(test, get_nlink(&st), 4);
}

/*
 * test_get_nlink_directory_one - directory with nlink=1 returns 0
 */
static void test_get_nlink_directory_one(struct kunit *test)
{
	struct kstat st = {};

	st.mode = S_IFDIR | 0755;
	st.nlink = 1;

	KUNIT_EXPECT_EQ(test, get_nlink(&st), 0);
}

/* --- ksmbd_NTtimeToUnix / ksmbd_UnixTimeToNT roundtrip tests --- */

/*
 * test_time_conversion_roundtrip - convert Unix to NT and back
 */
static void test_time_conversion_roundtrip(struct kunit *test)
{
	struct timespec64 ts_in = { .tv_sec = 1609459200, .tv_nsec = 0 };
	struct timespec64 ts_out;
	u64 nt_time;

	nt_time = ksmbd_UnixTimeToNT(ts_in);
	ts_out = ksmbd_NTtimeToUnix(cpu_to_le64(nt_time));

	KUNIT_EXPECT_EQ(test, ts_out.tv_sec, ts_in.tv_sec);
	KUNIT_EXPECT_EQ(test, ts_out.tv_nsec, ts_in.tv_nsec);
}

/*
 * test_time_conversion_epoch - Unix epoch should produce known NT time
 */
static void test_time_conversion_epoch(struct kunit *test)
{
	struct timespec64 epoch = { .tv_sec = 0, .tv_nsec = 0 };
	u64 nt_time;

	nt_time = ksmbd_UnixTimeToNT(epoch);
	/* Unix epoch = Jan 1 1970. NT epoch = Jan 1 1601.
	 * Difference = 369 years, with 89 leap days = NTFS_TIME_OFFSET
	 */
	KUNIT_EXPECT_EQ(test, nt_time, (u64)NTFS_TIME_OFFSET);
}

static struct kunit_case ksmbd_misc_test_cases[] = {
	KUNIT_CASE(test_match_pattern_exact),
	KUNIT_CASE(test_match_pattern_star),
	KUNIT_CASE(test_match_pattern_question),
	KUNIT_CASE(test_match_pattern_combined),
	KUNIT_CASE(test_match_pattern_empty),
	KUNIT_CASE(test_match_pattern_case_insensitive),
	KUNIT_CASE(test_validate_filename_valid),
	KUNIT_CASE(test_validate_filename_invalid_wildcards),
	KUNIT_CASE(test_validate_filename_invalid_special),
	KUNIT_CASE(test_validate_filename_control_char),
	KUNIT_CASE(test_validate_filename_empty),
	KUNIT_CASE(test_conv_path_to_unix),
	KUNIT_CASE(test_conv_path_to_windows),
	KUNIT_CASE(test_strip_last_slash),
	KUNIT_CASE(test_get_nlink_file),
	KUNIT_CASE(test_get_nlink_directory),
	KUNIT_CASE(test_get_nlink_directory_one),
	KUNIT_CASE(test_time_conversion_roundtrip),
	KUNIT_CASE(test_time_conversion_epoch),
	{}
};

static struct kunit_suite ksmbd_misc_test_suite = {
	.name = "ksmbd_misc",
	.test_cases = ksmbd_misc_test_cases,
};

kunit_test_suite(ksmbd_misc_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd miscellaneous helpers");
