// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd VSS/snapshot helper functions (ksmbd_vss.c)
 *
 *   Since KUnit tests cannot link against the ksmbd module directly,
 *   we replicate the pure-logic portions (GMT token validation, timestamp
 *   parsing, directory name to GMT conversion) inline.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/time64.h>

/* ── Replicated constants and logic from ksmbd_vss.h / ksmbd_vss.c ─── */

/* @GMT-YYYY.MM.DD-HH.MM.SS format: 24 chars + NUL */
#define TEST_GMT_TOKEN_LEN	25

struct test_snapshot_entry {
	char gmt_token[TEST_GMT_TOKEN_LEN];
	u64 timestamp;
};

/**
 * test_is_gmt_token() - Replicate ksmbd_vss_is_gmt_token()
 *
 * Checks the format @GMT-YYYY.MM.DD-HH.MM.SS (exactly 24 chars).
 */
static bool test_is_gmt_token(const char *name, int namlen)
{
	if (namlen != TEST_GMT_TOKEN_LEN - 1)
		return false;

	return name[0] == '@' &&
	       name[1] == 'G' &&
	       name[2] == 'M' &&
	       name[3] == 'T' &&
	       name[4] == '-' &&
	       name[9] == '.' &&
	       name[12] == '.' &&
	       name[15] == '-' &&
	       name[18] == '.' &&
	       name[21] == '.';
}

/**
 * test_parse_gmt_timestamp() - Replicate ksmbd_vss_parse_gmt_timestamp()
 */
static u64 test_parse_gmt_timestamp(const char *gmt_token)
{
	unsigned int year, month, day, hour, min, sec;
	int ret;

	ret = sscanf(gmt_token, "@GMT-%4u.%2u.%2u-%2u.%2u.%2u",
		     &year, &month, &day, &hour, &min, &sec);
	if (ret != 6)
		return 0;

	return (u64)mktime64(year, month, day, hour, min, sec);
}

/**
 * test_dirname_to_gmt() - Replicate ksmbd_vss_dirname_to_gmt()
 *
 * Supports:
 *   - @GMT-YYYY.MM.DD-HH.MM.SS (pass-through)
 *   - YYYY-MM-DD_HH:MM:SS (snapper format)
 *   - YYYY-MM-DD-HHMMSS (simple)
 *   - YYYY-MM-DD (date only, time defaults to 00:00:00)
 */
static int test_dirname_to_gmt(const char *dirname, int namlen,
			       struct test_snapshot_entry *entry)
{
	unsigned int year, month, day, hour = 0, min = 0, sec = 0;
	int ret;

	if (test_is_gmt_token(dirname, namlen)) {
		memcpy(entry->gmt_token, dirname,
		       TEST_GMT_TOKEN_LEN - 1);
		entry->gmt_token[TEST_GMT_TOKEN_LEN - 1] = '\0';
		entry->timestamp = test_parse_gmt_timestamp(dirname);
		return 0;
	}

	/* Try YYYY-MM-DD_HH:MM:SS (snapper format) */
	ret = sscanf(dirname, "%4u-%2u-%2u_%2u:%2u:%2u",
		     &year, &month, &day, &hour, &min, &sec);
	if (ret == 6)
		goto format;

	/* Try YYYY-MM-DD-HHMMSS */
	ret = sscanf(dirname, "%4u-%2u-%2u-%2u%2u%2u",
		     &year, &month, &day, &hour, &min, &sec);
	if (ret == 6)
		goto format;

	/* Try YYYY-MM-DD (date only) */
	hour = 0;
	min = 0;
	sec = 0;
	ret = sscanf(dirname, "%4u-%2u-%2u",
		     &year, &month, &day);
	if (ret == 3)
		goto format;

	return -EINVAL;

format:
	if (year < 1970 || month < 1 || month > 12 ||
	    day < 1 || day > 31 || hour > 23 ||
	    min > 59 || sec > 59)
		return -EINVAL;

	snprintf(entry->gmt_token, TEST_GMT_TOKEN_LEN,
		 "@GMT-%04u.%02u.%02u-%02u.%02u.%02u",
		 year, month, day, hour, min, sec);
	entry->timestamp =
		(u64)mktime64(year, month, day, hour, min, sec);
	return 0;
}

/* ── GMT token validation tests ─── */

static void test_gmt_token_valid(struct kunit *test)
{
	const char *token = "@GMT-2024.01.15-10.30.00";

	KUNIT_EXPECT_TRUE(test, test_is_gmt_token(token, 24));
}

static void test_gmt_token_wrong_prefix(struct kunit *test)
{
	const char *token = "@XMT-2024.01.15-10.30.00";

	KUNIT_EXPECT_FALSE(test, test_is_gmt_token(token, 24));
}

static void test_gmt_token_wrong_length_short(struct kunit *test)
{
	const char *token = "@GMT-2024.01.15";

	KUNIT_EXPECT_FALSE(test, test_is_gmt_token(token, 15));
}

static void test_gmt_token_wrong_length_long(struct kunit *test)
{
	const char *token = "@GMT-2024.01.15-10.30.00X";

	KUNIT_EXPECT_FALSE(test, test_is_gmt_token(token, 25));
}

static void test_gmt_token_missing_separator(struct kunit *test)
{
	/* Missing dot between MM and DD */
	const char *token = "@GMT-2024.0115--10.30.00";

	KUNIT_EXPECT_FALSE(test, test_is_gmt_token(token, 24));
}

static void test_gmt_token_empty(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_is_gmt_token("", 0));
}

/* ── Timestamp parsing tests ─── */

static void test_parse_timestamp_known_date(struct kunit *test)
{
	/*
	 * @GMT-2024.01.15-10.30.00
	 * Expected: mktime64(2024, 1, 15, 10, 30, 0)
	 */
	const char *token = "@GMT-2024.01.15-10.30.00";
	u64 ts;
	u64 expected;

	ts = test_parse_gmt_timestamp(token);
	expected = (u64)mktime64(2024, 1, 15, 10, 30, 0);
	KUNIT_EXPECT_EQ(test, ts, expected);
}

static void test_parse_timestamp_epoch(struct kunit *test)
{
	/* Unix epoch: 1970-01-01 00:00:00 */
	const char *token = "@GMT-1970.01.01-00.00.00";
	u64 ts;

	ts = test_parse_gmt_timestamp(token);
	KUNIT_EXPECT_EQ(test, ts, (u64)0);
}

static void test_parse_timestamp_invalid_format(struct kunit *test)
{
	const char *token = "@GMT-invalid-date-here!";
	u64 ts;

	ts = test_parse_gmt_timestamp(token);
	KUNIT_EXPECT_EQ(test, ts, (u64)0);
}

/* ── dirname_to_gmt conversion tests ─── */

static void test_dirname_gmt_passthrough(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "@GMT-2024.01.15-10.30.00";
	int ret;

	ret = test_dirname_to_gmt(dirname, 24, &entry);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, entry.gmt_token,
			    "@GMT-2024.01.15-10.30.00");
}

static void test_dirname_snapper_format(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "2024-01-15_10:30:00";
	int ret;

	ret = test_dirname_to_gmt(dirname, strlen(dirname), &entry);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, entry.gmt_token,
			    "@GMT-2024.01.15-10.30.00");
}

static void test_dirname_simple_format(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "2024-01-15-103000";
	int ret;

	ret = test_dirname_to_gmt(dirname, strlen(dirname), &entry);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, entry.gmt_token,
			    "@GMT-2024.01.15-10.30.00");
}

static void test_dirname_date_only(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "2024-01-15";
	int ret;

	ret = test_dirname_to_gmt(dirname, strlen(dirname), &entry);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, entry.gmt_token,
			    "@GMT-2024.01.15-00.00.00");
}

static void test_dirname_leap_year(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "2024-02-29";
	int ret;

	ret = test_dirname_to_gmt(dirname, strlen(dirname), &entry);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, entry.gmt_token,
			    "@GMT-2024.02.29-00.00.00");
}

static void test_dirname_invalid_garbage(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	int ret;

	ret = test_dirname_to_gmt("random_garbage", 14, &entry);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_dirname_year_before_epoch(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "1969-12-31";
	int ret;

	/* Year < 1970 should be rejected by sanity check */
	ret = test_dirname_to_gmt(dirname, strlen(dirname), &entry);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_dirname_invalid_month(struct kunit *test)
{
	struct test_snapshot_entry entry = {};
	const char *dirname = "2024-13-01";
	int ret;

	ret = test_dirname_to_gmt(dirname, strlen(dirname), &entry);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static struct kunit_case ksmbd_vss_test_cases[] = {
	KUNIT_CASE(test_gmt_token_valid),
	KUNIT_CASE(test_gmt_token_wrong_prefix),
	KUNIT_CASE(test_gmt_token_wrong_length_short),
	KUNIT_CASE(test_gmt_token_wrong_length_long),
	KUNIT_CASE(test_gmt_token_missing_separator),
	KUNIT_CASE(test_gmt_token_empty),
	KUNIT_CASE(test_parse_timestamp_known_date),
	KUNIT_CASE(test_parse_timestamp_epoch),
	KUNIT_CASE(test_parse_timestamp_invalid_format),
	KUNIT_CASE(test_dirname_gmt_passthrough),
	KUNIT_CASE(test_dirname_snapper_format),
	KUNIT_CASE(test_dirname_simple_format),
	KUNIT_CASE(test_dirname_date_only),
	KUNIT_CASE(test_dirname_leap_year),
	KUNIT_CASE(test_dirname_invalid_garbage),
	KUNIT_CASE(test_dirname_year_before_epoch),
	KUNIT_CASE(test_dirname_invalid_month),
	{}
};

static struct kunit_suite ksmbd_vss_test_suite = {
	.name = "ksmbd_vss",
	.test_cases = ksmbd_vss_test_cases,
};

kunit_test_suite(ksmbd_vss_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd VSS/snapshot helper functions");
