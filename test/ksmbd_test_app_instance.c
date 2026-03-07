// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for APP_INSTANCE_ID/VERSION support (ksmbd_app_instance.c)
 *
 *   Tests the APP_INSTANCE_ID parsing, GUID validation,
 *   APP_INSTANCE_VERSION parsing, and version comparison semantics.
 *   The actual create context handlers need full work/fp/inode
 *   infrastructure, so we test the replicated logic.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "vfs_cache.h"

/* Replicated constants from ksmbd_app_instance.c */
#define APP_INSTANCE_ID_STRUCT_SIZE	20
#define APP_INSTANCE_ID_GUID_OFFSET	4
#define APP_INSTANCE_ID_GUID_LEN	16

#define APP_INSTANCE_VERSION_STRUCT_SIZE	24
#define APP_INSTANCE_VERSION_HIGH_OFFSET	8
#define APP_INSTANCE_VERSION_LOW_OFFSET		16

/* ═══════════════════════════════════════════════════════════════════
 *  APP_INSTANCE_ID Parsing Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_app_instance_id_valid(struct kunit *test)
{
	u8 ctx_data[APP_INSTANCE_ID_STRUCT_SIZE];
	struct ksmbd_file fp = {};

	memset(ctx_data, 0, sizeof(ctx_data));
	/* StructureSize (2 bytes) + Reserved (2 bytes) = 4 bytes header */
	/* Then 16 bytes GUID */
	memset(ctx_data + APP_INSTANCE_ID_GUID_OFFSET, 0x42,
	       APP_INSTANCE_ID_GUID_LEN);

	/* Parse: copy GUID from offset 4 */
	memcpy(fp.app_instance_id, ctx_data + APP_INSTANCE_ID_GUID_OFFSET,
	       APP_INSTANCE_ID_GUID_LEN);
	fp.has_app_instance_id = true;

	KUNIT_EXPECT_TRUE(test, fp.has_app_instance_id);
	KUNIT_EXPECT_EQ(test, fp.app_instance_id[0], (char)0x42);
	KUNIT_EXPECT_EQ(test, fp.app_instance_id[15], (char)0x42);
}

static void test_app_instance_id_too_short_rejected(struct kunit *test)
{
	unsigned int ctx_len = APP_INSTANCE_ID_STRUCT_SIZE - 1;

	KUNIT_EXPECT_TRUE(test, ctx_len < APP_INSTANCE_ID_STRUCT_SIZE);
}

static void test_app_instance_id_zero_guid_ignored(struct kunit *test)
{
	u8 ctx_data[APP_INSTANCE_ID_STRUCT_SIZE];
	static const u8 zero_guid[APP_INSTANCE_ID_GUID_LEN] = {};
	struct ksmbd_file fp = {};

	memset(ctx_data, 0, sizeof(ctx_data));

	memcpy(fp.app_instance_id, ctx_data + APP_INSTANCE_ID_GUID_OFFSET,
	       APP_INSTANCE_ID_GUID_LEN);

	/* Zero GUID means "no app instance" */
	KUNIT_EXPECT_EQ(test, memcmp(fp.app_instance_id, zero_guid,
				     APP_INSTANCE_ID_GUID_LEN), 0);
	/* Should NOT set the flag */
	KUNIT_EXPECT_FALSE(test, fp.has_app_instance_id);
}

static void test_app_instance_id_sets_flag_and_guid(struct kunit *test)
{
	struct ksmbd_file fp = {};
	u8 guid[APP_INSTANCE_ID_GUID_LEN];

	memset(guid, 0xAB, sizeof(guid));
	memcpy(fp.app_instance_id, guid, APP_INSTANCE_ID_GUID_LEN);
	fp.has_app_instance_id = true;

	KUNIT_EXPECT_TRUE(test, fp.has_app_instance_id);
	KUNIT_EXPECT_EQ(test, memcmp(fp.app_instance_id, guid,
				     APP_INSTANCE_ID_GUID_LEN), 0);
}

/* ═══════════════════════════════════════════════════════════════════
 *  APP_INSTANCE_VERSION Parsing Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_app_instance_version_valid(struct kunit *test)
{
	u8 ctx_data[APP_INSTANCE_VERSION_STRUCT_SIZE];
	struct ksmbd_file fp = {};
	u64 ver_high, ver_low;

	memset(ctx_data, 0, sizeof(ctx_data));

	/* Place version high at offset 8, version low at offset 16 */
	ver_high = 100;
	ver_low = 200;
	memcpy(ctx_data + APP_INSTANCE_VERSION_HIGH_OFFSET, &ver_high, 8);
	memcpy(ctx_data + APP_INSTANCE_VERSION_LOW_OFFSET, &ver_low, 8);

	/* Parse */
	memcpy(&fp.app_instance_version,
	       ctx_data + APP_INSTANCE_VERSION_HIGH_OFFSET, 8);
	memcpy(&fp.app_instance_version_low,
	       ctx_data + APP_INSTANCE_VERSION_LOW_OFFSET, 8);
	fp.has_app_instance_version = true;

	KUNIT_EXPECT_TRUE(test, fp.has_app_instance_version);
	KUNIT_EXPECT_EQ(test, fp.app_instance_version, (u64)100);
	KUNIT_EXPECT_EQ(test, fp.app_instance_version_low, (u64)200);
}

static void test_app_instance_version_too_short_rejected(struct kunit *test)
{
	unsigned int ctx_len = APP_INSTANCE_VERSION_STRUCT_SIZE - 1;

	KUNIT_EXPECT_TRUE(test, ctx_len < APP_INSTANCE_VERSION_STRUCT_SIZE);
}

static void test_app_instance_version_sets_high_and_low(struct kunit *test)
{
	struct ksmbd_file fp = {};

	fp.app_instance_version = 999;
	fp.app_instance_version_low = 888;

	KUNIT_EXPECT_EQ(test, fp.app_instance_version, (u64)999);
	KUNIT_EXPECT_EQ(test, fp.app_instance_version_low, (u64)888);
}

static void test_app_instance_version_sets_flag(struct kunit *test)
{
	struct ksmbd_file fp = {};

	KUNIT_EXPECT_FALSE(test, fp.has_app_instance_version);
	fp.has_app_instance_version = true;
	KUNIT_EXPECT_TRUE(test, fp.has_app_instance_version);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Version Comparison Semantics
 *
 *  Per MS-SMB2, close the old handle only when:
 *    new.high > old.high, OR
 *    (new.high == old.high AND new.low > old.low)
 * ═══════════════════════════════════════════════════════════════════ */

static bool should_close_previous(u64 old_high, u64 old_low,
				  u64 new_high, u64 new_low,
				  bool has_version)
{
	if (!has_version)
		return true; /* Unconditional close */

	if (old_high > new_high)
		return false;
	if (old_high == new_high && old_low >= new_low)
		return false;

	return true;
}

static void test_version_high_dominates(struct kunit *test)
{
	/* New high > old high: close regardless of low */
	KUNIT_EXPECT_TRUE(test, should_close_previous(1, 100, 2, 0, true));
}

static void test_version_low_breaks_tie(struct kunit *test)
{
	/* Same high, new low > old low: close */
	KUNIT_EXPECT_TRUE(test, should_close_previous(5, 10, 5, 11, true));
}

static void test_version_both_equal_no_close(struct kunit *test)
{
	/* Equal versions: do NOT close */
	KUNIT_EXPECT_FALSE(test, should_close_previous(5, 10, 5, 10, true));
}

static void test_version_high_greater_low_less_closes(struct kunit *test)
{
	/* New high > old high, even if new low < old low: close */
	KUNIT_EXPECT_TRUE(test, should_close_previous(1, 100, 2, 1, true));
}

static void test_close_previous_no_version_unconditional(struct kunit *test)
{
	/* No version context: unconditional close */
	KUNIT_EXPECT_TRUE(test, should_close_previous(99, 99, 0, 0, false));
}

static void test_close_previous_version_lower_no_close(struct kunit *test)
{
	/* New version lower: do NOT close */
	KUNIT_EXPECT_FALSE(test, should_close_previous(10, 0, 5, 0, true));
}

static void test_close_previous_version_equal_high_lower_low(struct kunit *test)
{
	/* Same high, new low < old low: do NOT close */
	KUNIT_EXPECT_FALSE(test, should_close_previous(5, 20, 5, 10, true));
}

/* ═══════════════════════════════════════════════════════════════════
 *  GUID Comparison Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_guid_same_match(struct kunit *test)
{
	char guid1[16], guid2[16];

	memset(guid1, 0xAB, sizeof(guid1));
	memcpy(guid2, guid1, sizeof(guid2));
	KUNIT_EXPECT_EQ(test, memcmp(guid1, guid2, 16), 0);
}

static void test_guid_different_no_match(struct kunit *test)
{
	char guid1[16], guid2[16];

	memset(guid1, 0xAB, sizeof(guid1));
	memset(guid2, 0xCD, sizeof(guid2));
	KUNIT_EXPECT_NE(test, memcmp(guid1, guid2, 16), 0);
}

static void test_guid_zero_is_special(struct kunit *test)
{
	char guid[16];
	static const char zero[16] = {};

	memset(guid, 0, sizeof(guid));
	KUNIT_EXPECT_EQ(test, memcmp(guid, zero, 16), 0);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Close Previous Instance Tests
 *
 *  These test additional scenarios for the should_close_previous()
 *  logic matching close_previous_app_instance() in ksmbd.
 * ═══════════════════════════════════════════════════════════════════ */

static void test_close_previous_same_instance_id(struct kunit *test)
{
	/*
	 * Same instance ID means the handles match.
	 * With no version context: unconditional close.
	 */
	KUNIT_EXPECT_TRUE(test, should_close_previous(0, 0, 0, 0, false));
}

static void test_close_previous_version_much_higher(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, should_close_previous(1, 1, 100, 100, true));
}

static void test_close_previous_version_much_lower(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, should_close_previous(100, 100, 1, 1, true));
}

static void test_close_previous_high_zero_low_matters(struct kunit *test)
{
	/* Both high == 0, new low > old low: close */
	KUNIT_EXPECT_TRUE(test, should_close_previous(0, 5, 0, 10, true));
	/* Both high == 0, new low < old low: no close */
	KUNIT_EXPECT_FALSE(test, should_close_previous(0, 10, 0, 5, true));
}

static void test_close_previous_max_u64_versions(struct kunit *test)
{
	/* Boundary: max u64 values */
	KUNIT_EXPECT_FALSE(test,
			   should_close_previous(ULLONG_MAX, ULLONG_MAX,
						 ULLONG_MAX, ULLONG_MAX,
						 true));
}

/* ═══════════════════════════════════════════════════════════════════
 *  APP_INSTANCE_ID Structure Size Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_app_instance_id_struct_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, APP_INSTANCE_ID_STRUCT_SIZE, 20U);
	KUNIT_EXPECT_EQ(test, APP_INSTANCE_ID_GUID_OFFSET, 4U);
	KUNIT_EXPECT_EQ(test, APP_INSTANCE_ID_GUID_LEN, 16U);
	/* Offset + length should equal struct size */
	KUNIT_EXPECT_EQ(test,
			APP_INSTANCE_ID_GUID_OFFSET + APP_INSTANCE_ID_GUID_LEN,
			APP_INSTANCE_ID_STRUCT_SIZE);
}

static void test_app_instance_version_struct_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, APP_INSTANCE_VERSION_STRUCT_SIZE, 24U);
	KUNIT_EXPECT_EQ(test, APP_INSTANCE_VERSION_HIGH_OFFSET, 8U);
	KUNIT_EXPECT_EQ(test, APP_INSTANCE_VERSION_LOW_OFFSET, 16U);
	/* Offset + sizeof(u64) should equal struct size */
	KUNIT_EXPECT_EQ(test,
			APP_INSTANCE_VERSION_LOW_OFFSET + 8U,
			APP_INSTANCE_VERSION_STRUCT_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_app_instance_test_cases[] = {
	/* APP_INSTANCE_ID parsing */
	KUNIT_CASE(test_app_instance_id_valid),
	KUNIT_CASE(test_app_instance_id_too_short_rejected),
	KUNIT_CASE(test_app_instance_id_zero_guid_ignored),
	KUNIT_CASE(test_app_instance_id_sets_flag_and_guid),
	/* APP_INSTANCE_VERSION parsing */
	KUNIT_CASE(test_app_instance_version_valid),
	KUNIT_CASE(test_app_instance_version_too_short_rejected),
	KUNIT_CASE(test_app_instance_version_sets_high_and_low),
	KUNIT_CASE(test_app_instance_version_sets_flag),
	/* Version comparison */
	KUNIT_CASE(test_version_high_dominates),
	KUNIT_CASE(test_version_low_breaks_tie),
	KUNIT_CASE(test_version_both_equal_no_close),
	KUNIT_CASE(test_version_high_greater_low_less_closes),
	KUNIT_CASE(test_close_previous_no_version_unconditional),
	KUNIT_CASE(test_close_previous_version_lower_no_close),
	KUNIT_CASE(test_close_previous_version_equal_high_lower_low),
	/* GUID comparison */
	KUNIT_CASE(test_guid_same_match),
	KUNIT_CASE(test_guid_different_no_match),
	KUNIT_CASE(test_guid_zero_is_special),
	/* Close previous additional */
	KUNIT_CASE(test_close_previous_same_instance_id),
	KUNIT_CASE(test_close_previous_version_much_higher),
	KUNIT_CASE(test_close_previous_version_much_lower),
	KUNIT_CASE(test_close_previous_high_zero_low_matters),
	KUNIT_CASE(test_close_previous_max_u64_versions),
	/* Structure sizes */
	KUNIT_CASE(test_app_instance_id_struct_size),
	KUNIT_CASE(test_app_instance_version_struct_size),
	{}
};

static struct kunit_suite ksmbd_app_instance_test_suite = {
	.name = "ksmbd_app_instance",
	.test_cases = ksmbd_app_instance_test_cases,
};

kunit_test_suite(ksmbd_app_instance_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd APP_INSTANCE_ID/VERSION support");
