// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB protocol common helpers (smb_common.c)
 *
 *   Tests call production functions directly via exported symbols.
 *   Covers: ksmbd_lookup_protocol_idx, ksmbd_min_protocol,
 *   ksmbd_max_protocol, is_asterisk, smb_map_generic_desired_access.
 */

#include <kunit/test.h>
#include <linux/types.h>

#include "smb_common.h"

/* -- ksmbd_lookup_protocol_idx tests -- */

static void test_lookup_smb2_02(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB2_02"), SMB2_PROT);
}

static void test_lookup_smb2_10(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB2_10"), SMB21_PROT);
}

static void test_lookup_smb3_00(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB3_00"), SMB30_PROT);
}

static void test_lookup_smb3_02(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB3_02"), SMB302_PROT);
}

static void test_lookup_smb3_11(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB3_11"), SMB311_PROT);
}

#ifdef CONFIG_SMB_INSECURE_SERVER
static void test_lookup_nt1(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("NT1"), SMB1_PROT);
}

static void test_lookup_smb1_alias(struct kunit *test)
{
	/* "SMB1" is an alias for "NT1" added in ksmbd_lookup_protocol_idx */
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB1"), SMB1_PROT);
}
#endif

static void test_lookup_invalid_string(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("INVALID"), -1);
}

static void test_lookup_empty_string(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx(""), -1);
}

static void test_lookup_smb4_nonexistent(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_lookup_protocol_idx("SMB4_00"), -1);
}

/* -- min/max protocol tests -- */

static void test_min_protocol(struct kunit *test)
{
	int min = ksmbd_min_protocol();

#ifdef CONFIG_SMB_INSECURE_SERVER
	KUNIT_EXPECT_EQ(test, min, SMB1_PROT);
#else
	KUNIT_EXPECT_EQ(test, min, SMB2_PROT);
#endif
}

static void test_max_protocol(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_max_protocol(), SMB311_PROT);
}

/* -- is_asterisk tests -- */

static void test_is_asterisk_true(struct kunit *test)
{
	char star[] = "*";

	KUNIT_EXPECT_TRUE(test, is_asterisk(star));
}

static void test_is_asterisk_false(struct kunit *test)
{
	char notstar[] = "hello";

	KUNIT_EXPECT_FALSE(test, is_asterisk(notstar));
}

static void test_is_asterisk_null(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, is_asterisk(NULL));
}

static void test_is_asterisk_empty(struct kunit *test)
{
	char empty[] = "";

	KUNIT_EXPECT_FALSE(test, is_asterisk(empty));
}

/* -- smb_map_generic_desired_access tests -- */

static void test_generic_read_mapping(struct kunit *test)
{
	__le32 result;

	result = smb_map_generic_desired_access(FILE_GENERIC_READ_LE);
	/* FILE_GENERIC_READ_LE should be cleared, GENERIC_READ_FLAGS set */
	KUNIT_EXPECT_FALSE(test, !!(result & FILE_GENERIC_READ_LE));
	KUNIT_EXPECT_TRUE(test, !!(result & cpu_to_le32(GENERIC_READ_FLAGS)));
}

static void test_generic_write_mapping(struct kunit *test)
{
	__le32 result;

	result = smb_map_generic_desired_access(FILE_GENERIC_WRITE_LE);
	KUNIT_EXPECT_FALSE(test, !!(result & FILE_GENERIC_WRITE_LE));
	KUNIT_EXPECT_TRUE(test, !!(result & cpu_to_le32(GENERIC_WRITE_FLAGS)));
}

static void test_generic_execute_mapping(struct kunit *test)
{
	__le32 result;

	result = smb_map_generic_desired_access(FILE_GENERIC_EXECUTE_LE);
	KUNIT_EXPECT_FALSE(test, !!(result & FILE_GENERIC_EXECUTE_LE));
	KUNIT_EXPECT_TRUE(test, !!(result & cpu_to_le32(GENERIC_EXECUTE_FLAGS)));
}

static void test_generic_all_mapping(struct kunit *test)
{
	__le32 result;

	result = smb_map_generic_desired_access(FILE_GENERIC_ALL_LE);
	KUNIT_EXPECT_FALSE(test, !!(result & FILE_GENERIC_ALL_LE));
	KUNIT_EXPECT_TRUE(test, !!(result & cpu_to_le32(GENERIC_ALL_FLAGS)));
}

static void test_no_generic_bits_unchanged(struct kunit *test)
{
	__le32 input = FILE_READ_DATA_LE;
	__le32 result;

	result = smb_map_generic_desired_access(input);
	KUNIT_EXPECT_EQ(test, result, input);
}

static void test_zero_access_unchanged(struct kunit *test)
{
	__le32 result;

	result = smb_map_generic_desired_access(0);
	KUNIT_EXPECT_EQ(test, result, (__le32)0);
}

static struct kunit_case ksmbd_protocol_common_cases[] = {
	KUNIT_CASE(test_lookup_smb2_02),
	KUNIT_CASE(test_lookup_smb2_10),
	KUNIT_CASE(test_lookup_smb3_00),
	KUNIT_CASE(test_lookup_smb3_02),
	KUNIT_CASE(test_lookup_smb3_11),
#ifdef CONFIG_SMB_INSECURE_SERVER
	KUNIT_CASE(test_lookup_nt1),
	KUNIT_CASE(test_lookup_smb1_alias),
#endif
	KUNIT_CASE(test_lookup_invalid_string),
	KUNIT_CASE(test_lookup_empty_string),
	KUNIT_CASE(test_lookup_smb4_nonexistent),
	KUNIT_CASE(test_min_protocol),
	KUNIT_CASE(test_max_protocol),
	KUNIT_CASE(test_is_asterisk_true),
	KUNIT_CASE(test_is_asterisk_false),
	KUNIT_CASE(test_is_asterisk_null),
	KUNIT_CASE(test_is_asterisk_empty),
	KUNIT_CASE(test_generic_read_mapping),
	KUNIT_CASE(test_generic_write_mapping),
	KUNIT_CASE(test_generic_execute_mapping),
	KUNIT_CASE(test_generic_all_mapping),
	KUNIT_CASE(test_no_generic_bits_unchanged),
	KUNIT_CASE(test_zero_access_unchanged),
	{}
};

static struct kunit_suite ksmbd_protocol_common_suite = {
	.name = "ksmbd_protocol_common",
	.test_cases = ksmbd_protocol_common_cases,
};

kunit_test_suite(ksmbd_protocol_common_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB protocol common helpers (calls production code)");
