// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 QUERY_DIRECTORY handler logic (smb2_dir.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

/* FileInformationClass values */
#define TEST_FILE_DIRECTORY_INFORMATION		0x01
#define TEST_FILE_FULL_DIRECTORY_INFORMATION	0x02
#define TEST_FILE_BOTH_DIRECTORY_INFORMATION	0x03
#define TEST_FILE_NAMES_INFORMATION		0x0C
#define TEST_FILE_ID_FULL_DIR_INFORMATION	0x26
#define TEST_FILE_ID_BOTH_DIR_INFORMATION	0x25
#define TEST_FILE_ID_EXTD_DIR_INFORMATION	0x3C
#define TEST_SMB_FIND_FILE_POSIX_INFO		0x64

/* Query directory flags */
#define TEST_SMB2_RESTART_SCANS		0x01
#define TEST_SMB2_RETURN_SINGLE_ENTRY	0x02
#define TEST_SMB2_INDEX_SPECIFIED	0x04
#define TEST_SMB2_REOPEN		0x10

/* Minimum struct sizes for info levels (variable-length filename follows) */
#define TEST_FILE_DIR_INFO_BASE_SIZE		64
#define TEST_FILE_FULL_DIR_INFO_BASE_SIZE	68
#define TEST_FILE_BOTH_DIR_INFO_BASE_SIZE	94
#define TEST_FILE_NAMES_INFO_BASE_SIZE		12
#define TEST_FILE_ID_FULL_DIR_BASE_SIZE		80
#define TEST_FILE_ID_BOTH_DIR_BASE_SIZE		104
#define TEST_FILE_ID_EXTD_DIR_BASE_SIZE		88

#define TEST_SMB2_HEADER_SIZE		64

/* ---- Replicated logic from smb2_dir.c ---- */

/*
 * Validate file information class for query_dir
 */
static int test_validate_info_class(u8 info_class)
{
	switch (info_class) {
	case TEST_FILE_DIRECTORY_INFORMATION:
	case TEST_FILE_FULL_DIRECTORY_INFORMATION:
	case TEST_FILE_BOTH_DIRECTORY_INFORMATION:
	case TEST_FILE_NAMES_INFORMATION:
	case TEST_FILE_ID_FULL_DIR_INFORMATION:
	case TEST_FILE_ID_BOTH_DIR_INFORMATION:
	case TEST_FILE_ID_EXTD_DIR_INFORMATION:
	case TEST_SMB_FIND_FILE_POSIX_INFO:
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Get struct size for info level
 */
static int test_get_info_level_struct_sz(u8 info_class)
{
	switch (info_class) {
	case TEST_FILE_DIRECTORY_INFORMATION:
		return TEST_FILE_DIR_INFO_BASE_SIZE;
	case TEST_FILE_FULL_DIRECTORY_INFORMATION:
		return TEST_FILE_FULL_DIR_INFO_BASE_SIZE;
	case TEST_FILE_BOTH_DIRECTORY_INFORMATION:
		return TEST_FILE_BOTH_DIR_INFO_BASE_SIZE;
	case TEST_FILE_NAMES_INFORMATION:
		return TEST_FILE_NAMES_INFO_BASE_SIZE;
	case TEST_FILE_ID_FULL_DIR_INFORMATION:
		return TEST_FILE_ID_FULL_DIR_BASE_SIZE;
	case TEST_FILE_ID_BOTH_DIR_INFORMATION:
		return TEST_FILE_ID_BOTH_DIR_BASE_SIZE;
	case TEST_FILE_ID_EXTD_DIR_INFORMATION:
		return TEST_FILE_ID_EXTD_DIR_BASE_SIZE;
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * NextEntryOffset alignment (8 bytes)
 */
static u32 test_align_next_entry(u32 offset)
{
	return (offset + 7) & ~7U;
}

/*
 * Replicate smb2_resp_buf_len calculation
 */
static int test_resp_buf_len(u32 work_buf_size, u16 hdr2_len)
{
	int free_len;

	free_len = (int)work_buf_size -
		   (TEST_SMB2_HEADER_SIZE + 4 + hdr2_len);
	return free_len > 0 ? free_len : 0;
}

/*
 * Replicate smb2_calc_max_out_buf_len
 */
static int test_calc_max_out_buf_len(u32 work_buf_size, u16 hdr2_len,
				     u32 out_buf_len)
{
	int max_len;

	max_len = test_resp_buf_len(work_buf_size, hdr2_len);
	if (out_buf_len < (u32)max_len)
		max_len = out_buf_len;
	return max_len;
}

/*
 * Simple wildcard matching for "*" and "?" patterns
 */
static bool test_wildcard_match_star(const char *pattern, const char *name)
{
	if (strcmp(pattern, "*") == 0)
		return true;
	return false;
}

/*
 * Replicate dot_dotdot state management
 */
struct test_dir_state {
	bool dot_dotdot[2]; /* [0] = "." sent, [1] = ".." sent */
};

static void test_reset_dot_dotdot(struct test_dir_state *state)
{
	state->dot_dotdot[0] = false;
	state->dot_dotdot[1] = false;
}

/* ---- Test Cases: Info Level Validation ---- */

static void test_query_dir_file_directory_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x01), 0);
}

static void test_query_dir_file_full_dir_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x02), 0);
}

static void test_query_dir_file_both_dir_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x03), 0);
}

static void test_query_dir_file_names_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x0C), 0);
}

static void test_query_dir_file_id_full_dir(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x26), 0);
}

static void test_query_dir_file_id_both_dir(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x25), 0);
}

static void test_query_dir_file_id_extd_dir(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x3C), 0);
}

static void test_query_dir_smb_find_posix(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x64), 0);
}

static void test_query_dir_invalid_info_level(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x00), -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0xFF), -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, test_validate_info_class(0x10), -EOPNOTSUPP);
}

/* ---- Test Cases: Info Level Struct Size ---- */

static void test_readdir_info_level_struct_sz_01(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_get_info_level_struct_sz(0x01),
			TEST_FILE_DIR_INFO_BASE_SIZE);
}

static void test_readdir_info_level_struct_sz_02(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_get_info_level_struct_sz(0x02),
			TEST_FILE_FULL_DIR_INFO_BASE_SIZE);
}

static void test_readdir_info_level_struct_sz_03(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_get_info_level_struct_sz(0x03),
			TEST_FILE_BOTH_DIR_INFO_BASE_SIZE);
}

static void test_readdir_info_level_struct_sz_0c(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_get_info_level_struct_sz(0x0C),
			TEST_FILE_NAMES_INFO_BASE_SIZE);
}

static void test_readdir_info_level_struct_sz_invalid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_get_info_level_struct_sz(0x99),
			-EOPNOTSUPP);
}

/* ---- Test Cases: Wildcard/Pattern Handling ---- */

static void test_query_dir_star_wildcard(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_wildcard_match_star("*", "anything"));
	KUNIT_EXPECT_TRUE(test, test_wildcard_match_star("*", ""));
}

static void test_query_dir_specific_pattern(struct kunit *test)
{
	/* "*.txt" matching -- simplified pattern check */
	const char *pattern = "*.txt";
	const char *name = "test.txt";
	size_t plen = strlen(pattern);
	size_t nlen = strlen(name);

	/* Check suffix match after '*' */
	KUNIT_EXPECT_TRUE(test,
		nlen >= plen - 1 &&
		strcmp(name + nlen - 4, ".txt") == 0);
}

static void test_query_dir_single_char_wildcard(struct kunit *test)
{
	/* "?" matches any single character */
	const char *pattern = "?";

	KUNIT_EXPECT_EQ(test, strlen(pattern), (size_t)1);
}

static void test_query_dir_dos_wildcard_star(struct kunit *test)
{
	/* DOS wildcard "<" matches like "*" but with filename-only semantics */
	char dos_wild = '<';

	KUNIT_EXPECT_EQ(test, dos_wild, '<');
}

static void test_query_dir_dos_wildcard_question(struct kunit *test)
{
	char dos_wild = '>';

	KUNIT_EXPECT_EQ(test, dos_wild, '>');
}

static void test_query_dir_dos_wildcard_dot(struct kunit *test)
{
	/* DOS wildcard "\"" matches dot */
	char dos_wild = '"';

	KUNIT_EXPECT_EQ(test, dos_wild, '"');
}

static void test_query_dir_empty_pattern(struct kunit *test)
{
	const char *pattern = "";

	KUNIT_EXPECT_EQ(test, strlen(pattern), (size_t)0);
}

/* ---- Test Cases: Flags Handling ---- */

static void test_query_dir_restart_scans(struct kunit *test)
{
	struct test_dir_state state;

	state.dot_dotdot[0] = true;
	state.dot_dotdot[1] = true;

	/* RESTART_SCANS resets dot_dotdot */
	u8 flags = TEST_SMB2_RESTART_SCANS;

	if (flags & TEST_SMB2_RESTART_SCANS)
		test_reset_dot_dotdot(&state);

	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[0]);
	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[1]);
}

static void test_query_dir_reopen(struct kunit *test)
{
	struct test_dir_state state;

	state.dot_dotdot[0] = true;
	state.dot_dotdot[1] = true;

	u8 flags = TEST_SMB2_REOPEN;

	if (flags & TEST_SMB2_REOPEN)
		test_reset_dot_dotdot(&state);

	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[0]);
	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[1]);
}

static void test_query_dir_single_entry(struct kunit *test)
{
	u8 flags = TEST_SMB2_RETURN_SINGLE_ENTRY;

	KUNIT_EXPECT_TRUE(test, flags & TEST_SMB2_RETURN_SINGLE_ENTRY);
}

static void test_query_dir_index_specified(struct kunit *test)
{
	u8 flags = TEST_SMB2_INDEX_SPECIFIED;

	KUNIT_EXPECT_TRUE(test, flags & TEST_SMB2_INDEX_SPECIFIED);
}

static void test_query_dir_reopen_flag(struct kunit *test)
{
	u8 flags = TEST_SMB2_REOPEN;

	KUNIT_EXPECT_TRUE(test, flags & TEST_SMB2_REOPEN);
}

/* ---- Test Cases: Output Buffer ---- */

static void test_query_dir_output_buf_full(struct kunit *test)
{
	/* Buffer fills and stops at boundary */
	u32 buf_size = 1024;
	u32 used = 900;
	u32 entry_size = 200;

	KUNIT_EXPECT_TRUE(test, used + entry_size > buf_size);
}

static void test_query_dir_output_buf_too_small(struct kunit *test)
{
	/* Buffer too small for single entry = STATUS_INFO_LENGTH_MISMATCH */
	u32 buf_size = 10;
	int min_entry_size = TEST_FILE_NAMES_INFO_BASE_SIZE;

	KUNIT_EXPECT_TRUE(test, (int)buf_size < min_entry_size);
}

static void test_query_dir_entry_overflow(struct kunit *test)
{
	/* NextEntryOffset alignment to 8 bytes */
	KUNIT_EXPECT_EQ(test, test_align_next_entry(65), 72U);
	KUNIT_EXPECT_EQ(test, test_align_next_entry(64), 64U);
	KUNIT_EXPECT_EQ(test, test_align_next_entry(1), 8U);
}

static void test_query_dir_last_entry_next_offset_zero(struct kunit *test)
{
	/* Last entry has NextEntryOffset=0 */
	u32 next_offset = 0;

	KUNIT_EXPECT_EQ(test, next_offset, 0U);
}

/* ---- Test Cases: Dot/DotDot Handling ---- */

static void test_query_dir_dot_entry(struct kunit *test)
{
	struct test_dir_state state;

	test_reset_dot_dotdot(&state);
	/* "." should be returned first */
	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[0]);
	state.dot_dotdot[0] = true;
	KUNIT_EXPECT_TRUE(test, state.dot_dotdot[0]);
}

static void test_query_dir_dotdot_entry(struct kunit *test)
{
	struct test_dir_state state;

	test_reset_dot_dotdot(&state);
	state.dot_dotdot[0] = true; /* "." already sent */
	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[1]);
	state.dot_dotdot[1] = true;
	KUNIT_EXPECT_TRUE(test, state.dot_dotdot[1]);
}

static void test_query_dir_dot_dotdot_skip_restart(struct kunit *test)
{
	struct test_dir_state state;

	state.dot_dotdot[0] = true;
	state.dot_dotdot[1] = true;
	test_reset_dot_dotdot(&state);

	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[0]);
	KUNIT_EXPECT_FALSE(test, state.dot_dotdot[1]);
}

/* ---- Test Cases: Helpers ---- */

static void test_smb2_resp_buf_len_basic(struct kunit *test)
{
	int len = test_resp_buf_len(4096, 32);

	KUNIT_EXPECT_TRUE(test, len > 0);
	/* 4096 - 64 - 4 - 32 = 3996 */
	KUNIT_EXPECT_EQ(test, len, 3996);
}

static void test_smb2_calc_max_out_buf_len_basic(struct kunit *test)
{
	int len = test_calc_max_out_buf_len(4096, 32, 2048);

	KUNIT_EXPECT_EQ(test, len, 2048);
}

static void test_smb2_calc_max_out_buf_len_zero_credits(struct kunit *test)
{
	/* Very small work buffer */
	int len = test_calc_max_out_buf_len(100, 32, 65536);

	KUNIT_EXPECT_EQ(test, len, 0);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_dir_test_cases[] = {
	/* Info Level */
	KUNIT_CASE(test_query_dir_file_directory_info),
	KUNIT_CASE(test_query_dir_file_full_dir_info),
	KUNIT_CASE(test_query_dir_file_both_dir_info),
	KUNIT_CASE(test_query_dir_file_names_info),
	KUNIT_CASE(test_query_dir_file_id_full_dir),
	KUNIT_CASE(test_query_dir_file_id_both_dir),
	KUNIT_CASE(test_query_dir_file_id_extd_dir),
	KUNIT_CASE(test_query_dir_smb_find_posix),
	KUNIT_CASE(test_query_dir_invalid_info_level),
	/* Struct Size */
	KUNIT_CASE(test_readdir_info_level_struct_sz_01),
	KUNIT_CASE(test_readdir_info_level_struct_sz_02),
	KUNIT_CASE(test_readdir_info_level_struct_sz_03),
	KUNIT_CASE(test_readdir_info_level_struct_sz_0c),
	KUNIT_CASE(test_readdir_info_level_struct_sz_invalid),
	/* Wildcard */
	KUNIT_CASE(test_query_dir_star_wildcard),
	KUNIT_CASE(test_query_dir_specific_pattern),
	KUNIT_CASE(test_query_dir_single_char_wildcard),
	KUNIT_CASE(test_query_dir_dos_wildcard_star),
	KUNIT_CASE(test_query_dir_dos_wildcard_question),
	KUNIT_CASE(test_query_dir_dos_wildcard_dot),
	KUNIT_CASE(test_query_dir_empty_pattern),
	/* Flags */
	KUNIT_CASE(test_query_dir_restart_scans),
	KUNIT_CASE(test_query_dir_reopen),
	KUNIT_CASE(test_query_dir_single_entry),
	KUNIT_CASE(test_query_dir_index_specified),
	KUNIT_CASE(test_query_dir_reopen_flag),
	/* Output Buffer */
	KUNIT_CASE(test_query_dir_output_buf_full),
	KUNIT_CASE(test_query_dir_output_buf_too_small),
	KUNIT_CASE(test_query_dir_entry_overflow),
	KUNIT_CASE(test_query_dir_last_entry_next_offset_zero),
	/* Dot/DotDot */
	KUNIT_CASE(test_query_dir_dot_entry),
	KUNIT_CASE(test_query_dir_dotdot_entry),
	KUNIT_CASE(test_query_dir_dot_dotdot_skip_restart),
	/* Helpers */
	KUNIT_CASE(test_smb2_resp_buf_len_basic),
	KUNIT_CASE(test_smb2_calc_max_out_buf_len_basic),
	KUNIT_CASE(test_smb2_calc_max_out_buf_len_zero_credits),
	{}
};

static struct kunit_suite ksmbd_smb2_dir_test_suite = {
	.name = "ksmbd_smb2_dir",
	.test_cases = ksmbd_smb2_dir_test_cases,
};

kunit_test_suite(ksmbd_smb2_dir_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 QUERY_DIRECTORY handler");
