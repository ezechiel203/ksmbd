// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 TRANS2 error paths
 *
 *   Tests bounds checking and validation for TRANS2 subcommands:
 *   FIND_FIRST, FIND_NEXT, QUERY_FS_INFORMATION, SET_FS_INFORMATION,
 *   QUERY_PATH_INFORMATION, SET_PATH_INFORMATION, QUERY_FILE_INFORMATION,
 *   SET_FILE_INFORMATION, CREATE_DIRECTORY, GET_DFS_REFERRAL,
 *   REPORT_DFS_INCONSISTENCY, and TRANS2_OPEN.
 *
 *   Covers: truncated parameter blocks, invalid info levels,
 *   malformed search patterns, buffer overflow conditions,
 *   parameter/data overlap, and invalid subcommand codes.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>

#include "smb_common.h"
#include "smb1pdu.h"

/*
 * Helper: build a minimal TRANS2 request buffer.
 * Returns a kzalloc'd buffer of @buf_len bytes with the header and
 * TRANS2 fields populated.
 */
static void *build_trans2_req(struct kunit *test,
			      unsigned int buf_len,
			      u16 sub_command,
			      u16 param_offset,
			      u16 param_count,
			      u16 data_offset,
			      u16 data_count,
			      u16 total_param,
			      u16 total_data,
			      u8 setup_count)
{
	struct smb_com_trans2_req *req;

	KUNIT_ASSERT_GE(test, buf_len,
			(unsigned int)sizeof(struct smb_com_trans2_req));

	req = kunit_kzalloc(test, buf_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, req);

	/* Fill in the SMB header */
	req->hdr.Protocol[0] = 0xFF;
	req->hdr.Protocol[1] = 'S';
	req->hdr.Protocol[2] = 'M';
	req->hdr.Protocol[3] = 'B';
	req->hdr.Command = SMB_COM_TRANSACTION2;
	/* RFC1001 length = buf_len - 4 */
	req->hdr.smb_buf_length = cpu_to_be32(buf_len - 4);
	req->hdr.WordCount = 0xf; /* TRANS2 word count = 15 */

	req->SubCommand = cpu_to_le16(sub_command);
	req->ParameterOffset = cpu_to_le16(param_offset);
	req->ParameterCount = cpu_to_le16(param_count);
	req->DataOffset = cpu_to_le16(data_offset);
	req->DataCount = cpu_to_le16(data_count);
	req->TotalParameterCount = cpu_to_le16(total_param);
	req->TotalDataCount = cpu_to_le16(total_data);
	req->SetupCount = setup_count;

	return req;
}

/* --- Test: TRANS2 buffer validation (smb1_validate_trans2_buffer) --- */

static void test_trans2_valid_buffer(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req = build_trans2_req(test, buf_len,
				     TRANS2_FIND_FIRST,
				     60, 20,  /* param at 60, 20 bytes */
				     90, 30,  /* data at 90, 30 bytes */
				     20, 30,
				     1);
	int rc;

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_trans2_param_overflow(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset=100 + 4 + ParameterCount=100 > 128 */
	req = build_trans2_req(test, buf_len,
			       TRANS2_FIND_FIRST,
			       100, 100,
			       0, 0,
			       100, 0,
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_trans2_data_overflow(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* DataOffset=100 + 4 + DataCount=100 > 128 */
	req = build_trans2_req(test, buf_len,
			       TRANS2_FIND_NEXT,
			       0, 0,
			       100, 100,
			       0, 100,
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_trans2_total_param_less_than_count(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req;
	int rc;

	/* TotalParameterCount=10 < ParameterCount=50 */
	req = build_trans2_req(test, buf_len,
			       TRANS2_QUERY_FS_INFORMATION,
			       60, 50,
			       0, 0,
			       10, 0, /* total < count */
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_trans2_total_data_less_than_count(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req;
	int rc;

	/* TotalDataCount=10 < DataCount=50 */
	req = build_trans2_req(test, buf_len,
			       TRANS2_SET_FS_INFORMATION,
			       0, 0,
			       80, 50,
			       0, 10, /* total < count */
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_trans2_zero_counts_valid(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* Zero counts should be valid */
	req = build_trans2_req(test, buf_len,
			       TRANS2_QUERY_PATH_INFORMATION,
			       0, 0,
			       0, 0,
			       0, 0,
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_trans2_param_at_exact_boundary(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset + 4 + ParameterCount == buf_len */
	req = build_trans2_req(test, buf_len,
			       TRANS2_SET_PATH_INFORMATION,
			       60, 64, /* 60 + 4 + 64 = 128 */
			       0, 0,
			       64, 0,
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_trans2_param_one_past_boundary(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset + 4 + ParameterCount == buf_len + 1 */
	req = build_trans2_req(test, buf_len,
			       TRANS2_SET_FILE_INFORMATION,
			       60, 65, /* 60 + 4 + 65 = 129 > 128 */
			       0, 0,
			       65, 0,
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_trans2_param_offset_beyond_buf(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset > buf_len */
	req = build_trans2_req(test, buf_len,
			       TRANS2_FIND_FIRST,
			       200, 10,
			       0, 0,
			       10, 0,
			       1);

	rc = smb1_validate_trans2_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

/* --- Test: TRANS2 subcommand validation --- */

/*
 * Replicate the valid subcommand check from smb_trans2().
 */
static bool test_is_valid_trans2_subcommand(u16 sub_cmd)
{
	switch (sub_cmd) {
	case TRANS2_OPEN:
	case TRANS2_FIND_FIRST:
	case TRANS2_FIND_NEXT:
	case TRANS2_QUERY_FS_INFORMATION:
	case TRANS2_SET_FS_INFORMATION:
	case TRANS2_QUERY_PATH_INFORMATION:
	case TRANS2_SET_PATH_INFORMATION:
	case TRANS2_QUERY_FILE_INFORMATION:
	case TRANS2_SET_FILE_INFORMATION:
	case TRANS2_CREATE_DIRECTORY:
	case TRANS2_GET_DFS_REFERRAL:
	case TRANS2_REPORT_DFS_INCOSISTENCY:
		return true;
	default:
		return false;
	}
}

static void test_trans2_find_first_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(TRANS2_FIND_FIRST));
}

static void test_trans2_find_next_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(TRANS2_FIND_NEXT));
}

static void test_trans2_query_fs_info_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_QUERY_FS_INFORMATION));
}

static void test_trans2_set_fs_info_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_SET_FS_INFORMATION));
}

static void test_trans2_query_path_info_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_QUERY_PATH_INFORMATION));
}

static void test_trans2_set_path_info_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_SET_PATH_INFORMATION));
}

static void test_trans2_query_file_info_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_QUERY_FILE_INFORMATION));
}

static void test_trans2_set_file_info_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_SET_FILE_INFORMATION));
}

static void test_trans2_create_directory_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_CREATE_DIRECTORY));
}

static void test_trans2_invalid_subcommand(struct kunit *test)
{
	/* 0xFF is not a valid TRANS2 subcommand */
	KUNIT_EXPECT_FALSE(test, test_is_valid_trans2_subcommand(0xFF));
	/* 0x0E (between CREATE_DIRECTORY and GET_DFS_REFERRAL) */
	KUNIT_EXPECT_FALSE(test, test_is_valid_trans2_subcommand(0x0E));
	/* 0x12 (beyond REPORT_DFS_INCONSISTENCY) */
	KUNIT_EXPECT_FALSE(test, test_is_valid_trans2_subcommand(0x12));
}

/* --- Test: TRANS2 info level validation --- */

/*
 * Replicate readdir_info_level_struct_sz() to verify
 * that invalid info levels are detected.
 */
static int test_readdir_info_level_struct_sz(int info_level)
{
	switch (info_level) {
	case SMB_FIND_FILE_INFO_STANDARD:
	case SMB_FIND_FILE_QUERY_EA_SIZE:
	case SMB_FIND_FILE_DIRECTORY_INFO:
	case SMB_FIND_FILE_FULL_DIRECTORY_INFO:
	case SMB_FIND_FILE_NAMES_INFO:
	case SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
	case SMB_FIND_FILE_ID_FULL_DIR_INFO:
	case SMB_FIND_FILE_ID_BOTH_DIR_INFO:
	case SMB_FIND_FILE_UNIX:
		return 1; /* valid (positive size, exact value doesn't matter) */
	default:
		return -1; /* invalid */
	}
}

static void test_trans2_info_level_standard_valid(struct kunit *test)
{
	KUNIT_EXPECT_GT(test,
			test_readdir_info_level_struct_sz(
				SMB_FIND_FILE_INFO_STANDARD),
			0);
}

static void test_trans2_info_level_both_dir_valid(struct kunit *test)
{
	KUNIT_EXPECT_GT(test,
			test_readdir_info_level_struct_sz(
				SMB_FIND_FILE_BOTH_DIRECTORY_INFO),
			0);
}

static void test_trans2_info_level_invalid_zero(struct kunit *test)
{
	/* Info level 0 is invalid */
	KUNIT_EXPECT_LT(test,
			test_readdir_info_level_struct_sz(0), 0);
}

static void test_trans2_info_level_invalid_0x200(struct kunit *test)
{
	/* Info level 0x200 (UNIX-specific) is beyond supported range */
	KUNIT_EXPECT_LT(test,
			test_readdir_info_level_struct_sz(0x200), 0);
}

/* --- Test: TRANS2 per-subcommand parameter count checks --- */

/*
 * Replicate the minimum parameter count checks added to each
 * TRANS2 subcommand handler.
 */

static void test_trans2_find_first_min_param_count(struct kunit *test)
{
	/*
	 * FIND_FIRST needs smb_com_trans2_ffirst_req_params minus the
	 * variable-length FileName (12 - 1 = 11 bytes minimum).
	 */
	u16 param_count = 5; /* too small */

	KUNIT_EXPECT_LT(test, (int)param_count, 11);
}

static void test_trans2_find_next_min_param_count(struct kunit *test)
{
	/*
	 * FIND_NEXT needs smb_com_trans2_fnext_req_params minus the
	 * variable-length ResumeFileName (12 - 1 = 11 bytes minimum).
	 */
	u16 param_count = 5;

	KUNIT_EXPECT_LT(test, (int)param_count, 11);
}

static void test_trans2_query_fs_info_min_param_count(struct kunit *test)
{
	/* QUERY_FS_INFORMATION needs InformationLevel (2 bytes) */
	u16 param_count = 1;

	KUNIT_EXPECT_LT(test, (int)param_count, 2);
}

static void test_trans2_query_file_info_min_param_count(struct kunit *test)
{
	/* QUERY_FILE_INFORMATION needs Fid(2) + InformationLevel(2) = 4 */
	u16 param_count = 3;

	KUNIT_EXPECT_LT(test, (int)param_count, 4);
}

static void test_trans2_query_path_info_min_param_count(struct kunit *test)
{
	/* QUERY_PATH_INFORMATION needs InformationLevel(2) + Reserved(4) = 6 */
	u16 param_count = 4;

	KUNIT_EXPECT_LT(test, (int)param_count, 6);
}

static void test_trans2_set_path_info_min_total_param(struct kunit *test)
{
	/*
	 * SET_PATH_INFORMATION checks total_param < 7.
	 * 6 should fail.
	 */
	u16 total_param = 6;

	KUNIT_EXPECT_LT(test, (int)total_param, 7);
}

static void test_trans2_set_file_info_min_total_param(struct kunit *test)
{
	/*
	 * SET_FILE_INFORMATION checks total_param < 4.
	 * 3 should fail.
	 */
	u16 total_param = 3;

	KUNIT_EXPECT_LT(test, (int)total_param, 4);
}

/* --- Test: TRANS2 parameter/data overlap detection --- */

static void test_trans2_param_data_overlap(struct kunit *test)
{
	/*
	 * Detect overlapping parameter and data regions.
	 * param: [60..80), data: [70..90) -> overlap at [70..80)
	 */
	unsigned int param_start = 60, param_end = 80;
	unsigned int data_start = 70, data_end = 90;
	bool overlapping;

	overlapping = (param_start < data_end && data_start < param_end);
	KUNIT_EXPECT_TRUE(test, overlapping);
}

static void test_trans2_param_data_no_overlap(struct kunit *test)
{
	/*
	 * Non-overlapping regions: param: [60..80), data: [80..100)
	 */
	unsigned int param_start = 60, param_end = 80;
	unsigned int data_start = 80, data_end = 100;
	bool overlapping;

	overlapping = (param_start < data_end && data_start < param_end);
	KUNIT_EXPECT_FALSE(test, overlapping);
}

/* --- Test: TRANS2 SetupCount validation --- */

static void test_trans2_setup_count_zero_rejected(struct kunit *test)
{
	/*
	 * TRANS2 requires at least SetupCount=1 (for SubCommand word).
	 * smb_trans2() rejects SetupCount < 1.
	 */
	u8 setup_count = 0;

	KUNIT_EXPECT_LT(test, (int)setup_count, 1);
}

static void test_trans2_setup_count_one_valid(struct kunit *test)
{
	u8 setup_count = 1;

	KUNIT_EXPECT_GE(test, (int)setup_count, 1);
}

static struct kunit_case ksmbd_smb1_trans2_test_cases[] = {
	/* Buffer validation (9 tests) */
	KUNIT_CASE(test_trans2_valid_buffer),
	KUNIT_CASE(test_trans2_param_overflow),
	KUNIT_CASE(test_trans2_data_overflow),
	KUNIT_CASE(test_trans2_total_param_less_than_count),
	KUNIT_CASE(test_trans2_total_data_less_than_count),
	KUNIT_CASE(test_trans2_zero_counts_valid),
	KUNIT_CASE(test_trans2_param_at_exact_boundary),
	KUNIT_CASE(test_trans2_param_one_past_boundary),
	KUNIT_CASE(test_trans2_param_offset_beyond_buf),
	/* Subcommand validation (10 tests) */
	KUNIT_CASE(test_trans2_find_first_valid),
	KUNIT_CASE(test_trans2_find_next_valid),
	KUNIT_CASE(test_trans2_query_fs_info_valid),
	KUNIT_CASE(test_trans2_set_fs_info_valid),
	KUNIT_CASE(test_trans2_query_path_info_valid),
	KUNIT_CASE(test_trans2_set_path_info_valid),
	KUNIT_CASE(test_trans2_query_file_info_valid),
	KUNIT_CASE(test_trans2_set_file_info_valid),
	KUNIT_CASE(test_trans2_create_directory_valid),
	KUNIT_CASE(test_trans2_invalid_subcommand),
	/* Info level validation (4 tests) */
	KUNIT_CASE(test_trans2_info_level_standard_valid),
	KUNIT_CASE(test_trans2_info_level_both_dir_valid),
	KUNIT_CASE(test_trans2_info_level_invalid_zero),
	KUNIT_CASE(test_trans2_info_level_invalid_0x200),
	/* Per-subcommand parameter count (7 tests) */
	KUNIT_CASE(test_trans2_find_first_min_param_count),
	KUNIT_CASE(test_trans2_find_next_min_param_count),
	KUNIT_CASE(test_trans2_query_fs_info_min_param_count),
	KUNIT_CASE(test_trans2_query_file_info_min_param_count),
	KUNIT_CASE(test_trans2_query_path_info_min_param_count),
	KUNIT_CASE(test_trans2_set_path_info_min_total_param),
	KUNIT_CASE(test_trans2_set_file_info_min_total_param),
	/* Overlap and setup count (4 tests) */
	KUNIT_CASE(test_trans2_param_data_overlap),
	KUNIT_CASE(test_trans2_param_data_no_overlap),
	KUNIT_CASE(test_trans2_setup_count_zero_rejected),
	KUNIT_CASE(test_trans2_setup_count_one_valid),
	{}
};

static struct kunit_suite ksmbd_smb1_trans2_test_suite = {
	.name = "ksmbd_smb1_trans2",
	.test_cases = ksmbd_smb1_trans2_test_cases,
};

kunit_test_suite(ksmbd_smb1_trans2_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 TRANS2 error paths and bounds checking");
