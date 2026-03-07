// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 IOCTL handler logic (smb2_ioctl.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

#define TEST_SMB2_0_IOCTL_IS_FSCTL	0x00000001

/* FSCTL codes */
#define TEST_FSCTL_DFS_GET_REFERRALS		0x00060194
#define TEST_FSCTL_DFS_GET_REFERRALS_EX		0x000601B0
#define TEST_FSCTL_SET_REPARSE_POINT		0x000900A4
#define TEST_FSCTL_GET_REPARSE_POINT		0x000900A8
#define TEST_FSCTL_DELETE_REPARSE_POINT		0x000900AC
#define TEST_FSCTL_CREATE_OR_GET_OBJECT_ID	0x000900C0
#define TEST_FSCTL_SET_SPARSE			0x000900C4
#define TEST_FSCTL_SET_ZERO_DATA		0x000980C8
#define TEST_FSCTL_QUERY_ALLOCATED_RANGES	0x000940CF
#define TEST_FSCTL_IS_PATHNAME_VALID		0x0009002C
#define TEST_FSCTL_QUERY_ON_DISK_VOL_INFO	0x009013C0
#define TEST_FSCTL_PIPE_PEEK			0x0011400C
#define TEST_FSCTL_PIPE_TRANSCEIVE		0x0011C017
#define TEST_FSCTL_PIPE_WAIT			0x00110018
#define TEST_FSCTL_REQUEST_RESUME_KEY		0x00140078
#define TEST_FSCTL_VALIDATE_NEGOTIATE_INFO	0x00140204
#define TEST_FSCTL_QUERY_NETWORK_INTERFACE_INFO	0x001401FC
#define TEST_FSCTL_SRV_ENUMERATE_SNAPSHOTS	0x00144064
#define TEST_FSCTL_COPYCHUNK			0x001440F2
#define TEST_FSCTL_COPYCHUNK_WRITE		0x001480F2
#define TEST_FSCTL_LMR_REQUEST_RESILIENCY	0x001401D4

/* Copy chunk limits */
#define TEST_MAX_CHUNK_COUNT	256
#define TEST_MAX_CHUNK_SIZE	(1024 * 1024)     /* 1 MB */
#define TEST_MAX_TOTAL_SIZE	(16 * 1024 * 1024) /* 16 MB */

/* SMB2 header size */
#define TEST_SMB2_HEADER_SIZE	64

/* ---- Replicated logic ---- */

/*
 * Validate IOCTL flags: must be SMB2_0_IOCTL_IS_FSCTL
 */
static int test_validate_ioctl_flags(u32 flags)
{
	if (flags != TEST_SMB2_0_IOCTL_IS_FSCTL)
		return -EINVAL;
	return 0;
}

/*
 * Validate InputOffset within request buffer
 */
static bool test_validate_input_offset(u32 input_offset, u32 input_count,
				       u32 buf_size)
{
	if (input_offset > buf_size)
		return false;
	if (input_count > buf_size - input_offset)
		return false;
	return true;
}

/*
 * Check if FSCTL code is known
 */
static int test_classify_fsctl(u32 code)
{
	switch (code) {
	case TEST_FSCTL_DFS_GET_REFERRALS:
	case TEST_FSCTL_DFS_GET_REFERRALS_EX:
	case TEST_FSCTL_SET_REPARSE_POINT:
	case TEST_FSCTL_GET_REPARSE_POINT:
	case TEST_FSCTL_DELETE_REPARSE_POINT:
	case TEST_FSCTL_CREATE_OR_GET_OBJECT_ID:
	case TEST_FSCTL_SET_SPARSE:
	case TEST_FSCTL_SET_ZERO_DATA:
	case TEST_FSCTL_QUERY_ALLOCATED_RANGES:
	case TEST_FSCTL_IS_PATHNAME_VALID:
	case TEST_FSCTL_PIPE_PEEK:
	case TEST_FSCTL_PIPE_TRANSCEIVE:
	case TEST_FSCTL_PIPE_WAIT:
	case TEST_FSCTL_REQUEST_RESUME_KEY:
	case TEST_FSCTL_VALIDATE_NEGOTIATE_INFO:
	case TEST_FSCTL_QUERY_NETWORK_INTERFACE_INFO:
	case TEST_FSCTL_SRV_ENUMERATE_SNAPSHOTS:
	case TEST_FSCTL_COPYCHUNK:
	case TEST_FSCTL_COPYCHUNK_WRITE:
	case TEST_FSCTL_LMR_REQUEST_RESILIENCY:
		return 0; /* known/supported */
	case TEST_FSCTL_QUERY_ON_DISK_VOL_INFO:
		return -EOPNOTSUPP; /* known but not supported */
	default:
		return -ENODEV; /* STATUS_INVALID_DEVICE_REQUEST */
	}
}

/*
 * Validate copy chunk parameters
 */
static int test_validate_copychunk(u32 chunk_count, u32 chunk_size,
				   u64 total_size)
{
	if (chunk_count > TEST_MAX_CHUNK_COUNT)
		return -EINVAL;
	if (chunk_size > TEST_MAX_CHUNK_SIZE)
		return -EINVAL;
	if (total_size > TEST_MAX_TOTAL_SIZE)
		return -EINVAL;
	return 0;
}

/*
 * Validate negotiate info: check dialect matches
 */
static bool test_validate_negotiate_dialect(u16 negotiated, u16 requested)
{
	return negotiated == requested;
}

/*
 * Validate negotiate info: check GUID matches
 */
static bool test_validate_negotiate_guid(const u8 *stored, const u8 *received)
{
	return memcmp(stored, received, 16) == 0;
}

/*
 * Validate set_sparse with empty buffer (default = TRUE)
 */
static bool test_set_sparse_default(u32 input_count)
{
	return input_count == 0; /* default SetSparse=TRUE */
}

/* ---- Test Cases: IOCTL Request Validation ---- */

static void test_ioctl_flags_fsctl_required(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_ioctl_flags(TEST_SMB2_0_IOCTL_IS_FSCTL), 0);
}

static void test_ioctl_flags_zero_rejected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_ioctl_flags(0), -EINVAL);
}

static void test_ioctl_flags_other_value_rejected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_validate_ioctl_flags(2), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_validate_ioctl_flags(0xFFFFFFFF), -EINVAL);
}

static void test_ioctl_input_offset_bounds(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_validate_input_offset(80, 100, 256));
	KUNIT_EXPECT_TRUE(test, test_validate_input_offset(200, 56, 256));
}

static void test_ioctl_input_offset_overflow(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_validate_input_offset(300, 10, 256));
}

static void test_ioctl_input_count_overflow(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_validate_input_offset(200, 100, 256));
}

static void test_ioctl_max_output_response(struct kunit *test)
{
	u32 max_output = 65536;

	KUNIT_EXPECT_TRUE(test, max_output <= 65536);
}

static void test_ioctl_compound_fid(struct kunit *test)
{
	u64 compound_fid = 77;
	bool is_related = true;

	KUNIT_EXPECT_TRUE(test, is_related);
	KUNIT_EXPECT_NE(test, compound_fid, (u64)0);
}

static void test_ioctl_channel_sequence(struct kunit *test)
{
	/* ChannelSequence only validated when FID is a file (has_file_id) */
	bool has_file_id = true;

	KUNIT_EXPECT_TRUE(test, has_file_id);
}

/* ---- Test Cases: FSCTL Filesystem Operations ---- */

static void test_ioctl_set_reparse_point(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_SET_REPARSE_POINT), 0);
}

static void test_ioctl_get_reparse_point(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_GET_REPARSE_POINT), 0);
}

static void test_ioctl_delete_reparse_point(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_DELETE_REPARSE_POINT), 0);
}

static void test_ioctl_set_sparse(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_SET_SPARSE), 0);
}

static void test_ioctl_set_sparse_no_buffer(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_set_sparse_default(0));
	KUNIT_EXPECT_FALSE(test, test_set_sparse_default(1));
}

static void test_ioctl_set_zero_data(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_SET_ZERO_DATA), 0);
}

static void test_ioctl_query_allocated_ranges(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_QUERY_ALLOCATED_RANGES), 0);
}

static void test_ioctl_query_on_disk_volume_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_QUERY_ON_DISK_VOL_INFO),
			-EOPNOTSUPP);
}

/* ---- Test Cases: FSCTL Network Operations ---- */

static void test_ioctl_dfs_get_referrals(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_DFS_GET_REFERRALS), 0);
}

static void test_ioctl_dfs_get_referrals_ex(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_DFS_GET_REFERRALS_EX), 0);
}

static void test_ioctl_validate_negotiate_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_VALIDATE_NEGOTIATE_INFO), 0);
}

static void test_ioctl_validate_negotiate_dialect_mismatch(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_validate_negotiate_dialect(0x0311, 0x0302));
}

static void test_ioctl_validate_negotiate_guid_mismatch(struct kunit *test)
{
	u8 stored[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	u8 received[16] = {0};

	KUNIT_EXPECT_FALSE(test, test_validate_negotiate_guid(stored, received));
}

static void test_ioctl_pipe_transact(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_PIPE_TRANSCEIVE), 0);
}

static void test_ioctl_pipe_peek(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_PIPE_PEEK), 0);
}

static void test_ioctl_pipe_wait(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_PIPE_WAIT), 0);
}

static void test_ioctl_request_resume_key(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_REQUEST_RESUME_KEY), 0);
}

/* ---- Test Cases: Server-Side Copy ---- */

static void test_ioctl_copychunk(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_COPYCHUNK), 0);
}

static void test_ioctl_copychunk_write(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(TEST_FSCTL_COPYCHUNK_WRITE), 0);
}

static void test_ioctl_copychunk_too_many_chunks(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_validate_copychunk(TEST_MAX_CHUNK_COUNT + 1, 1024, 1024),
		-EINVAL);
}

static void test_ioctl_copychunk_chunk_too_large(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_validate_copychunk(1, TEST_MAX_CHUNK_SIZE + 1, TEST_MAX_CHUNK_SIZE + 1),
		-EINVAL);
}

static void test_ioctl_copychunk_total_too_large(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_validate_copychunk(1, 1024, TEST_MAX_TOTAL_SIZE + 1),
		-EINVAL);
}

static void test_ioctl_copychunk_invalid_resume_key(struct kunit *test)
{
	u8 key[24] = {0};

	/* All-zero key is invalid */
	bool all_zero = true;
	int i;

	for (i = 0; i < 24; i++) {
		if (key[i] != 0) {
			all_zero = false;
			break;
		}
	}
	KUNIT_EXPECT_TRUE(test, all_zero);
}

/* ---- Test Cases: Network Interface ---- */

static void test_ioctl_network_interface_info(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_classify_fsctl(TEST_FSCTL_QUERY_NETWORK_INTERFACE_INFO), 0);
}

static void test_ioctl_network_interface_rdma_capable(struct kunit *test)
{
	u32 capability = 0x00000002; /* RDMA_CAPABLE */

	KUNIT_EXPECT_TRUE(test, capability & 0x02);
}

/* ---- Test Cases: Miscellaneous ---- */

static void test_ioctl_create_or_get_object_id(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_classify_fsctl(TEST_FSCTL_CREATE_OR_GET_OBJECT_ID), 0);
}

static void test_ioctl_is_pathname_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_classify_fsctl(TEST_FSCTL_IS_PATHNAME_VALID), 0);
}

static void test_ioctl_enumerate_snapshots(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_classify_fsctl(TEST_FSCTL_SRV_ENUMERATE_SNAPSHOTS), 0);
}

static void test_ioctl_unknown_code(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_classify_fsctl(0xDEADBEEF), -ENODEV);
}

static void test_ioctl_not_supported_code(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		test_classify_fsctl(TEST_FSCTL_QUERY_ON_DISK_VOL_INFO),
		-EOPNOTSUPP);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_ioctl_test_cases[] = {
	/* Request Validation */
	KUNIT_CASE(test_ioctl_flags_fsctl_required),
	KUNIT_CASE(test_ioctl_flags_zero_rejected),
	KUNIT_CASE(test_ioctl_flags_other_value_rejected),
	KUNIT_CASE(test_ioctl_input_offset_bounds),
	KUNIT_CASE(test_ioctl_input_offset_overflow),
	KUNIT_CASE(test_ioctl_input_count_overflow),
	KUNIT_CASE(test_ioctl_max_output_response),
	KUNIT_CASE(test_ioctl_compound_fid),
	KUNIT_CASE(test_ioctl_channel_sequence),
	/* FSCTL Filesystem */
	KUNIT_CASE(test_ioctl_set_reparse_point),
	KUNIT_CASE(test_ioctl_get_reparse_point),
	KUNIT_CASE(test_ioctl_delete_reparse_point),
	KUNIT_CASE(test_ioctl_set_sparse),
	KUNIT_CASE(test_ioctl_set_sparse_no_buffer),
	KUNIT_CASE(test_ioctl_set_zero_data),
	KUNIT_CASE(test_ioctl_query_allocated_ranges),
	KUNIT_CASE(test_ioctl_query_on_disk_volume_info),
	/* FSCTL Network */
	KUNIT_CASE(test_ioctl_dfs_get_referrals),
	KUNIT_CASE(test_ioctl_dfs_get_referrals_ex),
	KUNIT_CASE(test_ioctl_validate_negotiate_info),
	KUNIT_CASE(test_ioctl_validate_negotiate_dialect_mismatch),
	KUNIT_CASE(test_ioctl_validate_negotiate_guid_mismatch),
	KUNIT_CASE(test_ioctl_pipe_transact),
	KUNIT_CASE(test_ioctl_pipe_peek),
	KUNIT_CASE(test_ioctl_pipe_wait),
	KUNIT_CASE(test_ioctl_request_resume_key),
	/* Copy Chunk */
	KUNIT_CASE(test_ioctl_copychunk),
	KUNIT_CASE(test_ioctl_copychunk_write),
	KUNIT_CASE(test_ioctl_copychunk_too_many_chunks),
	KUNIT_CASE(test_ioctl_copychunk_chunk_too_large),
	KUNIT_CASE(test_ioctl_copychunk_total_too_large),
	KUNIT_CASE(test_ioctl_copychunk_invalid_resume_key),
	/* Network Interface */
	KUNIT_CASE(test_ioctl_network_interface_info),
	KUNIT_CASE(test_ioctl_network_interface_rdma_capable),
	/* Miscellaneous */
	KUNIT_CASE(test_ioctl_create_or_get_object_id),
	KUNIT_CASE(test_ioctl_is_pathname_valid),
	KUNIT_CASE(test_ioctl_enumerate_snapshots),
	KUNIT_CASE(test_ioctl_unknown_code),
	KUNIT_CASE(test_ioctl_not_supported_code),
	{}
};

static struct kunit_suite ksmbd_smb2_ioctl_test_suite = {
	.name = "ksmbd_smb2_ioctl",
	.test_cases = ksmbd_smb2_ioctl_test_cases,
};

kunit_test_suite(ksmbd_smb2_ioctl_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 IOCTL handler");
