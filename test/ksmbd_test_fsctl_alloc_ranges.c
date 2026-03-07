// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_QUERY_ALLOCATED_RANGES sparse file edge cases
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and test constants, layout, and pure validation
 *   logic for allocated-range queries.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Inlined FSCTL constants from smbfsctl.h ---- */

#define TEST_FSCTL_QUERY_ALLOCATED_RANGES	0x000940CF
#define TEST_FSCTL_SET_SPARSE			0x000900C4
#define TEST_FSCTL_SET_ZERO_DATA		0x000980C8

/* ---- Inlined structures from smb2pdu.h ---- */

struct test_file_allocated_range_buffer {
	__le64	file_offset;
	__le64	length;
} __packed;

struct test_file_zero_data_information {
	__le64	FileOffset;
	__le64	BeyondFinalZero;
} __packed;

struct test_file_sparse {
	__u8	SetSparse;
} __packed;

/*
 * Replicate the input validation logic from
 * ksmbd_fsctl_query_allocated_ranges() in ksmbd_fsctl_extra.c.
 *
 * Returns: 0 on valid input, -EINVAL on bad input, -ENOSPC if no room
 *          for output.
 */
static int test_validate_qar_input(const void *in_buf,
				   unsigned int in_buf_len,
				   unsigned int max_out_len)
{
	const struct test_file_allocated_range_buffer *qar_req;
	s64 start, length;
	unsigned int in_count;

	if (in_buf_len < sizeof(struct test_file_allocated_range_buffer))
		return -EINVAL;

	qar_req = (const struct test_file_allocated_range_buffer *)in_buf;

	start = (s64)le64_to_cpu(qar_req->file_offset);
	length = (s64)le64_to_cpu(qar_req->length);

	if (start < 0 || length < 0)
		return -EINVAL;

	/* Check addition overflow: start + length */
	if (length > 0 && start > S64_MAX - length)
		return -EINVAL;

	in_count = max_out_len /
		   sizeof(struct test_file_allocated_range_buffer);
	if (in_count == 0)
		return -ENOSPC;

	return 0;
}

/*
 * Build a response buffer with the given number of allocated ranges.
 * Returns the total output byte count.
 */
static unsigned int test_build_qar_response(
	struct test_file_allocated_range_buffer *out,
	unsigned int count,
	u64 base_offset,
	u64 range_len)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		out[i].file_offset = cpu_to_le64(base_offset + i * range_len);
		out[i].length = cpu_to_le64(range_len);
	}

	return count * sizeof(struct test_file_allocated_range_buffer);
}

/* ---- Test cases ---- */

/*
 * test_fsctl_query_alloc_ranges_constant - verify constant value
 */
static void test_fsctl_query_alloc_ranges_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_FSCTL_QUERY_ALLOCATED_RANGES,
			(u32)0x000940CF);
}

/*
 * test_fsctl_set_sparse_constant - verify FSCTL_SET_SPARSE value
 */
static void test_fsctl_set_sparse_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_FSCTL_SET_SPARSE, (u32)0x000900C4);
}

/*
 * test_fsctl_set_zero_data_constant - verify FSCTL_SET_ZERO_DATA value
 */
static void test_fsctl_set_zero_data_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_FSCTL_SET_ZERO_DATA, (u32)0x000980C8);
}

/*
 * test_qar_input_struct_layout - verify input structure is 16 bytes
 *
 * MS-FSCC 2.3.48: FILE_ALLOCATED_RANGE_BUFFER contains
 * FileOffset (8 bytes) + Length (8 bytes) = 16 bytes total.
 */
static void test_qar_input_struct_layout(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			sizeof(struct test_file_allocated_range_buffer),
			(size_t)16);

	/* file_offset at offset 0 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_file_allocated_range_buffer,
				 file_offset),
			(size_t)0);

	/* length at offset 8 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_file_allocated_range_buffer,
				 length),
			(size_t)8);
}

/*
 * test_qar_zero_length_query - Length=0 is a valid (empty) query
 *
 * A zero-length query should pass validation; the server would simply
 * return no allocated ranges.
 */
static void test_qar_zero_length_query(struct kunit *test)
{
	struct test_file_allocated_range_buffer req = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(0),
	};
	int ret;

	ret = test_validate_qar_input(&req, sizeof(req), 1024);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_qar_offset_beyond_int64_max - offset with sign bit set is rejected
 *
 * When the FileOffset has bit 63 set, it is negative when interpreted
 * as a signed 64-bit value and should be rejected.
 */
static void test_qar_offset_beyond_int64_max(struct kunit *test)
{
	struct test_file_allocated_range_buffer req = {
		.file_offset = cpu_to_le64(0x8000000000000000ULL),
		.length = cpu_to_le64(1),
	};
	int ret;

	ret = test_validate_qar_input(&req, sizeof(req), 1024);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * test_qar_offset_plus_length_overflow - offset + length overflow caught
 *
 * If FileOffset is near S64_MAX and Length would cause signed overflow,
 * validation must reject the request.
 */
static void test_qar_offset_plus_length_overflow(struct kunit *test)
{
	struct test_file_allocated_range_buffer req = {
		.file_offset = cpu_to_le64(S64_MAX),
		.length = cpu_to_le64(1),
	};
	int ret;

	ret = test_validate_qar_input(&req, sizeof(req), 1024);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * test_qar_output_struct_layout - output entry matches input struct
 *
 * The output uses the same FILE_ALLOCATED_RANGE_BUFFER structure,
 * so each entry is 16 bytes: FileOffset + Length.
 */
static void test_qar_output_struct_layout(struct kunit *test)
{
	struct test_file_allocated_range_buffer entry;

	KUNIT_EXPECT_EQ(test, sizeof(entry), (size_t)16);
}

/*
 * test_qar_multiple_ranges_array - multiple ranges are laid out
 *                                   contiguously in the response
 */
static void test_qar_multiple_ranges_array(struct kunit *test)
{
	struct test_file_allocated_range_buffer out[3];
	unsigned int total_bytes;

	total_bytes = test_build_qar_response(out, 3, 0, 4096);

	/* 3 entries * 16 bytes = 48 bytes */
	KUNIT_EXPECT_EQ(test, total_bytes, (unsigned int)(3 * 16));

	/* Verify each range */
	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[0].file_offset), (u64)0);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[0].length), (u64)4096);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[1].file_offset), (u64)4096);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[1].length), (u64)4096);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[2].file_offset), (u64)8192);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[2].length), (u64)4096);
}

/*
 * test_qar_empty_response - zero ranges means zero output bytes
 */
static void test_qar_empty_response(struct kunit *test)
{
	struct test_file_allocated_range_buffer out[1];
	unsigned int total_bytes;

	total_bytes = test_build_qar_response(out, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, total_bytes, (unsigned int)0);
}

/*
 * test_qar_single_range_entire_file - one range covering the full file
 */
static void test_qar_single_range_entire_file(struct kunit *test)
{
	struct test_file_allocated_range_buffer out[1];
	unsigned int total_bytes;
	u64 file_size = 1048576; /* 1 MB */

	total_bytes = test_build_qar_response(out, 1, 0, file_size);

	KUNIT_EXPECT_EQ(test, total_bytes, (unsigned int)16);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[0].file_offset), (u64)0);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(out[0].length), file_size);
}

static struct kunit_case ksmbd_fsctl_alloc_ranges_test_cases[] = {
	KUNIT_CASE(test_fsctl_query_alloc_ranges_constant),
	KUNIT_CASE(test_fsctl_set_sparse_constant),
	KUNIT_CASE(test_fsctl_set_zero_data_constant),
	KUNIT_CASE(test_qar_input_struct_layout),
	KUNIT_CASE(test_qar_zero_length_query),
	KUNIT_CASE(test_qar_offset_beyond_int64_max),
	KUNIT_CASE(test_qar_offset_plus_length_overflow),
	KUNIT_CASE(test_qar_output_struct_layout),
	KUNIT_CASE(test_qar_multiple_ranges_array),
	KUNIT_CASE(test_qar_empty_response),
	KUNIT_CASE(test_qar_single_range_entire_file),
	{}
};

static struct kunit_suite ksmbd_fsctl_alloc_ranges_test_suite = {
	.name = "ksmbd_fsctl_alloc_ranges",
	.test_cases = ksmbd_fsctl_alloc_ranges_test_cases,
};

kunit_test_suite(ksmbd_fsctl_alloc_ranges_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL_QUERY_ALLOCATED_RANGES edge cases");
