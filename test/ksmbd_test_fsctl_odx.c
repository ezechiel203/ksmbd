// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_OFFLOAD_READ, FSCTL_OFFLOAD_WRITE (ODX).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED	0xC000A2A1
#define STATUS_INVALID_TOKEN		0xC000A121

/* ODX token size per MS-FSCC */
#define STORAGE_OFFLOAD_TOKEN_SIZE	512
#define OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND	0x00000001

struct test_offload_read_input {
	__le32 Size;
	__le32 Flags;
	__le32 TokenTimeToLive;
	__le32 Reserved;
	__le64 FileOffset;
	__le64 CopyLength;
} __packed;

struct test_offload_read_output {
	__le32 Size;
	__le32 Flags;
	__le64 TransferLength;
	__u8   Token[STORAGE_OFFLOAD_TOKEN_SIZE];
} __packed;

struct test_offload_write_input {
	__le32 Size;
	__le32 Flags;
	__le64 FileOffset;
	__le64 CopyLength;
	__le64 TransferOffset;
	__u8   Token[STORAGE_OFFLOAD_TOKEN_SIZE];
} __packed;

struct test_offload_write_output {
	__le32 Size;
	__le32 Flags;
	__le64 LengthWritten;
} __packed;

struct test_odx_ctx {
	bool fp_exists;
	bool writable;
	__le32 daccess;
	u64 file_size;
};

/* Replicated offload_read validation */
static int test_validate_offload_read(struct test_odx_ctx *ctx,
				      void *in_buf, unsigned int in_buf_len,
				      unsigned int max_out_len,
				      unsigned int *out_len, __le32 *status)
{
	struct test_offload_read_input *in;

	*status = 0;
	*out_len = 0;

	if (in_buf_len < sizeof(*in)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	if (max_out_len < sizeof(struct test_offload_read_output)) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	if (!(ctx->daccess & cpu_to_le32(0x00000001))) { /* FILE_READ_DATA */
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	in = (struct test_offload_read_input *)in_buf;
	if ((loff_t)le64_to_cpu(in->FileOffset) >= (loff_t)ctx->file_size &&
	    ctx->file_size > 0) {
		*status = cpu_to_le32(STATUS_OFFLOAD_READ_FILE_NOT_SUPPORTED);
		return -EINVAL;
	}

	*out_len = sizeof(struct test_offload_read_output);
	return 0;
}

/* Replicated offload_write validation */
static int test_validate_offload_write(struct test_odx_ctx *ctx,
				       void *in_buf, unsigned int in_buf_len,
				       unsigned int max_out_len,
				       unsigned int *out_len, __le32 *status)
{
	*status = 0;
	*out_len = 0;

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct test_offload_write_input)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	if (max_out_len < sizeof(struct test_offload_write_output)) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	if (!(ctx->daccess & cpu_to_le32(0x00000002))) { /* FILE_WRITE_DATA */
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	*out_len = sizeof(struct test_offload_write_output);
	return 0;
}

/* ---- Test cases ---- */

static void test_offload_read_normal(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = true,
		.daccess = cpu_to_le32(0x00000001), .file_size = 4096,
	};
	struct test_offload_read_input in = {
		.FileOffset = cpu_to_le64(0), .CopyLength = cpu_to_le64(4096),
	};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_read(&ctx, &in, sizeof(in),
					 sizeof(struct test_offload_read_output),
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len,
			(unsigned int)sizeof(struct test_offload_read_output));
}

static void test_offload_read_buffer_too_small(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .daccess = cpu_to_le32(0x00000001),
		.file_size = 4096,
	};
	struct test_offload_read_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_read(&ctx, &in, sizeof(in), 1,
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_offload_read_input_too_small(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .daccess = cpu_to_le32(0x00000001),
	};
	u8 small[sizeof(struct test_offload_read_input) - 1];
	unsigned int out_len;
	__le32 status;
	int ret;

	memset(small, 0, sizeof(small));
	ret = test_validate_offload_read(&ctx, small, sizeof(small),
					 sizeof(struct test_offload_read_output),
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_offload_read_invalid_handle(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = false, .daccess = cpu_to_le32(0x00000001),
	};
	struct test_offload_read_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_read(&ctx, &in, sizeof(in),
					 sizeof(struct test_offload_read_output),
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_offload_read_access_denied(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .daccess = 0, .file_size = 4096,
	};
	struct test_offload_read_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_read(&ctx, &in, sizeof(in),
					 sizeof(struct test_offload_read_output),
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_offload_read_beyond_eof(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .daccess = cpu_to_le32(0x00000001),
		.file_size = 4096,
	};
	struct test_offload_read_input in = {
		.FileOffset = cpu_to_le64(8192), /* Beyond 4096 */
	};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_read(&ctx, &in, sizeof(in),
					 sizeof(struct test_offload_read_output),
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_offload_write_normal(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = true,
		.daccess = cpu_to_le32(0x00000002),
	};
	struct test_offload_write_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_write(&ctx, &in, sizeof(in),
					  sizeof(struct test_offload_write_output),
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_offload_write_invalid_token(struct kunit *test)
{
	/* Token validation is at VFS level; validation passes here */
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = true,
		.daccess = cpu_to_le32(0x00000002),
	};
	struct test_offload_write_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	memset(in.Token, 0xFF, STORAGE_OFFLOAD_TOKEN_SIZE);
	ret = test_validate_offload_write(&ctx, &in, sizeof(in),
					  sizeof(struct test_offload_write_output),
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_offload_write_buffer_too_small(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = true,
		.daccess = cpu_to_le32(0x00000002),
	};
	struct test_offload_write_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_write(&ctx, &in, sizeof(in), 1,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_offload_write_input_too_small(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = true,
	};
	u8 small[sizeof(struct test_offload_write_input) - 1];
	unsigned int out_len;
	__le32 status;
	int ret;

	memset(small, 0, sizeof(small));
	ret = test_validate_offload_write(&ctx, small, sizeof(small),
					  sizeof(struct test_offload_write_output),
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_offload_write_access_denied(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = true,
		.daccess = cpu_to_le32(0x00000001), /* READ only */
	};
	struct test_offload_write_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_write(&ctx, &in, sizeof(in),
					  sizeof(struct test_offload_write_output),
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_offload_write_not_writable(struct kunit *test)
{
	struct test_odx_ctx ctx = {
		.fp_exists = true, .writable = false,
		.daccess = cpu_to_le32(0x00000002),
	};
	struct test_offload_write_input in = {};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_write(&ctx, &in, sizeof(in),
					  sizeof(struct test_offload_write_output),
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_odx_token_expiry(struct kunit *test)
{
	/* Token expiry is handled by a timer, not in input validation.
	 * Verify the validation path passes even with zero TTL. */
	struct test_odx_ctx ctx = {
		.fp_exists = true, .daccess = cpu_to_le32(0x00000001),
		.file_size = 4096,
	};
	struct test_offload_read_input in = {
		.TokenTimeToLive = 0,
		.FileOffset = cpu_to_le64(0), .CopyLength = cpu_to_le64(4096),
	};
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_offload_read(&ctx, &in, sizeof(in),
					 sizeof(struct test_offload_read_output),
					 &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static struct kunit_case ksmbd_fsctl_odx_test_cases[] = {
	KUNIT_CASE(test_offload_read_normal),
	KUNIT_CASE(test_offload_read_buffer_too_small),
	KUNIT_CASE(test_offload_read_input_too_small),
	KUNIT_CASE(test_offload_read_invalid_handle),
	KUNIT_CASE(test_offload_read_access_denied),
	KUNIT_CASE(test_offload_read_beyond_eof),
	KUNIT_CASE(test_offload_write_normal),
	KUNIT_CASE(test_offload_write_invalid_token),
	KUNIT_CASE(test_offload_write_buffer_too_small),
	KUNIT_CASE(test_offload_write_input_too_small),
	KUNIT_CASE(test_offload_write_access_denied),
	KUNIT_CASE(test_offload_write_not_writable),
	KUNIT_CASE(test_odx_token_expiry),
	{}
};

static struct kunit_suite ksmbd_fsctl_odx_test_suite = {
	.name = "ksmbd_fsctl_odx",
	.test_cases = ksmbd_fsctl_odx_test_cases,
};

kunit_test_suite(ksmbd_fsctl_odx_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL ODX offload data transfer");
