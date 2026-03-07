// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_GET_COMPRESSION, FSCTL_SET_COMPRESSION.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define COMPRESSION_FORMAT_NONE		0x0000
#define COMPRESSION_FORMAT_LZNT1	0x0002
#define ATTR_COMPRESSED_LE		cpu_to_le32(0x00000800)

#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_NOT_SUPPORTED		0xC00000BB

struct test_compress_ctx {
	bool fp_exists;
	bool writable;
	__le32 fattr;
};

static int test_get_compression(struct test_compress_ctx *ctx,
				unsigned int max_out_len,
				__le16 *out_state, unsigned int *out_len,
				__le32 *status)
{
	*status = 0;
	*out_len = 0;

	if (max_out_len < sizeof(__le16)) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	if (ctx->fattr & ATTR_COMPRESSED_LE)
		*out_state = cpu_to_le16(COMPRESSION_FORMAT_LZNT1);
	else
		*out_state = cpu_to_le16(COMPRESSION_FORMAT_NONE);

	*out_len = sizeof(__le16);
	return 0;
}

static int test_set_compression(struct test_compress_ctx *ctx,
				void *in_buf, unsigned int in_buf_len,
				__le32 *status)
{
	__le16 compression_state;
	u16 state;

	*status = 0;

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	if (in_buf_len < sizeof(__le16)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	memcpy(&compression_state, in_buf, sizeof(compression_state));
	state = le16_to_cpu(compression_state);

	if (state != COMPRESSION_FORMAT_NONE) {
		*status = cpu_to_le32(STATUS_NOT_SUPPORTED);
		return -EOPNOTSUPP;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	ctx->fattr &= ~ATTR_COMPRESSED_LE;
	return 0;
}

/* ---- Test cases ---- */

static void test_get_compression_none(struct kunit *test)
{
	struct test_compress_ctx ctx = { .fp_exists = true, .fattr = 0 };
	__le16 state;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_compression(&ctx, sizeof(__le16), &state, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(state), (u16)COMPRESSION_FORMAT_NONE);
}

static void test_get_compression_lznt1(struct kunit *test)
{
	struct test_compress_ctx ctx = { .fp_exists = true, .fattr = ATTR_COMPRESSED_LE };
	__le16 state;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_compression(&ctx, sizeof(__le16), &state, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(state), (u16)COMPRESSION_FORMAT_LZNT1);
}

static void test_get_compression_buffer_too_small(struct kunit *test)
{
	struct test_compress_ctx ctx = { .fp_exists = true };
	__le16 state;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_compression(&ctx, sizeof(__le16) - 1, &state, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_get_compression_invalid_handle(struct kunit *test)
{
	struct test_compress_ctx ctx = { .fp_exists = false };
	__le16 state;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_compression(&ctx, sizeof(__le16), &state, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static void test_set_compression_none(struct kunit *test)
{
	struct test_compress_ctx ctx = {
		.fp_exists = true, .writable = true,
		.fattr = ATTR_COMPRESSED_LE,
	};
	__le16 state = cpu_to_le16(COMPRESSION_FORMAT_NONE);
	__le32 status;
	int ret;

	ret = test_set_compression(&ctx, &state, sizeof(state), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, !!(ctx.fattr & ATTR_COMPRESSED_LE));
}

static void test_set_compression_lznt1_rejected(struct kunit *test)
{
	struct test_compress_ctx ctx = {
		.fp_exists = true, .writable = true,
	};
	__le16 state = cpu_to_le16(COMPRESSION_FORMAT_LZNT1);
	__le32 status;
	int ret;

	ret = test_set_compression(&ctx, &state, sizeof(state), &status);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_NOT_SUPPORTED);
}

static void test_set_compression_input_too_small(struct kunit *test)
{
	struct test_compress_ctx ctx = {
		.fp_exists = true, .writable = true,
	};
	u8 small[1];
	__le32 status;
	int ret;

	small[0] = 0;
	ret = test_set_compression(&ctx, small, 1, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_compression_read_only_tree(struct kunit *test)
{
	struct test_compress_ctx ctx = {
		.fp_exists = true, .writable = false,
	};
	__le16 state = cpu_to_le16(COMPRESSION_FORMAT_NONE);
	__le32 status;
	int ret;

	ret = test_set_compression(&ctx, &state, sizeof(state), &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_set_compression_invalid_handle(struct kunit *test)
{
	struct test_compress_ctx ctx = {
		.fp_exists = false, .writable = true,
	};
	__le16 state = cpu_to_le16(COMPRESSION_FORMAT_NONE);
	__le32 status;
	int ret;

	ret = test_set_compression(&ctx, &state, sizeof(state), &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static struct kunit_case ksmbd_fsctl_compression_test_cases[] = {
	KUNIT_CASE(test_get_compression_none),
	KUNIT_CASE(test_get_compression_lznt1),
	KUNIT_CASE(test_get_compression_buffer_too_small),
	KUNIT_CASE(test_get_compression_invalid_handle),
	KUNIT_CASE(test_set_compression_none),
	KUNIT_CASE(test_set_compression_lznt1_rejected),
	KUNIT_CASE(test_set_compression_input_too_small),
	KUNIT_CASE(test_set_compression_read_only_tree),
	KUNIT_CASE(test_set_compression_invalid_handle),
	{}
};

static struct kunit_suite ksmbd_fsctl_compression_test_suite = {
	.name = "ksmbd_fsctl_compression",
	.test_cases = ksmbd_fsctl_compression_test_cases,
};

kunit_test_suite(ksmbd_fsctl_compression_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL compression handlers");
