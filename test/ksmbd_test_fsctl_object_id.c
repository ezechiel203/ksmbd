// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for Object ID FSCTLs: CREATE_OR_GET, GET, SET,
 *   SET_EXTENDED, DELETE.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define STATUS_SUCCESS			0x00000000
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_FILE_CLOSED		0xC0000128
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_OBJECT_NAME_NOT_FOUND	0xC0000034

struct test_object_id_rsp {
	u8 ObjectId[16];
	u8 BirthObjectId[16];
	u8 DomainId[16];
	u8 Extended[16];
} __packed;

struct test_objid_ctx {
	bool writable;
	bool fp_exists;
	bool xattr_exists;
	int  xattr_size;	/* -1 = no xattr, 16 = valid, other = wrong size */
	u8   xattr_data[16];
};

/* Replicate object ID validation logic */

static int test_validate_get_object_id(struct test_objid_ctx *ctx,
				       unsigned int max_out_len,
				       struct test_object_id_rsp *rsp,
				       unsigned int *out_len, __le32 *status)
{
	*status = 0;
	*out_len = 0;

	if (max_out_len < sizeof(*rsp)) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_FILE_CLOSED);
		return -ENOENT;
	}

	memset(rsp, 0, sizeof(*rsp));

	if (ctx->xattr_exists) {
		if (ctx->xattr_size != 16)
			return -EINVAL;
		memcpy(rsp->ObjectId, ctx->xattr_data, 16);
	} else {
		/* Fallback: use inode-based ID */
		memset(rsp->ObjectId, 0xAA, 16);
	}
	memcpy(rsp->BirthObjectId, rsp->ObjectId, 16);
	*out_len = sizeof(*rsp);
	return 0;
}

static int test_validate_set_object_id(struct test_objid_ctx *ctx,
				       void *in_buf, unsigned int in_buf_len,
				       __le32 *status)
{
	*status = 0;

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	if (in_buf_len < 16) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_FILE_CLOSED);
		return -ENOENT;
	}

	return 0;
}

static int test_validate_delete_object_id(struct test_objid_ctx *ctx,
					  __le32 *status)
{
	*status = 0;

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	/* ENOENT/ENODATA on delete is not an error */
	return 0;
}

/* ---- Test cases ---- */

static void test_create_or_get_object_id_normal(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = true,
		.xattr_exists = false,
	};
	struct test_object_id_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_get_object_id(&ctx, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
}

static void test_create_or_get_object_id_buffer_too_small(struct kunit *test)
{
	struct test_objid_ctx ctx = { .fp_exists = true };
	struct test_object_id_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_get_object_id(&ctx, sizeof(rsp) - 1, &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_create_or_get_object_id_invalid_handle(struct kunit *test)
{
	struct test_objid_ctx ctx = { .fp_exists = false };
	struct test_object_id_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_get_object_id(&ctx, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_FILE_CLOSED);
}

static void test_get_object_id_existing(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.fp_exists = true, .xattr_exists = true, .xattr_size = 16,
	};
	struct test_object_id_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	memset(ctx.xattr_data, 0x42, 16);
	ret = test_validate_get_object_id(&ctx, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, rsp.ObjectId[0], (u8)0x42);
}

static void test_get_object_id_no_xattr(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.fp_exists = true, .xattr_exists = false,
	};
	struct test_object_id_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_get_object_id(&ctx, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* Fallback ID is 0xAA repeated */
	KUNIT_EXPECT_EQ(test, rsp.ObjectId[0], (u8)0xAA);
}

static void test_get_object_id_xattr_wrong_size(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.fp_exists = true, .xattr_exists = true, .xattr_size = 8,
	};
	struct test_object_id_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_validate_get_object_id(&ctx, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_set_object_id_normal(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	u8 data[16];
	__le32 status;
	int ret;

	memset(data, 0x55, 16);
	ret = test_validate_set_object_id(&ctx, data, 16, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_object_id_input_too_small(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	u8 data[15];
	__le32 status;
	int ret;

	ret = test_validate_set_object_id(&ctx, data, 15, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_object_id_read_only_tree(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = false, .fp_exists = true,
	};
	u8 data[16];
	__le32 status;
	int ret;

	ret = test_validate_set_object_id(&ctx, data, 16, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_set_object_id_invalid_handle(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = false,
	};
	u8 data[16];
	__le32 status;
	int ret;

	ret = test_validate_set_object_id(&ctx, data, 16, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_FILE_CLOSED);
}

static void test_set_object_id_extended_same_logic(struct kunit *test)
{
	/* SET_OBJECT_ID_EXTENDED uses the same validation as SET_OBJECT_ID */
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	u8 data[16];
	__le32 status;
	int ret;

	memset(data, 0x77, 16);
	ret = test_validate_set_object_id(&ctx, data, 16, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_delete_object_id_normal(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	__le32 status;
	int ret;

	ret = test_validate_delete_object_id(&ctx, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_delete_object_id_not_found(struct kunit *test)
{
	/* ENOENT/ENODATA on delete is silenced (not an error) */
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = true,
		.xattr_exists = false,
	};
	__le32 status;
	int ret;

	ret = test_validate_delete_object_id(&ctx, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_delete_object_id_read_only_tree(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = false, .fp_exists = true,
	};
	__le32 status;
	int ret;

	ret = test_validate_delete_object_id(&ctx, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_delete_object_id_invalid_handle(struct kunit *test)
{
	struct test_objid_ctx ctx = {
		.writable = true, .fp_exists = false,
	};
	__le32 status;
	int ret;

	ret = test_validate_delete_object_id(&ctx, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static struct kunit_case ksmbd_fsctl_object_id_test_cases[] = {
	KUNIT_CASE(test_create_or_get_object_id_normal),
	KUNIT_CASE(test_create_or_get_object_id_buffer_too_small),
	KUNIT_CASE(test_create_or_get_object_id_invalid_handle),
	KUNIT_CASE(test_get_object_id_existing),
	KUNIT_CASE(test_get_object_id_no_xattr),
	KUNIT_CASE(test_get_object_id_xattr_wrong_size),
	KUNIT_CASE(test_set_object_id_normal),
	KUNIT_CASE(test_set_object_id_input_too_small),
	KUNIT_CASE(test_set_object_id_read_only_tree),
	KUNIT_CASE(test_set_object_id_invalid_handle),
	KUNIT_CASE(test_set_object_id_extended_same_logic),
	KUNIT_CASE(test_delete_object_id_normal),
	KUNIT_CASE(test_delete_object_id_not_found),
	KUNIT_CASE(test_delete_object_id_read_only_tree),
	KUNIT_CASE(test_delete_object_id_invalid_handle),
	{}
};

static struct kunit_suite ksmbd_fsctl_object_id_test_suite = {
	.name = "ksmbd_fsctl_object_id",
	.test_cases = ksmbd_fsctl_object_id_test_cases,
};

kunit_test_suite(ksmbd_fsctl_object_id_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL Object ID handlers");
