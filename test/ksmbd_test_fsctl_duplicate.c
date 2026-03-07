// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_DUPLICATE_EXTENTS_TO_FILE and _EX validation.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_INVALID_HANDLE		0xC0000008

struct test_duplicate_extents {
	__le64 VolatileFileHandle;
	__le64 PersistentFileHandle;
	__le64 SourceFileOffset;
	__le64 TargetFileOffset;
	__le64 ByteCount;
} __packed;

struct test_duplicate_extents_ex {
	__le32 Size;
	__le32 DuplicateExtentsFlags;
	__le64 VolatileFileHandle;
	__le64 PersistentFileHandle;
	__le64 SourceFileOffset;
	__le64 TargetFileOffset;
	__le64 ByteCount;
} __packed;

struct test_dup_ctx {
	bool writable;
	bool src_exists;
	bool dst_exists;
	__le32 src_daccess;
	__le32 dst_daccess;
};

static int test_validate_duplicate(struct test_dup_ctx *ctx,
				   void *in_buf, unsigned int in_buf_len,
				   bool is_ex, __le32 *status)
{
	struct test_duplicate_extents *dup;
	loff_t src_off, dst_off, length;
	unsigned int min_size;

	*status = 0;

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	min_size = is_ex ? sizeof(struct test_duplicate_extents_ex)
			 : sizeof(struct test_duplicate_extents);
	if (in_buf_len < min_size) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	if (is_ex) {
		struct test_duplicate_extents_ex *ex = in_buf;
		/* Map to base fields for common validation */
		struct test_duplicate_extents tmp = {
			.VolatileFileHandle = ex->VolatileFileHandle,
			.PersistentFileHandle = ex->PersistentFileHandle,
			.SourceFileOffset = ex->SourceFileOffset,
			.TargetFileOffset = ex->TargetFileOffset,
			.ByteCount = ex->ByteCount,
		};
		dup = kzalloc(sizeof(*dup), GFP_KERNEL);
		if (!dup)
			return -ENOMEM;
		*dup = tmp;
	} else {
		dup = (struct test_duplicate_extents *)in_buf;
	}

	if (!ctx->src_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		if (is_ex) kfree(dup);
		return -ENOENT;
	}

	if (!ctx->dst_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		if (is_ex) kfree(dup);
		return -ENOENT;
	}

	if (!(ctx->src_daccess & cpu_to_le32(0x00000001))) { /* READ */
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		if (is_ex) kfree(dup);
		return -EACCES;
	}

	if (!(ctx->dst_daccess & cpu_to_le32(0x00000002))) { /* WRITE */
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		if (is_ex) kfree(dup);
		return -EACCES;
	}

	src_off = le64_to_cpu(dup->SourceFileOffset);
	dst_off = le64_to_cpu(dup->TargetFileOffset);
	length = le64_to_cpu(dup->ByteCount);

	if (length > 0 &&
	    (src_off + length < src_off || dst_off + length < dst_off)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		if (is_ex) kfree(dup);
		return -EINVAL;
	}

	if (is_ex) kfree(dup);
	return 0;
}

static struct test_dup_ctx default_dup_ctx(void)
{
	struct test_dup_ctx ctx = {
		.writable = true, .src_exists = true, .dst_exists = true,
		.src_daccess = cpu_to_le32(0x00000001),
		.dst_daccess = cpu_to_le32(0x00000002),
	};
	return ctx;
}

static void test_duplicate_normal(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_duplicate_input_too_small(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	u8 small[sizeof(struct test_duplicate_extents) - 1];
	__le32 status;
	int ret;

	memset(small, 0, sizeof(small));
	ret = test_validate_duplicate(&ctx, small, sizeof(small), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_duplicate_source_not_found(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ctx.src_exists = false;
	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_duplicate_dest_not_found(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ctx.dst_exists = false;
	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_duplicate_read_only_tree(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ctx.writable = false;
	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_duplicate_src_no_read(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ctx.src_daccess = 0;
	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_duplicate_dst_no_write(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ctx.dst_daccess = cpu_to_le32(0x00000001); /* READ only */
	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_duplicate_offset_overflow(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {
		.SourceFileOffset = cpu_to_le64(0xFFFFFFFFFFFFFF00ULL),
		.ByteCount = cpu_to_le64(0x200ULL),
	};
	__le32 status;
	int ret;

	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_duplicate_cross_device(struct kunit *test)
{
	/* Cross-device is detected at VFS level; validation passes */
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_duplicate_disk_full(struct kunit *test)
{
	/* ENOSPC at VFS level; validation passes */
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents dup = {};
	__le32 status;
	int ret;

	ret = test_validate_duplicate(&ctx, &dup, sizeof(dup), false, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_duplicate_ex_atomic_flag(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	struct test_duplicate_extents_ex dup_ex = {
		.Size = cpu_to_le32(sizeof(struct test_duplicate_extents_ex)),
		.DuplicateExtentsFlags = cpu_to_le32(0x00000001), /* ATOMIC */
	};
	__le32 status;
	int ret;

	ret = test_validate_duplicate(&ctx, &dup_ex, sizeof(dup_ex), true, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_duplicate_ex_input_too_small(struct kunit *test)
{
	struct test_dup_ctx ctx = default_dup_ctx();
	u8 small[sizeof(struct test_duplicate_extents_ex) - 1];
	__le32 status;
	int ret;

	memset(small, 0, sizeof(small));
	ret = test_validate_duplicate(&ctx, small, sizeof(small), true, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static struct kunit_case ksmbd_fsctl_duplicate_test_cases[] = {
	KUNIT_CASE(test_duplicate_normal),
	KUNIT_CASE(test_duplicate_input_too_small),
	KUNIT_CASE(test_duplicate_source_not_found),
	KUNIT_CASE(test_duplicate_dest_not_found),
	KUNIT_CASE(test_duplicate_read_only_tree),
	KUNIT_CASE(test_duplicate_src_no_read),
	KUNIT_CASE(test_duplicate_dst_no_write),
	KUNIT_CASE(test_duplicate_offset_overflow),
	KUNIT_CASE(test_duplicate_cross_device),
	KUNIT_CASE(test_duplicate_disk_full),
	KUNIT_CASE(test_duplicate_ex_atomic_flag),
	KUNIT_CASE(test_duplicate_ex_input_too_small),
	{}
};

static struct kunit_suite ksmbd_fsctl_duplicate_test_suite = {
	.name = "ksmbd_fsctl_duplicate",
	.test_cases = ksmbd_fsctl_duplicate_test_cases,
};

kunit_test_suite(ksmbd_fsctl_duplicate_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL duplicate extents validation");
