// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
 *   FSCTL_QUERY_ALLOCATED_RANGES validation logic.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* Wire structures */
struct test_file_sparse {
	__u8 SetSparse;
} __packed;

struct test_file_zero_data_information {
	__le64 FileOffset;
	__le64 BeyondFinalZero;
} __packed;

struct test_file_allocated_range_buffer {
	__le64 file_offset;
	__le64 length;
} __packed;

#define STATUS_SUCCESS			0x00000000
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_BUFFER_OVERFLOW		0x80000005
#define STATUS_INVALID_HANDLE		0xC0000008

#define ATTR_SPARSE_FILE_LE	cpu_to_le32(0x00000200)
#define ATTR_DIRECTORY_LE	cpu_to_le32(0x00000010)

/* Simulated context for sparse operations */
struct test_sparse_ctx {
	bool writable;
	bool fp_exists;
	bool is_directory;
	__le32 fattr;
	__le32 daccess;
};

/* ---- SET_SPARSE validation ---- */
static int test_validate_set_sparse(struct test_sparse_ctx *ctx,
				    void *in_buf, unsigned int in_buf_len,
				    __le32 *status)
{
	struct test_file_sparse *sparse;
	bool set_sparse = true;

	*status = cpu_to_le32(STATUS_SUCCESS);

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	if (ctx->is_directory) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	/* MS-FSCC 2.3.64: default to TRUE when buffer too small */
	if (in_buf_len >= sizeof(struct test_file_sparse)) {
		sparse = (struct test_file_sparse *)in_buf;
		set_sparse = sparse->SetSparse ? true : false;
	}

	if (set_sparse)
		ctx->fattr |= ATTR_SPARSE_FILE_LE;
	else
		ctx->fattr &= ~ATTR_SPARSE_FILE_LE;

	return 0;
}

/* ---- SET_ZERO_DATA validation ---- */
static int test_validate_set_zero_data(struct test_sparse_ctx *ctx,
				       void *in_buf, unsigned int in_buf_len,
				       __le32 *status)
{
	struct test_file_zero_data_information *zd;
	loff_t off, bfz, len;

	*status = cpu_to_le32(STATUS_SUCCESS);

	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	if (in_buf_len < sizeof(*zd)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	zd = (struct test_file_zero_data_information *)in_buf;
	off = le64_to_cpu(zd->FileOffset);
	bfz = le64_to_cpu(zd->BeyondFinalZero);

	if (off < 0 || bfz < 0 || off > bfz) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	len = bfz - off;
	if (len == 0)
		return 0; /* Noop */

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	return 0;
}

/* ---- QUERY_ALLOCATED_RANGES validation ---- */
static int test_validate_query_allocated(void *in_buf, unsigned int in_buf_len,
					 unsigned int max_out_len,
					 bool fp_exists,
					 __le32 *status)
{
	struct test_file_allocated_range_buffer *qar;
	loff_t start, length;
	unsigned int in_count;

	*status = cpu_to_le32(STATUS_SUCCESS);

	if (in_buf_len < sizeof(*qar)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	qar = (struct test_file_allocated_range_buffer *)in_buf;
	start = le64_to_cpu(qar->file_offset);
	length = le64_to_cpu(qar->length);

	if (start < 0 || length < 0) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	in_count = max_out_len / sizeof(*qar);
	if (in_count == 0) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	return 0;
}

/* ---- Test cases: SET_SPARSE ---- */

static void test_set_sparse_enable(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
		.fattr = 0, .is_directory = false,
	};
	struct test_file_sparse buf = { .SetSparse = 1 };
	__le32 status;
	int ret;

	ret = test_validate_set_sparse(&ctx, &buf, sizeof(buf), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, !!(ctx.fattr & ATTR_SPARSE_FILE_LE));
}

static void test_set_sparse_disable(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
		.fattr = ATTR_SPARSE_FILE_LE, .is_directory = false,
	};
	struct test_file_sparse buf = { .SetSparse = 0 };
	__le32 status;
	int ret;

	ret = test_validate_set_sparse(&ctx, &buf, sizeof(buf), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, !!(ctx.fattr & ATTR_SPARSE_FILE_LE));
}

static void test_set_sparse_no_buffer(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
		.fattr = 0, .is_directory = false,
	};
	__le32 status;
	int ret;

	/* Empty buffer defaults to sparse=TRUE */
	ret = test_validate_set_sparse(&ctx, NULL, 0, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, !!(ctx.fattr & ATTR_SPARSE_FILE_LE));
}

/*
 * Implementation note: ksmbd rejects SET_SPARSE on directories because Linux
 * filesystems don't support sparse directories. Windows/NTFS allows this.
 * This is an intentional implementation-specific divergence from MS-FSCC.
 */
static void test_set_sparse_directory_rejected(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
		.fattr = ATTR_DIRECTORY_LE, .is_directory = true,
	};
	struct test_file_sparse buf = { .SetSparse = 1 };
	__le32 status;
	int ret;

	ret = test_validate_set_sparse(&ctx, &buf, sizeof(buf), &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_sparse_access_denied(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = false, .fp_exists = true,
		.fattr = 0, .is_directory = false,
	};
	struct test_file_sparse buf = { .SetSparse = 1 };
	__le32 status;
	int ret;

	ret = test_validate_set_sparse(&ctx, &buf, sizeof(buf), &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_set_sparse_persist_dos_attrs(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
		.fattr = 0, .is_directory = false,
	};
	struct test_file_sparse buf = { .SetSparse = 1 };
	__le32 status;
	__le32 old_fattr;
	int ret;

	old_fattr = ctx.fattr;
	ret = test_validate_set_sparse(&ctx, &buf, sizeof(buf), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* fattr changed from 0 to SPARSE */
	KUNIT_EXPECT_NE(test, ctx.fattr, old_fattr);
}

/* ---- Test cases: QUERY_ALLOCATED_RANGES ---- */

static void test_query_allocated_ranges_normal(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) * 10, true, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_query_allocated_ranges_empty_file(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(0),
	};
	__le32 status;
	int ret;

	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) * 10, true, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_query_allocated_ranges_negative_offset(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar;
	__le32 status;
	int ret;

	/* -1 in signed form */
	qar.file_offset = cpu_to_le64((u64)-1LL);
	qar.length = cpu_to_le64(4096);

	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) * 10, true, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_query_allocated_ranges_zero_length(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(100),
		.length = cpu_to_le64(0),
	};
	__le32 status;
	int ret;

	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) * 10, true, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_query_allocated_ranges_buffer_overflow(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(1024 * 1024),
	};
	__le32 status;
	int ret;

	/* Very small output buffer -- can still fit one entry */
	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar), true, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_query_allocated_ranges_buffer_too_small(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	/* Output cannot hold even one entry */
	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) - 1, true, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_query_allocated_ranges_no_read_access(struct kunit *test)
{
	/* Access checks are done at a higher layer; validation passes */
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) * 10, true, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_query_allocated_ranges_invalid_handle(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_query_allocated(&qar, sizeof(qar),
					    sizeof(qar) * 10, false, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

/* ---- Test cases: SET_ZERO_DATA ---- */

static void test_set_zero_data_normal(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_zero_data_zero_length(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(100),
		.BeyondFinalZero = cpu_to_le64(100),
	};
	__le32 status;
	int ret;

	/* Noop: offset == beyond */
	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_zero_data_negative_offset(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	struct test_file_zero_data_information zd;
	__le32 status;
	int ret;

	zd.FileOffset = cpu_to_le64((u64)-1LL);
	zd.BeyondFinalZero = cpu_to_le64(4096);

	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_zero_data_offset_gt_beyond(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(4096),
		.BeyondFinalZero = cpu_to_le64(100),
	};
	__le32 status;
	int ret;

	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_zero_data_buffer_too_small(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	u8 small_buf[sizeof(struct test_file_zero_data_information) - 1];
	__le32 status;
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_set_zero_data(&ctx, small_buf, sizeof(small_buf),
					  &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_zero_data_read_only_tree(struct kunit *test)
{
	struct test_sparse_ctx ctx = {
		.writable = false, .fp_exists = true,
	};
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_set_zero_data_no_write_data(struct kunit *test)
{
	/* Write-access check is at handle level, not in this validation.
	 * The validation path checks tree-conn writable only. */
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_zero_data_lock_conflict(struct kunit *test)
{
	/* Lock conflict is a VFS-level error, not caught in validation */
	struct test_sparse_ctx ctx = {
		.writable = true, .fp_exists = true,
	};
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	__le32 status;
	int ret;

	ret = test_validate_set_zero_data(&ctx, &zd, sizeof(zd), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static struct kunit_case ksmbd_fsctl_sparse_test_cases[] = {
	KUNIT_CASE(test_set_sparse_enable),
	KUNIT_CASE(test_set_sparse_disable),
	KUNIT_CASE(test_set_sparse_no_buffer),
	KUNIT_CASE(test_set_sparse_directory_rejected),
	KUNIT_CASE(test_set_sparse_access_denied),
	KUNIT_CASE(test_set_sparse_persist_dos_attrs),
	KUNIT_CASE(test_query_allocated_ranges_normal),
	KUNIT_CASE(test_query_allocated_ranges_empty_file),
	KUNIT_CASE(test_query_allocated_ranges_negative_offset),
	KUNIT_CASE(test_query_allocated_ranges_zero_length),
	KUNIT_CASE(test_query_allocated_ranges_buffer_overflow),
	KUNIT_CASE(test_query_allocated_ranges_buffer_too_small),
	KUNIT_CASE(test_query_allocated_ranges_no_read_access),
	KUNIT_CASE(test_query_allocated_ranges_invalid_handle),
	KUNIT_CASE(test_set_zero_data_normal),
	KUNIT_CASE(test_set_zero_data_zero_length),
	KUNIT_CASE(test_set_zero_data_negative_offset),
	KUNIT_CASE(test_set_zero_data_offset_gt_beyond),
	KUNIT_CASE(test_set_zero_data_buffer_too_small),
	KUNIT_CASE(test_set_zero_data_read_only_tree),
	KUNIT_CASE(test_set_zero_data_no_write_data),
	KUNIT_CASE(test_set_zero_data_lock_conflict),
	{}
};

static struct kunit_suite ksmbd_fsctl_sparse_test_suite = {
	.name = "ksmbd_fsctl_sparse",
	.test_cases = ksmbd_fsctl_sparse_test_cases,
};

kunit_test_suite(ksmbd_fsctl_sparse_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL sparse/zero-data validation");
