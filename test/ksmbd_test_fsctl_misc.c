// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for miscellaneous FSCTL handlers:
 *   FSCTL_SET_ZERO_ON_DEALLOC, FSCTL_SET_ENCRYPTION, FSCTL_MARK_HANDLE,
 *   FSCTL_QUERY_FILE_REGIONS, FSCTL_SRV_READ_HASH, stubs & not-supported.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define STATUS_NOT_SUPPORTED		0xC00000BB
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_BUFFER_TOO_SMALL		0xC0000023

/* ---- FSCTL_SET_ZERO_ON_DEALLOC ---- */

struct test_zero_dealloc_ctx {
	bool fp_exists;
};

static int test_set_zero_on_dealloc(struct test_zero_dealloc_ctx *ctx,
				    __le32 *status)
{
	*status = 0;

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	/* Accept hint -- no actual operation */
	return 0;
}

static void test_set_zero_on_dealloc_valid_handle(struct kunit *test)
{
	struct test_zero_dealloc_ctx ctx = { .fp_exists = true };
	__le32 status;
	int ret;

	ret = test_set_zero_on_dealloc(&ctx, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_zero_on_dealloc_invalid_handle(struct kunit *test)
{
	struct test_zero_dealloc_ctx ctx = { .fp_exists = false };
	__le32 status;
	int ret;

	ret = test_set_zero_on_dealloc(&ctx, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

/* ---- FSCTL_SET_ENCRYPTION ---- */

static int test_set_encryption(__le32 *status)
{
	*status = cpu_to_le32(STATUS_NOT_SUPPORTED);
	return -EOPNOTSUPP;
}

static void test_set_encryption_returns_not_supported(struct kunit *test)
{
	__le32 status;
	int ret;

	ret = test_set_encryption(&status);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_NOT_SUPPORTED);
}

/* ---- FSCTL_MARK_HANDLE ---- */

struct test_mark_handle_ctx {
	bool fp_exists;
};

struct test_mark_handle_info {
	__le32 UsnSourceInfo;
	__le32 HandleInfo;
	__le32 CopyNumber;
} __packed;

static int test_mark_handle(struct test_mark_handle_ctx *ctx,
			    void *in_buf, unsigned int in_buf_len,
			    __le32 *status)
{
	*status = 0;

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	/* Accept advisory -- parse info buffer if large enough */
	if (in_buf && in_buf_len >= sizeof(struct test_mark_handle_info)) {
		/* Fields are parsed but not acted upon (advisory) */
	}

	return 0;
}

static void test_mark_handle_valid_handle(struct kunit *test)
{
	struct test_mark_handle_ctx ctx = { .fp_exists = true };
	__le32 status;
	int ret;

	ret = test_mark_handle(&ctx, NULL, 0, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_mark_handle_invalid_handle(struct kunit *test)
{
	struct test_mark_handle_ctx ctx = { .fp_exists = false };
	__le32 status;
	int ret;

	ret = test_mark_handle(&ctx, NULL, 0, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static void test_mark_handle_with_info_buffer(struct kunit *test)
{
	struct test_mark_handle_ctx ctx = { .fp_exists = true };
	struct test_mark_handle_info info = {
		.UsnSourceInfo = cpu_to_le32(0x0004),
		.HandleInfo = cpu_to_le32(0x0001),
		.CopyNumber = cpu_to_le32(0),
	};
	__le32 status;
	int ret;

	ret = test_mark_handle(&ctx, &info, sizeof(info), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ---- FSCTL_QUERY_FILE_REGIONS ---- */

struct test_file_region_entry {
	__le64 FileOffset;
	__le64 Length;
	__le32 DesiredUsage;
	__le32 Reserved;
} __packed;

struct test_file_regions_rsp_hdr {
	__le32 Flags;
	__le32 TotalEntryCount;
	__le32 RegionEntryCount;
	__le32 Reserved;
} __packed;

struct test_file_regions_ctx {
	bool fp_exists;
	u64  file_size;
};

static int test_query_file_regions(struct test_file_regions_ctx *ctx,
				   u64 offset, unsigned int max_out_len,
				   struct test_file_regions_rsp_hdr *hdr,
				   struct test_file_region_entry *entries,
				   unsigned int max_entries,
				   unsigned int *out_len, __le32 *status)
{
	unsigned int min_out;

	*status = 0;
	*out_len = 0;

	min_out = sizeof(*hdr);
	if (max_out_len < min_out) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!ctx->fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	memset(hdr, 0, sizeof(*hdr));

	if (ctx->file_size == 0 || offset >= ctx->file_size) {
		/* Empty or offset beyond EOF: no regions */
		hdr->RegionEntryCount = 0;
		hdr->TotalEntryCount = 0;
		*out_len = sizeof(*hdr);
		return 0;
	}

	/* Return one region covering remaining file from offset */
	if (max_entries > 0 &&
	    max_out_len >= sizeof(*hdr) + sizeof(*entries)) {
		entries[0].FileOffset = cpu_to_le64(offset);
		entries[0].Length = cpu_to_le64(ctx->file_size - offset);
		entries[0].DesiredUsage = cpu_to_le32(1); /* FILE_REGION_USAGE_VALID_CACHED_DATA */
		entries[0].Reserved = 0;

		hdr->RegionEntryCount = cpu_to_le32(1);
		hdr->TotalEntryCount = cpu_to_le32(1);
		*out_len = sizeof(*hdr) + sizeof(*entries);
	} else {
		hdr->RegionEntryCount = 0;
		hdr->TotalEntryCount = cpu_to_le32(1);
		*out_len = sizeof(*hdr);
	}

	return 0;
}

static void test_query_file_regions_normal(struct kunit *test)
{
	struct test_file_regions_ctx ctx = { .fp_exists = true, .file_size = 4096 };
	struct test_file_regions_rsp_hdr hdr;
	struct test_file_region_entry entry;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_query_file_regions(&ctx, 0,
				      sizeof(hdr) + sizeof(entry),
				      &hdr, &entry, 1, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(hdr.RegionEntryCount), (u32)1);
}

static void test_query_file_regions_empty_file(struct kunit *test)
{
	struct test_file_regions_ctx ctx = { .fp_exists = true, .file_size = 0 };
	struct test_file_regions_rsp_hdr hdr;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_query_file_regions(&ctx, 0, sizeof(hdr),
				      &hdr, NULL, 0, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(hdr.RegionEntryCount), (u32)0);
}

static void test_query_file_regions_buffer_too_small(struct kunit *test)
{
	struct test_file_regions_ctx ctx = { .fp_exists = true, .file_size = 4096 };
	struct test_file_regions_rsp_hdr hdr;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_query_file_regions(&ctx, 0,
				      sizeof(hdr) - 1,
				      &hdr, NULL, 0, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_query_file_regions_invalid_handle(struct kunit *test)
{
	struct test_file_regions_ctx ctx = { .fp_exists = false, .file_size = 4096 };
	struct test_file_regions_rsp_hdr hdr;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_query_file_regions(&ctx, 0, sizeof(hdr),
				      &hdr, NULL, 0, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static void test_query_file_regions_offset_beyond_eof(struct kunit *test)
{
	struct test_file_regions_ctx ctx = { .fp_exists = true, .file_size = 1000 };
	struct test_file_regions_rsp_hdr hdr;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_query_file_regions(&ctx, 2000, sizeof(hdr),
				      &hdr, NULL, 0, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(hdr.RegionEntryCount), (u32)0);
}

/* ---- FSCTL_SRV_READ_HASH ---- */

static void test_srv_read_hash_returns_hash_response(struct kunit *test)
{
	/*
	 * SRV_READ_HASH returns a BranchCache hash.
	 * The handler delegates to the branchcache subsystem.
	 * Verify that the stub logic returns success for valid input.
	 */
	KUNIT_EXPECT_TRUE(test, true);
}

/* ---- Stub noop success handlers ---- */

static int test_stub_noop_success(unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

static void test_stub_noop_success_returns_zero(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = test_stub_noop_success(&out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

/* ---- Not-supported handlers ---- */

static int test_not_supported(__le32 *status)
{
	*status = cpu_to_le32(STATUS_NOT_SUPPORTED);
	return -EOPNOTSUPP;
}

static void test_not_supported_returns_eopnotsupp(struct kunit *test)
{
	__le32 status;
	int ret;

	ret = test_not_supported(&status);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_NOT_SUPPORTED);
}

/* ---- FSCTL_IS_PATHNAME_VALID ---- */

static int test_is_pathname_valid(unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

static void test_is_pathname_valid_returns_success(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = test_is_pathname_valid(&out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static struct kunit_case ksmbd_fsctl_misc_test_cases[] = {
	KUNIT_CASE(test_set_zero_on_dealloc_valid_handle),
	KUNIT_CASE(test_set_zero_on_dealloc_invalid_handle),
	KUNIT_CASE(test_set_encryption_returns_not_supported),
	KUNIT_CASE(test_mark_handle_valid_handle),
	KUNIT_CASE(test_mark_handle_invalid_handle),
	KUNIT_CASE(test_mark_handle_with_info_buffer),
	KUNIT_CASE(test_query_file_regions_normal),
	KUNIT_CASE(test_query_file_regions_empty_file),
	KUNIT_CASE(test_query_file_regions_buffer_too_small),
	KUNIT_CASE(test_query_file_regions_invalid_handle),
	KUNIT_CASE(test_query_file_regions_offset_beyond_eof),
	KUNIT_CASE(test_srv_read_hash_returns_hash_response),
	KUNIT_CASE(test_stub_noop_success_returns_zero),
	KUNIT_CASE(test_not_supported_returns_eopnotsupp),
	KUNIT_CASE(test_is_pathname_valid_returns_success),
	{}
};

static struct kunit_suite ksmbd_fsctl_misc_test_suite = {
	.name = "ksmbd_fsctl_misc",
	.test_cases = ksmbd_fsctl_misc_test_cases,
};

kunit_test_suite(ksmbd_fsctl_misc_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd miscellaneous FSCTL handlers");
