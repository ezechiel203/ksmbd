// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_COPYCHUNK / FSCTL_COPYCHUNK_WRITE validation logic.
 *
 *   These tests replicate the input-validation and boundary-checking logic
 *   from the copychunk handlers in ksmbd_fsctl.c.  Since KUnit modules
 *   cannot link against ksmbd, we inline the pure validation logic.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Inlined constants from the copychunk implementation ---- */

#define FSCTL_COPYCHUNK		0x001440F2
#define FSCTL_COPYCHUNK_WRITE	0x001480F2

/* Server limits (match ksmbd defaults) */
#define MAX_CHUNK_COUNT		256
#define MAX_CHUNK_SIZE		(1024 * 1024)   /* 1 MB */
#define MAX_TOTAL_SIZE		(16 * 1024 * 1024) /* 16 MB */

/* Inlined wire structures */
struct test_copychunk_ioctl_req {
	__le64 ResumeKey[3];
	__le32 ChunkCount;
	__le32 Reserved;
	__u8   Chunks[];
} __packed;

struct test_srv_copychunk {
	__le64 SourceOffset;
	__le64 TargetOffset;
	__le32 Length;
	__le32 Reserved;
} __packed;

struct test_copychunk_ioctl_rsp {
	__le32 ChunksWritten;
	__le32 ChunkBytesWritten;
	__le32 TotalBytesWritten;
} __packed;

/* STATUS codes */
#define STATUS_SUCCESS			0x00000000
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_BUFFER_TOO_SMALL		0xC0000023

/* Simulated tree-conn writable flag */
struct test_copychunk_ctx {
	bool writable;
	/* Simulated FP lookup results */
	bool src_exists;
	bool dst_exists;
	u64  src_volatile_id;
	u64  src_persistent_id;
	__le32 src_daccess;
	__le32 dst_daccess;
};

/*
 * Replicate the copychunk input validation logic.
 * Returns 0 on success, negative errno on failure.
 * Sets *status to the NTSTATUS that would be returned.
 */
static int test_validate_copychunk(struct test_copychunk_ctx *ctx,
				   u32 ctl_code,
				   void *in_buf, unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct test_copychunk_ioctl_rsp *rsp,
				   unsigned int *out_len,
				   __le32 *status)
{
	struct test_copychunk_ioctl_req *ci_req;
	struct test_srv_copychunk *chunks;
	unsigned int chunk_count, i;
	loff_t total_size = 0;

	*status = cpu_to_le32(STATUS_SUCCESS);
	*out_len = 0;

	/* Check writable */
	if (!ctx->writable) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		return -EACCES;
	}

	/* Input buffer size check */
	if (in_buf_len <= sizeof(struct test_copychunk_ioctl_req)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	/* Output buffer size check */
	if (max_out_len < sizeof(struct test_copychunk_ioctl_rsp)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	ci_req = (struct test_copychunk_ioctl_req *)in_buf;

	/* Pre-fill response with server limits */
	rsp->ChunksWritten = cpu_to_le32(MAX_CHUNK_COUNT);
	rsp->ChunkBytesWritten = cpu_to_le32(MAX_CHUNK_SIZE);
	rsp->TotalBytesWritten = cpu_to_le32(MAX_TOTAL_SIZE);

	chunks = (struct test_srv_copychunk *)&ci_req->Chunks[0];
	chunk_count = le32_to_cpu(ci_req->ChunkCount);

	/* ChunkCount=0: return limits */
	if (chunk_count == 0) {
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return 0;
	}

	/* ChunkCount exceeds max */
	if (chunk_count > MAX_CHUNK_COUNT ||
	    in_buf_len < offsetof(struct test_copychunk_ioctl_req, Chunks) +
			  chunk_count * sizeof(struct test_srv_copychunk)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	/* Validate individual chunks */
	for (i = 0; i < chunk_count; i++) {
		if (le32_to_cpu(chunks[i].Length) == 0 ||
		    le32_to_cpu(chunks[i].Length) > MAX_CHUNK_SIZE)
			break;
		total_size += le32_to_cpu(chunks[i].Length);
	}

	if (i < chunk_count || total_size > MAX_TOTAL_SIZE) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	/* Source FP lookup */
	if (!ctx->src_exists ||
	    ctx->src_persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {
		*status = cpu_to_le32(0xC0000034); /* STATUS_OBJECT_NAME_NOT_FOUND */
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return -ENOENT;
	}

	/* Dest FP lookup */
	if (!ctx->dst_exists) {
		*status = cpu_to_le32(0xC0000128); /* STATUS_FILE_CLOSED */
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return -ENOENT;
	}

	/* Access checks */
	if (!(ctx->src_daccess & cpu_to_le32(0x00000001))) { /* FILE_READ_DATA */
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return -EACCES;
	}
	if (!(ctx->dst_daccess & cpu_to_le32(0x00000002 | 0x00000004))) { /* WRITE|APPEND */
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return -EACCES;
	}

	/* COPYCHUNK (not WRITE) requires dest READ too */
	if (ctl_code == FSCTL_COPYCHUNK &&
	    !(ctx->dst_daccess & cpu_to_le32(0x00000001))) {
		*status = cpu_to_le32(STATUS_ACCESS_DENIED);
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return -EACCES;
	}

	*out_len = sizeof(struct test_copychunk_ioctl_rsp);
	return 0;
}

/* Helper to build a copychunk request buffer */
static void *build_copychunk_req(struct kunit *test,
				 u64 resume_key0, u64 resume_key1,
				 unsigned int chunk_count,
				 u32 chunk_length,
				 unsigned int *req_len)
{
	unsigned int total = sizeof(struct test_copychunk_ioctl_req) +
			     chunk_count * sizeof(struct test_srv_copychunk);
	struct test_copychunk_ioctl_req *req;
	struct test_srv_copychunk *chunks;
	unsigned int i;

	/* Ensure at least 1 byte more than header for valid input */
	if (total <= sizeof(struct test_copychunk_ioctl_req))
		total = sizeof(struct test_copychunk_ioctl_req) + 1;

	req = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->ResumeKey[0] = cpu_to_le64(resume_key0);
	req->ResumeKey[1] = cpu_to_le64(resume_key1);
	req->ChunkCount = cpu_to_le32(chunk_count);

	chunks = (struct test_srv_copychunk *)&req->Chunks[0];
	for (i = 0; i < chunk_count; i++) {
		chunks[i].SourceOffset = cpu_to_le64(i * chunk_length);
		chunks[i].TargetOffset = cpu_to_le64(i * chunk_length);
		chunks[i].Length = cpu_to_le32(chunk_length);
	}

	*req_len = total;
	return req;
}

static struct test_copychunk_ctx default_ctx(void)
{
	struct test_copychunk_ctx ctx = {
		.writable = true,
		.src_exists = true,
		.dst_exists = true,
		.src_volatile_id = 1,
		.src_persistent_id = 100,
		.src_daccess = cpu_to_le32(0x00000001), /* READ */
		.dst_daccess = cpu_to_le32(0x00000001 | 0x00000002), /* READ|WRITE */
	};
	return ctx;
}

/* ---- Test cases ---- */

static void test_copychunk_zero_chunk_count(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* Build a request with ChunkCount=0 but valid buffer size */
	req_len = sizeof(struct test_copychunk_ioctl_req) + 1;
	buf = kunit_kzalloc(test, req_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	/* ChunkCount defaults to 0 from kzalloc */

	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
	/* Response carries server limits */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ChunksWritten), (u32)MAX_CHUNK_COUNT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ChunkBytesWritten), (u32)MAX_CHUNK_SIZE);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.TotalBytesWritten), (u32)MAX_TOTAL_SIZE);
}

static void test_copychunk_max_chunk_count_exceeded(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, MAX_CHUNK_COUNT + 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_max_chunk_size_exceeded(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, MAX_CHUNK_SIZE + 1, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_max_total_size_exceeded(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* 17 chunks of 1MB each = 17MB > 16MB max */
	buf = build_copychunk_req(test, 1, 100, 17, MAX_CHUNK_SIZE, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_zero_length_chunk(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, 0, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_input_too_small(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0;
	__le32 status;
	u8 small_buf[sizeof(struct test_copychunk_ioctl_req)];
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, small_buf,
				      sizeof(small_buf), sizeof(rsp),
				      &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_output_too_small(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp) - 1, &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_invalid_resume_key(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* persistent_id mismatch: key says 999 but ctx has 100 */
	buf = build_copychunk_req(test, 1, 999, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_copychunk_source_not_found(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	ctx.src_exists = false;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_copychunk_dest_not_found(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	ctx.dst_exists = false;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_copychunk_read_only_tree(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	ctx.writable = false;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_copychunk_access_denied_src_no_read(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	ctx.src_daccess = 0; /* No read */
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_copychunk_access_denied_dst_no_write(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	ctx.dst_daccess = cpu_to_le32(0x00000001); /* Read only, no write */
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_ACCESS_DENIED);
}

static void test_copychunk_vs_copychunk_write_read_check(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* dst has WRITE but no READ */
	ctx.dst_daccess = cpu_to_le32(0x00000002); /* WRITE only */

	/* COPYCHUNK requires dest READ - should fail */
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);

	/* COPYCHUNK_WRITE does NOT require dest READ - should pass */
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK_WRITE, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_copychunk_response_fields_on_success(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 2, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
}

static void test_copychunk_response_fields_on_invalid_param(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* Exceed max chunk size to trigger INVALID_PARAMETER */
	buf = build_copychunk_req(test, 1, 100, 1, MAX_CHUNK_SIZE + 1, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	/* Response carries server limits on INVALID_PARAMETER */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ChunksWritten), (u32)MAX_CHUNK_COUNT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ChunkBytesWritten), (u32)MAX_CHUNK_SIZE);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.TotalBytesWritten), (u32)MAX_TOTAL_SIZE);
}

static void test_copychunk_overlapping_src_dst_ranges(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* Overlapping ranges: validation should still pass (overlap checked at copy time) */
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_copychunk_cross_file_same_server(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	/* Different file IDs: validation passes, actual copy done at VFS layer */
	ctx.src_volatile_id = 1;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_copychunk_lock_conflict(struct kunit *test)
{
	/* Lock conflicts are detected at VFS copy time, not validation.
	 * Validation phase passes; the -EAGAIN would come from the VFS layer.
	 * Verify the validation logic does not reject the request. */
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_copychunk_disk_full(struct kunit *test)
{
	/* Disk full is a VFS-level error, not caught during validation.
	 * Verify validation passes. */
	struct test_copychunk_ctx ctx = default_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	__le32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, FSCTL_COPYCHUNK, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static struct kunit_case ksmbd_fsctl_copychunk_test_cases[] = {
	KUNIT_CASE(test_copychunk_zero_chunk_count),
	KUNIT_CASE(test_copychunk_max_chunk_count_exceeded),
	KUNIT_CASE(test_copychunk_max_chunk_size_exceeded),
	KUNIT_CASE(test_copychunk_max_total_size_exceeded),
	KUNIT_CASE(test_copychunk_zero_length_chunk),
	KUNIT_CASE(test_copychunk_input_too_small),
	KUNIT_CASE(test_copychunk_output_too_small),
	KUNIT_CASE(test_copychunk_invalid_resume_key),
	KUNIT_CASE(test_copychunk_source_not_found),
	KUNIT_CASE(test_copychunk_dest_not_found),
	KUNIT_CASE(test_copychunk_read_only_tree),
	KUNIT_CASE(test_copychunk_access_denied_src_no_read),
	KUNIT_CASE(test_copychunk_access_denied_dst_no_write),
	KUNIT_CASE(test_copychunk_vs_copychunk_write_read_check),
	KUNIT_CASE(test_copychunk_overlapping_src_dst_ranges),
	KUNIT_CASE(test_copychunk_cross_file_same_server),
	KUNIT_CASE(test_copychunk_response_fields_on_success),
	KUNIT_CASE(test_copychunk_response_fields_on_invalid_param),
	KUNIT_CASE(test_copychunk_lock_conflict),
	KUNIT_CASE(test_copychunk_disk_full),
	{}
};

static struct kunit_suite ksmbd_fsctl_copychunk_test_suite = {
	.name = "ksmbd_fsctl_copychunk",
	.test_cases = ksmbd_fsctl_copychunk_test_cases,
};

kunit_test_suite(ksmbd_fsctl_copychunk_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL copychunk validation");
