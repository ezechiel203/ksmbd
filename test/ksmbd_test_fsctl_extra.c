// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd_fsctl_extra.c — the extra FSCTL handlers:
 *     - FSCTL_FILE_LEVEL_TRIM input validation
 *     - FSCTL_COPYCHUNK / FSCTL_COPYCHUNK_WRITE range validation
 *     - FSCTL_SET_ZERO_DATA range arithmetic
 *     - FSCTL_QUERY_ALLOCATED_RANGES output buffer sizing
 *     - FSCTL_PIPE_WAIT timeout validation
 *     - FSCTL_DUPLICATE_EXTENTS_TO_FILE input validation
 *     - Extra handler registration/init/exit
 *
 *   Since KUnit modules cannot link against ksmbd, we inline the pure
 *   validation logic from ksmbd_fsctl_extra.c and test it in isolation.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>

/* ========================================================================
 * Inlined wire structures (matching production smb2pdu.h definitions)
 * ======================================================================== */

struct test_file_level_trim_range {
	__le64	offset;
	__le64	length;
} __packed;

struct test_file_level_trim {
	__le32	key;
	__le32	num_ranges;
	struct test_file_level_trim_range ranges[];
} __packed;

struct test_file_zero_data_information {
	__le64	FileOffset;
	__le64	BeyondFinalZero;
} __packed;

struct test_file_allocated_range_buffer {
	__le64	file_offset;
	__le64	length;
} __packed;

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

struct test_duplicate_extents_to_file {
	__u64  PersistentFileHandle;
	__u64  VolatileFileHandle;
	__le64 SourceFileOffset;
	__le64 TargetFileOffset;
	__le64 ByteCount;
} __packed;

struct test_fsctl_pipe_wait_req {
	__le64	Timeout;
	__u8	TimeoutSpecified;
	__u8	Padding;
	__le16	NameLength;
	/* __u8 Name[] follows */
} __packed;

/* ========================================================================
 * Inlined STATUS codes (host byte order for easier comparison)
 * ======================================================================== */

#define STATUS_SUCCESS			0x00000000
#define STATUS_BUFFER_OVERFLOW		0x80000005
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_INVALID_PARAMETER	0xC000000D
#define STATUS_ACCESS_DENIED		0xC0000022
#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_OBJECT_NAME_NOT_FOUND	0xC0000034
#define STATUS_IO_TIMEOUT		0xC00000B5

/* ========================================================================
 * Inlined server limits (matching ksmbd defaults from smb_common.c)
 * ======================================================================== */

#define MAX_CHUNK_COUNT		256
#define MAX_CHUNK_SIZE		(1024 * 1024)		/* 1 MB */
#define MAX_TOTAL_SIZE		(16 * 1024 * 1024)	/* 16 MB */

/* ========================================================================
 * Inlined validation logic from ksmbd_fsctl_extra.c
 *
 * These replicate the pure input-validation paths (prior to VFS calls)
 * so we can test them without requiring ksmbd module linkage.
 * ======================================================================== */

/* --- FILE_LEVEL_TRIM validation --- */

static int test_validate_file_level_trim(bool writable,
					 void *in_buf,
					 unsigned int in_buf_len,
					 bool fp_exists,
					 unsigned int *out_len,
					 u32 *status)
{
	struct test_file_level_trim *trim;
	unsigned int num_ranges, i;

	*status = STATUS_SUCCESS;
	*out_len = 0;

	if (!writable) {
		*status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct test_file_level_trim)) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	trim = (struct test_file_level_trim *)in_buf;
	num_ranges = le32_to_cpu(trim->num_ranges);

	/* Validate that all range entries fit in the input buffer */
	if (num_ranges > (in_buf_len - sizeof(struct test_file_level_trim)) /
			  sizeof(struct test_file_level_trim_range)) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (num_ranges == 0) {
		*out_len = 0;
		return 0;
	}

	if (!fp_exists) {
		*status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/* Validate individual ranges (skip VFS calls) */
	for (i = 0; i < num_ranges; i++) {
		loff_t off = le64_to_cpu(trim->ranges[i].offset);
		loff_t len = le64_to_cpu(trim->ranges[i].length);

		if (off < 0 || len <= 0)
			continue; /* Production code skips invalid ranges */
	}

	*out_len = 0;
	return 0;
}

/* --- SET_ZERO_DATA validation --- */

static int test_validate_set_zero_data(bool writable,
				       void *in_buf,
				       unsigned int in_buf_len,
				       bool fp_exists,
				       unsigned int *out_len,
				       u32 *status)
{
	struct test_file_zero_data_information *zd;
	loff_t off, bfz, len;

	*status = STATUS_SUCCESS;
	*out_len = 0;

	if (!writable) {
		*status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct test_file_zero_data_information)) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	zd = (struct test_file_zero_data_information *)in_buf;
	off = le64_to_cpu(zd->FileOffset);
	bfz = le64_to_cpu(zd->BeyondFinalZero);

	if (off < 0 || bfz < 0 || off > bfz) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	len = bfz - off;
	if (len == 0) {
		*out_len = 0;
		return 0;
	}

	if (!fp_exists) {
		*status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/* VFS call would happen here */
	*out_len = 0;
	return 0;
}

/* --- QUERY_ALLOCATED_RANGES validation --- */

static int test_validate_query_allocated_ranges(void *in_buf,
						unsigned int in_buf_len,
						unsigned int max_out_len,
						bool fp_exists,
						unsigned int *out_len,
						u32 *status)
{
	struct test_file_allocated_range_buffer *qar_req;
	loff_t start, length;
	unsigned int in_count;

	*status = STATUS_SUCCESS;
	*out_len = 0;

	if (in_buf_len < sizeof(struct test_file_allocated_range_buffer)) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	qar_req = (struct test_file_allocated_range_buffer *)in_buf;
	start = le64_to_cpu(qar_req->file_offset);
	length = le64_to_cpu(qar_req->length);

	if (start < 0 || length < 0) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	in_count = max_out_len /
		   sizeof(struct test_file_allocated_range_buffer);
	if (in_count == 0) {
		*status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	if (!fp_exists) {
		*status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	return 0;
}

/* --- COPYCHUNK validation (combined read+write variant) --- */

struct test_copychunk_ctx {
	bool writable;
	bool src_exists;
	bool dst_exists;
	u64  src_persistent_id;
	bool check_dst_read_access;
	__le32 dst_daccess;
};

static int test_validate_copychunk(struct test_copychunk_ctx *ctx,
				   void *in_buf,
				   unsigned int in_buf_len,
				   unsigned int max_out_len,
				   struct test_copychunk_ioctl_rsp *rsp,
				   unsigned int *out_len,
				   u32 *status)
{
	struct test_copychunk_ioctl_req *ci_req;
	struct test_srv_copychunk *chunks;
	unsigned int chunk_count, i;
	loff_t total_size = 0;

	*status = STATUS_SUCCESS;
	*out_len = 0;

	if (!ctx->writable) {
		*status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len <= sizeof(struct test_copychunk_ioctl_req)) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (max_out_len < sizeof(struct test_copychunk_ioctl_rsp)) {
		*status = STATUS_BUFFER_TOO_SMALL;
		return -ENOSPC;
	}

	ci_req = (struct test_copychunk_ioctl_req *)in_buf;

	/* Initialize response to zero */
	rsp->ChunksWritten = 0;
	rsp->ChunkBytesWritten = 0;
	rsp->TotalBytesWritten = 0;

	chunks = (struct test_srv_copychunk *)&ci_req->Chunks[0];
	chunk_count = le32_to_cpu(ci_req->ChunkCount);

	if (!chunk_count) {
		*out_len = sizeof(struct test_copychunk_ioctl_rsp);
		return 0;
	}

	/* MS-FSCC 2.3.12: reject when ChunkCount EXCEEDS max */
	if (chunk_count > MAX_CHUNK_COUNT ||
	    in_buf_len < offsetof(struct test_copychunk_ioctl_req, Chunks) +
			  chunk_count * sizeof(struct test_srv_copychunk)) {
		rsp->ChunksWritten = cpu_to_le32(MAX_CHUNK_COUNT);
		rsp->ChunkBytesWritten = cpu_to_le32(MAX_CHUNK_SIZE);
		rsp->TotalBytesWritten = cpu_to_le32(MAX_TOTAL_SIZE);
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	for (i = 0; i < chunk_count; i++) {
		if (!le32_to_cpu(chunks[i].Length) ||
		    le32_to_cpu(chunks[i].Length) > MAX_CHUNK_SIZE)
			break;
		total_size += le32_to_cpu(chunks[i].Length);
	}

	if (i < chunk_count || total_size > MAX_TOTAL_SIZE) {
		rsp->ChunksWritten = cpu_to_le32(MAX_CHUNK_COUNT);
		rsp->ChunkBytesWritten = cpu_to_le32(MAX_CHUNK_SIZE);
		rsp->TotalBytesWritten = cpu_to_le32(MAX_TOTAL_SIZE);
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	/* Source FP lookup */
	if (!ctx->src_exists ||
	    ctx->src_persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {
		*status = STATUS_OBJECT_NAME_NOT_FOUND;
		return -ENOENT;
	}

	/* Dest FP lookup */
	if (!ctx->dst_exists) {
		*status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	/* check_dst_read_access (COPYCHUNK vs COPYCHUNK_WRITE) */
	if (ctx->check_dst_read_access &&
	    !(ctx->dst_daccess & cpu_to_le32(0x00000001 | 0x80000000))) {
		*status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	*out_len = sizeof(struct test_copychunk_ioctl_rsp);
	return 0;
}

/* --- DUPLICATE_EXTENTS_TO_FILE validation --- */

static int test_validate_duplicate_extents(bool writable,
					   void *in_buf,
					   unsigned int in_buf_len,
					   bool src_exists,
					   bool dst_exists,
					   unsigned int *out_len,
					   u32 *status)
{
	*status = STATUS_SUCCESS;
	*out_len = 0;

	if (!writable) {
		*status = STATUS_ACCESS_DENIED;
		return -EACCES;
	}

	if (in_buf_len < sizeof(struct test_duplicate_extents_to_file)) {
		*status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	if (!src_exists) {
		*status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	if (!dst_exists) {
		*status = STATUS_INVALID_HANDLE;
		return -ENOENT;
	}

	return 0;
}

/* --- PIPE_WAIT validation --- */

static int test_validate_pipe_wait(void *in_buf,
				   unsigned int in_buf_len,
				   bool pipe_open,
				   unsigned int *out_len,
				   u32 *status,
				   unsigned int *wait_ms_out)
{
	struct test_fsctl_pipe_wait_req *req;
	s64 timeout_100ns;
	unsigned int wait_ms;

	*status = STATUS_SUCCESS;
	*out_len = 0;

	if (in_buf_len < sizeof(*req)) {
		/* No valid request structure; succeed unconditionally */
		return 0;
	}

	req = (struct test_fsctl_pipe_wait_req *)in_buf;
	timeout_100ns = (s64)le64_to_cpu(req->Timeout);

	if (!req->TimeoutSpecified) {
		wait_ms = 0xffffffffu;
	} else if (timeout_100ns == 0) {
		wait_ms = 0;
	} else {
		s64 computed = timeout_100ns / 10000LL;

		wait_ms = (unsigned int)computed;
		if (wait_ms == 0)
			wait_ms = 1;
	}

	if (wait_ms_out)
		*wait_ms_out = wait_ms;

	if (pipe_open)
		return 0;

	*status = STATUS_IO_TIMEOUT;
	return -ETIMEDOUT;
}

/* --- Extra handlers registration simulation --- */

#define FSCTL_FILE_LEVEL_TRIM		0x00098208
#define FSCTL_PIPE_WAIT			0x00110018
#define FSCTL_SET_ZERO_DATA		0x000980C8
#define FSCTL_QUERY_ALLOCATED_RANGES	0x000940CF
#define FSCTL_COPYCHUNK			0x001440F2
#define FSCTL_COPYCHUNK_WRITE		0x001480F2
#define FSCTL_DUPLICATE_EXTENTS_TO_FILE	0x00098344

struct test_fsctl_handler_entry {
	u32 ctl_code;
	bool registered;
};

#define MAX_EXTRA_HANDLERS 8

struct test_dispatch_table {
	struct test_fsctl_handler_entry entries[MAX_EXTRA_HANDLERS];
	unsigned int count;
};

static int test_register_handler(struct test_dispatch_table *tbl, u32 code)
{
	unsigned int i;

	for (i = 0; i < tbl->count; i++) {
		if (tbl->entries[i].ctl_code == code)
			return -EEXIST;
	}
	if (tbl->count >= MAX_EXTRA_HANDLERS)
		return -ENOMEM;

	tbl->entries[tbl->count].ctl_code = code;
	tbl->entries[tbl->count].registered = true;
	tbl->count++;
	return 0;
}

static void test_unregister_handler(struct test_dispatch_table *tbl, u32 code)
{
	unsigned int i;

	for (i = 0; i < tbl->count; i++) {
		if (tbl->entries[i].ctl_code == code) {
			tbl->entries[i].registered = false;
			return;
		}
	}
}

static int test_dispatch(struct test_dispatch_table *tbl, u32 code)
{
	unsigned int i;

	for (i = 0; i < tbl->count; i++) {
		if (tbl->entries[i].ctl_code == code &&
		    tbl->entries[i].registered)
			return 0;
	}
	return -EOPNOTSUPP;
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

	if (total <= sizeof(struct test_copychunk_ioctl_req))
		total = sizeof(struct test_copychunk_ioctl_req) + 1;

	req = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->ResumeKey[0] = cpu_to_le64(resume_key0);
	req->ResumeKey[1] = cpu_to_le64(resume_key1);
	req->ChunkCount = cpu_to_le32(chunk_count);

	chunks = (struct test_srv_copychunk *)&req->Chunks[0];
	for (i = 0; i < chunk_count; i++) {
		chunks[i].SourceOffset = cpu_to_le64((u64)i * chunk_length);
		chunks[i].TargetOffset = cpu_to_le64((u64)i * chunk_length);
		chunks[i].Length = cpu_to_le32(chunk_length);
	}

	*req_len = total;
	return req;
}

static struct test_copychunk_ctx default_copychunk_ctx(void)
{
	struct test_copychunk_ctx ctx = {
		.writable = true,
		.src_exists = true,
		.dst_exists = true,
		.src_persistent_id = 100,
		.check_dst_read_access = true,
		.dst_daccess = cpu_to_le32(0x00000001 | 0x00000002),
	};
	return ctx;
}

/* ========================================================================
 * Test cases: FILE_LEVEL_TRIM
 * ======================================================================== */

static void test_trim_normal(struct kunit *test)
{
	unsigned int total = sizeof(struct test_file_level_trim) +
			     2 * sizeof(struct test_file_level_trim_range);
	struct test_file_level_trim *buf;
	unsigned int out_len = 99;
	u32 status;
	int ret;

	buf = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	buf->num_ranges = cpu_to_le32(2);
	buf->ranges[0].offset = cpu_to_le64(0);
	buf->ranges[0].length = cpu_to_le64(4096);
	buf->ranges[1].offset = cpu_to_le64(8192);
	buf->ranges[1].length = cpu_to_le64(4096);

	ret = test_validate_file_level_trim(true, buf, total, true,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_trim_zero_ranges(struct kunit *test)
{
	struct test_file_level_trim buf = {
		.key = 0,
		.num_ranges = 0,
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_file_level_trim(true, &buf, sizeof(buf), true,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_trim_buffer_too_small(struct kunit *test)
{
	u8 small_buf[sizeof(struct test_file_level_trim) - 1];
	unsigned int out_len = 99;
	u32 status;
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_file_level_trim(true, small_buf, sizeof(small_buf),
					    true, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_trim_read_only_tree(struct kunit *test)
{
	struct test_file_level_trim buf = { .num_ranges = 0 };
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_file_level_trim(false, &buf, sizeof(buf), true,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_ACCESS_DENIED);
}

static void test_trim_ranges_exceed_buffer(struct kunit *test)
{
	/* Claim 10 ranges but only supply buffer for the header */
	struct test_file_level_trim buf = {
		.key = 0,
		.num_ranges = cpu_to_le32(10),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_file_level_trim(true, &buf, sizeof(buf), true,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_trim_invalid_handle(struct kunit *test)
{
	unsigned int total = sizeof(struct test_file_level_trim) +
			     sizeof(struct test_file_level_trim_range);
	struct test_file_level_trim *buf;
	unsigned int out_len = 99;
	u32 status;
	int ret;

	buf = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	buf->num_ranges = cpu_to_le32(1);
	buf->ranges[0].offset = cpu_to_le64(0);
	buf->ranges[0].length = cpu_to_le64(4096);

	ret = test_validate_file_level_trim(true, buf, total, false,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_HANDLE);
}

static void test_trim_negative_offset_skipped(struct kunit *test)
{
	unsigned int total = sizeof(struct test_file_level_trim) +
			     sizeof(struct test_file_level_trim_range);
	struct test_file_level_trim *buf;
	unsigned int out_len = 99;
	u32 status;
	int ret;

	buf = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	buf->num_ranges = cpu_to_le32(1);
	/* -1 as u64 = 0xFFFFFFFFFFFFFFFF, which is negative as loff_t */
	buf->ranges[0].offset = cpu_to_le64((u64)-1LL);
	buf->ranges[0].length = cpu_to_le64(4096);

	/* Production code skips invalid ranges but still returns success */
	ret = test_validate_file_level_trim(true, buf, total, true,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_trim_zero_length_range_skipped(struct kunit *test)
{
	unsigned int total = sizeof(struct test_file_level_trim) +
			     sizeof(struct test_file_level_trim_range);
	struct test_file_level_trim *buf;
	unsigned int out_len = 99;
	u32 status;
	int ret;

	buf = kunit_kzalloc(test, total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	buf->num_ranges = cpu_to_le32(1);
	buf->ranges[0].offset = cpu_to_le64(0);
	buf->ranges[0].length = cpu_to_le64(0); /* zero length */

	ret = test_validate_file_level_trim(true, buf, total, true,
					    &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ========================================================================
 * Test cases: SET_ZERO_DATA
 * ======================================================================== */

static void test_zero_data_normal(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_zero_data_zero_length(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(100),
		.BeyondFinalZero = cpu_to_le64(100),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	/* offset == beyond: noop */
	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_zero_data_negative_offset(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64((u64)-1LL),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_zero_data_negative_beyond(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64((u64)-1LL),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_zero_data_offset_gt_beyond(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(4096),
		.BeyondFinalZero = cpu_to_le64(100),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_zero_data_buffer_too_small(struct kunit *test)
{
	u8 small_buf[sizeof(struct test_file_zero_data_information) - 1];
	unsigned int out_len = 99;
	u32 status;
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_set_zero_data(true, small_buf, sizeof(small_buf),
					  true, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_zero_data_read_only_tree(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_set_zero_data(false, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_ACCESS_DENIED);
}

static void test_zero_data_invalid_handle(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), false,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_HANDLE);
}

static void test_zero_data_large_range(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(0x7FFFFFFFFFFFFFFFLL),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	/* Maximum positive loff_t range: should pass validation */
	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_zero_data_both_zero(struct kunit *test)
{
	struct test_file_zero_data_information zd = {
		.FileOffset = cpu_to_le64(0),
		.BeyondFinalZero = cpu_to_le64(0),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	/* Both zero: noop (len=0) */
	ret = test_validate_set_zero_data(true, &zd, sizeof(zd), true,
					  &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ========================================================================
 * Test cases: QUERY_ALLOCATED_RANGES
 * ======================================================================== */

static void test_qar_normal(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar) * 10, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_qar_zero_length(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(1000),
		.length = cpu_to_le64(0),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar) * 10, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_qar_negative_offset(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64((u64)-1LL),
		.length = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar) * 10, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_qar_negative_length(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64((u64)-1LL),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar) * 10, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_qar_buffer_too_small(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	/* Output cannot hold even one entry */
	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar) - 1, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_qar_buffer_zero_max_out(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   0, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_qar_input_too_small(struct kunit *test)
{
	u8 small_buf[sizeof(struct test_file_allocated_range_buffer) - 1];
	unsigned int out_len = 99;
	u32 status;
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_query_allocated_ranges(small_buf,
						   sizeof(small_buf),
						   1024, true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_qar_invalid_handle(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar) * 10, false,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_HANDLE);
}

static void test_qar_exact_one_entry_buffer(struct kunit *test)
{
	struct test_file_allocated_range_buffer qar = {
		.file_offset = cpu_to_le64(0),
		.length = cpu_to_le64(1024 * 1024),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	/* Buffer fits exactly one entry */
	ret = test_validate_query_allocated_ranges(&qar, sizeof(qar),
						   sizeof(qar), true,
						   &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ========================================================================
 * Test cases: COPYCHUNK range validation
 * ======================================================================== */

static void test_copychunk_zero_count(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	req_len = sizeof(struct test_copychunk_ioctl_req) + 1;
	buf = kunit_kzalloc(test, req_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
}

static void test_copychunk_exceed_max_count(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, MAX_CHUNK_COUNT + 1,
				  4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
	/* Response carries server limits */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ChunksWritten),
			(u32)MAX_CHUNK_COUNT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ChunkBytesWritten),
			(u32)MAX_CHUNK_SIZE);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.TotalBytesWritten),
			(u32)MAX_TOTAL_SIZE);
}

static void test_copychunk_exceed_max_chunk_size(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, MAX_CHUNK_SIZE + 1,
				  &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_exceed_max_total_size(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* 17 chunks of 1MB each = 17MB > 16MB max */
	buf = build_copychunk_req(test, 1, 100, 17, MAX_CHUNK_SIZE, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_zero_length_chunk(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, 0, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_input_too_small(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0;
	u32 status;
	u8 small_buf[sizeof(struct test_copychunk_ioctl_req)];
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_copychunk(&ctx, small_buf, sizeof(small_buf),
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_copychunk_output_too_small(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp) - 1, &rsp, &out_len,
				      &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_copychunk_read_only_tree(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	ctx.writable = false;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_ACCESS_DENIED);
}

static void test_copychunk_source_not_found(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	ctx.src_exists = false;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_OBJECT_NAME_NOT_FOUND);
}

static void test_copychunk_dest_not_found(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	ctx.dst_exists = false;
	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_HANDLE);
}

static void test_copychunk_resume_key_mismatch(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* persistent_id=100 in ctx, but resume_key[1]=999 in request */
	buf = build_copychunk_req(test, 1, 999, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_OBJECT_NAME_NOT_FOUND);
}

static void test_copychunk_dst_read_access_required(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* check_dst_read_access=true (COPYCHUNK), dst has WRITE only */
	ctx.check_dst_read_access = true;
	ctx.dst_daccess = cpu_to_le32(0x00000002); /* WRITE only */

	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_ACCESS_DENIED);
}

static void test_copychunk_write_no_read_check(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* check_dst_read_access=false (COPYCHUNK_WRITE), dst has WRITE only */
	ctx.check_dst_read_access = false;
	ctx.dst_daccess = cpu_to_le32(0x00000002); /* WRITE only */

	buf = build_copychunk_req(test, 1, 100, 1, 4096, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_copychunk_at_max_count_boundary(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* Exactly MAX_CHUNK_COUNT chunks, each small enough to pass */
	buf = build_copychunk_req(test, 1, 100, MAX_CHUNK_COUNT, 1, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
}

static void test_copychunk_at_max_chunk_size_boundary(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* Exactly MAX_CHUNK_SIZE: should pass */
	buf = build_copychunk_req(test, 1, 100, 1, MAX_CHUNK_SIZE, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_copychunk_at_max_total_boundary(struct kunit *test)
{
	struct test_copychunk_ctx ctx = default_copychunk_ctx();
	struct test_copychunk_ioctl_rsp rsp;
	unsigned int out_len = 0, req_len;
	u32 status;
	void *buf;
	int ret;

	/* 16 chunks of 1MB each = exactly 16MB = MAX_TOTAL_SIZE */
	buf = build_copychunk_req(test, 1, 100, 16, MAX_CHUNK_SIZE, &req_len);
	ret = test_validate_copychunk(&ctx, buf, req_len,
				      sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ========================================================================
 * Test cases: DUPLICATE_EXTENTS_TO_FILE
 * ======================================================================== */

static void test_dup_extents_normal(struct kunit *test)
{
	struct test_duplicate_extents_to_file dup = {
		.SourceFileOffset = cpu_to_le64(0),
		.TargetFileOffset = cpu_to_le64(0),
		.ByteCount = cpu_to_le64(4096),
	};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_duplicate_extents(true, &dup, sizeof(dup),
					      true, true, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_dup_extents_read_only_tree(struct kunit *test)
{
	struct test_duplicate_extents_to_file dup = {};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_duplicate_extents(false, &dup, sizeof(dup),
					      true, true, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_ACCESS_DENIED);
}

static void test_dup_extents_input_too_small(struct kunit *test)
{
	u8 small_buf[sizeof(struct test_duplicate_extents_to_file) - 1];
	unsigned int out_len = 99;
	u32 status;
	int ret;

	memset(small_buf, 0, sizeof(small_buf));
	ret = test_validate_duplicate_extents(true, small_buf,
					      sizeof(small_buf),
					      true, true, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_PARAMETER);
}

static void test_dup_extents_source_not_found(struct kunit *test)
{
	struct test_duplicate_extents_to_file dup = {};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_duplicate_extents(true, &dup, sizeof(dup),
					      false, true, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_HANDLE);
}

static void test_dup_extents_dest_not_found(struct kunit *test)
{
	struct test_duplicate_extents_to_file dup = {};
	unsigned int out_len = 99;
	u32 status;
	int ret;

	ret = test_validate_duplicate_extents(true, &dup, sizeof(dup),
					      true, false, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_INVALID_HANDLE);
}

/* ========================================================================
 * Test cases: PIPE_WAIT
 * ======================================================================== */

static void test_pipe_wait_no_request_data(struct kunit *test)
{
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	/* Empty buffer: succeed unconditionally */
	ret = test_validate_pipe_wait(NULL, 0, false, &out_len, &status,
				      &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_pipe_wait_pipe_open(struct kunit *test)
{
	struct test_fsctl_pipe_wait_req req = {
		.Timeout = cpu_to_le64(5000000LL), /* 500ms in 100ns units */
		.TimeoutSpecified = 1,
		.NameLength = 0,
	};
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	ret = test_validate_pipe_wait(&req, sizeof(req), true, &out_len,
				      &status, &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_pipe_wait_timeout_not_specified(struct kunit *test)
{
	struct test_fsctl_pipe_wait_req req = {
		.Timeout = cpu_to_le64(9999999LL),
		.TimeoutSpecified = 0,
		.NameLength = 0,
	};
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	/* Pipe not open, timeout not specified -> wait indefinitely */
	ret = test_validate_pipe_wait(&req, sizeof(req), false, &out_len,
				      &status, &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, status, (u32)STATUS_IO_TIMEOUT);
	KUNIT_EXPECT_EQ(test, wait_ms, (unsigned int)0xffffffffu);
}

static void test_pipe_wait_timeout_zero(struct kunit *test)
{
	struct test_fsctl_pipe_wait_req req = {
		.Timeout = cpu_to_le64(0),
		.TimeoutSpecified = 1,
		.NameLength = 0,
	};
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	/* Timeout=0 with TimeoutSpecified: immediate timeout */
	ret = test_validate_pipe_wait(&req, sizeof(req), false, &out_len,
				      &status, &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, wait_ms, (unsigned int)0);
}

static void test_pipe_wait_small_timeout(struct kunit *test)
{
	struct test_fsctl_pipe_wait_req req = {
		/* 1ms = 10000 * 100ns */
		.Timeout = cpu_to_le64(10000LL),
		.TimeoutSpecified = 1,
		.NameLength = 0,
	};
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	ret = test_validate_pipe_wait(&req, sizeof(req), false, &out_len,
				      &status, &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, wait_ms, (unsigned int)1);
}

static void test_pipe_wait_large_timeout(struct kunit *test)
{
	struct test_fsctl_pipe_wait_req req = {
		/* 10 seconds = 100000000 * 100ns */
		.Timeout = cpu_to_le64(100000000LL),
		.TimeoutSpecified = 1,
		.NameLength = 0,
	};
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	ret = test_validate_pipe_wait(&req, sizeof(req), false, &out_len,
				      &status, &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
	KUNIT_EXPECT_EQ(test, wait_ms, (unsigned int)10000);
}

static void test_pipe_wait_very_small_timeout_rounds_up(struct kunit *test)
{
	struct test_fsctl_pipe_wait_req req = {
		/* 0.1ms = 1000 * 100ns, computes to 0ms, rounds up to 1ms */
		.Timeout = cpu_to_le64(1000LL),
		.TimeoutSpecified = 1,
		.NameLength = 0,
	};
	unsigned int out_len = 99;
	unsigned int wait_ms = 0;
	u32 status;
	int ret;

	ret = test_validate_pipe_wait(&req, sizeof(req), false, &out_len,
				      &status, &wait_ms);
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
	/* 1000/10000 = 0 -> rounds up to 1 */
	KUNIT_EXPECT_EQ(test, wait_ms, (unsigned int)1);
}

/* ========================================================================
 * Test cases: FSCTL dispatch routing (extra_handlers[])
 * ======================================================================== */

static void test_extra_register_file_level_trim(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	ret = test_register_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tbl.count, (unsigned int)1);

	ret = test_dispatch(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_extra_register_pipe_wait(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	ret = test_register_handler(&tbl, FSCTL_PIPE_WAIT);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_dispatch(&tbl, FSCTL_PIPE_WAIT);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_extra_dispatch_unregistered(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	ret = test_dispatch(&tbl, 0xDEADBEEF);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

static void test_extra_register_duplicate(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	ret = test_register_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_register_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
}

static void test_extra_unregister_and_dispatch(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	ret = test_register_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, 0);

	test_unregister_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);

	ret = test_dispatch(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

static void test_extra_init_registers_both(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	/* Simulate ksmbd_fsctl_extra_init: register both handlers */
	ret = test_register_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_register_handler(&tbl, FSCTL_PIPE_WAIT);
	KUNIT_EXPECT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, tbl.count, (unsigned int)2);

	ret = test_dispatch(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_dispatch(&tbl, FSCTL_PIPE_WAIT);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Other codes still unregistered */
	ret = test_dispatch(&tbl, FSCTL_SET_ZERO_DATA);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

static void test_extra_exit_unregisters_all(struct kunit *test)
{
	struct test_dispatch_table tbl = {};
	int ret;

	test_register_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);
	test_register_handler(&tbl, FSCTL_PIPE_WAIT);

	/* Simulate ksmbd_fsctl_extra_exit: unregister in reverse order */
	test_unregister_handler(&tbl, FSCTL_PIPE_WAIT);
	test_unregister_handler(&tbl, FSCTL_FILE_LEVEL_TRIM);

	ret = test_dispatch(&tbl, FSCTL_FILE_LEVEL_TRIM);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);

	ret = test_dispatch(&tbl, FSCTL_PIPE_WAIT);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

/* ========================================================================
 * Test suite registration
 * ======================================================================== */

static struct kunit_case ksmbd_fsctl_extra_test_cases[] = {
	/* FILE_LEVEL_TRIM */
	KUNIT_CASE(test_trim_normal),
	KUNIT_CASE(test_trim_zero_ranges),
	KUNIT_CASE(test_trim_buffer_too_small),
	KUNIT_CASE(test_trim_read_only_tree),
	KUNIT_CASE(test_trim_ranges_exceed_buffer),
	KUNIT_CASE(test_trim_invalid_handle),
	KUNIT_CASE(test_trim_negative_offset_skipped),
	KUNIT_CASE(test_trim_zero_length_range_skipped),
	/* SET_ZERO_DATA */
	KUNIT_CASE(test_zero_data_normal),
	KUNIT_CASE(test_zero_data_zero_length),
	KUNIT_CASE(test_zero_data_negative_offset),
	KUNIT_CASE(test_zero_data_negative_beyond),
	KUNIT_CASE(test_zero_data_offset_gt_beyond),
	KUNIT_CASE(test_zero_data_buffer_too_small),
	KUNIT_CASE(test_zero_data_read_only_tree),
	KUNIT_CASE(test_zero_data_invalid_handle),
	KUNIT_CASE(test_zero_data_large_range),
	KUNIT_CASE(test_zero_data_both_zero),
	/* QUERY_ALLOCATED_RANGES */
	KUNIT_CASE(test_qar_normal),
	KUNIT_CASE(test_qar_zero_length),
	KUNIT_CASE(test_qar_negative_offset),
	KUNIT_CASE(test_qar_negative_length),
	KUNIT_CASE(test_qar_buffer_too_small),
	KUNIT_CASE(test_qar_buffer_zero_max_out),
	KUNIT_CASE(test_qar_input_too_small),
	KUNIT_CASE(test_qar_invalid_handle),
	KUNIT_CASE(test_qar_exact_one_entry_buffer),
	/* COPYCHUNK */
	KUNIT_CASE(test_copychunk_zero_count),
	KUNIT_CASE(test_copychunk_exceed_max_count),
	KUNIT_CASE(test_copychunk_exceed_max_chunk_size),
	KUNIT_CASE(test_copychunk_exceed_max_total_size),
	KUNIT_CASE(test_copychunk_zero_length_chunk),
	KUNIT_CASE(test_copychunk_input_too_small),
	KUNIT_CASE(test_copychunk_output_too_small),
	KUNIT_CASE(test_copychunk_read_only_tree),
	KUNIT_CASE(test_copychunk_source_not_found),
	KUNIT_CASE(test_copychunk_dest_not_found),
	KUNIT_CASE(test_copychunk_resume_key_mismatch),
	KUNIT_CASE(test_copychunk_dst_read_access_required),
	KUNIT_CASE(test_copychunk_write_no_read_check),
	KUNIT_CASE(test_copychunk_at_max_count_boundary),
	KUNIT_CASE(test_copychunk_at_max_chunk_size_boundary),
	KUNIT_CASE(test_copychunk_at_max_total_boundary),
	/* DUPLICATE_EXTENTS_TO_FILE */
	KUNIT_CASE(test_dup_extents_normal),
	KUNIT_CASE(test_dup_extents_read_only_tree),
	KUNIT_CASE(test_dup_extents_input_too_small),
	KUNIT_CASE(test_dup_extents_source_not_found),
	KUNIT_CASE(test_dup_extents_dest_not_found),
	/* PIPE_WAIT */
	KUNIT_CASE(test_pipe_wait_no_request_data),
	KUNIT_CASE(test_pipe_wait_pipe_open),
	KUNIT_CASE(test_pipe_wait_timeout_not_specified),
	KUNIT_CASE(test_pipe_wait_timeout_zero),
	KUNIT_CASE(test_pipe_wait_small_timeout),
	KUNIT_CASE(test_pipe_wait_large_timeout),
	KUNIT_CASE(test_pipe_wait_very_small_timeout_rounds_up),
	/* Dispatch routing */
	KUNIT_CASE(test_extra_register_file_level_trim),
	KUNIT_CASE(test_extra_register_pipe_wait),
	KUNIT_CASE(test_extra_dispatch_unregistered),
	KUNIT_CASE(test_extra_register_duplicate),
	KUNIT_CASE(test_extra_unregister_and_dispatch),
	KUNIT_CASE(test_extra_init_registers_both),
	KUNIT_CASE(test_extra_exit_unregisters_all),
	{}
};

static struct kunit_suite ksmbd_fsctl_extra_test_suite = {
	.name = "ksmbd_fsctl_extra",
	.test_cases = ksmbd_fsctl_extra_test_cases,
};

kunit_test_suite(ksmbd_fsctl_extra_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd extra FSCTL handlers (ksmbd_fsctl_extra.c)");
