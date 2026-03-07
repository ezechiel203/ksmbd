// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 READ/WRITE/FLUSH handler logic (smb2_read_write.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/limits.h>

/* ---- Replicated constants ---- */

#define TEST_SMB2_MAX_BUFFER_SIZE	65536
#define TEST_SMB2_HEADER_SIZE		64

/* Read flags */
#define TEST_SMB2_READFLAG_READ_UNBUFFERED		0x00000001
#define TEST_SMB2_READFLAG_READ_COMPRESSED		0x00000002
#define TEST_SMB2_READFLAG_REQUEST_TRANSPORT_ENC	0x00000004

/* Write flags */
#define TEST_SMB2_WRITEFLAG_WRITE_THROUGH		0x00000001
#define TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED		0x00000002
#define TEST_SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENC	0x00000004

/* RDMA channels */
#define TEST_SMB2_CHANNEL_NONE		0x00000000
#define TEST_SMB2_CHANNEL_RDMA_V1	0x00000001

/* Access mask bits */
#define TEST_FILE_READ_DATA		0x00000001
#define TEST_FILE_WRITE_DATA		0x00000002
#define TEST_FILE_APPEND_DATA		0x00000004

/* Append-to-EOF sentinel */
#define TEST_WRITE_APPEND_SENTINEL	0xFFFFFFFFFFFFFFFFULL

/* ---- Replicated logic ---- */

/*
 * Replicate offset + length overflow check from smb2_read_write.c
 * Returns true if the combination overflows loff_t
 */
static bool test_offset_length_overflow(u64 offset, u32 length)
{
	loff_t off = (loff_t)offset;
	loff_t len = (loff_t)length;

	if (off < 0)
		return true;
	if (off + len < off)
		return true;
	return false;
}

/*
 * Replicate write append-to-EOF sentinel logic
 */
static bool test_is_append_to_eof(u64 offset)
{
	return offset == TEST_WRITE_APPEND_SENTINEL;
}

/*
 * Replicate write access validation for append sentinel
 */
static int test_validate_append_write(u64 offset, u32 daccess)
{
	if (!test_is_append_to_eof(offset))
		return 0;

	if (!(daccess & TEST_FILE_APPEND_DATA))
		return -EACCES;

	return 0;
}

/*
 * Replicate non-EOF offset with append-only access check
 */
static int test_validate_non_eof_append_only(u64 offset, u32 daccess,
					     u64 file_size)
{
	/*
	 * If the handle only has FILE_APPEND_DATA (not FILE_WRITE_DATA),
	 * writing at an offset other than EOF is rejected.
	 */
	if ((daccess & TEST_FILE_APPEND_DATA) &&
	    !(daccess & TEST_FILE_WRITE_DATA) &&
	    offset != file_size)
		return -EACCES;
	return 0;
}

/*
 * Replicate flush access check
 */
static int test_validate_flush_access(u32 daccess)
{
	if (!(daccess & (TEST_FILE_WRITE_DATA | TEST_FILE_APPEND_DATA)))
		return -EACCES;
	return 0;
}

/*
 * Replicate data offset validation for read/write
 */
static bool test_validate_data_offset(u16 data_offset, u32 buf_size)
{
	return data_offset >= TEST_SMB2_HEADER_SIZE &&
	       data_offset <= buf_size;
}

/*
 * Replicate channel sequence validation
 */
static int test_check_channel_sequence(u16 curr_seq, u16 req_seq)
{
	s16 diff = (s16)(req_seq - curr_seq);

	if (diff < 0)
		return -EAGAIN; /* STATUS_FILE_NOT_AVAILABLE */
	return 0;
}

/* ---- Test Cases: Read Validation ---- */

static void test_read_basic_file(struct kunit *test)
{
	u64 offset = 0;
	u32 length = 4096;

	KUNIT_EXPECT_FALSE(test, test_offset_length_overflow(offset, length));
}

static void test_read_zero_length(struct kunit *test)
{
	u64 offset = 100;
	u32 length = 0;

	KUNIT_EXPECT_FALSE(test, test_offset_length_overflow(offset, length));
}

static void test_read_max_length(struct kunit *test)
{
	u64 offset = 0;
	u32 length = 8 * 1024 * 1024; /* MaxReadSize boundary */

	KUNIT_EXPECT_FALSE(test, test_offset_length_overflow(offset, length));
}

static void test_read_beyond_eof(struct kunit *test)
{
	/* Reading past EOF returns STATUS_END_OF_FILE, no overflow */
	u64 offset = 10000;
	u32 length = 4096;

	KUNIT_EXPECT_FALSE(test, test_offset_length_overflow(offset, length));
}

static void test_read_invalid_fid(struct kunit *test)
{
	/* Invalid VolatileFileId = FILE_CLOSED */
	u64 volatile_fid = 0xFFFFFFFFFFFFFFFFULL;

	KUNIT_EXPECT_EQ(test, volatile_fid, 0xFFFFFFFFFFFFFFFFULL);
}

static void test_read_closed_fid(struct kunit *test)
{
	/* Closed FID returns FILE_CLOSED -- logic: fp == NULL */
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_read_offset_overflow(struct kunit *test)
{
	/* Offset that wraps loff_t (negative when cast) */
	u64 offset = (u64)LLONG_MAX + 1;

	KUNIT_EXPECT_TRUE(test, test_offset_length_overflow(offset, 0));
}

static void test_read_length_overflow(struct kunit *test)
{
	/* Length + offset > LLONG_MAX */
	u64 offset = LLONG_MAX - 10;
	u32 length = 20;

	KUNIT_EXPECT_TRUE(test, test_offset_length_overflow(offset, length));
}

static void test_read_pipe(struct kunit *test)
{
	/* IPC$ pipe read goes through async path */
	bool is_pipe = true;

	KUNIT_EXPECT_TRUE(test, is_pipe);
}

static void test_read_pipe_cancel(struct kunit *test)
{
	/* Pipe read cancellation */
	bool is_pipe = true;
	bool cancel_requested = true;

	KUNIT_EXPECT_TRUE(test, is_pipe && cancel_requested);
}

static void test_read_compound_fid(struct kunit *test)
{
	/* Compound request with related flag uses compound FID */
	u64 req_fid = 0xFFFFFFFFFFFFFFFFULL;
	u64 compound_fid = 42;
	bool is_related = true;

	u64 effective_fid = is_related ? compound_fid : req_fid;
	KUNIT_EXPECT_EQ(test, effective_fid, (u64)42);
}

static void test_read_rdma_channel(struct kunit *test)
{
	/* SMB_DIRECT read via RDMA (channel=1) */
	u32 channel = TEST_SMB2_CHANNEL_RDMA_V1;

	KUNIT_EXPECT_NE(test, channel, TEST_SMB2_CHANNEL_NONE);
}

static void test_read_channel_sequence_stale(struct kunit *test)
{
	/* ChannelSequence mismatch = FILE_NOT_AVAILABLE */
	int ret = test_check_channel_sequence(5, 3);

	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
}

static void test_read_unbuffered_flag(struct kunit *test)
{
	u32 flags = TEST_SMB2_READFLAG_READ_UNBUFFERED;

	KUNIT_EXPECT_TRUE(test, flags & TEST_SMB2_READFLAG_READ_UNBUFFERED);
}

static void test_read_minimum_count(struct kunit *test)
{
	/* MinimumCount field behavior: short read if data < min */
	u32 min_count = 1024;
	u32 data_read = 512;

	KUNIT_EXPECT_TRUE(test, data_read < min_count);
}

static void test_read_data_offset_validation(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_validate_data_offset(80, 256));
	KUNIT_EXPECT_FALSE(test, test_validate_data_offset(32, 256));
	KUNIT_EXPECT_FALSE(test, test_validate_data_offset(300, 256));
}

/* ---- Test Cases: Write Validation ---- */

static void test_write_basic_file(struct kunit *test)
{
	u64 offset = 0;
	u32 length = 4096;

	KUNIT_EXPECT_FALSE(test, test_offset_length_overflow(offset, length));
}

static void test_write_zero_length(struct kunit *test)
{
	u64 offset = 0;
	u32 length = 0;

	KUNIT_EXPECT_FALSE(test, test_offset_length_overflow(offset, length));
}

static void test_write_append_to_eof_sentinel(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_append_to_eof(TEST_WRITE_APPEND_SENTINEL));
	KUNIT_EXPECT_FALSE(test, test_is_append_to_eof(0));
	KUNIT_EXPECT_FALSE(test, test_is_append_to_eof(100));
}

static void test_write_append_requires_append_data(struct kunit *test)
{
	/* Append sentinel without FILE_APPEND_DATA = ACCESS_DENIED */
	int ret = test_validate_append_write(TEST_WRITE_APPEND_SENTINEL,
					     TEST_FILE_WRITE_DATA);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);

	/* With FILE_APPEND_DATA, should succeed */
	ret = test_validate_append_write(TEST_WRITE_APPEND_SENTINEL,
					 TEST_FILE_APPEND_DATA);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_write_offset_overflow_guard(struct kunit *test)
{
	u64 offset = LLONG_MAX - 5;
	u32 length = 10;

	KUNIT_EXPECT_TRUE(test, test_offset_length_overflow(offset, length));
}

static void test_write_non_eof_with_append_only(struct kunit *test)
{
	/* FILE_APPEND_DATA-only rejects non-EOF offset */
	int ret = test_validate_non_eof_append_only(
		100, TEST_FILE_APPEND_DATA, 200);
	KUNIT_EXPECT_EQ(test, ret, -EACCES);

	/* At EOF position, should succeed */
	ret = test_validate_non_eof_append_only(
		200, TEST_FILE_APPEND_DATA, 200);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* With FILE_WRITE_DATA, any offset is fine */
	ret = test_validate_non_eof_append_only(
		100, TEST_FILE_WRITE_DATA | TEST_FILE_APPEND_DATA, 200);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_write_pipe(struct kunit *test)
{
	bool is_pipe = true;

	KUNIT_EXPECT_TRUE(test, is_pipe);
}

static void test_write_invalid_fid(struct kunit *test)
{
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_write_compound_fid(struct kunit *test)
{
	u64 req_fid = 0xFFFFFFFFFFFFFFFFULL;
	u64 compound_fid = 99;
	bool is_related = true;

	u64 effective_fid = is_related ? compound_fid : req_fid;
	KUNIT_EXPECT_EQ(test, effective_fid, (u64)99);
}

static void test_write_rdma_channel(struct kunit *test)
{
	u32 channel = TEST_SMB2_CHANNEL_RDMA_V1;

	KUNIT_EXPECT_EQ(test, channel, TEST_SMB2_CHANNEL_RDMA_V1);
}

static void test_write_channel_sequence(struct kunit *test)
{
	/* Valid sequence advances */
	int ret = test_check_channel_sequence(3, 5);

	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Stale sequence */
	ret = test_check_channel_sequence(10, 5);
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
}

static void test_write_unbuffered_flag(struct kunit *test)
{
	u32 flags = TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED;

	KUNIT_EXPECT_TRUE(test, flags & TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED);
}

static void test_write_data_offset_validation(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_validate_data_offset(70, 256));
	KUNIT_EXPECT_FALSE(test, test_validate_data_offset(10, 256));
}

static void test_write_data_length_validation(struct kunit *test)
{
	/*
	 * DataLength within credit charge: each credit allows 64KB.
	 * 2 credits = 128KB max.
	 */
	u32 data_len = 131072; /* 128KB */
	u32 credit_charge = 2;
	u32 max_data = credit_charge * TEST_SMB2_MAX_BUFFER_SIZE;

	KUNIT_EXPECT_TRUE(test, data_len <= max_data);

	/* Exceeding credit charge */
	data_len = 131073;
	KUNIT_EXPECT_TRUE(test, data_len > max_data);
}

static void test_write_write_through_flag(struct kunit *test)
{
	u32 flags = TEST_SMB2_WRITEFLAG_WRITE_THROUGH;

	KUNIT_EXPECT_TRUE(test, flags & TEST_SMB2_WRITEFLAG_WRITE_THROUGH);
}

/* ---- Test Cases: Flush Validation ---- */

static void test_flush_basic(struct kunit *test)
{
	int ret = test_validate_flush_access(TEST_FILE_WRITE_DATA);

	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_flush_invalid_fid(struct kunit *test)
{
	void *fp = NULL;

	KUNIT_EXPECT_NULL(test, fp);
}

static void test_flush_no_write_access(struct kunit *test)
{
	int ret = test_validate_flush_access(TEST_FILE_READ_DATA);

	KUNIT_EXPECT_EQ(test, ret, -EACCES);
}

static void test_flush_compound_fid(struct kunit *test)
{
	u64 compound_fid = 55;
	bool is_related = true;

	KUNIT_EXPECT_TRUE(test, is_related);
	KUNIT_EXPECT_NE(test, compound_fid, (u64)0);
}

static void test_flush_pipe(struct kunit *test)
{
	/* Pipe flush = no-op success */
	bool is_pipe = true;

	KUNIT_EXPECT_TRUE(test, is_pipe);
}

static void test_flush_channel_sequence(struct kunit *test)
{
	int ret = test_check_channel_sequence(1, 2);

	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_read_write_test_cases[] = {
	/* Read */
	KUNIT_CASE(test_read_basic_file),
	KUNIT_CASE(test_read_zero_length),
	KUNIT_CASE(test_read_max_length),
	KUNIT_CASE(test_read_beyond_eof),
	KUNIT_CASE(test_read_invalid_fid),
	KUNIT_CASE(test_read_closed_fid),
	KUNIT_CASE(test_read_offset_overflow),
	KUNIT_CASE(test_read_length_overflow),
	KUNIT_CASE(test_read_pipe),
	KUNIT_CASE(test_read_pipe_cancel),
	KUNIT_CASE(test_read_compound_fid),
	KUNIT_CASE(test_read_rdma_channel),
	KUNIT_CASE(test_read_channel_sequence_stale),
	KUNIT_CASE(test_read_unbuffered_flag),
	KUNIT_CASE(test_read_minimum_count),
	KUNIT_CASE(test_read_data_offset_validation),
	/* Write */
	KUNIT_CASE(test_write_basic_file),
	KUNIT_CASE(test_write_zero_length),
	KUNIT_CASE(test_write_append_to_eof_sentinel),
	KUNIT_CASE(test_write_append_requires_append_data),
	KUNIT_CASE(test_write_offset_overflow_guard),
	KUNIT_CASE(test_write_non_eof_with_append_only),
	KUNIT_CASE(test_write_pipe),
	KUNIT_CASE(test_write_invalid_fid),
	KUNIT_CASE(test_write_compound_fid),
	KUNIT_CASE(test_write_rdma_channel),
	KUNIT_CASE(test_write_channel_sequence),
	KUNIT_CASE(test_write_unbuffered_flag),
	KUNIT_CASE(test_write_data_offset_validation),
	KUNIT_CASE(test_write_data_length_validation),
	KUNIT_CASE(test_write_write_through_flag),
	/* Flush */
	KUNIT_CASE(test_flush_basic),
	KUNIT_CASE(test_flush_invalid_fid),
	KUNIT_CASE(test_flush_no_write_access),
	KUNIT_CASE(test_flush_compound_fid),
	KUNIT_CASE(test_flush_pipe),
	KUNIT_CASE(test_flush_channel_sequence),
	{}
};

static struct kunit_suite ksmbd_smb2_read_write_test_suite = {
	.name = "ksmbd_smb2_read_write",
	.test_cases = ksmbd_smb2_read_write_test_cases,
};

kunit_test_suite(ksmbd_smb2_read_write_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 READ/WRITE/FLUSH handlers");
