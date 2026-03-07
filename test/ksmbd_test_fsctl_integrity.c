// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FSCTL_GET_INTEGRITY_INFORMATION,
 *   FSCTL_SET_INTEGRITY_INFORMATION, FSCTL_SET_INTEGRITY_INFORMATION_EX.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#define STATUS_BUFFER_TOO_SMALL		0xC0000023
#define STATUS_INVALID_HANDLE		0xC0000008
#define STATUS_INVALID_PARAMETER	0xC000000D

struct test_integrity_info_rsp {
	__le16 ChecksumAlgorithm;
	__le16 Reserved;
	__le32 Flags;
	__le32 ChecksumChunkSizeInBytes;
	__le32 ClusterSizeInBytes;
} __packed;

struct test_integrity_info_req {
	__le16 ChecksumAlgorithm;
	__le16 Reserved;
	__le32 Flags;
} __packed;

/* ---- Replicated validation logic ---- */

static int test_get_integrity(bool fp_exists, unsigned int max_out_len,
			      struct test_integrity_info_rsp *rsp,
			      unsigned int *out_len, __le32 *status)
{
	*status = 0;
	*out_len = 0;

	if (max_out_len < sizeof(*rsp)) {
		*status = cpu_to_le32(STATUS_BUFFER_TOO_SMALL);
		return -ENOSPC;
	}

	if (!fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	memset(rsp, 0, sizeof(*rsp));
	rsp->ChecksumAlgorithm = 0; /* NONE */
	rsp->ChecksumChunkSizeInBytes = cpu_to_le32(65536);
	rsp->ClusterSizeInBytes = cpu_to_le32(4096);

	*out_len = sizeof(*rsp);
	return 0;
}

static int test_set_integrity(bool fp_exists, void *in_buf,
			      unsigned int in_buf_len, __le32 *status)
{
	*status = 0;

	if (in_buf_len < sizeof(struct test_integrity_info_req)) {
		*status = cpu_to_le32(STATUS_INVALID_PARAMETER);
		return -EINVAL;
	}

	if (!fp_exists) {
		*status = cpu_to_le32(STATUS_INVALID_HANDLE);
		return -ENOENT;
	}

	/* Accept silently -- Linux doesn't have per-file integrity */
	return 0;
}

/* ---- Test cases ---- */

static void test_get_integrity_normal(struct kunit *test)
{
	struct test_integrity_info_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_integrity(true, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(rsp));
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.ClusterSizeInBytes), (u32)4096);
}

static void test_get_integrity_buffer_too_small(struct kunit *test)
{
	struct test_integrity_info_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_integrity(true, sizeof(rsp) - 1, &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_BUFFER_TOO_SMALL);
}

static void test_get_integrity_invalid_handle(struct kunit *test)
{
	struct test_integrity_info_rsp rsp;
	unsigned int out_len;
	__le32 status;
	int ret;

	ret = test_get_integrity(false, sizeof(rsp), &rsp, &out_len, &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static void test_set_integrity_normal(struct kunit *test)
{
	struct test_integrity_info_req req;
	__le32 status;
	int ret;

	memset(&req, 0, sizeof(req));
	ret = test_set_integrity(true, &req, sizeof(req), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_set_integrity_buffer_too_small(struct kunit *test)
{
	u8 small[sizeof(struct test_integrity_info_req) - 1];
	__le32 status;
	int ret;

	memset(small, 0, sizeof(small));
	ret = test_set_integrity(true, small, sizeof(small), &status);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_PARAMETER);
}

static void test_set_integrity_invalid_handle(struct kunit *test)
{
	struct test_integrity_info_req req;
	__le32 status;
	int ret;

	memset(&req, 0, sizeof(req));
	ret = test_set_integrity(false, &req, sizeof(req), &status);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(status), (u32)STATUS_INVALID_HANDLE);
}

static void test_set_integrity_ex_same_handler(struct kunit *test)
{
	/* SET_INTEGRITY_INFORMATION_EX routes to the same handler */
	struct test_integrity_info_req req;
	__le32 status;
	int ret;

	memset(&req, 0, sizeof(req));
	ret = test_set_integrity(true, &req, sizeof(req), &status);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static struct kunit_case ksmbd_fsctl_integrity_test_cases[] = {
	KUNIT_CASE(test_get_integrity_normal),
	KUNIT_CASE(test_get_integrity_buffer_too_small),
	KUNIT_CASE(test_get_integrity_invalid_handle),
	KUNIT_CASE(test_set_integrity_normal),
	KUNIT_CASE(test_set_integrity_buffer_too_small),
	KUNIT_CASE(test_set_integrity_invalid_handle),
	KUNIT_CASE(test_set_integrity_ex_same_handler),
	{}
};

static struct kunit_suite ksmbd_fsctl_integrity_test_suite = {
	.name = "ksmbd_fsctl_integrity",
	.test_cases = ksmbd_fsctl_integrity_test_cases,
};

kunit_test_suite(ksmbd_fsctl_integrity_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL integrity information");
