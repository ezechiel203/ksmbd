// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd info-level dispatch table.
 *   Calls real production buffer_check_err() via MODULE_IMPORT_NS.
 *
 *   The info dispatch hash table logic is internal to smb2pdu.c and
 *   uses pure data structures (hashtable, spinlock). We test the
 *   buffer_check_err integration since it is the shared validation
 *   function used across all info dispatch paths.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "../smb2pdu.h"
#include "../smb2_query_set.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/*
 * Info dispatch hash key computation - pure logic test.
 * The hash key packs info_type, info_class, and op into a single u32.
 */
static inline u32 test_info_hash_key(u8 info_type, u8 info_class, u8 op)
{
	return (u32)info_type << 16 | (u32)info_class << 8 | (u32)op;
}

/* ---- Hash key tests ---- */

static void test_hash_key_unique_all_different(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 2, 0);
	u32 k2 = test_info_hash_key(3, 4, 1);

	KUNIT_EXPECT_NE(test, k1, k2);
}

static void test_hash_key_same_type_class_diff_op(struct kunit *test)
{
	u32 k_get = test_info_hash_key(1, 5, 0);
	u32 k_set = test_info_hash_key(1, 5, 1);

	KUNIT_EXPECT_NE(test, k_get, k_set);
}

static void test_hash_key_same_type_diff_class(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 5, 0);
	u32 k2 = test_info_hash_key(1, 6, 0);

	KUNIT_EXPECT_NE(test, k1, k2);
}

static void test_hash_key_diff_type_same_class(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 5, 0);
	u32 k2 = test_info_hash_key(2, 5, 0);

	KUNIT_EXPECT_NE(test, k1, k2);
}

static void test_hash_key_identical_inputs(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 5, 0);
	u32 k2 = test_info_hash_key(1, 5, 0);

	KUNIT_EXPECT_EQ(test, k1, k2);
}

static void test_hash_key_boundary_values(struct kunit *test)
{
	u32 k1 = test_info_hash_key(0, 0, 0);
	u32 k2 = test_info_hash_key(255, 255, 1);

	KUNIT_EXPECT_NE(test, k1, k2);
	KUNIT_EXPECT_EQ(test, k1, (u32)0);
	KUNIT_EXPECT_EQ(test, k2, (u32)(255U << 16 | 255U << 8 | 1U));
}

/* ---- buffer_check_err integration test ---- */

static void test_dispatch_buffer_check_err_ok(struct kunit *test)
{
	void *buf;
	struct smb2_query_info_rsp *rsp;
	void *rsp_org;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	rsp_org = buf;
	rsp = (struct smb2_query_info_rsp *)((char *)buf + 4);
	rsp->OutputBufferLength = cpu_to_le32(40);

	KUNIT_EXPECT_EQ(test, buffer_check_err(100, rsp, rsp_org), 0);
}

static void test_dispatch_buffer_check_err_fail(struct kunit *test)
{
	void *buf;
	struct smb2_query_info_rsp *rsp;
	void *rsp_org;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	rsp_org = buf;
	rsp = (struct smb2_query_info_rsp *)((char *)buf + 4);
	rsp->OutputBufferLength = cpu_to_le32(200);

	KUNIT_EXPECT_EQ(test, buffer_check_err(10, rsp, rsp_org), -EINVAL);
}

/* ---- pipe info dispatch paths ---- */

static void test_dispatch_standard_pipe(struct kunit *test)
{
	void *buf;
	struct smb2_query_info_rsp *rsp;
	struct smb2_file_standard_info *sinfo;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	rsp = (struct smb2_query_info_rsp *)((char *)buf + 4);

	get_standard_info_pipe(rsp, buf);
	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le64_to_cpu(sinfo->AllocationSize), (u64)4096);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(sinfo->NumberOfLinks), (u32)1);
}

static void test_dispatch_internal_pipe(struct kunit *test)
{
	void *buf;
	struct smb2_query_info_rsp *rsp;
	struct smb2_file_internal_info *info;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	rsp = (struct smb2_query_info_rsp *)((char *)buf + 4);

	get_internal_info_pipe(rsp, 99, buf);
	info = (struct smb2_file_internal_info *)rsp->Buffer;

	KUNIT_EXPECT_EQ(test, le64_to_cpu(info->IndexNumber),
			99ULL | (1ULL << 63));
}

/* ---- Registration ---- */

static struct kunit_case ksmbd_info_dispatch_test_cases[] = {
	KUNIT_CASE(test_hash_key_unique_all_different),
	KUNIT_CASE(test_hash_key_same_type_class_diff_op),
	KUNIT_CASE(test_hash_key_same_type_diff_class),
	KUNIT_CASE(test_hash_key_diff_type_same_class),
	KUNIT_CASE(test_hash_key_identical_inputs),
	KUNIT_CASE(test_hash_key_boundary_values),
	KUNIT_CASE(test_dispatch_buffer_check_err_ok),
	KUNIT_CASE(test_dispatch_buffer_check_err_fail),
	KUNIT_CASE(test_dispatch_standard_pipe),
	KUNIT_CASE(test_dispatch_internal_pipe),
	{}
};

static struct kunit_suite ksmbd_info_dispatch_test_suite = {
	.name = "ksmbd_info_dispatch",
	.test_cases = ksmbd_info_dispatch_test_cases,
};

kunit_test_suite(ksmbd_info_dispatch_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd info-level dispatch table");
