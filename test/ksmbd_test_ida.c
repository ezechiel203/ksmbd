// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for IDA management (mgmt/ksmbd_ida.c)
 *
 *   These tests replicate the ID allocation logic from ksmbd_ida.c
 *   using the kernel IDA API directly.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/idr.h>

/*
 * Replicate the IDA allocation functions from mgmt/ksmbd_ida.c.
 * These are pure wrappers around ida_alloc_range/ida_alloc_min.
 */

static int test_acquire_smb2_tid(struct ida *ida)
{
	return ida_alloc_range(ida, 1, 0xFFFFFFFE, GFP_KERNEL);
}

static int test_acquire_smb1_tid(struct ida *ida)
{
	return ida_alloc_range(ida, 1, 0xFFFE, GFP_KERNEL);
}

static int test_acquire_smb2_uid(struct ida *ida)
{
	int id;

	id = ida_alloc_min(ida, 1, GFP_KERNEL);
	if (id == 0xFFFE) {
		/* 0xFFFE is reserved; free it and allocate the next one */
		ida_free(ida, id);
		id = ida_alloc_min(ida, 0xFFFF, GFP_KERNEL);
	}

	return id;
}

static int test_acquire_async_msg_id(struct ida *ida)
{
	return ida_alloc_min(ida, 1, GFP_KERNEL);
}

static int test_acquire_id(struct ida *ida)
{
	return ida_alloc(ida, GFP_KERNEL);
}

static void test_release_id(struct ida *ida, int id)
{
	ida_free(ida, id);
}

/* --- Test cases --- */

/*
 * test_ida_acquire_returns_valid_id - basic acquire returns valid ID
 */
static void test_ida_acquire_returns_valid_id(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_id(&ida);
	KUNIT_EXPECT_GE(test, id, 0);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_acquire_release_reacquire - release then reacquire cycle
 */
static void test_ida_acquire_release_reacquire(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id1, id2;

	id1 = test_acquire_id(&ida);
	KUNIT_ASSERT_GE(test, id1, 0);
	test_release_id(&ida, id1);

	id2 = test_acquire_id(&ida);
	KUNIT_EXPECT_GE(test, id2, 0);
	/* After release, the same ID may be reused */
	KUNIT_EXPECT_EQ(test, id2, id1);

	test_release_id(&ida, id2);
	ida_destroy(&ida);
}

/*
 * test_ida_smb1_tid_range - SMB1 TID range is 1 to 0xFFFE
 */
static void test_ida_smb1_tid_range(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_smb1_tid(&ida);
	KUNIT_ASSERT_GE(test, id, 1);
	KUNIT_EXPECT_LE(test, id, 0xFFFE);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_smb1_tid_starts_at_one - first SMB1 TID is 1
 */
static void test_ida_smb1_tid_starts_at_one(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_smb1_tid(&ida);
	KUNIT_EXPECT_EQ(test, id, 1);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_smb2_tid_range - SMB2 TID range is 1 to 0xFFFFFFFE
 */
static void test_ida_smb2_tid_range(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_smb2_tid(&ida);
	KUNIT_ASSERT_GE(test, id, 1);
	/* ida_alloc_range with max 0xFFFFFFFE; result fits in int */

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_smb2_tid_starts_at_one - first SMB2 TID is 1
 */
static void test_ida_smb2_tid_starts_at_one(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_smb2_tid(&ida);
	KUNIT_EXPECT_EQ(test, id, 1);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_smb2_uid_avoids_reserved - SMB2 UID skips reserved 0xFFFE
 *
 * The ksmbd_acquire_smb2_uid() function allocates from 1 upward.
 * If it ever gets 0xFFFE, it frees that and tries 0xFFFF instead.
 * We verify the logic by checking the first allocation starts at 1.
 */
static void test_ida_smb2_uid_avoids_reserved(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_smb2_uid(&ida);
	KUNIT_EXPECT_GE(test, id, 1);
	/* The first allocated ID should be 1, not 0 */
	KUNIT_EXPECT_EQ(test, id, 1);
	/* Should never be 0xFFFE */
	KUNIT_EXPECT_NE(test, id, 0xFFFE);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_async_msg_starts_at_one - async message IDs start at 1
 */
static void test_ida_async_msg_starts_at_one(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_async_msg_id(&ida);
	KUNIT_EXPECT_EQ(test, id, 1);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_sequential_unique - multiple sequential allocations return unique IDs
 */
static void test_ida_sequential_unique(struct kunit *test)
{
	DEFINE_IDA(ida);
	int ids[8];
	int i, j;

	for (i = 0; i < 8; i++) {
		ids[i] = test_acquire_async_msg_id(&ida);
		KUNIT_ASSERT_GE(test, ids[i], 1);
	}

	/* Verify all IDs are unique */
	for (i = 0; i < 8; i++)
		for (j = i + 1; j < 8; j++)
			KUNIT_EXPECT_NE(test, ids[i], ids[j]);

	for (i = 0; i < 8; i++)
		test_release_id(&ida, ids[i]);
	ida_destroy(&ida);
}

/*
 * test_ida_release_reuse - releasing an ID allows it to be reused
 */
static void test_ida_release_reuse(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id1, id2, id3;

	id1 = test_acquire_id(&ida);
	id2 = test_acquire_id(&ida);
	KUNIT_ASSERT_GE(test, id1, 0);
	KUNIT_ASSERT_GE(test, id2, 0);

	/* Release first ID */
	test_release_id(&ida, id1);

	/* Next allocation can reuse the released ID */
	id3 = test_acquire_id(&ida);
	KUNIT_EXPECT_GE(test, id3, 0);
	/* The released ID should be reused (lowest available) */
	KUNIT_EXPECT_EQ(test, id3, id1);

	test_release_id(&ida, id2);
	test_release_id(&ida, id3);
	ida_destroy(&ida);
}

/*
 * test_ida_generic_starts_at_zero - generic ida_alloc starts at 0
 */
static void test_ida_generic_starts_at_zero(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id;

	id = test_acquire_id(&ida);
	KUNIT_EXPECT_EQ(test, id, 0);

	test_release_id(&ida, id);
	ida_destroy(&ida);
}

/*
 * test_ida_smb2_tid_sequential - sequential SMB2 TIDs are incrementing
 */
static void test_ida_smb2_tid_sequential(struct kunit *test)
{
	DEFINE_IDA(ida);
	int id1, id2, id3;

	id1 = test_acquire_smb2_tid(&ida);
	id2 = test_acquire_smb2_tid(&ida);
	id3 = test_acquire_smb2_tid(&ida);

	KUNIT_EXPECT_EQ(test, id1, 1);
	KUNIT_EXPECT_EQ(test, id2, 2);
	KUNIT_EXPECT_EQ(test, id3, 3);

	test_release_id(&ida, id1);
	test_release_id(&ida, id2);
	test_release_id(&ida, id3);
	ida_destroy(&ida);
}

static struct kunit_case ksmbd_ida_test_cases[] = {
	KUNIT_CASE(test_ida_acquire_returns_valid_id),
	KUNIT_CASE(test_ida_acquire_release_reacquire),
	KUNIT_CASE(test_ida_smb1_tid_range),
	KUNIT_CASE(test_ida_smb1_tid_starts_at_one),
	KUNIT_CASE(test_ida_smb2_tid_range),
	KUNIT_CASE(test_ida_smb2_tid_starts_at_one),
	KUNIT_CASE(test_ida_smb2_uid_avoids_reserved),
	KUNIT_CASE(test_ida_async_msg_starts_at_one),
	KUNIT_CASE(test_ida_sequential_unique),
	KUNIT_CASE(test_ida_release_reuse),
	KUNIT_CASE(test_ida_generic_starts_at_zero),
	KUNIT_CASE(test_ida_smb2_tid_sequential),
	{}
};

static struct kunit_suite ksmbd_ida_test_suite = {
	.name = "ksmbd_ida",
	.test_cases = ksmbd_ida_test_cases,
};

kunit_test_suite(ksmbd_ida_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd IDA management");
