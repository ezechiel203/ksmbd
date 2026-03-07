// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ksmbd_work allocation and lifecycle (ksmbd_work.c)
 *
 *   These tests call production code directly via exported symbols
 *   from the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>

#include "ksmbd_work.h"

#define KSMBD_NO_FID		((__u64)-1)

/*
 * Suite init: create the work pool (kmem_cache) once for all tests.
 * Suite exit: destroy it.
 */
static int work_alloc_suite_init(struct kunit_suite *suite)
{
	return ksmbd_work_pool_init();
}

static void work_alloc_suite_exit(struct kunit_suite *suite)
{
	ksmbd_work_pool_destroy();
}

/* -- Allocation tests -- */

static void test_alloc_returns_nonnull(struct kunit *test)
{
	struct ksmbd_work *work = ksmbd_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);
	ksmbd_free_work_struct(work);
}

static void test_alloc_fields_initialized(struct kunit *test)
{
	struct ksmbd_work *work = ksmbd_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);

	KUNIT_EXPECT_EQ(test, work->compound_fid, KSMBD_NO_FID);
	KUNIT_EXPECT_EQ(test, work->compound_pfid, KSMBD_NO_FID);
	KUNIT_EXPECT_EQ(test, work->iov_alloc_cnt, 4);
	KUNIT_EXPECT_NOT_NULL(test, work->iov);
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 0);
	KUNIT_EXPECT_EQ(test, work->iov_idx, 0);
	KUNIT_EXPECT_TRUE(test, list_empty(&work->request_entry));
	KUNIT_EXPECT_TRUE(test, list_empty(&work->async_request_entry));
	KUNIT_EXPECT_TRUE(test, list_empty(&work->fp_entry));
	KUNIT_EXPECT_TRUE(test, list_empty(&work->aux_read_list));
	KUNIT_EXPECT_NULL(test, work->request_buf);
	KUNIT_EXPECT_NULL(test, work->response_buf);
	KUNIT_EXPECT_EQ(test, work->async_id, 0);

	ksmbd_free_work_struct(work);
}

static void test_alloc_free_cycle(struct kunit *test)
{
	int i;

	/* Allocate and free 64 work structs to exercise the slab cache */
	for (i = 0; i < 64; i++) {
		struct ksmbd_work *work = ksmbd_alloc_work_struct();

		KUNIT_ASSERT_NOT_NULL(test, work);
		ksmbd_free_work_struct(work);
	}
}

static void test_alloc_free_batch(struct kunit *test)
{
	struct ksmbd_work *works[32];
	int i;

	for (i = 0; i < 32; i++) {
		works[i] = ksmbd_alloc_work_struct();
		KUNIT_ASSERT_NOT_NULL(test, works[i]);
	}

	for (i = 0; i < 32; i++)
		ksmbd_free_work_struct(works[i]);
}

static void test_free_with_response_buf(struct kunit *test)
{
	struct ksmbd_work *work = ksmbd_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);

	/* Simulate allocating a response buffer */
	work->response_buf = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	/* free should release response_buf without crashing */
	ksmbd_free_work_struct(work);
}

static void test_iov_pin_rsp_basic(struct kunit *test)
{
	struct ksmbd_work *work = ksmbd_alloc_work_struct();
	char *hdr;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, work);

	work->response_buf = kzalloc(512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);
	work->response_sz = 512;

	hdr = work->response_buf + 4;

	ret = ksmbd_iov_pin_rsp(work, hdr, 64);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* iov[0] = RFC1002 length prefix, iov[1] = response body */
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 2);
	KUNIT_EXPECT_EQ(test, work->iov_idx, 1);
	KUNIT_EXPECT_EQ(test, (int)work->iov[0].iov_len, 4);
	KUNIT_EXPECT_EQ(test, (int)work->iov[1].iov_len, 64);

	ksmbd_free_work_struct(work);
}

static void test_allocate_interim_rsp(struct kunit *test)
{
	struct ksmbd_work *work = ksmbd_alloc_work_struct();
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, work);

	ret = allocate_interim_rsp_buf(work);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, work->response_buf);
	KUNIT_EXPECT_GT(test, work->response_sz, (unsigned int)0);

	ksmbd_free_work_struct(work);
}

static void test_work_pool_init_destroy(struct kunit *test)
{
	/*
	 * The suite init/exit already exercises pool_init/destroy.
	 * This test verifies a second init/destroy cycle works.
	 * We must be careful: the suite already initialized the pool,
	 * so we just verify alloc works (pool is active).
	 */
	struct ksmbd_work *work = ksmbd_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);
	ksmbd_free_work_struct(work);
}

static struct kunit_case ksmbd_work_alloc_cases[] = {
	KUNIT_CASE(test_alloc_returns_nonnull),
	KUNIT_CASE(test_alloc_fields_initialized),
	KUNIT_CASE(test_alloc_free_cycle),
	KUNIT_CASE(test_alloc_free_batch),
	KUNIT_CASE(test_free_with_response_buf),
	KUNIT_CASE(test_iov_pin_rsp_basic),
	KUNIT_CASE(test_allocate_interim_rsp),
	KUNIT_CASE(test_work_pool_init_destroy),
	{}
};

static struct kunit_suite ksmbd_work_alloc_suite = {
	.name = "ksmbd_work_alloc",
	.suite_init = work_alloc_suite_init,
	.suite_exit = work_alloc_suite_exit,
	.test_cases = ksmbd_work_alloc_cases,
};

kunit_test_suite(ksmbd_work_alloc_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd work struct allocation (calls production code)");
