// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ksmbd_work allocation, IOV pinning, and lifecycle
 *   (ksmbd_work.c)
 *
 *   These tests replicate the IOV pinning and work struct logic
 *   from ksmbd_work.c without linking to the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ── Replicated constants ─── */

#define TEST_KSMBD_NO_FID		((__u64)-1)
#define TEST_IOV_ALLOC_CNT		4
#define TEST_MAX_CIFS_SMALL_BUF_SZ	448

/* ── Simplified work struct for testing ─── */

struct test_aux_read {
	void			*buf;
	struct list_head	entry;
};

struct test_work {
	void			*request_buf;
	void			*response_buf;
	unsigned int		response_sz;
	void			*tr_buf;

	struct kvec		*iov;
	int			iov_alloc_cnt;
	int			iov_cnt;
	int			iov_idx;

	u64			compound_fid;
	u64			compound_pfid;

	struct list_head	request_entry;
	struct list_head	async_request_entry;
	struct list_head	fp_entry;
	struct list_head	aux_read_list;

	bool			send_no_response;
	int			async_id;
};

/* ── Replicated alloc/free logic ─── */

static struct test_work *test_alloc_work_struct(void)
{
	struct test_work *work = kzalloc(sizeof(*work), GFP_KERNEL);

	if (work) {
		work->compound_fid = TEST_KSMBD_NO_FID;
		work->compound_pfid = TEST_KSMBD_NO_FID;
		INIT_LIST_HEAD(&work->request_entry);
		INIT_LIST_HEAD(&work->async_request_entry);
		INIT_LIST_HEAD(&work->fp_entry);
		INIT_LIST_HEAD(&work->aux_read_list);
		work->iov_alloc_cnt = TEST_IOV_ALLOC_CNT;
		work->iov = kzalloc(sizeof(struct kvec) * work->iov_alloc_cnt,
				    GFP_KERNEL);
		if (!work->iov) {
			kfree(work);
			work = NULL;
		}
	}
	return work;
}

static void test_free_work_struct(struct test_work *work)
{
	struct test_aux_read *ar, *tmp;

	list_for_each_entry_safe(ar, tmp, &work->aux_read_list, entry) {
		kfree(ar->buf);
		list_del(&ar->entry);
		kfree(ar);
	}

	kvfree(work->response_buf);
	kvfree(work->tr_buf);
	kvfree(work->request_buf);
	kfree(work->iov);
	kfree(work);
}

/* ── Replicated IOV pinning logic ─── */

static inline void __test_iov_pin(struct test_work *work, void *ib,
				  unsigned int ib_len)
{
	work->iov_idx++;
	work->iov[work->iov_idx].iov_base = ib;
	work->iov[work->iov_idx].iov_len = ib_len;
	work->iov_cnt++;
}

static int __test_iov_pin_rsp(struct test_work *work, void *ib, int len,
			      void *aux_buf, unsigned int aux_size)
{
	struct test_aux_read *ar = NULL;
	int need_iov_cnt = 1;

	if (aux_size) {
		need_iov_cnt++;
		ar = kmalloc(sizeof(struct test_aux_read), GFP_KERNEL);
		if (!ar)
			return -ENOMEM;
	}

	if (work->iov_alloc_cnt < work->iov_idx + 1 + need_iov_cnt) {
		struct kvec *new;

		work->iov_alloc_cnt += 4;
		new = krealloc(work->iov,
			       sizeof(struct kvec) * work->iov_alloc_cnt,
			       GFP_KERNEL | __GFP_ZERO);
		if (!new) {
			kfree(ar);
			work->iov_alloc_cnt -= 4;
			return -ENOMEM;
		}
		work->iov = new;
	}

	/* Plus rfc_length size on first iov */
	if (!work->iov_idx) {
		work->iov[work->iov_idx].iov_base = work->response_buf;
		*(__be32 *)work->iov[0].iov_base = 0;
		work->iov[work->iov_idx].iov_len = 4;
		work->iov_cnt++;
	}

	__test_iov_pin(work, ib, len);

	if (aux_size) {
		__test_iov_pin(work, aux_buf, aux_size);
		ar->buf = aux_buf;
		list_add(&ar->entry, &work->aux_read_list);
	}

	return 0;
}

static int test_iov_pin_rsp(struct test_work *work, void *ib, int len)
{
	return __test_iov_pin_rsp(work, ib, len, NULL, 0);
}

static int test_iov_pin_rsp_read(struct test_work *work, void *ib, int len,
				 void *aux_buf, unsigned int aux_size)
{
	return __test_iov_pin_rsp(work, ib, len, aux_buf, aux_size);
}

/* ──────────────────────────────────────────────────────────
 * Allocation and initialization tests
 * ────────────────────────────────────────────────────────── */

static void test_work_alloc_basic(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);
	KUNIT_EXPECT_EQ(test, work->compound_fid, TEST_KSMBD_NO_FID);
	KUNIT_EXPECT_EQ(test, work->compound_pfid, TEST_KSMBD_NO_FID);
	KUNIT_EXPECT_EQ(test, work->iov_alloc_cnt, TEST_IOV_ALLOC_CNT);
	KUNIT_EXPECT_NOT_NULL(test, work->iov);
	KUNIT_EXPECT_TRUE(test, list_empty(&work->request_entry));
	KUNIT_EXPECT_TRUE(test, list_empty(&work->async_request_entry));
	KUNIT_EXPECT_TRUE(test, list_empty(&work->fp_entry));
	KUNIT_EXPECT_TRUE(test, list_empty(&work->aux_read_list));
	test_free_work_struct(work);
}

static void test_work_free_releases_all_buffers(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(256, GFP_KERNEL);
	work->request_buf = kzalloc(256, GFP_KERNEL);
	work->tr_buf = kzalloc(256, GFP_KERNEL);

	/* This should not leak (verified by kasan/kfence in CI) */
	test_free_work_struct(work);
}

static void test_work_free_with_aux_read(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();
	struct test_aux_read *ar;

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(256, GFP_KERNEL);

	ar = kmalloc(sizeof(*ar), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ar);
	ar->buf = kzalloc(64, GFP_KERNEL);
	list_add(&ar->entry, &work->aux_read_list);

	test_free_work_struct(work);
}

/* ──────────────────────────────────────────────────────────
 * IOV pinning tests
 * ────────────────────────────────────────────────────────── */

static void test_iov_pin_rsp_first_call(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();
	char *rsp_hdr;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	rsp_hdr = work->response_buf + 4;
	memset(rsp_hdr, 0xAA, 64);

	ret = test_iov_pin_rsp(work, rsp_hdr, 64);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* iov[0] = RFC1002, iov[1] = response */
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 2);
	KUNIT_EXPECT_EQ(test, work->iov_idx, 1);
	KUNIT_EXPECT_EQ(test, (int)work->iov[0].iov_len, 4);
	KUNIT_EXPECT_EQ(test, (int)work->iov[1].iov_len, 64);
	test_free_work_struct(work);
}

static void test_iov_pin_rsp_second_call(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();
	char *rsp1, *rsp2;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	rsp1 = work->response_buf + 4;
	rsp2 = work->response_buf + 68;

	ret = test_iov_pin_rsp(work, rsp1, 64);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = test_iov_pin_rsp(work, rsp2, 64);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* iov[0] = RFC1002, iov[1] = first rsp, iov[2] = second rsp */
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 3);
	KUNIT_EXPECT_EQ(test, work->iov_idx, 2);
	test_free_work_struct(work);
}

static void test_iov_pin_rsp_read_with_aux(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();
	char *rsp_hdr;
	void *aux;
	int ret;

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	rsp_hdr = work->response_buf + 4;
	aux = kzalloc(128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, aux);

	ret = test_iov_pin_rsp_read(work, rsp_hdr, 64, aux, 128);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* iov[0] = RFC1002, iov[1] = header, iov[2] = aux */
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 3);
	KUNIT_EXPECT_EQ(test, work->iov_idx, 2);
	KUNIT_EXPECT_FALSE(test, list_empty(&work->aux_read_list));
	test_free_work_struct(work);
}

static void test_iov_pin_rsp_realloc(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();
	char *bufs[6];
	int ret, i;

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	for (i = 0; i < 6; i++)
		bufs[i] = work->response_buf + 4 + i * 64;

	/* Pin 6 times to exceed initial iov_alloc_cnt of 4 */
	for (i = 0; i < 6; i++) {
		ret = test_iov_pin_rsp(work, bufs[i], 64);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	/* iov[0]=RFC1002 + 6 responses = 7 total */
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 7);
	KUNIT_EXPECT_GE(test, work->iov_alloc_cnt, 7);
	test_free_work_struct(work);
}

/* ──────────────────────────────────────────────────────────
 * Interim response buffer test
 * ────────────────────────────────────────────────────────── */

static void test_allocate_interim_rsp_buf(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);

	work->response_buf = kzalloc(TEST_MAX_CIFS_SMALL_BUF_SZ, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);
	work->response_sz = TEST_MAX_CIFS_SMALL_BUF_SZ;

	KUNIT_EXPECT_NOT_NULL(test, work->response_buf);
	KUNIT_EXPECT_EQ(test, work->response_sz,
			(unsigned int)TEST_MAX_CIFS_SMALL_BUF_SZ);
	test_free_work_struct(work);
}

/* ──────────────────────────────────────────────────────────
 * Work pool lifecycle tests (replicated minimal logic)
 * ────────────────────────────────────────────────────────── */

static void test_work_pool_init_destroy(struct kunit *test)
{
	/*
	 * Replicate: allocate and free many work structs to simulate
	 * pool usage. Verify no crashes or leaks.
	 */
	struct test_work *works[32];
	int i;

	for (i = 0; i < 32; i++) {
		works[i] = test_alloc_work_struct();
		KUNIT_ASSERT_NOT_NULL(test, works[i]);
	}

	for (i = 0; i < 32; i++)
		test_free_work_struct(works[i]);
}

static void test_work_send_no_response_flag(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);
	KUNIT_EXPECT_FALSE(test, work->send_no_response);

	work->send_no_response = true;
	KUNIT_EXPECT_TRUE(test, work->send_no_response);
	test_free_work_struct(work);
}

static void test_work_async_id_tracking(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);
	KUNIT_EXPECT_EQ(test, work->async_id, 0);

	work->async_id = 42;
	KUNIT_EXPECT_EQ(test, work->async_id, 42);

	/* Simulate release: clear async_id */
	work->async_id = 0;
	KUNIT_EXPECT_EQ(test, work->async_id, 0);
	test_free_work_struct(work);
}

static void test_iov_pin_rsp_realloc_stress(struct kunit *test)
{
	/*
	 * Pin 16 times to exercise multiple reallocations.
	 * Initial alloc is 4, so we need reallocs at 4, 8, 12, 16.
	 */
	struct test_work *work = test_alloc_work_struct();
	int ret, i;

	KUNIT_ASSERT_NOT_NULL(test, work);
	work->response_buf = kzalloc(8192, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, work->response_buf);

	for (i = 0; i < 16; i++) {
		char *ptr = work->response_buf + 4 + i * 32;

		ret = test_iov_pin_rsp(work, ptr, 32);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	/* iov[0]=RFC1002 + 16 responses = 17 total */
	KUNIT_EXPECT_EQ(test, work->iov_cnt, 17);
	KUNIT_EXPECT_GE(test, work->iov_alloc_cnt, 17);
	test_free_work_struct(work);
}

static void test_work_compound_fid_lifecycle(struct kunit *test)
{
	struct test_work *work = test_alloc_work_struct();

	KUNIT_ASSERT_NOT_NULL(test, work);

	/* Initial state: no FID */
	KUNIT_EXPECT_EQ(test, work->compound_fid, TEST_KSMBD_NO_FID);

	/* Set FID (simulate CREATE response) */
	work->compound_fid = 0x1234;
	work->compound_pfid = 0x5678;
	KUNIT_EXPECT_NE(test, work->compound_fid, TEST_KSMBD_NO_FID);

	/* Reset FID */
	work->compound_fid = TEST_KSMBD_NO_FID;
	work->compound_pfid = TEST_KSMBD_NO_FID;
	KUNIT_EXPECT_EQ(test, work->compound_fid, TEST_KSMBD_NO_FID);

	test_free_work_struct(work);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_work_test_cases[] = {
	/* Allocation */
	KUNIT_CASE(test_work_alloc_basic),
	KUNIT_CASE(test_work_free_releases_all_buffers),
	KUNIT_CASE(test_work_free_with_aux_read),
	/* IOV pinning */
	KUNIT_CASE(test_iov_pin_rsp_first_call),
	KUNIT_CASE(test_iov_pin_rsp_second_call),
	KUNIT_CASE(test_iov_pin_rsp_read_with_aux),
	KUNIT_CASE(test_iov_pin_rsp_realloc),
	/* Interim response buffer */
	KUNIT_CASE(test_allocate_interim_rsp_buf),
	/* Pool lifecycle */
	KUNIT_CASE(test_work_pool_init_destroy),
	KUNIT_CASE(test_work_send_no_response_flag),
	KUNIT_CASE(test_work_async_id_tracking),
	KUNIT_CASE(test_iov_pin_rsp_realloc_stress),
	KUNIT_CASE(test_work_compound_fid_lifecycle),
	{}
};

static struct kunit_suite ksmbd_work_test_suite = {
	.name = "ksmbd_work",
	.test_cases = ksmbd_work_test_cases,
};

kunit_test_suite(ksmbd_work_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd work struct and IOV management");
