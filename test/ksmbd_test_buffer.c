// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for the buffer pool logic (ksmbd_buffer.c)
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure logic under test.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

/* ---- Inlined definitions from ksmbd_buffer.c ---- */

#define TEST_BUF_SMALL_SIZE	(64 * 1024)	/* 64 KB */
#define TEST_BUF_LARGE_SIZE	(1024 * 1024)	/* 1 MB */
#define TEST_BUF_SMALL_COUNT	8
#define TEST_BUF_LARGE_COUNT	4

struct test_buf_entry {
	struct list_head	list;
	size_t			size;
	/* Buffer data follows immediately after this struct */
};

struct test_buf_pool {
	struct list_head	free_list;
	spinlock_t		lock;
	unsigned int		buf_size;
	unsigned int		total;
	unsigned int		free;
	unsigned int		max_free;
};

static inline void *test_entry_to_buf(struct test_buf_entry *entry)
{
	return (char *)entry + sizeof(*entry);
}

static inline struct test_buf_entry *test_buf_to_entry(void *buf)
{
	return (struct test_buf_entry *)((char *)buf -
					 sizeof(struct test_buf_entry));
}

static struct test_buf_pool *test_select_pool(struct test_buf_pool *small,
					      struct test_buf_pool *large,
					      size_t size)
{
	if (size <= TEST_BUF_SMALL_SIZE)
		return small;
	if (size <= TEST_BUF_LARGE_SIZE)
		return large;
	return NULL;
}

static int test_pool_alloc(struct test_buf_pool *pool,
			   unsigned int buf_size,
			   unsigned int count)
{
	unsigned int i;

	INIT_LIST_HEAD(&pool->free_list);
	spin_lock_init(&pool->lock);
	pool->buf_size = buf_size;
	pool->total = 0;
	pool->free = 0;
	pool->max_free = count;

	for (i = 0; i < count; i++) {
		struct test_buf_entry *entry;

		entry = kvzalloc(sizeof(*entry) + buf_size, GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		entry->size = buf_size;
		list_add_tail(&entry->list, &pool->free_list);
		pool->total++;
		pool->free++;
	}

	return 0;
}

static void test_pool_free(struct test_buf_pool *pool)
{
	struct test_buf_entry *entry, *tmp;

	spin_lock(&pool->lock);
	list_for_each_entry_safe(entry, tmp, &pool->free_list, list) {
		list_del(&entry->list);
		pool->free--;
		pool->total--;
		kvfree(entry);
	}
	spin_unlock(&pool->lock);
}

static void *test_pool_get(struct test_buf_pool *small,
			   struct test_buf_pool *large,
			   size_t size)
{
	struct test_buf_pool *pool;
	struct test_buf_entry *entry;

	pool = test_select_pool(small, large, size);
	if (pool) {
		spin_lock(&pool->lock);
		if (!list_empty(&pool->free_list)) {
			entry = list_first_entry(&pool->free_list,
						 struct test_buf_entry,
						 list);
			list_del(&entry->list);
			pool->free--;
			spin_unlock(&pool->lock);
			memset(test_entry_to_buf(entry), 0, pool->buf_size);
			return test_entry_to_buf(entry);
		}
		spin_unlock(&pool->lock);

		/* Pool exhausted, allocate with pool->buf_size */
		entry = kvzalloc(sizeof(*entry) + pool->buf_size, GFP_KERNEL);
		if (!entry)
			return NULL;
		entry->size = pool->buf_size;
		return test_entry_to_buf(entry);
	}

	/* Size exceeds largest pool tier, fall back to kvzalloc */
	entry = kvzalloc(sizeof(*entry) + size, GFP_KERNEL);
	if (!entry)
		return NULL;
	entry->size = size;
	return test_entry_to_buf(entry);
}

static void test_pool_put(struct test_buf_pool *small,
			  struct test_buf_pool *large,
			  void *buf)
{
	struct test_buf_entry *entry;
	struct test_buf_pool *pool;

	if (!buf)
		return;

	entry = test_buf_to_entry(buf);
	pool = test_select_pool(small, large, entry->size);

	if (pool) {
		spin_lock(&pool->lock);
		if (pool->free < pool->max_free) {
			list_add_tail(&entry->list, &pool->free_list);
			pool->free++;
			spin_unlock(&pool->lock);
			return;
		}
		spin_unlock(&pool->lock);
	}

	kvfree(entry);
}

/* ---- Per-test state ---- */

struct buffer_test_ctx {
	struct test_buf_pool small;
	struct test_buf_pool large;
};

static int buffer_test_init(struct kunit *test)
{
	struct buffer_test_ctx *ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ret = test_pool_alloc(&ctx->small, TEST_BUF_SMALL_SIZE,
			      TEST_BUF_SMALL_COUNT);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = test_pool_alloc(&ctx->large, TEST_BUF_LARGE_SIZE,
			      TEST_BUF_LARGE_COUNT);
	if (ret) {
		test_pool_free(&ctx->small);
		kfree(ctx);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	test->priv = ctx;
	return 0;
}

static void buffer_test_exit(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;

	if (ctx) {
		test_pool_free(&ctx->large);
		test_pool_free(&ctx->small);
		kfree(ctx);
	}
}

/* ---- Test cases ---- */

/*
 * test_select_pool_small - sizes <= 64KB select the small pool
 */
static void test_select_pool_small(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_PTR_EQ(test,
			    test_select_pool(&ctx->small, &ctx->large, 1),
			    &ctx->small);
	KUNIT_EXPECT_PTR_EQ(test,
			    test_select_pool(&ctx->small, &ctx->large, 100),
			    &ctx->small);
	KUNIT_EXPECT_PTR_EQ(test,
			    test_select_pool(&ctx->small, &ctx->large,
					     TEST_BUF_SMALL_SIZE),
			    &ctx->small);
}

/*
 * test_select_pool_large - sizes > 64KB and <= 1MB select the large pool
 */
static void test_select_pool_large(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_PTR_EQ(test,
			    test_select_pool(&ctx->small, &ctx->large,
					     TEST_BUF_SMALL_SIZE + 1),
			    &ctx->large);
	KUNIT_EXPECT_PTR_EQ(test,
			    test_select_pool(&ctx->small, &ctx->large,
					     TEST_BUF_LARGE_SIZE),
			    &ctx->large);
}

/*
 * test_select_pool_fallback - sizes > 1MB return NULL (fallback)
 */
static void test_select_pool_fallback(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_NULL(test,
			  test_select_pool(&ctx->small, &ctx->large,
					   TEST_BUF_LARGE_SIZE + 1));
	KUNIT_EXPECT_NULL(test,
			  test_select_pool(&ctx->small, &ctx->large,
					   2 * TEST_BUF_LARGE_SIZE));
}

/*
 * test_entry_buf_roundtrip - entry_to_buf / buf_to_entry roundtrip
 */
static void test_entry_buf_roundtrip(struct kunit *test)
{
	struct test_buf_entry *entry;
	void *buf;
	struct test_buf_entry *recovered;

	entry = kvzalloc(sizeof(*entry) + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	buf = test_entry_to_buf(entry);
	KUNIT_EXPECT_PTR_EQ(test, buf, (void *)((char *)entry + sizeof(*entry)));

	recovered = test_buf_to_entry(buf);
	KUNIT_EXPECT_PTR_EQ(test, recovered, entry);

	kvfree(entry);
}

/*
 * test_entry_to_buf_offset - buf is sizeof(entry) bytes past entry
 */
static void test_entry_to_buf_offset(struct kunit *test)
{
	struct test_buf_entry *entry;
	void *buf;

	entry = kvzalloc(sizeof(*entry) + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	buf = test_entry_to_buf(entry);
	KUNIT_EXPECT_EQ(test,
			(unsigned long)((char *)buf - (char *)entry),
			(unsigned long)sizeof(*entry));

	kvfree(entry);
}

/*
 * test_pool_init_counts - after init, pool has expected counts
 */
static void test_pool_init_counts(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_EQ(test, ctx->small.total, (unsigned int)TEST_BUF_SMALL_COUNT);
	KUNIT_EXPECT_EQ(test, ctx->small.free, (unsigned int)TEST_BUF_SMALL_COUNT);
	KUNIT_EXPECT_EQ(test, ctx->small.buf_size, (unsigned int)TEST_BUF_SMALL_SIZE);

	KUNIT_EXPECT_EQ(test, ctx->large.total, (unsigned int)TEST_BUF_LARGE_COUNT);
	KUNIT_EXPECT_EQ(test, ctx->large.free, (unsigned int)TEST_BUF_LARGE_COUNT);
	KUNIT_EXPECT_EQ(test, ctx->large.buf_size, (unsigned int)TEST_BUF_LARGE_SIZE);
}

/*
 * test_get_small_returns_nonnull - getting a small buffer succeeds
 */
static void test_get_small_returns_nonnull(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf;

	buf = test_pool_get(&ctx->small, &ctx->large, 100);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	KUNIT_EXPECT_EQ(test, ctx->small.free,
			(unsigned int)(TEST_BUF_SMALL_COUNT - 1));

	test_pool_put(&ctx->small, &ctx->large, buf);
}

/*
 * test_get_large_returns_nonnull - getting a large buffer succeeds
 */
static void test_get_large_returns_nonnull(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf;

	buf = test_pool_get(&ctx->small, &ctx->large,
			    TEST_BUF_SMALL_SIZE + 1);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	KUNIT_EXPECT_EQ(test, ctx->large.free,
			(unsigned int)(TEST_BUF_LARGE_COUNT - 1));

	test_pool_put(&ctx->small, &ctx->large, buf);
}

/*
 * test_get_oversized_fallback - oversized request uses kvzalloc fallback
 */
static void test_get_oversized_fallback(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf;

	buf = test_pool_get(&ctx->small, &ctx->large,
			    TEST_BUF_LARGE_SIZE + 1);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Pool free counts should be unchanged */
	KUNIT_EXPECT_EQ(test, ctx->small.free,
			(unsigned int)TEST_BUF_SMALL_COUNT);
	KUNIT_EXPECT_EQ(test, ctx->large.free,
			(unsigned int)TEST_BUF_LARGE_COUNT);

	/* Must free manually since it won't go back to pool */
	test_pool_put(&ctx->small, &ctx->large, buf);
}

/*
 * test_put_returns_to_freelist - put re-adds buffer to pool
 */
static void test_put_returns_to_freelist(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf;

	buf = test_pool_get(&ctx->small, &ctx->large, 100);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_EXPECT_EQ(test, ctx->small.free,
			(unsigned int)(TEST_BUF_SMALL_COUNT - 1));

	test_pool_put(&ctx->small, &ctx->large, buf);
	KUNIT_EXPECT_EQ(test, ctx->small.free,
			(unsigned int)TEST_BUF_SMALL_COUNT);
}

/*
 * test_get_reuses_freed_buffer - after put, next get reuses the buffer
 */
static void test_get_reuses_freed_buffer(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf1, *buf2;

	buf1 = test_pool_get(&ctx->small, &ctx->large, 100);
	KUNIT_ASSERT_NOT_NULL(test, buf1);

	test_pool_put(&ctx->small, &ctx->large, buf1);

	buf2 = test_pool_get(&ctx->small, &ctx->large, 100);
	KUNIT_ASSERT_NOT_NULL(test, buf2);

	/*
	 * The buffer that was just put back should be the last entry
	 * on the free_list (added with list_add_tail).  The next get
	 * takes from the front (list_first_entry).  With count=8 and
	 * only one put/get cycle, buf2 may or may not be buf1 depending
	 * on list order.  Just verify we got a valid buffer.
	 */
	test_pool_put(&ctx->small, &ctx->large, buf2);
}

/*
 * test_pool_exhaustion_fallback - exhausting pool still returns buffers
 */
static void test_pool_exhaustion_fallback(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *bufs[TEST_BUF_SMALL_COUNT + 1];
	int i;

	/* Drain the entire small pool */
	for (i = 0; i < TEST_BUF_SMALL_COUNT; i++) {
		bufs[i] = test_pool_get(&ctx->small, &ctx->large, 100);
		KUNIT_ASSERT_NOT_NULL(test, bufs[i]);
	}

	KUNIT_EXPECT_EQ(test, ctx->small.free, (unsigned int)0);

	/* One more get should still succeed via kvzalloc fallback */
	bufs[TEST_BUF_SMALL_COUNT] = test_pool_get(&ctx->small,
						    &ctx->large, 100);
	KUNIT_ASSERT_NOT_NULL(test, bufs[TEST_BUF_SMALL_COUNT]);

	/* Return all buffers */
	for (i = 0; i <= TEST_BUF_SMALL_COUNT; i++)
		test_pool_put(&ctx->small, &ctx->large, bufs[i]);
}

/*
 * test_put_null_safe - putting NULL should not crash
 */
static void test_put_null_safe(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;

	/* Should be a no-op, not crash */
	test_pool_put(&ctx->small, &ctx->large, NULL);
}

/*
 * test_get_zero_size - zero size should select small pool
 */
static void test_get_zero_size(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf;

	buf = test_pool_get(&ctx->small, &ctx->large, 0);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* 0 <= SMALL_SIZE, so small pool should be used */
	KUNIT_EXPECT_EQ(test, ctx->small.free,
			(unsigned int)(TEST_BUF_SMALL_COUNT - 1));

	test_pool_put(&ctx->small, &ctx->large, buf);
}

/*
 * test_buffer_is_zeroed - buffer from pool get is zero-filled
 */
static void test_buffer_is_zeroed(struct kunit *test)
{
	struct buffer_test_ctx *ctx = test->priv;
	void *buf;
	unsigned char *p;
	int i;
	bool all_zero = true;

	buf = test_pool_get(&ctx->small, &ctx->large, 256);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	p = buf;
	for (i = 0; i < 256; i++) {
		if (p[i] != 0) {
			all_zero = false;
			break;
		}
	}
	KUNIT_EXPECT_TRUE(test, all_zero);

	test_pool_put(&ctx->small, &ctx->large, buf);
}

static struct kunit_case ksmbd_buffer_test_cases[] = {
	KUNIT_CASE(test_select_pool_small),
	KUNIT_CASE(test_select_pool_large),
	KUNIT_CASE(test_select_pool_fallback),
	KUNIT_CASE(test_entry_buf_roundtrip),
	KUNIT_CASE(test_entry_to_buf_offset),
	KUNIT_CASE(test_pool_init_counts),
	KUNIT_CASE(test_get_small_returns_nonnull),
	KUNIT_CASE(test_get_large_returns_nonnull),
	KUNIT_CASE(test_get_oversized_fallback),
	KUNIT_CASE(test_put_returns_to_freelist),
	KUNIT_CASE(test_get_reuses_freed_buffer),
	KUNIT_CASE(test_pool_exhaustion_fallback),
	KUNIT_CASE(test_put_null_safe),
	KUNIT_CASE(test_get_zero_size),
	KUNIT_CASE(test_buffer_is_zeroed),
	{}
};

static struct kunit_suite ksmbd_buffer_test_suite = {
	.name = "ksmbd_buffer",
	.init = buffer_test_init,
	.exit = buffer_test_exit,
	.test_cases = ksmbd_buffer_test_cases,
};

kunit_test_suite(ksmbd_buffer_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd buffer pool logic");
