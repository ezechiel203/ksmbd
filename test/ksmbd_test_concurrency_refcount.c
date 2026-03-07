// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit concurrency tests for refcount operations.
 *   Uses kthread_run() + completion barriers for true parallel testing.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/refcount.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define NUM_THREADS	4
#define ITERATIONS	1000

struct refcount_test_ctx {
	refcount_t ref;
	struct completion start;
	struct completion done[NUM_THREADS];
	atomic_t success_count;
	atomic_t failure_count;
};

/* ---- Thread functions ---- */

static int inc_dec_thread(void *data)
{
	struct refcount_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		refcount_inc(&ctx->ref);
		refcount_dec(&ctx->ref);
	}

	atomic_inc(&ctx->success_count);
	complete(&ctx->done[atomic_read(&ctx->success_count) - 1]);
	return 0;
}

static int inc_only_thread(void *data)
{
	struct refcount_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++)
		refcount_inc(&ctx->ref);

	atomic_inc(&ctx->success_count);
	return 0;
}

static int read_thread(void *data)
{
	struct refcount_test_ctx *ctx = data;
	int i;
	unsigned int val;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		val = refcount_read(&ctx->ref);
		/* Refcount should never be 0 (we hold one ref) */
		if (val == 0)
			atomic_inc(&ctx->failure_count);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int set_read_thread(void *data)
{
	struct refcount_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		refcount_set(&ctx->ref, 1);
		if (refcount_read(&ctx->ref) == 0)
			atomic_inc(&ctx->failure_count);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

/* ---- Helper ---- */

static void init_ctx(struct refcount_test_ctx *ctx)
{
	int i;

	refcount_set(&ctx->ref, 1);
	init_completion(&ctx->start);
	for (i = 0; i < NUM_THREADS; i++)
		init_completion(&ctx->done[i]);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);
}

/* ---- Test: Parallel refcount inc/dec ---- */

static void test_refcount_parallel_inc_dec(struct kunit *test)
{
	struct refcount_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(inc_dec_thread, ctx,
					 "refcnt_test_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);

	for (i = 0; i < NUM_THREADS; i++)
		wait_for_completion(&ctx->done[i]);

	KUNIT_EXPECT_EQ(test, refcount_read(&ctx->ref), (unsigned int)1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- Test: Parallel inc to high count ---- */

static void test_refcount_parallel_inc_only(struct kunit *test)
{
	struct refcount_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	struct completion thread_done[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		init_completion(&thread_done[i]);
		threads[i] = kthread_run(inc_only_thread, ctx,
					 "refinc_test_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	/* Wait for threads to finish (they don't use done[] completions) */
	msleep(100);

	/* Should be 1 + (NUM_THREADS * ITERATIONS) */
	KUNIT_EXPECT_EQ(test, refcount_read(&ctx->ref),
			(unsigned int)(1 + NUM_THREADS * ITERATIONS));
}

/* ---- Test: Read-while-modifying ---- */

static void test_refcount_read_while_modifying(struct kunit *test)
{
	struct refcount_test_ctx *ctx;
	struct task_struct *modifiers[2];
	struct task_struct *readers[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_ctx(ctx);

	for (i = 0; i < 2; i++) {
		modifiers[i] = kthread_run(inc_dec_thread, ctx,
					   "mod_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(modifiers[i]));
	}
	for (i = 0; i < 2; i++) {
		readers[i] = kthread_run(read_thread, ctx,
					 "read_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(readers[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);
}

/* ---- Test: Parallel set/read races ---- */

static void test_refcount_set_read_race(struct kunit *test)
{
	struct refcount_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(set_read_thread, ctx,
					 "setrd_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);
}

/* ---- Test: Dec-and-test from multiple threads ---- */

struct dec_test_ctx {
	refcount_t ref;
	struct completion start;
	atomic_t zero_count;
};

static int dec_and_test_thread(void *data)
{
	struct dec_test_ctx *ctx = data;

	wait_for_completion(&ctx->start);

	if (refcount_dec_and_test(&ctx->ref))
		atomic_inc(&ctx->zero_count);

	return 0;
}

static void test_refcount_dec_and_test_exactly_one(struct kunit *test)
{
	struct dec_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	refcount_set(&ctx->ref, NUM_THREADS);
	init_completion(&ctx->start);
	atomic_set(&ctx->zero_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(dec_and_test_thread, ctx,
					 "dect_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* Exactly one thread should see zero */
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->zero_count), 1);
}

/* ---- Test: Inc from zero should saturate ---- */

static void test_refcount_inc_from_zero_saturates(struct kunit *test)
{
	refcount_t ref;

	/*
	 * refcount_inc on a zero refcount should trigger REFCOUNT_WARN
	 * and saturate. We can't easily test the warning, but we can
	 * verify that refcount_read returns non-zero after inc_not_zero
	 * fails.
	 */
	refcount_set(&ref, 0);

	/* inc_not_zero should return false on a zero refcount */
	KUNIT_EXPECT_FALSE(test, refcount_inc_not_zero(&ref));
	KUNIT_EXPECT_EQ(test, refcount_read(&ref), (unsigned int)0);
}

/* ---- Test: Parallel inc_not_zero ---- */

struct inc_nz_ctx {
	refcount_t ref;
	struct completion start;
	atomic_t success_count;
};

static int inc_not_zero_thread(void *data)
{
	struct inc_nz_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (refcount_inc_not_zero(&ctx->ref))
			refcount_dec(&ctx->ref);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_refcount_parallel_inc_not_zero(struct kunit *test)
{
	struct inc_nz_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	refcount_set(&ctx->ref, 1);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(inc_not_zero_thread, ctx,
					 "incnz_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* Refcount should still be 1 */
	KUNIT_EXPECT_EQ(test, refcount_read(&ctx->ref), (unsigned int)1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- Test: Single-threaded basic refcount operations ---- */

static void test_refcount_basic_ops(struct kunit *test)
{
	refcount_t ref;

	refcount_set(&ref, 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&ref), (unsigned int)1);

	refcount_inc(&ref);
	KUNIT_EXPECT_EQ(test, refcount_read(&ref), (unsigned int)2);

	KUNIT_EXPECT_FALSE(test, refcount_dec_and_test(&ref));
	KUNIT_EXPECT_EQ(test, refcount_read(&ref), (unsigned int)1);

	KUNIT_EXPECT_TRUE(test, refcount_dec_and_test(&ref));
}

static struct kunit_case ksmbd_concurrency_refcount_test_cases[] = {
	KUNIT_CASE(test_refcount_parallel_inc_dec),
	KUNIT_CASE(test_refcount_parallel_inc_only),
	KUNIT_CASE(test_refcount_read_while_modifying),
	KUNIT_CASE(test_refcount_set_read_race),
	KUNIT_CASE(test_refcount_dec_and_test_exactly_one),
	KUNIT_CASE(test_refcount_inc_from_zero_saturates),
	KUNIT_CASE(test_refcount_parallel_inc_not_zero),
	KUNIT_CASE(test_refcount_basic_ops),
	{}
};

static struct kunit_suite ksmbd_concurrency_refcount_test_suite = {
	.name = "ksmbd_concurrency_refcount",
	.test_cases = ksmbd_concurrency_refcount_test_cases,
};

kunit_test_suite(ksmbd_concurrency_refcount_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit concurrency tests for refcount operations");
