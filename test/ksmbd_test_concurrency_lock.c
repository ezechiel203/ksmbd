// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit concurrency tests for lock contention.
 *   Uses kthreads for parallel lock acquire/release operations.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define NUM_THREADS	4
#define ITERATIONS	1000

/* ---- Spinlock contention ---- */

struct spinlock_test_ctx {
	spinlock_t lock;
	struct completion start;
	atomic_t counter;
	atomic_t success_count;
};

static int spinlock_inc_thread(void *data)
{
	struct spinlock_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		atomic_inc(&ctx->counter);
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_spinlock_parallel_increment(struct kunit *test)
{
	struct spinlock_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->counter, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(spinlock_inc_thread, ctx,
					 "spin_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->counter),
			NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- RW lock: readers + writers ---- */

struct rwlock_test_ctx {
	rwlock_t lock;
	struct completion start;
	int shared_data;
	atomic_t read_count;
	atomic_t write_count;
	atomic_t success_count;
	atomic_t failure_count;
};

static int rwlock_reader_thread(void *data)
{
	struct rwlock_test_ctx *ctx = data;
	int i;
	int val;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		read_lock(&ctx->lock);
		val = ctx->shared_data;
		/* Value should always be consistent (set by writer) */
		if (val < 0)
			atomic_inc(&ctx->failure_count);
		atomic_inc(&ctx->read_count);
		read_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int rwlock_writer_thread(void *data)
{
	struct rwlock_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		write_lock(&ctx->lock);
		ctx->shared_data = i;
		atomic_inc(&ctx->write_count);
		write_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_rwlock_readers_writers(struct kunit *test)
{
	struct rwlock_test_ctx *ctx;
	struct task_struct *readers[2];
	struct task_struct *writers[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	rwlock_init(&ctx->lock);
	init_completion(&ctx->start);
	ctx->shared_data = 0;
	atomic_set(&ctx->read_count, 0);
	atomic_set(&ctx->write_count, 0);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);

	for (i = 0; i < 2; i++) {
		readers[i] = kthread_run(rwlock_reader_thread, ctx,
					 "rd_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(readers[i]));
	}
	for (i = 0; i < 2; i++) {
		writers[i] = kthread_run(rwlock_writer_thread, ctx,
					 "wr_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(writers[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
}

/* ---- Mutex contention ---- */

struct mutex_test_ctx {
	struct mutex lock;
	struct completion start;
	int counter;
	atomic_t success_count;
};

static int mutex_inc_thread(void *data)
{
	struct mutex_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		mutex_lock(&ctx->lock);
		ctx->counter++;
		mutex_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_mutex_parallel_increment(struct kunit *test)
{
	struct mutex_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	mutex_init(&ctx->lock);
	init_completion(&ctx->start);
	ctx->counter = 0;
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(mutex_inc_thread, ctx,
					 "mtx_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, ctx->counter, NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- trylock contention ---- */

struct trylock_test_ctx {
	spinlock_t lock;
	struct completion start;
	atomic_t acquired_count;
	atomic_t failed_count;
	atomic_t success_count;
};

static int trylock_thread(void *data)
{
	struct trylock_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (spin_trylock(&ctx->lock)) {
			atomic_inc(&ctx->acquired_count);
			spin_unlock(&ctx->lock);
		} else {
			atomic_inc(&ctx->failed_count);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_trylock_contention(struct kunit *test)
{
	struct trylock_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->acquired_count, 0);
	atomic_set(&ctx->failed_count, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(trylock_thread, ctx,
					 "try_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* acquired + failed should equal total attempts */
	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->acquired_count) +
		atomic_read(&ctx->failed_count),
		NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- Mixed lock types ---- */

static void test_lock_basic_spinlock(struct kunit *test)
{
	spinlock_t lock;

	spin_lock_init(&lock);

	spin_lock(&lock);
	spin_unlock(&lock);

	KUNIT_SUCCEED(test);
}

static struct kunit_case ksmbd_concurrency_lock_test_cases[] = {
	KUNIT_CASE(test_spinlock_parallel_increment),
	KUNIT_CASE(test_rwlock_readers_writers),
	KUNIT_CASE(test_mutex_parallel_increment),
	KUNIT_CASE(test_trylock_contention),
	KUNIT_CASE(test_lock_basic_spinlock),
	{}
};

static struct kunit_suite ksmbd_concurrency_lock_test_suite = {
	.name = "ksmbd_concurrency_lock",
	.test_cases = ksmbd_concurrency_lock_test_cases,
};

kunit_test_suite(ksmbd_concurrency_lock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit concurrency tests for lock contention");
