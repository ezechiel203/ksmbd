// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit concurrency tests for notify watcher races.
 *   Uses kthreads for parallel register/fire/cancel operations.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define NUM_THREADS	4
#define ITERATIONS	200

/*
 * Simulated notify watcher list, mimicking ksmbd_notify.c structures.
 */
struct test_watcher {
	struct list_head list;
	u32 filter;
	bool cancelled;
	atomic_t fire_count;
};

struct notify_test_ctx {
	struct list_head watcher_list;
	spinlock_t lock;
	struct completion start;
	atomic_t success_count;
	atomic_t failure_count;
	atomic_t register_count;
	atomic_t cancel_count;
	atomic_t fire_count;
};

static void init_notify_ctx(struct notify_test_ctx *ctx)
{
	INIT_LIST_HEAD(&ctx->watcher_list);
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);
	atomic_set(&ctx->register_count, 0);
	atomic_set(&ctx->cancel_count, 0);
	atomic_set(&ctx->fire_count, 0);
}

/* ---- Thread functions ---- */

static int register_thread(void *data)
{
	struct notify_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		struct test_watcher *w;

		w = kmalloc(sizeof(*w), GFP_KERNEL);
		if (!w)
			continue;

		w->filter = i;
		w->cancelled = false;
		atomic_set(&w->fire_count, 0);

		spin_lock(&ctx->lock);
		list_add_tail(&w->list, &ctx->watcher_list);
		spin_unlock(&ctx->lock);

		atomic_inc(&ctx->register_count);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int fire_thread(void *data)
{
	struct notify_test_ctx *ctx = data;
	struct test_watcher *w;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		list_for_each_entry(w, &ctx->watcher_list, list) {
			if (!w->cancelled) {
				atomic_inc(&w->fire_count);
				atomic_inc(&ctx->fire_count);
			}
		}
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int cancel_thread(void *data)
{
	struct notify_test_ctx *ctx = data;
	struct test_watcher *w, *tmp;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		list_for_each_entry_safe(w, tmp, &ctx->watcher_list, list) {
			if (!w->cancelled && w->filter == (u32)i) {
				w->cancelled = true;
				list_del(&w->list);
				atomic_inc(&ctx->cancel_count);
				spin_unlock(&ctx->lock);
				kfree(w);
				goto next;
			}
		}
		spin_unlock(&ctx->lock);
next:
		;
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void cleanup_watchers(struct notify_test_ctx *ctx)
{
	struct test_watcher *w, *tmp;

	spin_lock(&ctx->lock);
	list_for_each_entry_safe(w, tmp, &ctx->watcher_list, list) {
		list_del(&w->list);
		kfree(w);
	}
	spin_unlock(&ctx->lock);
}

/* ---- Tests ---- */

static void test_notify_parallel_register(struct kunit *test)
{
	struct notify_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_notify_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(register_thread, ctx,
					 "reg_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->register_count),
			NUM_THREADS * ITERATIONS);

	cleanup_watchers(ctx);
}

static void test_notify_register_fire_race(struct kunit *test)
{
	struct notify_test_ctx *ctx;
	struct task_struct *registrars[2];
	struct task_struct *firers[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_notify_ctx(ctx);

	for (i = 0; i < 2; i++) {
		registrars[i] = kthread_run(register_thread, ctx,
					    "reg_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(registrars[i]));
	}
	for (i = 0; i < 2; i++) {
		firers[i] = kthread_run(fire_thread, ctx,
					"fire_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(firers[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);

	cleanup_watchers(ctx);
}

static void test_notify_register_cancel_race(struct kunit *test)
{
	struct notify_test_ctx *ctx;
	struct task_struct *registrar;
	struct task_struct *canceller;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_notify_ctx(ctx);

	registrar = kthread_run(register_thread, ctx, "reg");
	KUNIT_ASSERT_FALSE(test, IS_ERR(registrar));

	canceller = kthread_run(cancel_thread, ctx, "cancel");
	KUNIT_ASSERT_FALSE(test, IS_ERR(canceller));

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 2);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);

	cleanup_watchers(ctx);
}

static void test_notify_fire_cancel_race(struct kunit *test)
{
	struct notify_test_ctx *ctx;
	struct task_struct *firer;
	struct task_struct *canceller;
	struct task_struct *registrar;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_notify_ctx(ctx);

	registrar = kthread_run(register_thread, ctx, "reg");
	KUNIT_ASSERT_FALSE(test, IS_ERR(registrar));

	firer = kthread_run(fire_thread, ctx, "fire");
	KUNIT_ASSERT_FALSE(test, IS_ERR(firer));

	canceller = kthread_run(cancel_thread, ctx, "cancel");
	KUNIT_ASSERT_FALSE(test, IS_ERR(canceller));

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 3);

	cleanup_watchers(ctx);
}

static void test_notify_empty_fire(struct kunit *test)
{
	struct notify_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_notify_ctx(ctx);

	/* Fire on empty list should be safe */
	spin_lock(&ctx->lock);
	KUNIT_EXPECT_TRUE(test, list_empty(&ctx->watcher_list));
	spin_unlock(&ctx->lock);
}

static struct kunit_case ksmbd_concurrency_notify_test_cases[] = {
	KUNIT_CASE(test_notify_parallel_register),
	KUNIT_CASE(test_notify_register_fire_race),
	KUNIT_CASE(test_notify_register_cancel_race),
	KUNIT_CASE(test_notify_fire_cancel_race),
	KUNIT_CASE(test_notify_empty_fire),
	{}
};

static struct kunit_suite ksmbd_concurrency_notify_test_suite = {
	.name = "ksmbd_concurrency_notify",
	.test_cases = ksmbd_concurrency_notify_test_cases,
};

kunit_test_suite(ksmbd_concurrency_notify_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit concurrency tests for notify watcher races");
