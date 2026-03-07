// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit concurrency tests for connection state machine races.
 *   Uses kthreads racing state transitions like ksmbd does internally.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define NUM_THREADS	4
#define ITERATIONS	500

/*
 * Simulated connection states matching ksmbd's connection.h:
 *   NEED_NEGOTIATE -> GOOD -> DISCONNECTING -> EXITING
 */
enum test_conn_state {
	STATE_NEW = 0,
	STATE_NEED_NEGOTIATE,
	STATE_GOOD,
	STATE_DISCONNECTING,
	STATE_EXITING,
};

struct state_test_ctx {
	atomic_t state;
	spinlock_t lock;
	struct completion start;
	atomic_t success_count;
	atomic_t failure_count;
	atomic_t transition_count;
};

static void init_state_ctx(struct state_test_ctx *ctx)
{
	atomic_set(&ctx->state, STATE_NEW);
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);
	atomic_set(&ctx->transition_count, 0);
}

/* Try to transition: only succeeds if current state matches expected */
static bool try_transition(struct state_test_ctx *ctx,
			   enum test_conn_state expected,
			   enum test_conn_state new_state)
{
	bool success = false;

	spin_lock(&ctx->lock);
	if (atomic_read(&ctx->state) == expected) {
		atomic_set(&ctx->state, new_state);
		success = true;
	}
	spin_unlock(&ctx->lock);

	return success;
}

/* ---- Thread functions ---- */

static int negotiate_thread(void *data)
{
	struct state_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (try_transition(ctx, STATE_NEW, STATE_NEED_NEGOTIATE))
			atomic_inc(&ctx->transition_count);
		if (try_transition(ctx, STATE_NEED_NEGOTIATE, STATE_GOOD))
			atomic_inc(&ctx->transition_count);
		/* Reset for next iteration */
		try_transition(ctx, STATE_GOOD, STATE_NEW);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int disconnect_thread(void *data)
{
	struct state_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (try_transition(ctx, STATE_GOOD, STATE_DISCONNECTING))
			atomic_inc(&ctx->transition_count);
		/* Reset back */
		try_transition(ctx, STATE_DISCONNECTING, STATE_NEW);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int read_state_thread(void *data)
{
	struct state_test_ctx *ctx = data;
	int i;
	int state;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		state = atomic_read(&ctx->state);
		if (state < STATE_NEW || state > STATE_EXITING)
			atomic_inc(&ctx->failure_count);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int full_lifecycle_thread(void *data)
{
	struct state_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		try_transition(ctx, STATE_NEW, STATE_NEED_NEGOTIATE);
		try_transition(ctx, STATE_NEED_NEGOTIATE, STATE_GOOD);
		try_transition(ctx, STATE_GOOD, STATE_DISCONNECTING);
		try_transition(ctx, STATE_DISCONNECTING, STATE_EXITING);
		/* Reset */
		spin_lock(&ctx->lock);
		atomic_set(&ctx->state, STATE_NEW);
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

/* ---- Tests ---- */

static void test_state_parallel_negotiate(struct kunit *test)
{
	struct state_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(negotiate_thread, ctx,
					 "neg_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* State should be valid */
	KUNIT_EXPECT_GE(test, atomic_read(&ctx->state), (int)STATE_NEW);
	KUNIT_EXPECT_LE(test, atomic_read(&ctx->state), (int)STATE_EXITING);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

static void test_state_negotiate_disconnect_race(struct kunit *test)
{
	struct state_test_ctx *ctx;
	struct task_struct *neg_threads[2];
	struct task_struct *disc_threads[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);

	for (i = 0; i < 2; i++) {
		neg_threads[i] = kthread_run(negotiate_thread, ctx,
					     "neg_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(neg_threads[i]));
	}
	for (i = 0; i < 2; i++) {
		disc_threads[i] = kthread_run(disconnect_thread, ctx,
					      "disc_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(disc_threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
}

static void test_state_read_while_transitioning(struct kunit *test)
{
	struct state_test_ctx *ctx;
	struct task_struct *writers[2];
	struct task_struct *readers[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);

	for (i = 0; i < 2; i++) {
		writers[i] = kthread_run(negotiate_thread, ctx,
					 "write_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(writers[i]));
	}
	for (i = 0; i < 2; i++) {
		readers[i] = kthread_run(read_state_thread, ctx,
					 "read_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(readers[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);
}

static void test_state_full_lifecycle_race(struct kunit *test)
{
	struct state_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(full_lifecycle_thread, ctx,
					 "life_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- Test: Only one thread wins a state transition ---- */

struct single_winner_ctx {
	atomic_t state;
	spinlock_t lock;
	struct completion start;
	atomic_t winner_count;
};

static int single_winner_thread(void *data)
{
	struct single_winner_ctx *ctx = data;
	bool won;

	wait_for_completion(&ctx->start);

	spin_lock(&ctx->lock);
	if (atomic_read(&ctx->state) == STATE_GOOD) {
		atomic_set(&ctx->state, STATE_DISCONNECTING);
		won = true;
	} else {
		won = false;
	}
	spin_unlock(&ctx->lock);

	if (won)
		atomic_inc(&ctx->winner_count);

	return 0;
}

static void test_state_single_winner(struct kunit *test)
{
	struct single_winner_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	atomic_set(&ctx->state, STATE_GOOD);
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->winner_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(single_winner_thread, ctx,
					 "win_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(100);

	/* Exactly one thread should win */
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->winner_count), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->state),
			(int)STATE_DISCONNECTING);
}

/* ---- Test: CAS-style transition ---- */

static void test_state_cas_transition(struct kunit *test)
{
	struct state_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);

	KUNIT_EXPECT_TRUE(test,
		try_transition(ctx, STATE_NEW, STATE_NEED_NEGOTIATE));
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->state),
			(int)STATE_NEED_NEGOTIATE);

	/* Wrong expected state should fail */
	KUNIT_EXPECT_FALSE(test,
		try_transition(ctx, STATE_NEW, STATE_GOOD));
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->state),
			(int)STATE_NEED_NEGOTIATE);
}

static void test_state_invalid_transition_rejected(struct kunit *test)
{
	struct state_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);
	atomic_set(&ctx->state, STATE_GOOD);

	/* Can't go back to NEED_NEGOTIATE from GOOD */
	KUNIT_EXPECT_FALSE(test,
		try_transition(ctx, STATE_NEW, STATE_NEED_NEGOTIATE));
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->state), (int)STATE_GOOD);
}

static void test_state_exiting_is_terminal(struct kunit *test)
{
	struct state_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_state_ctx(ctx);
	atomic_set(&ctx->state, STATE_EXITING);

	/* No transition from EXITING to anything */
	KUNIT_EXPECT_FALSE(test,
		try_transition(ctx, STATE_NEW, STATE_NEED_NEGOTIATE));
	KUNIT_EXPECT_FALSE(test,
		try_transition(ctx, STATE_GOOD, STATE_DISCONNECTING));
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->state), (int)STATE_EXITING);
}

static struct kunit_case ksmbd_concurrency_state_test_cases[] = {
	KUNIT_CASE(test_state_parallel_negotiate),
	KUNIT_CASE(test_state_negotiate_disconnect_race),
	KUNIT_CASE(test_state_read_while_transitioning),
	KUNIT_CASE(test_state_full_lifecycle_race),
	KUNIT_CASE(test_state_single_winner),
	KUNIT_CASE(test_state_cas_transition),
	KUNIT_CASE(test_state_invalid_transition_rejected),
	KUNIT_CASE(test_state_exiting_is_terminal),
	{}
};

static struct kunit_suite ksmbd_concurrency_state_test_suite = {
	.name = "ksmbd_concurrency_state",
	.test_cases = ksmbd_concurrency_state_test_cases,
};

kunit_test_suite(ksmbd_concurrency_state_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit concurrency tests for connection state machine");
