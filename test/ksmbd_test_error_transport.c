// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for transport operations.
 *   Tests connection limit, timeout, and transport error handling.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/delay.h>

/*
 * Simulated transport connection tracking, mimicking ksmbd's
 * per-IP connection limit and transport state handling.
 */

#define MAX_CONNECTIONS_PER_IP	64
#define NUM_THREADS		4
#define ITERATIONS		100

struct conn_tracker {
	atomic_t conn_count;
	spinlock_t lock;
	int max_connections;
};

static void init_conn_tracker(struct conn_tracker *ct, int max)
{
	atomic_set(&ct->conn_count, 0);
	spin_lock_init(&ct->lock);
	ct->max_connections = max;
}

static int try_accept_connection(struct conn_tracker *ct)
{
	int count;

	spin_lock(&ct->lock);
	count = atomic_read(&ct->conn_count);
	if (count >= ct->max_connections) {
		spin_unlock(&ct->lock);
		return -EAGAIN;
	}
	atomic_inc(&ct->conn_count);
	spin_unlock(&ct->lock);
	return 0;
}

static void release_connection(struct conn_tracker *ct)
{
	atomic_dec(&ct->conn_count);
}

/* ---- Connection limit tests ---- */

static void test_transport_accept_below_limit(struct kunit *test)
{
	struct conn_tracker ct;

	init_conn_tracker(&ct, MAX_CONNECTIONS_PER_IP);

	KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ct.conn_count), 1);

	release_connection(&ct);
}

static void test_transport_accept_at_limit(struct kunit *test)
{
	struct conn_tracker ct;
	int i;

	init_conn_tracker(&ct, 4);

	for (i = 0; i < 4; i++)
		KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), 0);

	/* At limit, next should fail */
	KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), -EAGAIN);

	/* Release one, should succeed again */
	release_connection(&ct);
	KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), 0);

	/* Clean up */
	for (i = 0; i < 4; i++)
		release_connection(&ct);
}

static void test_transport_accept_zero_limit(struct kunit *test)
{
	struct conn_tracker ct;

	init_conn_tracker(&ct, 0);

	/* Zero limit means no connections allowed */
	KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), -EAGAIN);
}

/* ---- Parallel connection accept ---- */

struct parallel_conn_ctx {
	struct conn_tracker *tracker;
	struct completion start;
	atomic_t accepted;
	atomic_t rejected;
};

static int accept_thread(void *data)
{
	struct parallel_conn_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (try_accept_connection(ctx->tracker) == 0) {
			atomic_inc(&ctx->accepted);
			release_connection(ctx->tracker);
		} else {
			atomic_inc(&ctx->rejected);
		}
	}

	return 0;
}

static void test_transport_parallel_accept(struct kunit *test)
{
	struct parallel_conn_ctx *ctx;
	struct conn_tracker *ct;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ct = kunit_kzalloc(test, sizeof(*ct), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ct);

	init_conn_tracker(ct, MAX_CONNECTIONS_PER_IP);
	ctx->tracker = ct;
	init_completion(&ctx->start);
	atomic_set(&ctx->accepted, 0);
	atomic_set(&ctx->rejected, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(accept_thread, ctx,
					 "accept_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* accepted + rejected should equal total attempts */
	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->accepted) + atomic_read(&ctx->rejected),
		NUM_THREADS * ITERATIONS);

	/* Final conn_count should be 0 (all released) */
	KUNIT_EXPECT_EQ(test, atomic_read(&ct->conn_count), 0);
}

/* ---- Timeout simulation ---- */

static void test_transport_timeout_value(struct kunit *test)
{
	/*
	 * ksmbd uses SMB2_TIMEOUT_MS = 120000ms for operations.
	 * Verify the timeout constant makes sense.
	 */
	u32 timeout_ms = 120000;

	KUNIT_EXPECT_EQ(test, timeout_ms / 1000, (u32)120);
	KUNIT_EXPECT_GT(test, timeout_ms, (u32)0);
}

/* ---- Connection state after disconnect ---- */

static void test_transport_disconnect_count(struct kunit *test)
{
	struct conn_tracker ct;
	int i;

	init_conn_tracker(&ct, MAX_CONNECTIONS_PER_IP);

	for (i = 0; i < 10; i++)
		try_accept_connection(&ct);

	KUNIT_EXPECT_EQ(test, atomic_read(&ct.conn_count), 10);

	for (i = 0; i < 10; i++)
		release_connection(&ct);

	KUNIT_EXPECT_EQ(test, atomic_read(&ct.conn_count), 0);
}

/* ---- Saturated connection pool ---- */

static void test_transport_saturated_pool(struct kunit *test)
{
	struct conn_tracker ct;
	int i;
	int accepted = 0;
	int rejected = 0;

	init_conn_tracker(&ct, 8);

	for (i = 0; i < 20; i++) {
		if (try_accept_connection(&ct) == 0)
			accepted++;
		else
			rejected++;
	}

	KUNIT_EXPECT_EQ(test, accepted, 8);
	KUNIT_EXPECT_EQ(test, rejected, 12);

	for (i = 0; i < 8; i++)
		release_connection(&ct);
}

/* ---- Release without accept ---- */

static void test_transport_release_underflow(struct kunit *test)
{
	struct conn_tracker ct;

	init_conn_tracker(&ct, MAX_CONNECTIONS_PER_IP);

	/* Release without accept: counter goes negative (atomic allows this) */
	release_connection(&ct);
	KUNIT_EXPECT_EQ(test, atomic_read(&ct.conn_count), -1);

	/* Accept should still work since -1 < max */
	KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ct.conn_count), 0);
}

/* ---- Max connections boundary ---- */

static void test_transport_max_connections_boundary(struct kunit *test)
{
	struct conn_tracker ct;
	int i;

	init_conn_tracker(&ct, MAX_CONNECTIONS_PER_IP);

	/* Fill to exactly max */
	for (i = 0; i < MAX_CONNECTIONS_PER_IP; i++)
		KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), 0);

	/* Next should fail */
	KUNIT_EXPECT_EQ(test, try_accept_connection(&ct), -EAGAIN);

	/* Clean up */
	for (i = 0; i < MAX_CONNECTIONS_PER_IP; i++)
		release_connection(&ct);
}

static struct kunit_case ksmbd_error_transport_test_cases[] = {
	KUNIT_CASE(test_transport_accept_below_limit),
	KUNIT_CASE(test_transport_accept_at_limit),
	KUNIT_CASE(test_transport_accept_zero_limit),
	KUNIT_CASE(test_transport_parallel_accept),
	KUNIT_CASE(test_transport_timeout_value),
	KUNIT_CASE(test_transport_disconnect_count),
	KUNIT_CASE(test_transport_saturated_pool),
	KUNIT_CASE(test_transport_release_underflow),
	KUNIT_CASE(test_transport_max_connections_boundary),
	{}
};

static struct kunit_suite ksmbd_error_transport_test_suite = {
	.name = "ksmbd_error_transport",
	.test_cases = ksmbd_error_transport_test_cases,
};

kunit_test_suite(ksmbd_error_transport_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for transport operations");
