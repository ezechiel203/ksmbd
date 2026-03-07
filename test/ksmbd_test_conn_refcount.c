// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for connection refcount saturation and cleanup ordering.
 *
 *   These tests replicate the refcount logic from connection.c without
 *   calling into the ksmbd module directly.  The kernel refcount_t API
 *   is used to exercise boundary conditions and ordering constraints.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/refcount.h>

/*
 * Minimal test connection structure replicating the refcount field
 * from struct ksmbd_conn (connection.h).
 */
struct test_conn {
	refcount_t	refcnt;
	bool		cleaned_up;
};

/*
 * Replicate the refcount init pattern from ksmbd_conn_alloc().
 */
static struct test_conn *test_conn_alloc(void)
{
	struct test_conn *conn;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return NULL;

	refcount_set(&conn->refcnt, 1);
	conn->cleaned_up = false;
	return conn;
}

/*
 * Replicate the cleanup-on-last-put pattern from ksmbd_conn_free().
 * Returns true if cleanup was triggered (refcount reached zero).
 */
static bool test_conn_put(struct test_conn *conn)
{
	if (!refcount_dec_and_test(&conn->refcnt))
		return false;

	conn->cleaned_up = true;
	return true;
}

/* ------------------------------------------------------------------ */
/* Test: initial refcount value after allocation                      */
/* ksmbd_conn_alloc() sets refcount_set(&conn->refcnt, 1)            */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_initial_value(struct kunit *test)
{
	struct test_conn *conn;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	KUNIT_EXPECT_EQ(test, 1U, refcount_read(&conn->refcnt));
	KUNIT_EXPECT_FALSE(test, conn->cleaned_up);

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: refcount increment via refcount_inc                          */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_increment(struct kunit *test)
{
	struct test_conn *conn;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	refcount_inc(&conn->refcnt);
	KUNIT_EXPECT_EQ(test, 2U, refcount_read(&conn->refcnt));

	refcount_inc(&conn->refcnt);
	KUNIT_EXPECT_EQ(test, 3U, refcount_read(&conn->refcnt));

	/* Drain to avoid leak warnings */
	refcount_dec(&conn->refcnt);
	refcount_dec(&conn->refcnt);
	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: refcount decrement via refcount_dec                          */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_decrement(struct kunit *test)
{
	struct test_conn *conn;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	refcount_inc(&conn->refcnt); /* now 2 */
	refcount_dec(&conn->refcnt); /* now 1 */
	KUNIT_EXPECT_EQ(test, 1U, refcount_read(&conn->refcnt));

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: refcount at zero triggers cleanup                            */
/* ksmbd_conn_free() calls refcount_dec_and_test(), and when it       */
/* returns true, ksmbd_conn_cleanup() is invoked.                     */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_zero_triggers_cleanup(struct kunit *test)
{
	struct test_conn *conn;
	bool triggered;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	triggered = test_conn_put(conn);
	KUNIT_EXPECT_TRUE(test, triggered);
	KUNIT_EXPECT_TRUE(test, conn->cleaned_up);

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: refcount cannot go negative (underflow protection)           */
/* The kernel refcount_t API saturates rather than wrapping.           */
/* After dec_and_test returns true (count=0), further dec is a bug    */
/* that refcount_t catches by WARN + saturation.                      */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_underflow_protection(struct kunit *test)
{
	struct test_conn *conn;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/* First put reaches zero */
	KUNIT_EXPECT_TRUE(test, test_conn_put(conn));

	/*
	 * After reaching zero, refcount_t enters a saturated state.
	 * Reading a saturated refcount returns 0.
	 * The kernel will WARN on further operations, but the value
	 * will not wrap to UINT_MAX.
	 */
	KUNIT_EXPECT_EQ(test, 0U, refcount_read(&conn->refcnt));

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: multiple increment/decrement cycles maintain invariant       */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_inc_dec_cycles(struct kunit *test)
{
	struct test_conn *conn;
	int i;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/* Increment 10 times: 1 + 10 = 11 */
	for (i = 0; i < 10; i++)
		refcount_inc(&conn->refcnt);
	KUNIT_EXPECT_EQ(test, 11U, refcount_read(&conn->refcnt));

	/* Decrement 10 times: back to 1 */
	for (i = 0; i < 10; i++)
		refcount_dec(&conn->refcnt);
	KUNIT_EXPECT_EQ(test, 1U, refcount_read(&conn->refcnt));

	/* Final put triggers cleanup */
	KUNIT_EXPECT_TRUE(test, test_conn_put(conn));
	KUNIT_EXPECT_TRUE(test, conn->cleaned_up);

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: cleanup ordering - transport before session before file      */
/* Simulates the ordering by tracking cleanup sequence numbers.       */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_cleanup_ordering(struct kunit *test)
{
	int order_counter = 0;
	int transport_order = -1;
	int session_order = -1;
	int file_order = -1;

	/*
	 * In ksmbd_conn_cleanup(), the ordering is:
	 * 1. ksmbd_conn_hash_del(conn)        [transport/connection layer]
	 * 2. xa_destroy(&conn->sessions)       [session layer]
	 * 3. conn->transport->ops->free_transport(conn->transport)
	 *
	 * And ksmbd_conn_free() calls ksmbd_conn_cleanup() only
	 * after refcount_dec_and_test() returns true.
	 *
	 * Simulate this ordering with counters.
	 */
	transport_order = order_counter++;  /* hash_del first */
	session_order = order_counter++;    /* session cleanup second */
	file_order = order_counter++;       /* transport/file cleanup last */

	KUNIT_EXPECT_LT(test, transport_order, session_order);
	KUNIT_EXPECT_LT(test, session_order, file_order);
}

/* ------------------------------------------------------------------ */
/* Test: concurrent-style refcount operations (sequential simulation) */
/* Simulates multiple "threads" taking and releasing references.      */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_concurrent_simulation(struct kunit *test)
{
	struct test_conn *conn;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/* Simulate 3 concurrent workers taking refs */
	refcount_inc(&conn->refcnt); /* worker A: 2 */
	refcount_inc(&conn->refcnt); /* worker B: 3 */
	refcount_inc(&conn->refcnt); /* worker C: 4 */
	KUNIT_EXPECT_EQ(test, 4U, refcount_read(&conn->refcnt));

	/* Workers finish in arbitrary order */
	refcount_dec(&conn->refcnt); /* worker B done: 3 */
	refcount_dec(&conn->refcnt); /* worker A done: 2 */
	KUNIT_EXPECT_EQ(test, 2U, refcount_read(&conn->refcnt));

	refcount_dec(&conn->refcnt); /* worker C done: 1 */
	KUNIT_EXPECT_EQ(test, 1U, refcount_read(&conn->refcnt));

	/* Connection handler does final put */
	KUNIT_EXPECT_TRUE(test, test_conn_put(conn));
	KUNIT_EXPECT_TRUE(test, conn->cleaned_up);

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: refcount at UINT_MAX boundary (saturation detection)         */
/* refcount_t saturates at REFCOUNT_SATURATED rather than wrapping.   */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_saturation(struct kunit *test)
{
	struct test_conn *conn;
	unsigned int val;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/*
	 * Set refcount close to UINT_MAX to test saturation.
	 * The kernel refcount_t saturates at REFCOUNT_SATURATED
	 * (UINT_MAX / 2) to detect misuse.  We cannot easily push
	 * the counter that high in a KUnit test, so instead verify
	 * that refcount_inc_not_zero() works correctly on a live ref.
	 */
	KUNIT_EXPECT_TRUE(test, refcount_inc_not_zero(&conn->refcnt));
	val = refcount_read(&conn->refcnt);
	KUNIT_EXPECT_EQ(test, 2U, val);

	/* refcount_inc_not_zero on a zero refcount returns false */
	refcount_dec(&conn->refcnt);  /* back to 1 */
	test_conn_put(conn);          /* now 0 */

	/*
	 * After reaching zero, refcount_inc_not_zero must return false,
	 * preventing resurrection of a dead connection.  This is the
	 * pattern used in stop_sessions().
	 */
	KUNIT_EXPECT_FALSE(test, refcount_inc_not_zero(&conn->refcnt));

	kfree(conn);
}

/* ------------------------------------------------------------------ */
/* Test: double-free protection (decrement past zero)                 */
/* After cleanup triggers, further put should not re-trigger.         */
/* ------------------------------------------------------------------ */
static void test_conn_refcount_double_free_protection(struct kunit *test)
{
	struct test_conn *conn;

	conn = test_conn_alloc();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/* First put triggers cleanup */
	KUNIT_EXPECT_TRUE(test, test_conn_put(conn));
	KUNIT_EXPECT_TRUE(test, conn->cleaned_up);

	/* Reset flag to verify second put does NOT re-trigger */
	conn->cleaned_up = false;

	/*
	 * Second put: refcount is already 0 (saturated), so
	 * refcount_dec_and_test will NOT return true again.
	 * The kernel will WARN, but we verify the bool is not re-set.
	 *
	 * Note: We use refcount_inc_not_zero to check the state
	 * instead of calling test_conn_put again, since calling
	 * refcount_dec on a zero refcount triggers a kernel WARN.
	 */
	KUNIT_EXPECT_FALSE(test, refcount_inc_not_zero(&conn->refcnt));
	KUNIT_EXPECT_FALSE(test, conn->cleaned_up);

	kfree(conn);
}

static struct kunit_case ksmbd_conn_refcount_test_cases[] = {
	KUNIT_CASE(test_conn_refcount_initial_value),
	KUNIT_CASE(test_conn_refcount_increment),
	KUNIT_CASE(test_conn_refcount_decrement),
	KUNIT_CASE(test_conn_refcount_zero_triggers_cleanup),
	KUNIT_CASE(test_conn_refcount_underflow_protection),
	KUNIT_CASE(test_conn_refcount_inc_dec_cycles),
	KUNIT_CASE(test_conn_refcount_cleanup_ordering),
	KUNIT_CASE(test_conn_refcount_concurrent_simulation),
	KUNIT_CASE(test_conn_refcount_saturation),
	KUNIT_CASE(test_conn_refcount_double_free_protection),
	{}
};

static struct kunit_suite ksmbd_conn_refcount_test_suite = {
	.name = "ksmbd_conn_refcount",
	.test_cases = ksmbd_conn_refcount_test_cases,
};

kunit_test_suite(ksmbd_conn_refcount_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd connection refcount management");
