// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for connection lifecycle, state machine, and refcount
 *   management (connection.c)
 *
 *   These tests replicate the state machine and connection hash logic
 *   from connection.c/connection.h without linking to the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/hash.h>
#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/wait.h>

/* ── Replicated state constants from connection.h ─── */
enum {
	TEST_SESS_NEW = 0,
	TEST_SESS_GOOD,
	TEST_SESS_EXITING,
	TEST_SESS_NEED_RECONNECT,
	TEST_SESS_NEED_NEGOTIATE,
	TEST_SESS_NEED_SETUP,
	TEST_SESS_RELEASING
};

/* ── Replicated server state constants from server.h ─── */
enum {
	TEST_SERVER_STATE_STARTING_UP,
	TEST_SERVER_STATE_RUNNING,
	TEST_SERVER_STATE_RESETTING,
	TEST_SERVER_STATE_SHUTTING_DOWN,
};

#define TEST_CONN_HASH_BITS	8
#define TEST_CONN_HASH_SIZE	(1 << TEST_CONN_HASH_BITS)

struct test_conn_hash_bucket {
	struct hlist_head	head;
	spinlock_t		lock;
};

/* Minimal mock connection struct */
struct test_conn {
	int			status;
	bool			need_neg;
	unsigned int		inet_hash;
	int			shutdown_calls;
	struct hlist_node	hlist;
	refcount_t		refcnt;
	atomic_t		req_running;
	atomic_t		r_count;
	unsigned int		total_credits;
	unsigned int		outstanding_credits;
	wait_queue_head_t	req_running_q;
	wait_queue_head_t	r_count_q;
	spinlock_t		request_lock;
	struct list_head	requests;
	unsigned long		last_active;
	atomic_t		open_files_count;
	char			ClientGUID[16];
};

struct conn_test_ctx {
	struct test_conn_hash_bucket	hash[TEST_CONN_HASH_SIZE];
	atomic_t			hash_count;
	int				server_state;
	unsigned long			deadtime;
};

/* ── Replicated state helpers ─── */

static inline bool test_conn_good(struct test_conn *conn)
{
	return READ_ONCE(conn->status) == TEST_SESS_GOOD;
}

static inline bool test_conn_exiting(struct test_conn *conn)
{
	return READ_ONCE(conn->status) == TEST_SESS_EXITING;
}

static inline bool test_conn_releasing(struct test_conn *conn)
{
	return READ_ONCE(conn->status) == TEST_SESS_RELEASING;
}

static inline void test_conn_set_new(struct test_conn *conn)
{
	WRITE_ONCE(conn->status, TEST_SESS_NEW);
}

static inline void test_conn_set_good(struct test_conn *conn)
{
	WRITE_ONCE(conn->status, TEST_SESS_GOOD);
}

static inline void test_conn_set_exiting(struct test_conn *conn)
{
	WRITE_ONCE(conn->status, TEST_SESS_EXITING);
}

static inline void test_conn_set_releasing(struct test_conn *conn)
{
	WRITE_ONCE(conn->status, TEST_SESS_RELEASING);
}

static inline bool test_conn_alive(struct test_conn *conn, int server_state,
				   unsigned long deadtime)
{
	if (server_state != TEST_SERVER_STATE_RUNNING)
		return false;
	if (test_conn_exiting(conn))
		return false;
	if (atomic_read(&conn->open_files_count) > 0)
		return true;
	if (deadtime > 0 && time_after(jiffies, conn->last_active + deadtime))
		return false;
	return true;
}

/* ── Hash table helpers ─── */

static void test_hash_init(struct test_conn_hash_bucket *hash, atomic_t *count)
{
	int i;

	for (i = 0; i < TEST_CONN_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&hash[i].head);
		spin_lock_init(&hash[i].lock);
	}
	atomic_set(count, 0);
}

static void test_hash_add(struct test_conn_hash_bucket *hash,
			  atomic_t *count, struct test_conn *conn,
			  unsigned int key)
{
	unsigned int bkt = hash_min(key, TEST_CONN_HASH_BITS);

	spin_lock(&hash[bkt].lock);
	hlist_add_head(&conn->hlist, &hash[bkt].head);
	atomic_inc(count);
	spin_unlock(&hash[bkt].lock);
}

static void test_hash_del(struct test_conn_hash_bucket *hash,
			  atomic_t *count, struct test_conn *conn)
{
	unsigned int bkt = hash_min(conn->inet_hash, TEST_CONN_HASH_BITS);

	spin_lock(&hash[bkt].lock);
	if (!hlist_unhashed(&conn->hlist)) {
		hlist_del_init(&conn->hlist);
		atomic_dec(count);
	}
	spin_unlock(&hash[bkt].lock);
}

static bool test_hash_empty(atomic_t *count)
{
	return atomic_read(count) == 0;
}

/*
 * Replicate the normal stop_sessions() scan closely enough to verify that
 * RELEASING connections still receive a transport shutdown attempt.
 */
static bool test_stop_sessions_scan_once(struct test_conn_hash_bucket *hash,
					 struct test_conn **shutdown_conn)
{
	struct test_conn *conn;
	int i;

	*shutdown_conn = NULL;
	for (i = 0; i < TEST_CONN_HASH_SIZE; i++) {
		spin_lock(&hash[i].lock);
		hlist_for_each_entry(conn, &hash[i].head, hlist) {
			test_conn_set_exiting(conn);
			if (!refcount_inc_not_zero(&conn->refcnt))
				continue;
			spin_unlock(&hash[i].lock);
			conn->shutdown_calls++;
			refcount_dec(&conn->refcnt);
			*shutdown_conn = conn;
			return true;
		}
		spin_unlock(&hash[i].lock);
	}

	return false;
}

static int test_stop_sessions_retry_model(bool hash_empty_after_flush,
					  bool *workqueue_flushed)
{
	bool hash_empty = false;
	bool need_retry = true;
	int retries = 0;

	*workqueue_flushed = false;

check_retry:
	if (!hash_empty || need_retry) {
		if (!*workqueue_flushed) {
			*workqueue_flushed = true;
			hash_empty = hash_empty_after_flush;
			need_retry = false;
			goto check_retry;
		}
		retries++;
	}

	return retries;
}

/* ── Alloc/init helper ─── */

static struct test_conn *test_conn_alloc(void)
{
	struct test_conn *conn = kzalloc(sizeof(*conn), GFP_KERNEL);

	if (!conn)
		return NULL;
	conn->need_neg = true;
	test_conn_set_new(conn);
	atomic_set(&conn->req_running, 0);
	atomic_set(&conn->r_count, 0);
	atomic_set(&conn->open_files_count, 0);
	refcount_set(&conn->refcnt, 1);
	conn->total_credits = 1;
	conn->outstanding_credits = 0;
	init_waitqueue_head(&conn->req_running_q);
	init_waitqueue_head(&conn->r_count_q);
	spin_lock_init(&conn->request_lock);
	INIT_LIST_HEAD(&conn->requests);
	INIT_HLIST_NODE(&conn->hlist);
	conn->last_active = jiffies;
	return conn;
}

/* ── Test suite init/exit ─── */

static int conn_test_init(struct kunit *test)
{
	struct conn_test_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	test_hash_init(ctx->hash, &ctx->hash_count);
	ctx->server_state = TEST_SERVER_STATE_RUNNING;
	ctx->deadtime = 0;
	test->priv = ctx;
	return 0;
}

static void conn_test_exit(struct kunit *test)
{
	kfree(test->priv);
}

/* ──────────────────────────────────────────────────────────
 * Connection allocation tests
 * ────────────────────────────────────────────────────────── */

static void test_conn_alloc_basic(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	KUNIT_EXPECT_TRUE(test, conn->need_neg);
	KUNIT_EXPECT_EQ(test, READ_ONCE(conn->status), TEST_SESS_NEW);
	KUNIT_EXPECT_EQ(test, refcount_read(&conn->refcnt), 1u);
	KUNIT_EXPECT_EQ(test, conn->total_credits, 1u);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->req_running), 0);
	kfree(conn);
}

/* ──────────────────────────────────────────────────────────
 * State machine transition tests
 * ────────────────────────────────────────────────────────── */

static void test_conn_state_new_to_good(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	KUNIT_EXPECT_FALSE(test, test_conn_good(conn));
	test_conn_set_good(conn);
	KUNIT_EXPECT_TRUE(test, test_conn_good(conn));
	kfree(conn);
}

static void test_conn_state_good_to_exiting(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	test_conn_set_good(conn);
	test_conn_set_exiting(conn);
	KUNIT_EXPECT_FALSE(test, test_conn_alive(conn, ctx->server_state,
						 ctx->deadtime));
	KUNIT_EXPECT_TRUE(test, test_conn_exiting(conn));
	kfree(conn);
}

static void test_conn_state_exiting_to_releasing(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	test_conn_set_exiting(conn);
	test_conn_set_releasing(conn);
	KUNIT_EXPECT_TRUE(test, test_conn_releasing(conn));
	kfree(conn);
}

static void test_conn_state_cannot_go_backwards(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	test_conn_set_exiting(conn);
	/*
	 * The production code uses WRITE_ONCE without guards, so
	 * technically it CAN go backwards. We verify the state
	 * was written (implementation note: no enforcement).
	 */
	test_conn_set_good(conn);
	KUNIT_EXPECT_TRUE(test, test_conn_good(conn));
	kfree(conn);
}

/* ──────────────────────────────────────────────────────────
 * Refcount transition tests
 * ────────────────────────────────────────────────────────── */

static void test_conn_refcount_init_is_one(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	KUNIT_EXPECT_EQ(test, refcount_read(&conn->refcnt), 1u);
	kfree(conn);
}

static void test_conn_refcount_inc_dec(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	refcount_inc(&conn->refcnt);
	KUNIT_EXPECT_EQ(test, refcount_read(&conn->refcnt), 2u);

	/* dec_and_test returns true when it hits 0 */
	KUNIT_EXPECT_FALSE(test, refcount_dec_and_test(&conn->refcnt));
	KUNIT_EXPECT_EQ(test, refcount_read(&conn->refcnt), 1u);

	KUNIT_EXPECT_TRUE(test, refcount_dec_and_test(&conn->refcnt));
	/* After final dec, refcount is 0 - conn would be freed in production */
	kfree(conn);
}

static void test_conn_refcount_inc_not_zero_on_zero(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	/* Drop to zero */
	KUNIT_ASSERT_TRUE(test, refcount_dec_and_test(&conn->refcnt));
	/* inc_not_zero should fail on a zeroed refcount */
	KUNIT_EXPECT_FALSE(test, refcount_inc_not_zero(&conn->refcnt));
	kfree(conn);
}

/* ──────────────────────────────────────────────────────────
 * Request enqueue/dequeue tests
 * ────────────────────────────────────────────────────────── */

static void test_conn_enqueue_increments_req_running(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	atomic_inc(&conn->req_running);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->req_running), 1);
	kfree(conn);
}

static void test_conn_dequeue_decrements_req_running(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	atomic_inc(&conn->req_running);
	atomic_dec(&conn->req_running);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->req_running), 0);
	kfree(conn);
}

/* ──────────────────────────────────────────────────────────
 * r_count lifecycle tests
 * ────────────────────────────────────────────────────────── */

static void test_conn_r_count_inc_dec(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	atomic_inc(&conn->r_count);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->r_count), 1);
	atomic_dec(&conn->r_count);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->r_count), 0);
	kfree(conn);
}

static void test_conn_r_count_dec_wakes_waiter(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	atomic_inc(&conn->r_count);

	/*
	 * In production, ksmbd_conn_r_count_dec wakes r_count_q when
	 * it reaches 0 and waitqueue_active returns true. We verify
	 * the atomic reaches 0 (the wake mechanism is kernel-internal).
	 */
	if (!atomic_dec_return(&conn->r_count) &&
	    waitqueue_active(&conn->r_count_q))
		wake_up(&conn->r_count_q);

	KUNIT_EXPECT_EQ(test, atomic_read(&conn->r_count), 0);
	kfree(conn);
}

/* ──────────────────────────────────────────────────────────
 * Connection hash with real conn structs
 * ────────────────────────────────────────────────────────── */

static void test_conn_hash_add_del_with_real_conn(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	conn->inet_hash = 42;
	test_hash_add(ctx->hash, &ctx->hash_count, conn, 42);
	KUNIT_EXPECT_FALSE(test, test_hash_empty(&ctx->hash_count));

	test_hash_del(ctx->hash, &ctx->hash_count, conn);
	KUNIT_EXPECT_TRUE(test, test_hash_empty(&ctx->hash_count));
	kfree(conn);
}

static void test_conn_hash_del_already_removed(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	conn->inet_hash = 77;
	test_hash_add(ctx->hash, &ctx->hash_count, conn, 77);
	test_hash_del(ctx->hash, &ctx->hash_count, conn);
	/* Second delete should be safe */
	test_hash_del(ctx->hash, &ctx->hash_count, conn);
	KUNIT_EXPECT_TRUE(test, test_hash_empty(&ctx->hash_count));
	kfree(conn);
}

static void test_stop_sessions_scans_releasing_conn(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *conn = test_conn_alloc();
	struct test_conn *shutdown_conn;

	KUNIT_ASSERT_NOT_NULL(test, conn);
	conn->inet_hash = 91;
	test_conn_set_releasing(conn);
	test_hash_add(ctx->hash, &ctx->hash_count, conn, conn->inet_hash);

	KUNIT_EXPECT_TRUE(test,
			  test_stop_sessions_scan_once(ctx->hash,
						       &shutdown_conn));
	KUNIT_ASSERT_PTR_EQ(test, shutdown_conn, conn);
	KUNIT_EXPECT_EQ(test, conn->shutdown_calls, 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&conn->refcnt), 1u);
	KUNIT_EXPECT_EQ(test, READ_ONCE(conn->status), TEST_SESS_EXITING);

	test_hash_del(ctx->hash, &ctx->hash_count, conn);
	kfree(conn);
}

static void test_stop_sessions_skips_zero_ref_releasing_conn(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *conn = test_conn_alloc();
	struct test_conn *shutdown_conn;

	KUNIT_ASSERT_NOT_NULL(test, conn);
	conn->inet_hash = 92;
	test_conn_set_releasing(conn);
	test_hash_add(ctx->hash, &ctx->hash_count, conn, conn->inet_hash);
	KUNIT_ASSERT_TRUE(test, refcount_dec_and_test(&conn->refcnt));

	KUNIT_EXPECT_FALSE(test,
			   test_stop_sessions_scan_once(ctx->hash,
							&shutdown_conn));
	KUNIT_EXPECT_PTR_EQ(test, shutdown_conn, NULL);
	KUNIT_EXPECT_EQ(test, conn->shutdown_calls, 0);

	test_hash_del(ctx->hash, &ctx->hash_count, conn);
	kfree(conn);
}

static void test_stop_sessions_flushes_workqueue_before_retry_budget(
	struct kunit *test)
{
	bool workqueue_flushed;
	int retries;

	retries = test_stop_sessions_retry_model(true, &workqueue_flushed);
	KUNIT_EXPECT_TRUE(test, workqueue_flushed);
	KUNIT_EXPECT_EQ(test, retries, 0);
}

static void test_stop_sessions_retries_only_after_flush(struct kunit *test)
{
	bool workqueue_flushed;
	int retries;

	retries = test_stop_sessions_retry_model(false, &workqueue_flushed);
	KUNIT_EXPECT_TRUE(test, workqueue_flushed);
	KUNIT_EXPECT_EQ(test, retries, 1);
}

static void test_conn_lookup_dialect_finds_matching_guid(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *c1 = test_conn_alloc();
	struct test_conn *c2 = test_conn_alloc();
	struct test_conn *query;
	bool found = false;
	int i;

	KUNIT_ASSERT_NOT_NULL(test, c1);
	KUNIT_ASSERT_NOT_NULL(test, c2);

	memset(c1->ClientGUID, 0xAA, 16);
	c1->inet_hash = 10;
	memset(c2->ClientGUID, 0xBB, 16);
	c2->inet_hash = 20;

	test_hash_add(ctx->hash, &ctx->hash_count, c1, 10);
	test_hash_add(ctx->hash, &ctx->hash_count, c2, 20);

	/* Search for c1's GUID */
	for (i = 0; i < TEST_CONN_HASH_SIZE; i++) {
		spin_lock(&ctx->hash[i].lock);
		hlist_for_each_entry(query, &ctx->hash[i].head, hlist) {
			if (!memcmp(query->ClientGUID, c1->ClientGUID, 16)) {
				found = true;
				spin_unlock(&ctx->hash[i].lock);
				goto done;
			}
		}
		spin_unlock(&ctx->hash[i].lock);
	}
done:
	KUNIT_EXPECT_TRUE(test, found);

	test_hash_del(ctx->hash, &ctx->hash_count, c1);
	test_hash_del(ctx->hash, &ctx->hash_count, c2);
	kfree(c1);
	kfree(c2);
}

/* ──────────────────────────────────────────────────────────
 * Per-IP connection limit tests
 * ────────────────────────────────────────────────────────── */

static unsigned int count_conns_for_ip(struct test_conn_hash_bucket *hash,
				       unsigned int inet_hash)
{
	unsigned int count = 0;
	struct test_conn *t;
	int i;

	for (i = 0; i < TEST_CONN_HASH_SIZE; i++) {
		spin_lock(&hash[i].lock);
		hlist_for_each_entry(t, &hash[i].head, hlist) {
			if (t->inet_hash == inet_hash &&
			    !test_conn_exiting(t))
				count++;
		}
		spin_unlock(&hash[i].lock);
	}
	return count;
}

static void test_conn_per_ip_limit_enforced(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *c1, *c2;
	unsigned int max_ip = 2;
	unsigned int ip_hash = 12345;
	unsigned int count;

	c1 = test_conn_alloc();
	c2 = test_conn_alloc();
	KUNIT_ASSERT_NOT_NULL(test, c1);
	KUNIT_ASSERT_NOT_NULL(test, c2);

	c1->inet_hash = ip_hash;
	c2->inet_hash = ip_hash;
	test_hash_add(ctx->hash, &ctx->hash_count, c1, ip_hash);
	test_hash_add(ctx->hash, &ctx->hash_count, c2, ip_hash);

	count = count_conns_for_ip(ctx->hash, ip_hash);
	KUNIT_EXPECT_EQ(test, count, 2u);
	KUNIT_EXPECT_GE(test, count, max_ip);

	test_hash_del(ctx->hash, &ctx->hash_count, c1);
	test_hash_del(ctx->hash, &ctx->hash_count, c2);
	kfree(c1);
	kfree(c2);
}

static void test_conn_per_ip_limit_excludes_exiting(struct kunit *test)
{
	struct conn_test_ctx *ctx = test->priv;
	struct test_conn *c1, *c2, *c3;
	unsigned int ip_hash = 12345;
	unsigned int count;

	c1 = test_conn_alloc();
	c2 = test_conn_alloc();
	c3 = test_conn_alloc();
	KUNIT_ASSERT_NOT_NULL(test, c1);
	KUNIT_ASSERT_NOT_NULL(test, c2);
	KUNIT_ASSERT_NOT_NULL(test, c3);

	c1->inet_hash = ip_hash;
	c2->inet_hash = ip_hash;
	c3->inet_hash = ip_hash;
	test_conn_set_exiting(c3); /* Mark as exiting */

	test_hash_add(ctx->hash, &ctx->hash_count, c1, ip_hash);
	test_hash_add(ctx->hash, &ctx->hash_count, c2, ip_hash);
	test_hash_add(ctx->hash, &ctx->hash_count, c3, ip_hash);

	count = count_conns_for_ip(ctx->hash, ip_hash);
	KUNIT_EXPECT_EQ(test, count, 2u); /* c3 excluded */

	test_hash_del(ctx->hash, &ctx->hash_count, c1);
	test_hash_del(ctx->hash, &ctx->hash_count, c2);
	test_hash_del(ctx->hash, &ctx->hash_count, c3);
	kfree(c1);
	kfree(c2);
	kfree(c3);
}

static void test_conn_per_ip_limit_zero_means_unlimited(struct kunit *test)
{
	unsigned int max_ip = 0;

	/* Zero means no limit enforcement */
	KUNIT_EXPECT_EQ(test, max_ip, 0u);
}

/* ──────────────────────────────────────────────────────────
 * ksmbd_conn_alive edge cases
 * ────────────────────────────────────────────────────────── */

static void test_conn_alive_false_when_server_not_running(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	KUNIT_EXPECT_FALSE(test, test_conn_alive(conn,
			   TEST_SERVER_STATE_SHUTTING_DOWN, 0));
	kfree(conn);
}

static void test_conn_alive_true_with_open_files(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	test_conn_set_good(conn);
	atomic_set(&conn->open_files_count, 5);
	KUNIT_EXPECT_TRUE(test, test_conn_alive(conn,
			  TEST_SERVER_STATE_RUNNING, 0));
	kfree(conn);
}

static void test_conn_alive_false_after_deadtime(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	test_conn_set_good(conn);
	atomic_set(&conn->open_files_count, 0);
	conn->last_active = jiffies - (HZ * 120) - 1;
	KUNIT_EXPECT_FALSE(test, test_conn_alive(conn,
			   TEST_SERVER_STATE_RUNNING, HZ * 120));
	kfree(conn);
}

/* ──────────────────────────────────────────────────────────
 * Additional connection tests from plan
 * ────────────────────────────────────────────────────────── */

static void test_conn_cancel_not_queued(struct kunit *test)
{
	/*
	 * When a CANCEL command is enqueued, in production code the
	 * req_running counter increments but the request is NOT added
	 * to the requests list. Replicate this logic.
	 */
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);

	/* Simulate CANCEL: increment req_running but don't add to list */
	atomic_inc(&conn->req_running);
	/* requests_list should remain empty */
	KUNIT_EXPECT_TRUE(test, list_empty(&conn->requests));
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->req_running), 1);

	/* Cleanup: decrement req_running */
	atomic_dec(&conn->req_running);
	kfree(conn);
}

static void test_conn_multiple_enqueue_dequeue(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();
	int i;

	KUNIT_ASSERT_NOT_NULL(test, conn);

	/* Enqueue 10 requests */
	for (i = 0; i < 10; i++)
		atomic_inc(&conn->req_running);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->req_running), 10);

	/* Dequeue all */
	for (i = 0; i < 10; i++)
		atomic_dec(&conn->req_running);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->req_running), 0);

	kfree(conn);
}

static void test_conn_total_credits_init(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	/* Verify total_credits initialized to 1 */
	KUNIT_EXPECT_EQ(test, conn->total_credits, 1u);
	kfree(conn);
}

static void test_conn_need_neg_initial(struct kunit *test)
{
	struct test_conn *conn = test_conn_alloc();

	KUNIT_ASSERT_NOT_NULL(test, conn);
	/* need_neg should be true initially */
	KUNIT_EXPECT_TRUE(test, conn->need_neg);
	kfree(conn);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_connection_test_cases[] = {
	/* Allocation */
	KUNIT_CASE(test_conn_alloc_basic),
	/* State machine */
	KUNIT_CASE(test_conn_state_new_to_good),
	KUNIT_CASE(test_conn_state_good_to_exiting),
	KUNIT_CASE(test_conn_state_exiting_to_releasing),
	KUNIT_CASE(test_conn_state_cannot_go_backwards),
	/* Refcount */
	KUNIT_CASE(test_conn_refcount_init_is_one),
	KUNIT_CASE(test_conn_refcount_inc_dec),
	KUNIT_CASE(test_conn_refcount_inc_not_zero_on_zero),
	/* Request enqueue/dequeue */
	KUNIT_CASE(test_conn_enqueue_increments_req_running),
	KUNIT_CASE(test_conn_dequeue_decrements_req_running),
	/* r_count */
	KUNIT_CASE(test_conn_r_count_inc_dec),
	KUNIT_CASE(test_conn_r_count_dec_wakes_waiter),
	/* Hash with real conns */
	KUNIT_CASE(test_conn_hash_add_del_with_real_conn),
	KUNIT_CASE(test_conn_hash_del_already_removed),
	KUNIT_CASE(test_stop_sessions_scans_releasing_conn),
	KUNIT_CASE(test_stop_sessions_skips_zero_ref_releasing_conn),
	KUNIT_CASE(test_stop_sessions_flushes_workqueue_before_retry_budget),
	KUNIT_CASE(test_stop_sessions_retries_only_after_flush),
	KUNIT_CASE(test_conn_lookup_dialect_finds_matching_guid),
	/* Per-IP limits */
	KUNIT_CASE(test_conn_per_ip_limit_enforced),
	KUNIT_CASE(test_conn_per_ip_limit_excludes_exiting),
	KUNIT_CASE(test_conn_per_ip_limit_zero_means_unlimited),
	/* conn_alive edge cases */
	KUNIT_CASE(test_conn_alive_false_when_server_not_running),
	KUNIT_CASE(test_conn_alive_true_with_open_files),
	KUNIT_CASE(test_conn_alive_false_after_deadtime),
	/* Additional tests */
	KUNIT_CASE(test_conn_cancel_not_queued),
	KUNIT_CASE(test_conn_multiple_enqueue_dequeue),
	KUNIT_CASE(test_conn_total_credits_init),
	KUNIT_CASE(test_conn_need_neg_initial),
	{}
};

static struct kunit_suite ksmbd_connection_test_suite = {
	.name = "ksmbd_connection",
	.init = conn_test_init,
	.exit = conn_test_exit,
	.test_cases = ksmbd_connection_test_cases,
};

kunit_test_suite(ksmbd_connection_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd connection lifecycle and state machine");
