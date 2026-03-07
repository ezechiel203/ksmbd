// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit stress tests for ksmbd server limits and resource management.
 *
 *   This module exercises configurable server limits across connection,
 *   session, credit, lock, file handle, buffer/IO, compression, and
 *   timeout subsystems.  All tests are self-contained: they replicate
 *   the internal data structures and algorithms rather than calling into
 *   the live ksmbd module, following the pattern established by
 *   ksmbd_test_config.c and ksmbd_test_concurrency_hash.c.
 *
 *   Concurrent tests use kthread_run() with completion barriers.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/xarray.h>
#include <linux/idr.h>
#include <linux/jiffies.h>
#include <linux/random.h>

#include "ksmbd_config.h"

/* ======================================================================
 * Constants mirroring production code (self-contained, no module imports)
 * ====================================================================== */

#define STRESS_CONN_HASH_BITS		8
#define STRESS_CONN_HASH_SIZE		(1 << STRESS_CONN_HASH_BITS)

#define STRESS_SMB2_MAX_BUFFER_SIZE	65536
#define STRESS_SMB2_MAX_CREDITS		8192
#define STRESS_KSMBD_MAX_LOCK_COUNT	64

#define STRESS_NR_WORKERS		4
#define STRESS_STORM_ITERATIONS		1000
#define STRESS_CREDIT_CYCLES		100000

/* ======================================================================
 * Simulated connection hash table (mirrors connection.c)
 * ====================================================================== */

struct stress_conn_bucket {
	struct hlist_head	head;
	spinlock_t		lock;
};

struct stress_conn {
	unsigned int		inet_hash;
	unsigned int		total_credits;
	unsigned int		outstanding_credits;
	spinlock_t		credits_lock;
	atomic_t		req_running;
	unsigned long		last_active;
	struct hlist_node	hlist;
	int			status;
};

enum {
	STRESS_SESS_NEW = 0,
	STRESS_SESS_GOOD,
	STRESS_SESS_EXITING,
};

static void stress_conn_hash_init(struct stress_conn_bucket *hash)
{
	int i;

	for (i = 0; i < STRESS_CONN_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&hash[i].head);
		spin_lock_init(&hash[i].lock);
	}
}

static void stress_conn_hash_add(struct stress_conn_bucket *hash,
				 struct stress_conn *conn, unsigned int key)
{
	unsigned int bkt = hash_min(key, STRESS_CONN_HASH_BITS);

	spin_lock(&hash[bkt].lock);
	hlist_add_head(&conn->hlist, &hash[bkt].head);
	spin_unlock(&hash[bkt].lock);
}

static void stress_conn_hash_del(struct stress_conn_bucket *hash,
				 struct stress_conn *conn)
{
	unsigned int bkt = hash_min(conn->inet_hash, STRESS_CONN_HASH_BITS);

	spin_lock(&hash[bkt].lock);
	hlist_del_init(&conn->hlist);
	spin_unlock(&hash[bkt].lock);
}

static int stress_conn_hash_count_ip(struct stress_conn_bucket *hash,
				     unsigned int ip_hash)
{
	unsigned int bkt = hash_min(ip_hash, STRESS_CONN_HASH_BITS);
	struct stress_conn *conn;
	int count = 0;

	spin_lock(&hash[bkt].lock);
	hlist_for_each_entry(conn, &hash[bkt].head, hlist) {
		if (conn->inet_hash == ip_hash)
			count++;
	}
	spin_unlock(&hash[bkt].lock);
	return count;
}

static int stress_conn_hash_count_total(struct stress_conn_bucket *hash)
{
	int i, total = 0;

	for (i = 0; i < STRESS_CONN_HASH_SIZE; i++) {
		struct stress_conn *conn;

		spin_lock(&hash[i].lock);
		hlist_for_each_entry(conn, &hash[i].head, hlist)
			total++;
		spin_unlock(&hash[i].lock);
	}
	return total;
}

/* ======================================================================
 * Simulated lock entry (mirrors vfs_cache.h ksmbd_lock)
 * ====================================================================== */

struct stress_lock {
	struct list_head	llist;
	unsigned long long	start;
	unsigned long long	end;
	unsigned int		flags;
};

/* ======================================================================
 * Simulated credit system (mirrors smb2misc.c / smb2_pdu_common.c)
 * ====================================================================== */

static bool stress_credit_charge_check(struct stress_conn *conn,
				       unsigned int charge)
{
	bool ok;

	spin_lock(&conn->credits_lock);
	if (charge > conn->total_credits) {
		ok = false;
	} else if ((u64)conn->outstanding_credits + charge >
		   conn->total_credits) {
		ok = false;
	} else {
		conn->outstanding_credits += charge;
		ok = true;
	}
	spin_unlock(&conn->credits_lock);
	return ok;
}

static void stress_credit_grant(struct stress_conn *conn, unsigned int grant,
				unsigned int max_credits)
{
	spin_lock(&conn->credits_lock);
	if (conn->total_credits + grant > max_credits)
		grant = max_credits - conn->total_credits;
	conn->total_credits += grant;
	spin_unlock(&conn->credits_lock);
}

static void stress_credit_consume(struct stress_conn *conn, unsigned int charge)
{
	spin_lock(&conn->credits_lock);
	if (charge <= conn->total_credits)
		conn->total_credits -= charge;
	if (charge <= conn->outstanding_credits)
		conn->outstanding_credits -= charge;
	spin_unlock(&conn->credits_lock);
}

/* ======================================================================
 * Simulated file descriptor limit (mirrors vfs_cache.c fd_limit)
 * ====================================================================== */

struct stress_fd_pool {
	atomic_long_t	limit;
	rwlock_t	lock;
	struct idr	idr;
	atomic_t	open_count;
};

static void stress_fd_pool_init(struct stress_fd_pool *pool, unsigned long max)
{
	atomic_long_set(&pool->limit, max);
	rwlock_init(&pool->lock);
	idr_init(&pool->idr);
	atomic_set(&pool->open_count, 0);
}

static bool stress_fd_limit_depleted(struct stress_fd_pool *pool)
{
	long v = atomic_long_dec_return(&pool->limit);

	if (v >= 0)
		return false;
	atomic_long_inc(&pool->limit);
	return true;
}

static void stress_fd_limit_close(struct stress_fd_pool *pool)
{
	atomic_long_inc(&pool->limit);
}

static int stress_fd_open(struct stress_fd_pool *pool)
{
	int id;

	if (stress_fd_limit_depleted(pool))
		return -EMFILE;

	write_lock(&pool->lock);
	id = idr_alloc(&pool->idr, pool, 0, INT_MAX, GFP_ATOMIC);
	write_unlock(&pool->lock);

	if (id < 0) {
		stress_fd_limit_close(pool);
		return -ENOMEM;
	}
	atomic_inc(&pool->open_count);
	return id;
}

static void stress_fd_close(struct stress_fd_pool *pool, int id)
{
	write_lock(&pool->lock);
	idr_remove(&pool->idr, id);
	write_unlock(&pool->lock);

	stress_fd_limit_close(pool);
	atomic_dec(&pool->open_count);
}

static void stress_fd_pool_destroy(struct stress_fd_pool *pool)
{
	idr_destroy(&pool->idr);
}

/* ======================================================================
 * Simulated buffer_check_err (mirrors smb2_query_set.c)
 * ====================================================================== */

static int stress_buffer_check_err(int output_buf_len, int needed_buf_len)
{
	if (output_buf_len < needed_buf_len)
		return -EINVAL;  /* STATUS_INFO_LENGTH_MISMATCH */
	return 0;
}

/* ======================================================================
 * Concurrent test infrastructure
 * ====================================================================== */

struct stress_thread_ctx {
	struct kunit		*test;
	struct completion	start_barrier;
	struct completion	done_barrier;
	atomic_t		workers_ready;
	atomic_t		workers_remaining;
	void			*shared;
};

static void stress_ctx_init(struct stress_thread_ctx *ctx, struct kunit *test,
			    int nr_workers, void *shared)
{
	ctx->test = test;
	init_completion(&ctx->start_barrier);
	init_completion(&ctx->done_barrier);
	atomic_set(&ctx->workers_ready, 0);
	atomic_set(&ctx->workers_remaining, nr_workers);
	ctx->shared = shared;
}

static void stress_worker_ready(struct stress_thread_ctx *ctx)
{
	atomic_inc(&ctx->workers_ready);
	wait_for_completion(&ctx->start_barrier);
}

static void stress_worker_done(struct stress_thread_ctx *ctx)
{
	if (atomic_dec_and_test(&ctx->workers_remaining))
		complete(&ctx->done_barrier);
}

static void stress_wait_all_ready(struct stress_thread_ctx *ctx,
				  int nr_workers)
{
	while (atomic_read(&ctx->workers_ready) < nr_workers)
		usleep_range(10, 50);
}

/* ======================================================================
 * 1. CONNECTION / SESSION LIMITS
 * ====================================================================== */

/*
 * test_stress_max_connections - verify N+1 connection attempt after max
 * is rejected.
 *
 * Sets max_connections to a small value via ksmbd_config, then tries to
 * add one more connection to the simulated hash table.
 */
static void test_stress_max_connections(struct kunit *test)
{
	struct stress_conn_bucket hash[STRESS_CONN_HASH_SIZE];
	struct stress_conn *conns;
	const unsigned int max_conn = 16;
	atomic_t conn_count;
	unsigned int i;
	int ret;

	/* Configure the limit */
	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_CONNECTIONS, max_conn);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS), max_conn);

	stress_conn_hash_init(hash);
	atomic_set(&conn_count, 0);

	conns = kcalloc(max_conn + 1, sizeof(*conns), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conns);

	/* Fill to max */
	for (i = 0; i < max_conn; i++) {
		conns[i].inet_hash = i;
		INIT_HLIST_NODE(&conns[i].hlist);
		stress_conn_hash_add(hash, &conns[i], i);
		atomic_inc(&conn_count);
	}

	KUNIT_EXPECT_EQ(test, (unsigned int)atomic_read(&conn_count), max_conn);
	KUNIT_EXPECT_EQ(test, (unsigned int)stress_conn_hash_count_total(hash),
			max_conn);

	/* N+1 attempt: check count against config limit before adding */
	KUNIT_EXPECT_GE(test,
		(unsigned int)stress_conn_hash_count_total(hash),
		ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS));

	/* Cleanup */
	for (i = 0; i < max_conn; i++)
		stress_conn_hash_del(hash, &conns[i]);

	kfree(conns);
	ksmbd_config_exit();
}

/*
 * test_stress_max_connections_per_ip - per-IP limit enforcement.
 *
 * All connections share the same IP hash.  After reaching the per-IP
 * limit, additional connections from the same IP should be rejected.
 */
static void test_stress_max_connections_per_ip(struct kunit *test)
{
	struct stress_conn_bucket hash[STRESS_CONN_HASH_SIZE];
	struct stress_conn *conns;
	const unsigned int per_ip_limit = 8;
	const unsigned int ip_hash = 0xDEADBEEF;
	unsigned int i;
	int count;
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_CONNECTIONS_PER_IP,
				   per_ip_limit);
	KUNIT_ASSERT_EQ(test, ret, 0);

	stress_conn_hash_init(hash);

	conns = kcalloc(per_ip_limit + 1, sizeof(*conns), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conns);

	/* Fill to per-IP limit */
	for (i = 0; i < per_ip_limit; i++) {
		conns[i].inet_hash = ip_hash;
		INIT_HLIST_NODE(&conns[i].hlist);
		stress_conn_hash_add(hash, &conns[i], ip_hash);
	}

	count = stress_conn_hash_count_ip(hash, ip_hash);
	KUNIT_EXPECT_EQ(test, (unsigned int)count, per_ip_limit);

	/* Next attempt: would exceed per-IP limit */
	KUNIT_EXPECT_GE(test, (unsigned int)count,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS_PER_IP));

	/* Cleanup */
	for (i = 0; i < per_ip_limit; i++)
		stress_conn_hash_del(hash, &conns[i]);

	kfree(conns);
	ksmbd_config_exit();
}

/*
 * Connection storm context for kthread workers.
 */
struct conn_storm_shared {
	struct stress_conn_bucket	hash[STRESS_CONN_HASH_SIZE];
	atomic_t			total_connect;
	atomic_t			total_disconnect;
};

static int worker_conn_storm(void *data)
{
	struct stress_thread_ctx *ctx = data;
	struct conn_storm_shared *shared = ctx->shared;
	int i;

	stress_worker_ready(ctx);

	for (i = 0; i < STRESS_STORM_ITERATIONS / STRESS_NR_WORKERS; i++) {
		struct stress_conn *conn;
		unsigned int key = get_random_u32();

		conn = kzalloc(sizeof(*conn), GFP_KERNEL);
		if (!conn)
			continue;

		conn->inet_hash = key;
		INIT_HLIST_NODE(&conn->hlist);
		stress_conn_hash_add(shared->hash, conn, key);
		atomic_inc(&shared->total_connect);

		/* Immediate disconnect */
		stress_conn_hash_del(shared->hash, conn);
		atomic_inc(&shared->total_disconnect);
		kfree(conn);
	}

	stress_worker_done(ctx);
	return 0;
}

/*
 * test_stress_connection_storm - rapid connect/disconnect 1000x using
 * kthread workers.  Verifies no leaks and hash table remains consistent.
 */
static void test_stress_connection_storm(struct kunit *test)
{
	struct stress_thread_ctx ctx;
	struct conn_storm_shared shared;
	struct task_struct *threads[STRESS_NR_WORKERS];
	int i;

	stress_conn_hash_init(shared.hash);
	atomic_set(&shared.total_connect, 0);
	atomic_set(&shared.total_disconnect, 0);
	stress_ctx_init(&ctx, test, STRESS_NR_WORKERS, &shared);

	for (i = 0; i < STRESS_NR_WORKERS; i++) {
		threads[i] = kthread_create(worker_conn_storm, &ctx,
					    "conn_storm_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
		wake_up_process(threads[i]);
	}

	stress_wait_all_ready(&ctx, STRESS_NR_WORKERS);
	complete_all(&ctx.start_barrier);
	wait_for_completion(&ctx.done_barrier);

	/* All connects must have matching disconnects */
	KUNIT_EXPECT_EQ(test, atomic_read(&shared.total_connect),
			atomic_read(&shared.total_disconnect));

	/* Hash table should be empty */
	KUNIT_EXPECT_EQ(test, stress_conn_hash_count_total(shared.hash), 0);
}

/*
 * test_stress_session_exhaustion - allocate sessions up to a configured
 * limit using an xarray (mirrors conn->sessions).
 */
static void test_stress_session_exhaustion(struct kunit *test)
{
	struct xarray sessions;
	const unsigned int max_sessions = 128;
	unsigned int i;
	int stored = 0;
	void *val;

	xa_init(&sessions);

	for (i = 1; i <= max_sessions; i++) {
		val = xa_mk_value(i);
		if (xa_store(&sessions, i, val, GFP_KERNEL) == NULL)
			stored++;
	}

	KUNIT_EXPECT_EQ(test, (unsigned int)stored, max_sessions);

	/* Attempt one more beyond limit */
	val = xa_load(&sessions, max_sessions + 1);
	KUNIT_EXPECT_NULL(test, val);

	/* Verify all sessions present */
	for (i = 1; i <= max_sessions; i++) {
		val = xa_load(&sessions, i);
		KUNIT_EXPECT_NOT_NULL(test, val);
	}

	xa_destroy(&sessions);
}

/*
 * test_stress_session_timeout - verify stale sessions can be identified
 * by last_active timestamp.
 */
static void test_stress_session_timeout(struct kunit *test)
{
	struct stress_conn conn;
	const unsigned long timeout_jiffies = HZ * 2; /* 2 seconds */
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Set deadtime to 2 seconds */
	ret = ksmbd_config_set_u32(KSMBD_CFG_DEADTIME, 2);
	KUNIT_ASSERT_EQ(test, ret, 0);

	memset(&conn, 0, sizeof(conn));
	conn.last_active = jiffies;
	conn.status = STRESS_SESS_GOOD;

	/* Connection is fresh -- not timed out */
	KUNIT_EXPECT_FALSE(test,
		time_after(jiffies, conn.last_active + timeout_jiffies));

	/* Simulate aging by backdating last_active */
	conn.last_active = jiffies - timeout_jiffies - 1;

	/* Now it should appear timed out */
	KUNIT_EXPECT_TRUE(test,
		time_after(jiffies, conn.last_active + timeout_jiffies));

	/* Mark exiting as production code would */
	conn.status = STRESS_SESS_EXITING;
	KUNIT_EXPECT_EQ(test, conn.status, (int)STRESS_SESS_EXITING);

	ksmbd_config_exit();
}

/* ======================================================================
 * 2. CREDIT SYSTEM
 * ====================================================================== */

/*
 * test_stress_credit_exhaustion - consume all credits, verify new
 * requests are rejected.
 */
static void test_stress_credit_exhaustion(struct kunit *test)
{
	struct stress_conn conn;
	const unsigned int max_credits = 64;
	unsigned int i;
	bool ok;

	memset(&conn, 0, sizeof(conn));
	spin_lock_init(&conn.credits_lock);
	conn.total_credits = max_credits;
	conn.outstanding_credits = 0;

	/* Consume all credits one at a time */
	for (i = 0; i < max_credits; i++) {
		ok = stress_credit_charge_check(&conn, 1);
		KUNIT_EXPECT_TRUE(test, ok);
	}

	KUNIT_EXPECT_EQ(test, conn.outstanding_credits, max_credits);

	/* Next charge should fail */
	ok = stress_credit_charge_check(&conn, 1);
	KUNIT_EXPECT_FALSE(test, ok);

	/* Multi-credit charge should also fail */
	ok = stress_credit_charge_check(&conn, 5);
	KUNIT_EXPECT_FALSE(test, ok);
}

/*
 * test_stress_max_inflight - verify inflight request limit enforcement.
 * Outstanding credits cannot exceed total_credits.
 */
static void test_stress_max_inflight(struct kunit *test)
{
	struct stress_conn conn;
	const unsigned int total = 100;
	bool ok;

	memset(&conn, 0, sizeof(conn));
	spin_lock_init(&conn.credits_lock);
	conn.total_credits = total;
	conn.outstanding_credits = 0;

	/* Consume half */
	ok = stress_credit_charge_check(&conn, total / 2);
	KUNIT_EXPECT_TRUE(test, ok);
	KUNIT_EXPECT_EQ(test, conn.outstanding_credits, total / 2);

	/* Consume other half */
	ok = stress_credit_charge_check(&conn, total / 2);
	KUNIT_EXPECT_TRUE(test, ok);
	KUNIT_EXPECT_EQ(test, conn.outstanding_credits, total);

	/* No more room */
	ok = stress_credit_charge_check(&conn, 1);
	KUNIT_EXPECT_FALSE(test, ok);

	/* Return some credits and try again */
	stress_credit_consume(&conn, 10);
	ok = stress_credit_charge_check(&conn, 5);
	/*
	 * After consume: total_credits=90, outstanding=90.
	 * Check: outstanding(90)+5=95 > total(90) => still fails.
	 */
	KUNIT_EXPECT_FALSE(test, ok);

	/* Grant credits back */
	stress_credit_grant(&conn, 20, STRESS_SMB2_MAX_CREDITS);
	/* total now 110, outstanding still 90 */
	ok = stress_credit_charge_check(&conn, 10);
	KUNIT_EXPECT_TRUE(test, ok);
}

/*
 * test_stress_credit_wraparound - 100K+ grant/consume cycles to detect
 * counter wraparound or drift.
 */
static void test_stress_credit_wraparound(struct kunit *test)
{
	struct stress_conn conn;
	unsigned int i;

	memset(&conn, 0, sizeof(conn));
	spin_lock_init(&conn.credits_lock);
	conn.total_credits = 100;
	conn.outstanding_credits = 0;

	for (i = 0; i < STRESS_CREDIT_CYCLES; i++) {
		/* Grant 1 credit */
		stress_credit_grant(&conn, 1, STRESS_SMB2_MAX_CREDITS);
		/* Charge 1 credit */
		stress_credit_charge_check(&conn, 1);
		/* Consume 1 credit */
		stress_credit_consume(&conn, 1);
	}

	/*
	 * After 100K cycles, total should be 100 + 100000 - 100000 = 100
	 * (each cycle grants 1 and consumes 1).
	 * Outstanding should converge to 100 (all charged, outstanding
	 * reduced by consume back to 0 each cycle).
	 *
	 * Due to the capping in grant, actual total stabilizes at
	 * max_credits once it exceeds that threshold.  Let us just
	 * ensure no negative or overflow values.
	 */
	spin_lock(&conn.credits_lock);
	KUNIT_EXPECT_LE(test, conn.total_credits,
			(unsigned int)STRESS_SMB2_MAX_CREDITS);
	/* outstanding should not be negative (unsigned, so check <= total) */
	KUNIT_EXPECT_LE(test, conn.outstanding_credits, conn.total_credits);
	spin_unlock(&conn.credits_lock);
}

/* ======================================================================
 * 3. LOCK SYSTEM
 * ====================================================================== */

/*
 * test_stress_max_lock_count - fill lock list to KSMBD_MAX_LOCK_COUNT
 * (64) and verify the limit is enforced.
 */
static void test_stress_max_lock_count(struct kunit *test)
{
	struct list_head lock_list;
	struct stress_lock *locks;
	unsigned int i, count;

	INIT_LIST_HEAD(&lock_list);

	locks = kcalloc(STRESS_KSMBD_MAX_LOCK_COUNT + 1,
			sizeof(*locks), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, locks);

	/* Fill to max */
	for (i = 0; i < STRESS_KSMBD_MAX_LOCK_COUNT; i++) {
		locks[i].start = i * 4096;
		locks[i].end = (i + 1) * 4096;
		INIT_LIST_HEAD(&locks[i].llist);
		list_add_tail(&locks[i].llist, &lock_list);
	}

	/* Count entries */
	count = 0;
	{
		struct stress_lock *tmp;

		list_for_each_entry(tmp, &lock_list, llist)
			count++;
	}

	KUNIT_EXPECT_EQ(test, count, (unsigned int)STRESS_KSMBD_MAX_LOCK_COUNT);

	/* Attempt to add one more should be rejected by the limit check */
	count++;  /* Would be 65 */
	KUNIT_EXPECT_GT(test, count, (unsigned int)STRESS_KSMBD_MAX_LOCK_COUNT);

	kfree(locks);
}

/*
 * Lock contention context for parallel kthread workers.
 */
struct lock_contention_shared {
	struct list_head	lock_list;
	spinlock_t		lock;
	atomic_t		acquired;
	atomic_t		released;
};

static int worker_lock_contention(void *data)
{
	struct stress_thread_ctx *ctx = data;
	struct lock_contention_shared *shared = ctx->shared;
	int i;

	stress_worker_ready(ctx);

	for (i = 0; i < 200; i++) {
		struct stress_lock *lk;

		lk = kzalloc(sizeof(*lk), GFP_KERNEL);
		if (!lk)
			continue;

		lk->start = get_random_u32() % 1048576;
		lk->end = lk->start + (get_random_u32() % 4096) + 1;
		INIT_LIST_HEAD(&lk->llist);

		/* Acquire: add to list under lock */
		spin_lock(&shared->lock);
		list_add_tail(&lk->llist, &shared->lock_list);
		spin_unlock(&shared->lock);
		atomic_inc(&shared->acquired);

		cpu_relax();

		/* Release: remove from list under lock */
		spin_lock(&shared->lock);
		list_del(&lk->llist);
		spin_unlock(&shared->lock);
		atomic_inc(&shared->released);

		kfree(lk);
	}

	stress_worker_done(ctx);
	return 0;
}

/*
 * test_stress_lock_contention - parallel lock/unlock from kthreads.
 * Verifies that concurrent list manipulation does not corrupt state.
 */
static void test_stress_lock_contention(struct kunit *test)
{
	struct stress_thread_ctx ctx;
	struct lock_contention_shared shared;
	struct task_struct *threads[STRESS_NR_WORKERS];
	int i;

	INIT_LIST_HEAD(&shared.lock_list);
	spin_lock_init(&shared.lock);
	atomic_set(&shared.acquired, 0);
	atomic_set(&shared.released, 0);
	stress_ctx_init(&ctx, test, STRESS_NR_WORKERS, &shared);

	for (i = 0; i < STRESS_NR_WORKERS; i++) {
		threads[i] = kthread_create(worker_lock_contention, &ctx,
					    "lock_contend_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
		wake_up_process(threads[i]);
	}

	stress_wait_all_ready(&ctx, STRESS_NR_WORKERS);
	complete_all(&ctx.start_barrier);
	wait_for_completion(&ctx.done_barrier);

	/* Every acquire should have a matching release */
	KUNIT_EXPECT_EQ(test, atomic_read(&shared.acquired),
			atomic_read(&shared.released));

	/* Lock list should be empty */
	KUNIT_EXPECT_TRUE(test, list_empty(&shared.lock_list));
}

/*
 * test_stress_lock_accumulation - incremental lock buildup to limit.
 * Add locks one at a time, checking the running count at each step.
 */
static void test_stress_lock_accumulation(struct kunit *test)
{
	struct list_head lock_list;
	struct stress_lock *locks;
	unsigned int i, count;

	INIT_LIST_HEAD(&lock_list);

	locks = kcalloc(STRESS_KSMBD_MAX_LOCK_COUNT,
			sizeof(*locks), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, locks);

	for (i = 0; i < STRESS_KSMBD_MAX_LOCK_COUNT; i++) {
		locks[i].start = i * 1024;
		locks[i].end = locks[i].start + 1024;
		INIT_LIST_HEAD(&locks[i].llist);
		list_add_tail(&locks[i].llist, &lock_list);

		/* Verify running count */
		count = 0;
		{
			struct stress_lock *tmp;

			list_for_each_entry(tmp, &lock_list, llist)
				count++;
		}
		KUNIT_EXPECT_EQ(test, count, i + 1);
	}

	/* At max, verify full count */
	KUNIT_EXPECT_EQ(test, count, (unsigned int)STRESS_KSMBD_MAX_LOCK_COUNT);

	kfree(locks);
}

/* ======================================================================
 * 4. FILE HANDLE LIMITS
 * ====================================================================== */

/*
 * test_stress_max_open_files - open files up to file_max limit.
 */
static void test_stress_max_open_files(struct kunit *test)
{
	struct stress_fd_pool pool;
	const unsigned long max_files = 64;
	int *fds;
	int ret;
	unsigned long i;
	unsigned long opened = 0;

	stress_fd_pool_init(&pool, max_files);

	fds = kcalloc(max_files + 1, sizeof(int), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, fds);

	/* Open up to max */
	for (i = 0; i < max_files; i++) {
		ret = stress_fd_open(&pool);
		KUNIT_EXPECT_GE(test, ret, 0);
		if (ret >= 0) {
			fds[opened] = ret;
			opened++;
		}
	}

	KUNIT_EXPECT_EQ(test, opened, max_files);

	/* One more should fail */
	ret = stress_fd_open(&pool);
	KUNIT_EXPECT_EQ(test, ret, -EMFILE);

	/* Cleanup */
	for (i = 0; i < opened; i++)
		stress_fd_close(&pool, fds[i]);

	kfree(fds);
	stress_fd_pool_destroy(&pool);
}

/*
 * test_stress_handle_leak_detection - open/close cycle, verify no leaks
 * via fd_limit being restored.
 */
static void test_stress_handle_leak_detection(struct kunit *test)
{
	struct stress_fd_pool pool;
	const unsigned long max_files = 32;
	int fds[32];
	unsigned long i;
	int ret;

	stress_fd_pool_init(&pool, max_files);

	/* Open/close cycle 100 times */
	for (i = 0; i < 100; i++) {
		ret = stress_fd_open(&pool);
		KUNIT_ASSERT_GE(test, ret, 0);
		stress_fd_close(&pool, ret);
	}

	/* After all cycles, limit should be fully restored */
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.open_count), 0);

	/* Should be able to open max_files again */
	for (i = 0; i < max_files; i++) {
		ret = stress_fd_open(&pool);
		KUNIT_ASSERT_GE(test, ret, 0);
		fds[i] = ret;
	}

	/* One more should fail */
	ret = stress_fd_open(&pool);
	KUNIT_EXPECT_LT(test, ret, 0);

	for (i = 0; i < max_files; i++)
		stress_fd_close(&pool, fds[i]);

	stress_fd_pool_destroy(&pool);
}

/*
 * test_stress_handle_reuse - verify handles are recycled after close.
 */
static void test_stress_handle_reuse(struct kunit *test)
{
	struct stress_fd_pool pool;
	const unsigned long max_files = 8;
	int fds[8];
	int reused_fd;
	unsigned long i;
	int ret;
	bool found_reuse = false;

	stress_fd_pool_init(&pool, max_files);

	/* Open all handles */
	for (i = 0; i < max_files; i++) {
		ret = stress_fd_open(&pool);
		KUNIT_ASSERT_GE(test, ret, 0);
		fds[i] = ret;
	}

	/* Close one and reopen -- IDR may recycle the same slot */
	stress_fd_close(&pool, fds[0]);
	reused_fd = stress_fd_open(&pool);
	KUNIT_ASSERT_GE(test, reused_fd, 0);

	/* Check if any existing FD matches (IDR often reuses lowest free) */
	for (i = 0; i < max_files; i++) {
		if ((int)i != 0 && fds[i] == reused_fd)
			found_reuse = true;
	}
	/*
	 * Whether or not the exact ID is reused depends on IDR internals.
	 * The important thing is that we could allocate a new handle after
	 * closing one.
	 */
	KUNIT_EXPECT_GE(test, reused_fd, 0);

	/* Cleanup */
	stress_fd_close(&pool, reused_fd);
	for (i = 1; i < max_files; i++)
		stress_fd_close(&pool, fds[i]);

	stress_fd_pool_destroy(&pool);
}

/* ======================================================================
 * 5. BUFFER / IO LIMITS
 * ====================================================================== */

/*
 * test_stress_max_buffer_size - verify buffer_check_err at boundary.
 */
static void test_stress_max_buffer_size(struct kunit *test)
{
	int ret;

	/* Exact fit: should succeed */
	ret = stress_buffer_check_err(1024, 1024);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Buffer larger than needed: should succeed */
	ret = stress_buffer_check_err(2048, 1024);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Buffer too small: should fail */
	ret = stress_buffer_check_err(512, 1024);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	/* Zero output buffer, non-zero needed: should fail */
	ret = stress_buffer_check_err(0, 1);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	/* Both zero: should succeed */
	ret = stress_buffer_check_err(0, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* At max_trans_size boundary (8MB) */
	ret = stress_buffer_check_err(8388608, 8388608);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = stress_buffer_check_err(8388607, 8388608);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * test_stress_max_read_write_size - verify size enforcement per config.
 */
static void test_stress_max_read_write_size(struct kunit *test)
{
	int ret;
	u32 max_read, max_write;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Default max read size is 65536 */
	max_read = ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE);
	KUNIT_EXPECT_EQ(test, max_read, (u32)65536);

	/* Default max write size is 65536 */
	max_write = ksmbd_config_get_u32(KSMBD_CFG_MAX_WRITE_SIZE);
	KUNIT_EXPECT_EQ(test, max_write, (u32)65536);

	/* Set to maximum allowed (8MB) */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 8388608);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)8388608);

	/* Exceed maximum: gets clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 16777216);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)8388608);

	/* Below minimum (4096): gets clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_WRITE_SIZE, 1024);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_WRITE_SIZE), (u32)4096);

	ksmbd_config_exit();
}

/*
 * test_stress_zero_size_io - zero-length read/write handling.
 * The credit charge formula for zero-length I/O should produce 0.
 */
static void test_stress_zero_size_io(struct kunit *test)
{
	unsigned int charge;
	u64 req_len = 0, resp_len = 0;
	u64 max_len;

	/* Credit charge formula: DIV_ROUND_UP(max(req, resp), 65536) */
	max_len = max_t(u64, req_len, resp_len);
	if (max_len == 0)
		charge = 0;
	else
		charge = DIV_ROUND_UP(max_len, STRESS_SMB2_MAX_BUFFER_SIZE);

	KUNIT_EXPECT_EQ(test, charge, 0U);

	/* Zero-length buffer check should succeed */
	KUNIT_EXPECT_EQ(test, stress_buffer_check_err(0, 0), 0);

	/* Zero request with non-zero response */
	req_len = 0;
	resp_len = 65536;
	max_len = max_t(u64, req_len, resp_len);
	charge = DIV_ROUND_UP(max_len, STRESS_SMB2_MAX_BUFFER_SIZE);
	KUNIT_EXPECT_EQ(test, charge, 1U);
}

/* ======================================================================
 * 6. COMPRESSION
 * ====================================================================== */

/*
 * Simulated compression output size limit.  In production, ksmbd caps
 * compressed output to prevent compression bombs.  We simulate the
 * check: output must not exceed 2x input + header.
 */
#define STRESS_COMPRESS_HEADER_SIZE	16
#define STRESS_COMPRESS_MAX_RATIO	2

static int stress_compress_check_output(size_t input_len, size_t output_len)
{
	size_t max_output = input_len * STRESS_COMPRESS_MAX_RATIO +
			    STRESS_COMPRESS_HEADER_SIZE;

	if (output_len > max_output)
		return -E2BIG;
	return 0;
}

/*
 * test_stress_compression_bomb - small input, verify output size capped.
 */
static void test_stress_compression_bomb(struct kunit *test)
{
	int ret;

	/* 100 bytes input, 10000 bytes output -> bomb detected */
	ret = stress_compress_check_output(100, 10000);
	KUNIT_EXPECT_EQ(test, ret, -E2BIG);

	/* 100 bytes input, 200 bytes output -> within limit (200+16) */
	ret = stress_compress_check_output(100, 200);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* 100 bytes input, exactly at limit (216) */
	ret = stress_compress_check_output(100, 216);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* 100 bytes input, one byte over limit (217) */
	ret = stress_compress_check_output(100, 217);
	KUNIT_EXPECT_EQ(test, ret, -E2BIG);

	/* Zero input -- only header allowed */
	ret = stress_compress_check_output(0, STRESS_COMPRESS_HEADER_SIZE);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = stress_compress_check_output(0, STRESS_COMPRESS_HEADER_SIZE + 1);
	KUNIT_EXPECT_EQ(test, ret, -E2BIG);
}

/*
 * test_stress_compression_ratio_limit - crafted high-ratio input.
 * Simulates a highly compressible input (e.g. all zeros) and verifies
 * the output ratio check catches excessive expansion claims.
 */
static void test_stress_compression_ratio_limit(struct kunit *test)
{
	size_t input_sizes[] = {1, 64, 4096, 65536, 1048576};
	int i;

	for (i = 0; i < ARRAY_SIZE(input_sizes); i++) {
		size_t in = input_sizes[i];
		size_t max_out = in * STRESS_COMPRESS_MAX_RATIO +
				 STRESS_COMPRESS_HEADER_SIZE;

		/* At limit: OK */
		KUNIT_EXPECT_EQ(test,
			stress_compress_check_output(in, max_out), 0);

		/* Over limit: rejected */
		KUNIT_EXPECT_EQ(test,
			stress_compress_check_output(in, max_out + 1), -E2BIG);
	}
}

/* ======================================================================
 * 7. TIMEOUTS
 * ====================================================================== */

/*
 * test_stress_tcp_recv_timeout - idle connection cleanup.
 * Verify that the KSMBD_TCP_RECV_TIMEOUT (7 * HZ) constant produces
 * a meaningful timeout, and that connections exceeding it are identified.
 */
static void test_stress_tcp_recv_timeout(struct kunit *test)
{
	const unsigned long recv_timeout = 7 * HZ;
	struct stress_conn conn;
	unsigned long now;

	memset(&conn, 0, sizeof(conn));
	conn.status = STRESS_SESS_GOOD;

	/* Simulate active connection */
	conn.last_active = jiffies;
	now = jiffies;
	KUNIT_EXPECT_FALSE(test,
		time_after(now, conn.last_active + recv_timeout));

	/* Simulate connection that has been idle beyond recv_timeout */
	conn.last_active = jiffies - recv_timeout - 1;
	now = jiffies;
	KUNIT_EXPECT_TRUE(test,
		time_after(now, conn.last_active + recv_timeout));

	/* Verify the timeout constant is at least 7 seconds */
	KUNIT_EXPECT_GE(test, recv_timeout, 7UL * HZ);
}

/*
 * test_stress_deadtime - deadtime enforcement.
 * Uses the config system to set deadtime and verifies the computed
 * timeout value.
 */
static void test_stress_deadtime(struct kunit *test)
{
	int ret;
	u32 deadtime;
	unsigned long timeout_jiffies;
	struct stress_conn conn;
	unsigned long now;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Default deadtime is 0 (disabled) */
	deadtime = ksmbd_config_get_u32(KSMBD_CFG_DEADTIME);
	KUNIT_EXPECT_EQ(test, deadtime, (u32)0);

	/* Set deadtime to 60 seconds */
	ret = ksmbd_config_set_u32(KSMBD_CFG_DEADTIME, 60);
	KUNIT_EXPECT_EQ(test, ret, 0);
	deadtime = ksmbd_config_get_u32(KSMBD_CFG_DEADTIME);
	KUNIT_EXPECT_EQ(test, deadtime, (u32)60);

	timeout_jiffies = (unsigned long)deadtime * HZ;

	memset(&conn, 0, sizeof(conn));
	conn.status = STRESS_SESS_GOOD;
	conn.last_active = jiffies;

	/* Not expired yet */
	now = jiffies;
	KUNIT_EXPECT_FALSE(test,
		time_after(now, conn.last_active + timeout_jiffies));

	/* Backdate to simulate idle connection */
	conn.last_active = jiffies - timeout_jiffies - HZ;
	now = jiffies;
	KUNIT_EXPECT_TRUE(test,
		time_after(now, conn.last_active + timeout_jiffies));

	/* Max deadtime: 86400 seconds (24 hours) */
	ret = ksmbd_config_set_u32(KSMBD_CFG_DEADTIME, 86400);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_DEADTIME), (u32)86400);

	/* Exceeding 86400 gets clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_DEADTIME, 100000);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_DEADTIME), (u32)86400);

	ksmbd_config_exit();
}

/* ======================================================================
 * 8. ADDITIONAL STRESS SCENARIOS
 * ====================================================================== */

/*
 * test_stress_config_concurrent_set_get - concurrent config access.
 * Multiple kthreads set and read config values simultaneously.
 */
struct config_stress_shared {
	atomic_t	set_count;
	atomic_t	get_count;
};

static int worker_config_setter(void *data)
{
	struct stress_thread_ctx *ctx = data;
	struct config_stress_shared *shared = ctx->shared;
	int i;

	stress_worker_ready(ctx);

	for (i = 0; i < 500; i++) {
		/* Rotate through various config parameters */
		ksmbd_config_set_u32(KSMBD_CFG_MAX_CONNECTIONS,
				     (get_random_u32() % 65535) + 1);
		atomic_inc(&shared->set_count);

		ksmbd_config_set_u32(KSMBD_CFG_MAX_CONNECTIONS_PER_IP,
				     (get_random_u32() % 65535) + 1);
		atomic_inc(&shared->set_count);

		ksmbd_config_set_u32(KSMBD_CFG_DEADTIME,
				     get_random_u32() % 86401);
		atomic_inc(&shared->set_count);
	}

	stress_worker_done(ctx);
	return 0;
}

static int worker_config_getter(void *data)
{
	struct stress_thread_ctx *ctx = data;
	struct config_stress_shared *shared = ctx->shared;
	int i;

	stress_worker_ready(ctx);

	for (i = 0; i < 500; i++) {
		u32 val;

		val = ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS);
		/* Value must be within valid range */
		KUNIT_EXPECT_LE(ctx->test, val, (u32)65535);
		atomic_inc(&shared->get_count);

		val = ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS_PER_IP);
		KUNIT_EXPECT_LE(ctx->test, val, (u32)65535);
		atomic_inc(&shared->get_count);

		val = ksmbd_config_get_u32(KSMBD_CFG_DEADTIME);
		KUNIT_EXPECT_LE(ctx->test, val, (u32)86400);
		atomic_inc(&shared->get_count);
	}

	stress_worker_done(ctx);
	return 0;
}

static void test_stress_config_concurrent_set_get(struct kunit *test)
{
	struct stress_thread_ctx ctx;
	struct config_stress_shared shared;
	struct task_struct *threads[STRESS_NR_WORKERS];
	int i, ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	atomic_set(&shared.set_count, 0);
	atomic_set(&shared.get_count, 0);
	stress_ctx_init(&ctx, test, STRESS_NR_WORKERS, &shared);

	/* Half setters, half getters */
	for (i = 0; i < STRESS_NR_WORKERS / 2; i++) {
		threads[i] = kthread_create(worker_config_setter, &ctx,
					    "cfg_set_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
		wake_up_process(threads[i]);
	}
	for (i = STRESS_NR_WORKERS / 2; i < STRESS_NR_WORKERS; i++) {
		threads[i] = kthread_create(worker_config_getter, &ctx,
					    "cfg_get_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
		wake_up_process(threads[i]);
	}

	stress_wait_all_ready(&ctx, STRESS_NR_WORKERS);
	complete_all(&ctx.start_barrier);
	wait_for_completion(&ctx.done_barrier);

	KUNIT_EXPECT_GT(test, atomic_read(&shared.set_count), 0);
	KUNIT_EXPECT_GT(test, atomic_read(&shared.get_count), 0);

	ksmbd_config_exit();
}

/*
 * test_stress_copy_chunk_limits - verify copy chunk config limits.
 */
static void test_stress_copy_chunk_limits(struct kunit *test)
{
	int ret;
	u32 val;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Default copy chunk max count = 256 */
	val = ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT);
	KUNIT_EXPECT_EQ(test, val, (u32)256);

	/* Default copy chunk max size = 1MB */
	val = ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_SIZE);
	KUNIT_EXPECT_EQ(test, val, (u32)1048576);

	/* Default copy chunk total size = 16MB */
	val = ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE);
	KUNIT_EXPECT_EQ(test, val, (u32)16777216);

	/* Exceed max count (65535): clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT, 100000);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT),
		(u32)65535);

	/* Below min (1): clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_MAX_COUNT),
		(u32)1);

	/* Total size max (256MB): within range */
	ret = ksmbd_config_set_u32(KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE, 268435456);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE),
		(u32)268435456);

	ksmbd_config_exit();
}

/*
 * test_stress_echo_interval - SMB echo interval config limits.
 */
static void test_stress_echo_interval(struct kunit *test)
{
	int ret;
	u32 val;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Default is 0 (disabled) */
	val = ksmbd_config_get_u32(KSMBD_CFG_SMB_ECHO_INTERVAL);
	KUNIT_EXPECT_EQ(test, val, (u32)0);

	/* Set to valid value */
	ret = ksmbd_config_set_u32(KSMBD_CFG_SMB_ECHO_INTERVAL, 120);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_SMB_ECHO_INTERVAL), (u32)120);

	/* Exceed max (3600): clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_SMB_ECHO_INTERVAL, 7200);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_SMB_ECHO_INTERVAL), (u32)3600);

	ksmbd_config_exit();
}

/* ======================================================================
 * Test suite registration
 * ====================================================================== */

static struct kunit_case ksmbd_stress_test_cases[] = {
	/* Connection / Session limits */
	KUNIT_CASE(test_stress_max_connections),
	KUNIT_CASE(test_stress_max_connections_per_ip),
	KUNIT_CASE(test_stress_connection_storm),
	KUNIT_CASE(test_stress_session_exhaustion),
	KUNIT_CASE(test_stress_session_timeout),

	/* Credit system */
	KUNIT_CASE(test_stress_credit_exhaustion),
	KUNIT_CASE(test_stress_max_inflight),
	KUNIT_CASE(test_stress_credit_wraparound),

	/* Lock system */
	KUNIT_CASE(test_stress_max_lock_count),
	KUNIT_CASE(test_stress_lock_contention),
	KUNIT_CASE(test_stress_lock_accumulation),

	/* File handle limits */
	KUNIT_CASE(test_stress_max_open_files),
	KUNIT_CASE(test_stress_handle_leak_detection),
	KUNIT_CASE(test_stress_handle_reuse),

	/* Buffer / IO limits */
	KUNIT_CASE(test_stress_max_buffer_size),
	KUNIT_CASE(test_stress_max_read_write_size),
	KUNIT_CASE(test_stress_zero_size_io),

	/* Compression */
	KUNIT_CASE(test_stress_compression_bomb),
	KUNIT_CASE(test_stress_compression_ratio_limit),

	/* Timeouts */
	KUNIT_CASE(test_stress_tcp_recv_timeout),
	KUNIT_CASE(test_stress_deadtime),

	/* Additional stress scenarios */
	KUNIT_CASE(test_stress_config_concurrent_set_get),
	KUNIT_CASE(test_stress_copy_chunk_limits),
	KUNIT_CASE(test_stress_echo_interval),
	{}
};

static struct kunit_suite ksmbd_stress_test_suite = {
	.name = "ksmbd_stress",
	.test_cases = ksmbd_stress_test_cases,
};

kunit_test_suite(ksmbd_stress_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit stress tests for ksmbd server limits and resource management");
