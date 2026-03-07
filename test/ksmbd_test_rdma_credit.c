// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for RDMA/SMB Direct credit pool accounting
 *
 *   These tests exercise the smbd_credit_pool API that underpins
 *   the per-connection receive credit management in transport_rdma.c.
 *   No RDMA hardware or kernel RDMA stack is required; all tests
 *   operate purely on the credit pool math/logic layer.
 *
 *   The credit pool maintains the invariant:
 *     granted + available == total
 *
 *   Tests cover: initialization, granting, reclaiming, bounds checking,
 *   invariant verification, exhaustion, recovery, leak detection,
 *   multi-lifecycle simulation, and abrupt disconnect reclaim.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#include "transport_rdma.h"

/* ──────────────────────────────────────────────────────────────────────────
 * 1. Initialization tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_pool_init_default - pool initializes with correct defaults
 *
 * After initialization with the default total (255), the pool should have
 * all credits available and none granted.
 */
static void test_credit_pool_init_default(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int ret;

	ret = smbd_credit_pool_init(&pool, SMBD_CREDIT_POOL_DEFAULT_TOTAL);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, pool.total, 255);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_granted), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_reclaimed), 0);
}

/*
 * test_credit_pool_init_custom - pool initializes with a custom total
 */
static void test_credit_pool_init_custom(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int ret;

	ret = smbd_credit_pool_init(&pool, 100);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, pool.total, 100);
	KUNIT_EXPECT_EQ(test, pool.available, 100);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
}

/*
 * test_credit_pool_init_invalid - init rejects zero and negative totals
 */
static void test_credit_pool_init_invalid(struct kunit *test)
{
	struct smbd_credit_pool pool;

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_init(&pool, 0), -EINVAL);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_init(&pool, -1), -EINVAL);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_init(&pool, -255), -EINVAL);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 2. Grant tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_grant_basic - granting N credits decrements available by N
 */
static void test_credit_grant_basic(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int ret;

	smbd_credit_pool_init(&pool, 255);

	ret = smbd_credit_pool_grant(&pool, 10);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, pool.available, 245);
	KUNIT_EXPECT_EQ(test, pool.granted, 10);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_granted), 10);
}

/*
 * test_credit_grant_zero - granting zero credits is a no-op
 */
static void test_credit_grant_zero(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, 0), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_granted), 0);
}

/*
 * test_credit_grant_negative - granting negative credits is rejected
 */
static void test_credit_grant_negative(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, -1), -EINVAL);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, -255), -EINVAL);
	/* Pool state should be unchanged */
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
}

/*
 * test_credit_grant_exceeds_available - cannot grant more than available
 */
static void test_credit_grant_exceeds_available(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, 256), -ENOSPC);
	/* Pool state should be unchanged */
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 3. Reclaim tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_reclaim_basic - reclaiming N credits increments available by N
 */
static void test_credit_reclaim_basic(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);
	smbd_credit_pool_grant(&pool, 100);

	KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 50), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 205);
	KUNIT_EXPECT_EQ(test, pool.granted, 50);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_reclaimed), 50);
}

/*
 * test_credit_reclaim_zero - reclaiming zero credits is a no-op
 */
static void test_credit_reclaim_zero(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);
	smbd_credit_pool_grant(&pool, 10);

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_reclaim(&pool, 0), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 245);
	KUNIT_EXPECT_EQ(test, pool.granted, 10);
}

/*
 * test_credit_reclaim_negative - reclaiming negative credits is rejected
 */
static void test_credit_reclaim_negative(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);
	smbd_credit_pool_grant(&pool, 10);

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_reclaim(&pool, -1), -EINVAL);
	KUNIT_EXPECT_EQ(test, pool.available, 245);
	KUNIT_EXPECT_EQ(test, pool.granted, 10);
}

/*
 * test_credit_reclaim_exceeds_granted - cannot reclaim more than granted
 */
static void test_credit_reclaim_exceeds_granted(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);
	smbd_credit_pool_grant(&pool, 10);

	KUNIT_EXPECT_EQ(test, smbd_credit_pool_reclaim(&pool, 11), -EINVAL);
	/* Pool state should be unchanged */
	KUNIT_EXPECT_EQ(test, pool.available, 245);
	KUNIT_EXPECT_EQ(test, pool.granted, 10);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 4. Grant + reclaim cycle tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_grant_reclaim_cycle - grant + reclaim returns to initial state
 */
static void test_credit_grant_reclaim_cycle(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	/* Grant all */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 255), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 0);
	KUNIT_EXPECT_EQ(test, pool.granted, 255);

	/* Reclaim all */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 255), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);

	/* Lifetime counters reflect the cycle */
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_granted), 255);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_reclaimed), 255);
}

/*
 * test_credit_partial_reclaim - grant 100, reclaim 50, verify 205 available
 */
static void test_credit_partial_reclaim(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 100), 0);
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 50), 0);

	KUNIT_EXPECT_EQ(test, pool.available, 205);
	KUNIT_EXPECT_EQ(test, pool.granted, 50);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 5. Invariant tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_invariant_after_operations - invariant holds after mixed ops
 */
static void test_credit_invariant_after_operations(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int i;

	smbd_credit_pool_init(&pool, 255);

	/* Simulate a sequence of grants and reclaims */
	for (i = 0; i < 50; i++) {
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 1), 0);
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_audit(&pool), 0);
	}

	for (i = 0; i < 25; i++) {
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 1), 0);
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_audit(&pool), 0);
	}

	/* Final state: 25 granted, 230 available */
	KUNIT_EXPECT_EQ(test, pool.granted, 25);
	KUNIT_EXPECT_EQ(test, pool.available, 230);
	KUNIT_EXPECT_EQ(test, pool.granted + pool.available, pool.total);
}

/*
 * test_credit_invariant_always_true - granted + available == total (always)
 */
static void test_credit_invariant_always_true(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	/* After init */
	KUNIT_EXPECT_EQ(test, pool.granted + pool.available, pool.total);

	/* After grant */
	smbd_credit_pool_grant(&pool, 100);
	KUNIT_EXPECT_EQ(test, pool.granted + pool.available, pool.total);

	/* After partial reclaim */
	smbd_credit_pool_reclaim(&pool, 30);
	KUNIT_EXPECT_EQ(test, pool.granted + pool.available, pool.total);

	/* After full reclaim */
	smbd_credit_pool_reclaim(&pool, 70);
	KUNIT_EXPECT_EQ(test, pool.granted + pool.available, pool.total);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 6. Exhaustion and recovery tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_pool_exhaustion - grant all 255, try granting 1 more -> fail
 */
static void test_credit_pool_exhaustion(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 255), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 0);

	/* Should fail */
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, 1), -ENOSPC);
	KUNIT_EXPECT_EQ(test, pool.available, 0);
	KUNIT_EXPECT_EQ(test, pool.granted, 255);
}

/*
 * test_credit_pool_recovery - full exhaustion + reclaim recovers the pool
 */
static void test_credit_pool_recovery(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	/* Exhaust */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 255), 0);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, 1), -ENOSPC);

	/* Reclaim all */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 255), 0);

	/* Pool is fully recovered */
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);

	/* Can grant again */
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, 100), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 155);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 7. Abrupt disconnect simulation
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_reclaim_all_on_disconnect - reclaim_all returns all credits
 *
 * Simulates abrupt disconnect: some credits are granted (posted to HW),
 * then reclaim_all is called (as would happen after ib_drain_qp).
 */
static void test_credit_reclaim_all_on_disconnect(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int reclaimed;

	smbd_credit_pool_init(&pool, 255);

	/* Simulate 200 posted buffers */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 200), 0);

	/* Abrupt disconnect: reclaim all */
	reclaimed = smbd_credit_pool_reclaim_all(&pool);
	KUNIT_EXPECT_EQ(test, reclaimed, 200);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_audit(&pool), 0);
}

/*
 * test_credit_reclaim_all_empty - reclaim_all on empty pool returns 0
 */
static void test_credit_reclaim_all_empty(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int reclaimed;

	smbd_credit_pool_init(&pool, 255);

	reclaimed = smbd_credit_pool_reclaim_all(&pool);
	KUNIT_EXPECT_EQ(test, reclaimed, 0);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 8. Audit and leak detection tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_audit_clean - audit succeeds on a clean pool
 */
static void test_credit_audit_clean(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_audit(&pool), 0);

	smbd_credit_pool_grant(&pool, 100);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_audit(&pool), 0);

	smbd_credit_pool_reclaim(&pool, 100);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_audit(&pool), 0);
}

/*
 * test_credit_leak_detection - check_leak detects outstanding credits
 */
static void test_credit_leak_detection(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	/* No leak on clean pool */
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_check_leak(&pool), 0);

	/* Grant without reclaiming -> leak */
	smbd_credit_pool_grant(&pool, 10);
	KUNIT_EXPECT_NE(test, smbd_credit_pool_check_leak(&pool), 0);

	/* Partial reclaim -> still a leak */
	smbd_credit_pool_reclaim(&pool, 5);
	KUNIT_EXPECT_NE(test, smbd_credit_pool_check_leak(&pool), 0);

	/* Full reclaim -> no leak */
	smbd_credit_pool_reclaim(&pool, 5);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_check_leak(&pool), 0);
}

/*
 * test_credit_audit_detects_corruption - audit detects a corrupted pool
 *
 * Manually corrupt the pool state and verify audit catches it.
 */
static void test_credit_audit_detects_corruption(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	/* Manually corrupt: break the invariant */
	spin_lock(&pool.lock);
	pool.available = 200;
	pool.granted = 100;
	/* 200 + 100 = 300 != 255, invariant broken */
	spin_unlock(&pool.lock);

	KUNIT_EXPECT_NE(test, smbd_credit_pool_audit(&pool), 0);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 9. Multi-lifecycle simulation tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_multiple_lifecycles - simulate multiple connection lifecycles
 *
 * Each lifecycle: grant some credits, do work, reclaim all.
 * After each lifecycle, verify no leak and pool is whole.
 */
static void test_credit_multiple_lifecycles(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int lifecycle;

	smbd_credit_pool_init(&pool, 255);

	for (lifecycle = 0; lifecycle < 10; lifecycle++) {
		int grant_count = (lifecycle + 1) * 20;

		if (grant_count > 255)
			grant_count = 255;

		/* Connection setup: grant credits */
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, grant_count), 0);
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_audit(&pool), 0);

		/* Simulate some recv completions (partial reclaim) */
		if (grant_count > 10) {
			KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 10), 0);
			/* Re-grant the reclaimed ones */
			KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 10), 0);
		}

		/* Connection teardown: reclaim all */
		smbd_credit_pool_reclaim_all(&pool);
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_audit(&pool), 0);
		KUNIT_ASSERT_EQ(test, pool.available, 255);
		KUNIT_ASSERT_EQ(test, pool.granted, 0);
	}
}

/* ──────────────────────────────────────────────────────────────────────────
 * 10. Concurrent access simulation tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_sequential_concurrent_simulation - model concurrent grant/reclaim
 *
 * Simulates interleaved grant and reclaim operations as would happen
 * from concurrent recv_done and post_recv_credits paths.
 */
static void test_credit_sequential_concurrent_simulation(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int i;

	smbd_credit_pool_init(&pool, 255);

	/*
	 * Simulate the pattern: post_recv_credits grants a batch,
	 * recv_done reclaims one at a time, interleaved.
	 */
	for (i = 0; i < 100; i++) {
		/* post_recv_credits: grant 5 */
		if (pool.available >= 5) {
			KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 5), 0);
		}

		/* recv_done: reclaim 3 */
		if (pool.granted >= 3) {
			KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 3), 0);
		}

		/* Invariant must always hold */
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_audit(&pool), 0);
	}

	/* Cleanup: reclaim all remaining */
	smbd_credit_pool_reclaim_all(&pool);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
}

/*
 * test_credit_rapid_grant_reclaim - rapidly grant and reclaim 1 credit each
 *
 * Stress test: 1000 iterations of grant-1, reclaim-1.
 * Pool should be unchanged at the end.
 */
static void test_credit_rapid_grant_reclaim(struct kunit *test)
{
	struct smbd_credit_pool pool;
	int i;

	smbd_credit_pool_init(&pool, 255);

	for (i = 0; i < 1000; i++) {
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 1), 0);
		KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 1), 0);
	}

	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_granted), 1000);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_reclaimed), 1000);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_check_leak(&pool), 0);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 11. Edge case tests
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_credit_pool_size_one - pool with total=1 works correctly
 */
static void test_credit_pool_size_one(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 1);

	KUNIT_EXPECT_EQ(test, pool.total, 1);
	KUNIT_EXPECT_EQ(test, pool.available, 1);

	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 1), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 0);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_grant(&pool, 1), -ENOSPC);

	KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 1), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 1);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_audit(&pool), 0);
}

/*
 * test_credit_large_batch_grant - grant and reclaim large batch at once
 */
static void test_credit_large_batch_grant(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	/* Grant all at once */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_grant(&pool, 255), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 0);
	KUNIT_EXPECT_EQ(test, pool.granted, 255);

	/* Reclaim all at once */
	KUNIT_ASSERT_EQ(test, smbd_credit_pool_reclaim(&pool, 255), 0);
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_audit(&pool), 0);
}

/*
 * test_credit_lifetime_counters_accumulate - lifetime counters grow correctly
 *
 * Verifies that lifetime_granted and lifetime_reclaimed accumulate
 * across multiple grant/reclaim operations, unlike the instantaneous
 * granted/available counters.
 */
static void test_credit_lifetime_counters_accumulate(struct kunit *test)
{
	struct smbd_credit_pool pool;

	smbd_credit_pool_init(&pool, 255);

	smbd_credit_pool_grant(&pool, 50);
	smbd_credit_pool_reclaim(&pool, 50);

	smbd_credit_pool_grant(&pool, 100);
	smbd_credit_pool_reclaim(&pool, 100);

	smbd_credit_pool_grant(&pool, 200);
	smbd_credit_pool_reclaim(&pool, 200);

	/* Pool is back to initial state */
	KUNIT_EXPECT_EQ(test, pool.available, 255);
	KUNIT_EXPECT_EQ(test, pool.granted, 0);

	/* But lifetime counters reflect all operations */
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_granted), 350);
	KUNIT_EXPECT_EQ(test, atomic_read(&pool.lifetime_reclaimed), 350);
	KUNIT_EXPECT_EQ(test, smbd_credit_pool_check_leak(&pool), 0);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_rdma_credit_test_cases[] = {
	/* Initialization */
	KUNIT_CASE(test_credit_pool_init_default),
	KUNIT_CASE(test_credit_pool_init_custom),
	KUNIT_CASE(test_credit_pool_init_invalid),
	/* Grant */
	KUNIT_CASE(test_credit_grant_basic),
	KUNIT_CASE(test_credit_grant_zero),
	KUNIT_CASE(test_credit_grant_negative),
	KUNIT_CASE(test_credit_grant_exceeds_available),
	/* Reclaim */
	KUNIT_CASE(test_credit_reclaim_basic),
	KUNIT_CASE(test_credit_reclaim_zero),
	KUNIT_CASE(test_credit_reclaim_negative),
	KUNIT_CASE(test_credit_reclaim_exceeds_granted),
	/* Grant + reclaim cycle */
	KUNIT_CASE(test_credit_grant_reclaim_cycle),
	KUNIT_CASE(test_credit_partial_reclaim),
	/* Invariant */
	KUNIT_CASE(test_credit_invariant_after_operations),
	KUNIT_CASE(test_credit_invariant_always_true),
	/* Exhaustion and recovery */
	KUNIT_CASE(test_credit_pool_exhaustion),
	KUNIT_CASE(test_credit_pool_recovery),
	/* Abrupt disconnect */
	KUNIT_CASE(test_credit_reclaim_all_on_disconnect),
	KUNIT_CASE(test_credit_reclaim_all_empty),
	/* Audit and leak detection */
	KUNIT_CASE(test_credit_audit_clean),
	KUNIT_CASE(test_credit_leak_detection),
	KUNIT_CASE(test_credit_audit_detects_corruption),
	/* Multi-lifecycle */
	KUNIT_CASE(test_credit_multiple_lifecycles),
	/* Concurrent simulation */
	KUNIT_CASE(test_credit_sequential_concurrent_simulation),
	KUNIT_CASE(test_credit_rapid_grant_reclaim),
	/* Edge cases */
	KUNIT_CASE(test_credit_pool_size_one),
	KUNIT_CASE(test_credit_large_batch_grant),
	KUNIT_CASE(test_credit_lifetime_counters_accumulate),
	{}
};

static struct kunit_suite ksmbd_rdma_credit_test_suite = {
	.name = "ksmbd_rdma_credit",
	.test_cases = ksmbd_rdma_credit_test_cases,
};

kunit_test_suite(ksmbd_rdma_credit_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for RDMA/SMB Direct credit pool accounting");
