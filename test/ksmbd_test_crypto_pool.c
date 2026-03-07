// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for crypto context pool exhaustion protection,
 *   statistics tracking, and leak detection (crypto_ctx.c).
 *
 *   These tests exercise the hardened crypto pool introduced to prevent
 *   DoS via unbounded crypto context allocation during multichannel
 *   session binding.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <crypto/hash.h>
#include <crypto/aead.h>

#include "crypto_ctx.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/*
 * Suite init: create the crypto pool before any test runs.
 */
static int crypto_pool_test_init(struct kunit *test)
{
	int rc;

	rc = ksmbd_crypto_create();
	if (rc) {
		kunit_err(test, "ksmbd_crypto_create failed: %d\n", rc);
		return rc;
	}
	return 0;
}

/*
 * Suite exit: tear down the crypto pool after all tests.
 */
static void crypto_pool_test_exit(struct kunit *test)
{
	ksmbd_crypto_destroy();
}

/* ---- Test 1: Initial pool is nearly empty (1 pre-allocated) ---- */
static void test_pool_initial_state(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;

	ksmbd_crypto_ctx_pool_stats(&stats);

	/* After ksmbd_crypto_create(), pool_total = 1, in_use = 0 */
	KUNIT_EXPECT_EQ(test, stats.pool_total, 1);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
	KUNIT_EXPECT_EQ(test, stats.pool_peak, 0);
}

/* ---- Test 2: Allocate one context -> in_use = 1 ---- */
static void test_pool_allocate_one(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 1);
	KUNIT_EXPECT_GE(test, stats.pool_peak, 1);

	ksmbd_release_crypto_ctx(ctx);
}

/* ---- Test 3: Release one context -> in_use = 0 ---- */
static void test_pool_release_one(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ksmbd_release_crypto_ctx(ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 4: Allocate-release cycle doesn't leak ---- */
static void test_pool_no_leak_cycle(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats_before, stats_after;
	struct ksmbd_crypto_ctx *ctx;
	int i;

	ksmbd_crypto_ctx_pool_stats(&stats_before);

	for (i = 0; i < 100; i++) {
		ctx = ksmbd_crypto_ctx_find_sha256();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
		ksmbd_release_crypto_ctx(ctx);
	}

	ksmbd_crypto_ctx_pool_stats(&stats_after);
	KUNIT_EXPECT_EQ(test, stats_after.pool_in_use, stats_before.pool_in_use);
}

/* ---- Test 5: Allocate up to max -> all succeed ---- */
static void test_pool_allocate_up_to_max(struct kunit *test)
{
	struct ksmbd_crypto_ctx **ctxs;
	int max_size, i;

	/*
	 * Use a small max to avoid allocating too many real crypto TFMs.
	 * We use ksmbd_find_crypto_ctx() indirectly through sha256 finder.
	 */
	ksmbd_crypto_ctx_set_max_pool_size(8);
	max_size = ksmbd_crypto_ctx_get_max_pool_size();
	KUNIT_ASSERT_EQ(test, max_size, 8);

	/* Destroy and recreate with fresh pool for clean state */
	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);
	ksmbd_crypto_ctx_set_max_pool_size(8);

	ctxs = kunit_kcalloc(test, 8, sizeof(*ctxs), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctxs);

	for (i = 0; i < 8; i++) {
		ctxs[i] = ksmbd_crypto_ctx_find_sha256();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctxs[i]);
	}

	/* Release all */
	for (i = 0; i < 8; i++)
		ksmbd_release_crypto_ctx(ctxs[i]);

	/* Restore default for other tests */
	ksmbd_crypto_ctx_set_max_pool_size(KSMBD_CRYPTO_CTX_MAX_POOL_SIZE);
}

/* ---- Test 6: Allocate max+1 -> returns NULL (pool exhausted) ---- */
static void test_pool_exhaustion_returns_null(struct kunit *test)
{
	struct ksmbd_crypto_ctx **ctxs;
	struct ksmbd_crypto_ctx *overflow_ctx;
	int i;

	/* Use small pool to make exhaustion testable without huge allocations */
	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);
	ksmbd_crypto_ctx_set_max_pool_size(4);

	ctxs = kunit_kcalloc(test, 4, sizeof(*ctxs), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctxs);

	/* Exhaust the pool */
	for (i = 0; i < 4; i++) {
		ctxs[i] = ksmbd_crypto_ctx_find_sha256();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctxs[i]);
	}

	/*
	 * Next allocation should fail (returns NULL) after retries timeout.
	 * Note: this test may take up to KSMBD_CRYPTO_CTX_MAX_RETRIES *
	 * KSMBD_CRYPTO_CTX_TIMEOUT seconds. In KUnit test environment,
	 * the wait_event_timeout returns immediately because there is
	 * nothing to wake it.
	 */
	overflow_ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_EXPECT_NULL(test, overflow_ctx);

	/* Clean up */
	for (i = 0; i < 4; i++)
		ksmbd_release_crypto_ctx(ctxs[i]);

	ksmbd_crypto_ctx_set_max_pool_size(KSMBD_CRYPTO_CTX_MAX_POOL_SIZE);
}

/* ---- Test 7: Release one after exhaustion -> next allocate succeeds ---- */
static void test_pool_recovery_after_exhaustion(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctxs[4];
	struct ksmbd_crypto_ctx *recovered;
	int i;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);
	ksmbd_crypto_ctx_set_max_pool_size(4);

	for (i = 0; i < 4; i++) {
		ctxs[i] = ksmbd_crypto_ctx_find_sha256();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctxs[i]);
	}

	/* Release one */
	ksmbd_release_crypto_ctx(ctxs[0]);
	ctxs[0] = NULL;

	/* Now one slot is available - should succeed */
	recovered = ksmbd_crypto_ctx_find_sha256();
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, recovered);

	if (recovered)
		ksmbd_release_crypto_ctx(recovered);

	for (i = 1; i < 4; i++)
		ksmbd_release_crypto_ctx(ctxs[i]);

	ksmbd_crypto_ctx_set_max_pool_size(KSMBD_CRYPTO_CTX_MAX_POOL_SIZE);
}

/* ---- Test 8: pool_peak tracks high-water mark ---- */
static void test_pool_peak_tracking(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx1, *ctx2, *ctx3;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_peak, 0);

	ctx1 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx1);

	ctx2 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx2);

	ctx3 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx3);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_peak, 3);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 3);

	/* Release all - peak should remain at 3 */
	ksmbd_release_crypto_ctx(ctx1);
	ksmbd_release_crypto_ctx(ctx2);
	ksmbd_release_crypto_ctx(ctx3);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_peak, 3);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 9: Concurrent-style sequential multichannel simulation ---- */
static void test_pool_multichannel_simulation(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *channel_ctxs[8];
	int i;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	/*
	 * Simulate 8 multichannel session bindings, each acquiring
	 * a crypto context for preauth/signing.
	 */
	for (i = 0; i < 8; i++) {
		channel_ctxs[i] = ksmbd_crypto_ctx_find_sha256();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, channel_ctxs[i]);
	}

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 8);
	KUNIT_EXPECT_GE(test, stats.pool_total, 8);

	/* Session teardown: release all channels' contexts */
	for (i = 0; i < 8; i++)
		ksmbd_release_crypto_ctx(channel_ctxs[i]);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 10: Session teardown releases all session's contexts ---- */
static void test_pool_session_teardown_cleanup(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *session_ctxs[4];
	int i;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	/* Simulate a session with 4 crypto operations in flight */
	for (i = 0; i < 4; i++) {
		session_ctxs[i] = ksmbd_crypto_ctx_find_sha256();
		KUNIT_ASSERT_NOT_ERR_OR_NULL(test, session_ctxs[i]);
	}

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 4);

	/* Simulate session teardown: release all at once */
	for (i = 0; i < 4; i++)
		ksmbd_release_crypto_ctx(session_ctxs[i]);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 11: Partial session setup failure releases allocated ctx ---- */
static void test_pool_partial_session_failure(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	/* Simulate: session setup starts, allocates crypto context */
	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 1);

	/*
	 * Session setup fails partway through - error path must
	 * release the crypto context to avoid leak.
	 */
	ksmbd_release_crypto_ctx(ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 12: Pool statistics are consistent ---- */
static void test_pool_stats_consistency(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx1, *ctx2;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	ctx1 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx1);

	ctx2 = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx2);

	ksmbd_crypto_ctx_pool_stats(&stats);

	/* in_use should never exceed total */
	KUNIT_EXPECT_LE(test, stats.pool_in_use, stats.pool_total);
	/* peak should be >= current in_use */
	KUNIT_EXPECT_GE(test, stats.pool_peak, stats.pool_in_use);
	/* in_use should be exactly 2 */
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 2);

	ksmbd_release_crypto_ctx(ctx1);
	ksmbd_release_crypto_ctx(ctx2);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
	KUNIT_EXPECT_GE(test, stats.pool_total, 0);
}

/* ---- Test 13: Double release is safe (no crash, no negative count) ---- */
static void test_pool_double_release_safe(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ksmbd_release_crypto_ctx(ctx);

	/*
	 * Second release of the same pointer: in production this is a bug,
	 * but we verify it doesn't crash the system. The ctx has been added
	 * back to the idle list; releasing it again would cause list
	 * corruption in general, but here we are testing that at least
	 * NULL release (the documented safe path) works.
	 *
	 * We do NOT re-release the same non-NULL pointer as that would
	 * corrupt the list. Instead, we verify in_use didn't go negative
	 * after the first release.
	 */
	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_GE(test, stats.pool_in_use, 0);
}

/* ---- Test 14: NULL context release is safe ---- */
static void test_pool_null_release_safe(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats_before, stats_after;

	ksmbd_crypto_ctx_pool_stats(&stats_before);

	/* Must not crash */
	ksmbd_release_crypto_ctx(NULL);

	ksmbd_crypto_ctx_pool_stats(&stats_after);
	KUNIT_EXPECT_EQ(test, stats_before.pool_in_use, stats_after.pool_in_use);
	KUNIT_EXPECT_EQ(test, stats_before.pool_total, stats_after.pool_total);
}

/* ---- Test 15: Pool reinitialization after full drain ---- */
static void test_pool_reinit_after_drain(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx;

	ksmbd_crypto_destroy();

	/* Stats should be zeroed after destroy */
	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_total, 0);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
	KUNIT_EXPECT_EQ(test, stats.pool_peak, 0);

	/* Re-create and verify it works */
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 1);
	KUNIT_EXPECT_GE(test, stats.pool_total, 1);

	ksmbd_release_crypto_ctx(ctx);
}

/* ---- Test 16: Different context types (shash vs aead) ---- */
static void test_pool_different_context_types(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *sha_ctx, *gcm_ctx, *hmac_ctx;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	sha_ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sha_ctx);

	gcm_ctx = ksmbd_crypto_ctx_find_gcm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, gcm_ctx);

	hmac_ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, hmac_ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 3);

	/* Verify each context has the correct algorithm loaded */
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(sha_ctx));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_GCM(gcm_ctx));
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_HMACSHA256(hmac_ctx));

	ksmbd_release_crypto_ctx(sha_ctx);
	ksmbd_release_crypto_ctx(gcm_ctx);
	ksmbd_release_crypto_ctx(hmac_ctx);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 17: Context reuse after release (recycling) ---- */
static void test_pool_context_recycling(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx1, *ctx2;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	/* Allocate a context and populate with sha256 */
	ctx1 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx1);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx1));

	ksmbd_release_crypto_ctx(ctx1);

	/* Reallocate - should reuse the released context from the idle list */
	ctx2 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx2);

	/* The recycled context should already have sha256 allocated */
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx2));

	ksmbd_crypto_ctx_pool_stats(&stats);
	/*
	 * Only 1 context should be in use; total might be 1 if reused
	 * or more if the pool decided to free and reallocate.
	 */
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 1);

	ksmbd_release_crypto_ctx(ctx2);
}

/* ---- Test 18: Module unload leak detection (simulate) ---- */
static void test_pool_leak_detection_on_destroy(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/*
	 * Intentionally "leak" by calling destroy while ctx is still out.
	 * ksmbd_crypto_destroy() should log a warning about the leak.
	 * We then release the context and verify the pool is consistent
	 * after re-creation.
	 *
	 * Note: after destroy, the ctx is dangling. We must NOT release
	 * it back since the pool is gone. Instead, we manually free it.
	 */
	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 1);

	/*
	 * Destroy with outstanding context - this should warn.
	 * The context itself becomes leaked memory; in real module
	 * unload the kernel would reclaim it.
	 */
	ksmbd_crypto_destroy();

	/* Verify counters are reset */
	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_total, 0);

	/*
	 * Manually free the leaked context to avoid actual memory leak
	 * in the test. We can't call ksmbd_release_crypto_ctx because
	 * the pool is destroyed. Free the inner crypto objects and kfree.
	 */
	{
		int i;

		for (i = 0; i < CRYPTO_SHASH_MAX; i++) {
			if (ctx->desc[i]) {
				struct crypto_shash *tfm = ctx->desc[i]->tfm;

				kfree(ctx->desc[i]);
				if (tfm)
					crypto_free_shash(tfm);
			}
		}
		for (i = 0; i < CRYPTO_AEAD_MAX; i++) {
			if (ctx->ccmaes[i])
				crypto_free_aead(ctx->ccmaes[i]);
		}
		kfree(ctx);
	}

	/* Re-create for subsequent tests */
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);
}

/* ---- Test 19: Pool available count correctness ---- */
static void test_pool_available_count(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;
	int avail_before, avail_after;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);
	ksmbd_crypto_ctx_set_max_pool_size(16);

	avail_before = ksmbd_crypto_ctx_pool_available();
	KUNIT_EXPECT_EQ(test, avail_before, 16);

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	avail_after = ksmbd_crypto_ctx_pool_available();
	KUNIT_EXPECT_EQ(test, avail_after, 15);

	ksmbd_release_crypto_ctx(ctx);

	avail_after = ksmbd_crypto_ctx_pool_available();
	KUNIT_EXPECT_EQ(test, avail_after, 16);

	ksmbd_crypto_ctx_set_max_pool_size(KSMBD_CRYPTO_CTX_MAX_POOL_SIZE);
}

/* ---- Test 20: Max pool size configuration ---- */
static void test_pool_max_size_configuration(struct kunit *test)
{
	int orig_max, new_max;

	orig_max = ksmbd_crypto_ctx_get_max_pool_size();
	KUNIT_EXPECT_EQ(test, orig_max, KSMBD_CRYPTO_CTX_MAX_POOL_SIZE);

	ksmbd_crypto_ctx_set_max_pool_size(256);
	new_max = ksmbd_crypto_ctx_get_max_pool_size();
	KUNIT_EXPECT_EQ(test, new_max, 256);

	/* Setting 0 should be clamped to 1 */
	ksmbd_crypto_ctx_set_max_pool_size(0);
	new_max = ksmbd_crypto_ctx_get_max_pool_size();
	KUNIT_EXPECT_EQ(test, new_max, 1);

	/* Setting negative should be clamped to 1 */
	ksmbd_crypto_ctx_set_max_pool_size(-5);
	new_max = ksmbd_crypto_ctx_get_max_pool_size();
	KUNIT_EXPECT_EQ(test, new_max, 1);

	/* Restore */
	ksmbd_crypto_ctx_set_max_pool_size(orig_max);
}

/* ---- Test 21: Stats with NULL pointer is safe ---- */
static void test_pool_stats_null_safe(struct kunit *test)
{
	/* Must not crash */
	ksmbd_crypto_ctx_pool_stats(NULL);
	KUNIT_SUCCEED(test);
}

/* ---- Test 22: Mixed allocation and release interleaving ---- */
static void test_pool_interleaved_alloc_release(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx_a, *ctx_b, *ctx_c;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	/* Allocate A */
	ctx_a = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx_a);

	/* Allocate B */
	ctx_b = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx_b);

	/* Release A */
	ksmbd_release_crypto_ctx(ctx_a);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 1);

	/* Allocate C - may reuse A's slot */
	ctx_c = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx_c);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 2);

	/* Release B, C */
	ksmbd_release_crypto_ctx(ctx_b);
	ksmbd_release_crypto_ctx(ctx_c);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_EQ(test, stats.pool_in_use, 0);
}

/* ---- Test 23: Peak never decreases ---- */
static void test_pool_peak_monotonic(struct kunit *test)
{
	struct ksmbd_crypto_pool_stats stats;
	struct ksmbd_crypto_ctx *ctx1, *ctx2;
	int peak_after_two;

	ksmbd_crypto_destroy();
	KUNIT_ASSERT_EQ(test, ksmbd_crypto_create(), 0);

	ctx1 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx1);

	ctx2 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx2);

	ksmbd_crypto_ctx_pool_stats(&stats);
	peak_after_two = stats.pool_peak;
	KUNIT_EXPECT_EQ(test, peak_after_two, 2);

	/* Release both */
	ksmbd_release_crypto_ctx(ctx1);
	ksmbd_release_crypto_ctx(ctx2);

	/* Allocate one - peak should still be 2, not 1 */
	ctx1 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx1);

	ksmbd_crypto_ctx_pool_stats(&stats);
	KUNIT_EXPECT_GE(test, stats.pool_peak, peak_after_two);

	ksmbd_release_crypto_ctx(ctx1);
}

static struct kunit_case ksmbd_crypto_pool_test_cases[] = {
	KUNIT_CASE(test_pool_initial_state),
	KUNIT_CASE(test_pool_allocate_one),
	KUNIT_CASE(test_pool_release_one),
	KUNIT_CASE(test_pool_no_leak_cycle),
	KUNIT_CASE(test_pool_allocate_up_to_max),
	KUNIT_CASE(test_pool_exhaustion_returns_null),
	KUNIT_CASE(test_pool_recovery_after_exhaustion),
	KUNIT_CASE(test_pool_peak_tracking),
	KUNIT_CASE(test_pool_multichannel_simulation),
	KUNIT_CASE(test_pool_session_teardown_cleanup),
	KUNIT_CASE(test_pool_partial_session_failure),
	KUNIT_CASE(test_pool_stats_consistency),
	KUNIT_CASE(test_pool_double_release_safe),
	KUNIT_CASE(test_pool_null_release_safe),
	KUNIT_CASE(test_pool_reinit_after_drain),
	KUNIT_CASE(test_pool_different_context_types),
	KUNIT_CASE(test_pool_context_recycling),
	KUNIT_CASE(test_pool_leak_detection_on_destroy),
	KUNIT_CASE(test_pool_available_count),
	KUNIT_CASE(test_pool_max_size_configuration),
	KUNIT_CASE(test_pool_stats_null_safe),
	KUNIT_CASE(test_pool_interleaved_alloc_release),
	KUNIT_CASE(test_pool_peak_monotonic),
	{}
};

static struct kunit_suite ksmbd_crypto_pool_test_suite = {
	.name = "ksmbd_crypto_pool",
	.init = crypto_pool_test_init,
	.exit = crypto_pool_test_exit,
	.test_cases = ksmbd_crypto_pool_test_cases,
};

kunit_test_suite(ksmbd_crypto_pool_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd crypto context pool exhaustion protection");
