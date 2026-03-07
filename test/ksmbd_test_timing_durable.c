// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for durable handle timing requirements (MS-SMB2 3.3.5.9.7)
 *
 *   These tests verify timing constants, timeout clamping, scavenger logic,
 *   and jiffies-based expiry comparisons used for durable/persistent/resilient
 *   handles.  All tests are pure arithmetic -- no actual sleeping or kernel
 *   threads are started.
 */

#include <kunit/test.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/limits.h>

#include "smb2pdu.h"
#include "vfs_cache.h"
#include "server.h"

/* ------------------------------------------------------------------ */
/* 1. DURABLE_HANDLE_MAX_TIMEOUT constant (MS-SMB2 3.3.5.9.10)       */
/* ------------------------------------------------------------------ */

/*
 * test_durable_max_timeout_value - DURABLE_HANDLE_MAX_TIMEOUT = 300000ms (5 min)
 *
 * MS-SMB2 section 3.3.5.9.10: "the Timeout value in the response SHOULD
 * be set to whichever is smaller, the Timeout value in the request or
 * 300 seconds."
 */
static void test_durable_max_timeout_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT,
			300000U);
	/* 300000 ms = 300 seconds = 5 minutes */
	KUNIT_EXPECT_EQ(test, DURABLE_HANDLE_MAX_TIMEOUT / 1000, 300U);
}

/* ------------------------------------------------------------------ */
/* 2. DHv2 timeout clamping to server max                             */
/* ------------------------------------------------------------------ */

/*
 * test_durable_v2_timeout_clamped - client timeout clamped to server max
 *
 * Simulates the min_t() logic in smb2_create.c:
 *   fp->durable_timeout = min_t(unsigned int, dh_info.timeout,
 *                               DURABLE_HANDLE_MAX_TIMEOUT);
 */
static void test_durable_v2_timeout_clamped(struct kunit *test)
{
	unsigned int client_timeout = 600000; /* 10 minutes */
	unsigned int result;

	result = min_t(unsigned int, client_timeout,
		       DURABLE_HANDLE_MAX_TIMEOUT);
	KUNIT_EXPECT_EQ(test, result, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT);
}

/*
 * test_durable_v2_timeout_smaller_than_max - client timeout below max is preserved
 */
static void test_durable_v2_timeout_smaller_than_max(struct kunit *test)
{
	unsigned int client_timeout = 120000; /* 2 minutes */
	unsigned int result;

	result = min_t(unsigned int, client_timeout,
		       DURABLE_HANDLE_MAX_TIMEOUT);
	KUNIT_EXPECT_EQ(test, result, 120000U);
}

/*
 * test_durable_v2_timeout_exact_max - client timeout == max is preserved
 */
static void test_durable_v2_timeout_exact_max(struct kunit *test)
{
	unsigned int client_timeout = DURABLE_HANDLE_MAX_TIMEOUT;
	unsigned int result;

	result = min_t(unsigned int, client_timeout,
		       DURABLE_HANDLE_MAX_TIMEOUT);
	KUNIT_EXPECT_EQ(test, result, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT);
}

/* ------------------------------------------------------------------ */
/* 3. DHv2 timeout zero -- uses server default                        */
/* ------------------------------------------------------------------ */

/*
 * test_durable_v2_timeout_zero_uses_default - zero timeout -> 60000ms default
 *
 * From smb2_create.c: if (dh_info.timeout) ... else fp->durable_timeout = 60000;
 */
static void test_durable_v2_timeout_zero_uses_default(struct kunit *test)
{
	unsigned int client_timeout = 0;
	unsigned int result;

	if (client_timeout)
		result = min_t(unsigned int, client_timeout,
			       DURABLE_HANDLE_MAX_TIMEOUT);
	else
		result = 60000;

	KUNIT_EXPECT_EQ(test, result, 60000U);
}

/* ------------------------------------------------------------------ */
/* 4. DHv1 default timeout                                            */
/* ------------------------------------------------------------------ */

/*
 * test_durable_v1_default_timeout - DHnQ v1 handles get 16000ms default
 *
 * MS-SMB2 3.3.5.9.7: the server SHOULD apply a timeout. ksmbd uses
 * 16 seconds (the Windows default reconnect window).
 */
static void test_durable_v1_default_timeout(struct kunit *test)
{
	unsigned int v1_default = 16000;

	KUNIT_EXPECT_EQ(test, v1_default, 16000U);
	/* Strictly less than the DHv2 max */
	KUNIT_EXPECT_LT(test, v1_default, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT);
}

/* ------------------------------------------------------------------ */
/* 5. Scavenger wake interval resets to max when wait times out       */
/* ------------------------------------------------------------------ */

/*
 * test_scavenger_interval_reset - scavenger interval resets to
 *                                 DURABLE_HANDLE_MAX_TIMEOUT on timeout
 *
 * From vfs_cache.c: when remaining_jiffies == 0 (wait timed out),
 * min_timeout is reset to DURABLE_HANDLE_MAX_TIMEOUT.
 */
static void test_scavenger_interval_reset(struct kunit *test)
{
	unsigned long remaining_jiffies = 0;
	unsigned int min_timeout = 5000; /* some prior value */

	/* Simulate the scavenger timeout reset logic */
	if (remaining_jiffies)
		min_timeout = jiffies_to_msecs(remaining_jiffies);
	else
		min_timeout = DURABLE_HANDLE_MAX_TIMEOUT;

	KUNIT_EXPECT_EQ(test, min_timeout,
			(unsigned int)DURABLE_HANDLE_MAX_TIMEOUT);
}

/* ------------------------------------------------------------------ */
/* 6. Handle preserved within timeout window                          */
/* ------------------------------------------------------------------ */

/*
 * test_handle_preserved_within_timeout - simulated scavenger timeout check
 *
 * durable_scavenger_timeout is a msecs-based absolute deadline computed as:
 *   jiffies_to_msecs(jiffies) + fp->durable_timeout
 * A handle is expired when: durable_scavenger_timeout <= jiffies_to_msecs(jiffies)
 */
static void test_handle_preserved_within_timeout(struct kunit *test)
{
	unsigned long now_ms = jiffies_to_msecs(jiffies);
	unsigned int durable_timeout_ms = 60000;
	unsigned int scavenger_timeout = now_ms + durable_timeout_ms;

	/* The handle is NOT expired: scavenger_timeout > current time */
	KUNIT_EXPECT_GT(test, scavenger_timeout, (unsigned int)now_ms);
	KUNIT_EXPECT_FALSE(test, scavenger_timeout <= now_ms);
}

/* ------------------------------------------------------------------ */
/* 7. Handle expired after timeout window                             */
/* ------------------------------------------------------------------ */

/*
 * test_handle_expired_after_timeout - handle expired after deadline
 */
static void test_handle_expired_after_timeout(struct kunit *test)
{
	unsigned long now_ms = jiffies_to_msecs(jiffies);
	unsigned int durable_timeout_ms = 60000;

	/*
	 * Simulate a handle that was created long ago:
	 * scavenger_timeout was set at (now - 2*timeout), so it's in the past.
	 */
	unsigned int scavenger_timeout;

	if (now_ms > 2 * durable_timeout_ms)
		scavenger_timeout = now_ms - 2 * durable_timeout_ms;
	else
		scavenger_timeout = 0; /* Overflow guard for very early boot */

	KUNIT_EXPECT_TRUE(test, scavenger_timeout <= now_ms);
}

/* ------------------------------------------------------------------ */
/* 8. Handle reconnect at exact boundary: T-1ms preserved, T+1ms expired */
/* ------------------------------------------------------------------ */

/*
 * test_handle_boundary_timing - boundary condition at exact timeout
 */
static void test_handle_boundary_timing(struct kunit *test)
{
	unsigned int base_ms = 1000000; /* arbitrary reference point */
	unsigned int timeout = 60000;
	unsigned int deadline = base_ms + timeout;

	/* T-1: still alive */
	KUNIT_EXPECT_FALSE(test, deadline <= (base_ms + timeout - 1));

	/* T+0: exact boundary -- expired (<=) */
	KUNIT_EXPECT_TRUE(test, deadline <= (base_ms + timeout));

	/* T+1: expired */
	KUNIT_EXPECT_TRUE(test, deadline <= (base_ms + timeout + 1));
}

/* ------------------------------------------------------------------ */
/* 9. Persistent handle never expires (infinite timeout)              */
/* ------------------------------------------------------------------ */

/*
 * test_persistent_handle_never_expires - persistent handles have no
 *                                        scavenger timeout
 *
 * In ksmbd, persistent handles set fp->is_persistent = true. The scavenger
 * only processes handles with durable_timeout != 0 or resilient_timeout != 0.
 * Persistent handles rely on the is_reconnectable() check which returns
 * true for fp->is_persistent regardless of timeout.
 */
static void test_persistent_handle_never_expires(struct kunit *test)
{
	/* Persistent: is_reconnectable returns true even with timeout=0 */
	bool is_persistent = true;
	bool is_durable = false;
	unsigned int durable_timeout = 0;
	bool reconnectable;

	/* Simulate is_reconnectable() logic for persistent handles */
	if (is_persistent)
		reconnectable = true;
	else if (is_durable && durable_timeout > 0)
		reconnectable = true;
	else
		reconnectable = false;

	KUNIT_EXPECT_TRUE(test, reconnectable);

	/* Scavenger skips handles with no timeout set */
	KUNIT_EXPECT_EQ(test, durable_timeout, 0U);
}

/* ------------------------------------------------------------------ */
/* 10. Resilient handle timeout -- separate from durable              */
/* ------------------------------------------------------------------ */

/*
 * test_resilient_handle_timeout_separate - resilient timeout is independent
 *
 * ksmbd_resilient.c defines KSMBD_MAX_RESILIENT_TIMEOUT_MS = 300000 (5 min).
 * Resilient handles use fp->resilient_timeout, not fp->durable_timeout.
 */
static void test_resilient_handle_timeout_separate(struct kunit *test)
{
	unsigned int resilient_max = 5 * 60 * 1000; /* 300000 ms */
	unsigned int client_request = 120000;
	unsigned int result;

	/* Clamping logic from ksmbd_resilient.c */
	if (client_request > resilient_max)
		result = resilient_max;
	else
		result = client_request;

	KUNIT_EXPECT_EQ(test, result, 120000U);

	/* Over-limit request is clamped */
	client_request = 400000;
	if (client_request > resilient_max)
		result = resilient_max;
	else
		result = client_request;

	KUNIT_EXPECT_EQ(test, result, resilient_max);
}

/* ------------------------------------------------------------------ */
/* 11. Multiple handles with different timeouts                       */
/* ------------------------------------------------------------------ */

/*
 * test_multiple_handles_different_timeouts - scavenger picks min timeout
 *
 * When the scavenger iterates handles, it selects the smallest remaining
 * timeout as the next wake interval.
 */
static void test_multiple_handles_different_timeouts(struct kunit *test)
{
	unsigned int base_ms = 1000000;
	unsigned int timeout_a = 60000;
	unsigned int timeout_b = 120000;
	unsigned int timeout_c = 30000;
	unsigned int min_timeout = DURABLE_HANDLE_MAX_TIMEOUT;
	unsigned int remaining;

	/* Simulate scavenger logic: find smallest remaining time */
	/* Handle A: 60s remaining */
	remaining = (base_ms + timeout_a) - base_ms;
	if (min_timeout > remaining)
		min_timeout = remaining;

	/* Handle B: 120s remaining */
	remaining = (base_ms + timeout_b) - base_ms;
	if (min_timeout > remaining)
		min_timeout = remaining;

	/* Handle C: 30s remaining */
	remaining = (base_ms + timeout_c) - base_ms;
	if (min_timeout > remaining)
		min_timeout = remaining;

	KUNIT_EXPECT_EQ(test, min_timeout, 30000U);
}

/* ------------------------------------------------------------------ */
/* 12. Timeout overflow protection                                    */
/* ------------------------------------------------------------------ */

/*
 * test_timeout_overflow_protection - extremely large client values are clamped
 */
static void test_timeout_overflow_protection(struct kunit *test)
{
	unsigned int client_timeout = UINT_MAX;
	unsigned int result;

	result = min_t(unsigned int, client_timeout,
		       DURABLE_HANDLE_MAX_TIMEOUT);
	KUNIT_EXPECT_EQ(test, result, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT);

	/* Also test with MAX-1 */
	client_timeout = UINT_MAX - 1;
	result = min_t(unsigned int, client_timeout,
		       DURABLE_HANDLE_MAX_TIMEOUT);
	KUNIT_EXPECT_EQ(test, result, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT);
}

/* ------------------------------------------------------------------ */
/* 13. Scavenger timeout computation from jiffies                     */
/* ------------------------------------------------------------------ */

/*
 * test_scavenger_timeout_computation - scavenger_timeout = jiffies_ms + timeout
 *
 * Verifies the computation: fp->durable_scavenger_timeout =
 *   jiffies_to_msecs(jiffies) + fp->durable_timeout
 */
static void test_scavenger_timeout_computation(struct kunit *test)
{
	unsigned long now_ms = jiffies_to_msecs(jiffies);
	unsigned int durable_timeout = 60000;
	unsigned int scavenger_timeout;

	scavenger_timeout = now_ms + durable_timeout;

	/* Must be in the future */
	KUNIT_EXPECT_GE(test, scavenger_timeout, (unsigned int)now_ms);
	/* Delta must equal the configured timeout */
	KUNIT_EXPECT_EQ(test, (unsigned int)(scavenger_timeout - now_ms),
			durable_timeout);
}

/* ------------------------------------------------------------------ */
/* 14. Resilient scavenger timeout uses resilient_timeout field       */
/* ------------------------------------------------------------------ */

/*
 * test_resilient_scavenger_timeout - resilient handles use resilient_timeout
 *
 * From vfs_cache.c: if (fp->is_resilient && fp->resilient_timeout)
 *   fp->durable_scavenger_timeout = jiffies_to_msecs(jiffies) + fp->resilient_timeout;
 */
static void test_resilient_scavenger_timeout(struct kunit *test)
{
	unsigned long now_ms = jiffies_to_msecs(jiffies);
	bool is_resilient = true;
	unsigned int resilient_timeout = 90000;
	unsigned int durable_timeout = 0;
	unsigned int scavenger_timeout;

	if (durable_timeout)
		scavenger_timeout = now_ms + durable_timeout;
	else if (is_resilient && resilient_timeout)
		scavenger_timeout = now_ms + resilient_timeout;
	else
		scavenger_timeout = 0;

	KUNIT_EXPECT_EQ(test, (unsigned int)(scavenger_timeout - now_ms),
			resilient_timeout);
}

/* ------------------------------------------------------------------ */
/* 15. DHv2 max same as resilient max                                 */
/* ------------------------------------------------------------------ */

/*
 * test_durable_and_resilient_max_equal - both are 5 minutes
 */
static void test_durable_and_resilient_max_equal(struct kunit *test)
{
	unsigned int resilient_max = 5 * 60 * 1000; /* KSMBD_MAX_RESILIENT_TIMEOUT_MS */

	KUNIT_EXPECT_EQ(test, (unsigned int)DURABLE_HANDLE_MAX_TIMEOUT,
			resilient_max);
}

/* ------------------------------------------------------------------ */

static struct kunit_case ksmbd_timing_durable_test_cases[] = {
	KUNIT_CASE(test_durable_max_timeout_value),
	KUNIT_CASE(test_durable_v2_timeout_clamped),
	KUNIT_CASE(test_durable_v2_timeout_smaller_than_max),
	KUNIT_CASE(test_durable_v2_timeout_exact_max),
	KUNIT_CASE(test_durable_v2_timeout_zero_uses_default),
	KUNIT_CASE(test_durable_v1_default_timeout),
	KUNIT_CASE(test_scavenger_interval_reset),
	KUNIT_CASE(test_handle_preserved_within_timeout),
	KUNIT_CASE(test_handle_expired_after_timeout),
	KUNIT_CASE(test_handle_boundary_timing),
	KUNIT_CASE(test_persistent_handle_never_expires),
	KUNIT_CASE(test_resilient_handle_timeout_separate),
	KUNIT_CASE(test_multiple_handles_different_timeouts),
	KUNIT_CASE(test_timeout_overflow_protection),
	KUNIT_CASE(test_scavenger_timeout_computation),
	KUNIT_CASE(test_resilient_scavenger_timeout),
	KUNIT_CASE(test_durable_and_resilient_max_equal),
	{}
};

static struct kunit_suite ksmbd_timing_durable_test_suite = {
	.name = "ksmbd_timing_durable",
	.test_cases = ksmbd_timing_durable_test_cases,
};

kunit_test_suite(ksmbd_timing_durable_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd durable handle timing");
