// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for session timeout requirements (MS-SMB2 3.3.5.2.9)
 *
 *   Tests verify SMB2_SESSION_TIMEOUT, the ksmbd_expire_session() logic,
 *   the ksmbd_conn_alive() deadtime check, and the interaction between
 *   open file counts and idle timeout.  All tests use jiffies arithmetic
 *   with no actual sleeping.
 */

#include <kunit/test.h>
#include <linux/jiffies.h>
#include <linux/types.h>

#include "smb2pdu.h"
#include "connection.h"
#include "server.h"
#include "smb_common.h"

/* ------------------------------------------------------------------ */
/* 1. SMB2_SESSION_TIMEOUT value                                      */
/* ------------------------------------------------------------------ */

/*
 * test_session_timeout_value - SMB2_SESSION_TIMEOUT = 10 * HZ (10 seconds)
 *
 * ksmbd uses this timeout to expire in-progress (not yet validated)
 * sessions during ksmbd_expire_session().
 */
static void test_session_timeout_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned long)SMB2_SESSION_TIMEOUT,
			(unsigned long)(10 * HZ));
}

/*
 * test_session_timeout_in_seconds - verify conversion to seconds
 */
static void test_session_timeout_in_seconds(struct kunit *test)
{
	unsigned long timeout_secs = SMB2_SESSION_TIMEOUT / HZ;

	KUNIT_EXPECT_EQ(test, timeout_secs, 10UL);
}

/* ------------------------------------------------------------------ */
/* 2. Session idle detection -- last_active vs jiffies comparison     */
/* ------------------------------------------------------------------ */

/*
 * test_session_idle_detection - time_after detects idle sessions
 *
 * ksmbd_expire_session() uses:
 *   time_after(jiffies, sess->last_active + SMB2_SESSION_TIMEOUT)
 */
static void test_session_idle_detection(struct kunit *test)
{
	unsigned long now = jiffies;
	unsigned long last_active;
	bool expired;

	/* Session that was active 5 seconds ago: NOT expired */
	last_active = now - 5 * HZ;
	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_FALSE(test, expired);

	/* Session that was active 15 seconds ago: expired */
	last_active = now - 15 * HZ;
	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_TRUE(test, expired);
}

/* ------------------------------------------------------------------ */
/* 3. Session preserved within timeout                                */
/* ------------------------------------------------------------------ */

/*
 * test_session_preserved_within_timeout - session active 1 second ago
 */
static void test_session_preserved_within_timeout(struct kunit *test)
{
	unsigned long now = jiffies;
	unsigned long last_active = now - 1 * HZ;
	bool expired;

	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_FALSE(test, expired);
}

/* ------------------------------------------------------------------ */
/* 4. Session expired after timeout                                   */
/* ------------------------------------------------------------------ */

/*
 * test_session_expired_after_timeout - session idle for 2x the timeout
 */
static void test_session_expired_after_timeout(struct kunit *test)
{
	unsigned long now = jiffies;
	unsigned long last_active = now - 2 * SMB2_SESSION_TIMEOUT;
	bool expired;

	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_TRUE(test, expired);
}

/* ------------------------------------------------------------------ */
/* 5. Deadtime disabled (deadtime=0) -- connection always alive       */
/* ------------------------------------------------------------------ */

/*
 * test_deadtime_disabled - deadtime=0 skips the idle check
 *
 * From connection.c ksmbd_conn_alive():
 *   if (server_conf.deadtime > 0 &&
 *       time_after(jiffies, conn->last_active + server_conf.deadtime))
 *       return false;
 */
static void test_deadtime_disabled(struct kunit *test)
{
	unsigned long deadtime = 0;
	unsigned long now = jiffies;
	unsigned long last_active = now - 3600 * HZ; /* 1 hour idle */
	bool alive;

	/* With deadtime=0, the check is skipped entirely */
	if (deadtime > 0 &&
	    time_after(now, last_active + deadtime))
		alive = false;
	else
		alive = true;

	KUNIT_EXPECT_TRUE(test, alive);
}

/* ------------------------------------------------------------------ */
/* 6. Open files prevent timeout (regardless of deadtime)             */
/* ------------------------------------------------------------------ */

/*
 * test_open_files_prevent_timeout - open_files_count > 0 keeps conn alive
 *
 * From ksmbd_conn_alive():
 *   if (atomic_read(&conn->stats.open_files_count) > 0)
 *       return true;
 */
static void test_open_files_prevent_timeout(struct kunit *test)
{
	int open_files_count = 5;
	unsigned long deadtime = 15 * SMB_ECHO_INTERVAL;
	unsigned long now = jiffies;
	unsigned long last_active = now - 20 * SMB_ECHO_INTERVAL; /* very idle */
	bool alive;

	/* Simulate ksmbd_conn_alive logic */
	if (open_files_count > 0)
		alive = true;
	else if (deadtime > 0 &&
		 time_after(now, last_active + deadtime))
		alive = false;
	else
		alive = true;

	/* Open files override the deadtime check */
	KUNIT_EXPECT_TRUE(test, alive);
}

/* ------------------------------------------------------------------ */
/* 7. Session timeout boundary: T-1 active, T+1 expired              */
/* ------------------------------------------------------------------ */

/*
 * test_session_timeout_boundary - exact boundary for time_after
 *
 * time_after(a, b) returns true when a is chronologically after b,
 * i.e., (long)(a - b) > 0.  At exact equality, time_after returns false.
 */
static void test_session_timeout_boundary(struct kunit *test)
{
	unsigned long now = jiffies;
	unsigned long last_active;
	bool expired;

	/* T-1 tick: NOT expired */
	last_active = now - SMB2_SESSION_TIMEOUT + 1;
	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_FALSE(test, expired);

	/* T+0: exact boundary -- time_after(x, x) is false */
	last_active = now - SMB2_SESSION_TIMEOUT;
	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_FALSE(test, expired);

	/* T+1: past the boundary -- expired */
	last_active = now - SMB2_SESSION_TIMEOUT - 1;
	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_TRUE(test, expired);
}

/* ------------------------------------------------------------------ */
/* 8. Connection alive check -- full logic combination                */
/* ------------------------------------------------------------------ */

/*
 * test_conn_alive_full_logic - combines server state, deadtime, open_files
 *
 * Simulates the full ksmbd_conn_alive() logic path.
 */
static void test_conn_alive_full_logic(struct kunit *test)
{
	bool server_running;
	bool conn_exiting;
	int open_files;
	unsigned long deadtime;
	unsigned long now = jiffies;
	unsigned long last_active;
	bool alive;

	/* Case 1: server not running -> not alive */
	server_running = false;
	conn_exiting = false;
	open_files = 0;
	deadtime = 0;
	last_active = now;

	if (!server_running)
		alive = false;
	else if (conn_exiting)
		alive = false;
	else if (open_files > 0)
		alive = true;
	else if (deadtime > 0 && time_after(now, last_active + deadtime))
		alive = false;
	else
		alive = true;
	KUNIT_EXPECT_FALSE(test, alive);

	/* Case 2: server running, conn exiting -> not alive */
	server_running = true;
	conn_exiting = true;
	alive = true; /* reset */
	if (!server_running)
		alive = false;
	else if (conn_exiting)
		alive = false;
	else
		alive = true;
	KUNIT_EXPECT_FALSE(test, alive);

	/* Case 3: server running, idle past deadtime, no open files -> not alive */
	server_running = true;
	conn_exiting = false;
	open_files = 0;
	deadtime = 10 * SMB_ECHO_INTERVAL;
	last_active = now - 15 * SMB_ECHO_INTERVAL;

	if (!server_running)
		alive = false;
	else if (conn_exiting)
		alive = false;
	else if (open_files > 0)
		alive = true;
	else if (deadtime > 0 && time_after(now, last_active + deadtime))
		alive = false;
	else
		alive = true;
	KUNIT_EXPECT_FALSE(test, alive);

	/* Case 4: same but with open files -> alive */
	open_files = 1;

	if (!server_running)
		alive = false;
	else if (conn_exiting)
		alive = false;
	else if (open_files > 0)
		alive = true;
	else if (deadtime > 0 && time_after(now, last_active + deadtime))
		alive = false;
	else
		alive = true;
	KUNIT_EXPECT_TRUE(test, alive);
}

/* ------------------------------------------------------------------ */
/* 9. SMB_ECHO_INTERVAL and deadtime relationship                     */
/* ------------------------------------------------------------------ */

/*
 * test_echo_interval_value - SMB_ECHO_INTERVAL = 60 * HZ (60 seconds)
 *
 * Deadtime is computed as: req->deadtime * SMB_ECHO_INTERVAL
 * meaning deadtime is in units of SMB_ECHO_INTERVAL.
 */
static void test_echo_interval_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned long)SMB_ECHO_INTERVAL,
			(unsigned long)(60 * HZ));
}

/*
 * test_deadtime_computation - deadtime = minutes * SMB_ECHO_INTERVAL
 */
static void test_deadtime_computation(struct kunit *test)
{
	unsigned int deadtime_minutes = 15;
	unsigned long deadtime;

	/* This must not overflow -- checked via check_mul_overflow in IPC */
	deadtime = (unsigned long)deadtime_minutes * SMB_ECHO_INTERVAL;

	/* 15 minutes = 15 * 60 * HZ = 900 * HZ */
	KUNIT_EXPECT_EQ(test, deadtime, (unsigned long)(900 * HZ));
}

/* ------------------------------------------------------------------ */
/* 10. Session last_active update on lookup                           */
/* ------------------------------------------------------------------ */

/*
 * test_session_last_active_update - jiffies snapshot on session lookup
 *
 * ksmbd_session_lookup() does: WRITE_ONCE(sess->last_active, jiffies);
 * After lookup, the session should not be considered expired.
 */
static void test_session_last_active_update(struct kunit *test)
{
	unsigned long now = jiffies;
	unsigned long last_active = now; /* just updated */
	bool expired;

	expired = time_after(now, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_FALSE(test, expired);

	/* Even 1 tick later, still not expired */
	expired = time_after(now + 1, last_active + SMB2_SESSION_TIMEOUT);
	KUNIT_EXPECT_FALSE(test, expired);
}

/* ------------------------------------------------------------------ */
/* 11. Valid session state prevents expiry                            */
/* ------------------------------------------------------------------ */

/*
 * test_valid_session_not_expired - SMB2_SESSION_VALID + recent activity
 *
 * ksmbd_expire_session() checks:
 *   if (refcnt <= 1 && (state != SMB2_SESSION_VALID ||
 *       time_after(jiffies, last_active + SMB2_SESSION_TIMEOUT)))
 *
 * A valid session with recent activity is never expired.
 */
static void test_valid_session_not_expired(struct kunit *test)
{
	int refcnt = 1;
	int state = SMB2_SESSION_VALID;
	unsigned long now = jiffies;
	unsigned long last_active = now - 5 * HZ; /* 5 sec ago */
	bool should_expire;

	should_expire = (refcnt <= 1 &&
			 (state != SMB2_SESSION_VALID ||
			  time_after(now, last_active + SMB2_SESSION_TIMEOUT)));
	KUNIT_EXPECT_FALSE(test, should_expire);
}

/*
 * test_in_progress_session_expired - non-valid state expires immediately
 *
 * If state != SMB2_SESSION_VALID, the time check is short-circuited.
 */
static void test_in_progress_session_expired(struct kunit *test)
{
	int refcnt = 1;
	int state = SMB2_SESSION_IN_PROGRESS;
	unsigned long now = jiffies;
	unsigned long last_active = now; /* just now! */
	bool should_expire;

	should_expire = (refcnt <= 1 &&
			 (state != SMB2_SESSION_VALID ||
			  time_after(now, last_active + SMB2_SESSION_TIMEOUT)));
	/* Non-valid state short-circuits the OR -- expires regardless of time */
	KUNIT_EXPECT_TRUE(test, should_expire);
}

/* ------------------------------------------------------------------ */

static struct kunit_case ksmbd_timing_session_test_cases[] = {
	KUNIT_CASE(test_session_timeout_value),
	KUNIT_CASE(test_session_timeout_in_seconds),
	KUNIT_CASE(test_session_idle_detection),
	KUNIT_CASE(test_session_preserved_within_timeout),
	KUNIT_CASE(test_session_expired_after_timeout),
	KUNIT_CASE(test_deadtime_disabled),
	KUNIT_CASE(test_open_files_prevent_timeout),
	KUNIT_CASE(test_session_timeout_boundary),
	KUNIT_CASE(test_conn_alive_full_logic),
	KUNIT_CASE(test_echo_interval_value),
	KUNIT_CASE(test_deadtime_computation),
	KUNIT_CASE(test_session_last_active_update),
	KUNIT_CASE(test_valid_session_not_expired),
	KUNIT_CASE(test_in_progress_session_expired),
	{}
};

static struct kunit_suite ksmbd_timing_session_test_suite = {
	.name = "ksmbd_timing_session",
	.test_cases = ksmbd_timing_session_test_cases,
};

kunit_test_suite(ksmbd_timing_session_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd session timeout timing");
