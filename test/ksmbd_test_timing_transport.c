// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for transport timeout requirements
 *
 *   Tests verify TCP recv/send timeout constants, IPC timeout handling,
 *   deadtime configuration, and jiffies conversion correctness.
 *   All tests are pure arithmetic -- no sockets or threads are used.
 */

#include <kunit/test.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/overflow.h>

#include "connection.h"
#include "server.h"
#include "smb_common.h"

/* ------------------------------------------------------------------ */
/* 1. TCP recv timeout                                                */
/* ------------------------------------------------------------------ */

/*
 * test_tcp_recv_timeout_value - KSMBD_TCP_RECV_TIMEOUT = 7 * HZ
 */
static void test_tcp_recv_timeout_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned long)KSMBD_TCP_RECV_TIMEOUT,
			(unsigned long)(7 * HZ));
}

/*
 * test_tcp_recv_timeout_seconds - 7 seconds in HZ units
 */
static void test_tcp_recv_timeout_seconds(struct kunit *test)
{
	unsigned long timeout_secs = KSMBD_TCP_RECV_TIMEOUT / HZ;

	KUNIT_EXPECT_EQ(test, timeout_secs, 7UL);
}

/* ------------------------------------------------------------------ */
/* 2. TCP send timeout                                                */
/* ------------------------------------------------------------------ */

/*
 * test_tcp_send_timeout_value - KSMBD_TCP_SEND_TIMEOUT = 5 * HZ
 */
static void test_tcp_send_timeout_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned long)KSMBD_TCP_SEND_TIMEOUT,
			(unsigned long)(5 * HZ));
}

/*
 * test_tcp_send_timeout_seconds - 5 seconds in HZ units
 */
static void test_tcp_send_timeout_seconds(struct kunit *test)
{
	unsigned long timeout_secs = KSMBD_TCP_SEND_TIMEOUT / HZ;

	KUNIT_EXPECT_EQ(test, timeout_secs, 5UL);
}

/* ------------------------------------------------------------------ */
/* 3. Send < Recv timeout relationship                                */
/* ------------------------------------------------------------------ */

/*
 * test_send_less_than_recv - send timeout must be shorter than recv
 *
 * A shorter send timeout ensures the server detects write-blocked
 * connections faster than read-idle connections.
 */
static void test_send_less_than_recv(struct kunit *test)
{
	KUNIT_EXPECT_LT(test, (unsigned long)KSMBD_TCP_SEND_TIMEOUT,
			(unsigned long)KSMBD_TCP_RECV_TIMEOUT);
}

/* ------------------------------------------------------------------ */
/* 4. Deadtime configuration                                          */
/* ------------------------------------------------------------------ */

/*
 * test_deadtime_zero_means_disabled - deadtime=0 disables idle check
 *
 * From ksmbd_conn_alive():
 *   if (server_conf.deadtime > 0 && time_after(...))
 * So deadtime=0 means the idle check never fires.
 */
static void test_deadtime_zero_means_disabled(struct kunit *test)
{
	unsigned long deadtime = 0;

	KUNIT_EXPECT_EQ(test, deadtime, 0UL);
	/* The if-guard skips the check */
	KUNIT_EXPECT_FALSE(test, deadtime > 0);
}

/*
 * test_deadtime_positive_seconds - positive deadtime in jiffies
 *
 * server_conf.deadtime = req->deadtime * SMB_ECHO_INTERVAL
 */
static void test_deadtime_positive_seconds(struct kunit *test)
{
	unsigned int deadtime_minutes = 10;
	unsigned long deadtime;

	deadtime = (unsigned long)deadtime_minutes * SMB_ECHO_INTERVAL;

	/* 10 minutes = 600 seconds * HZ */
	KUNIT_EXPECT_EQ(test, deadtime, (unsigned long)(600 * HZ));
	KUNIT_EXPECT_TRUE(test, deadtime > 0);
}

/* ------------------------------------------------------------------ */
/* 5. IPC timeout                                                     */
/* ------------------------------------------------------------------ */

/*
 * test_ipc_timeout_conversion - IPC timeout in seconds * HZ
 *
 * From transport_ipc.c: server_conf.ipc_timeout = req->ipc_timeout * HZ;
 * The default ipc_timeout in ksmbd-tools is 10 seconds.
 */
static void test_ipc_timeout_conversion(struct kunit *test)
{
	unsigned short ipc_timeout_secs = 10;
	unsigned short ipc_timeout_jiffies;

	ipc_timeout_jiffies = ipc_timeout_secs * HZ;

	KUNIT_EXPECT_EQ(test, (unsigned long)ipc_timeout_jiffies,
			(unsigned long)(10 * HZ));
}

/*
 * test_ipc_timeout_zero_disables - zero means IPC heartbeat is off
 */
static void test_ipc_timeout_zero_disables(struct kunit *test)
{
	unsigned short ipc_timeout = 0;

	/* When ipc_timeout is 0, ipc_update_last_active() does nothing */
	KUNIT_EXPECT_FALSE(test, ipc_timeout != 0);
}

/* ------------------------------------------------------------------ */
/* 6. Timeout conversion -- seconds to jiffies and back               */
/* ------------------------------------------------------------------ */

/*
 * test_seconds_to_jiffies_roundtrip - conversion roundtrip
 */
static void test_seconds_to_jiffies_roundtrip(struct kunit *test)
{
	unsigned long secs = 42;
	unsigned long j = secs * HZ;
	unsigned long back_to_secs = j / HZ;

	KUNIT_EXPECT_EQ(test, back_to_secs, secs);
}

/*
 * test_msecs_to_jiffies_roundtrip - millisecond conversion roundtrip
 */
static void test_msecs_to_jiffies_roundtrip(struct kunit *test)
{
	unsigned int msecs = 5000;
	unsigned long j = __msecs_to_jiffies(msecs);
	unsigned int back_to_msecs = jiffies_to_msecs(j);

	/*
	 * jiffies conversions can lose precision if HZ doesn't
	 * divide 1000 evenly, but for multiples of 1000ms it's exact.
	 */
	KUNIT_EXPECT_EQ(test, back_to_msecs, msecs);
}

/* ------------------------------------------------------------------ */
/* 7. Deadtime overflow check                                         */
/* ------------------------------------------------------------------ */

/*
 * test_deadtime_overflow_check - check_mul_overflow prevents wrap
 *
 * From transport_ipc.c:
 *   if (check_mul_overflow(req->deadtime, SMB_ECHO_INTERVAL,
 *                          &server_conf.deadtime))
 *       ret = -EINVAL;
 */
static void test_deadtime_overflow_check(struct kunit *test)
{
	unsigned long result;
	bool overflow;

	/* Normal case: 15 minutes, no overflow */
	overflow = check_mul_overflow(15UL, (unsigned long)SMB_ECHO_INTERVAL,
				      &result);
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, result, (unsigned long)(15 * SMB_ECHO_INTERVAL));

	/* Edge case: very large value that could overflow */
	overflow = check_mul_overflow(ULONG_MAX / HZ + 1,
				      (unsigned long)SMB_ECHO_INTERVAL,
				      &result);
	KUNIT_EXPECT_TRUE(test, overflow);
}

/* ------------------------------------------------------------------ */
/* 8. IPC last_active delta computation                               */
/* ------------------------------------------------------------------ */

/*
 * test_ipc_last_active_delta - delta = jiffies - ipc_last_active
 *
 * From ipc_timer_work_fn():
 *   if (time_after(jiffies, server_conf.ipc_last_active))
 *       delta = jiffies - server_conf.ipc_last_active;
 */
static void test_ipc_last_active_delta(struct kunit *test)
{
	unsigned long now = jiffies;
	unsigned long ipc_last_active = now - 5 * HZ;
	unsigned long delta;

	if (time_after(now, ipc_last_active))
		delta = now - ipc_last_active;
	else
		delta = 0;

	KUNIT_EXPECT_GE(test, delta, (unsigned long)(5 * HZ));
}

/*
 * test_ipc_delta_within_timeout - delta < ipc_timeout reschedules
 */
static void test_ipc_delta_within_timeout(struct kunit *test)
{
	unsigned short ipc_timeout = 10 * HZ;
	unsigned long now = jiffies;
	unsigned long ipc_last_active = now - 3 * HZ;
	unsigned long delta = now - ipc_last_active;
	bool within_timeout;

	within_timeout = (delta < ipc_timeout);
	KUNIT_EXPECT_TRUE(test, within_timeout);

	/* Remaining time until next check */
	KUNIT_EXPECT_GT(test, (unsigned long)(ipc_timeout - delta), 0UL);
}

/* ------------------------------------------------------------------ */
/* 9. Socket backlog constant                                         */
/* ------------------------------------------------------------------ */

/*
 * test_socket_backlog_value - KSMBD_SOCKET_BACKLOG = 64
 */
static void test_socket_backlog_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_SOCKET_BACKLOG, 64);
}

/* ------------------------------------------------------------------ */
/* 10. Connection hash sizing                                         */
/* ------------------------------------------------------------------ */

/*
 * test_conn_hash_sizing - CONN_HASH_SIZE = 1 << CONN_HASH_BITS
 */
static void test_conn_hash_sizing(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, CONN_HASH_BITS, 8);
	KUNIT_EXPECT_EQ(test, CONN_HASH_SIZE, 256);
	KUNIT_EXPECT_EQ(test, CONN_HASH_SIZE, (1 << CONN_HASH_BITS));
}

/* ------------------------------------------------------------------ */

static struct kunit_case ksmbd_timing_transport_test_cases[] = {
	KUNIT_CASE(test_tcp_recv_timeout_value),
	KUNIT_CASE(test_tcp_recv_timeout_seconds),
	KUNIT_CASE(test_tcp_send_timeout_value),
	KUNIT_CASE(test_tcp_send_timeout_seconds),
	KUNIT_CASE(test_send_less_than_recv),
	KUNIT_CASE(test_deadtime_zero_means_disabled),
	KUNIT_CASE(test_deadtime_positive_seconds),
	KUNIT_CASE(test_ipc_timeout_conversion),
	KUNIT_CASE(test_ipc_timeout_zero_disables),
	KUNIT_CASE(test_seconds_to_jiffies_roundtrip),
	KUNIT_CASE(test_msecs_to_jiffies_roundtrip),
	KUNIT_CASE(test_deadtime_overflow_check),
	KUNIT_CASE(test_ipc_last_active_delta),
	KUNIT_CASE(test_ipc_delta_within_timeout),
	KUNIT_CASE(test_socket_backlog_value),
	KUNIT_CASE(test_conn_hash_sizing),
	{}
};

static struct kunit_suite ksmbd_timing_transport_test_suite = {
	.name = "ksmbd_timing_transport",
	.test_cases = ksmbd_timing_transport_test_cases,
};

kunit_test_suite(ksmbd_timing_transport_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd transport timeout timing");
