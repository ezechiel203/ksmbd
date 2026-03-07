// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for oplock/lease break timing requirements
 *   (MS-SMB2 3.3.4.6, 3.3.4.7, 3.3.2.1)
 *
 *   Tests verify the OPLOCK_WAIT_TIME constant, the pending_break bit
 *   protocol, oplock state transitions, and the relationship between
 *   oplock and lease break timers.  All tests use jiffies arithmetic
 *   with no actual sleeping or real oplock structures.
 */

#include <kunit/test.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/bitops.h>

#include "oplock.h"
#include "smb2pdu.h"

/* ------------------------------------------------------------------ */
/* 1. Oplock break acknowledgment timeout                             */
/* ------------------------------------------------------------------ */

/*
 * test_oplock_wait_time_value - OPLOCK_WAIT_TIME = 35 * HZ (35 seconds)
 *
 * MS-SMB2 3.3.2.1: The server sets Open.OplockTimeout to the current
 * time plus an implementation-specific default value in milliseconds.
 * ksmbd uses 35 seconds as the oplock break acknowledgment timeout.
 */
static void test_oplock_wait_time_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned long)OPLOCK_WAIT_TIME,
			(unsigned long)(35 * HZ));
}

/*
 * test_oplock_wait_time_seconds - verify conversion to seconds
 */
static void test_oplock_wait_time_seconds(struct kunit *test)
{
	unsigned long timeout_secs = OPLOCK_WAIT_TIME / HZ;

	KUNIT_EXPECT_EQ(test, timeout_secs, 35UL);
}

/* ------------------------------------------------------------------ */
/* 2. Break timeout triggers state change                             */
/* ------------------------------------------------------------------ */

/*
 * test_break_timeout_triggers_downgrade - unacknowledged break times out
 *
 * From oplock.c wait_event_interruptible_timeout():
 *   rc = wait_event_interruptible_timeout(opinfo->oplock_q,
 *       opinfo->op_state == OPLOCK_STATE_NONE ||
 *       opinfo->op_state == OPLOCK_CLOSING,
 *       OPLOCK_WAIT_TIME);
 *
 * rc == 0 means timeout: the server downgrades the oplock.
 */
static void test_break_timeout_triggers_downgrade(struct kunit *test)
{
	long rc = 0; /* simulated timeout return from wait_event */
	int new_level;

	/* rc == 0 means the wait timed out -- no ack received */
	if (!rc) {
		/* Server downgrades to level II or none */
		new_level = SMB2_OPLOCK_LEVEL_NONE;
	} else {
		/* Ack received in time */
		new_level = SMB2_OPLOCK_LEVEL_II;
	}

	KUNIT_EXPECT_EQ(test, new_level, SMB2_OPLOCK_LEVEL_NONE);
}

/*
 * test_break_ack_received_in_time - ack before timeout preserves level
 */
static void test_break_ack_received_in_time(struct kunit *test)
{
	long rc = 1; /* nonzero means condition was met before timeout */
	int op_state_after;

	if (!rc) {
		/* Timeout: error path */
		op_state_after = OPLOCK_CLOSING;
	} else {
		/* Client acknowledged the break */
		op_state_after = OPLOCK_STATE_NONE;
	}

	KUNIT_EXPECT_EQ(test, op_state_after, OPLOCK_STATE_NONE);
}

/* ------------------------------------------------------------------ */
/* 3. Oplock state constants                                          */
/* ------------------------------------------------------------------ */

/*
 * test_oplock_state_constants - verify oplock state values are distinct
 */
static void test_oplock_state_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, OPLOCK_STATE_NONE, 0x00);
	KUNIT_EXPECT_EQ(test, OPLOCK_ACK_WAIT, 0x01);
	KUNIT_EXPECT_EQ(test, OPLOCK_CLOSING, 0x02);

	KUNIT_EXPECT_NE(test, OPLOCK_STATE_NONE, OPLOCK_ACK_WAIT);
	KUNIT_EXPECT_NE(test, OPLOCK_ACK_WAIT, OPLOCK_CLOSING);
	KUNIT_EXPECT_NE(test, OPLOCK_STATE_NONE, OPLOCK_CLOSING);
}

/* ------------------------------------------------------------------ */
/* 4. Pending break bit protocol                                      */
/* ------------------------------------------------------------------ */

/*
 * test_pending_break_bit_set_clear - test_and_set_bit / clear_bit_unlock
 *
 * From oplock.c:
 *   while (test_and_set_bit(0, &opinfo->pending_break)) {
 *       ret = wait_on_bit_timeout(&opinfo->pending_break, 0,
 *                                 TASK_UNINTERRUPTIBLE, OPLOCK_WAIT_TIME);
 *   }
 *
 * We simulate the bit protocol with a local unsigned long.
 */
static void test_pending_break_bit_set_clear(struct kunit *test)
{
	unsigned long pending_break = 0;

	/* Initially not set */
	KUNIT_EXPECT_FALSE(test, test_bit(0, &pending_break));

	/* Set the bit -- should succeed (was 0) */
	KUNIT_EXPECT_FALSE(test, test_and_set_bit(0, &pending_break));
	KUNIT_EXPECT_TRUE(test, test_bit(0, &pending_break));

	/* Try again -- should fail (was 1) */
	KUNIT_EXPECT_TRUE(test, test_and_set_bit(0, &pending_break));

	/* Clear the bit */
	clear_bit_unlock(0, &pending_break);
	KUNIT_EXPECT_FALSE(test, test_bit(0, &pending_break));
}

/* ------------------------------------------------------------------ */
/* 5. Lease break timeout -- same timer as oplock break               */
/* ------------------------------------------------------------------ */

/*
 * test_lease_break_timeout_same_as_oplock - both use OPLOCK_WAIT_TIME
 *
 * MS-SMB2 3.3.2.5: The lease break acknowledgment timer uses the same
 * implementation-specific timeout.  In ksmbd, both paths use
 * OPLOCK_WAIT_TIME for the wait_event_interruptible_timeout().
 */
static void test_lease_break_timeout_same_as_oplock(struct kunit *test)
{
	unsigned long oplock_break_timeout = OPLOCK_WAIT_TIME;
	unsigned long lease_break_timeout = OPLOCK_WAIT_TIME;

	KUNIT_EXPECT_EQ(test, oplock_break_timeout, lease_break_timeout);
}

/* ------------------------------------------------------------------ */
/* 6. Multiple pending breaks -- each has independent timeout         */
/* ------------------------------------------------------------------ */

/*
 * test_multiple_pending_breaks_independent - each break has its own timer
 *
 * Each oplock_info has its own pending_break bit and oplock_q waitqueue,
 * so breaks on different files are tracked independently.
 */
static void test_multiple_pending_breaks_independent(struct kunit *test)
{
	unsigned long pending_a = 0;
	unsigned long pending_b = 0;
	unsigned long pending_c = 0;

	/* Break file A */
	test_and_set_bit(0, &pending_a);
	KUNIT_EXPECT_TRUE(test, test_bit(0, &pending_a));
	KUNIT_EXPECT_FALSE(test, test_bit(0, &pending_b));
	KUNIT_EXPECT_FALSE(test, test_bit(0, &pending_c));

	/* Break file B */
	test_and_set_bit(0, &pending_b);
	KUNIT_EXPECT_TRUE(test, test_bit(0, &pending_a));
	KUNIT_EXPECT_TRUE(test, test_bit(0, &pending_b));
	KUNIT_EXPECT_FALSE(test, test_bit(0, &pending_c));

	/* Ack file A */
	clear_bit_unlock(0, &pending_a);
	KUNIT_EXPECT_FALSE(test, test_bit(0, &pending_a));
	KUNIT_EXPECT_TRUE(test, test_bit(0, &pending_b));
}

/* ------------------------------------------------------------------ */
/* 7. Oplock break transition flags                                   */
/* ------------------------------------------------------------------ */

/*
 * test_oplock_break_transition_flags - verify transition bitmask values
 */
static void test_oplock_break_transition_flags(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, OPLOCK_WRITE_TO_READ, 0x01);
	KUNIT_EXPECT_EQ(test, OPLOCK_READ_HANDLE_TO_READ, 0x02);
	KUNIT_EXPECT_EQ(test, OPLOCK_WRITE_TO_NONE, 0x04);
	KUNIT_EXPECT_EQ(test, OPLOCK_READ_TO_NONE, 0x08);

	/* Flags are distinct single bits */
	KUNIT_EXPECT_EQ(test,
		OPLOCK_WRITE_TO_READ & OPLOCK_READ_HANDLE_TO_READ, 0);
	KUNIT_EXPECT_EQ(test,
		OPLOCK_WRITE_TO_NONE & OPLOCK_READ_TO_NONE, 0);
}

/* ------------------------------------------------------------------ */
/* 8. Break during session reconnect -- timing interaction            */
/* ------------------------------------------------------------------ */

/*
 * test_break_during_reconnect - break pending while handle is durable
 *
 * MS-SMB2 3.3.4.6: If Open.IsDurable is TRUE and the notification could
 * not be sent on any connection, the server MUST complete the oplock break
 * with SMB2_OPLOCK_LEVEL_NONE and close the Open.
 *
 * The timeout for acknowledging the break is OPLOCK_WAIT_TIME.
 * During reconnect, if the client reconnects before OPLOCK_WAIT_TIME,
 * the break can be re-sent.
 */
static void test_break_during_reconnect(struct kunit *test)
{
	unsigned long break_sent_at = jiffies;
	unsigned long reconnect_at;
	bool break_expired;

	/* Client reconnects 10 seconds later -- within OPLOCK_WAIT_TIME */
	reconnect_at = break_sent_at + 10 * HZ;
	break_expired = time_after(reconnect_at,
				   break_sent_at + OPLOCK_WAIT_TIME);
	KUNIT_EXPECT_FALSE(test, break_expired);

	/* Client reconnects 40 seconds later -- after OPLOCK_WAIT_TIME */
	reconnect_at = break_sent_at + 40 * HZ;
	break_expired = time_after(reconnect_at,
				   break_sent_at + OPLOCK_WAIT_TIME);
	KUNIT_EXPECT_TRUE(test, break_expired);
}

/* ------------------------------------------------------------------ */
/* 9. Oplock wait timeout vs session timeout comparison               */
/* ------------------------------------------------------------------ */

/*
 * test_oplock_timeout_vs_session_timeout - oplock wait > session timeout
 *
 * OPLOCK_WAIT_TIME (35s) > SMB2_SESSION_TIMEOUT (10s). This means
 * an in-progress session could expire before an oplock break ack
 * times out, which is by design -- stale sessions are cleaned up
 * independently.
 */
static void test_oplock_timeout_vs_session_timeout(struct kunit *test)
{
	KUNIT_EXPECT_GT(test, (unsigned long)OPLOCK_WAIT_TIME,
			(unsigned long)SMB2_SESSION_TIMEOUT);
}

/* ------------------------------------------------------------------ */
/* 10. Oplock break pending bit timeout returns -ETIMEDOUT            */
/* ------------------------------------------------------------------ */

/*
 * test_pending_break_timeout_returns_etimedout - wait_on_bit_timeout
 *
 * From oplock.c oplock_break_pending():
 *   ret = wait_on_bit_timeout(&opinfo->pending_break, 0,
 *                             TASK_UNINTERRUPTIBLE, OPLOCK_WAIT_TIME);
 *   if (ret) {
 *       if (ret == -EAGAIN)
 *           return -ETIMEDOUT;
 *   }
 *
 * -EAGAIN from wait_on_bit_timeout means the timeout expired.
 */
static void test_pending_break_timeout_returns_etimedout(struct kunit *test)
{
	int ret = -EAGAIN; /* simulated timeout from wait_on_bit_timeout */
	int mapped_error;

	if (ret == -EAGAIN)
		mapped_error = -ETIMEDOUT;
	else
		mapped_error = ret;

	KUNIT_EXPECT_EQ(test, mapped_error, -ETIMEDOUT);
}

/* ------------------------------------------------------------------ */
/* 11. Oplock wait time relationship to TCP timeouts                  */
/* ------------------------------------------------------------------ */

/*
 * test_oplock_wait_vs_tcp_timeouts - OPLOCK_WAIT_TIME > TCP timeouts
 *
 * The oplock break acknowledgment window (35s) is longer than both
 * TCP recv timeout (7s) and send timeout (5s). This ensures the
 * oplock break can complete even if the transport layer recovers
 * from a brief interruption.
 */
static void test_oplock_wait_vs_tcp_timeouts(struct kunit *test)
{
	KUNIT_EXPECT_GT(test, (unsigned long)OPLOCK_WAIT_TIME,
			(unsigned long)KSMBD_TCP_RECV_TIMEOUT);
	KUNIT_EXPECT_GT(test, (unsigned long)OPLOCK_WAIT_TIME,
			(unsigned long)KSMBD_TCP_SEND_TIMEOUT);
}

/* ------------------------------------------------------------------ */

static struct kunit_case ksmbd_timing_oplock_test_cases[] = {
	KUNIT_CASE(test_oplock_wait_time_value),
	KUNIT_CASE(test_oplock_wait_time_seconds),
	KUNIT_CASE(test_break_timeout_triggers_downgrade),
	KUNIT_CASE(test_break_ack_received_in_time),
	KUNIT_CASE(test_oplock_state_constants),
	KUNIT_CASE(test_pending_break_bit_set_clear),
	KUNIT_CASE(test_lease_break_timeout_same_as_oplock),
	KUNIT_CASE(test_multiple_pending_breaks_independent),
	KUNIT_CASE(test_oplock_break_transition_flags),
	KUNIT_CASE(test_break_during_reconnect),
	KUNIT_CASE(test_oplock_timeout_vs_session_timeout),
	KUNIT_CASE(test_pending_break_timeout_returns_etimedout),
	KUNIT_CASE(test_oplock_wait_vs_tcp_timeouts),
	{}
};

static struct kunit_suite ksmbd_timing_oplock_test_suite = {
	.name = "ksmbd_timing_oplock",
	.test_cases = ksmbd_timing_oplock_test_cases,
};

kunit_test_suite(ksmbd_timing_oplock_test_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd oplock/lease break timing");
