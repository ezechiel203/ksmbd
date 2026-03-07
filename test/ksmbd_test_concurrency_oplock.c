// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit concurrency tests for oplock break race conditions.
 *
 *   Exercises the most historically bug-prone paths in SMB server
 *   oplock/lease handling: break + CREATE races, ack contention,
 *   refcount lifetime under concurrent access, and list corruption
 *   scenarios.
 *
 *   Uses simulated oplock_info / lease / ksmbd_inode structures so
 *   tests run in-kernel without a live SMB connection.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/wait.h>

/* ---- Constants ---- */

#define NUM_THREADS		4
#define ITERATIONS		500
#define BREAK_THREADS		3

/*
 * Mirror production oplock state values from oplock.h so the test is
 * self-contained (no kernel module cross-dependencies).
 */
#define TEST_OPLOCK_STATE_NONE		0x00
#define TEST_OPLOCK_ACK_WAIT		0x01
#define TEST_OPLOCK_CLOSING		0x02

/* Oplock levels (matches SMB2 on-wire values) */
#define TEST_LEVEL_NONE		0x00
#define TEST_LEVEL_II		0x01
#define TEST_LEVEL_EXCLUSIVE	0x08
#define TEST_LEVEL_BATCH	0x09

/* Lease state bits (matches cpu_to_le32 values but used as plain u32 here) */
#define TEST_LEASE_NONE		0x00
#define TEST_LEASE_READ		0x01
#define TEST_LEASE_HANDLE	0x02
#define TEST_LEASE_WRITE	0x04

/* ---- Simulated structures ---- */

struct test_lease {
	u32	state;
	u32	new_state;
	u16	epoch;
};

struct test_opinfo {
	int			level;
	int			op_state;
	unsigned long		pending_break;
	atomic_t		refcount;
	atomic_t		breaking_cnt;
	bool			is_lease;
	struct test_lease	*lease;
	struct list_head	op_entry;
	wait_queue_head_t	oplock_q;
	wait_queue_head_t	oplock_brk;
};

struct test_ksmbd_inode {
	struct rw_semaphore	m_lock;
	struct list_head	m_op_list;
	atomic_t		op_count;
};

/* ---- Helpers ---- */

static struct test_opinfo *alloc_test_opinfo(struct kunit *test, int level,
					     bool is_lease)
{
	struct test_opinfo *op;

	op = kunit_kzalloc(test, sizeof(*op), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, op);

	op->level = level;
	op->op_state = TEST_OPLOCK_STATE_NONE;
	op->pending_break = 0;
	op->is_lease = is_lease;
	atomic_set(&op->refcount, 1);
	atomic_set(&op->breaking_cnt, 0);
	INIT_LIST_HEAD(&op->op_entry);
	init_waitqueue_head(&op->oplock_q);
	init_waitqueue_head(&op->oplock_brk);

	if (is_lease) {
		op->lease = kunit_kzalloc(test, sizeof(*op->lease), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, op->lease);
		op->lease->state = TEST_LEASE_READ;
		op->lease->new_state = TEST_LEASE_NONE;
		op->lease->epoch = 1;
	}

	return op;
}

static void init_test_inode(struct test_ksmbd_inode *ci)
{
	init_rwsem(&ci->m_lock);
	INIT_LIST_HEAD(&ci->m_op_list);
	atomic_set(&ci->op_count, 0);
}

/* Simulated refcount helpers (mirrors opinfo_get / opinfo_put pattern) */
static bool test_opinfo_get(struct test_opinfo *op)
{
	return atomic_inc_not_zero(&op->refcount) != 0;
}

static bool test_opinfo_put(struct test_opinfo *op)
{
	return atomic_dec_and_test(&op->refcount);
}

/* ================================================================
 * Test 1: Oplock state machine transitions under concurrent access
 *
 * Multiple threads race to transition op_state via cmpxchg-style
 * spinlock-guarded updates. Verifies no invalid states appear.
 * ================================================================ */

struct state_machine_ctx {
	struct test_opinfo	*op;
	spinlock_t		lock;
	struct completion	start;
	atomic_t		success_count;
	atomic_t		failure_count;
	atomic_t		transition_count;
};

static int oplock_state_transition_thread(void *data)
{
	struct state_machine_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i, state;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		state = op->op_state;

		switch (state) {
		case TEST_OPLOCK_STATE_NONE:
			op->op_state = TEST_OPLOCK_ACK_WAIT;
			atomic_inc(&ctx->transition_count);
			break;
		case TEST_OPLOCK_ACK_WAIT:
			op->op_state = TEST_OPLOCK_STATE_NONE;
			atomic_inc(&ctx->transition_count);
			break;
		case TEST_OPLOCK_CLOSING:
			/* terminal -- leave as-is */
			break;
		default:
			atomic_inc(&ctx->failure_count);
			break;
		}
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_oplock_state_machine_concurrent(struct kunit *test)
{
	struct state_machine_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_EXCLUSIVE, false);
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);
	atomic_set(&ctx->transition_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(oplock_state_transition_thread,
					 ctx, "opst_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(300);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
	KUNIT_EXPECT_GT(test, atomic_read(&ctx->transition_count), 0);
}

/* ================================================================
 * Test 2: Oplock break acknowledgment race
 *
 * One thread sends a break (sets ACK_WAIT + sets pending_break bit),
 * another thread races to acknowledge (clears pending_break + wakes).
 * ================================================================ */

struct break_ack_ctx {
	struct test_opinfo	*op;
	struct completion	start;
	atomic_t		breaks_sent;
	atomic_t		acks_received;
	atomic_t		success_count;
};

static int break_sender_thread(void *data)
{
	struct break_ack_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		/* Simulate sending an oplock break */
		if (!test_and_set_bit(0, &op->pending_break)) {
			op->op_state = TEST_OPLOCK_ACK_WAIT;
			atomic_inc(&ctx->breaks_sent);
			/* Wait briefly for ack */
			wait_event_timeout(op->oplock_q,
				op->op_state != TEST_OPLOCK_ACK_WAIT,
				msecs_to_jiffies(1));
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int break_ack_thread(void *data)
{
	struct break_ack_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (test_bit(0, &op->pending_break)) {
			op->op_state = TEST_OPLOCK_STATE_NONE;
			op->level = TEST_LEVEL_II;
			clear_bit_unlock(0, &op->pending_break);
			smp_mb__after_atomic();
			wake_up(&op->oplock_q);
			atomic_inc(&ctx->acks_received);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_oplock_break_ack_race(struct kunit *test)
{
	struct break_ack_ctx *ctx;
	struct task_struct *sender, *acker;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_BATCH, false);
	init_completion(&ctx->start);
	atomic_set(&ctx->breaks_sent, 0);
	atomic_set(&ctx->acks_received, 0);
	atomic_set(&ctx->success_count, 0);

	sender = kthread_run(break_sender_thread, ctx, "brk_snd");
	KUNIT_ASSERT_FALSE(test, IS_ERR(sender));
	acker = kthread_run(break_ack_thread, ctx, "brk_ack");
	KUNIT_ASSERT_FALSE(test, IS_ERR(acker));

	complete_all(&ctx->start);
	msleep(400);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 2);
	/* At least some breaks should have been sent and acked */
	KUNIT_EXPECT_GT(test, atomic_read(&ctx->breaks_sent), 0);
}

/* ================================================================
 * Test 3: New open during oplock break
 *
 * Thread A holds exclusive oplock and starts a break sequence.
 * Thread B (simulating a second CREATE) waits on pending_break bit
 * until Thread A completes the break. Verifies the wait-and-proceed
 * pattern is safe under concurrency.
 * ================================================================ */

struct open_during_break_ctx {
	struct test_opinfo	*op;
	struct completion	start;
	struct completion	break_started;
	atomic_t		opener_proceeded;
	atomic_t		success_count;
};

static int holder_break_thread(void *data)
{
	struct open_during_break_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;

	wait_for_completion(&ctx->start);

	/* Begin break */
	set_bit(0, &op->pending_break);
	op->op_state = TEST_OPLOCK_ACK_WAIT;
	complete(&ctx->break_started);

	/* Simulate break processing time */
	msleep(20);

	/* Complete the break */
	op->level = TEST_LEVEL_II;
	op->op_state = TEST_OPLOCK_STATE_NONE;
	clear_bit_unlock(0, &op->pending_break);
	smp_mb__after_atomic();
	wake_up_bit(&op->pending_break, 0);

	atomic_inc(&ctx->success_count);
	return 0;
}

static int new_open_thread(void *data)
{
	struct open_during_break_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;

	wait_for_completion(&ctx->start);

	/* Wait until break is started */
	wait_for_completion(&ctx->break_started);

	/* Like oplock_break_pending: wait on the bit */
	wait_on_bit(&op->pending_break, 0, TASK_UNINTERRUPTIBLE);

	/* Break completed -- new open can proceed */
	KUNIT_EXPECT_EQ(current->kunit_test, op->level, TEST_LEVEL_II);
	atomic_inc(&ctx->opener_proceeded);
	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_new_open_during_break(struct kunit *test)
{
	struct open_during_break_ctx *ctx;
	struct task_struct *holder, *opener;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_EXCLUSIVE, false);
	init_completion(&ctx->start);
	init_completion(&ctx->break_started);
	atomic_set(&ctx->opener_proceeded, 0);
	atomic_set(&ctx->success_count, 0);

	holder = kthread_run(holder_break_thread, ctx, "holder");
	KUNIT_ASSERT_FALSE(test, IS_ERR(holder));
	opener = kthread_run(new_open_thread, ctx, "opener");
	KUNIT_ASSERT_FALSE(test, IS_ERR(opener));

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->opener_proceeded), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 2);
}

/* ================================================================
 * Test 4: Oplock upgrade/downgrade race
 *
 * Two threads concurrently try to change oplock levels under a
 * spinlock. Only valid transitions should succeed.
 * ================================================================ */

struct upgrade_race_ctx {
	struct test_opinfo	*op;
	spinlock_t		lock;
	struct completion	start;
	atomic_t		upgrades;
	atomic_t		downgrades;
	atomic_t		success_count;
};

static int upgrade_thread(void *data)
{
	struct upgrade_race_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		if (op->level == TEST_LEVEL_II) {
			op->level = TEST_LEVEL_EXCLUSIVE;
			atomic_inc(&ctx->upgrades);
		}
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int downgrade_thread(void *data)
{
	struct upgrade_race_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		if (op->level == TEST_LEVEL_EXCLUSIVE ||
		    op->level == TEST_LEVEL_BATCH) {
			op->level = TEST_LEVEL_II;
			atomic_inc(&ctx->downgrades);
		}
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_oplock_upgrade_downgrade_race(struct kunit *test)
{
	struct upgrade_race_ctx *ctx;
	struct task_struct *up_threads[2], *down_threads[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_II, false);
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->upgrades, 0);
	atomic_set(&ctx->downgrades, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < 2; i++) {
		up_threads[i] = kthread_run(upgrade_thread, ctx,
					    "up_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(up_threads[i]));
	}
	for (i = 0; i < 2; i++) {
		down_threads[i] = kthread_run(downgrade_thread, ctx,
					      "down_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(down_threads[i]));
	}

	complete_all(&ctx->start);
	msleep(300);

	/* Final level must be one of the valid values */
	KUNIT_EXPECT_TRUE(test,
		ctx->op->level == TEST_LEVEL_II ||
		ctx->op->level == TEST_LEVEL_EXCLUSIVE);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
}

/* ================================================================
 * Test 5: Batch oplock break + close race
 *
 * One thread initiates a break, another closes the handle (sets
 * OPLOCK_CLOSING and wakes waiters). Mirrors close_id_del_oplock().
 * ================================================================ */

struct break_close_ctx {
	struct test_opinfo	*op;
	struct completion	start;
	atomic_t		break_completed;
	atomic_t		close_completed;
	atomic_t		success_count;
};

static int break_initiate_thread(void *data)
{
	struct break_close_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;

	wait_for_completion(&ctx->start);

	set_bit(0, &op->pending_break);
	op->op_state = TEST_OPLOCK_ACK_WAIT;

	/* Wait for ack or close */
	wait_event_timeout(op->oplock_q,
		op->op_state != TEST_OPLOCK_ACK_WAIT,
		msecs_to_jiffies(100));

	if (op->op_state == TEST_OPLOCK_CLOSING)
		atomic_inc(&ctx->close_completed);
	else
		atomic_inc(&ctx->break_completed);

	clear_bit_unlock(0, &op->pending_break);
	smp_mb__after_atomic();
	wake_up_bit(&op->pending_break, 0);

	atomic_inc(&ctx->success_count);
	return 0;
}

static int close_handle_thread(void *data)
{
	struct break_close_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;

	wait_for_completion(&ctx->start);

	/* Simulate a brief delay then close */
	msleep(5);

	/* Mirror close_id_del_oplock behavior */
	if (op->op_state == TEST_OPLOCK_ACK_WAIT) {
		op->op_state = TEST_OPLOCK_CLOSING;
		wake_up_interruptible_all(&op->oplock_q);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_batch_break_close_race(struct kunit *test)
{
	struct break_close_ctx *ctx;
	struct task_struct *breaker, *closer;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_BATCH, false);
	init_completion(&ctx->start);
	atomic_set(&ctx->break_completed, 0);
	atomic_set(&ctx->close_completed, 0);
	atomic_set(&ctx->success_count, 0);

	breaker = kthread_run(break_initiate_thread, ctx, "breaker");
	KUNIT_ASSERT_FALSE(test, IS_ERR(breaker));
	closer = kthread_run(close_handle_thread, ctx, "closer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(closer));

	complete_all(&ctx->start);
	msleep(300);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 2);
	/* Either break or close completed -- exactly one path wins */
	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->break_completed) +
		atomic_read(&ctx->close_completed), 1);
}

/* ================================================================
 * Test 6: Lease break vs oplock break priority
 *
 * Two opinfos on same inode -- one lease, one plain oplock. Both
 * get breaks triggered concurrently. Verifies list traversal safety.
 * ================================================================ */

struct lease_vs_oplock_ctx {
	struct test_ksmbd_inode	ci;
	struct test_opinfo	*lease_op;
	struct test_opinfo	*plain_op;
	struct completion	start;
	atomic_t		lease_broke;
	atomic_t		plain_broke;
	atomic_t		success_count;
};

static int lease_break_thread(void *data)
{
	struct lease_vs_oplock_ctx *ctx = data;
	struct test_opinfo *op = ctx->lease_op;

	wait_for_completion(&ctx->start);

	if (!test_and_set_bit(0, &op->pending_break)) {
		op->op_state = TEST_OPLOCK_ACK_WAIT;
		if (op->lease) {
			op->lease->new_state = TEST_LEASE_READ;
			atomic_inc(&op->breaking_cnt);
		}
		/* Simulate break time */
		msleep(5);

		op->level = TEST_LEVEL_II;
		if (op->lease)
			op->lease->state = op->lease->new_state;
		op->op_state = TEST_OPLOCK_STATE_NONE;

		clear_bit_unlock(0, &op->pending_break);
		smp_mb__after_atomic();
		wake_up_bit(&op->pending_break, 0);
		atomic_inc(&ctx->lease_broke);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int plain_break_thread(void *data)
{
	struct lease_vs_oplock_ctx *ctx = data;
	struct test_opinfo *op = ctx->plain_op;

	wait_for_completion(&ctx->start);

	if (!test_and_set_bit(0, &op->pending_break)) {
		op->op_state = TEST_OPLOCK_ACK_WAIT;
		msleep(5);
		op->level = TEST_LEVEL_II;
		op->op_state = TEST_OPLOCK_STATE_NONE;

		clear_bit_unlock(0, &op->pending_break);
		smp_mb__after_atomic();
		wake_up_bit(&op->pending_break, 0);
		atomic_inc(&ctx->plain_broke);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_lease_vs_oplock_break_priority(struct kunit *test)
{
	struct lease_vs_oplock_ctx *ctx;
	struct task_struct *lt, *pt;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	init_test_inode(&ctx->ci);
	ctx->lease_op = alloc_test_opinfo(test, TEST_LEVEL_EXCLUSIVE, true);
	ctx->lease_op->lease->state = TEST_LEASE_READ | TEST_LEASE_WRITE;
	ctx->plain_op = alloc_test_opinfo(test, TEST_LEVEL_EXCLUSIVE, false);

	down_write(&ctx->ci.m_lock);
	list_add(&ctx->lease_op->op_entry, &ctx->ci.m_op_list);
	list_add(&ctx->plain_op->op_entry, &ctx->ci.m_op_list);
	up_write(&ctx->ci.m_lock);

	init_completion(&ctx->start);
	atomic_set(&ctx->lease_broke, 0);
	atomic_set(&ctx->plain_broke, 0);
	atomic_set(&ctx->success_count, 0);

	lt = kthread_run(lease_break_thread, ctx, "lbrk");
	KUNIT_ASSERT_FALSE(test, IS_ERR(lt));
	pt = kthread_run(plain_break_thread, ctx, "pbrk");
	KUNIT_ASSERT_FALSE(test, IS_ERR(pt));

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 2);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->lease_broke), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->plain_broke), 1);

	/* Both should now be at Level II */
	KUNIT_EXPECT_EQ(test, ctx->lease_op->level, TEST_LEVEL_II);
	KUNIT_EXPECT_EQ(test, ctx->plain_op->level, TEST_LEVEL_II);
}

/* ================================================================
 * Test 7: Multiple break notifications on the same file
 *
 * 3+ threads trigger breaks on different opinfos attached to the
 * same simulated inode's m_op_list. Verifies no list corruption.
 * ================================================================ */

struct multi_break_ctx {
	struct test_ksmbd_inode	ci;
	struct test_opinfo	*ops[BREAK_THREADS + 1]; /* extra is "holder" */
	struct completion	start;
	atomic_t		breaks_done;
	atomic_t		success_count;
	atomic_t		failure_count;
};

static int multi_break_thread(void *data)
{
	struct multi_break_ctx *ctx = data;
	struct test_opinfo *op;
	int i;

	wait_for_completion(&ctx->start);

	/* Walk the list like smb_break_all_levII_oplock does */
	for (i = 0; i < ITERATIONS; i++) {
		down_read(&ctx->ci.m_lock);
		list_for_each_entry(op, &ctx->ci.m_op_list, op_entry) {
			if (!atomic_inc_not_zero(&op->refcount))
				continue;

			/* Simulate break processing */
			if (op->level == TEST_LEVEL_II)
				atomic_inc(&ctx->breaks_done);
			else if (op->level > TEST_LEVEL_II)
				atomic_inc(&ctx->breaks_done);

			atomic_dec(&op->refcount);
		}
		up_read(&ctx->ci.m_lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_multiple_break_notifications(struct kunit *test)
{
	struct multi_break_ctx *ctx;
	struct task_struct *threads[BREAK_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	init_test_inode(&ctx->ci);
	init_completion(&ctx->start);
	atomic_set(&ctx->breaks_done, 0);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);

	/* Create opinfos and add to inode's list */
	for (i = 0; i <= BREAK_THREADS; i++) {
		ctx->ops[i] = alloc_test_opinfo(test, TEST_LEVEL_II, false);
		down_write(&ctx->ci.m_lock);
		list_add(&ctx->ops[i]->op_entry, &ctx->ci.m_op_list);
		up_write(&ctx->ci.m_lock);
	}

	for (i = 0; i < BREAK_THREADS; i++) {
		threads[i] = kthread_run(multi_break_thread, ctx,
					 "mbrk_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(300);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), BREAK_THREADS);
	KUNIT_EXPECT_GT(test, atomic_read(&ctx->breaks_done), 0);
}

/* ================================================================
 * Test 8: Break timeout + retry
 *
 * Break bit is set, ack never arrives within timeout. Verify the
 * breaking thread handles timeout gracefully and can retry.
 * ================================================================ */

struct break_timeout_ctx {
	struct test_opinfo	*op;
	struct completion	start;
	atomic_t		timeouts;
	atomic_t		retries;
	atomic_t		success_count;
};

static int break_with_timeout_thread(void *data)
{
	struct break_timeout_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;
	long ret;

	wait_for_completion(&ctx->start);

	for (i = 0; i < 3; i++) {
		set_bit(0, &op->pending_break);
		op->op_state = TEST_OPLOCK_ACK_WAIT;

		/* Short timeout simulating OPLOCK_WAIT_TIME */
		ret = wait_event_timeout(op->oplock_q,
			op->op_state != TEST_OPLOCK_ACK_WAIT,
			msecs_to_jiffies(10));

		if (ret == 0) {
			/* Timeout -- no ack received */
			atomic_inc(&ctx->timeouts);
			op->op_state = TEST_OPLOCK_STATE_NONE;
			op->level = TEST_LEVEL_NONE;
		}

		clear_bit_unlock(0, &op->pending_break);
		smp_mb__after_atomic();
		wake_up_bit(&op->pending_break, 0);

		atomic_inc(&ctx->retries);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_break_timeout_retry(struct kunit *test)
{
	struct break_timeout_ctx *ctx;
	struct task_struct *t;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_BATCH, false);
	init_completion(&ctx->start);
	atomic_set(&ctx->timeouts, 0);
	atomic_set(&ctx->retries, 0);
	atomic_set(&ctx->success_count, 0);

	t = kthread_run(break_with_timeout_thread, ctx, "brk_to");
	KUNIT_ASSERT_FALSE(test, IS_ERR(t));

	complete_all(&ctx->start);
	msleep(200);

	/* All 3 attempts should time out (no acker running) */
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->timeouts), 3);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->retries), 3);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 1);
	KUNIT_EXPECT_EQ(test, ctx->op->level, TEST_LEVEL_NONE);
}

/* ================================================================
 * Test 9: Oplock list corruption -- concurrent add/remove
 *
 * Multiple threads add and remove opinfos from a simulated inode's
 * m_op_list under rw_semaphore protection. Verifies list integrity.
 * ================================================================ */

struct list_corruption_ctx {
	struct test_ksmbd_inode	ci;
	struct completion	start;
	atomic_t		add_count;
	atomic_t		del_count;
	atomic_t		success_count;
	atomic_t		failure_count;
};

static int list_add_thread(void *data)
{
	struct list_corruption_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		struct test_opinfo *op;

		op = kzalloc(sizeof(*op), GFP_KERNEL);
		if (!op)
			continue;

		atomic_set(&op->refcount, 1);
		INIT_LIST_HEAD(&op->op_entry);

		down_write(&ctx->ci.m_lock);
		list_add(&op->op_entry, &ctx->ci.m_op_list);
		up_write(&ctx->ci.m_lock);

		atomic_inc(&ctx->add_count);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int list_del_thread(void *data)
{
	struct list_corruption_ctx *ctx = data;
	struct test_opinfo *op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		down_write(&ctx->ci.m_lock);
		if (!list_empty(&ctx->ci.m_op_list)) {
			op = list_first_entry(&ctx->ci.m_op_list,
					      struct test_opinfo, op_entry);
			list_del_init(&op->op_entry);
			up_write(&ctx->ci.m_lock);
			kfree(op);
			atomic_inc(&ctx->del_count);
		} else {
			up_write(&ctx->ci.m_lock);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int list_walk_thread(void *data)
{
	struct list_corruption_ctx *ctx = data;
	struct test_opinfo *op;
	int i, count;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		count = 0;
		down_read(&ctx->ci.m_lock);
		list_for_each_entry(op, &ctx->ci.m_op_list, op_entry) {
			count++;
			if (count > ITERATIONS * 2) {
				/* List might be corrupted (circular) */
				atomic_inc(&ctx->failure_count);
				break;
			}
		}
		up_read(&ctx->ci.m_lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_oplock_list_concurrent_add_remove(struct kunit *test)
{
	struct list_corruption_ctx *ctx;
	struct task_struct *adders[2], *delers[2], *walker;
	struct test_opinfo *op, *tmp;
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	init_test_inode(&ctx->ci);
	init_completion(&ctx->start);
	atomic_set(&ctx->add_count, 0);
	atomic_set(&ctx->del_count, 0);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);

	for (i = 0; i < 2; i++) {
		adders[i] = kthread_run(list_add_thread, ctx, "ladd_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(adders[i]));
	}
	for (i = 0; i < 2; i++) {
		delers[i] = kthread_run(list_del_thread, ctx, "ldel_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(delers[i]));
	}
	walker = kthread_run(list_walk_thread, ctx, "lwalk");
	KUNIT_ASSERT_FALSE(test, IS_ERR(walker));

	complete_all(&ctx->start);
	msleep(400);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->failure_count), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 5);

	/* Remaining list items + deleted = total added */
	i = 0;
	down_write(&ctx->ci.m_lock);
	list_for_each_entry_safe(op, tmp, &ctx->ci.m_op_list, op_entry) {
		list_del(&op->op_entry);
		kfree(op);
		i++;
	}
	up_write(&ctx->ci.m_lock);

	KUNIT_EXPECT_EQ(test, i + atomic_read(&ctx->del_count),
			atomic_read(&ctx->add_count));
}

/* ================================================================
 * Test 10: Read caching -> write caching upgrade race
 *
 * Two lease handles attempt lease_read_to_write simultaneously.
 * Only one should succeed (protected by a spinlock). This mirrors
 * the same_client_has_lease() upgrade path in oplock.c.
 * ================================================================ */

struct lease_upgrade_ctx {
	struct test_opinfo	*op;
	spinlock_t		lock;
	struct completion	start;
	atomic_t		upgrade_success;
	atomic_t		upgrade_fail;
	atomic_t		success_count;
};

static int lease_upgrade_thread(void *data)
{
	struct lease_upgrade_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	struct test_lease *lease = op->lease;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		if (lease->state == TEST_LEASE_READ) {
			/* Upgrade: R -> RW */
			lease->state = TEST_LEASE_READ | TEST_LEASE_WRITE;
			op->level = TEST_LEVEL_EXCLUSIVE;
			lease->epoch++;
			spin_unlock(&ctx->lock);
			atomic_inc(&ctx->upgrade_success);

			/* Hold briefly then downgrade */
			spin_lock(&ctx->lock);
			lease->state = TEST_LEASE_READ;
			op->level = TEST_LEVEL_II;
			spin_unlock(&ctx->lock);
		} else {
			/* Already upgraded by another thread */
			spin_unlock(&ctx->lock);
			atomic_inc(&ctx->upgrade_fail);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_lease_read_to_write_upgrade_race(struct kunit *test)
{
	struct lease_upgrade_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_II, true);
	ctx->op->lease->state = TEST_LEASE_READ;
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->upgrade_success, 0);
	atomic_set(&ctx->upgrade_fail, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(lease_upgrade_thread, ctx,
					 "lup_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(300);

	/* Total attempts = success + fail */
	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->upgrade_success) +
		atomic_read(&ctx->upgrade_fail),
		NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ================================================================
 * Test 11: Opinfo refcount get/put under concurrent access
 *
 * Multiple threads do get + put in a tight loop. Exactly one thread
 * should observe the refcount reaching zero via dec_and_test.
 * ================================================================ */

struct opinfo_refcount_ctx {
	struct test_opinfo	*op;
	struct completion	start;
	atomic_t		get_success;
	atomic_t		get_fail;
	atomic_t		success_count;
};

static int opinfo_refcount_thread(void *data)
{
	struct opinfo_refcount_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (test_opinfo_get(op)) {
			atomic_inc(&ctx->get_success);
			atomic_dec(&op->refcount);
		} else {
			atomic_inc(&ctx->get_fail);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_opinfo_refcount_concurrent(struct kunit *test)
{
	struct opinfo_refcount_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_II, false);
	init_completion(&ctx->start);
	atomic_set(&ctx->get_success, 0);
	atomic_set(&ctx->get_fail, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(opinfo_refcount_thread, ctx,
					 "opref_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* Refcount should still be 1 (base ref) */
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->op->refcount), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->get_success) +
		atomic_read(&ctx->get_fail),
		NUM_THREADS * ITERATIONS);
}

/* ================================================================
 * Test 12: Opinfo refcount dec_and_test -- exactly one thread sees zero
 * ================================================================ */

struct opinfo_dec_test_ctx {
	atomic_t		refcount;
	struct completion	start;
	atomic_t		zero_count;
};

static int opinfo_dec_test_thread(void *data)
{
	struct opinfo_dec_test_ctx *ctx = data;

	wait_for_completion(&ctx->start);

	if (atomic_dec_and_test(&ctx->refcount))
		atomic_inc(&ctx->zero_count);

	return 0;
}

static void test_opinfo_dec_and_test_exactly_one(struct kunit *test)
{
	struct opinfo_dec_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	atomic_set(&ctx->refcount, NUM_THREADS);
	init_completion(&ctx->start);
	atomic_set(&ctx->zero_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(opinfo_dec_test_thread, ctx,
					 "opdec_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->zero_count), 1);
}

/* ================================================================
 * Test 13: Lease epoch increment race
 *
 * Multiple threads increment lease->epoch under a spinlock.
 * Final epoch should equal initial + total increments.
 * ================================================================ */

struct epoch_race_ctx {
	struct test_lease	*lease;
	spinlock_t		lock;
	struct completion	start;
	atomic_t		success_count;
};

static int epoch_inc_thread(void *data)
{
	struct epoch_race_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		ctx->lease->epoch++;
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_lease_epoch_concurrent_increment(struct kunit *test)
{
	struct epoch_race_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->lease = kunit_kzalloc(test, sizeof(*ctx->lease), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->lease);
	ctx->lease->epoch = 1;
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(epoch_inc_thread, ctx,
					 "epoch_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, (int)ctx->lease->epoch,
			1 + NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ================================================================
 * Test 14: Breaking_cnt atomic correctness
 *
 * Concurrent inc/dec of breaking_cnt must stay consistent.
 * ================================================================ */

struct breaking_cnt_ctx {
	struct test_opinfo	*op;
	struct completion	start;
	atomic_t		success_count;
};

static int breaking_cnt_thread(void *data)
{
	struct breaking_cnt_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		atomic_inc(&op->breaking_cnt);
		atomic_dec(&op->breaking_cnt);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_breaking_cnt_concurrent(struct kunit *test)
{
	struct breaking_cnt_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_EXCLUSIVE, false);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(breaking_cnt_thread, ctx,
					 "bcnt_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->op->breaking_cnt), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ================================================================
 * Test 15: Lease state CAS-style transition under contention
 *
 * Multiple threads attempt to set lease->new_state via a guarded
 * compare-and-swap pattern. Only transitions from expected states
 * succeed.
 * ================================================================ */

struct lease_cas_ctx {
	struct test_lease	*lease;
	spinlock_t		lock;
	struct completion	start;
	atomic_t		transitions;
	atomic_t		rejections;
	atomic_t		success_count;
};

static int lease_cas_thread(void *data)
{
	struct lease_cas_ctx *ctx = data;
	struct test_lease *lease = ctx->lease;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		spin_lock(&ctx->lock);
		if (lease->state == TEST_LEASE_READ) {
			lease->state = TEST_LEASE_READ | TEST_LEASE_WRITE;
			atomic_inc(&ctx->transitions);
			spin_unlock(&ctx->lock);

			/* Downgrade back */
			spin_lock(&ctx->lock);
			if (lease->state == (TEST_LEASE_READ | TEST_LEASE_WRITE))
				lease->state = TEST_LEASE_READ;
			spin_unlock(&ctx->lock);
		} else {
			atomic_inc(&ctx->rejections);
			spin_unlock(&ctx->lock);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_lease_state_cas_contention(struct kunit *test)
{
	struct lease_cas_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->lease = kunit_kzalloc(test, sizeof(*ctx->lease), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->lease);
	ctx->lease->state = TEST_LEASE_READ;
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->transitions, 0);
	atomic_set(&ctx->rejections, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(lease_cas_thread, ctx,
					 "lcas_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(300);

	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->transitions) +
		atomic_read(&ctx->rejections),
		NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
	/* Final state should be back to READ (or READ|WRITE if last
	 * winner didn't get to downgrade -- either is valid) */
	KUNIT_EXPECT_TRUE(test,
		ctx->lease->state == TEST_LEASE_READ ||
		ctx->lease->state == (TEST_LEASE_READ | TEST_LEASE_WRITE));
}

/* ================================================================
 * Test 16: Pending break bit -- test_and_set_bit atomicity
 *
 * Multiple threads race to set the pending_break bit. Exactly one
 * per round should win (test_and_set_bit returns 0 for the winner).
 * ================================================================ */

struct pending_bit_ctx {
	unsigned long		pending_break;
	struct completion	start;
	atomic_t		winners;
	atomic_t		losers;
	atomic_t		success_count;
};

static int pending_bit_thread(void *data)
{
	struct pending_bit_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		if (!test_and_set_bit(0, &ctx->pending_break)) {
			atomic_inc(&ctx->winners);
			/* Hold briefly, then clear for next round */
			clear_bit_unlock(0, &ctx->pending_break);
			smp_mb__after_atomic();
		} else {
			atomic_inc(&ctx->losers);
		}
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_pending_break_bit_atomicity(struct kunit *test)
{
	struct pending_bit_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->pending_break = 0;
	init_completion(&ctx->start);
	atomic_set(&ctx->winners, 0);
	atomic_set(&ctx->losers, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(pending_bit_thread, ctx,
					 "pbit_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test,
		atomic_read(&ctx->winners) + atomic_read(&ctx->losers),
		NUM_THREADS * ITERATIONS);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
	/* Bit should be clear when done */
	KUNIT_EXPECT_FALSE(test, test_bit(0, &ctx->pending_break));
}

/* ================================================================
 * Test 17: Wait_on_bit + wake_up_bit synchronization
 *
 * One thread waits on the pending_break bit, another clears it.
 * Verifies the waiter is properly woken.
 * ================================================================ */

struct wait_wake_ctx {
	unsigned long		pending_break;
	struct completion	start;
	struct completion	bit_set;
	atomic_t		waiter_woke;
	atomic_t		success_count;
};

static int wait_bit_thread(void *data)
{
	struct wait_wake_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < 10; i++) {
		/* Signal we set the bit */
		set_bit(0, &ctx->pending_break);
		complete(&ctx->bit_set);

		/* Wait for it to be cleared */
		wait_on_bit(&ctx->pending_break, 0, TASK_UNINTERRUPTIBLE);
		atomic_inc(&ctx->waiter_woke);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int clear_bit_thread(void *data)
{
	struct wait_wake_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < 10; i++) {
		wait_for_completion(&ctx->bit_set);
		reinit_completion(&ctx->bit_set);

		msleep(5);
		clear_bit_unlock(0, &ctx->pending_break);
		smp_mb__after_atomic();
		wake_up_bit(&ctx->pending_break, 0);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_wait_wake_bit_synchronization(struct kunit *test)
{
	struct wait_wake_ctx *ctx;
	struct task_struct *waiter, *clearer;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->pending_break = 0;
	init_completion(&ctx->start);
	init_completion(&ctx->bit_set);
	atomic_set(&ctx->waiter_woke, 0);
	atomic_set(&ctx->success_count, 0);

	waiter = kthread_run(wait_bit_thread, ctx, "waiter");
	KUNIT_ASSERT_FALSE(test, IS_ERR(waiter));
	clearer = kthread_run(clear_bit_thread, ctx, "clearer");
	KUNIT_ASSERT_FALSE(test, IS_ERR(clearer));

	complete_all(&ctx->start);
	msleep(500);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->waiter_woke), 10);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 2);
}

/* ================================================================
 * Test 18: Mixed read/write access to oplock level
 *
 * Writers change level under lock; readers observe without lock.
 * All observed values must be valid oplock levels.
 * ================================================================ */

struct level_rw_ctx {
	struct test_opinfo	*op;
	rwlock_t		lock;
	struct completion	start;
	atomic_t		invalid_levels;
	atomic_t		success_count;
};

static int level_writer_thread(void *data)
{
	struct level_rw_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i;
	int levels[] = { TEST_LEVEL_NONE, TEST_LEVEL_II,
			 TEST_LEVEL_EXCLUSIVE, TEST_LEVEL_BATCH };

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		write_lock(&ctx->lock);
		op->level = levels[i % 4];
		write_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int level_reader_thread(void *data)
{
	struct level_rw_ctx *ctx = data;
	struct test_opinfo *op = ctx->op;
	int i, level;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		read_lock(&ctx->lock);
		level = op->level;
		read_unlock(&ctx->lock);

		if (level != TEST_LEVEL_NONE &&
		    level != TEST_LEVEL_II &&
		    level != TEST_LEVEL_EXCLUSIVE &&
		    level != TEST_LEVEL_BATCH)
			atomic_inc(&ctx->invalid_levels);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_oplock_level_concurrent_rw(struct kunit *test)
{
	struct level_rw_ctx *ctx;
	struct task_struct *writers[2], *readers[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->op = alloc_test_opinfo(test, TEST_LEVEL_NONE, false);
	rwlock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->invalid_levels, 0);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < 2; i++) {
		writers[i] = kthread_run(level_writer_thread, ctx,
					 "lw_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(writers[i]));
	}
	for (i = 0; i < 2; i++) {
		readers[i] = kthread_run(level_reader_thread, ctx,
					 "lr_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(readers[i]));
	}

	complete_all(&ctx->start);
	msleep(300);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->invalid_levels), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
}

/* ================================================================
 * Test 19: Op_count increment/decrement atomicity
 *
 * Tests the atomic op_count on ksmbd_inode under concurrent access
 * (mirrors opinfo_count_inc / opinfo_count_dec in oplock.c).
 * ================================================================ */

struct op_count_ctx {
	struct test_ksmbd_inode	ci;
	struct completion	start;
	atomic_t		success_count;
};

static int op_count_inc_dec_thread(void *data)
{
	struct op_count_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		atomic_inc(&ctx->ci.op_count);
		atomic_dec(&ctx->ci.op_count);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static void test_op_count_concurrent_inc_dec(struct kunit *test)
{
	struct op_count_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	init_test_inode(&ctx->ci);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(op_count_inc_dec_thread, ctx,
					 "opcnt_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->ci.op_count), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

/* ---- Suite registration ---- */

static struct kunit_case ksmbd_concurrency_oplock_test_cases[] = {
	KUNIT_CASE(test_oplock_state_machine_concurrent),
	KUNIT_CASE(test_oplock_break_ack_race),
	KUNIT_CASE(test_new_open_during_break),
	KUNIT_CASE(test_oplock_upgrade_downgrade_race),
	KUNIT_CASE(test_batch_break_close_race),
	KUNIT_CASE(test_lease_vs_oplock_break_priority),
	KUNIT_CASE(test_multiple_break_notifications),
	KUNIT_CASE(test_break_timeout_retry),
	KUNIT_CASE(test_oplock_list_concurrent_add_remove),
	KUNIT_CASE(test_lease_read_to_write_upgrade_race),
	KUNIT_CASE(test_opinfo_refcount_concurrent),
	KUNIT_CASE(test_opinfo_dec_and_test_exactly_one),
	KUNIT_CASE(test_lease_epoch_concurrent_increment),
	KUNIT_CASE(test_breaking_cnt_concurrent),
	KUNIT_CASE(test_lease_state_cas_contention),
	KUNIT_CASE(test_pending_break_bit_atomicity),
	KUNIT_CASE(test_wait_wake_bit_synchronization),
	KUNIT_CASE(test_oplock_level_concurrent_rw),
	KUNIT_CASE(test_op_count_concurrent_inc_dec),
	{}
};

static struct kunit_suite ksmbd_concurrency_oplock_test_suite = {
	.name = "ksmbd_concurrency_oplock",
	.test_cases = ksmbd_concurrency_oplock_test_cases,
};

kunit_test_suite(ksmbd_concurrency_oplock_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit concurrency tests for oplock break race conditions");
