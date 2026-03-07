// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit concurrency tests for hash table concurrent access.
 *   Uses kthreads for parallel insert/lookup/delete operations.
 */

#include <kunit/test.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define HASH_BITS_TEST	8
#define NUM_THREADS	4
#define ITERATIONS	200

struct hash_entry {
	u32 key;
	u32 value;
	struct hlist_node node;
};

struct hash_test_ctx {
	DECLARE_HASHTABLE(table, HASH_BITS_TEST);
	spinlock_t lock;
	struct completion start;
	atomic_t success_count;
	atomic_t failure_count;
	struct hash_entry *entries;
	int num_entries;
};

static void init_hash_ctx(struct hash_test_ctx *ctx)
{
	hash_init(ctx->table);
	spin_lock_init(&ctx->lock);
	init_completion(&ctx->start);
	atomic_set(&ctx->success_count, 0);
	atomic_set(&ctx->failure_count, 0);
}

/* ---- Thread functions ---- */

static int insert_thread(void *data)
{
	struct hash_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		struct hash_entry *e = &ctx->entries[i];

		spin_lock(&ctx->lock);
		hash_add(ctx->table, &e->node, e->key);
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int lookup_thread(void *data)
{
	struct hash_test_ctx *ctx = data;
	int i;
	struct hash_entry *e;
	bool found;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		u32 key = i;

		found = false;
		spin_lock(&ctx->lock);
		hash_for_each_possible(ctx->table, e, node, key) {
			if (e->key == key) {
				found = true;
				break;
			}
		}
		spin_unlock(&ctx->lock);
		/* Not finding is OK since inserts are concurrent */
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int delete_thread(void *data)
{
	struct hash_test_ctx *ctx = data;
	int i;
	struct hash_entry *e;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		u32 key = i;

		spin_lock(&ctx->lock);
		hash_for_each_possible(ctx->table, e, node, key) {
			if (e->key == key) {
				hash_del(&e->node);
				break;
			}
		}
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

static int insert_delete_thread(void *data)
{
	struct hash_test_ctx *ctx = data;
	int i;

	wait_for_completion(&ctx->start);

	for (i = 0; i < ITERATIONS; i++) {
		struct hash_entry *e = &ctx->entries[i];

		spin_lock(&ctx->lock);
		hash_add(ctx->table, &e->node, e->key);
		spin_unlock(&ctx->lock);

		spin_lock(&ctx->lock);
		hash_del(&e->node);
		spin_unlock(&ctx->lock);
	}

	atomic_inc(&ctx->success_count);
	return 0;
}

/* ---- Tests ---- */

static void test_hash_parallel_insert(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i, j;
	int total = ITERATIONS * NUM_THREADS;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	ctx->entries = kunit_kzalloc(test,
		sizeof(struct hash_entry) * total, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->entries);

	for (i = 0; i < NUM_THREADS; i++) {
		/* Each thread gets its own range of entries */
		struct hash_test_ctx *tctx;

		tctx = kunit_kzalloc(test, sizeof(*tctx), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, tctx);
		memcpy(tctx, ctx, sizeof(*ctx));
		tctx->entries = &ctx->entries[i * ITERATIONS];

		for (j = 0; j < ITERATIONS; j++) {
			tctx->entries[j].key = i * ITERATIONS + j;
			tctx->entries[j].value = i * ITERATIONS + j;
		}

		threads[i] = kthread_run(insert_thread, tctx,
					 "ins_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	/* All threads should complete */
	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

static void test_hash_parallel_lookup(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	/* Pre-populate hash table */
	ctx->entries = kunit_kzalloc(test,
		sizeof(struct hash_entry) * ITERATIONS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->entries);

	for (i = 0; i < ITERATIONS; i++) {
		ctx->entries[i].key = i;
		ctx->entries[i].value = i * 10;
		hash_add(ctx->table, &ctx->entries[i].node, i);
	}

	for (i = 0; i < NUM_THREADS; i++) {
		threads[i] = kthread_run(lookup_thread, ctx,
					 "lkup_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

static void test_hash_parallel_insert_delete(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct task_struct *threads[NUM_THREADS];
	int i, j;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	for (i = 0; i < NUM_THREADS; i++) {
		struct hash_test_ctx *tctx;

		tctx = kunit_kzalloc(test, sizeof(*tctx), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, tctx);
		memcpy(tctx, ctx, sizeof(*ctx));

		tctx->entries = kunit_kzalloc(test,
			sizeof(struct hash_entry) * ITERATIONS, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, tctx->entries);

		for (j = 0; j < ITERATIONS; j++) {
			tctx->entries[j].key = i * ITERATIONS + j;
			tctx->entries[j].value = j;
		}

		threads[i] = kthread_run(insert_delete_thread, tctx,
					 "insdel_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(threads[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), NUM_THREADS);
}

static void test_hash_insert_lookup_race(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct task_struct *inserter;
	struct task_struct *lookers[3];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	ctx->entries = kunit_kzalloc(test,
		sizeof(struct hash_entry) * ITERATIONS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->entries);

	for (i = 0; i < ITERATIONS; i++) {
		ctx->entries[i].key = i;
		ctx->entries[i].value = i;
	}

	inserter = kthread_run(insert_thread, ctx, "ins");
	KUNIT_ASSERT_FALSE(test, IS_ERR(inserter));

	for (i = 0; i < 3; i++) {
		lookers[i] = kthread_run(lookup_thread, ctx,
					 "look_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(lookers[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
}

static void test_hash_insert_delete_lookup_race(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct task_struct *inserter;
	struct task_struct *deleter;
	struct task_struct *lookers[2];
	int i;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	ctx->entries = kunit_kzalloc(test,
		sizeof(struct hash_entry) * ITERATIONS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->entries);

	for (i = 0; i < ITERATIONS; i++) {
		ctx->entries[i].key = i;
		ctx->entries[i].value = i;
	}

	inserter = kthread_run(insert_thread, ctx, "ins");
	KUNIT_ASSERT_FALSE(test, IS_ERR(inserter));

	deleter = kthread_run(delete_thread, ctx, "del");
	KUNIT_ASSERT_FALSE(test, IS_ERR(deleter));

	for (i = 0; i < 2; i++) {
		lookers[i] = kthread_run(lookup_thread, ctx,
					 "look_%d", i);
		KUNIT_ASSERT_FALSE(test, IS_ERR(lookers[i]));
	}

	complete_all(&ctx->start);
	msleep(200);

	KUNIT_EXPECT_EQ(test, atomic_read(&ctx->success_count), 4);
}

/* ---- Test: Empty hash table iteration ---- */

static void test_hash_empty_iteration(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct hash_entry *e;
	int bkt;
	int count = 0;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	hash_for_each(ctx->table, bkt, e, node)
		count++;

	KUNIT_EXPECT_EQ(test, count, 0);
}

/* ---- Test: Single entry operations ---- */

static void test_hash_single_insert_lookup_delete(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct hash_entry entry = { .key = 42, .value = 100 };
	struct hash_entry *found;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	hash_add(ctx->table, &entry.node, entry.key);

	found = NULL;
	hash_for_each_possible(ctx->table, found, node, 42) {
		if (found->key == 42)
			break;
	}
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, found->value, (u32)100);

	hash_del(&entry.node);

	found = NULL;
	hash_for_each_possible(ctx->table, found, node, 42) {
		if (found->key == 42)
			break;
		found = NULL;
	}
	KUNIT_EXPECT_NULL(test, found);
}

/* ---- Test: Hash collision handling ---- */

static void test_hash_collision_handling(struct kunit *test)
{
	struct hash_test_ctx *ctx;
	struct hash_entry e1 = { .key = 0, .value = 1 };
	struct hash_entry e2 = { .key = (1 << HASH_BITS_TEST), .value = 2 };
	struct hash_entry *found;
	int count = 0;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	init_hash_ctx(ctx);

	/* These keys should hash to the same bucket */
	hash_add(ctx->table, &e1.node, e1.key);
	hash_add(ctx->table, &e2.node, e2.key);

	hash_for_each_possible(ctx->table, found, node, 0)
		count++;

	/* At least one entry should be in this bucket */
	KUNIT_EXPECT_GE(test, count, 1);

	hash_del(&e1.node);
	hash_del(&e2.node);
}

static struct kunit_case ksmbd_concurrency_hash_test_cases[] = {
	KUNIT_CASE(test_hash_parallel_insert),
	KUNIT_CASE(test_hash_parallel_lookup),
	KUNIT_CASE(test_hash_parallel_insert_delete),
	KUNIT_CASE(test_hash_insert_lookup_race),
	KUNIT_CASE(test_hash_insert_delete_lookup_race),
	KUNIT_CASE(test_hash_empty_iteration),
	KUNIT_CASE(test_hash_single_insert_lookup_delete),
	KUNIT_CASE(test_hash_collision_handling),
	{}
};

static struct kunit_suite ksmbd_concurrency_hash_test_suite = {
	.name = "ksmbd_concurrency_hash",
	.test_cases = ksmbd_concurrency_hash_test_cases,
};

kunit_test_suite(ksmbd_concurrency_hash_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit concurrency tests for hash table operations");
