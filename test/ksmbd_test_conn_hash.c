// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for connection hash table operations (connection.c)
 *
 *   These tests replicate the hash table logic from connection.c
 *   without calling into the ksmbd module directly.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/hash.h>

/* Replicate the connection hash constants from connection.h */
#define TEST_CONN_HASH_BITS	8
#define TEST_CONN_HASH_SIZE	(1 << TEST_CONN_HASH_BITS)

struct test_conn_hash_bucket {
	struct hlist_head	head;
	spinlock_t		lock;
};

struct test_conn_entry {
	unsigned int		inet_hash;
	struct hlist_node	hlist;
};

struct conn_hash_test_ctx {
	struct test_conn_hash_bucket	hash[TEST_CONN_HASH_SIZE];
};

/* Replicate ksmbd_conn_hash_init() */
static void test_hash_init(struct test_conn_hash_bucket *hash)
{
	int i;

	for (i = 0; i < TEST_CONN_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&hash[i].head);
		spin_lock_init(&hash[i].lock);
	}
}

/* Replicate ksmbd_conn_hash_add() */
static void test_hash_add(struct test_conn_hash_bucket *hash,
			   struct test_conn_entry *entry, unsigned int key)
{
	unsigned int bkt = hash_min(key, TEST_CONN_HASH_BITS);

	spin_lock(&hash[bkt].lock);
	hlist_add_head(&entry->hlist, &hash[bkt].head);
	spin_unlock(&hash[bkt].lock);
}

/* Replicate ksmbd_conn_hash_del() */
static void test_hash_del(struct test_conn_hash_bucket *hash,
			   struct test_conn_entry *entry)
{
	unsigned int bkt = hash_min(entry->inet_hash, TEST_CONN_HASH_BITS);

	spin_lock(&hash[bkt].lock);
	hlist_del_init(&entry->hlist);
	spin_unlock(&hash[bkt].lock);
}

/* Replicate ksmbd_conn_hash_empty() */
static bool test_hash_empty(struct test_conn_hash_bucket *hash)
{
	int i;

	for (i = 0; i < TEST_CONN_HASH_SIZE; i++) {
		spin_lock(&hash[i].lock);
		if (!hlist_empty(&hash[i].head)) {
			spin_unlock(&hash[i].lock);
			return false;
		}
		spin_unlock(&hash[i].lock);
	}
	return true;
}

static int conn_hash_test_init(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	test_hash_init(ctx->hash);
	test->priv = ctx;
	return 0;
}

static void conn_hash_test_exit(struct kunit *test)
{
	kfree(test->priv);
}

/*
 * test_hash_init_all_empty - after init, all buckets should be empty
 */
static void test_hash_init_all_empty(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	int i;

	for (i = 0; i < TEST_CONN_HASH_SIZE; i++)
		KUNIT_EXPECT_TRUE(test, hlist_empty(&ctx->hash[i].head));

	KUNIT_EXPECT_TRUE(test, test_hash_empty(ctx->hash));
}

/*
 * test_hash_add_makes_nonempty - adding one entry makes hash non-empty
 */
static void test_hash_add_makes_nonempty(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	struct test_conn_entry entry = { .inet_hash = 42 };

	INIT_HLIST_NODE(&entry.hlist);
	test_hash_add(ctx->hash, &entry, 42);

	KUNIT_EXPECT_FALSE(test, test_hash_empty(ctx->hash));

	test_hash_del(ctx->hash, &entry);
}

/*
 * test_hash_add_del_restores_empty - add then delete returns to empty
 */
static void test_hash_add_del_restores_empty(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	struct test_conn_entry entry = { .inet_hash = 100 };

	INIT_HLIST_NODE(&entry.hlist);
	test_hash_add(ctx->hash, &entry, 100);
	KUNIT_EXPECT_FALSE(test, test_hash_empty(ctx->hash));

	test_hash_del(ctx->hash, &entry);
	KUNIT_EXPECT_TRUE(test, test_hash_empty(ctx->hash));
}

/*
 * test_hash_multiple_same_bucket - entries with same hash go to same bucket
 */
static void test_hash_multiple_same_bucket(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	struct test_conn_entry e1 = { .inet_hash = 0 };
	struct test_conn_entry e2 = { .inet_hash = 0 };
	unsigned int bkt = hash_min(0u, TEST_CONN_HASH_BITS);
	int count = 0;
	struct test_conn_entry *cur;

	INIT_HLIST_NODE(&e1.hlist);
	INIT_HLIST_NODE(&e2.hlist);

	test_hash_add(ctx->hash, &e1, 0);
	test_hash_add(ctx->hash, &e2, 0);

	hlist_for_each_entry(cur, &ctx->hash[bkt].head, hlist)
		count++;

	KUNIT_EXPECT_EQ(test, count, 2);

	test_hash_del(ctx->hash, &e1);
	test_hash_del(ctx->hash, &e2);
}

/*
 * test_hash_multiple_different_buckets - different keys go to different buckets
 */
static void test_hash_multiple_different_buckets(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	/* Choose keys likely to hash to different buckets */
	struct test_conn_entry e1 = { .inet_hash = 1 };
	struct test_conn_entry e2 = { .inet_hash = 0x10000 };
	unsigned int bkt1 = hash_min(1u, TEST_CONN_HASH_BITS);
	unsigned int bkt2 = hash_min(0x10000u, TEST_CONN_HASH_BITS);

	INIT_HLIST_NODE(&e1.hlist);
	INIT_HLIST_NODE(&e2.hlist);

	/* Only run meaningful test if they hash to different buckets */
	if (bkt1 == bkt2) {
		kunit_skip(test, "chosen keys hash to same bucket");
		return;
	}

	test_hash_add(ctx->hash, &e1, 1);
	test_hash_add(ctx->hash, &e2, 0x10000);

	KUNIT_EXPECT_FALSE(test, hlist_empty(&ctx->hash[bkt1].head));
	KUNIT_EXPECT_FALSE(test, hlist_empty(&ctx->hash[bkt2].head));

	test_hash_del(ctx->hash, &e1);
	test_hash_del(ctx->hash, &e2);
}

/*
 * test_hash_del_from_empty_bucket - deleting from empty bucket is safe
 *
 * hlist_del_init on an already-initialized-but-not-added node is a no-op.
 */
static void test_hash_del_from_empty_bucket(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	struct test_conn_entry entry = { .inet_hash = 77 };

	INIT_HLIST_NODE(&entry.hlist);

	/* Entry was never added, so deleting should be safe */
	test_hash_del(ctx->hash, &entry);

	KUNIT_EXPECT_TRUE(test, test_hash_empty(ctx->hash));
}

/*
 * test_hash_del_twice_safe - double delete is safe with hlist_del_init
 */
static void test_hash_del_twice_safe(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	struct test_conn_entry entry = { .inet_hash = 99 };

	INIT_HLIST_NODE(&entry.hlist);
	test_hash_add(ctx->hash, &entry, 99);
	test_hash_del(ctx->hash, &entry);
	/* Second delete should be safe because hlist_del_init re-inits */
	test_hash_del(ctx->hash, &entry);

	KUNIT_EXPECT_TRUE(test, test_hash_empty(ctx->hash));
}

/*
 * test_hash_bucket_index_range - bucket index is always in valid range
 */
static void test_hash_bucket_index_range(struct kunit *test)
{
	unsigned int keys[] = { 0, 1, 255, 256, 1000, 0xFFFFFFFF };
	int i;

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		unsigned int bkt = hash_min(keys[i], TEST_CONN_HASH_BITS);

		KUNIT_EXPECT_LT(test, bkt, (unsigned int)TEST_CONN_HASH_SIZE);
	}
}

/*
 * test_hash_size_is_power_of_two - CONN_HASH_SIZE must be power of 2
 */
static void test_hash_size_is_power_of_two(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, is_power_of_2(TEST_CONN_HASH_SIZE));
	KUNIT_EXPECT_EQ(test, TEST_CONN_HASH_SIZE, 256);
}

/*
 * test_hash_add_many_entries - add many entries and verify all present
 */
static void test_hash_add_many_entries(struct kunit *test)
{
	struct conn_hash_test_ctx *ctx = test->priv;
	struct test_conn_entry *entries;
	int n = 16;
	int i;

	entries = kcalloc(n, sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	for (i = 0; i < n; i++) {
		entries[i].inet_hash = i * 37; /* spread across buckets */
		INIT_HLIST_NODE(&entries[i].hlist);
		test_hash_add(ctx->hash, &entries[i], entries[i].inet_hash);
	}

	KUNIT_EXPECT_FALSE(test, test_hash_empty(ctx->hash));

	/* Remove all */
	for (i = 0; i < n; i++)
		test_hash_del(ctx->hash, &entries[i]);

	KUNIT_EXPECT_TRUE(test, test_hash_empty(ctx->hash));

	kfree(entries);
}

static struct kunit_case ksmbd_conn_hash_test_cases[] = {
	KUNIT_CASE(test_hash_init_all_empty),
	KUNIT_CASE(test_hash_add_makes_nonempty),
	KUNIT_CASE(test_hash_add_del_restores_empty),
	KUNIT_CASE(test_hash_multiple_same_bucket),
	KUNIT_CASE(test_hash_multiple_different_buckets),
	KUNIT_CASE(test_hash_del_from_empty_bucket),
	KUNIT_CASE(test_hash_del_twice_safe),
	KUNIT_CASE(test_hash_bucket_index_range),
	KUNIT_CASE(test_hash_size_is_power_of_two),
	KUNIT_CASE(test_hash_add_many_entries),
	{}
};

static struct kunit_suite ksmbd_conn_hash_test_suite = {
	.name = "ksmbd_conn_hash",
	.init = conn_hash_test_init,
	.exit = conn_hash_test_exit,
	.test_cases = ksmbd_conn_hash_test_cases,
};

kunit_test_suite(ksmbd_conn_hash_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd connection hash table operations");
