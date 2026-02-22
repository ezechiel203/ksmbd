// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd info-level dispatch table (ksmbd_info.c)
 *
 *   Since KUnit tests cannot link against the ksmbd module directly,
 *   we replicate the pure-logic portions (hash key computation, handler
 *   table structures, register/unregister/lookup lifecycle) inline.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/* ── Replicated structures and logic from ksmbd_info.h / ksmbd_info.c ─── */

enum test_info_op {
	TEST_INFO_GET,
	TEST_INFO_SET,
};

struct test_info_handler {
	u8 info_type;
	u8 info_class;
	enum test_info_op op;
	int (*handler)(void *buf, unsigned int buf_len,
		       unsigned int *out_len);
	struct hlist_node node;
};

#define TEST_INFO_HASH_BITS	8
static DEFINE_HASHTABLE(test_info_handlers, TEST_INFO_HASH_BITS);
static DEFINE_SPINLOCK(test_info_lock);

/**
 * test_info_hash_key() - Replicate info_hash_key() from ksmbd_info.c
 */
static inline u32 test_info_hash_key(u8 info_type, u8 info_class,
				     enum test_info_op op)
{
	return (u32)info_type << 16 | (u32)info_class << 8 | (u32)op;
}

static int test_register_info_handler(struct test_info_handler *h)
{
	struct test_info_handler *cur;
	u32 key = test_info_hash_key(h->info_type, h->info_class, h->op);

	spin_lock(&test_info_lock);
	hash_for_each_possible(test_info_handlers, cur, node, key) {
		if (cur->info_type == h->info_type &&
		    cur->info_class == h->info_class &&
		    cur->op == h->op) {
			spin_unlock(&test_info_lock);
			return -EEXIST;
		}
	}
	hash_add(test_info_handlers, &h->node, key);
	spin_unlock(&test_info_lock);
	return 0;
}

static void test_unregister_info_handler(struct test_info_handler *h)
{
	spin_lock(&test_info_lock);
	hash_del(&h->node);
	spin_unlock(&test_info_lock);
}

static struct test_info_handler *test_lookup_info_handler(u8 info_type,
							  u8 info_class,
							  enum test_info_op op)
{
	struct test_info_handler *h;
	u32 key = test_info_hash_key(info_type, info_class, op);

	hash_for_each_possible(test_info_handlers, h, node, key) {
		if (h->info_type == info_type &&
		    h->info_class == info_class &&
		    h->op == op)
			return h;
	}
	return NULL;
}

/* Simple test handler callback */
static int dummy_handler(void *buf, unsigned int buf_len,
			 unsigned int *out_len)
{
	*out_len = 42;
	return 0;
}

/* ── Suite init/exit: reinitialize hash table each run ─── */

static int info_dispatch_suite_init(struct kunit_suite *suite)
{
	hash_init(test_info_handlers);
	return 0;
}

/* ── Test: hash key produces unique keys for different inputs ─── */

static void test_hash_key_unique_all_different(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 2, TEST_INFO_GET);
	u32 k2 = test_info_hash_key(3, 4, TEST_INFO_SET);

	KUNIT_EXPECT_NE(test, k1, k2);
}

static void test_hash_key_same_type_class_diff_op(struct kunit *test)
{
	u32 k_get = test_info_hash_key(1, 5, TEST_INFO_GET);
	u32 k_set = test_info_hash_key(1, 5, TEST_INFO_SET);

	KUNIT_EXPECT_NE(test, k_get, k_set);
}

static void test_hash_key_same_type_diff_class(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 5, TEST_INFO_GET);
	u32 k2 = test_info_hash_key(1, 6, TEST_INFO_GET);

	KUNIT_EXPECT_NE(test, k1, k2);
}

static void test_hash_key_diff_type_same_class(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 5, TEST_INFO_GET);
	u32 k2 = test_info_hash_key(2, 5, TEST_INFO_GET);

	KUNIT_EXPECT_NE(test, k1, k2);
}

static void test_hash_key_identical_inputs(struct kunit *test)
{
	u32 k1 = test_info_hash_key(1, 5, TEST_INFO_GET);
	u32 k2 = test_info_hash_key(1, 5, TEST_INFO_GET);

	KUNIT_EXPECT_EQ(test, k1, k2);
}

static void test_hash_key_boundary_values(struct kunit *test)
{
	u32 k1 = test_info_hash_key(0, 0, TEST_INFO_GET);
	u32 k2 = test_info_hash_key(255, 255, TEST_INFO_SET);

	/* Both should be valid and distinct */
	KUNIT_EXPECT_NE(test, k1, k2);
	/* key for (0,0,GET) should be 0x00000000 */
	KUNIT_EXPECT_EQ(test, k1, (u32)0);
	/* key for (255,255,SET) should be 0x00FFFF01 */
	KUNIT_EXPECT_EQ(test, k2, (u32)(255U << 16 | 255U << 8 | 1U));
}

/* ── Test: register/lookup lifecycle ─── */

static void test_register_and_lookup(struct kunit *test)
{
	struct test_info_handler h = {
		.info_type = 1,
		.info_class = 9,
		.op = TEST_INFO_GET,
		.handler = dummy_handler,
	};
	struct test_info_handler *found;
	int ret;

	hash_init(test_info_handlers);

	ret = test_register_info_handler(&h);
	KUNIT_ASSERT_EQ(test, ret, 0);

	found = test_lookup_info_handler(1, 9, TEST_INFO_GET);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_PTR_EQ(test, found, &h);

	test_unregister_info_handler(&h);
}

static void test_lookup_not_found(struct kunit *test)
{
	struct test_info_handler *found;

	hash_init(test_info_handlers);

	found = test_lookup_info_handler(99, 99, TEST_INFO_SET);
	KUNIT_EXPECT_NULL(test, found);
}

static void test_register_unregister_lookup_gone(struct kunit *test)
{
	struct test_info_handler h = {
		.info_type = 2,
		.info_class = 10,
		.op = TEST_INFO_SET,
		.handler = dummy_handler,
	};
	struct test_info_handler *found;
	int ret;

	hash_init(test_info_handlers);

	ret = test_register_info_handler(&h);
	KUNIT_ASSERT_EQ(test, ret, 0);

	test_unregister_info_handler(&h);

	found = test_lookup_info_handler(2, 10, TEST_INFO_SET);
	KUNIT_EXPECT_NULL(test, found);
}

/* ── Test: duplicate registration returns -EEXIST ─── */

static void test_duplicate_registration(struct kunit *test)
{
	struct test_info_handler h1 = {
		.info_type = 5,
		.info_class = 20,
		.op = TEST_INFO_GET,
		.handler = dummy_handler,
	};
	struct test_info_handler h2 = {
		.info_type = 5,
		.info_class = 20,
		.op = TEST_INFO_GET,
		.handler = dummy_handler,
	};
	int ret;

	hash_init(test_info_handlers);

	ret = test_register_info_handler(&h1);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = test_register_info_handler(&h2);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);

	test_unregister_info_handler(&h1);
}

/* ── Test: multiple handlers with different keys coexist ─── */

static void test_multiple_handlers_coexist(struct kunit *test)
{
	struct test_info_handler h1 = {
		.info_type = 1, .info_class = 1, .op = TEST_INFO_GET,
		.handler = dummy_handler,
	};
	struct test_info_handler h2 = {
		.info_type = 1, .info_class = 2, .op = TEST_INFO_GET,
		.handler = dummy_handler,
	};
	struct test_info_handler h3 = {
		.info_type = 2, .info_class = 1, .op = TEST_INFO_SET,
		.handler = dummy_handler,
	};
	struct test_info_handler *found;

	hash_init(test_info_handlers);

	KUNIT_ASSERT_EQ(test, test_register_info_handler(&h1), 0);
	KUNIT_ASSERT_EQ(test, test_register_info_handler(&h2), 0);
	KUNIT_ASSERT_EQ(test, test_register_info_handler(&h3), 0);

	found = test_lookup_info_handler(1, 1, TEST_INFO_GET);
	KUNIT_EXPECT_PTR_EQ(test, found, &h1);

	found = test_lookup_info_handler(1, 2, TEST_INFO_GET);
	KUNIT_EXPECT_PTR_EQ(test, found, &h2);

	found = test_lookup_info_handler(2, 1, TEST_INFO_SET);
	KUNIT_EXPECT_PTR_EQ(test, found, &h3);

	test_unregister_info_handler(&h1);
	test_unregister_info_handler(&h2);
	test_unregister_info_handler(&h3);
}

/* ── Test: handler callback invocation ─── */

static void test_handler_invocation(struct kunit *test)
{
	struct test_info_handler h = {
		.info_type = 1,
		.info_class = 9,
		.op = TEST_INFO_GET,
		.handler = dummy_handler,
	};
	struct test_info_handler *found;
	unsigned int out_len = 0;
	int ret;

	hash_init(test_info_handlers);

	KUNIT_ASSERT_EQ(test, test_register_info_handler(&h), 0);

	found = test_lookup_info_handler(1, 9, TEST_INFO_GET);
	KUNIT_ASSERT_NOT_NULL(test, found);

	ret = found->handler(NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, 42U);

	test_unregister_info_handler(&h);
}

static struct kunit_case ksmbd_info_dispatch_test_cases[] = {
	KUNIT_CASE(test_hash_key_unique_all_different),
	KUNIT_CASE(test_hash_key_same_type_class_diff_op),
	KUNIT_CASE(test_hash_key_same_type_diff_class),
	KUNIT_CASE(test_hash_key_diff_type_same_class),
	KUNIT_CASE(test_hash_key_identical_inputs),
	KUNIT_CASE(test_hash_key_boundary_values),
	KUNIT_CASE(test_register_and_lookup),
	KUNIT_CASE(test_lookup_not_found),
	KUNIT_CASE(test_register_unregister_lookup_gone),
	KUNIT_CASE(test_duplicate_registration),
	KUNIT_CASE(test_multiple_handlers_coexist),
	KUNIT_CASE(test_handler_invocation),
	{}
};

static struct kunit_suite ksmbd_info_dispatch_test_suite = {
	.name = "ksmbd_info_dispatch",
	.suite_init = info_dispatch_suite_init,
	.test_cases = ksmbd_info_dispatch_test_cases,
};

kunit_test_suite(ksmbd_info_dispatch_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd info-level dispatch table");
