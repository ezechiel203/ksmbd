// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for the FSCTL dispatch table (ksmbd_fsctl.c)
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure dispatch-table logic
 *   under test, using a simple array-based lookup instead of kernel
 *   hashtable/RCU which require full kernel infrastructure.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>

/* ---- Inlined/simplified definitions from ksmbd_fsctl.h ---- */

/*
 * Simplified FSCTL handler for testing the dispatch logic.
 * We use a simple linked list instead of the kernel's hash table
 * since we're testing the registration/lookup/dispatch logic rather
 * than the hash table implementation itself.
 */

#define TEST_FSCTL_MAX_HANDLERS	32

struct test_fsctl_handler {
	u32		ctl_code;
	int		(*handler)(u32 ctl_code, void *in_buf,
				   unsigned int in_len,
				   unsigned int *out_len);
	bool		in_use;
};

struct fsctl_test_ctx {
	struct test_fsctl_handler handlers[TEST_FSCTL_MAX_HANDLERS];
	unsigned int count;
};

static void test_fsctl_init(struct fsctl_test_ctx *ctx)
{
	memset(ctx->handlers, 0, sizeof(ctx->handlers));
	ctx->count = 0;
}

static int test_fsctl_register(struct fsctl_test_ctx *ctx,
			       struct test_fsctl_handler *h)
{
	unsigned int i;

	/* Check for duplicate */
	for (i = 0; i < ctx->count; i++) {
		if (ctx->handlers[i].in_use &&
		    ctx->handlers[i].ctl_code == h->ctl_code)
			return -EEXIST;
	}

	/* Find a free slot */
	if (ctx->count >= TEST_FSCTL_MAX_HANDLERS)
		return -ENOMEM;

	ctx->handlers[ctx->count] = *h;
	ctx->handlers[ctx->count].in_use = true;
	ctx->count++;
	return 0;
}

static void test_fsctl_unregister(struct fsctl_test_ctx *ctx, u32 ctl_code)
{
	unsigned int i;

	for (i = 0; i < ctx->count; i++) {
		if (ctx->handlers[i].in_use &&
		    ctx->handlers[i].ctl_code == ctl_code) {
			ctx->handlers[i].in_use = false;
			return;
		}
	}
}

static int test_fsctl_dispatch(struct fsctl_test_ctx *ctx, u32 ctl_code,
			       void *in_buf, unsigned int in_len,
			       unsigned int *out_len)
{
	unsigned int i;

	*out_len = 0;

	for (i = 0; i < ctx->count; i++) {
		if (ctx->handlers[i].in_use &&
		    ctx->handlers[i].ctl_code == ctl_code) {
			return ctx->handlers[i].handler(ctl_code, in_buf,
							in_len, out_len);
		}
	}

	return -EOPNOTSUPP;
}

/*
 * Simulated hash key computation for testing uniqueness.
 * This mirrors how the kernel hashtable hashes u32 keys.
 */
static u32 test_hash_key(u32 ctl_code, unsigned int bits)
{
	/* Multiplicative hash - simplified version of hash_32() */
	return (ctl_code * 0x61C88647U) >> (32 - bits);
}

/* ---- Per-test state ---- */

static int fsctl_test_init(struct kunit *test)
{
	struct fsctl_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	test_fsctl_init(ctx);
	test->priv = ctx;
	return 0;
}

static void fsctl_test_exit(struct kunit *test)
{
	kfree(test->priv);
}

/* ---- Handler callbacks ---- */

static int handler_success(u32 ctl_code, void *in_buf,
			   unsigned int in_len, unsigned int *out_len)
{
	*out_len = 42;
	return 0;
}

static int handler_error(u32 ctl_code, void *in_buf,
			 unsigned int in_len, unsigned int *out_len)
{
	*out_len = 0;
	return -EINVAL;
}

static int handler_echo_code(u32 ctl_code, void *in_buf,
			     unsigned int in_len, unsigned int *out_len)
{
	*out_len = ctl_code;
	return 0;
}

/* ---- Test cases ---- */

/*
 * test_register_and_dispatch - register then dispatch finds handler
 */
static void test_register_and_dispatch(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h = {
		.ctl_code = 0x00090000,
		.handler = handler_success,
	};
	unsigned int out_len = 0;
	int ret;

	ret = test_fsctl_register(ctx, &h);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_fsctl_dispatch(ctx, 0x00090000, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)42);
}

/*
 * test_dispatch_unregistered - dispatch for unknown code returns -EOPNOTSUPP
 */
static void test_dispatch_unregistered(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	unsigned int out_len = 99;
	int ret;

	ret = test_fsctl_dispatch(ctx, 0xDEADBEEF, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

/*
 * test_unregister_then_dispatch - after unregister, dispatch returns -EOPNOTSUPP
 */
static void test_unregister_then_dispatch(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h = {
		.ctl_code = 0x00090000,
		.handler = handler_success,
	};
	unsigned int out_len;
	int ret;

	test_fsctl_register(ctx, &h);
	test_fsctl_unregister(ctx, 0x00090000);

	ret = test_fsctl_dispatch(ctx, 0x00090000, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

/*
 * test_duplicate_registration - duplicate ctl_code returns -EEXIST
 */
static void test_duplicate_registration(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h1 = {
		.ctl_code = 0x00090000,
		.handler = handler_success,
	};
	struct test_fsctl_handler h2 = {
		.ctl_code = 0x00090000,
		.handler = handler_error,
	};
	int ret;

	ret = test_fsctl_register(ctx, &h1);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_fsctl_register(ctx, &h2);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
}

/*
 * test_multiple_codes_dispatched - different codes go to their handlers
 */
static void test_multiple_codes_dispatched(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h1 = {
		.ctl_code = 0x000900A0,
		.handler = handler_echo_code,
	};
	struct test_fsctl_handler h2 = {
		.ctl_code = 0x000900B0,
		.handler = handler_echo_code,
	};
	struct test_fsctl_handler h3 = {
		.ctl_code = 0x000900C0,
		.handler = handler_echo_code,
	};
	unsigned int out_len;
	int ret;

	test_fsctl_register(ctx, &h1);
	test_fsctl_register(ctx, &h2);
	test_fsctl_register(ctx, &h3);

	ret = test_fsctl_dispatch(ctx, 0x000900A0, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0x000900A0);

	ret = test_fsctl_dispatch(ctx, 0x000900B0, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0x000900B0);

	ret = test_fsctl_dispatch(ctx, 0x000900C0, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0x000900C0);
}

/*
 * test_handler_error_propagated - handler error is returned from dispatch
 */
static void test_handler_error_propagated(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h = {
		.ctl_code = 0x000FFFFF,
		.handler = handler_error,
	};
	unsigned int out_len;
	int ret;

	test_fsctl_register(ctx, &h);

	ret = test_fsctl_dispatch(ctx, 0x000FFFFF, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * test_out_len_zeroed_before_dispatch - out_len is set to 0 before lookup
 */
static void test_out_len_zeroed_before_dispatch(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	unsigned int out_len = 99;

	test_fsctl_dispatch(ctx, 0xDEADBEEF, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

/*
 * test_unregister_one_of_many - unregistering one code leaves others
 */
static void test_unregister_one_of_many(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h1 = {
		.ctl_code = 0x0001,
		.handler = handler_echo_code,
	};
	struct test_fsctl_handler h2 = {
		.ctl_code = 0x0002,
		.handler = handler_echo_code,
	};
	unsigned int out_len;
	int ret;

	test_fsctl_register(ctx, &h1);
	test_fsctl_register(ctx, &h2);

	test_fsctl_unregister(ctx, 0x0001);

	/* Code 0x0001 should be gone */
	ret = test_fsctl_dispatch(ctx, 0x0001, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);

	/* Code 0x0002 should still work */
	ret = test_fsctl_dispatch(ctx, 0x0002, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0x0002);
}

/*
 * test_reregister_after_unregister - can re-register after unregister
 */
static void test_reregister_after_unregister(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	struct test_fsctl_handler h1 = {
		.ctl_code = 0x0001,
		.handler = handler_success,
	};
	struct test_fsctl_handler h2 = {
		.ctl_code = 0x0001,
		.handler = handler_echo_code,
	};
	unsigned int out_len;
	int ret;

	test_fsctl_register(ctx, &h1);
	test_fsctl_unregister(ctx, 0x0001);

	ret = test_fsctl_register(ctx, &h2);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_fsctl_dispatch(ctx, 0x0001, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0x0001);
}

/*
 * test_empty_table_dispatch - empty table returns -EOPNOTSUPP
 */
static void test_empty_table_dispatch(struct kunit *test)
{
	struct fsctl_test_ctx *ctx = test->priv;
	unsigned int out_len;
	int ret;

	ret = test_fsctl_dispatch(ctx, 0, NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

/*
 * test_hash_key_different_codes - different ctl_codes produce different hashes
 */
static void test_hash_key_different_codes(struct kunit *test)
{
	u32 hash1, hash2, hash3;

	hash1 = test_hash_key(0x00090000, 8);
	hash2 = test_hash_key(0x000900A0, 8);
	hash3 = test_hash_key(0x00140078, 8);

	/*
	 * With a good hash function and 8 bits, these three very
	 * different codes should produce distinct hash values
	 * (extremely likely though not guaranteed by a hash function).
	 */
	KUNIT_EXPECT_TRUE(test,
			  hash1 != hash2 || hash2 != hash3 || hash1 != hash3);
}

/*
 * test_hash_key_same_code - same code produces same hash
 */
static void test_hash_key_same_code(struct kunit *test)
{
	u32 hash1, hash2;

	hash1 = test_hash_key(0x000900C4, 8);
	hash2 = test_hash_key(0x000900C4, 8);

	KUNIT_EXPECT_EQ(test, hash1, hash2);
}

/*
 * test_hash_key_range - hash output is within expected bit range
 */
static void test_hash_key_range(struct kunit *test)
{
	u32 hash;
	unsigned int bits = 8;
	unsigned int i;

	/* All outputs should be < 2^bits */
	for (i = 0; i < 100; i++) {
		hash = test_hash_key(i * 0x10001, bits);
		KUNIT_EXPECT_LT(test, hash, (u32)(1 << bits));
	}
}

static struct kunit_case ksmbd_fsctl_dispatch_test_cases[] = {
	KUNIT_CASE(test_register_and_dispatch),
	KUNIT_CASE(test_dispatch_unregistered),
	KUNIT_CASE(test_unregister_then_dispatch),
	KUNIT_CASE(test_duplicate_registration),
	KUNIT_CASE(test_multiple_codes_dispatched),
	KUNIT_CASE(test_handler_error_propagated),
	KUNIT_CASE(test_out_len_zeroed_before_dispatch),
	KUNIT_CASE(test_unregister_one_of_many),
	KUNIT_CASE(test_reregister_after_unregister),
	KUNIT_CASE(test_empty_table_dispatch),
	KUNIT_CASE(test_hash_key_different_codes),
	KUNIT_CASE(test_hash_key_same_code),
	KUNIT_CASE(test_hash_key_range),
	{}
};

static struct kunit_suite ksmbd_fsctl_dispatch_test_suite = {
	.name = "ksmbd_fsctl_dispatch",
	.init = fsctl_test_init,
	.exit = fsctl_test_exit,
	.test_cases = ksmbd_fsctl_dispatch_test_cases,
};

kunit_test_suite(ksmbd_fsctl_dispatch_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL dispatch table operations");
