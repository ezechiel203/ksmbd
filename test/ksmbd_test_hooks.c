// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for the hook registration and dispatch system (ksmbd_hooks.c)
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure logic under test,
 *   omitting RCU, static keys, and module refcounting which are not
 *   testable in a simple KUnit context.
 */

#include <kunit/test.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>

/* ---- Inlined definitions from ksmbd_hooks.h ---- */

#define TEST_HOOK_CONTINUE	0
#define TEST_HOOK_STOP		1
#define TEST_HOOK_DROP		2

enum test_hook_point {
	TEST_HOOK_PRE_NEGOTIATE,
	TEST_HOOK_POST_NEGOTIATE,
	TEST_HOOK_PRE_SESSION_SETUP,
	TEST_HOOK_POST_SESSION_SETUP,
	TEST_HOOK_PRE_CREATE,
	TEST_HOOK_POST_CREATE,
	TEST_HOOK_AUDIT,
	__TEST_HOOK_MAX,
};

struct test_hook_handler {
	struct list_head	list;
	enum test_hook_point	point;
	int			priority;
	int			(*hook_fn)(void *work, void *priv);
	void			*priv;
};

/* ---- Simplified hook subsystem (no RCU/static key/module ref) ---- */

struct hooks_test_ctx {
	struct list_head	chains[__TEST_HOOK_MAX];
	unsigned int		count;
};

static void test_hooks_init(struct hooks_test_ctx *ctx)
{
	int i;

	for (i = 0; i < __TEST_HOOK_MAX; i++)
		INIT_LIST_HEAD(&ctx->chains[i]);
	ctx->count = 0;
}

static int test_register_hook(struct hooks_test_ctx *ctx,
			      struct test_hook_handler *handler)
{
	struct test_hook_handler *pos;
	struct list_head *head;

	if (!handler || !handler->hook_fn)
		return -EINVAL;

	if (handler->point < 0 || handler->point >= __TEST_HOOK_MAX)
		return -EINVAL;

	head = &ctx->chains[handler->point];

	/* Insert in priority order (lower value = called first) */
	list_for_each_entry(pos, head, list) {
		if (pos->priority > handler->priority) {
			list_add_tail(&handler->list, &pos->list);
			goto inserted;
		}
	}

	list_add_tail(&handler->list, head);

inserted:
	ctx->count++;
	return 0;
}

static void test_unregister_hook(struct hooks_test_ctx *ctx,
				 struct test_hook_handler *handler)
{
	if (!handler)
		return;

	list_del(&handler->list);
	if (ctx->count > 0)
		ctx->count--;
}

static int test_run_hooks(struct hooks_test_ctx *ctx,
			  enum test_hook_point point,
			  void *work)
{
	struct test_hook_handler *handler;
	int ret = TEST_HOOK_CONTINUE;

	if (point < 0 || point >= __TEST_HOOK_MAX)
		return TEST_HOOK_CONTINUE;

	list_for_each_entry(handler, &ctx->chains[point], list) {
		ret = handler->hook_fn(work, handler->priv);
		if (ret != TEST_HOOK_CONTINUE)
			break;
	}

	return ret;
}

/* ---- Per-test state ---- */

static int hooks_test_init(struct kunit *test)
{
	struct hooks_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	test_hooks_init(ctx);
	test->priv = ctx;
	return 0;
}

static void hooks_test_exit(struct kunit *test)
{
	kfree(test->priv);
}

/* ---- Hook callback helpers ---- */

static int hook_fn_continue(void *work, void *priv)
{
	int *counter = priv;

	if (counter)
		(*counter)++;
	return TEST_HOOK_CONTINUE;
}

static int hook_fn_stop(void *work, void *priv)
{
	int *counter = priv;

	if (counter)
		(*counter)++;
	return TEST_HOOK_STOP;
}

static int hook_fn_drop(void *work, void *priv)
{
	int *counter = priv;

	if (counter)
		(*counter)++;
	return TEST_HOOK_DROP;
}

/* Records call order */
struct order_ctx {
	int order[8];
	int idx;
};

static int hook_fn_record_order(void *work, void *priv)
{
	struct order_ctx *oc = work;
	int id = *(int *)priv;

	if (oc && oc->idx < 8)
		oc->order[oc->idx++] = id;
	return TEST_HOOK_CONTINUE;
}

/* ---- Test cases ---- */

/*
 * test_init_all_chains_empty - after init, all chains are empty
 */
static void test_init_all_chains_empty(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int i;

	for (i = 0; i < __TEST_HOOK_MAX; i++)
		KUNIT_EXPECT_TRUE(test, list_empty(&ctx->chains[i]));

	KUNIT_EXPECT_EQ(test, ctx->count, (unsigned int)0);
}

/*
 * test_register_adds_handler - registering adds handler to correct chain
 */
static void test_register_adds_handler(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	struct test_hook_handler h = {
		.point = TEST_HOOK_PRE_NEGOTIATE,
		.priority = 100,
		.hook_fn = hook_fn_continue,
	};

	KUNIT_EXPECT_EQ(test, test_register_hook(ctx, &h), 0);
	KUNIT_EXPECT_FALSE(test,
			   list_empty(&ctx->chains[TEST_HOOK_PRE_NEGOTIATE]));
	KUNIT_EXPECT_EQ(test, ctx->count, (unsigned int)1);
}

/*
 * test_register_null_handler - NULL handler returns -EINVAL
 */
static void test_register_null_handler(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_EQ(test, test_register_hook(ctx, NULL), -EINVAL);
}

/*
 * test_register_null_fn - handler without hook_fn returns -EINVAL
 */
static void test_register_null_fn(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	struct test_hook_handler h = {
		.point = TEST_HOOK_PRE_NEGOTIATE,
		.priority = 100,
		.hook_fn = NULL,
	};

	KUNIT_EXPECT_EQ(test, test_register_hook(ctx, &h), -EINVAL);
}

/*
 * test_register_invalid_point - invalid hook point returns -EINVAL
 */
static void test_register_invalid_point(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	struct test_hook_handler h = {
		.point = __TEST_HOOK_MAX,
		.priority = 100,
		.hook_fn = hook_fn_continue,
	};

	KUNIT_EXPECT_EQ(test, test_register_hook(ctx, &h), -EINVAL);
}

/*
 * test_dispatch_calls_handler - dispatch invokes registered handler
 */
static void test_dispatch_calls_handler(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int counter = 0;
	struct test_hook_handler h = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_continue,
		.priv = &counter,
	};

	test_register_hook(ctx, &h);

	test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, counter, 1);
}

/*
 * test_dispatch_empty_returns_continue - empty chain returns CONTINUE
 */
static void test_dispatch_empty_returns_continue(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int ret;

	ret = test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, ret, TEST_HOOK_CONTINUE);
}

/*
 * test_dispatch_invalid_point - invalid point returns CONTINUE
 */
static void test_dispatch_invalid_point(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int ret;

	ret = test_run_hooks(ctx, __TEST_HOOK_MAX, NULL);
	KUNIT_EXPECT_EQ(test, ret, TEST_HOOK_CONTINUE);
}

/*
 * test_priority_ordering - lower priority number is called first
 */
static void test_priority_ordering(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	struct order_ctx oc = { .idx = 0 };
	int id1 = 1, id2 = 2, id3 = 3;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_PRE_CREATE,
		.priority = 300,
		.hook_fn = hook_fn_record_order,
		.priv = &id3,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_PRE_CREATE,
		.priority = 100,
		.hook_fn = hook_fn_record_order,
		.priv = &id1,
	};
	struct test_hook_handler h3 = {
		.point = TEST_HOOK_PRE_CREATE,
		.priority = 200,
		.hook_fn = hook_fn_record_order,
		.priv = &id2,
	};

	/* Register in non-sorted order */
	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);
	test_register_hook(ctx, &h3);

	test_run_hooks(ctx, TEST_HOOK_PRE_CREATE, &oc);

	KUNIT_EXPECT_EQ(test, oc.idx, 3);
	KUNIT_EXPECT_EQ(test, oc.order[0], 1); /* prio 100 first */
	KUNIT_EXPECT_EQ(test, oc.order[1], 2); /* prio 200 second */
	KUNIT_EXPECT_EQ(test, oc.order[2], 3); /* prio 300 third */
}

/*
 * test_stop_halts_chain - HOOK_STOP prevents subsequent handlers
 */
static void test_stop_halts_chain(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int counter1 = 0, counter2 = 0;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_stop,
		.priv = &counter1,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 200,
		.hook_fn = hook_fn_continue,
		.priv = &counter2,
	};
	int ret;

	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);

	ret = test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, ret, TEST_HOOK_STOP);
	KUNIT_EXPECT_EQ(test, counter1, 1);
	KUNIT_EXPECT_EQ(test, counter2, 0); /* never called */
}

/*
 * test_drop_halts_chain - HOOK_DROP prevents subsequent handlers
 */
static void test_drop_halts_chain(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int counter1 = 0, counter2 = 0;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_drop,
		.priv = &counter1,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 200,
		.hook_fn = hook_fn_continue,
		.priv = &counter2,
	};
	int ret;

	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);

	ret = test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, ret, TEST_HOOK_DROP);
	KUNIT_EXPECT_EQ(test, counter1, 1);
	KUNIT_EXPECT_EQ(test, counter2, 0);
}

/*
 * test_continue_continues_chain - CONTINUE lets all handlers run
 */
static void test_continue_continues_chain(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int counter1 = 0, counter2 = 0;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_continue,
		.priv = &counter1,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 200,
		.hook_fn = hook_fn_continue,
		.priv = &counter2,
	};

	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);

	test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, counter1, 1);
	KUNIT_EXPECT_EQ(test, counter2, 1);
}

/*
 * test_unregister_removes_handler - unregistered handler is not called
 */
static void test_unregister_removes_handler(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int counter = 0;
	struct test_hook_handler h = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_continue,
		.priv = &counter,
	};

	test_register_hook(ctx, &h);
	test_unregister_hook(ctx, &h);

	test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, counter, 0);
	KUNIT_EXPECT_EQ(test, ctx->count, (unsigned int)0);
}

/*
 * test_unregister_null_safe - unregistering NULL should not crash
 */
static void test_unregister_null_safe(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;

	test_unregister_hook(ctx, NULL);
	KUNIT_EXPECT_EQ(test, ctx->count, (unsigned int)0);
}

/*
 * test_multiple_hooks_same_point - multiple handlers on one point
 */
static void test_multiple_hooks_same_point(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int c1 = 0, c2 = 0, c3 = 0;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_PRE_CREATE,
		.priority = 100,
		.hook_fn = hook_fn_continue,
		.priv = &c1,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_PRE_CREATE,
		.priority = 200,
		.hook_fn = hook_fn_continue,
		.priv = &c2,
	};
	struct test_hook_handler h3 = {
		.point = TEST_HOOK_PRE_CREATE,
		.priority = 300,
		.hook_fn = hook_fn_continue,
		.priv = &c3,
	};

	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);
	test_register_hook(ctx, &h3);

	KUNIT_EXPECT_EQ(test, ctx->count, (unsigned int)3);

	test_run_hooks(ctx, TEST_HOOK_PRE_CREATE, NULL);
	KUNIT_EXPECT_EQ(test, c1, 1);
	KUNIT_EXPECT_EQ(test, c2, 1);
	KUNIT_EXPECT_EQ(test, c3, 1);
}

/*
 * test_different_points_isolated - hooks on different points are independent
 */
static void test_different_points_isolated(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	int c_negotiate = 0, c_audit = 0;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_PRE_NEGOTIATE,
		.priority = 100,
		.hook_fn = hook_fn_continue,
		.priv = &c_negotiate,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_continue,
		.priv = &c_audit,
	};

	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);

	test_run_hooks(ctx, TEST_HOOK_PRE_NEGOTIATE, NULL);
	KUNIT_EXPECT_EQ(test, c_negotiate, 1);
	KUNIT_EXPECT_EQ(test, c_audit, 0);

	test_run_hooks(ctx, TEST_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, c_audit, 1);
}

/*
 * test_same_priority_fifo - same priority handlers are called in FIFO order
 */
static void test_same_priority_fifo(struct kunit *test)
{
	struct hooks_test_ctx *ctx = test->priv;
	struct order_ctx oc = { .idx = 0 };
	int id1 = 1, id2 = 2;
	struct test_hook_handler h1 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_record_order,
		.priv = &id1,
	};
	struct test_hook_handler h2 = {
		.point = TEST_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_record_order,
		.priv = &id2,
	};

	/* h1 registered first, should be called first at same priority */
	test_register_hook(ctx, &h1);
	test_register_hook(ctx, &h2);

	test_run_hooks(ctx, TEST_HOOK_AUDIT, &oc);

	KUNIT_EXPECT_EQ(test, oc.idx, 2);
	KUNIT_EXPECT_EQ(test, oc.order[0], 1);
	KUNIT_EXPECT_EQ(test, oc.order[1], 2);
}

static struct kunit_case ksmbd_hooks_test_cases[] = {
	KUNIT_CASE(test_init_all_chains_empty),
	KUNIT_CASE(test_register_adds_handler),
	KUNIT_CASE(test_register_null_handler),
	KUNIT_CASE(test_register_null_fn),
	KUNIT_CASE(test_register_invalid_point),
	KUNIT_CASE(test_dispatch_calls_handler),
	KUNIT_CASE(test_dispatch_empty_returns_continue),
	KUNIT_CASE(test_dispatch_invalid_point),
	KUNIT_CASE(test_priority_ordering),
	KUNIT_CASE(test_stop_halts_chain),
	KUNIT_CASE(test_drop_halts_chain),
	KUNIT_CASE(test_continue_continues_chain),
	KUNIT_CASE(test_unregister_removes_handler),
	KUNIT_CASE(test_unregister_null_safe),
	KUNIT_CASE(test_multiple_hooks_same_point),
	KUNIT_CASE(test_different_points_isolated),
	KUNIT_CASE(test_same_priority_fifo),
	{}
};

static struct kunit_suite ksmbd_hooks_test_suite = {
	.name = "ksmbd_hooks",
	.init = hooks_test_init,
	.exit = hooks_test_exit,
	.test_cases = ksmbd_hooks_test_cases,
};

kunit_test_suite(ksmbd_hooks_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd hook registration and dispatch");
