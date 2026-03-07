// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ksmbd hook subsystem (ksmbd_hooks.c)
 *
 *   Calls production ksmbd_hooks_init/exit, ksmbd_register_hook,
 *   ksmbd_unregister_hook, and __ksmbd_run_hooks directly via
 *   exported symbols.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/module.h>

#include "ksmbd_hooks.h"

/* Hook callback: increment counter and continue */
static int hook_fn_count(struct ksmbd_work *work, void *priv)
{
	int *counter = priv;

	if (counter)
		(*counter)++;
	return KSMBD_HOOK_CONTINUE;
}

/* Hook callback: increment counter and stop */
static int hook_fn_stop(struct ksmbd_work *work, void *priv)
{
	int *counter = priv;

	if (counter)
		(*counter)++;
	return KSMBD_HOOK_STOP;
}

/* Hook callback: increment counter and drop */
static int hook_fn_drop(struct ksmbd_work *work, void *priv)
{
	int *counter = priv;

	if (counter)
		(*counter)++;
	return KSMBD_HOOK_DROP;
}

/*
 * Suite init/exit: init and tear down the hook subsystem once.
 * This tests ksmbd_hooks_init/exit as side effects.
 */
static int hooks_direct_suite_init(struct kunit_suite *suite)
{
	return ksmbd_hooks_init();
}

static void hooks_direct_suite_exit(struct kunit_suite *suite)
{
	ksmbd_hooks_exit();
}

/* -- Registration tests -- */

static void test_register_null_returns_einval(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, ksmbd_register_hook(NULL), -EINVAL);
}

static void test_register_no_fn_returns_einval(struct kunit *test)
{
	struct ksmbd_hook_handler h = {
		.point = KSMBD_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = NULL,
		.owner = THIS_MODULE,
	};

	KUNIT_EXPECT_EQ(test, ksmbd_register_hook(&h), -EINVAL);
}

static void test_register_invalid_point_returns_einval(struct kunit *test)
{
	struct ksmbd_hook_handler h = {
		.point = __KSMBD_HOOK_MAX,
		.priority = 100,
		.hook_fn = hook_fn_count,
		.owner = THIS_MODULE,
	};

	KUNIT_EXPECT_EQ(test, ksmbd_register_hook(&h), -EINVAL);
}

static void test_register_and_dispatch(struct kunit *test)
{
	int counter = 0;
	int ret;
	struct ksmbd_hook_handler h = {
		.point = KSMBD_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_count,
		.priv = &counter,
		.owner = THIS_MODULE,
	};

	ret = ksmbd_register_hook(&h);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = __ksmbd_run_hooks(KSMBD_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, ret, KSMBD_HOOK_CONTINUE);
	KUNIT_EXPECT_EQ(test, counter, 1);

	ksmbd_unregister_hook(&h);
}

static void test_unregister_prevents_dispatch(struct kunit *test)
{
	int counter = 0;
	int ret;
	struct ksmbd_hook_handler h = {
		.point = KSMBD_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_count,
		.priv = &counter,
		.owner = THIS_MODULE,
	};

	ksmbd_register_hook(&h);
	ksmbd_unregister_hook(&h);

	ret = __ksmbd_run_hooks(KSMBD_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, ret, KSMBD_HOOK_CONTINUE);
	KUNIT_EXPECT_EQ(test, counter, 0);
}

static void test_dispatch_empty_returns_continue(struct kunit *test)
{
	int ret;

	ret = __ksmbd_run_hooks(KSMBD_HOOK_PRE_NEGOTIATE, NULL);
	KUNIT_EXPECT_EQ(test, ret, KSMBD_HOOK_CONTINUE);
}

static void test_dispatch_invalid_point(struct kunit *test)
{
	int ret;

	ret = __ksmbd_run_hooks(__KSMBD_HOOK_MAX, NULL);
	KUNIT_EXPECT_EQ(test, ret, KSMBD_HOOK_CONTINUE);
}

static void test_stop_halts_chain(struct kunit *test)
{
	int c1 = 0, c2 = 0;
	int ret;
	struct ksmbd_hook_handler h1 = {
		.point = KSMBD_HOOK_PRE_CREATE,
		.priority = 100,
		.hook_fn = hook_fn_stop,
		.priv = &c1,
		.owner = THIS_MODULE,
	};
	struct ksmbd_hook_handler h2 = {
		.point = KSMBD_HOOK_PRE_CREATE,
		.priority = 200,
		.hook_fn = hook_fn_count,
		.priv = &c2,
		.owner = THIS_MODULE,
	};

	ksmbd_register_hook(&h1);
	ksmbd_register_hook(&h2);

	ret = __ksmbd_run_hooks(KSMBD_HOOK_PRE_CREATE, NULL);
	KUNIT_EXPECT_EQ(test, ret, KSMBD_HOOK_STOP);
	KUNIT_EXPECT_EQ(test, c1, 1);
	KUNIT_EXPECT_EQ(test, c2, 0);

	ksmbd_unregister_hook(&h1);
	ksmbd_unregister_hook(&h2);
}

static void test_drop_halts_chain(struct kunit *test)
{
	int c1 = 0, c2 = 0;
	int ret;
	struct ksmbd_hook_handler h1 = {
		.point = KSMBD_HOOK_PRE_CREATE,
		.priority = 100,
		.hook_fn = hook_fn_drop,
		.priv = &c1,
		.owner = THIS_MODULE,
	};
	struct ksmbd_hook_handler h2 = {
		.point = KSMBD_HOOK_PRE_CREATE,
		.priority = 200,
		.hook_fn = hook_fn_count,
		.priv = &c2,
		.owner = THIS_MODULE,
	};

	ksmbd_register_hook(&h1);
	ksmbd_register_hook(&h2);

	ret = __ksmbd_run_hooks(KSMBD_HOOK_PRE_CREATE, NULL);
	KUNIT_EXPECT_EQ(test, ret, KSMBD_HOOK_DROP);
	KUNIT_EXPECT_EQ(test, c1, 1);
	KUNIT_EXPECT_EQ(test, c2, 0);

	ksmbd_unregister_hook(&h1);
	ksmbd_unregister_hook(&h2);
}

static void test_continue_runs_all(struct kunit *test)
{
	int c1 = 0, c2 = 0, c3 = 0;
	struct ksmbd_hook_handler h1 = {
		.point = KSMBD_HOOK_POST_READ,
		.priority = 100,
		.hook_fn = hook_fn_count,
		.priv = &c1,
		.owner = THIS_MODULE,
	};
	struct ksmbd_hook_handler h2 = {
		.point = KSMBD_HOOK_POST_READ,
		.priority = 200,
		.hook_fn = hook_fn_count,
		.priv = &c2,
		.owner = THIS_MODULE,
	};
	struct ksmbd_hook_handler h3 = {
		.point = KSMBD_HOOK_POST_READ,
		.priority = 300,
		.hook_fn = hook_fn_count,
		.priv = &c3,
		.owner = THIS_MODULE,
	};

	ksmbd_register_hook(&h1);
	ksmbd_register_hook(&h2);
	ksmbd_register_hook(&h3);

	__ksmbd_run_hooks(KSMBD_HOOK_POST_READ, NULL);
	KUNIT_EXPECT_EQ(test, c1, 1);
	KUNIT_EXPECT_EQ(test, c2, 1);
	KUNIT_EXPECT_EQ(test, c3, 1);

	ksmbd_unregister_hook(&h1);
	ksmbd_unregister_hook(&h2);
	ksmbd_unregister_hook(&h3);
}

static void test_different_points_isolated(struct kunit *test)
{
	int c_neg = 0, c_aud = 0;
	struct ksmbd_hook_handler h1 = {
		.point = KSMBD_HOOK_PRE_NEGOTIATE,
		.priority = 100,
		.hook_fn = hook_fn_count,
		.priv = &c_neg,
		.owner = THIS_MODULE,
	};
	struct ksmbd_hook_handler h2 = {
		.point = KSMBD_HOOK_AUDIT,
		.priority = 100,
		.hook_fn = hook_fn_count,
		.priv = &c_aud,
		.owner = THIS_MODULE,
	};

	ksmbd_register_hook(&h1);
	ksmbd_register_hook(&h2);

	__ksmbd_run_hooks(KSMBD_HOOK_PRE_NEGOTIATE, NULL);
	KUNIT_EXPECT_EQ(test, c_neg, 1);
	KUNIT_EXPECT_EQ(test, c_aud, 0);

	__ksmbd_run_hooks(KSMBD_HOOK_AUDIT, NULL);
	KUNIT_EXPECT_EQ(test, c_aud, 1);

	ksmbd_unregister_hook(&h1);
	ksmbd_unregister_hook(&h2);
}

static void test_unregister_null_safe(struct kunit *test)
{
	/* Should not crash */
	ksmbd_unregister_hook(NULL);
}

static struct kunit_case ksmbd_hooks_direct_cases[] = {
	KUNIT_CASE(test_register_null_returns_einval),
	KUNIT_CASE(test_register_no_fn_returns_einval),
	KUNIT_CASE(test_register_invalid_point_returns_einval),
	KUNIT_CASE(test_register_and_dispatch),
	KUNIT_CASE(test_unregister_prevents_dispatch),
	KUNIT_CASE(test_dispatch_empty_returns_continue),
	KUNIT_CASE(test_dispatch_invalid_point),
	KUNIT_CASE(test_stop_halts_chain),
	KUNIT_CASE(test_drop_halts_chain),
	KUNIT_CASE(test_continue_runs_all),
	KUNIT_CASE(test_different_points_isolated),
	KUNIT_CASE(test_unregister_null_safe),
	{}
};

static struct kunit_suite ksmbd_hooks_direct_suite = {
	.name = "ksmbd_hooks_direct",
	.suite_init = hooks_direct_suite_init,
	.suite_exit = hooks_direct_suite_exit,
	.test_cases = ksmbd_hooks_direct_cases,
};

kunit_test_suite(ksmbd_hooks_direct_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd hook subsystem (calls production code)");
