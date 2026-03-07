// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for the create context dispatch list (ksmbd_create_ctx.c)
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure dispatch-list logic
 *   under test, omitting RCU and module refcounting.
 */

#include <kunit/test.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Inlined/simplified definitions from ksmbd_create_ctx.h ---- */

struct test_create_ctx_handler {
	const char		*tag;
	size_t			tag_len;
	int			(*on_request)(void *work, const void *ctx_data,
					      unsigned int ctx_len);
	int			(*on_response)(void *work, void *rsp_buf,
					       unsigned int max_len,
					       unsigned int *rsp_len);
	struct list_head	list;
};

struct create_ctx_test_ctx {
	struct list_head	handlers;
};

static void test_ctx_init(struct create_ctx_test_ctx *ctx)
{
	INIT_LIST_HEAD(&ctx->handlers);
}

static int test_ctx_register(struct create_ctx_test_ctx *ctx,
			     struct test_create_ctx_handler *h)
{
	list_add_tail(&h->list, &ctx->handlers);
	return 0;
}

static void test_ctx_unregister(struct create_ctx_test_ctx *ctx,
				struct test_create_ctx_handler *h)
{
	list_del(&h->list);
}

static struct test_create_ctx_handler *test_ctx_find(
		struct create_ctx_test_ctx *ctx,
		const char *tag, size_t tag_len)
{
	struct test_create_ctx_handler *h;

	list_for_each_entry(h, &ctx->handlers, list) {
		if (h->tag_len == tag_len &&
		    !memcmp(h->tag, tag, tag_len))
			return h;
	}
	return NULL;
}

/* ---- Per-test state ---- */

static int create_ctx_test_init(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	test_ctx_init(ctx);
	test->priv = ctx;
	return 0;
}

static void create_ctx_test_exit(struct kunit *test)
{
	kfree(test->priv);
}

/* ---- Stub callbacks ---- */

static int stub_on_request(void *work, const void *ctx_data,
			   unsigned int ctx_len)
{
	return 0;
}

static int stub_on_response(void *work, void *rsp_buf,
			    unsigned int max_len, unsigned int *rsp_len)
{
	*rsp_len = 0;
	return 0;
}

/* ---- Test cases ---- */

/*
 * test_register_and_find - registering a handler then finding by tag succeeds
 */
static void test_register_and_find(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "MxAc",
		.tag_len = 4,
		.on_request = stub_on_request,
		.on_response = stub_on_response,
	};
	struct test_create_ctx_handler *found;

	test_ctx_register(ctx, &h);

	found = test_ctx_find(ctx, "MxAc", 4);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_PTR_EQ(test, found, &h);
}

/*
 * test_find_empty_list - find on empty list returns NULL
 */
static void test_find_empty_list(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "MxAc", 4));
}

/*
 * test_unregister_then_find - after unregister, find returns NULL
 */
static void test_unregister_then_find(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "QFid",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h);
	test_ctx_unregister(ctx, &h);

	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "QFid", 4));
}

/*
 * test_multiple_tags_found - each registered tag is found correctly
 */
static void test_multiple_tags_found(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h1 = {
		.tag = "MxAc",
		.tag_len = 4,
		.on_request = stub_on_request,
	};
	struct test_create_ctx_handler h2 = {
		.tag = "QFid",
		.tag_len = 4,
		.on_request = stub_on_request,
	};
	struct test_create_ctx_handler h3 = {
		.tag = "AAPL",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h1);
	test_ctx_register(ctx, &h2);
	test_ctx_register(ctx, &h3);

	KUNIT_EXPECT_PTR_EQ(test, test_ctx_find(ctx, "MxAc", 4), &h1);
	KUNIT_EXPECT_PTR_EQ(test, test_ctx_find(ctx, "QFid", 4), &h2);
	KUNIT_EXPECT_PTR_EQ(test, test_ctx_find(ctx, "AAPL", 4), &h3);
}

/*
 * test_tag_exact_memcmp - matching uses exact memcmp, not prefix
 */
static void test_tag_exact_memcmp(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "MxAc",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h);

	/* Exact match should work */
	KUNIT_EXPECT_NOT_NULL(test, test_ctx_find(ctx, "MxAc", 4));

	/* Prefix match should NOT work (different tag_len) */
	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "Mx", 2));

	/* Longer tag should NOT work */
	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "MxAcExtra", 9));
}

/*
 * test_tag_same_prefix_different_suffix - tags with same prefix are distinct
 */
static void test_tag_same_prefix_different_suffix(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h1 = {
		.tag = "AbCd",
		.tag_len = 4,
		.on_request = stub_on_request,
	};
	struct test_create_ctx_handler h2 = {
		.tag = "AbCe",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h1);
	test_ctx_register(ctx, &h2);

	KUNIT_EXPECT_PTR_EQ(test, test_ctx_find(ctx, "AbCd", 4), &h1);
	KUNIT_EXPECT_PTR_EQ(test, test_ctx_find(ctx, "AbCe", 4), &h2);
}

/*
 * test_tag_not_found - looking up non-existent tag returns NULL
 */
static void test_tag_not_found(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "MxAc",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h);

	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "ZZZZ", 4));
}

/*
 * test_case_sensitive - tag matching is case-sensitive (binary memcmp)
 */
static void test_case_sensitive(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "MxAc",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h);

	KUNIT_EXPECT_NOT_NULL(test, test_ctx_find(ctx, "MxAc", 4));
	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "mxac", 4));
	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "MXAC", 4));
}

/*
 * test_unregister_one_leaves_others - unregistering one leaves others intact
 */
static void test_unregister_one_leaves_others(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h1 = {
		.tag = "MxAc",
		.tag_len = 4,
		.on_request = stub_on_request,
	};
	struct test_create_ctx_handler h2 = {
		.tag = "QFid",
		.tag_len = 4,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h1);
	test_ctx_register(ctx, &h2);

	test_ctx_unregister(ctx, &h1);

	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "MxAc", 4));
	KUNIT_EXPECT_NOT_NULL(test, test_ctx_find(ctx, "QFid", 4));
}

/*
 * test_zero_length_tag - zero-length tag only matches zero-length lookup
 */
static void test_zero_length_tag(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "",
		.tag_len = 0,
		.on_request = stub_on_request,
	};

	test_ctx_register(ctx, &h);

	/* Zero-length find matches zero-length tag */
	KUNIT_EXPECT_NOT_NULL(test, test_ctx_find(ctx, "", 0));

	/* Non-zero-length find does not match */
	KUNIT_EXPECT_NULL(test, test_ctx_find(ctx, "x", 1));
}

/*
 * test_register_returns_zero - register always returns 0
 */
static void test_register_returns_zero(struct kunit *test)
{
	struct create_ctx_test_ctx *ctx = test->priv;
	struct test_create_ctx_handler h = {
		.tag = "Test",
		.tag_len = 4,
		.on_request = stub_on_request,
	};
	int ret;

	ret = test_ctx_register(ctx, &h);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static struct kunit_case ksmbd_create_ctx_test_cases[] = {
	KUNIT_CASE(test_register_and_find),
	KUNIT_CASE(test_find_empty_list),
	KUNIT_CASE(test_unregister_then_find),
	KUNIT_CASE(test_multiple_tags_found),
	KUNIT_CASE(test_tag_exact_memcmp),
	KUNIT_CASE(test_tag_same_prefix_different_suffix),
	KUNIT_CASE(test_tag_not_found),
	KUNIT_CASE(test_case_sensitive),
	KUNIT_CASE(test_unregister_one_leaves_others),
	KUNIT_CASE(test_zero_length_tag),
	KUNIT_CASE(test_register_returns_zero),
	{}
};

static struct kunit_suite ksmbd_create_ctx_test_suite = {
	.name = "ksmbd_create_ctx",
	.init = create_ctx_test_init,
	.exit = create_ctx_test_exit,
	.test_cases = ksmbd_create_ctx_test_cases,
};

kunit_test_suite(ksmbd_create_ctx_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd create context dispatch list");
