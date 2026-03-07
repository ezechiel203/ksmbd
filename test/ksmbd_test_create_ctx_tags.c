// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for create context tag dispatch:
 *   Finding MxAc/QFid, verifying inline-handled tags are NOT in list,
 *   register/unregister custom tags.
 */

#include <kunit/test.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Inlined dispatch list from ksmbd_create_ctx.c ---- */

struct test_ctx_handler {
	const char	*tag;
	size_t		tag_len;
	struct list_head list;
};

struct test_ctx_list {
	struct list_head handlers;
};

static void test_list_init(struct test_ctx_list *l)
{
	INIT_LIST_HEAD(&l->handlers);
}

static int test_list_register(struct test_ctx_list *l,
			      struct test_ctx_handler *h)
{
	list_add_tail(&h->list, &l->handlers);
	return 0;
}

static void test_list_unregister(struct test_ctx_handler *h)
{
	list_del(&h->list);
}

static struct test_ctx_handler *test_list_find(struct test_ctx_list *l,
					       const char *tag,
					       size_t tag_len)
{
	struct test_ctx_handler *h;

	list_for_each_entry(h, &l->handlers, list) {
		if (h->tag_len == tag_len &&
		    !memcmp(h->tag, tag, tag_len))
			return h;
	}
	return NULL;
}

/* ---- Per-test state ---- */

static int ctx_tags_test_init(struct kunit *test)
{
	struct test_ctx_list *l;

	l = kzalloc(sizeof(*l), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, l);
	test_list_init(l);

	/* Register built-in handlers (MxAc and QFid) */
	{
		struct test_ctx_handler *mxac, *qfid;

		mxac = kzalloc(sizeof(*mxac), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, mxac);
		mxac->tag = "MxAc";
		mxac->tag_len = 4;
		test_list_register(l, mxac);

		qfid = kzalloc(sizeof(*qfid), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, qfid);
		qfid->tag = "QFid";
		qfid->tag_len = 4;
		test_list_register(l, qfid);
	}

	test->priv = l;
	return 0;
}

static void ctx_tags_test_exit(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;
	struct test_ctx_handler *h, *tmp;

	list_for_each_entry_safe(h, tmp, &l->handlers, list) {
		list_del(&h->list);
		kfree(h);
	}
	kfree(l);
}

/* ---- Test cases ---- */

static void test_find_mxac_tag(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "MxAc", 4));
}

static void test_find_qfid_tag(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "QFid", 4));
}

static void test_find_unknown_tag(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	KUNIT_EXPECT_NULL(test, test_list_find(l, "XXXX", 4));
}

static void test_find_secd_not_in_list(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	/* "SecD" is handled inline in smb2_create.c, not in dispatch list */
	KUNIT_EXPECT_NULL(test, test_list_find(l, "SecD", 4));
}

static void test_find_dhq_not_in_list(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	/* "DHnQ" is handled inline in smb2_create.c */
	KUNIT_EXPECT_NULL(test, test_list_find(l, "DHnQ", 4));
}

static void test_find_rqls_not_in_list(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	/* "RqLs" is handled inline in smb2_create.c */
	KUNIT_EXPECT_NULL(test, test_list_find(l, "RqLs", 4));
}

static void test_find_posix_tag_not_in_list(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;

	/*
	 * POSIX create context uses a 16-byte tag, handled inline.
	 * Not in dispatch list.
	 */
	u8 posix_tag[16];

	memset(posix_tag, 0, sizeof(posix_tag));
	KUNIT_EXPECT_NULL(test, test_list_find(l, (const char *)posix_tag, 16));
}

static void test_register_custom_tag(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;
	struct test_ctx_handler *custom;

	custom = kzalloc(sizeof(*custom), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, custom);
	custom->tag = "CuSt";
	custom->tag_len = 4;
	test_list_register(l, custom);

	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "CuSt", 4));
	/* MxAc and QFid should still be found */
	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "MxAc", 4));
	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "QFid", 4));
}

static void test_unregister_custom_tag(struct kunit *test)
{
	struct test_ctx_list *l = test->priv;
	struct test_ctx_handler *custom;

	custom = kzalloc(sizeof(*custom), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, custom);
	custom->tag = "RmMe";
	custom->tag_len = 4;
	test_list_register(l, custom);

	/* Verify it's there */
	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "RmMe", 4));

	/* Unregister and verify it's gone */
	test_list_unregister(custom);
	KUNIT_EXPECT_NULL(test, test_list_find(l, "RmMe", 4));

	/* Others still present */
	KUNIT_EXPECT_NOT_NULL(test, test_list_find(l, "MxAc", 4));

	kfree(custom);
}

static struct kunit_case ksmbd_create_ctx_tags_test_cases[] = {
	KUNIT_CASE(test_find_mxac_tag),
	KUNIT_CASE(test_find_qfid_tag),
	KUNIT_CASE(test_find_unknown_tag),
	KUNIT_CASE(test_find_secd_not_in_list),
	KUNIT_CASE(test_find_dhq_not_in_list),
	KUNIT_CASE(test_find_rqls_not_in_list),
	KUNIT_CASE(test_find_posix_tag_not_in_list),
	KUNIT_CASE(test_register_custom_tag),
	KUNIT_CASE(test_unregister_custom_tag),
	{}
};

static struct kunit_suite ksmbd_create_ctx_tags_test_suite = {
	.name = "ksmbd_create_ctx_tags",
	.init = ctx_tags_test_init,
	.exit = ctx_tags_test_exit,
	.test_cases = ksmbd_create_ctx_tags_test_cases,
};

kunit_test_suite(ksmbd_create_ctx_tags_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd create context tag dispatch");
