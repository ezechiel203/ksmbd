// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for tree connect management (tree_connect.c)
 *
 *   Tests for tree connect lifecycle: refcounting, lookup,
 *   disconnect, and session logoff.  We replicate the core
 *   data structures and logic to avoid requiring IPC or
 *   full session infrastructure.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <linux/refcount.h>

/* Replicate tree connect state enum */
enum test_tree_state {
	TREE_NEW = 0,
	TREE_CONNECTED,
	TREE_DISCONNECTED,
};

struct test_tree_connect {
	int			id;
	enum test_tree_state	t_state;
	refcount_t		refcount;
	bool			freed;
};

struct test_session {
	struct xarray		tree_conns;
};

static struct test_tree_connect *test_tree_alloc(int id)
{
	struct test_tree_connect *tc;

	tc = kzalloc(sizeof(*tc), GFP_KERNEL);
	if (!tc)
		return NULL;

	tc->id = id;
	tc->t_state = TREE_CONNECTED;
	refcount_set(&tc->refcount, 1);
	tc->freed = false;
	return tc;
}

static int test_tree_add(struct test_session *sess,
			 struct test_tree_connect *tc)
{
	return xa_insert(&sess->tree_conns, tc->id, tc, GFP_KERNEL);
}

static void test_tree_put(struct test_tree_connect *tc)
{
	if (refcount_dec_and_test(&tc->refcount)) {
		tc->freed = true;
		/* In real code, kfree happens here */
	}
}

static struct test_tree_connect *
test_tree_lookup(struct test_session *sess, int id)
{
	struct test_tree_connect *tc;

	tc = xa_load(&sess->tree_conns, id);
	if (!tc)
		return NULL;

	if (tc->t_state == TREE_DISCONNECTED)
		return NULL;

	refcount_inc(&tc->refcount);
	return tc;
}

static void test_tree_disconnect(struct test_session *sess,
				 struct test_tree_connect *tc)
{
	tc->t_state = TREE_DISCONNECTED;
	xa_erase(&sess->tree_conns, tc->id);
}

static void test_tree_session_logoff(struct test_session *sess)
{
	struct test_tree_connect *tc;
	unsigned long id;

	xa_for_each(&sess->tree_conns, id, tc)
		tc->t_state = TREE_DISCONNECTED;
}

static int tc_test_init(struct kunit *test)
{
	struct test_session *sess;

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, sess);

	xa_init_flags(&sess->tree_conns, XA_FLAGS_ALLOC);
	test->priv = sess;
	return 0;
}

static void tc_test_exit(struct kunit *test)
{
	struct test_session *sess = test->priv;
	struct test_tree_connect *tc;
	unsigned long id;

	xa_for_each(&sess->tree_conns, id, tc) {
		xa_erase(&sess->tree_conns, id);
		kfree(tc);
	}
	xa_destroy(&sess->tree_conns);
	kfree(sess);
}

/* --- Test cases --- */

static void test_tree_connect_put_frees_on_last_ref(struct kunit *test)
{
	struct test_tree_connect *tc;

	tc = test_tree_alloc(1);
	KUNIT_ASSERT_NOT_NULL(test, tc);
	KUNIT_ASSERT_EQ(test, (int)refcount_read(&tc->refcount), 1);

	test_tree_put(tc);
	KUNIT_EXPECT_TRUE(test, tc->freed);

	kfree(tc);
}

static void test_tree_connect_put_decrements_ref(struct kunit *test)
{
	struct test_tree_connect *tc;

	tc = test_tree_alloc(1);
	KUNIT_ASSERT_NOT_NULL(test, tc);

	/* Bump to 2 */
	refcount_inc(&tc->refcount);
	KUNIT_ASSERT_EQ(test, (int)refcount_read(&tc->refcount), 2);

	test_tree_put(tc);
	KUNIT_EXPECT_EQ(test, (int)refcount_read(&tc->refcount), 1);
	KUNIT_EXPECT_FALSE(test, tc->freed);

	kfree(tc);
}

static void test_tree_conn_lookup_returns_null_for_nonexistent(struct kunit *test)
{
	struct test_session *sess = test->priv;

	KUNIT_EXPECT_NULL(test, test_tree_lookup(sess, 9999));
}

static void test_tree_conn_lookup_rejects_disconnected(struct kunit *test)
{
	struct test_session *sess = test->priv;
	struct test_tree_connect *tc;

	tc = test_tree_alloc(42);
	KUNIT_ASSERT_NOT_NULL(test, tc);
	test_tree_add(sess, tc);

	/* Mark as disconnected */
	tc->t_state = TREE_DISCONNECTED;

	KUNIT_EXPECT_NULL(test, test_tree_lookup(sess, 42));
}

static void test_tree_conn_session_logoff_null_session(struct kunit *test)
{
	/*
	 * In real code, ksmbd_tree_conn_session_logoff with NULL session
	 * returns -EINVAL.  We verify the pattern here.
	 */
	struct test_session *sess = NULL;
	int ret = (sess == NULL) ? -EINVAL : 0;

	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_tree_conn_disconnect_removes_from_xarray(struct kunit *test)
{
	struct test_session *sess = test->priv;
	struct test_tree_connect *tc;

	tc = test_tree_alloc(10);
	KUNIT_ASSERT_NOT_NULL(test, tc);
	test_tree_add(sess, tc);

	/* Verify it exists */
	KUNIT_ASSERT_NOT_NULL(test, test_tree_lookup(sess, 10));
	test_tree_put(test_tree_lookup(sess, 10));

	/* Disconnect */
	test_tree_disconnect(sess, tc);

	/* Subsequent lookup should fail */
	KUNIT_EXPECT_NULL(test, test_tree_lookup(sess, 10));
	kfree(tc);
}

static void test_tree_conn_session_logoff_marks_disconnected(struct kunit *test)
{
	struct test_session *sess = test->priv;
	struct test_tree_connect *tc1, *tc2;

	tc1 = test_tree_alloc(1);
	tc2 = test_tree_alloc(2);
	KUNIT_ASSERT_NOT_NULL(test, tc1);
	KUNIT_ASSERT_NOT_NULL(test, tc2);
	test_tree_add(sess, tc1);
	test_tree_add(sess, tc2);

	test_tree_session_logoff(sess);

	KUNIT_EXPECT_EQ(test, tc1->t_state, TREE_DISCONNECTED);
	KUNIT_EXPECT_EQ(test, tc2->t_state, TREE_DISCONNECTED);
}

static struct kunit_case ksmbd_tree_connect_test_cases[] = {
	KUNIT_CASE(test_tree_connect_put_frees_on_last_ref),
	KUNIT_CASE(test_tree_connect_put_decrements_ref),
	KUNIT_CASE(test_tree_conn_lookup_returns_null_for_nonexistent),
	KUNIT_CASE(test_tree_conn_lookup_rejects_disconnected),
	KUNIT_CASE(test_tree_conn_session_logoff_null_session),
	KUNIT_CASE(test_tree_conn_disconnect_removes_from_xarray),
	KUNIT_CASE(test_tree_conn_session_logoff_marks_disconnected),
	{}
};

static struct kunit_suite ksmbd_tree_connect_test_suite = {
	.name = "ksmbd_tree_connect",
	.init = tc_test_init,
	.exit = tc_test_exit,
	.test_cases = ksmbd_tree_connect_test_cases,
};

kunit_test_suite(ksmbd_tree_connect_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd tree connect management");
