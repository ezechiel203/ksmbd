// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for witness protocol state management (ksmbd_witness.c)
 *
 *   The witness subsystem manages resources and registrations using
 *   linked lists, IDAs, and atomics.  We replicate the core data
 *   structures and logic to test resource/registration lifecycle,
 *   limits, and edge cases without requiring netdevice notifiers
 *   or IPC.
 */

#include <kunit/test.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/idr.h>
#include <linux/string.h>
#include <linux/atomic.h>

/* Replicate constants from ksmbd_netlink.h */
#define TEST_WITNESS_NAME_MAX		256
#define TEST_WITNESS_STATE_AVAILABLE	0
#define TEST_WITNESS_STATE_UNAVAILABLE	1
#define TEST_WITNESS_STATE_UNKNOWN	0xFF
#define TEST_WITNESS_RESOURCE_IP	0
#define TEST_WITNESS_RESOURCE_SHARE	1
#define TEST_WITNESS_RESOURCE_NODE	2

#define TEST_MAX_WITNESS_REGISTRATIONS		256
#define TEST_MAX_WITNESS_REGS_PER_SESSION	64

struct test_witness_resource {
	unsigned int	type;
	unsigned int	state;
	char		name[TEST_WITNESS_NAME_MAX];
	struct list_head list;
	struct list_head subscribers;
	spinlock_t	lock;
};

struct test_witness_registration {
	u32		reg_id;
	u64		session_id;
	char		client_name[TEST_WITNESS_NAME_MAX];
	char		resource_name[TEST_WITNESS_NAME_MAX];
	unsigned int	type;
	struct list_head list;
	struct list_head global_list;
};

/* Per-test state */
struct witness_test_ctx {
	struct list_head resources;
	struct rw_semaphore lock;
	struct list_head registrations;
	spinlock_t reg_lock;
	struct ida ida;
	atomic_t reg_count;
};

static int witness_test_init(struct kunit *test)
{
	struct witness_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	INIT_LIST_HEAD(&ctx->resources);
	init_rwsem(&ctx->lock);
	INIT_LIST_HEAD(&ctx->registrations);
	spin_lock_init(&ctx->reg_lock);
	ida_init(&ctx->ida);
	atomic_set(&ctx->reg_count, 0);

	test->priv = ctx;
	return 0;
}

static void witness_test_exit(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	struct test_witness_registration *reg, *rtmp;
	struct test_witness_resource *res, *tmp;

	/* Free registrations */
	list_for_each_entry_safe(reg, rtmp, &ctx->registrations, global_list) {
		list_del(&reg->global_list);
		ida_free(&ctx->ida, reg->reg_id);
		kfree(reg);
	}

	/* Free resources */
	list_for_each_entry_safe(res, tmp, &ctx->resources, list) {
		list_del(&res->list);
		kfree(res);
	}

	ida_destroy(&ctx->ida);
	kfree(ctx);
}

/* Replicated helper functions */

static struct test_witness_resource *
__test_resource_lookup(struct witness_test_ctx *ctx, const char *name)
{
	struct test_witness_resource *res;

	list_for_each_entry(res, &ctx->resources, list) {
		if (!strncmp(res->name, name, TEST_WITNESS_NAME_MAX))
			return res;
	}
	return NULL;
}

static struct test_witness_resource *
test_resource_add(struct witness_test_ctx *ctx, const char *name,
		  unsigned int type)
{
	struct test_witness_resource *res;

	if (!name || !name[0])
		return ERR_PTR(-EINVAL);

	down_write(&ctx->lock);
	if (__test_resource_lookup(ctx, name)) {
		up_write(&ctx->lock);
		return ERR_PTR(-EEXIST);
	}

	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res) {
		up_write(&ctx->lock);
		return ERR_PTR(-ENOMEM);
	}

	res->type = type;
	res->state = TEST_WITNESS_STATE_UNKNOWN;
	strscpy(res->name, name, TEST_WITNESS_NAME_MAX);
	INIT_LIST_HEAD(&res->subscribers);
	spin_lock_init(&res->lock);
	list_add_tail(&res->list, &ctx->resources);
	up_write(&ctx->lock);
	return res;
}

static void test_resource_del(struct witness_test_ctx *ctx, const char *name)
{
	struct test_witness_resource *res;
	struct test_witness_registration *reg, *tmp;

	down_write(&ctx->lock);
	res = __test_resource_lookup(ctx, name);
	if (!res) {
		up_write(&ctx->lock);
		return;
	}

	spin_lock(&res->lock);
	list_for_each_entry_safe(reg, tmp, &res->subscribers, list)
		list_del_init(&reg->list);
	spin_unlock(&res->lock);

	list_del(&res->list);
	up_write(&ctx->lock);
	kfree(res);
}

static bool test_resource_lookup(struct witness_test_ctx *ctx,
				 const char *name)
{
	bool found;

	down_read(&ctx->lock);
	found = __test_resource_lookup(ctx, name) != NULL;
	up_read(&ctx->lock);
	return found;
}

static int test_witness_register(struct witness_test_ctx *ctx,
				 const char *client_name,
				 const char *resource_name,
				 unsigned int type,
				 u64 session_id,
				 u32 *reg_id_out)
{
	struct test_witness_registration *reg, *r;
	struct test_witness_resource *res;
	int id;

	if (!client_name || !resource_name)
		return -EINVAL;

	/* Per-session limit */
	if (session_id) {
		int sess_count = 0;

		spin_lock(&ctx->reg_lock);
		list_for_each_entry(r, &ctx->registrations, global_list) {
			if (r->session_id == session_id &&
			    ++sess_count >=
			    TEST_MAX_WITNESS_REGS_PER_SESSION) {
				spin_unlock(&ctx->reg_lock);
				return -ENOSPC;
			}
		}
		spin_unlock(&ctx->reg_lock);
	}

	if (atomic_inc_return(&ctx->reg_count) >
	    TEST_MAX_WITNESS_REGISTRATIONS) {
		atomic_dec(&ctx->reg_count);
		return -ENOSPC;
	}

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (!reg) {
		atomic_dec(&ctx->reg_count);
		return -ENOMEM;
	}

	id = ida_alloc_min(&ctx->ida, 1, GFP_KERNEL);
	if (id < 0) {
		kfree(reg);
		atomic_dec(&ctx->reg_count);
		return id;
	}

	reg->reg_id = (u32)id;
	reg->type = type;
	reg->session_id = session_id;
	strscpy(reg->client_name, client_name, TEST_WITNESS_NAME_MAX);
	strscpy(reg->resource_name, resource_name, TEST_WITNESS_NAME_MAX);
	INIT_LIST_HEAD(&reg->list);
	INIT_LIST_HEAD(&reg->global_list);

	/* Auto-create resource if not found */
	down_write(&ctx->lock);
	res = __test_resource_lookup(ctx, resource_name);
	if (!res) {
		up_write(&ctx->lock);
		res = test_resource_add(ctx, resource_name, type);
		if (IS_ERR(res) && PTR_ERR(res) != -EEXIST) {
			ida_free(&ctx->ida, id);
			kfree(reg);
			atomic_dec(&ctx->reg_count);
			return PTR_ERR(res);
		}
		down_write(&ctx->lock);
		res = __test_resource_lookup(ctx, resource_name);
		if (!res) {
			up_write(&ctx->lock);
			ida_free(&ctx->ida, id);
			kfree(reg);
			atomic_dec(&ctx->reg_count);
			return -ENOENT;
		}
	}

	spin_lock(&res->lock);
	list_add_tail(&reg->list, &res->subscribers);
	spin_unlock(&res->lock);
	up_write(&ctx->lock);

	spin_lock(&ctx->reg_lock);
	list_add_tail(&reg->global_list, &ctx->registrations);
	spin_unlock(&ctx->reg_lock);

	*reg_id_out = reg->reg_id;
	return 0;
}

static int test_witness_unregister(struct witness_test_ctx *ctx, u32 reg_id)
{
	struct test_witness_registration *reg, *found = NULL;

	spin_lock(&ctx->reg_lock);
	list_for_each_entry(reg, &ctx->registrations, global_list) {
		if (reg->reg_id == reg_id) {
			found = reg;
			list_del_init(&found->global_list);
			break;
		}
	}
	spin_unlock(&ctx->reg_lock);

	if (!found)
		return -ENOENT;

	down_write(&ctx->lock);
	if (!list_empty(&found->list)) {
		struct test_witness_resource *res;

		res = __test_resource_lookup(ctx, found->resource_name);
		if (res) {
			spin_lock(&res->lock);
			list_del_init(&found->list);
			spin_unlock(&res->lock);
		}
	}
	up_write(&ctx->lock);

	ida_free(&ctx->ida, found->reg_id);
	kfree(found);
	atomic_dec(&ctx->reg_count);
	return 0;
}

static void test_witness_unregister_session(struct witness_test_ctx *ctx,
					    u64 session_id)
{
	struct test_witness_registration *reg, *tmp;
	LIST_HEAD(to_free);

	if (!session_id)
		return;

	spin_lock(&ctx->reg_lock);
	list_for_each_entry_safe(reg, tmp, &ctx->registrations, global_list) {
		if (reg->session_id == session_id) {
			list_del_init(&reg->global_list);
			list_add(&reg->global_list, &to_free);
		}
	}
	spin_unlock(&ctx->reg_lock);

	list_for_each_entry_safe(reg, tmp, &to_free, global_list) {
		down_write(&ctx->lock);
		if (!list_empty(&reg->list)) {
			struct test_witness_resource *res;

			res = __test_resource_lookup(ctx,
						     reg->resource_name);
			if (res) {
				spin_lock(&res->lock);
				list_del_init(&reg->list);
				spin_unlock(&res->lock);
			}
		}
		up_write(&ctx->lock);

		list_del(&reg->global_list);
		ida_free(&ctx->ida, reg->reg_id);
		kfree(reg);
		atomic_dec(&ctx->reg_count);
	}
}

static int test_witness_registration_count(struct witness_test_ctx *ctx)
{
	struct test_witness_registration *reg;
	int count = 0;

	spin_lock(&ctx->reg_lock);
	list_for_each_entry(reg, &ctx->registrations, global_list)
		count++;
	spin_unlock(&ctx->reg_lock);
	return count;
}

/* --- Test cases --- */

static void test_witness_resource_add_basic(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	struct test_witness_resource *res;

	res = test_resource_add(ctx, "192.168.1.1", TEST_WITNESS_RESOURCE_IP);
	KUNIT_EXPECT_FALSE(test, IS_ERR(res));
	KUNIT_EXPECT_STREQ(test, res->name, "192.168.1.1");
	KUNIT_EXPECT_EQ(test, res->type, TEST_WITNESS_RESOURCE_IP);
	KUNIT_EXPECT_EQ(test, res->state, TEST_WITNESS_STATE_UNKNOWN);
}

static void test_witness_resource_add_duplicate(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	struct test_witness_resource *res;

	res = test_resource_add(ctx, "192.168.1.1", TEST_WITNESS_RESOURCE_IP);
	KUNIT_ASSERT_FALSE(test, IS_ERR(res));

	res = test_resource_add(ctx, "192.168.1.1", TEST_WITNESS_RESOURCE_IP);
	KUNIT_EXPECT_TRUE(test, IS_ERR(res));
	KUNIT_EXPECT_EQ(test, (int)PTR_ERR(res), -EEXIST);
}

static void test_witness_resource_add_null_name(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	struct test_witness_resource *res;

	res = test_resource_add(ctx, NULL, TEST_WITNESS_RESOURCE_IP);
	KUNIT_EXPECT_TRUE(test, IS_ERR(res));
	KUNIT_EXPECT_EQ(test, (int)PTR_ERR(res), -EINVAL);
}

static void test_witness_resource_add_empty_name(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	struct test_witness_resource *res;

	res = test_resource_add(ctx, "", TEST_WITNESS_RESOURCE_IP);
	KUNIT_EXPECT_TRUE(test, IS_ERR(res));
	KUNIT_EXPECT_EQ(test, (int)PTR_ERR(res), -EINVAL);
}

static void test_witness_resource_del_existing(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;

	test_resource_add(ctx, "res1", TEST_WITNESS_RESOURCE_SHARE);
	KUNIT_ASSERT_TRUE(test, test_resource_lookup(ctx, "res1"));

	test_resource_del(ctx, "res1");
	KUNIT_EXPECT_FALSE(test, test_resource_lookup(ctx, "res1"));
}

static void test_witness_resource_del_nonexistent(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;

	/* Should not crash */
	test_resource_del(ctx, "nonexistent");
}

static void test_witness_resource_lookup_existing(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;

	test_resource_add(ctx, "test_res", TEST_WITNESS_RESOURCE_NODE);
	KUNIT_EXPECT_TRUE(test, test_resource_lookup(ctx, "test_res"));
}

static void test_witness_resource_lookup_nonexistent(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_FALSE(test, test_resource_lookup(ctx, "nope"));
}

static void test_witness_register_basic(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	int ret;

	ret = test_witness_register(ctx, "client1", "res1",
				    TEST_WITNESS_RESOURCE_IP, 100, &reg_id);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GT(test, reg_id, (u32)0);
}

static void test_witness_register_auto_creates_resource(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;

	KUNIT_EXPECT_FALSE(test, test_resource_lookup(ctx, "auto_res"));

	test_witness_register(ctx, "client1", "auto_res",
			      TEST_WITNESS_RESOURCE_SHARE, 100, &reg_id);
	KUNIT_EXPECT_TRUE(test, test_resource_lookup(ctx, "auto_res"));
}

static void test_witness_register_null_client_name(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	int ret;

	ret = test_witness_register(ctx, NULL, "res1",
				    TEST_WITNESS_RESOURCE_IP, 100, &reg_id);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_witness_register_null_resource_name(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	int ret;

	ret = test_witness_register(ctx, "client1", NULL,
				    TEST_WITNESS_RESOURCE_IP, 100, &reg_id);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_witness_register_max_global_limit(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	char name[32];
	int i, ret;

	for (i = 0; i < TEST_MAX_WITNESS_REGISTRATIONS; i++) {
		snprintf(name, sizeof(name), "client_%d", i);
		ret = test_witness_register(ctx, name, "shared_res",
					    TEST_WITNESS_RESOURCE_IP,
					    0, &reg_id);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	/* One more should fail */
	ret = test_witness_register(ctx, "overflow", "shared_res",
				    TEST_WITNESS_RESOURCE_IP, 0, &reg_id);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_witness_register_max_per_session_limit(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	char name[32];
	int i, ret;
	u64 sess_id = 42;

	for (i = 0; i < TEST_MAX_WITNESS_REGS_PER_SESSION; i++) {
		snprintf(name, sizeof(name), "client_%d", i);
		ret = test_witness_register(ctx, name, "res1",
					    TEST_WITNESS_RESOURCE_IP,
					    sess_id, &reg_id);
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	/* One more for same session should fail */
	ret = test_witness_register(ctx, "overflow", "res1",
				    TEST_WITNESS_RESOURCE_IP,
				    sess_id, &reg_id);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
}

static void test_witness_unregister_existing(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	int ret;

	test_witness_register(ctx, "client1", "res1",
			      TEST_WITNESS_RESOURCE_IP, 0, &reg_id);

	ret = test_witness_unregister(ctx, reg_id);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_witness_unregister_nonexistent(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	int ret;

	ret = test_witness_unregister(ctx, 99999);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_witness_unregister_double(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	int ret;

	test_witness_register(ctx, "client1", "res1",
			      TEST_WITNESS_RESOURCE_IP, 0, &reg_id);
	ret = test_witness_unregister(ctx, reg_id);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_witness_unregister(ctx, reg_id);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_witness_unregister_session_basic(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	u64 sess_id = 7;
	int i;

	for (i = 0; i < 3; i++) {
		char name[32];

		snprintf(name, sizeof(name), "client_%d", i);
		test_witness_register(ctx, name, "res1",
				      TEST_WITNESS_RESOURCE_IP,
				      sess_id, &reg_id);
	}

	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 3);

	test_witness_unregister_session(ctx, sess_id);
	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 0);
}

static void test_witness_unregister_session_zero_id(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;

	test_witness_register(ctx, "client1", "res1",
			      TEST_WITNESS_RESOURCE_IP, 0, &reg_id);

	/* session_id=0 should be a no-op */
	test_witness_unregister_session(ctx, 0);
	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 1);
}

static void test_witness_unregister_session_no_match(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;

	test_witness_register(ctx, "client1", "res1",
			      TEST_WITNESS_RESOURCE_IP, 1, &reg_id);

	/* Different session ID should not remove anything */
	test_witness_unregister_session(ctx, 999);
	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 1);
}

static void test_witness_registration_count_empty(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;

	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 0);
}

static void test_witness_registration_count_after_register(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;
	int i;

	for (i = 0; i < 5; i++) {
		char name[32];

		snprintf(name, sizeof(name), "client_%d", i);
		test_witness_register(ctx, name, "res1",
				      TEST_WITNESS_RESOURCE_IP, 0, &reg_id);
	}

	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 5);
}

static void test_witness_registration_count_after_unregister(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_ids[3] = {};
	int i;

	for (i = 0; i < 3; i++) {
		char name[32];

		snprintf(name, sizeof(name), "client_%d", i);
		test_witness_register(ctx, name, "res1",
				      TEST_WITNESS_RESOURCE_IP,
				      0, &reg_ids[i]);
	}

	test_witness_unregister(ctx, reg_ids[1]);
	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 2);
}

/*
 * Replicate notify_state_change: set state on a resource and
 * return -ENOENT if resource doesn't exist, 0 if found.
 */
static int test_witness_notify_state_change(struct witness_test_ctx *ctx,
					     const char *resource_name,
					     unsigned int new_state)
{
	struct test_witness_resource *res;

	down_read(&ctx->lock);
	res = __test_resource_lookup(ctx, resource_name);
	if (!res) {
		up_read(&ctx->lock);
		return -ENOENT;
	}
	spin_lock(&res->lock);
	res->state = new_state;
	spin_unlock(&res->lock);
	up_read(&ctx->lock);
	return 0;
}

static void test_witness_notify_state_change_nonexistent(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	int ret;

	ret = test_witness_notify_state_change(ctx, "no_such_resource",
					       TEST_WITNESS_STATE_UNAVAILABLE);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_witness_notify_state_change_no_subscribers(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	int ret;

	/* Add resource but no subscribers */
	test_resource_add(ctx, "lonely_res", TEST_WITNESS_RESOURCE_IP);

	ret = test_witness_notify_state_change(ctx, "lonely_res",
					       TEST_WITNESS_STATE_UNAVAILABLE);
	/* Should succeed even with no subscribers */
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_witness_resource_del_detaches_subscribers(struct kunit *test)
{
	struct witness_test_ctx *ctx = test->priv;
	u32 reg_id = 0;

	test_witness_register(ctx, "client1", "res_to_del",
			      TEST_WITNESS_RESOURCE_IP, 0, &reg_id);
	KUNIT_ASSERT_TRUE(test, test_resource_lookup(ctx, "res_to_del"));

	test_resource_del(ctx, "res_to_del");
	KUNIT_EXPECT_FALSE(test, test_resource_lookup(ctx, "res_to_del"));

	/*
	 * Registration still in global list but detached from resource.
	 * Cleanup will happen in test_exit.
	 */
	KUNIT_EXPECT_EQ(test, test_witness_registration_count(ctx), 1);
}

static struct kunit_case ksmbd_witness_test_cases[] = {
	KUNIT_CASE(test_witness_resource_add_basic),
	KUNIT_CASE(test_witness_resource_add_duplicate),
	KUNIT_CASE(test_witness_resource_add_null_name),
	KUNIT_CASE(test_witness_resource_add_empty_name),
	KUNIT_CASE(test_witness_resource_del_existing),
	KUNIT_CASE(test_witness_resource_del_nonexistent),
	KUNIT_CASE(test_witness_resource_lookup_existing),
	KUNIT_CASE(test_witness_resource_lookup_nonexistent),
	KUNIT_CASE(test_witness_register_basic),
	KUNIT_CASE(test_witness_register_auto_creates_resource),
	KUNIT_CASE(test_witness_register_null_client_name),
	KUNIT_CASE(test_witness_register_null_resource_name),
	KUNIT_CASE(test_witness_register_max_global_limit),
	KUNIT_CASE(test_witness_register_max_per_session_limit),
	KUNIT_CASE(test_witness_unregister_existing),
	KUNIT_CASE(test_witness_unregister_nonexistent),
	KUNIT_CASE(test_witness_unregister_double),
	KUNIT_CASE(test_witness_unregister_session_basic),
	KUNIT_CASE(test_witness_unregister_session_zero_id),
	KUNIT_CASE(test_witness_unregister_session_no_match),
	KUNIT_CASE(test_witness_registration_count_empty),
	KUNIT_CASE(test_witness_registration_count_after_register),
	KUNIT_CASE(test_witness_registration_count_after_unregister),
	KUNIT_CASE(test_witness_resource_del_detaches_subscribers),
	/* notify_state_change tests */
	KUNIT_CASE(test_witness_notify_state_change_nonexistent),
	KUNIT_CASE(test_witness_notify_state_change_no_subscribers),
	{}
};

static struct kunit_suite ksmbd_witness_test_suite = {
	.name = "ksmbd_witness",
	.init = witness_test_init,
	.exit = witness_test_exit,
	.test_cases = ksmbd_witness_test_cases,
};

kunit_test_suite(ksmbd_witness_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd witness protocol state management");
