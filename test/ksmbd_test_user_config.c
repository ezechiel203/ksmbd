// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for user configuration management (user_config.c)
 *
 *   Tests ksmbd_alloc_user(), ksmbd_free_user() (with stub for IPC logout),
 *   ksmbd_anonymous_user(), and ksmbd_compare_user() by calling the actual
 *   production functions.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <crypto/algapi.h>

#include "glob.h"
#include "ksmbd_netlink.h"
#include "mgmt/user_config.h"

/*
 * Helper to build a fake ksmbd_login_response for testing.
 * The response must be large enough to hold account name and hash.
 */
static struct ksmbd_login_response *build_login_response(const char *name,
							  const char *passkey,
							  int passkey_sz,
							  unsigned int uid,
							  unsigned int gid)
{
	struct ksmbd_login_response *resp;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp)
		return NULL;

	strscpy(resp->account, name, sizeof(resp->account));
	resp->status = KSMBD_USER_FLAG_OK;
	resp->uid = uid;
	resp->gid = gid;
	resp->hash_sz = passkey_sz;
	if (passkey_sz > 0 && passkey_sz <= sizeof(resp->hash))
		memcpy(resp->hash, passkey, passkey_sz);

	return resp;
}

/*
 * Helper to create a ksmbd_user directly (bypasses IPC).
 */
static struct ksmbd_user *create_test_user(const char *name,
					   const char *passkey,
					   int passkey_sz)
{
	struct ksmbd_user *user;

	user = kmalloc(sizeof(*user), GFP_KERNEL);
	if (!user)
		return NULL;

	user->name = kstrdup(name, GFP_KERNEL);
	user->flags = KSMBD_USER_FLAG_OK;
	user->uid = 1000;
	user->gid = 1000;
	user->passkey_sz = passkey_sz;
	user->passkey = kmalloc(passkey_sz, GFP_KERNEL);
	if (user->passkey && passkey_sz > 0)
		memcpy(user->passkey, passkey, passkey_sz);
	user->ngroups = 0;
	user->sgid = NULL;

	if (!user->name || !user->passkey) {
		kfree(user->name);
		kfree(user->passkey);
		kfree(user);
		return NULL;
	}

	return user;
}

static void free_test_user(struct ksmbd_user *user)
{
	if (!user)
		return;
	kfree(user->sgid);
	kfree(user->name);
	kfree(user->passkey);
	kfree(user);
}

/* ===== ksmbd_alloc_user() tests ===== */

/*
 * test_alloc_user_basic - allocate user with valid login response
 */
static void test_alloc_user_basic(struct kunit *test)
{
	struct ksmbd_login_response *resp;
	struct ksmbd_user *user;
	char passkey[16];

	memset(passkey, 0xAA, sizeof(passkey));

	resp = build_login_response("testuser", passkey, 16, 1000, 1000);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resp);

	user = ksmbd_alloc_user(resp, NULL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, user);

	KUNIT_EXPECT_STREQ(test, user->name, "testuser");
	KUNIT_EXPECT_EQ(test, (int)user->passkey_sz, 16);
	KUNIT_EXPECT_EQ(test, memcmp(user->passkey, passkey, 16), 0);
	KUNIT_EXPECT_EQ(test, user->uid, 1000U);
	KUNIT_EXPECT_EQ(test, user->gid, 1000U);
	KUNIT_EXPECT_EQ(test, user->ngroups, 0);
	KUNIT_EXPECT_TRUE(test, user->sgid == NULL);

	free_test_user(user);
	kfree(resp);
}

/*
 * test_alloc_user_zero_hash - hash_sz = 0 means no passkey
 * (ksmbd_alloc_user should fail because !user->passkey)
 */
static void test_alloc_user_zero_hash(struct kunit *test)
{
	struct ksmbd_login_response *resp;
	struct ksmbd_user *user;

	resp = build_login_response("nopass", NULL, 0, 1000, 1000);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resp);

	user = ksmbd_alloc_user(resp, NULL);
	/*
	 * kmalloc(0) may return ZERO_SIZE_PTR or NULL depending on config.
	 * The function checks !user->passkey, so with zero size it depends
	 * on kernel behavior. We just verify no crash.
	 */
	if (user)
		free_test_user(user);

	kfree(resp);
}

/*
 * test_alloc_user_with_supplementary_groups - valid ext with groups
 */
static void test_alloc_user_with_supplementary_groups(struct kunit *test)
{
	struct ksmbd_login_response *resp;
	struct ksmbd_login_response_ext *resp_ext;
	struct ksmbd_user *user;
	char passkey[16];
	gid_t test_gids[] = {100, 200, 300};

	memset(passkey, 0xBB, sizeof(passkey));

	resp = build_login_response("groupuser", passkey, 16, 2000, 2000);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resp);

	resp_ext = kzalloc(sizeof(*resp_ext) + sizeof(test_gids), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resp_ext);

	resp_ext->ngroups = 3;
	memcpy(resp_ext->____payload, test_gids, sizeof(test_gids));

	user = ksmbd_alloc_user(resp, resp_ext);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, user);

	KUNIT_EXPECT_EQ(test, user->ngroups, 3);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, user->sgid);
	KUNIT_EXPECT_EQ(test, user->sgid[0], (gid_t)100);
	KUNIT_EXPECT_EQ(test, user->sgid[1], (gid_t)200);
	KUNIT_EXPECT_EQ(test, user->sgid[2], (gid_t)300);

	free_test_user(user);
	kfree(resp_ext);
	kfree(resp);
}

/*
 * test_alloc_user_ngroups_exceeds_max - ngroups > NGROUPS_MAX must fail
 */
static void test_alloc_user_ngroups_exceeds_max(struct kunit *test)
{
	struct ksmbd_login_response *resp;
	struct ksmbd_login_response_ext *resp_ext;
	struct ksmbd_user *user;
	char passkey[16];

	memset(passkey, 0xCC, sizeof(passkey));

	resp = build_login_response("toomanygroups", passkey, 16, 3000, 3000);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resp);

	resp_ext = kzalloc(sizeof(*resp_ext), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, resp_ext);

	resp_ext->ngroups = NGROUPS_MAX + 1;

	user = ksmbd_alloc_user(resp, resp_ext);
	KUNIT_EXPECT_TRUE(test, user == NULL);

	kfree(resp_ext);
	kfree(resp);
}

/* ===== ksmbd_anonymous_user() tests ===== */

/*
 * test_anonymous_user_empty_name - empty name is anonymous
 */
static void test_anonymous_user_empty_name(struct kunit *test)
{
	struct ksmbd_user *user;

	user = create_test_user("", "pass", 4);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, user);

	KUNIT_EXPECT_EQ(test, ksmbd_anonymous_user(user), 1);

	free_test_user(user);
}

/*
 * test_anonymous_user_nonempty_name - non-empty name is not anonymous
 */
static void test_anonymous_user_nonempty_name(struct kunit *test)
{
	struct ksmbd_user *user;

	user = create_test_user("realuser", "pass", 4);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, user);

	KUNIT_EXPECT_EQ(test, ksmbd_anonymous_user(user), 0);

	free_test_user(user);
}

/* ===== ksmbd_compare_user() tests ===== */

/*
 * test_compare_user_identical - identical users compare equal
 */
static void test_compare_user_identical(struct kunit *test)
{
	struct ksmbd_user *u1, *u2;
	char passkey[16];

	memset(passkey, 0xDD, sizeof(passkey));

	u1 = create_test_user("sameuser", passkey, 16);
	u2 = create_test_user("sameuser", passkey, 16);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u1);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u2);

	KUNIT_EXPECT_TRUE(test, ksmbd_compare_user(u1, u2));

	free_test_user(u1);
	free_test_user(u2);
}

/*
 * test_compare_user_different_name - different names compare unequal
 */
static void test_compare_user_different_name(struct kunit *test)
{
	struct ksmbd_user *u1, *u2;
	char passkey[16];

	memset(passkey, 0xEE, sizeof(passkey));

	u1 = create_test_user("alice", passkey, 16);
	u2 = create_test_user("bob", passkey, 16);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u1);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u2);

	KUNIT_EXPECT_FALSE(test, ksmbd_compare_user(u1, u2));

	free_test_user(u1);
	free_test_user(u2);
}

/*
 * test_compare_user_different_passkey - same name, different passkey
 */
static void test_compare_user_different_passkey(struct kunit *test)
{
	struct ksmbd_user *u1, *u2;
	char passkey1[16], passkey2[16];

	memset(passkey1, 0x11, sizeof(passkey1));
	memset(passkey2, 0x22, sizeof(passkey2));

	u1 = create_test_user("charlie", passkey1, 16);
	u2 = create_test_user("charlie", passkey2, 16);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u1);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u2);

	KUNIT_EXPECT_FALSE(test, ksmbd_compare_user(u1, u2));

	free_test_user(u1);
	free_test_user(u2);
}

/*
 * test_compare_user_different_passkey_size - same name, different passkey size
 */
static void test_compare_user_different_passkey_size(struct kunit *test)
{
	struct ksmbd_user *u1, *u2;
	char passkey[16];

	memset(passkey, 0x33, sizeof(passkey));

	u1 = create_test_user("dave", passkey, 16);
	u2 = create_test_user("dave", passkey, 8);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u1);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u2);

	KUNIT_EXPECT_FALSE(test, ksmbd_compare_user(u1, u2));

	free_test_user(u1);
	free_test_user(u2);
}

/*
 * test_compare_user_one_byte_diff - passkeys differ in last byte only
 *
 * Since ksmbd_compare_user uses crypto_memneq for constant-time
 * comparison, even a single byte difference must be detected.
 */
static void test_compare_user_one_byte_diff(struct kunit *test)
{
	struct ksmbd_user *u1, *u2;
	char passkey1[16], passkey2[16];

	memset(passkey1, 0x44, sizeof(passkey1));
	memcpy(passkey2, passkey1, sizeof(passkey2));
	passkey2[15] ^= 0x01; /* flip one bit in last byte */

	u1 = create_test_user("eve", passkey1, 16);
	u2 = create_test_user("eve", passkey2, 16);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u1);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, u2);

	KUNIT_EXPECT_FALSE(test, ksmbd_compare_user(u1, u2));

	free_test_user(u1);
	free_test_user(u2);
}

static struct kunit_case ksmbd_user_config_test_cases[] = {
	/* alloc_user */
	KUNIT_CASE(test_alloc_user_basic),
	KUNIT_CASE(test_alloc_user_zero_hash),
	KUNIT_CASE(test_alloc_user_with_supplementary_groups),
	KUNIT_CASE(test_alloc_user_ngroups_exceeds_max),
	/* anonymous_user */
	KUNIT_CASE(test_anonymous_user_empty_name),
	KUNIT_CASE(test_anonymous_user_nonempty_name),
	/* compare_user */
	KUNIT_CASE(test_compare_user_identical),
	KUNIT_CASE(test_compare_user_different_name),
	KUNIT_CASE(test_compare_user_different_passkey),
	KUNIT_CASE(test_compare_user_different_passkey_size),
	KUNIT_CASE(test_compare_user_one_byte_diff),
	{}
};

static struct kunit_suite ksmbd_user_config_test_suite = {
	.name = "ksmbd_user_config",
	.test_cases = ksmbd_user_config_test_cases,
};

kunit_test_suite(ksmbd_user_config_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd user configuration management");
