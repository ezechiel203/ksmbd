// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit tests for oplock.c lease functions:
 *     - alloc_lease(): allocate and initialize lease from lease_ctx_info
 *     - compare_guid_key(): compare ClientGUID + lease key pairs
 *     - add_lease_global_list(): add lease to global lease table
 *
 *   These tests call the production code directly via VISIBLE_IF_KUNIT
 *   exports. No logic is reimplemented.
 */

#include <kunit/test.h>
#include <kunit/visibility.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "oplock.h"
#include "smb2pdu.h"
#include "vfs_cache.h"
#include "connection.h"

/* ====================================================================
 * Helper: allocate a minimal oplock_info for lease tests
 *
 * Uses kunit_kzalloc for automatic cleanup. Does NOT allocate a lease
 * (alloc_lease tests will do that via the production function).
 * ==================================================================== */
static struct oplock_info *alloc_bare_opinfo(struct kunit *test)
{
	struct oplock_info *opinfo;

	opinfo = kunit_kzalloc(test, sizeof(*opinfo), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, opinfo);
	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	opinfo->op_state = OPLOCK_STATE_NONE;
	INIT_LIST_HEAD(&opinfo->op_entry);
	INIT_LIST_HEAD(&opinfo->lease_entry);
	init_waitqueue_head(&opinfo->oplock_q);
	init_waitqueue_head(&opinfo->oplock_brk);
	refcount_set(&opinfo->refcount, 1);
	atomic_set(&opinfo->breaking_cnt, 0);
	return opinfo;
}

/*
 * Helper: allocate a test opinfo with a pre-allocated lease and conn.
 * Used by compare_guid_key and add_lease_global_list tests.
 */
static struct oplock_info *alloc_test_opinfo_with_conn(struct kunit *test)
{
	struct oplock_info *opinfo;
	struct lease *lease;
	struct ksmbd_conn *conn;

	opinfo = alloc_bare_opinfo(test);

	lease = kunit_kzalloc(test, sizeof(*lease), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, lease);
	opinfo->o_lease = lease;
	opinfo->is_lease = true;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn);
	refcount_set(&conn->refcnt, 1);
	opinfo->conn = conn;

	return opinfo;
}

/* ====================================================================
 * Section 1: alloc_lease() tests
 * ==================================================================== */

/*
 * test_alloc_lease_basic - alloc_lease allocates and initializes fields
 */
static void test_alloc_lease_basic(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_bare_opinfo(test);
	struct lease_ctx_info lctx = {};
	int rc;

	/* Fill lctx with known values */
	memset(lctx.lease_key, 0xAA, SMB2_LEASE_KEY_SIZE);
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_WRITE_CACHING_LE;
	lctx.flags = cpu_to_le32(0x04);
	lctx.duration = cpu_to_le64(0);
	lctx.is_dir = false;
	memset(lctx.parent_lease_key, 0xBB, SMB2_LEASE_KEY_SIZE);
	lctx.version = 2;
	lctx.epoch = cpu_to_le16(5);

	rc = alloc_lease(opinfo, &lctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_ASSERT_NOT_NULL(test, opinfo->o_lease);

	/* Verify all fields were copied correctly */
	KUNIT_EXPECT_EQ(test,
			memcmp(opinfo->o_lease->lease_key, lctx.lease_key,
			       SMB2_LEASE_KEY_SIZE), 0);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->state, lctx.req_state);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->new_state, (__le32)0);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->flags, lctx.flags);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->duration, lctx.duration);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->is_dir, false);
	KUNIT_EXPECT_EQ(test,
			memcmp(opinfo->o_lease->parent_lease_key,
			       lctx.parent_lease_key, SMB2_LEASE_KEY_SIZE), 0);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->version, 2);
	/* epoch is le16_to_cpu(lctx.epoch) */
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->epoch,
			(unsigned short)le16_to_cpu(lctx.epoch));
	KUNIT_EXPECT_NULL(test, opinfo->o_lease->l_lb);

	/* Verify lease_entry was initialized */
	KUNIT_EXPECT_TRUE(test, list_empty(&opinfo->lease_entry));

	/* Clean up the kmalloc'd lease (not kunit-managed) */
	kfree(opinfo->o_lease);
}

/*
 * test_alloc_lease_dir - alloc_lease with is_dir=true
 */
static void test_alloc_lease_dir(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_bare_opinfo(test);
	struct lease_ctx_info lctx = {};
	int rc;

	memset(lctx.lease_key, 0x11, SMB2_LEASE_KEY_SIZE);
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_HANDLE_CACHING_LE;
	lctx.is_dir = true;
	lctx.version = 2;
	lctx.epoch = cpu_to_le16(1);

	rc = alloc_lease(opinfo, &lctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->is_dir, true);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->state,
			SMB2_LEASE_READ_CACHING_LE |
			SMB2_LEASE_HANDLE_CACHING_LE);

	kfree(opinfo->o_lease);
}

/*
 * test_alloc_lease_v1 - alloc_lease with version 1 (no parent key)
 */
static void test_alloc_lease_v1(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_bare_opinfo(test);
	struct lease_ctx_info lctx = {};
	int rc;

	memset(lctx.lease_key, 0x55, SMB2_LEASE_KEY_SIZE);
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE;
	lctx.version = 1;
	lctx.epoch = cpu_to_le16(0);

	rc = alloc_lease(opinfo, &lctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->version, 1);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->epoch, (unsigned short)0);

	kfree(opinfo->o_lease);
}

/*
 * test_alloc_lease_none_state - alloc_lease with NONE state
 */
static void test_alloc_lease_none_state(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_bare_opinfo(test);
	struct lease_ctx_info lctx = {};
	int rc;

	memset(lctx.lease_key, 0xFF, SMB2_LEASE_KEY_SIZE);
	lctx.req_state = SMB2_LEASE_NONE_LE;
	lctx.version = 1;

	rc = alloc_lease(opinfo, &lctx);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->state, SMB2_LEASE_NONE_LE);

	kfree(opinfo->o_lease);
}

/* ====================================================================
 * Section 2: compare_guid_key() tests
 * ==================================================================== */

/*
 * test_compare_guid_key_equal - matching GUID and key returns 1
 */
static void test_compare_guid_key_equal(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	char guid[SMB2_CLIENT_GUID_SIZE];
	char key[SMB2_LEASE_KEY_SIZE];
	int ret;

	memset(guid, 0xAA, SMB2_CLIENT_GUID_SIZE);
	memset(key, 0xBB, SMB2_LEASE_KEY_SIZE);

	/* Set opinfo's conn GUID and lease key to same values */
	memcpy(opinfo->conn->ClientGUID, guid, SMB2_CLIENT_GUID_SIZE);
	memcpy(opinfo->o_lease->lease_key, key, SMB2_LEASE_KEY_SIZE);

	ret = compare_guid_key(opinfo, guid, key);
	KUNIT_EXPECT_EQ(test, ret, 1);
}

/*
 * test_compare_guid_key_diff_guid - different GUID returns 0
 */
static void test_compare_guid_key_diff_guid(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	char guid1[SMB2_CLIENT_GUID_SIZE];
	char guid2[SMB2_CLIENT_GUID_SIZE];
	char key[SMB2_LEASE_KEY_SIZE];
	int ret;

	memset(guid1, 0xAA, SMB2_CLIENT_GUID_SIZE);
	memset(guid2, 0xCC, SMB2_CLIENT_GUID_SIZE);
	memset(key, 0xBB, SMB2_LEASE_KEY_SIZE);

	memcpy(opinfo->conn->ClientGUID, guid1, SMB2_CLIENT_GUID_SIZE);
	memcpy(opinfo->o_lease->lease_key, key, SMB2_LEASE_KEY_SIZE);

	/* Pass different GUID */
	ret = compare_guid_key(opinfo, guid2, key);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_compare_guid_key_diff_key - different lease key returns 0
 */
static void test_compare_guid_key_diff_key(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	char guid[SMB2_CLIENT_GUID_SIZE];
	char key1[SMB2_LEASE_KEY_SIZE];
	char key2[SMB2_LEASE_KEY_SIZE];
	int ret;

	memset(guid, 0xAA, SMB2_CLIENT_GUID_SIZE);
	memset(key1, 0xBB, SMB2_LEASE_KEY_SIZE);
	memset(key2, 0xDD, SMB2_LEASE_KEY_SIZE);

	memcpy(opinfo->conn->ClientGUID, guid, SMB2_CLIENT_GUID_SIZE);
	memcpy(opinfo->o_lease->lease_key, key1, SMB2_LEASE_KEY_SIZE);

	/* Pass different key */
	ret = compare_guid_key(opinfo, guid, key2);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_compare_guid_key_both_diff - both GUID and key differ returns 0
 */
static void test_compare_guid_key_both_diff(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	char guid1[SMB2_CLIENT_GUID_SIZE];
	char guid2[SMB2_CLIENT_GUID_SIZE];
	char key1[SMB2_LEASE_KEY_SIZE];
	char key2[SMB2_LEASE_KEY_SIZE];
	int ret;

	memset(guid1, 0x11, SMB2_CLIENT_GUID_SIZE);
	memset(guid2, 0x22, SMB2_CLIENT_GUID_SIZE);
	memset(key1, 0x33, SMB2_LEASE_KEY_SIZE);
	memset(key2, 0x44, SMB2_LEASE_KEY_SIZE);

	memcpy(opinfo->conn->ClientGUID, guid1, SMB2_CLIENT_GUID_SIZE);
	memcpy(opinfo->o_lease->lease_key, key1, SMB2_LEASE_KEY_SIZE);

	ret = compare_guid_key(opinfo, guid2, key2);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_compare_guid_key_zero - all-zero GUID and key match
 */
static void test_compare_guid_key_zero(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	char guid[SMB2_CLIENT_GUID_SIZE];
	char key[SMB2_LEASE_KEY_SIZE];
	int ret;

	memset(guid, 0, SMB2_CLIENT_GUID_SIZE);
	memset(key, 0, SMB2_LEASE_KEY_SIZE);

	memset(opinfo->conn->ClientGUID, 0, SMB2_CLIENT_GUID_SIZE);
	memset(opinfo->o_lease->lease_key, 0, SMB2_LEASE_KEY_SIZE);

	ret = compare_guid_key(opinfo, guid, key);
	KUNIT_EXPECT_EQ(test, ret, 1);
}

/*
 * test_compare_guid_key_one_byte_diff - single byte difference detected
 */
static void test_compare_guid_key_one_byte_diff(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	char guid[SMB2_CLIENT_GUID_SIZE];
	char key[SMB2_LEASE_KEY_SIZE];
	int ret;

	memset(guid, 0xAA, SMB2_CLIENT_GUID_SIZE);
	memset(key, 0xBB, SMB2_LEASE_KEY_SIZE);

	memcpy(opinfo->conn->ClientGUID, guid, SMB2_CLIENT_GUID_SIZE);
	memcpy(opinfo->o_lease->lease_key, key, SMB2_LEASE_KEY_SIZE);

	/* Flip last byte of GUID */
	guid[SMB2_CLIENT_GUID_SIZE - 1] = 0xAB;
	ret = compare_guid_key(opinfo, guid, key);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Restore GUID, flip last byte of key */
	guid[SMB2_CLIENT_GUID_SIZE - 1] = 0xAA;
	key[SMB2_LEASE_KEY_SIZE - 1] = 0xBC;
	ret = compare_guid_key(opinfo, guid, key);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* ====================================================================
 * Section 3: add_lease_global_list() tests
 * ==================================================================== */

/*
 * test_add_lease_global_list_new_client - first lease for a new client
 *
 * add_lease_global_list should create a new lease_table for the client
 * GUID and add the opinfo's lease to it.
 */
static void test_add_lease_global_list_new_client(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo_with_conn(test);
	int rc;

	memset(opinfo->conn->ClientGUID, 0xEE, SMB2_CLIENT_GUID_SIZE);
	memset(opinfo->o_lease->lease_key, 0xFF, SMB2_LEASE_KEY_SIZE);

	rc = add_lease_global_list(opinfo);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* After add, l_lb should be set (lease table assigned) */
	KUNIT_ASSERT_NOT_NULL(test, opinfo->o_lease->l_lb);

	/* The lease entry should be in the table's list (not empty) */
	KUNIT_EXPECT_FALSE(test, list_empty(&opinfo->lease_entry));

	/* Client GUID in the lease table should match */
	KUNIT_EXPECT_EQ(test,
			memcmp(opinfo->o_lease->l_lb->client_guid,
			       opinfo->conn->ClientGUID,
			       SMB2_CLIENT_GUID_SIZE), 0);

	/*
	 * Cleanup: remove from global list to avoid affecting other tests.
	 * We must remove under the lease table lock, then free the table.
	 */
	{
		struct lease_table *lb = opinfo->o_lease->l_lb;

		spin_lock(&lb->lb_lock);
		list_del_init(&opinfo->lease_entry);
		spin_unlock(&lb->lb_lock);
		/* Note: the lease_table is in the global list and will be
		 * cleaned up by destroy_lease_table or module exit.
		 * For test isolation, we accept this minor leak.
		 */
	}
}

/*
 * test_add_lease_global_list_same_client - second lease for same client
 *
 * Adding a second opinfo with the same ClientGUID should reuse the
 * existing lease_table (not create a duplicate).
 */
static void test_add_lease_global_list_same_client(struct kunit *test)
{
	struct oplock_info *op1 = alloc_test_opinfo_with_conn(test);
	struct oplock_info *op2 = alloc_test_opinfo_with_conn(test);
	int rc;

	/* Same client GUID for both */
	memset(op1->conn->ClientGUID, 0xDD, SMB2_CLIENT_GUID_SIZE);
	memset(op2->conn->ClientGUID, 0xDD, SMB2_CLIENT_GUID_SIZE);

	memset(op1->o_lease->lease_key, 0x11, SMB2_LEASE_KEY_SIZE);
	memset(op2->o_lease->lease_key, 0x22, SMB2_LEASE_KEY_SIZE);

	rc = add_lease_global_list(op1);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = add_lease_global_list(op2);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Both should share the same lease_table */
	KUNIT_ASSERT_NOT_NULL(test, op1->o_lease->l_lb);
	KUNIT_ASSERT_NOT_NULL(test, op2->o_lease->l_lb);
	KUNIT_EXPECT_PTR_EQ(test, op1->o_lease->l_lb, op2->o_lease->l_lb);

	/* Both should be in the lease list */
	KUNIT_EXPECT_FALSE(test, list_empty(&op1->lease_entry));
	KUNIT_EXPECT_FALSE(test, list_empty(&op2->lease_entry));

	/* Cleanup */
	{
		struct lease_table *lb = op1->o_lease->l_lb;

		spin_lock(&lb->lb_lock);
		list_del_init(&op1->lease_entry);
		list_del_init(&op2->lease_entry);
		spin_unlock(&lb->lb_lock);
	}
}

/*
 * test_add_lease_global_list_diff_client - different clients get separate tables
 */
static void test_add_lease_global_list_diff_client(struct kunit *test)
{
	struct oplock_info *op1 = alloc_test_opinfo_with_conn(test);
	struct oplock_info *op2 = alloc_test_opinfo_with_conn(test);
	int rc;

	/* Different client GUIDs */
	memset(op1->conn->ClientGUID, 0xAA, SMB2_CLIENT_GUID_SIZE);
	memset(op2->conn->ClientGUID, 0xBB, SMB2_CLIENT_GUID_SIZE);

	memset(op1->o_lease->lease_key, 0x11, SMB2_LEASE_KEY_SIZE);
	memset(op2->o_lease->lease_key, 0x22, SMB2_LEASE_KEY_SIZE);

	rc = add_lease_global_list(op1);
	KUNIT_ASSERT_EQ(test, rc, 0);

	rc = add_lease_global_list(op2);
	KUNIT_ASSERT_EQ(test, rc, 0);

	/* Should have different lease tables */
	KUNIT_ASSERT_NOT_NULL(test, op1->o_lease->l_lb);
	KUNIT_ASSERT_NOT_NULL(test, op2->o_lease->l_lb);
	KUNIT_EXPECT_NE(test, (unsigned long)op1->o_lease->l_lb,
			(unsigned long)op2->o_lease->l_lb);

	/* Cleanup */
	{
		struct lease_table *lb1 = op1->o_lease->l_lb;
		struct lease_table *lb2 = op2->o_lease->l_lb;

		spin_lock(&lb1->lb_lock);
		list_del_init(&op1->lease_entry);
		spin_unlock(&lb1->lb_lock);

		spin_lock(&lb2->lb_lock);
		list_del_init(&op2->lease_entry);
		spin_unlock(&lb2->lb_lock);
	}
}

static struct kunit_case ksmbd_oplock_lease_test_cases[] = {
	/* alloc_lease() tests */
	KUNIT_CASE(test_alloc_lease_basic),
	KUNIT_CASE(test_alloc_lease_dir),
	KUNIT_CASE(test_alloc_lease_v1),
	KUNIT_CASE(test_alloc_lease_none_state),
	/* compare_guid_key() tests */
	KUNIT_CASE(test_compare_guid_key_equal),
	KUNIT_CASE(test_compare_guid_key_diff_guid),
	KUNIT_CASE(test_compare_guid_key_diff_key),
	KUNIT_CASE(test_compare_guid_key_both_diff),
	KUNIT_CASE(test_compare_guid_key_zero),
	KUNIT_CASE(test_compare_guid_key_one_byte_diff),
	/* add_lease_global_list() tests */
	KUNIT_CASE(test_add_lease_global_list_new_client),
	KUNIT_CASE(test_add_lease_global_list_same_client),
	KUNIT_CASE(test_add_lease_global_list_diff_client),
	{}
};

static struct kunit_suite ksmbd_oplock_lease_test_suite = {
	.name = "ksmbd_oplock_lease",
	.test_cases = ksmbd_oplock_lease_test_cases,
};

kunit_test_suite(ksmbd_oplock_lease_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd oplock lease functions");
