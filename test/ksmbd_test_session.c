// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for session management (user_session.c)
 *
 *   Tests the session lifecycle functions that can be called directly
 *   without requiring full IPC infrastructure. For functions that need
 *   kernel-userspace IPC (RPC, login), we test the static helpers and
 *   structural invariants.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xarray.h>
#include <linux/rwsem.h>
#include <linux/refcount.h>

#include "smb_common.h"
#include "smb2pdu.h"
#include "mgmt/user_session.h"
#include "mgmt/user_config.h"
#include "connection.h"

/*
 * Helper to create a minimal mock connection for session registration.
 * Only initializes the fields used by session register/lookup.
 */
static struct ksmbd_conn *create_mock_conn(void)
{
	struct ksmbd_conn *conn;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return NULL;

	xa_init(&conn->sessions);
	init_rwsem(&conn->session_lock);
	INIT_LIST_HEAD(&conn->preauth_sess_table);
	conn->dialect = SMB311_PROT_ID;

	return conn;
}

static void destroy_mock_conn(struct ksmbd_conn *conn)
{
	if (!conn)
		return;
	xa_destroy(&conn->sessions);
	kfree(conn);
}

/* ===== ksmbd_smb2_session_create() tests ===== */

/*
 * test_smb2_session_create - creates a session with valid ID
 */
static void test_smb2_session_create(struct kunit *test)
{
	struct ksmbd_session *sess;

	sess = ksmbd_smb2_session_create();
	if (!sess) {
		kunit_skip(test, "ksmbd_smb2_session_create returned NULL (IDA exhaustion)");
		return;
	}

	KUNIT_EXPECT_GT(test, (unsigned long long)sess->id, 0ULL);

	/* Clean up -- need to manually free since destroy calls IPC */
	/* Just release the session fields we can without IPC */
	memzero_explicit(sess->sess_key, sizeof(sess->sess_key));
	kfree_sensitive(sess->Preauth_HashValue);
	xa_destroy(&sess->ksmbd_chann_list);
	xa_destroy(&sess->tree_conns);
	xa_destroy(&sess->rpc_handle_list);
	ida_destroy(&sess->tree_conn_ida);
	kfree_sensitive(sess);
}

/*
 * test_smb2_session_create_initializes_fields - check initial field values
 */
static void test_smb2_session_create_initializes_fields(struct kunit *test)
{
	struct ksmbd_session *sess;

	sess = ksmbd_smb2_session_create();
	if (!sess) {
		kunit_skip(test, "ksmbd_smb2_session_create returned NULL");
		return;
	}

	/* Session must start in IN_PROGRESS state */
	KUNIT_EXPECT_EQ(test, sess->state, SMB2_SESSION_IN_PROGRESS);

	/* refcnt should be 2 (1 for caller + 1 for global table) */
	KUNIT_EXPECT_EQ(test, (int)refcount_read(&sess->refcnt), 2);

	/* sequence_number starts at 1 */
	KUNIT_EXPECT_EQ(test, sess->sequence_number, 1U);

	/* User should be NULL initially */
	KUNIT_EXPECT_TRUE(test, sess->user == NULL);

	/* Flags should indicate SMB2 */
	KUNIT_EXPECT_TRUE(test, test_session_flag(sess, CIFDS_SESSION_FLAG_SMB2));

	/* Clean up */
	kfree_sensitive(sess->Preauth_HashValue);
	xa_destroy(&sess->ksmbd_chann_list);
	xa_destroy(&sess->tree_conns);
	xa_destroy(&sess->rpc_handle_list);
	ida_destroy(&sess->tree_conn_ida);
	kfree_sensitive(sess);
}

/* ===== Session flag helpers ===== */

/*
 * test_session_flag_set_clear - test_session_flag, set_session_flag, clear_session_flag
 */
static void test_session_flag_set_clear(struct kunit *test)
{
	struct ksmbd_session sess;

	memset(&sess, 0, sizeof(sess));

	KUNIT_EXPECT_FALSE(test, test_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2));

	set_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2);
	KUNIT_EXPECT_TRUE(test, test_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2));

	clear_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2);
	KUNIT_EXPECT_FALSE(test, test_session_flag(&sess, CIFDS_SESSION_FLAG_SMB2));
}

/* ===== Session put NULL safety ===== */

/*
 * test_session_put_null - ksmbd_user_session_put(NULL) must not crash
 */
static void test_session_put_null(struct kunit *test)
{
	ksmbd_user_session_put(NULL);
	KUNIT_SUCCEED(test);
}

/* ===== Preauth session tests ===== */

/*
 * test_preauth_session_alloc_lookup - alloc + lookup round-trip
 */
static void test_preauth_session_alloc_lookup(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct preauth_session *preauth;
	struct preauth_integrity_info preauth_info;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	/* Set up minimal preauth_info */
	memset(&preauth_info, 0, sizeof(preauth_info));
	memset(preauth_info.Preauth_HashValue, 0xAA, PREAUTH_HASHVALUE_SIZE);
	conn->preauth_info = &preauth_info;

	down_write(&conn->session_lock);
	preauth = ksmbd_preauth_session_alloc(conn, 42);
	up_write(&conn->session_lock);

	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, preauth);
	KUNIT_EXPECT_EQ(test, (unsigned long long)preauth->id, 42ULL);

	/* Verify the preauth hash was copied */
	KUNIT_EXPECT_EQ(test, memcmp(preauth->Preauth_HashValue,
				     preauth_info.Preauth_HashValue,
				     PREAUTH_HASHVALUE_SIZE), 0);

	/* Lookup should find it */
	{
		struct preauth_session *found;

		down_read(&conn->session_lock);
		found = ksmbd_preauth_session_lookup(conn, 42);
		up_read(&conn->session_lock);
		KUNIT_EXPECT_PTR_EQ(test, found, preauth);
	}

	/* Cleanup */
	list_del(&preauth->preauth_entry);
	kfree(preauth);
	conn->preauth_info = NULL;
	destroy_mock_conn(conn);
}

/*
 * test_preauth_session_lookup_nonexistent - lookup non-existent ID
 */
static void test_preauth_session_lookup_nonexistent(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct preauth_session *found;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	down_read(&conn->session_lock);
	found = ksmbd_preauth_session_lookup(conn, 99999);
	up_read(&conn->session_lock);

	KUNIT_EXPECT_TRUE(test, found == NULL);

	destroy_mock_conn(conn);
}

/*
 * test_preauth_session_remove - alloc, then remove
 */
static void test_preauth_session_remove(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct preauth_session *preauth;
	struct preauth_integrity_info preauth_info;
	int rc;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	memset(&preauth_info, 0, sizeof(preauth_info));
	conn->preauth_info = &preauth_info;

	down_write(&conn->session_lock);
	preauth = ksmbd_preauth_session_alloc(conn, 100);
	up_write(&conn->session_lock);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, preauth);

	down_write(&conn->session_lock);
	rc = ksmbd_preauth_session_remove(conn, 100);
	up_write(&conn->session_lock);
	KUNIT_EXPECT_EQ(test, rc, 0);

	/* Subsequent lookup should return NULL */
	{
		struct preauth_session *found;

		down_read(&conn->session_lock);
		found = ksmbd_preauth_session_lookup(conn, 100);
		up_read(&conn->session_lock);
		KUNIT_EXPECT_TRUE(test, found == NULL);
	}

	conn->preauth_info = NULL;
	destroy_mock_conn(conn);
}

/*
 * test_preauth_session_remove_nonexistent - remove non-existent ID
 */
static void test_preauth_session_remove_nonexistent(struct kunit *test)
{
	struct ksmbd_conn *conn;
	int rc;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	down_write(&conn->session_lock);
	rc = ksmbd_preauth_session_remove(conn, 77777);
	up_write(&conn->session_lock);

	KUNIT_EXPECT_EQ(test, rc, -ENOENT);

	destroy_mock_conn(conn);
}

/* ===== Session in connection test ===== */

/*
 * test_session_in_connection_false - non-existent session
 */
static void test_session_in_connection_false(struct kunit *test)
{
	struct ksmbd_conn *conn;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	KUNIT_EXPECT_FALSE(test, is_ksmbd_session_in_connection(conn, 12345));

	destroy_mock_conn(conn);
}

/* ===== Session lookup tests ===== */

/*
 * test_session_lookup_nonexistent - lookup non-existent session ID
 */
static void test_session_lookup_nonexistent(struct kunit *test)
{
	struct ksmbd_conn *conn;
	struct ksmbd_session *found;

	conn = create_mock_conn();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);

	found = ksmbd_session_lookup(conn, 99999);
	KUNIT_EXPECT_TRUE(test, found == NULL);

	destroy_mock_conn(conn);
}

/* ===== Tree conn ID tests ===== */

/*
 * test_acquire_release_tree_conn_id - basic tree conn ID lifecycle
 */
static void test_acquire_release_tree_conn_id(struct kunit *test)
{
	struct ksmbd_session sess;
	int id;

	memset(&sess, 0, sizeof(sess));
	ida_init(&sess.tree_conn_ida);

	id = ksmbd_acquire_tree_conn_id(&sess);
	KUNIT_EXPECT_GE(test, id, 0);

	ksmbd_release_tree_conn_id(&sess, id);

	/* Should be able to reacquire */
	{
		int id2 = ksmbd_acquire_tree_conn_id(&sess);

		KUNIT_EXPECT_GE(test, id2, 0);
		ksmbd_release_tree_conn_id(&sess, id2);
	}

	ida_destroy(&sess.tree_conn_ida);
}

/*
 * test_acquire_multiple_tree_conn_ids - acquire several IDs, all unique
 */
static void test_acquire_multiple_tree_conn_ids(struct kunit *test)
{
	struct ksmbd_session sess;
	int ids[4];
	int i, j;

	memset(&sess, 0, sizeof(sess));
	ida_init(&sess.tree_conn_ida);

	for (i = 0; i < 4; i++) {
		ids[i] = ksmbd_acquire_tree_conn_id(&sess);
		KUNIT_EXPECT_GE(test, ids[i], 0);
	}

	/* All IDs should be unique */
	for (i = 0; i < 4; i++) {
		for (j = i + 1; j < 4; j++)
			KUNIT_EXPECT_NE(test, ids[i], ids[j]);
	}

	for (i = 0; i < 4; i++)
		ksmbd_release_tree_conn_id(&sess, ids[i]);

	ida_destroy(&sess.tree_conn_ida);
}

#ifdef CONFIG_SMB_INSECURE_SERVER
/*
 * test_smb1_session_create - SMB1 session creation
 */
static void test_smb1_session_create(struct kunit *test)
{
	struct ksmbd_session *sess;

	sess = ksmbd_smb1_session_create();
	if (!sess) {
		kunit_skip(test, "ksmbd_smb1_session_create returned NULL");
		return;
	}

	KUNIT_EXPECT_GT(test, (unsigned long long)sess->id, 0ULL);
	KUNIT_EXPECT_TRUE(test, test_session_flag(sess, CIFDS_SESSION_FLAG_SMB1));

	/* Clean up */
	kfree_sensitive(sess->Preauth_HashValue);
	xa_destroy(&sess->ksmbd_chann_list);
	xa_destroy(&sess->tree_conns);
	xa_destroy(&sess->rpc_handle_list);
	ida_destroy(&sess->tree_conn_ida);
	kfree_sensitive(sess);
}
#endif

static struct kunit_case ksmbd_session_test_cases[] = {
	KUNIT_CASE(test_smb2_session_create),
	KUNIT_CASE(test_smb2_session_create_initializes_fields),
	KUNIT_CASE(test_session_flag_set_clear),
	KUNIT_CASE(test_session_put_null),
	KUNIT_CASE(test_preauth_session_alloc_lookup),
	KUNIT_CASE(test_preauth_session_lookup_nonexistent),
	KUNIT_CASE(test_preauth_session_remove),
	KUNIT_CASE(test_preauth_session_remove_nonexistent),
	KUNIT_CASE(test_session_in_connection_false),
	KUNIT_CASE(test_session_lookup_nonexistent),
	KUNIT_CASE(test_acquire_release_tree_conn_id),
	KUNIT_CASE(test_acquire_multiple_tree_conn_ids),
#ifdef CONFIG_SMB_INSECURE_SERVER
	KUNIT_CASE(test_smb1_session_create),
#endif
	{}
};

static struct kunit_suite ksmbd_session_test_suite = {
	.name = "ksmbd_session",
	.test_cases = ksmbd_session_test_cases,
};

kunit_test_suite(ksmbd_session_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd session management");
