// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for oplock state machine (oplock.c)
 *
 *   This file exercises both the publicly-exported oplock helpers and
 *   the formerly-static functions that are now conditionally visible
 *   via VISIBLE_IF_KUNIT / EXPORT_SYMBOL_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "connection.h"
#include "oplock.h"
#include "smb2pdu.h"
#include "vfs_cache.h"

/* VISIBLE_IF_KUNIT helpers from oplock.c */
int lease_none_upgrade(struct oplock_info *opinfo, __le32 new_state);
void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,
			struct lease_ctx_info *lctx);
void grant_read_oplock(struct oplock_info *opinfo_new,
		       struct lease_ctx_info *lctx);
void grant_none_oplock(struct oplock_info *opinfo_new,
		       struct lease_ctx_info *lctx);
void copy_lease(struct oplock_info *op1, struct oplock_info *op2);
void set_oplock_level(struct oplock_info *opinfo, int level,
		      struct lease_ctx_info *lctx);
struct oplock_info *opinfo_get_list(struct ksmbd_inode *ci);
void ksmbd_apply_disconnected_only_lease_policy(int *req_op_level,
						struct lease_ctx_info *lctx);
void ksmbd_apply_read_handle_lease_policy(int *req_op_level,
					  struct lease_ctx_info *lctx);
bool ksmbd_is_strict_stat_open(const struct ksmbd_file *fp);

static struct oplock_info *alloc_test_opinfo(struct kunit *test)
{
	struct oplock_info *opinfo;
	struct lease *lease;

	opinfo = kunit_kzalloc(test, sizeof(*opinfo), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, opinfo);
	lease = kunit_kzalloc(test, sizeof(*lease), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, lease);
	opinfo->o_lease = lease;
	opinfo->is_lease = true;
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

static struct ksmbd_conn *alloc_test_conn(struct kunit *test)
{
	struct ksmbd_conn *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn);
	refcount_set(&conn->refcnt, 1);
	return conn;
}

static struct ksmbd_inode *alloc_test_inode(struct kunit *test)
{
	struct ksmbd_inode *ci;

	ci = kunit_kzalloc(test, sizeof(*ci), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ci);
	INIT_LIST_HEAD(&ci->m_fp_list);
	INIT_LIST_HEAD(&ci->m_op_list);
	init_rwsem(&ci->m_lock);
	return ci;
}

static void test_lease_to_oplock_rwh(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)SMB2_OPLOCK_LEVEL_BATCH);
}

static void test_lease_to_oplock_rw(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)SMB2_OPLOCK_LEVEL_EXCLUSIVE);
}

static void test_lease_to_oplock_r(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(SMB2_LEASE_READ_CACHING_LE), (__u8)SMB2_OPLOCK_LEVEL_II);
}

static void test_lease_to_oplock_rh(struct kunit *test)
{
	__le32 state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)SMB2_OPLOCK_LEVEL_II);
}

static void test_lease_to_oplock_none(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(SMB2_LEASE_NONE_LE), (__u8)0);
}

static void test_lease_to_oplock_write_only(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(SMB2_LEASE_WRITE_CACHING_LE), (__u8)0);
}

static void test_lease_to_oplock_wh(struct kunit *test)
{
	__le32 state = SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)0);
}

static void test_oplock_level_ordering(struct kunit *test)
{
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_NONE, SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_II, SMB2_OPLOCK_LEVEL_EXCLUSIVE);
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_EXCLUSIVE, SMB2_OPLOCK_LEVEL_BATCH);
	KUNIT_EXPECT_NE(test, SMB2_OPLOCK_LEVEL_BATCH, SMB2_OPLOCK_LEVEL_LEASE);
}

static void test_oplock_level_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_NONE, 0x00);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_II, 0x01);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_EXCLUSIVE, 0x08);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_BATCH, 0x09);
	KUNIT_EXPECT_EQ(test, SMB2_OPLOCK_LEVEL_LEASE, 0xFF);
}

static void test_lease_state_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_NONE_LE, cpu_to_le32(0x00));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_READ_CACHING_LE, cpu_to_le32(0x01));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_HANDLE_CACHING_LE, cpu_to_le32(0x02));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_WRITE_CACHING_LE, cpu_to_le32(0x04));
}

static void test_lease_state_combinations(struct kunit *test)
{
	__le32 rwh = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	KUNIT_EXPECT_EQ(test, rwh, cpu_to_le32(0x07));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE, cpu_to_le32(0x05));
	KUNIT_EXPECT_EQ(test, SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE, cpu_to_le32(0x03));
}

static void test_lease_none_upgrade_rwh(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	__le32 new_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	opinfo->o_lease->state = SMB2_LEASE_NONE_LE;
	KUNIT_EXPECT_EQ(test, lease_none_upgrade(opinfo, new_state), 0);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_BATCH);
}

static void test_lease_none_upgrade_bad_state(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	opinfo->o_lease->state = SMB2_LEASE_READ_CACHING_LE;
	KUNIT_EXPECT_EQ(test, lease_none_upgrade(opinfo, SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE), -EINVAL);
}

static void test_grant_write_oplock_batch(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	struct lease_ctx_info lctx = {};
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	memset(lctx.lease_key, 0xDD, SMB2_LEASE_KEY_SIZE);
	grant_write_oplock(opinfo, SMB2_OPLOCK_LEVEL_BATCH, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_BATCH);
}

static void test_grant_read_oplock_rh(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	struct lease_ctx_info lctx = {};
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	memset(lctx.lease_key, 0x11, SMB2_LEASE_KEY_SIZE);
	grant_read_oplock(opinfo, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_TRUE(test, (opinfo->o_lease->state & SMB2_LEASE_READ_CACHING_LE) != 0);
	KUNIT_EXPECT_TRUE(test, (opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE) != 0);
}

static void test_grant_none_oplock_test(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	struct lease_ctx_info lctx = {};
	memset(lctx.lease_key, 0x22, SMB2_LEASE_KEY_SIZE);
	grant_none_oplock(opinfo, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->state, (__le32)0);
}

static void test_copy_lease_test(struct kunit *test)
{
	struct oplock_info *src = alloc_test_opinfo(test);
	struct oplock_info *dst = alloc_test_opinfo(test);
	memset(src->o_lease->lease_key, 0xAA, SMB2_LEASE_KEY_SIZE);
	src->o_lease->state = SMB2_LEASE_READ_CACHING_LE;
	src->o_lease->epoch = 7;
	copy_lease(src, dst);
	KUNIT_EXPECT_EQ(test, memcmp(dst->o_lease->lease_key, src->o_lease->lease_key, SMB2_LEASE_KEY_SIZE), 0);
	KUNIT_EXPECT_EQ(test, dst->o_lease->state, src->o_lease->state);
	KUNIT_EXPECT_EQ(test, dst->o_lease->epoch, (unsigned short)7);
}

static void test_set_oplock_level_batch(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	struct lease_ctx_info lctx = {};
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
	memset(lctx.lease_key, 0x33, SMB2_LEASE_KEY_SIZE);
	set_oplock_level(opinfo, SMB2_OPLOCK_LEVEL_BATCH, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_BATCH);
}

static void test_disconnected_only_policy_strips_write_not_handle(struct kunit *test)
{
	struct lease_ctx_info lctx = {};
	int req_op_level = SMB2_OPLOCK_LEVEL_LEASE;

	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_WRITE_CACHING_LE |
			 SMB2_LEASE_HANDLE_CACHING_LE;

	ksmbd_apply_disconnected_only_lease_policy(&req_op_level, &lctx);

	KUNIT_EXPECT_EQ(test, req_op_level, SMB2_OPLOCK_LEVEL_LEASE);
	KUNIT_EXPECT_EQ(test, lctx.req_state,
			(__le32)(SMB2_LEASE_READ_CACHING_LE |
				 SMB2_LEASE_HANDLE_CACHING_LE));
}

static void test_disconnected_only_policy_downgrades_nonlease_to_level_ii(struct kunit *test)
{
	int req_op_level = SMB2_OPLOCK_LEVEL_BATCH;

	ksmbd_apply_disconnected_only_lease_policy(&req_op_level, NULL);

	KUNIT_EXPECT_EQ(test, req_op_level, SMB2_OPLOCK_LEVEL_II);
}

static void test_read_handle_policy_restores_rh(struct kunit *test)
{
	struct lease_ctx_info lctx = {};
	int req_op_level = SMB2_OPLOCK_LEVEL_NONE;

	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_WRITE_CACHING_LE |
			 SMB2_LEASE_HANDLE_CACHING_LE;

	ksmbd_apply_read_handle_lease_policy(&req_op_level, &lctx);

	KUNIT_EXPECT_EQ(test, req_op_level, SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_EQ(test, lctx.req_state,
			(__le32)(SMB2_LEASE_READ_CACHING_LE |
				 SMB2_LEASE_HANDLE_CACHING_LE));
}

static void test_strict_stat_open_excludes_read_control(struct kunit *test)
{
	struct ksmbd_file *fp;

	fp = kunit_kzalloc(test, sizeof(*fp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fp);

	fp->attrib_only = true;
	fp->daccess = FILE_READ_ATTRIBUTES_LE | FILE_SYNCHRONIZE_LE;
	KUNIT_EXPECT_TRUE(test, ksmbd_is_strict_stat_open(fp));

	fp->daccess |= FILE_READ_CONTROL_LE;
	KUNIT_EXPECT_FALSE(test, ksmbd_is_strict_stat_open(fp));
}

static void test_opinfo_get_list_skips_disconnected_first_entry(struct kunit *test)
{
	struct ksmbd_inode *ci = alloc_test_inode(test);
	struct oplock_info *disconnected = alloc_test_opinfo(test);
	struct oplock_info *connected = alloc_test_opinfo(test);
	struct ksmbd_conn *conn = alloc_test_conn(test);
	struct oplock_info *found;

	disconnected->conn = NULL;
	connected->conn = conn;
	list_add_tail(&disconnected->op_entry, &ci->m_op_list);
	list_add_tail(&connected->op_entry, &ci->m_op_list);

	found = opinfo_get_list(ci);

	KUNIT_ASSERT_PTR_EQ(test, found, connected);
	opinfo_put(found);
}

static struct kunit_case ksmbd_oplock_test_cases[] = {
	KUNIT_CASE(test_lease_to_oplock_rwh),
	KUNIT_CASE(test_lease_to_oplock_rw),
	KUNIT_CASE(test_lease_to_oplock_r),
	KUNIT_CASE(test_lease_to_oplock_rh),
	KUNIT_CASE(test_lease_to_oplock_none),
	KUNIT_CASE(test_lease_to_oplock_write_only),
	KUNIT_CASE(test_lease_to_oplock_wh),
	KUNIT_CASE(test_oplock_level_ordering),
	KUNIT_CASE(test_oplock_level_values),
	KUNIT_CASE(test_lease_state_values),
	KUNIT_CASE(test_lease_state_combinations),
	KUNIT_CASE(test_lease_none_upgrade_rwh),
	KUNIT_CASE(test_lease_none_upgrade_bad_state),
	KUNIT_CASE(test_grant_write_oplock_batch),
	KUNIT_CASE(test_grant_read_oplock_rh),
	KUNIT_CASE(test_grant_none_oplock_test),
	KUNIT_CASE(test_copy_lease_test),
	KUNIT_CASE(test_set_oplock_level_batch),
	KUNIT_CASE(test_disconnected_only_policy_strips_write_not_handle),
	KUNIT_CASE(test_disconnected_only_policy_downgrades_nonlease_to_level_ii),
	KUNIT_CASE(test_read_handle_policy_restores_rh),
	KUNIT_CASE(test_strict_stat_open_excludes_read_control),
	KUNIT_CASE(test_opinfo_get_list_skips_disconnected_first_entry),
	{}
};

static struct kunit_suite ksmbd_oplock_test_suite = {
	.name = "ksmbd_oplock",
	.test_cases = ksmbd_oplock_test_cases,
};

kunit_test_suite(ksmbd_oplock_test_suite);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd oplock state machine");
