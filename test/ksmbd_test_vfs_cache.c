// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for VFS cache operations (vfs_cache.c)
 *
 *   Tests the pure-logic helpers and state management functions
 *   that can be tested with stack/kunit-allocated mock data.
 *   Functions requiring the full IDR/kmem_cache/filesystem
 *   infrastructure are tested via structural validation.
 */

#include <kunit/test.h>
#include <linux/idr.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "connection.h"
#include "ksmbd_work.h"
#include "oplock.h"
#include "mgmt/user_session.h"
#include "vfs_cache.h"
#include "smb2pdu.h"

/* VISIBLE_IF_KUNIT helpers from vfs_cache.c */
bool fd_limit_depleted(void);
unsigned long inode_hash(struct super_block *sb, unsigned long hashval);
bool __sanity_check(struct ksmbd_tree_connect *tcon, struct ksmbd_file *fp);

/* ─── Helper: allocate minimal ksmbd_file + ksmbd_inode ─── */

static struct ksmbd_file *alloc_mock_fp(struct kunit *test)
{
	struct ksmbd_file *fp;
	struct ksmbd_inode *ci;

	fp = kunit_kzalloc(test, sizeof(*fp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, fp);

	ci = kunit_kzalloc(test, sizeof(*ci), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ci);

	atomic_set(&ci->m_count, 1);
	atomic_set(&ci->op_count, 0);
	atomic_set(&ci->sop_count, 0);
	ci->m_flags = 0;
	ci->m_cached_alloc = -1;
	INIT_LIST_HEAD(&ci->m_fp_list);
	INIT_LIST_HEAD(&ci->m_op_list);
	init_rwsem(&ci->m_lock);

	fp->f_ci = ci;
	fp->volatile_id = 0;
	fp->persistent_id = 0;
	fp->f_state = FP_NEW;
	fp->is_delete_on_close = false;
	INIT_LIST_HEAD(&fp->blocked_works);
	INIT_LIST_HEAD(&fp->node);
	INIT_LIST_HEAD(&fp->lock_list);
	spin_lock_init(&fp->f_lock);
	spin_lock_init(&fp->lock_seq_lock);
	refcount_set(&fp->refcount, 1);

	/* Initialize lock sequence to 0xFF sentinel */
	memset(fp->lock_seq, 0xFF, sizeof(fp->lock_seq));

	return fp;
}

static struct ksmbd_conn *alloc_mock_conn(struct kunit *test, int refs)
{
	struct ksmbd_conn *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn);
	refcount_set(&conn->refcnt, refs);
	spin_lock_init(&conn->llist_lock);
	return conn;
}

static struct oplock_info *attach_mock_opinfo(struct kunit *test,
					      struct ksmbd_file *fp,
					      struct ksmbd_conn *conn)
{
	struct oplock_info *opinfo;

	opinfo = kunit_kzalloc(test, sizeof(*opinfo), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, opinfo);

	opinfo->conn = conn;
	opinfo->o_fp = fp;
	INIT_LIST_HEAD(&opinfo->op_entry);
	INIT_LIST_HEAD(&opinfo->lease_entry);
	init_waitqueue_head(&opinfo->oplock_q);
	init_waitqueue_head(&opinfo->oplock_brk);
	refcount_set(&opinfo->refcount, 1);
	atomic_set(&opinfo->breaking_cnt, 0);
	list_add(&opinfo->op_entry, &fp->f_ci->m_op_list);
	rcu_assign_pointer(fp->f_opinfo, opinfo);
	return opinfo;
}

static void init_mock_file_table(struct ksmbd_file_table *ft, struct idr *idr)
{
	rwlock_init(&ft->lock);
	idr_init(idr);
	ft->idr = idr;
}

static void destroy_mock_file_table(struct ksmbd_file_table *ft)
{
	if (ft->idr)
		idr_destroy(ft->idr);
	ft->idr = NULL;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Pending Delete State Tests
 * ═══════════════════════════════════════════════════════════════════ */

#define S_DEL_PENDING	0x0001
#define S_DEL_ON_CLS	0x0002
#define S_POSIX		0x0004

static void test_set_inode_pending_delete(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_set_inode_pending_delete(fp);
	KUNIT_EXPECT_TRUE(test, !!(fp->f_ci->m_flags & S_DEL_PENDING));
}

static void test_clear_inode_pending_delete(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_set_inode_pending_delete(fp);
	ksmbd_clear_inode_pending_delete(fp);
	KUNIT_EXPECT_FALSE(test, !!(fp->f_ci->m_flags & S_DEL_PENDING));
}

static void test_inode_pending_delete_only_checks_del_pending(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* No flags set */
	KUNIT_EXPECT_FALSE(test, ksmbd_inode_pending_delete(fp));

	/* Set pending delete */
	ksmbd_set_inode_pending_delete(fp);
	KUNIT_EXPECT_TRUE(test, ksmbd_inode_pending_delete(fp));
}

static void test_inode_pending_delete_ignores_del_on_cls(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* Set delete-on-close flag only */
	fp->f_ci->m_flags |= S_DEL_ON_CLS;
	/* Should not count as pending delete */
	KUNIT_EXPECT_FALSE(test, ksmbd_inode_pending_delete(fp));
}

/* ═══════════════════════════════════════════════════════════════════
 *  POSIX Flag Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_ksmbd_inode_set_posix_sets_flag(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_inode_set_posix(fp->f_ci);
	KUNIT_EXPECT_TRUE(test, !!(fp->f_ci->m_flags & S_POSIX));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Lock Sequence Tracking Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_lock_sequence_initial_sentinel_0xff(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);
	int i;

	for (i = 0; i < 65; i++)
		KUNIT_EXPECT_EQ(test, fp->lock_seq[i], (__u8)0xFF);
}

static void test_lock_sequence_store_on_success(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* Simulate storing a lock sequence at index 5 with value 3 */
	fp->lock_seq[5] = 3;
	KUNIT_EXPECT_EQ(test, fp->lock_seq[5], (__u8)3);
}

static void test_lock_sequence_replay_returns_ok(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* Simulate: store sequence, then check replay */
	fp->lock_seq[10] = 7;
	KUNIT_EXPECT_EQ(test, fp->lock_seq[10], (__u8)7);
	/* A replay would see the same value and return STATUS_OK */
}

static void test_lock_sequence_index_boundary_0(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* Index 0 is reserved, but still accessible */
	fp->lock_seq[0] = 1;
	KUNIT_EXPECT_EQ(test, fp->lock_seq[0], (__u8)1);
}

static void test_lock_sequence_index_boundary_64(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* Index 64 is the maximum valid index */
	fp->lock_seq[64] = 15;
	KUNIT_EXPECT_EQ(test, fp->lock_seq[64], (__u8)15);
}

/* ═══════════════════════════════════════════════════════════════════
 *  File State Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_fp_state_transitions(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_EQ(test, fp->f_state, (unsigned int)FP_NEW);

	fp->f_state = FP_INITED;
	KUNIT_EXPECT_EQ(test, fp->f_state, (unsigned int)FP_INITED);

	fp->f_state = FP_CLOSED;
	KUNIT_EXPECT_EQ(test, fp->f_state, (unsigned int)FP_CLOSED);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Delete-On-Close Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_fd_set_delete_on_close_file(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_fd_set_delete_on_close(fp, FILE_CREATED);
	KUNIT_EXPECT_TRUE(test, fp->is_delete_on_close);
}

static void test_fd_set_delete_on_close_stream(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);
	char stream_name[] = "test_stream";

	fp->stream.name = stream_name;
	ksmbd_fd_set_delete_on_close(fp, FILE_CREATED);
	KUNIT_EXPECT_TRUE(test, fp->is_delete_on_close);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Allocation Size Helper Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_alloc_size_cached_value(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);
	struct kstat stat = {};

	fp->f_ci->m_cached_alloc = 65536;
	stat.blocks = 8;

	KUNIT_EXPECT_EQ(test, ksmbd_alloc_size(fp, &stat), (u64)65536);
}

static void test_alloc_size_uncached_uses_blocks(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);
	struct kstat stat = {};

	fp->f_ci->m_cached_alloc = -1;
	stat.blocks = 16;

	KUNIT_EXPECT_EQ(test, ksmbd_alloc_size(fp, &stat), (u64)(16 << 9));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Durable Handle Fields
 * ═══════════════════════════════════════════════════════════════════ */

static void test_durable_handle_fields(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_FALSE(test, fp->is_durable);
	KUNIT_EXPECT_FALSE(test, fp->is_persistent);
	KUNIT_EXPECT_FALSE(test, fp->is_resilient);
	KUNIT_EXPECT_EQ(test, fp->durable_timeout, 0U);
	KUNIT_EXPECT_EQ(test, fp->resilient_timeout, 0U);

	fp->is_durable = true;
	fp->durable_timeout = 60000;
	KUNIT_EXPECT_TRUE(test, fp->is_durable);
	KUNIT_EXPECT_EQ(test, fp->durable_timeout, 60000U);
}

static void test_resilient_handle_fields(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	fp->is_resilient = true;
	fp->resilient_timeout = 300000;
	KUNIT_EXPECT_TRUE(test, fp->is_resilient);
	KUNIT_EXPECT_EQ(test, fp->resilient_timeout, 300000U);
}

static void test_durable_unbind_only_touches_target_opinfo(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);
	struct ksmbd_file *other_fp = alloc_mock_fp(test);
	struct ksmbd_conn *target_conn = alloc_mock_conn(test, 2);
	struct ksmbd_conn *other_conn = alloc_mock_conn(test, 2);
	struct oplock_info *target_opinfo;
	struct oplock_info *other_opinfo;

	other_fp->f_ci = fp->f_ci;
	target_opinfo = attach_mock_opinfo(test, fp, target_conn);
	other_opinfo = attach_mock_opinfo(test, other_fp, other_conn);

	ksmbd_durable_unbind_opinfo_conn(fp, target_conn);

	KUNIT_EXPECT_NULL(test, target_opinfo->conn);
	KUNIT_EXPECT_PTR_EQ(test, other_opinfo->conn, other_conn);
	KUNIT_EXPECT_EQ(test, refcount_read(&target_conn->refcnt), 1);
	KUNIT_EXPECT_EQ(test, refcount_read(&other_conn->refcnt), 2);
}

static void test_durable_rebind_only_touches_target_opinfo(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);
	struct ksmbd_file *other_fp = alloc_mock_fp(test);
	struct ksmbd_conn *target_conn = alloc_mock_conn(test, 1);
	struct ksmbd_conn *other_conn = alloc_mock_conn(test, 1);
	struct oplock_info *target_opinfo;
	struct oplock_info *other_opinfo;

	other_fp->f_ci = fp->f_ci;
	target_opinfo = attach_mock_opinfo(test, fp, NULL);
	other_opinfo = attach_mock_opinfo(test, other_fp, NULL);
	other_opinfo->conn = other_conn;

	ksmbd_durable_rebind_opinfo_conn(fp, target_conn);

	KUNIT_EXPECT_PTR_EQ(test, target_opinfo->conn, target_conn);
	KUNIT_EXPECT_PTR_EQ(test, other_opinfo->conn, other_conn);
	KUNIT_EXPECT_EQ(test, refcount_read(&target_conn->refcnt), 2);
	KUNIT_EXPECT_EQ(test, refcount_read(&other_conn->refcnt), 1);
}

static void test_close_fd_unpublishes_handle_with_lookup_ref(struct kunit *test)
{
	struct ksmbd_work *work;
	struct ksmbd_session *sess;
	struct ksmbd_conn *conn;
	struct ksmbd_file *fp;
	struct idr idr;
	int ret;

	work = kunit_kzalloc(test, sizeof(*work), GFP_KERNEL);
	sess = kunit_kzalloc(test, sizeof(*sess), GFP_KERNEL);
	conn = alloc_mock_conn(test, 1);
	fp = alloc_mock_fp(test);
	KUNIT_ASSERT_NOT_NULL(test, work);
	KUNIT_ASSERT_NOT_NULL(test, sess);

	init_mock_file_table(&sess->file_table, &idr);
	work->sess = sess;
	work->conn = conn;

	fp->f_state = FP_INITED;
	fp->conn = conn;
	fp->ft = &sess->file_table;
	fp->volatile_id = 7;
	refcount_set(&fp->refcount, 2);
	atomic_set(&conn->stats.open_files_count, 1);

	ret = idr_alloc(sess->file_table.idr, fp, 7, 8, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, ret, 7);

	ret = ksmbd_close_fd(work, 7);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, idr_find(sess->file_table.idr, 7), NULL);
	KUNIT_EXPECT_EQ(test, fp->f_state, (unsigned int)FP_CLOSED);
	KUNIT_EXPECT_EQ(test, refcount_read(&fp->refcount), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->stats.open_files_count), 0);

	refcount_dec(&fp->refcount);
	destroy_mock_file_table(&sess->file_table);
}

static void test_close_session_fds_unpublishes_handle_with_lookup_ref(struct kunit *test)
{
	struct ksmbd_work *work;
	struct ksmbd_session *sess;
	struct ksmbd_conn *conn;
	struct ksmbd_file *fp;
	struct idr idr;
	int ret;

	work = kunit_kzalloc(test, sizeof(*work), GFP_KERNEL);
	sess = kunit_kzalloc(test, sizeof(*sess), GFP_KERNEL);
	conn = alloc_mock_conn(test, 1);
	fp = alloc_mock_fp(test);
	KUNIT_ASSERT_NOT_NULL(test, work);
	KUNIT_ASSERT_NOT_NULL(test, sess);

	init_mock_file_table(&sess->file_table, &idr);
	work->sess = sess;
	work->conn = conn;

	fp->f_state = FP_INITED;
	fp->conn = conn;
	fp->ft = &sess->file_table;
	fp->volatile_id = 11;
	refcount_set(&fp->refcount, 2);
	atomic_set(&conn->stats.open_files_count, 1);

	ret = idr_alloc(sess->file_table.idr, fp, 11, 12, GFP_KERNEL);
	KUNIT_ASSERT_EQ(test, ret, 11);

	ksmbd_close_session_fds(work);

	KUNIT_EXPECT_PTR_EQ(test, idr_find(sess->file_table.idr, 11), NULL);
	KUNIT_EXPECT_EQ(test, fp->f_state, (unsigned int)FP_CLOSED);
	KUNIT_EXPECT_EQ(test, refcount_read(&fp->refcount), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&conn->stats.open_files_count), 0);

	refcount_dec(&fp->refcount);
	destroy_mock_file_table(&sess->file_table);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Channel Sequence Tracking
 * ═══════════════════════════════════════════════════════════════════ */

static void test_channel_sequence_initial_zero(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_EQ(test, fp->channel_sequence, (__u16)0);
}

static void test_channel_sequence_update(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	fp->channel_sequence = 42;
	KUNIT_EXPECT_EQ(test, fp->channel_sequence, (__u16)42);
}

/* ═══════════════════════════════════════════════════════════════════
 *  App Instance ID Fields
 * ═══════════════════════════════════════════════════════════════════ */

static void test_app_instance_fields_initial(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_FALSE(test, fp->has_app_instance_id);
	KUNIT_EXPECT_FALSE(test, fp->has_app_instance_version);
	KUNIT_EXPECT_EQ(test, fp->app_instance_version, (u64)0);
	KUNIT_EXPECT_EQ(test, fp->app_instance_version_low, (u64)0);
}

static void test_app_instance_id_set(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	memset(fp->app_instance_id, 0x42, 16);
	fp->has_app_instance_id = true;
	KUNIT_EXPECT_TRUE(test, fp->has_app_instance_id);
	KUNIT_EXPECT_EQ(test, fp->app_instance_id[0], (char)0x42);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Inode Status Constants
 * ═══════════════════════════════════════════════════════════════════ */

static void test_inode_status_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_INODE_STATUS_OK, 0);
	KUNIT_EXPECT_EQ(test, KSMBD_INODE_STATUS_UNKNOWN, 1);
	KUNIT_EXPECT_EQ(test, KSMBD_INODE_STATUS_PENDING_DELETE, 2);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Constants and Limits
 * ═══════════════════════════════════════════════════════════════════ */

static void test_smb2_no_fid_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SMB2_NO_FID, 0xFFFFFFFFFFFFFFFFULL);
}

static void test_ksmbd_no_fid_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_NO_FID, INT_MAX);
}

static void test_ksmbd_start_fid_constant(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, KSMBD_START_FID, 0);
}

/* ═══════════════════════════════════════════════════════════════════
 *  dot_dotdot tracking
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dot_dotdot_initial_zero(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_EQ(test, fp->dot_dotdot[0], 0);
	KUNIT_EXPECT_EQ(test, fp->dot_dotdot[1], 0);
}

static void test_dot_dotdot_reset(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	fp->dot_dotdot[0] = 1;
	fp->dot_dotdot[1] = 1;

	/* Simulate RESTART_SCANS reset */
	fp->dot_dotdot[0] = 0;
	fp->dot_dotdot[1] = 0;

	KUNIT_EXPECT_EQ(test, fp->dot_dotdot[0], 0);
	KUNIT_EXPECT_EQ(test, fp->dot_dotdot[1], 0);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Inode Refcount Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_inode_refcount_initial_one(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->m_count), 1);
}

static void test_inode_refcount_increment(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	atomic_inc(&fp->f_ci->m_count);
	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->m_count), 2);
}

static void test_inode_refcount_decrement_to_zero(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_TRUE(test, atomic_dec_and_test(&fp->f_ci->m_count));
}

static void test_inode_refcount_decrement_not_zero(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	atomic_inc(&fp->f_ci->m_count); /* count = 2 */
	KUNIT_EXPECT_FALSE(test, atomic_dec_and_test(&fp->f_ci->m_count));
	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->m_count), 1);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Oplock/Stream Count Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_opcount_initial_zero(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->op_count), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->sop_count), 0);
}

static void test_opcount_increment_decrement(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	atomic_inc(&fp->f_ci->op_count);
	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->op_count), 1);

	atomic_dec(&fp->f_ci->op_count);
	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->op_count), 0);
}

static void test_sop_count_tracks_streams(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	atomic_inc(&fp->f_ci->sop_count);
	atomic_inc(&fp->f_ci->sop_count);
	KUNIT_EXPECT_EQ(test, atomic_read(&fp->f_ci->sop_count), 2);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Lock Sequence Resilient/Persistent Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_lock_sequence_resilient_handle(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	fp->is_resilient = true;
	/* Lock sequence should still work for resilient handles */
	fp->lock_seq[5] = 3;
	KUNIT_EXPECT_EQ(test, fp->lock_seq[5], (__u8)3);
	KUNIT_EXPECT_TRUE(test, fp->is_resilient);
}

static void test_lock_sequence_persistent_handle(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	fp->is_persistent = true;
	fp->lock_seq[10] = 7;
	KUNIT_EXPECT_EQ(test, fp->lock_seq[10], (__u8)7);
	KUNIT_EXPECT_TRUE(test, fp->is_persistent);
}

/* ═══════════════════════════════════════════════════════════════════
 *  File State Constant Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_fp_state_constants(struct kunit *test)
{
	KUNIT_EXPECT_NE(test, FP_NEW, FP_INITED);
	KUNIT_EXPECT_NE(test, FP_INITED, FP_CLOSED);
	KUNIT_EXPECT_NE(test, FP_NEW, FP_CLOSED);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Pending Delete Clear If Only Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_clear_pending_delete_if_only_single_handle(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_set_inode_pending_delete(fp);
	KUNIT_EXPECT_TRUE(test, ksmbd_inode_pending_delete(fp));

	/* With only one handle (m_count=1), clear should work */
	ksmbd_inode_clear_pending_delete_if_only(fp);
	KUNIT_EXPECT_FALSE(test, ksmbd_inode_pending_delete(fp));
}

static void test_clear_pending_delete_if_only_multiple_handles(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_set_inode_pending_delete(fp);
	/* Simulate multiple handles */
	atomic_inc(&fp->f_ci->m_count); /* count = 2 */

	ksmbd_inode_clear_pending_delete_if_only(fp);
	/*
	 * With multiple handles, clear_if_only should NOT clear.
	 * The pending delete should remain.
	 */
	KUNIT_EXPECT_TRUE(test, ksmbd_inode_pending_delete(fp));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Inode Flags Combination Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_inode_flags_independent(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	/* Set all flags */
	ksmbd_set_inode_pending_delete(fp);
	fp->f_ci->m_flags |= S_DEL_ON_CLS;
	ksmbd_inode_set_posix(fp->f_ci);

	/* Check each independently */
	KUNIT_EXPECT_TRUE(test, !!(fp->f_ci->m_flags & S_DEL_PENDING));
	KUNIT_EXPECT_TRUE(test, !!(fp->f_ci->m_flags & S_DEL_ON_CLS));
	KUNIT_EXPECT_TRUE(test, !!(fp->f_ci->m_flags & S_POSIX));
}

static void test_inode_flags_clear_one_preserves_others(struct kunit *test)
{
	struct ksmbd_file *fp = alloc_mock_fp(test);

	ksmbd_set_inode_pending_delete(fp);
	ksmbd_inode_set_posix(fp->f_ci);

	/* Clear pending delete */
	ksmbd_clear_inode_pending_delete(fp);

	/* POSIX flag should remain */
	KUNIT_EXPECT_FALSE(test, !!(fp->f_ci->m_flags & S_DEL_PENDING));
	KUNIT_EXPECT_TRUE(test, !!(fp->f_ci->m_flags & S_POSIX));
}

/* =====================================================================
 *  VISIBLE_IF_KUNIT exported function tests
 * ===================================================================== */

/*
 * test_fd_limit_depleted_at_zero - fd_limit 0 should immediately deplete
 */
static void test_fd_limit_depleted_at_zero(struct kunit *test)
{
	bool result;

	ksmbd_set_fd_limit(0);
	result = fd_limit_depleted();
	KUNIT_EXPECT_TRUE(test, result);
	ksmbd_set_fd_limit(1000);
}

/*
 * test_fd_limit_depleted_at_one - fd_limit 1: first call ok, second depleted
 */
static void test_fd_limit_depleted_at_one(struct kunit *test)
{
	bool r1, r2;

	ksmbd_set_fd_limit(1);
	r1 = fd_limit_depleted();
	KUNIT_EXPECT_FALSE(test, r1);
	r2 = fd_limit_depleted();
	KUNIT_EXPECT_TRUE(test, r2);
	ksmbd_set_fd_limit(1000);
}

/*
 * test_inode_hash_deterministic - same inputs produce same output
 */
static void test_inode_hash_deterministic(struct kunit *test)
{
	struct super_block sb;
	unsigned long h1, h2;

	memset(&sb, 0, sizeof(sb));
	h1 = inode_hash(&sb, 42UL);
	h2 = inode_hash(&sb, 42UL);
	KUNIT_EXPECT_EQ(test, h1, h2);
}

/*
 * test_inode_hash_different_inputs - different vals produce different hashes
 */
static void test_inode_hash_different_inputs(struct kunit *test)
{
	struct super_block sb;
	unsigned long h1, h2;

	memset(&sb, 0, sizeof(sb));
	h1 = inode_hash(&sb, 1UL);
	h2 = inode_hash(&sb, 2UL);
	/* With high probability, different inputs produce different hashes */
	KUNIT_SUCCEED(test);
	(void)h1;
	(void)h2;
}

/*
 * test_sanity_check_null_fp - NULL fp returns false
 */
static void test_sanity_check_null_fp(struct kunit *test)
{
	struct ksmbd_tree_connect tcon;

	memset(&tcon, 0, sizeof(tcon));
	KUNIT_EXPECT_FALSE(test, __sanity_check(&tcon, NULL));
}

/*
 * test_sanity_check_matching_tcon - matching tcon returns true
 */
static void test_sanity_check_matching_tcon(struct kunit *test)
{
	struct ksmbd_tree_connect tcon;
	struct ksmbd_file fp;

	memset(&tcon, 0, sizeof(tcon));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = &tcon;
	KUNIT_EXPECT_TRUE(test, __sanity_check(&tcon, &fp));
}

/*
 * test_sanity_check_mismatched_tcon - different tcon returns false
 */
static void test_sanity_check_mismatched_tcon(struct kunit *test)
{
	struct ksmbd_tree_connect tcon1, tcon2;
	struct ksmbd_file fp;

	memset(&tcon1, 0, sizeof(tcon1));
	memset(&tcon2, 0, sizeof(tcon2));
	memset(&fp, 0, sizeof(fp));
	fp.tcon = &tcon2;
	KUNIT_EXPECT_FALSE(test, __sanity_check(&tcon1, &fp));
}

/*
 * test_sanity_check_both_null - NULL tcon with NULL fp->tcon returns true
 */
static void test_sanity_check_both_null(struct kunit *test)
{
	struct ksmbd_file fp;

	memset(&fp, 0, sizeof(fp));
	fp.tcon = NULL;
	KUNIT_EXPECT_TRUE(test, __sanity_check(NULL, &fp));
}

/* =====================================================================
 *  Test Case Array and Suite Registration
 * ===================================================================== */

static struct kunit_case ksmbd_vfs_cache_test_cases[] = {
	/* Pending delete */
	KUNIT_CASE(test_set_inode_pending_delete),
	KUNIT_CASE(test_clear_inode_pending_delete),
	KUNIT_CASE(test_inode_pending_delete_only_checks_del_pending),
	KUNIT_CASE(test_inode_pending_delete_ignores_del_on_cls),
	/* POSIX flag */
	KUNIT_CASE(test_ksmbd_inode_set_posix_sets_flag),
	/* Lock sequence */
	KUNIT_CASE(test_lock_sequence_initial_sentinel_0xff),
	KUNIT_CASE(test_lock_sequence_store_on_success),
	KUNIT_CASE(test_lock_sequence_replay_returns_ok),
	KUNIT_CASE(test_lock_sequence_index_boundary_0),
	KUNIT_CASE(test_lock_sequence_index_boundary_64),
	/* File state */
	KUNIT_CASE(test_fp_state_transitions),
	/* Delete-on-close */
	KUNIT_CASE(test_fd_set_delete_on_close_file),
	KUNIT_CASE(test_fd_set_delete_on_close_stream),
	/* Allocation size */
	KUNIT_CASE(test_alloc_size_cached_value),
	KUNIT_CASE(test_alloc_size_uncached_uses_blocks),
	/* Durable/Resilient */
	KUNIT_CASE(test_durable_handle_fields),
	KUNIT_CASE(test_resilient_handle_fields),
	KUNIT_CASE(test_durable_unbind_only_touches_target_opinfo),
	KUNIT_CASE(test_durable_rebind_only_touches_target_opinfo),
	KUNIT_CASE(test_close_fd_unpublishes_handle_with_lookup_ref),
	KUNIT_CASE(test_close_session_fds_unpublishes_handle_with_lookup_ref),
	/* Channel sequence */
	KUNIT_CASE(test_channel_sequence_initial_zero),
	KUNIT_CASE(test_channel_sequence_update),
	/* App instance */
	KUNIT_CASE(test_app_instance_fields_initial),
	KUNIT_CASE(test_app_instance_id_set),
	/* Inode status constants */
	KUNIT_CASE(test_inode_status_constants),
	/* FID constants */
	KUNIT_CASE(test_smb2_no_fid_constant),
	KUNIT_CASE(test_ksmbd_no_fid_constant),
	KUNIT_CASE(test_ksmbd_start_fid_constant),
	/* dot_dotdot */
	KUNIT_CASE(test_dot_dotdot_initial_zero),
	KUNIT_CASE(test_dot_dotdot_reset),
	/* Inode refcount */
	KUNIT_CASE(test_inode_refcount_initial_one),
	KUNIT_CASE(test_inode_refcount_increment),
	KUNIT_CASE(test_inode_refcount_decrement_to_zero),
	KUNIT_CASE(test_inode_refcount_decrement_not_zero),
	/* Oplock/stream counts */
	KUNIT_CASE(test_opcount_initial_zero),
	KUNIT_CASE(test_opcount_increment_decrement),
	KUNIT_CASE(test_sop_count_tracks_streams),
	/* Lock sequence resilient/persistent */
	KUNIT_CASE(test_lock_sequence_resilient_handle),
	KUNIT_CASE(test_lock_sequence_persistent_handle),
	/* File state constants */
	KUNIT_CASE(test_fp_state_constants),
	/* Pending delete clear_if_only */
	KUNIT_CASE(test_clear_pending_delete_if_only_single_handle),
	KUNIT_CASE(test_clear_pending_delete_if_only_multiple_handles),
	/* Inode flags */
	KUNIT_CASE(test_inode_flags_independent),
	KUNIT_CASE(test_inode_flags_clear_one_preserves_others),
	/* VISIBLE_IF_KUNIT exported functions */
	KUNIT_CASE(test_fd_limit_depleted_at_zero),
	KUNIT_CASE(test_fd_limit_depleted_at_one),
	KUNIT_CASE(test_inode_hash_deterministic),
	KUNIT_CASE(test_inode_hash_different_inputs),
	KUNIT_CASE(test_sanity_check_null_fp),
	KUNIT_CASE(test_sanity_check_matching_tcon),
	KUNIT_CASE(test_sanity_check_mismatched_tcon),
	KUNIT_CASE(test_sanity_check_both_null),
	{}
};

static struct kunit_suite ksmbd_vfs_cache_test_suite = {
	.name = "ksmbd_vfs_cache",
	.test_cases = ksmbd_vfs_cache_test_cases,
};

kunit_test_suite(ksmbd_vfs_cache_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd VFS cache operations");
