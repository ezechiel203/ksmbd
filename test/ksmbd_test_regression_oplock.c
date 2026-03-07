// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit regression tests for oplock / lease edge cases.
 *
 *   These tests exercise functions that were formerly static in oplock.c
 *   and are now conditionally exported via VISIBLE_IF_KUNIT / EXPORT_SYMBOL_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "oplock.h"
#include "smb2pdu.h"
#include "vfs_cache.h"

/*
 * Helper: allocate a minimal oplock_info + lease for unit tests.
 * The caller must kfree() the returned opinfo and its o_lease.
 */
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

/*
 * REG-038: reg_dir_lease_rh_granted
 *
 * Verify that granting a read oplock on a directory lease request
 * with R+H results in a lease state that includes both R and H bits.
 * MS-SMB2 Section 3.3.5.9: directory leases should grant R+H when
 * only read is possible but handle caching was requested.
 */
static void reg_dir_lease_rh_granted(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	struct lease_ctx_info lctx = {};

	/* Request R+H for a directory */
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_HANDLE_CACHING_LE;
	memset(lctx.lease_key, 0xAA, SMB2_LEASE_KEY_SIZE);
	lctx.is_dir = true;

	opinfo->o_lease->is_dir = true;
	opinfo->o_lease->state = SMB2_LEASE_NONE_LE;

	grant_read_oplock(opinfo, &lctx);

	/* After grant_read_oplock with R+H request, state should be R+H */
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_TRUE(test,
		(opinfo->o_lease->state & SMB2_LEASE_READ_CACHING_LE) != 0);
	KUNIT_EXPECT_TRUE(test,
		(opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE) != 0);
}

/*
 * REG-039: reg_dir_lease_handle_break
 *
 * After granting R+H to a directory, verify that lease_none_upgrade
 * from NONE to R+H correctly sets the level.  The level should be
 * SMB2_OPLOCK_LEVEL_II because R+H with H set but no W triggers
 * the H-without-W branch.
 */
static void reg_dir_lease_handle_break(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);

	opinfo->o_lease->state = SMB2_LEASE_NONE_LE;
	opinfo->o_lease->is_dir = true;

	/* Upgrade from NONE to R+H */
	KUNIT_EXPECT_EQ(test,
		lease_none_upgrade(opinfo,
			SMB2_LEASE_READ_CACHING_LE |
			SMB2_LEASE_HANDLE_CACHING_LE),
		0);

	/* MS-SMB2: R+H without W => level II (the H-with-no-W path) */
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_II);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->state,
		SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE);
}

/*
 * REG-010: reg_outstanding_async_counter
 *
 * Verify that copy_lease faithfully duplicates all lease fields
 * from one opinfo to another, especially the epoch counter which
 * must be monotonically increasing for correct lease break
 * notification sequencing.
 */
static void reg_outstanding_async_counter(struct kunit *test)
{
	struct oplock_info *src = alloc_test_opinfo(test);
	struct oplock_info *dst = alloc_test_opinfo(test);

	/* Set up source lease with specific values */
	memset(src->o_lease->lease_key, 0xBB, SMB2_LEASE_KEY_SIZE);
	src->o_lease->state = SMB2_LEASE_READ_CACHING_LE |
			      SMB2_LEASE_WRITE_CACHING_LE;
	src->o_lease->new_state = SMB2_LEASE_READ_CACHING_LE;
	src->o_lease->epoch = 42;
	src->o_lease->version = 2;
	src->o_lease->duration = cpu_to_le64(0);
	src->o_lease->flags = SMB2_LEASE_FLAG_BREAK_IN_PROGRESS_LE;

	/* Copy */
	copy_lease(src, dst);

	/* Verify all fields were copied */
	KUNIT_EXPECT_EQ(test, memcmp(dst->o_lease->lease_key,
		src->o_lease->lease_key, SMB2_LEASE_KEY_SIZE), 0);
	KUNIT_EXPECT_EQ(test, dst->o_lease->state, src->o_lease->state);
	KUNIT_EXPECT_EQ(test, dst->o_lease->new_state,
			src->o_lease->new_state);
	KUNIT_EXPECT_EQ(test, dst->o_lease->epoch, src->o_lease->epoch);
	KUNIT_EXPECT_EQ(test, dst->o_lease->version, src->o_lease->version);
	KUNIT_EXPECT_EQ(test, dst->o_lease->duration,
			src->o_lease->duration);
}

/*
 * REG-040: reg_parent_dir_lease_break
 *
 * Verify that set_oplock_level correctly assigns the oplock level
 * and propagates lease state for all standard grant paths.
 * This is the core of parent-directory lease break handling:
 * when a child is opened, the parent lease level must be
 * downgraded appropriately.
 */
static void reg_parent_dir_lease_break(struct kunit *test)
{
	struct oplock_info *opinfo = alloc_test_opinfo(test);
	struct lease_ctx_info lctx = {};

	memset(lctx.lease_key, 0xCC, SMB2_LEASE_KEY_SIZE);

	/* Test batch level */
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_WRITE_CACHING_LE |
			 SMB2_LEASE_HANDLE_CACHING_LE;
	set_oplock_level(opinfo, SMB2_OPLOCK_LEVEL_BATCH, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_BATCH);
	KUNIT_EXPECT_EQ(test, opinfo->o_lease->state, lctx.req_state);

	/* Test exclusive level */
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE |
			 SMB2_LEASE_WRITE_CACHING_LE;
	set_oplock_level(opinfo, SMB2_OPLOCK_LEVEL_EXCLUSIVE, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_EXCLUSIVE);

	/* Test level II */
	lctx.req_state = SMB2_LEASE_READ_CACHING_LE;
	set_oplock_level(opinfo, SMB2_OPLOCK_LEVEL_II, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_II);

	/* Test none level */
	set_oplock_level(opinfo, SMB2_OPLOCK_LEVEL_NONE, &lctx);
	KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_NONE);
}

static struct kunit_case ksmbd_regression_oplock_cases[] = {
	KUNIT_CASE(reg_dir_lease_rh_granted),
	KUNIT_CASE(reg_dir_lease_handle_break),
	KUNIT_CASE(reg_outstanding_async_counter),
	KUNIT_CASE(reg_parent_dir_lease_break),
	{}
};

static struct kunit_suite ksmbd_regression_oplock_suite = {
	.name = "ksmbd_regression_oplock",
	.test_cases = ksmbd_regression_oplock_cases,
};

kunit_test_suite(ksmbd_regression_oplock_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit regression tests for ksmbd oplock/lease edge cases");
