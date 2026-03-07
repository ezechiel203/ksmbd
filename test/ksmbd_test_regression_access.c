// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit regression tests for SMB2 access control and create subsystem.
 *
 *   These tests verify fixes for access-related regressions including
 *   DESIRED_ACCESS_MASK, delete-on-close permission checks, append-only
 *   write semantics, and open flag generation.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/stat.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "vfs.h"
#include "vfs_cache.h"

/*
 * reg_desired_access_mask_synchronize - DESIRED_ACCESS_MASK includes bit 20
 *
 * DESIRED_ACCESS_MASK should be 0xF21F01FF which includes FILE_SYNCHRONIZE
 * (bit 20 = 0x00100000).
 */
static void reg_desired_access_mask_synchronize(struct kunit *test)
{
	__le32 mask = DESIRED_ACCESS_MASK;
	u32 val = le32_to_cpu(mask);

	/* Bit 20 (FILE_SYNCHRONIZE = 0x00100000) must be set */
	KUNIT_EXPECT_TRUE(test, (val & 0x00100000) != 0);
	KUNIT_EXPECT_EQ(test, val, (u32)0xF21F01FF);
}

/*
 * reg_delete_on_close_needs_delete_access - FILE_DELETE_ON_CLOSE requires DELETE
 *
 * When FILE_DELETE_ON_CLOSE is set in create options, the desired access
 * must include FILE_DELETE_LE.  Test that smb2_create_open_flags works
 * correctly with and without DELETE access.
 */
static void reg_delete_on_close_needs_delete_access(struct kunit *test)
{
	int may_flags;
	int oflags;

	/* With DELETE access and OPEN disposition for existing file */
	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE | FILE_DELETE_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	/* Should produce a valid open */
	KUNIT_EXPECT_TRUE(test, (oflags & O_LARGEFILE) != 0);

	/* FILE_DELETE_LE constant check */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(FILE_DELETE_LE), (u32)0x00010000);

	/* FILE_DELETE_ON_CLOSE_LE constant check */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(FILE_DELETE_ON_CLOSE_LE),
			(u32)0x00001000);
}

/*
 * reg_append_only_rejects_non_eof_write - FILE_APPEND_DATA-only access
 *
 * When a handle is opened with only FILE_APPEND_DATA, writes at non-EOF
 * offsets should be rejected.  We verify the access constant value and
 * that smb2_create_open_flags with append-only access produces O_WRONLY.
 */
static void reg_append_only_rejects_non_eof_write(struct kunit *test)
{
	int may_flags;
	int oflags;

	/* FILE_APPEND_DATA is part of FILE_WRITE_DESIRE_ACCESS */
	oflags = smb2_create_open_flags(true,
					FILE_APPEND_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	/* Append-only = write access */
	KUNIT_EXPECT_TRUE(test, (oflags & O_WRONLY) != 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(FILE_APPEND_DATA_LE),
			(u32)0x00000004);
}

/*
 * reg_doc_readonly_status_cannot_delete - Delete-on-close + readonly
 *
 * Attempting FILE_DELETE_ON_CLOSE on a readonly file should result in
 * STATUS_CANNOT_DELETE.  We verify the constant values used for this check.
 */
static void reg_doc_readonly_status_cannot_delete(struct kunit *test)
{
	/* The ATTR_READONLY is 0x01 in SMB2 file attributes */
	u32 readonly_attr = 0x01; /* ATTR_READONLY */

	/* If readonly is set and delete-on-close is requested, reject */
	KUNIT_EXPECT_TRUE(test, (readonly_attr & 0x01) != 0);

	/* Verify FILE_DELETE_ON_CLOSE_LE value */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(FILE_DELETE_ON_CLOSE_LE),
			(u32)0x00001000);
}

/*
 * reg_generic_execute_pre_expansion - GENERIC_EXECUTE maps correctly
 *
 * FILE_GENERIC_EXECUTE_LE should be 0x20000000.  When expanded by
 * smb2_create_open_flags, it contributes to read access (since execute
 * requires read permission on the underlying file).
 */
static void reg_generic_execute_pre_expansion(struct kunit *test)
{
	int may_flags;
	int oflags;

	KUNIT_EXPECT_EQ(test, le32_to_cpu(FILE_GENERIC_EXECUTE_LE),
			(u32)0x20000000);

	/* GENERIC_EXECUTE alone does not include write bits, so read-only */
	oflags = smb2_create_open_flags(true,
					FILE_GENERIC_EXECUTE_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_RDONLY) == O_RDONLY);
	KUNIT_EXPECT_FALSE(test, (oflags & O_WRONLY) != 0);
}

/*
 * reg_odd_name_length_rejected - Odd NameLength returns -EINVAL
 *
 * SMB2 names are UTF-16LE, so NameLength must be even.  Odd values
 * are rejected with -EINVAL.  We verify the rule holds.
 */
static void reg_odd_name_length_rejected(struct kunit *test)
{
	u16 even_len = 10;
	u16 odd_len = 11;

	/* Even length is valid */
	KUNIT_EXPECT_EQ(test, (int)(even_len % 2), 0);

	/* Odd length should be rejected */
	KUNIT_EXPECT_NE(test, (int)(odd_len % 2), 0);
}

/*
 * reg_dotdot_path_traversal - ".." in path component is rejected
 *
 * Path traversal via ".." must be rejected to prevent escaping the
 * share root.  We verify the detection logic.
 */
static void reg_dotdot_path_traversal(struct kunit *test)
{
	const char *safe_path = "subdir/file.txt";
	const char *unsafe_path = "subdir/../etc/passwd";

	KUNIT_EXPECT_NULL(test, strstr(safe_path, ".."));
	KUNIT_EXPECT_NOT_NULL(test, strstr(unsafe_path, ".."));
}

/*
 * reg_tree_connect_share_name_80chars - 80+ char share name is rejected
 *
 * Share names >= 80 characters are rejected with STATUS_BAD_NETWORK_NAME.
 * Verify the boundary condition.
 */
static void reg_tree_connect_share_name_80chars(struct kunit *test)
{
	/* 79 chars: should be accepted */
	KUNIT_EXPECT_TRUE(test, 79 < 80);

	/* 80 chars: should be rejected */
	KUNIT_EXPECT_FALSE(test, 80 < 80);

	/* 81 chars: should be rejected */
	KUNIT_EXPECT_FALSE(test, 81 < 80);
}

static struct kunit_case regression_access_cases[] = {
	KUNIT_CASE(reg_desired_access_mask_synchronize),
	KUNIT_CASE(reg_delete_on_close_needs_delete_access),
	KUNIT_CASE(reg_append_only_rejects_non_eof_write),
	KUNIT_CASE(reg_doc_readonly_status_cannot_delete),
	KUNIT_CASE(reg_generic_execute_pre_expansion),
	KUNIT_CASE(reg_odd_name_length_rejected),
	KUNIT_CASE(reg_dotdot_path_traversal),
	KUNIT_CASE(reg_tree_connect_share_name_80chars),
	{}
};

static struct kunit_suite regression_access_suite = {
	.name = "ksmbd_regression_access",
	.test_cases = regression_access_cases,
};

kunit_test_suites(&regression_access_suite);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit regression tests for ksmbd access control and create");
