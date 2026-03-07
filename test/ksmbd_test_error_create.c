// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit error-path tests for SMB2 create subsystem (smb2_create.c).
 *
 *   These tests exercise smb2_create_open_flags with various invalid
 *   dispositions, flag conflicts, and access/disposition combinations.
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
 * err_create_open_existing_file - FILE_OPEN on existing file: no O_CREAT.
 */
static void err_create_open_existing_file(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	/* FILE_OPEN on existing file: no O_CREAT, no O_TRUNC */
	KUNIT_EXPECT_FALSE(test, (oflags & O_CREAT) != 0);
	KUNIT_EXPECT_FALSE(test, (oflags & O_TRUNC) != 0);
}

/*
 * err_create_open_nonexistent - FILE_OPEN on missing file: no O_CREAT.
 */
static void err_create_open_nonexistent(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	/* FILE_OPEN on non-existing: O_CREAT cleared */
	KUNIT_EXPECT_FALSE(test, (oflags & O_CREAT) != 0);
}

/*
 * err_create_create_existing - FILE_CREATE on existing file: no O_TRUNC.
 */
static void err_create_create_existing(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_CREATE_LE,
					&may_flags,
					0, S_IFREG);
	/* FILE_CREATE on existing: no truncation */
	KUNIT_EXPECT_FALSE(test, (oflags & O_TRUNC) != 0);
}

/*
 * err_create_create_nonexistent - FILE_CREATE on missing: O_CREAT set.
 */
static void err_create_create_nonexistent(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_CREATE_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_CREAT) != 0);
}

/*
 * err_create_supersede_existing - FILE_SUPERSEDE on existing: O_TRUNC.
 */
static void err_create_supersede_existing(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_SUPERSEDE_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_TRUNC) != 0);
}

/*
 * err_create_supersede_nonexistent - FILE_SUPERSEDE on missing: O_CREAT.
 */
static void err_create_supersede_nonexistent(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_SUPERSEDE_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_CREAT) != 0);
}

/*
 * err_create_overwrite_existing - FILE_OVERWRITE on existing: O_TRUNC.
 */
static void err_create_overwrite_existing(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OVERWRITE_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_TRUNC) != 0);
}

/*
 * err_create_overwrite_nonexistent - FILE_OVERWRITE on missing: no O_CREAT.
 */
static void err_create_overwrite_nonexistent(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_OVERWRITE_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_FALSE(test, (oflags & O_CREAT) != 0);
}

/*
 * err_create_overwrite_if_existing - FILE_OVERWRITE_IF on existing: O_TRUNC.
 */
static void err_create_overwrite_if_existing(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OVERWRITE_IF_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_TRUNC) != 0);
}

/*
 * err_create_overwrite_if_nonexistent - FILE_OVERWRITE_IF on missing: O_CREAT.
 */
static void err_create_overwrite_if_nonexistent(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_OVERWRITE_IF_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_CREAT) != 0);
}

/*
 * err_create_open_if_nonexistent - FILE_OPEN_IF on missing: O_CREAT.
 */
static void err_create_open_if_nonexistent(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_OPEN_IF_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_CREAT) != 0);
}

/*
 * err_create_read_only_access - Read-only access produces O_RDONLY.
 */
static void err_create_read_only_access(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	/* O_RDONLY is 0, so check no write bits set */
	KUNIT_EXPECT_FALSE(test, (oflags & O_WRONLY) != 0);
	KUNIT_EXPECT_FALSE(test, (oflags & O_RDWR) != 0);
	KUNIT_EXPECT_TRUE(test, (may_flags & MAY_READ) != 0);
}

/*
 * err_create_write_only_access - Write-only access produces O_WRONLY.
 */
static void err_create_write_only_access(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_WRONLY) != 0);
	KUNIT_EXPECT_TRUE(test, (may_flags & MAY_WRITE) != 0);
}

/*
 * err_create_rdwr_access - Read+Write access produces O_RDWR.
 */
static void err_create_rdwr_access(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE | FILE_WRITE_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_RDWR) != 0);
	KUNIT_EXPECT_TRUE(test, (may_flags & MAY_READ) != 0);
	KUNIT_EXPECT_TRUE(test, (may_flags & MAY_WRITE) != 0);
}

/*
 * err_create_directory_strips_write - Directory access strips write bits.
 */
static void err_create_directory_strips_write(struct kunit *test)
{
	int may_flags;
	int oflags;

	/* FILE_DIRECTORY_FILE in coptions should cause write access strip */
	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					FILE_DIRECTORY_FILE_LE,
					S_IFDIR);
	/* After stripping write, should be read-only */
	KUNIT_EXPECT_FALSE(test, (oflags & O_WRONLY) != 0);
}

/*
 * err_create_read_attributes_opath - FILE_READ_ATTRIBUTES produces O_PATH.
 */
static void err_create_read_attributes_opath(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_ATTRIBUTES_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_PATH) != 0);
}

/*
 * err_create_block_device_opath - Block device mode produces O_PATH.
 */
static void err_create_block_device_opath(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFBLK);
	KUNIT_EXPECT_TRUE(test, (oflags & O_PATH) != 0);
}

/*
 * err_create_char_device_opath - Char device mode produces O_PATH.
 */
static void err_create_char_device_opath(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFCHR);
	KUNIT_EXPECT_TRUE(test, (oflags & O_PATH) != 0);
}

/*
 * err_create_always_nonblock_largefile - O_NONBLOCK|O_LARGEFILE always set.
 */
static void err_create_always_nonblock_largefile(struct kunit *test)
{
	int may_flags;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_TRUE(test, (oflags & O_NONBLOCK) != 0);
	KUNIT_EXPECT_TRUE(test, (oflags & O_LARGEFILE) != 0);
}

/*
 * err_create_invalid_disposition_existing - Invalid disposition (0x06) on
 * existing.
 *
 * Disposition values beyond FILE_OVERWRITE_IF (0x05) should fall through
 * the switch default and produce no O_CREAT/O_TRUNC.
 */
static void err_create_invalid_disposition_existing(struct kunit *test)
{
	int may_flags;
	int oflags;

	/* 0x06 masked by FILE_CREATE_MASK_LE (0x07) => 0x06, unknown case */
	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					cpu_to_le32(0x06),
					&may_flags,
					0, S_IFREG);
	KUNIT_EXPECT_FALSE(test, (oflags & O_CREAT) != 0);
	KUNIT_EXPECT_FALSE(test, (oflags & O_TRUNC) != 0);
}

static struct kunit_case error_create_cases[] = {
	KUNIT_CASE(err_create_open_existing_file),
	KUNIT_CASE(err_create_open_nonexistent),
	KUNIT_CASE(err_create_create_existing),
	KUNIT_CASE(err_create_create_nonexistent),
	KUNIT_CASE(err_create_supersede_existing),
	KUNIT_CASE(err_create_supersede_nonexistent),
	KUNIT_CASE(err_create_overwrite_existing),
	KUNIT_CASE(err_create_overwrite_nonexistent),
	KUNIT_CASE(err_create_overwrite_if_existing),
	KUNIT_CASE(err_create_overwrite_if_nonexistent),
	KUNIT_CASE(err_create_open_if_nonexistent),
	KUNIT_CASE(err_create_read_only_access),
	KUNIT_CASE(err_create_write_only_access),
	KUNIT_CASE(err_create_rdwr_access),
	KUNIT_CASE(err_create_directory_strips_write),
	KUNIT_CASE(err_create_read_attributes_opath),
	KUNIT_CASE(err_create_block_device_opath),
	KUNIT_CASE(err_create_char_device_opath),
	KUNIT_CASE(err_create_always_nonblock_largefile),
	KUNIT_CASE(err_create_invalid_disposition_existing),
	{}
};

static struct kunit_suite error_create_suite = {
	.name = "ksmbd_error_create",
	.test_cases = error_create_cases,
};

kunit_test_suites(&error_create_suite);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error-path tests for ksmbd create subsystem");
