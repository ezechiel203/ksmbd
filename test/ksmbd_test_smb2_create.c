// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB2 create helpers (smb2_create.c)
 *
 *   Tests call real smb2_create_open_flags() via VISIBLE_IF_KUNIT.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/stat.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "smb_common.h"

/* --- smb2_create_open_flags() tests --- */

/*
 * test_open_flags_read_existing - opening existing file for read
 */
static void test_open_flags_read_existing(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_RDONLY);
	KUNIT_EXPECT_FALSE(test, oflags & O_CREAT);
	KUNIT_EXPECT_FALSE(test, oflags & O_TRUNC);
	KUNIT_EXPECT_TRUE(test, may_flags & MAY_READ);
}

/*
 * test_open_flags_write_existing - opening existing file for write
 */
static void test_open_flags_write_existing(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_WRONLY);
	KUNIT_EXPECT_TRUE(test, may_flags & MAY_WRITE);
}

/*
 * test_open_flags_readwrite - read+write access
 */
static void test_open_flags_readwrite(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE | FILE_WRITE_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_RDWR);
	KUNIT_EXPECT_TRUE(test, may_flags & MAY_READ);
	KUNIT_EXPECT_TRUE(test, may_flags & MAY_WRITE);
}

/*
 * test_open_flags_create_new - creating a new file
 */
static void test_open_flags_create_new(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_CREATE_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_CREAT);
}

/*
 * test_open_flags_overwrite - FILE_OVERWRITE truncates existing
 */
static void test_open_flags_overwrite(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OVERWRITE_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_TRUNC);
}

/*
 * test_open_flags_supersede - FILE_SUPERSEDE truncates existing
 */
static void test_open_flags_supersede(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_SUPERSEDE_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_TRUNC);
}

/*
 * test_open_flags_open_if_new - FILE_OPEN_IF on new file creates
 */
static void test_open_flags_open_if_new(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_WRITE_DATA_LE,
					FILE_OPEN_IF_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_CREAT);
}

/*
 * test_open_flags_directory_discards_write - directory strips write access
 */
static void test_open_flags_directory_discards_write(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_WRITE_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					FILE_DIRECTORY_FILE_LE,
					S_IFDIR | 0755);

	/* Write access stripped for directories, falls to O_RDONLY */
	KUNIT_EXPECT_TRUE(test, oflags & O_RDONLY);
}

/*
 * test_open_flags_read_attributes_opath - FILE_READ_ATTRIBUTES_LE uses O_PATH
 */
static void test_open_flags_read_attributes_opath(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_ATTRIBUTES_LE,
					FILE_OPEN_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_PATH);
}

/*
 * test_open_flags_nonblock_largefile - always sets O_NONBLOCK | O_LARGEFILE
 */
static void test_open_flags_nonblock_largefile(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(true,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_TRUE(test, oflags & O_NONBLOCK);
	KUNIT_EXPECT_TRUE(test, oflags & O_LARGEFILE);
}

/*
 * test_open_flags_open_nonexistent - FILE_OPEN on non-existent = no O_CREAT
 */
static void test_open_flags_open_nonexistent(struct kunit *test)
{
	int may_flags = 0;
	int oflags;

	oflags = smb2_create_open_flags(false,
					FILE_READ_DATA_LE,
					FILE_OPEN_LE,
					&may_flags,
					0,
					S_IFREG | 0644);

	KUNIT_EXPECT_FALSE(test, oflags & O_CREAT);
}

static struct kunit_case ksmbd_smb2_create_test_cases[] = {
	KUNIT_CASE(test_open_flags_read_existing),
	KUNIT_CASE(test_open_flags_write_existing),
	KUNIT_CASE(test_open_flags_readwrite),
	KUNIT_CASE(test_open_flags_create_new),
	KUNIT_CASE(test_open_flags_overwrite),
	KUNIT_CASE(test_open_flags_supersede),
	KUNIT_CASE(test_open_flags_open_if_new),
	KUNIT_CASE(test_open_flags_directory_discards_write),
	KUNIT_CASE(test_open_flags_read_attributes_opath),
	KUNIT_CASE(test_open_flags_nonblock_largefile),
	KUNIT_CASE(test_open_flags_open_nonexistent),
	{}
};

static struct kunit_suite ksmbd_smb2_create_test_suite = {
	.name = "ksmbd_smb2_create",
	.test_cases = ksmbd_smb2_create_test_cases,
};

kunit_test_suite(ksmbd_smb2_create_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 create helpers");
