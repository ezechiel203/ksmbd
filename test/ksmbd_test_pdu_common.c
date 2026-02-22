// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for PDU common helpers (smb2_pdu_common.c)
 *
 *   These tests replicate the pure logic of smb2_get_reparse_tag_special_file()
 *   and smb2_get_dos_mode() without calling into the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/types.h>

/* Replicate reparse tag constants from smbfsctl.h */
#define TEST_IO_REPARSE_TAG_LX_SYMLINK	cpu_to_le32(0xA000001D)
#define TEST_IO_REPARSE_TAG_AF_UNIX	cpu_to_le32(0x80000023)
#define TEST_IO_REPARSE_TAG_LX_FIFO	cpu_to_le32(0x80000024)
#define TEST_IO_REPARSE_TAG_LX_CHR	cpu_to_le32(0x80000025)
#define TEST_IO_REPARSE_TAG_LX_BLK	cpu_to_le32(0x80000026)

/* Replicate file attribute constants from smb_common.h */
#define TEST_ATTR_READONLY	0x0001
#define TEST_ATTR_HIDDEN	0x0002
#define TEST_ATTR_SYSTEM	0x0004
#define TEST_ATTR_DIRECTORY	0x0010
#define TEST_ATTR_ARCHIVE	0x0020
#define TEST_ATTR_SPARSE	0x0200
#define TEST_ATTR_REPARSE	0x0400

/*
 * Replicate smb2_get_reparse_tag_special_file() from smb2_pdu_common.c
 */
static __le32 test_get_reparse_tag(umode_t mode)
{
	if (S_ISDIR(mode) || S_ISREG(mode))
		return 0;

	if (S_ISLNK(mode))
		return TEST_IO_REPARSE_TAG_LX_SYMLINK;
	else if (S_ISFIFO(mode))
		return TEST_IO_REPARSE_TAG_LX_FIFO;
	else if (S_ISSOCK(mode))
		return TEST_IO_REPARSE_TAG_AF_UNIX;
	else if (S_ISCHR(mode))
		return TEST_IO_REPARSE_TAG_LX_CHR;
	else if (S_ISBLK(mode))
		return TEST_IO_REPARSE_TAG_LX_BLK;

	return 0;
}

/*
 * Replicate smb2_get_dos_mode() from smb2_pdu_common.c.
 * We omit server_conf.share_fake_fscaps check since that requires
 * module state; instead we test the attribute logic directly.
 */
static int test_get_dos_mode(umode_t mode, int attribute, bool sparse_support)
{
	int attr = 0;

	if (S_ISDIR(mode)) {
		attr = TEST_ATTR_DIRECTORY |
			(attribute & (TEST_ATTR_HIDDEN | TEST_ATTR_SYSTEM));
	} else {
		attr = (attribute & 0x00005137) | TEST_ATTR_ARCHIVE;
		attr &= ~(TEST_ATTR_DIRECTORY);
		if (S_ISREG(mode) && sparse_support)
			attr |= TEST_ATTR_SPARSE;

		if (test_get_reparse_tag(mode))
			attr |= TEST_ATTR_REPARSE;
	}

	return attr;
}

/* --- smb2_get_reparse_tag_special_file() tests --- */

/*
 * test_reparse_tag_fifo - S_IFIFO maps to IO_REPARSE_TAG_LX_FIFO
 */
static void test_reparse_tag_fifo(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFIFO);

	KUNIT_EXPECT_EQ(test, tag, TEST_IO_REPARSE_TAG_LX_FIFO);
}

/*
 * test_reparse_tag_sock - S_IFSOCK maps to IO_REPARSE_TAG_AF_UNIX
 */
static void test_reparse_tag_sock(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFSOCK);

	KUNIT_EXPECT_EQ(test, tag, TEST_IO_REPARSE_TAG_AF_UNIX);
}

/*
 * test_reparse_tag_chr - S_IFCHR maps to IO_REPARSE_TAG_LX_CHR
 */
static void test_reparse_tag_chr(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFCHR);

	KUNIT_EXPECT_EQ(test, tag, TEST_IO_REPARSE_TAG_LX_CHR);
}

/*
 * test_reparse_tag_blk - S_IFBLK maps to IO_REPARSE_TAG_LX_BLK
 */
static void test_reparse_tag_blk(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFBLK);

	KUNIT_EXPECT_EQ(test, tag, TEST_IO_REPARSE_TAG_LX_BLK);
}

/*
 * test_reparse_tag_lnk - S_IFLNK maps to IO_REPARSE_TAG_LX_SYMLINK
 */
static void test_reparse_tag_lnk(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFLNK);

	KUNIT_EXPECT_EQ(test, tag, TEST_IO_REPARSE_TAG_LX_SYMLINK);
}

/*
 * test_reparse_tag_dir_returns_zero - directories return 0
 */
static void test_reparse_tag_dir_returns_zero(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFDIR | 0755);

	KUNIT_EXPECT_EQ(test, tag, (__le32)0);
}

/*
 * test_reparse_tag_reg_returns_zero - regular files return 0
 */
static void test_reparse_tag_reg_returns_zero(struct kunit *test)
{
	__le32 tag = test_get_reparse_tag(S_IFREG | 0644);

	KUNIT_EXPECT_EQ(test, tag, (__le32)0);
}

/* --- smb2_get_dos_mode() tests --- */

/*
 * test_dos_mode_directory - S_IFDIR sets ATTR_DIRECTORY
 */
static void test_dos_mode_directory(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFDIR | 0755, 0, false);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_DIRECTORY);
	KUNIT_EXPECT_FALSE(test, attr & TEST_ATTR_ARCHIVE);
}

/*
 * test_dos_mode_directory_hidden - directory with HIDDEN attribute
 */
static void test_dos_mode_directory_hidden(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFDIR | 0755, TEST_ATTR_HIDDEN, false);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_DIRECTORY);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_HIDDEN);
}

/*
 * test_dos_mode_directory_system - directory with SYSTEM attribute
 */
static void test_dos_mode_directory_system(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFDIR | 0755, TEST_ATTR_SYSTEM, false);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_DIRECTORY);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_SYSTEM);
}

/*
 * test_dos_mode_regular_file_default - regular file gets ATTR_ARCHIVE
 */
static void test_dos_mode_regular_file_default(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFREG | 0644, 0, false);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_ARCHIVE);
	KUNIT_EXPECT_FALSE(test, attr & TEST_ATTR_DIRECTORY);
}

/*
 * test_dos_mode_regular_readonly - readonly attribute passed through
 */
static void test_dos_mode_regular_readonly(struct kunit *test)
{
	int attr;

	/* 0x00005137 mask includes ATTR_READONLY (0x0001) */
	attr = test_get_dos_mode(S_IFREG | 0444, TEST_ATTR_READONLY, false);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_READONLY);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_ARCHIVE);
}

/*
 * test_dos_mode_fifo_gets_reparse - FIFO gets ATTR_REPARSE
 */
static void test_dos_mode_fifo_gets_reparse(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFIFO, 0, false);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_REPARSE);
}

/*
 * test_dos_mode_sparse_support - sparse flag set when supported
 */
static void test_dos_mode_sparse_support(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFREG | 0644, 0, true);
	KUNIT_EXPECT_TRUE(test, attr & TEST_ATTR_SPARSE);
}

/*
 * test_dos_mode_no_sparse_without_support - no sparse without support
 */
static void test_dos_mode_no_sparse_without_support(struct kunit *test)
{
	int attr;

	attr = test_get_dos_mode(S_IFREG | 0644, 0, false);
	KUNIT_EXPECT_FALSE(test, attr & TEST_ATTR_SPARSE);
}

static struct kunit_case ksmbd_pdu_common_test_cases[] = {
	KUNIT_CASE(test_reparse_tag_fifo),
	KUNIT_CASE(test_reparse_tag_sock),
	KUNIT_CASE(test_reparse_tag_chr),
	KUNIT_CASE(test_reparse_tag_blk),
	KUNIT_CASE(test_reparse_tag_lnk),
	KUNIT_CASE(test_reparse_tag_dir_returns_zero),
	KUNIT_CASE(test_reparse_tag_reg_returns_zero),
	KUNIT_CASE(test_dos_mode_directory),
	KUNIT_CASE(test_dos_mode_directory_hidden),
	KUNIT_CASE(test_dos_mode_directory_system),
	KUNIT_CASE(test_dos_mode_regular_file_default),
	KUNIT_CASE(test_dos_mode_regular_readonly),
	KUNIT_CASE(test_dos_mode_fifo_gets_reparse),
	KUNIT_CASE(test_dos_mode_sparse_support),
	KUNIT_CASE(test_dos_mode_no_sparse_without_support),
	{}
};

static struct kunit_suite ksmbd_pdu_common_test_suite = {
	.name = "ksmbd_pdu_common",
	.test_cases = ksmbd_pdu_common_test_cases,
};

kunit_test_suite(ksmbd_pdu_common_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd PDU common helpers");
