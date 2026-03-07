// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 pure-logic functions (smb1pdu.c)
 *
 *   Tests exercise the VISIBLE_IF_KUNIT-exported functions from smb1pdu.c:
 *   file_create_dispostion_flags, convert_generic_access_flags,
 *   smb_get_dos_attr, get_filetype, smb_NTtimeToUnix, unix_to_dos_time,
 *   andx_response_buffer, cifs_convert_ace.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/posix_acl_xattr.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb1pdu.h"
#include "smb_common.h"
#include "misc.h"

/* VISIBLE_IF_KUNIT functions from smb1pdu.c */
extern int file_create_dispostion_flags(int dispostion, bool file_present);
extern int convert_generic_access_flags(int access_flag, int *open_flags,
					int *may_flags, int attrib);
extern __u32 smb_get_dos_attr(struct kstat *stat);
extern __u32 get_filetype(mode_t mode);
extern struct timespec64 smb_NTtimeToUnix(__le64 ntutc);
extern void unix_to_dos_time(struct timespec64 ts, __le16 *time, __le16 *date);
extern char *andx_response_buffer(char *buf, size_t buf_size, size_t min_size);
extern void cifs_convert_ace(struct posix_acl_xattr_entry *ace,
			     struct cifs_posix_ace *cifs_ace);

/* ================================================================
 * file_create_dispostion_flags() tests (13 cases)
 * ================================================================ */

static void test_disposition_supersede_present(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_SUPERSEDE, true);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_TRUNC);
}

static void test_disposition_supersede_absent(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_SUPERSEDE, false);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_CREAT);
}

static void test_disposition_open_present(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OPEN, true);

	KUNIT_EXPECT_EQ(test, flags, 0);
}

static void test_disposition_open_absent(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OPEN, false);

	KUNIT_EXPECT_EQ(test, flags, -ENOENT);
}

static void test_disposition_create_present(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_CREATE, true);

	KUNIT_EXPECT_EQ(test, flags, -EEXIST);
}

static void test_disposition_create_absent(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_CREATE, false);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_CREAT);
}

static void test_disposition_open_if_present(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OPEN_IF, true);

	KUNIT_EXPECT_EQ(test, flags, 0);
}

static void test_disposition_open_if_absent(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OPEN_IF, false);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_CREAT);
}

static void test_disposition_overwrite_present(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OVERWRITE, true);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_TRUNC);
}

static void test_disposition_overwrite_absent(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OVERWRITE, false);

	KUNIT_EXPECT_EQ(test, flags, -ENOENT);
}

static void test_disposition_overwrite_if_present(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OVERWRITE_IF, true);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_TRUNC);
}

static void test_disposition_overwrite_if_absent(struct kunit *test)
{
	int flags = file_create_dispostion_flags(FILE_OVERWRITE_IF, false);

	KUNIT_EXPECT_GE(test, flags, 0);
	KUNIT_EXPECT_TRUE(test, flags & O_CREAT);
}

static void test_disposition_invalid(struct kunit *test)
{
	int flags = file_create_dispostion_flags(0xFF, true);

	KUNIT_EXPECT_EQ(test, flags, -EINVAL);
}

/* ================================================================
 * smb_get_dos_attr() tests (5 cases)
 * ================================================================ */

static void test_dos_attr_regular_writable(struct kunit *test)
{
	struct kstat stat = {};

	stat.mode = S_IFREG | 0644;
	stat.size = 1024;
	stat.blocks = 8;
	stat.blksize = 512;

	__u32 attr = smb_get_dos_attr(&stat);

	/* Regular writable file: no READONLY, ends up as ATTR_NORMAL */
	KUNIT_EXPECT_FALSE(test, attr & ATTR_READONLY);
	KUNIT_EXPECT_TRUE(test, attr & ATTR_NORMAL);
}

static void test_dos_attr_readonly(struct kunit *test)
{
	struct kstat stat = {};

	stat.mode = S_IFREG | 0444;
	stat.size = 1024;
	stat.blocks = 8;
	stat.blksize = 512;

	__u32 attr = smb_get_dos_attr(&stat);

	KUNIT_EXPECT_TRUE(test, attr & ATTR_READONLY);
}

static void test_dos_attr_hidden_system(struct kunit *test)
{
	struct kstat stat = {};

	stat.mode = S_IFREG | S_ISVTX | 0644;
	stat.size = 1024;
	stat.blocks = 8;
	stat.blksize = 512;

	__u32 attr = smb_get_dos_attr(&stat);

	KUNIT_EXPECT_TRUE(test, attr & ATTR_HIDDEN);
	KUNIT_EXPECT_TRUE(test, attr & ATTR_SYSTEM);
}

static void test_dos_attr_directory(struct kunit *test)
{
	struct kstat stat = {};

	stat.mode = S_IFDIR | 0755;
	stat.size = 4096;
	stat.blocks = 8;
	stat.blksize = 512;

	__u32 attr = smb_get_dos_attr(&stat);

	KUNIT_EXPECT_TRUE(test, attr & ATTR_DIRECTORY);
}

static void test_dos_attr_sparse(struct kunit *test)
{
	struct kstat stat = {};

	stat.mode = S_IFREG | 0644;
	/* size > blocks * blksize triggers ATTR_SPARSE */
	stat.size = 1048576;
	stat.blocks = 1;
	stat.blksize = 512;

	__u32 attr = smb_get_dos_attr(&stat);

	KUNIT_EXPECT_TRUE(test, attr & ATTR_SPARSE);
}

/* ================================================================
 * get_filetype() tests (7 cases)
 * ================================================================ */

static void test_filetype_regular(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFREG), (__u32)UNIX_FILE);
}

static void test_filetype_directory(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFDIR), (__u32)UNIX_DIR);
}

static void test_filetype_symlink(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFLNK), (__u32)UNIX_SYMLINK);
}

static void test_filetype_chardev(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFCHR), (__u32)UNIX_CHARDEV);
}

static void test_filetype_blockdev(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFBLK), (__u32)UNIX_BLOCKDEV);
}

static void test_filetype_fifo(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFIFO), (__u32)UNIX_FIFO);
}

static void test_filetype_socket(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, get_filetype(S_IFSOCK), (__u32)UNIX_SOCKET);
}

/* ================================================================
 * smb_NTtimeToUnix() / unix_to_dos_time() tests (5 cases)
 * ================================================================ */

static void test_nttime_zero(struct kunit *test)
{
	struct timespec64 ts = smb_NTtimeToUnix(cpu_to_le64(0));

	/*
	 * NT time 0 corresponds to a date before the Unix epoch.
	 * The result should be a negative tv_sec.
	 */
	KUNIT_EXPECT_LT(test, ts.tv_sec, (time64_t)0);
}

static void test_nttime_epoch(struct kunit *test)
{
	/*
	 * Unix epoch (1970-01-01) in NT time:
	 * NTFS_TIME_OFFSET = ((369*365 + 89) * 24 * 3600) * 10000000
	 */
	struct timespec64 ts = smb_NTtimeToUnix(cpu_to_le64(NTFS_TIME_OFFSET));

	KUNIT_EXPECT_EQ(test, ts.tv_sec, (time64_t)0);
	KUNIT_EXPECT_EQ(test, ts.tv_nsec, (long)0);
}

static void test_nttime_known_timestamp(struct kunit *test)
{
	/*
	 * 2000-01-01 00:00:00 UTC in NT time:
	 * 30 years * 365.25 days * 86400 seconds * 10000000 =
	 * actually: 125911584000000000
	 */
	u64 nt_2000 = NTFS_TIME_OFFSET + (u64)30 * 365 * 86400 * 10000000ULL +
		      (u64)7 * 86400 * 10000000ULL; /* 7 leap days 1970-1999 */
	struct timespec64 ts = smb_NTtimeToUnix(cpu_to_le64(nt_2000));

	/* 2000-01-01 00:00:00 UTC = 946684800 seconds since epoch */
	KUNIT_EXPECT_EQ(test, ts.tv_sec, (time64_t)946684800);
}

static void test_dos_time_roundtrip(struct kunit *test)
{
	struct timespec64 ts = { .tv_sec = 946684800, .tv_nsec = 0 };
	__le16 dos_time, dos_date;
	__le16 dos_time2, dos_date2;

	unix_to_dos_time(ts, &dos_time, &dos_date);

	/* Same input should produce same output */
	unix_to_dos_time(ts, &dos_time2, &dos_date2);
	KUNIT_EXPECT_EQ(test, dos_time, dos_time2);
	KUNIT_EXPECT_EQ(test, dos_date, dos_date2);
}

static void test_dos_time_date_nonzero(struct kunit *test)
{
	/* A recent timestamp should produce non-zero DOS time and date */
	struct timespec64 ts = { .tv_sec = 1609459200, .tv_nsec = 0 }; /* 2021-01-01 */
	__le16 dos_time, dos_date;

	unix_to_dos_time(ts, &dos_time, &dos_date);

	/* Both should be non-zero for a valid date after 1980 */
	KUNIT_EXPECT_NE(test, dos_date, cpu_to_le16(0));
}

/* ================================================================
 * andx_response_buffer() tests (3 cases)
 * ================================================================ */

static void test_andx_buffer_valid(struct kunit *test)
{
	/*
	 * andx_response_buffer reads get_rfc1002_len(buf) from the
	 * first 4 bytes (BE32, bottom 24 bits). Simulate a buffer
	 * with pdu_length = 64.
	 */
	char buf[256];
	char *result;

	memset(buf, 0, sizeof(buf));
	/* Set RFC1002 length to 64 (big-endian in first 4 bytes) */
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 64;

	result = andx_response_buffer(buf, sizeof(buf), 32);
	KUNIT_ASSERT_NOT_NULL(test, result);
	/* offset = 4 + 64 = 68, so result should point to buf[68] */
	KUNIT_EXPECT_PTR_EQ(test, result, buf + 68);
}

static void test_andx_buffer_too_small(struct kunit *test)
{
	char buf[64];
	char *result;

	memset(buf, 0, sizeof(buf));
	/* Set RFC1002 length to 60 -> offset = 64, need 32 more = 96 > 64 */
	buf[3] = 60;

	result = andx_response_buffer(buf, sizeof(buf), 32);
	KUNIT_EXPECT_NULL(test, result);
}

static void test_andx_buffer_exact_fit(struct kunit *test)
{
	char buf[100];
	char *result;

	memset(buf, 0, sizeof(buf));
	/* Set RFC1002 length to 80 -> offset = 84, need 16 -> total 100 */
	buf[3] = 80;

	result = andx_response_buffer(buf, 100, 16);
	KUNIT_ASSERT_NOT_NULL(test, result);
	KUNIT_EXPECT_PTR_EQ(test, result, buf + 84);
}

/* ================================================================
 * cifs_convert_ace() tests (2 cases)
 * ================================================================ */

static void test_convert_ace_basic(struct kunit *test)
{
	struct posix_acl_xattr_entry ace = {};
	struct cifs_posix_ace cifs_ace = {};

	cifs_ace.cifs_e_perm = 7;    /* rwx */
	cifs_ace.cifs_e_tag = 1;     /* ACL_USER */
	cifs_ace.cifs_uid = cpu_to_le64(1000);

	cifs_convert_ace(&ace, &cifs_ace);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(ace.e_perm), 7);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ace.e_tag), 1);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ace.e_id), (__u32)1000);
}

static void test_convert_ace_zero(struct kunit *test)
{
	struct posix_acl_xattr_entry ace = {};
	struct cifs_posix_ace cifs_ace = {};

	cifs_ace.cifs_e_perm = 0;
	cifs_ace.cifs_e_tag = 0;
	cifs_ace.cifs_uid = cpu_to_le64(0);

	cifs_convert_ace(&ace, &cifs_ace);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(ace.e_perm), 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ace.e_tag), 0);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ace.e_id), (__u32)0);
}

/* ================================================================
 * Test case array and suite definition
 * ================================================================ */

static struct kunit_case ksmbd_smb1_logic_test_cases[] = {
	/* file_create_dispostion_flags */
	KUNIT_CASE(test_disposition_supersede_present),
	KUNIT_CASE(test_disposition_supersede_absent),
	KUNIT_CASE(test_disposition_open_present),
	KUNIT_CASE(test_disposition_open_absent),
	KUNIT_CASE(test_disposition_create_present),
	KUNIT_CASE(test_disposition_create_absent),
	KUNIT_CASE(test_disposition_open_if_present),
	KUNIT_CASE(test_disposition_open_if_absent),
	KUNIT_CASE(test_disposition_overwrite_present),
	KUNIT_CASE(test_disposition_overwrite_absent),
	KUNIT_CASE(test_disposition_overwrite_if_present),
	KUNIT_CASE(test_disposition_overwrite_if_absent),
	KUNIT_CASE(test_disposition_invalid),
	/* smb_get_dos_attr */
	KUNIT_CASE(test_dos_attr_regular_writable),
	KUNIT_CASE(test_dos_attr_readonly),
	KUNIT_CASE(test_dos_attr_hidden_system),
	KUNIT_CASE(test_dos_attr_directory),
	KUNIT_CASE(test_dos_attr_sparse),
	/* get_filetype */
	KUNIT_CASE(test_filetype_regular),
	KUNIT_CASE(test_filetype_directory),
	KUNIT_CASE(test_filetype_symlink),
	KUNIT_CASE(test_filetype_chardev),
	KUNIT_CASE(test_filetype_blockdev),
	KUNIT_CASE(test_filetype_fifo),
	KUNIT_CASE(test_filetype_socket),
	/* smb_NTtimeToUnix / unix_to_dos_time */
	KUNIT_CASE(test_nttime_zero),
	KUNIT_CASE(test_nttime_epoch),
	KUNIT_CASE(test_nttime_known_timestamp),
	KUNIT_CASE(test_dos_time_roundtrip),
	KUNIT_CASE(test_dos_time_date_nonzero),
	/* andx_response_buffer */
	KUNIT_CASE(test_andx_buffer_valid),
	KUNIT_CASE(test_andx_buffer_too_small),
	KUNIT_CASE(test_andx_buffer_exact_fit),
	/* cifs_convert_ace */
	KUNIT_CASE(test_convert_ace_basic),
	KUNIT_CASE(test_convert_ace_zero),
	{}
};

static struct kunit_suite ksmbd_smb1_logic_test_suite = {
	.name = "ksmbd_smb1_logic",
	.test_cases = ksmbd_smb1_logic_test_cases,
};

kunit_test_suite(ksmbd_smb1_logic_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB1 pure-logic functions");
