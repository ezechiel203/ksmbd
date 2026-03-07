// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for newly-exported SMB1 pure-logic helper functions.
 *
 *   Tests cover the following VISIBLE_IF_KUNIT functions:
 *
 *   From smb1pdu.c:
 *     smb_cmd_to_str, smb_trans2_cmd_to_str, is_smbreq_unicode,
 *     ksmbd_openflags_to_mayflags, convert_open_flags,
 *     smb_posix_convert_flags, smb_get_disposition,
 *     convert_ace_to_cifs_ace, smb1_readdir_info_level_struct_sz,
 *     dos_date_time_to_unix
 *
 *   From smb1misc.c:
 *     smb1_req_struct_size, smb1_get_byte_count
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

/* Extern declarations for VISIBLE_IF_KUNIT functions */

/* smb1pdu.c */
extern const char *smb_cmd_to_str(u16 cmd);
extern const char *smb_trans2_cmd_to_str(u16 cmd);
extern int is_smbreq_unicode(struct smb_hdr *hdr);
extern int ksmbd_openflags_to_mayflags(int open_flags);
extern int convert_open_flags(bool file_present,
			      __u16 mode, __u16 dispostion,
			      int *may_flags);
extern __u32 smb_posix_convert_flags(__u32 flags, int *may_flags);
extern int smb_get_disposition(unsigned int flags, bool file_present,
			       struct kstat *stat, unsigned int *open_flags);
extern __u16 convert_ace_to_cifs_ace(struct cifs_posix_ace *cifs_ace,
				     const struct posix_acl_xattr_entry *local_ace);
extern int smb1_readdir_info_level_struct_sz(int info_level);
extern time64_t dos_date_time_to_unix(__le16 date, __le16 time);

/* smb1misc.c */
extern int smb1_req_struct_size(struct smb_hdr *hdr);
extern int smb1_get_byte_count(struct smb_hdr *hdr, unsigned int buflen);

/* ================================================================
 * smb_cmd_to_str() tests
 * ================================================================ */

static void test_cmd_to_str_negotiate(struct kunit *test)
{
	const char *s = smb_cmd_to_str(SMB_COM_NEGOTIATE);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "SMB_COM_NEGOTIATE");
}

static void test_cmd_to_str_close(struct kunit *test)
{
	const char *s = smb_cmd_to_str(SMB_COM_CLOSE);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "SMB_COM_CLOSE");
}

static void test_cmd_to_str_session_setup(struct kunit *test)
{
	const char *s = smb_cmd_to_str(SMB_COM_SESSION_SETUP_ANDX);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "SMB_COM_SESSION_SETUP_ANDX");
}

static void test_cmd_to_str_echo(struct kunit *test)
{
	const char *s = smb_cmd_to_str(SMB_COM_ECHO);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "SMB_COM_ECHO");
}

static void test_cmd_to_str_unknown(struct kunit *test)
{
	/* Command 0xFF is beyond the table */
	const char *s = smb_cmd_to_str(0xFF);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "unknown_cmd");
}

static void test_cmd_to_str_null_entry(struct kunit *test)
{
	/*
	 * Command 0x03 (SMB_COM_OPEN) has no entry in the table,
	 * so it should return NULL (the slot is NULL).
	 */
	const char *s = smb_cmd_to_str(0x03);

	/* NULL entry in table means the pointer is NULL */
	KUNIT_EXPECT_TRUE(test, s == NULL || strcmp(s, "unknown_cmd") != 0);
}

/* ================================================================
 * smb_trans2_cmd_to_str() tests
 * ================================================================ */

static void test_trans2_cmd_to_str_find_first(struct kunit *test)
{
	const char *s = smb_trans2_cmd_to_str(TRANS2_FIND_FIRST);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "TRANS2_FIND_FIRST");
}

static void test_trans2_cmd_to_str_query_path(struct kunit *test)
{
	const char *s = smb_trans2_cmd_to_str(TRANS2_QUERY_PATH_INFORMATION);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "TRANS2_QUERY_PATH_INFORMATION");
}

static void test_trans2_cmd_to_str_unknown(struct kunit *test)
{
	const char *s = smb_trans2_cmd_to_str(0xFF);

	KUNIT_ASSERT_NOT_NULL(test, s);
	KUNIT_EXPECT_STREQ(test, s, "unknown_trans2_cmd");
}

/* ================================================================
 * is_smbreq_unicode() tests
 * ================================================================ */

static void test_is_smbreq_unicode_set(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Flags2 = SMBFLG2_UNICODE;
	KUNIT_EXPECT_EQ(test, is_smbreq_unicode(&hdr), 1);
}

static void test_is_smbreq_unicode_clear(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Flags2 = 0;
	KUNIT_EXPECT_EQ(test, is_smbreq_unicode(&hdr), 0);
}

static void test_is_smbreq_unicode_other_flags(struct kunit *test)
{
	struct smb_hdr hdr = {};

	/* Set other flags but not UNICODE */
	hdr.Flags2 = SMBFLG2_ERR_STATUS | SMBFLG2_EXT_SEC;
	KUNIT_EXPECT_EQ(test, is_smbreq_unicode(&hdr), 0);
}

static void test_is_smbreq_unicode_all_flags(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Flags2 = SMBFLG2_UNICODE | SMBFLG2_ERR_STATUS | SMBFLG2_EXT_SEC;
	KUNIT_EXPECT_EQ(test, is_smbreq_unicode(&hdr), 1);
}

/* ================================================================
 * ksmbd_openflags_to_mayflags() tests
 * ================================================================ */

static void test_mayflags_rdonly(struct kunit *test)
{
	int may = ksmbd_openflags_to_mayflags(O_RDONLY);

	KUNIT_EXPECT_TRUE(test, may & MAY_OPEN);
	KUNIT_EXPECT_TRUE(test, may & MAY_READ);
	KUNIT_EXPECT_FALSE(test, may & MAY_WRITE);
}

static void test_mayflags_wronly(struct kunit *test)
{
	int may = ksmbd_openflags_to_mayflags(O_WRONLY);

	KUNIT_EXPECT_TRUE(test, may & MAY_OPEN);
	KUNIT_EXPECT_TRUE(test, may & MAY_WRITE);
	KUNIT_EXPECT_FALSE(test, may & MAY_READ);
}

static void test_mayflags_rdwr(struct kunit *test)
{
	int may = ksmbd_openflags_to_mayflags(O_RDWR);

	KUNIT_EXPECT_TRUE(test, may & MAY_OPEN);
	KUNIT_EXPECT_TRUE(test, may & MAY_READ);
	KUNIT_EXPECT_TRUE(test, may & MAY_WRITE);
}

static void test_mayflags_rdonly_with_extra(struct kunit *test)
{
	/* Extra flags like O_CREAT should not affect MAY flags */
	int may = ksmbd_openflags_to_mayflags(O_RDONLY | O_CREAT);

	KUNIT_EXPECT_TRUE(test, may & MAY_OPEN);
	KUNIT_EXPECT_TRUE(test, may & MAY_READ);
	KUNIT_EXPECT_FALSE(test, may & MAY_WRITE);
}

/* ================================================================
 * convert_open_flags() tests (OPEN_ANDX mode/disposition)
 * ================================================================ */

static void test_convert_open_flags_read_present(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	/* mode=SMBOPEN_READ(0), disposition=default(0, file present) */
	ret = convert_open_flags(true, SMBOPEN_READ, 0, &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, (ret & O_ACCMODE) == O_RDONLY);
}

static void test_convert_open_flags_write_present(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	ret = convert_open_flags(true, SMBOPEN_WRITE, 0, &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, (ret & O_ACCMODE) == O_WRONLY);
}

static void test_convert_open_flags_readwrite(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	ret = convert_open_flags(true, SMBOPEN_READWRITE, 0, &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, (ret & O_ACCMODE) == O_RDWR);
}

static void test_convert_open_flags_write_through(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	ret = convert_open_flags(true, SMBOPEN_READ | SMBOPEN_WRITE_THROUGH,
				 0, &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, ret & O_SYNC);
}

static void test_convert_open_flags_file_absent_no_create(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	/* File not present, disposition has no CREATE bit -> -EINVAL */
	ret = convert_open_flags(false, SMBOPEN_READ,
				 SMBOPEN_DISPOSITION_NONE, &may_flags);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_convert_open_flags_file_absent_create(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	ret = convert_open_flags(false, SMBOPEN_READ, SMBOPEN_OCREATE,
				 &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, ret & O_CREAT);
}

static void test_convert_open_flags_present_trunc(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	ret = convert_open_flags(true, SMBOPEN_WRITE, SMBOPEN_OTRUNC,
				 &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, ret & O_TRUNC);
}

static void test_convert_open_flags_present_append(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	ret = convert_open_flags(true, SMBOPEN_WRITE, SMBOPEN_OAPPEND,
				 &may_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, ret & O_APPEND);
}

static void test_convert_open_flags_present_none(struct kunit *test)
{
	int may_flags = 0;
	int ret;

	/* DISPOSITION_NONE on existing file -> -EEXIST */
	ret = convert_open_flags(true, SMBOPEN_READ,
				 SMBOPEN_DISPOSITION_NONE, &may_flags);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
}

/* ================================================================
 * smb_posix_convert_flags() tests
 * ================================================================ */

static void test_posix_flags_rdonly(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_RDONLY, &may_flags);

	KUNIT_EXPECT_TRUE(test, (ret & O_ACCMODE) == O_RDONLY);
}

static void test_posix_flags_wronly(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_WRONLY, &may_flags);

	KUNIT_EXPECT_TRUE(test, (ret & O_ACCMODE) == O_WRONLY);
}

static void test_posix_flags_rdwr(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_RDWR, &may_flags);

	KUNIT_EXPECT_TRUE(test, (ret & O_ACCMODE) == O_RDWR);
}

static void test_posix_flags_creat(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_RDONLY | SMB_O_CREAT,
					     &may_flags);

	KUNIT_EXPECT_TRUE(test, ret & O_CREAT);
}

static void test_posix_flags_append(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_WRONLY | SMB_O_APPEND,
					     &may_flags);

	KUNIT_EXPECT_TRUE(test, ret & O_APPEND);
}

static void test_posix_flags_sync(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_RDONLY | SMB_O_SYNC,
					     &may_flags);

	KUNIT_EXPECT_TRUE(test, ret & O_DSYNC);
}

static void test_posix_flags_directory(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_RDONLY | SMB_O_DIRECTORY,
					     &may_flags);

	KUNIT_EXPECT_TRUE(test, ret & O_DIRECTORY);
}

static void test_posix_flags_nofollow(struct kunit *test)
{
	int may_flags = 0;
	__u32 ret = smb_posix_convert_flags(SMB_O_RDONLY | SMB_O_NOFOLLOW,
					     &may_flags);

	KUNIT_EXPECT_TRUE(test, ret & O_NOFOLLOW);
}

/* ================================================================
 * smb_get_disposition() tests
 * ================================================================ */

static void test_get_disposition_creat_excl(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* CREAT|EXCL -> FILE_CREATE. File absent -> O_CREAT */
	ret = smb_get_disposition(SMB_O_CREAT | SMB_O_EXCL, false,
				  &stat, &open_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, open_flags & O_CREAT);
}

static void test_get_disposition_creat_excl_present(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* CREAT|EXCL -> FILE_CREATE. File present -> -EEXIST */
	ret = smb_get_disposition(SMB_O_CREAT | SMB_O_EXCL, true,
				  &stat, &open_flags);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
}

static void test_get_disposition_creat_trunc(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* CREAT|TRUNC -> FILE_OVERWRITE_IF. File present -> O_TRUNC */
	ret = smb_get_disposition(SMB_O_CREAT | SMB_O_TRUNC, true,
				  &stat, &open_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, open_flags & O_TRUNC);
}

static void test_get_disposition_plain_open(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* No flags -> FILE_OPEN. File present -> success, no create/trunc */
	ret = smb_get_disposition(0, true, &stat, &open_flags);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void test_get_disposition_plain_open_absent(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* No flags -> FILE_OPEN. File absent -> -ENOENT */
	ret = smb_get_disposition(0, false, &stat, &open_flags);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

static void test_get_disposition_creat_only(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* CREAT only -> FILE_OPEN_IF. File absent -> O_CREAT */
	ret = smb_get_disposition(SMB_O_CREAT, false, &stat, &open_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, open_flags & O_CREAT);
}

static void test_get_disposition_trunc_only(struct kunit *test)
{
	struct kstat stat = {};
	unsigned int open_flags = 0;
	int ret;

	/* TRUNC only -> FILE_OVERWRITE. File present -> O_TRUNC */
	ret = smb_get_disposition(SMB_O_TRUNC, true, &stat, &open_flags);
	KUNIT_EXPECT_GE(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, open_flags & O_TRUNC);
}

/* ================================================================
 * convert_ace_to_cifs_ace() tests
 * ================================================================ */

static void test_ace_to_cifs_basic(struct kunit *test)
{
	struct cifs_posix_ace cifs_ace = {};
	struct posix_acl_xattr_entry local_ace = {};
	__u16 ret;

	local_ace.e_perm = cpu_to_le16(7);    /* rwx */
	local_ace.e_tag = cpu_to_le16(1);     /* ACL_USER */
	local_ace.e_id = cpu_to_le32(1000);

	ret = convert_ace_to_cifs_ace(&cifs_ace, &local_ace);

	KUNIT_EXPECT_EQ(test, ret, (__u16)0);
	KUNIT_EXPECT_EQ(test, cifs_ace.cifs_e_perm, (__u8)7);
	KUNIT_EXPECT_EQ(test, cifs_ace.cifs_e_tag, (__u8)1);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(cifs_ace.cifs_uid), (u64)1000);
}

static void test_ace_to_cifs_negative_one_id(struct kunit *test)
{
	struct cifs_posix_ace cifs_ace = {};
	struct posix_acl_xattr_entry local_ace = {};

	local_ace.e_perm = cpu_to_le16(4);
	local_ace.e_tag = cpu_to_le16(0);
	local_ace.e_id = cpu_to_le32(-1);

	convert_ace_to_cifs_ace(&cifs_ace, &local_ace);

	/* -1 should be preserved in 64-bit form */
	KUNIT_EXPECT_EQ(test, le64_to_cpu(cifs_ace.cifs_uid),
			(u64)(s64)-1);
}

static void test_ace_to_cifs_zero(struct kunit *test)
{
	struct cifs_posix_ace cifs_ace = {};
	struct posix_acl_xattr_entry local_ace = {};

	local_ace.e_perm = cpu_to_le16(0);
	local_ace.e_tag = cpu_to_le16(0);
	local_ace.e_id = cpu_to_le32(0);

	convert_ace_to_cifs_ace(&cifs_ace, &local_ace);

	KUNIT_EXPECT_EQ(test, cifs_ace.cifs_e_perm, (__u8)0);
	KUNIT_EXPECT_EQ(test, cifs_ace.cifs_e_tag, (__u8)0);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(cifs_ace.cifs_uid), (u64)0);
}

/* ================================================================
 * smb1_readdir_info_level_struct_sz() tests
 * ================================================================ */

static void test_info_level_standard(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(SMB_FIND_FILE_INFO_STANDARD);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_both_dir(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(
			SMB_FIND_FILE_BOTH_DIRECTORY_INFO);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_unix(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(SMB_FIND_FILE_UNIX);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_names(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(SMB_FIND_FILE_NAMES_INFO);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_directory(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(
			SMB_FIND_FILE_DIRECTORY_INFO);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_id_full(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(
			SMB_FIND_FILE_ID_FULL_DIR_INFO);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_id_both(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(
			SMB_FIND_FILE_ID_BOTH_DIR_INFO);

	KUNIT_EXPECT_GT(test, sz, 0);
}

static void test_info_level_invalid(struct kunit *test)
{
	int sz = smb1_readdir_info_level_struct_sz(0xFFFF);

	KUNIT_EXPECT_EQ(test, sz, -EOPNOTSUPP);
}

/* ================================================================
 * dos_date_time_to_unix() tests
 * ================================================================ */

static void test_dos_datetime_2000_01_01(struct kunit *test)
{
	/*
	 * DOS date for 2000-01-01:
	 *   year = 2000-1980 = 20 -> bits 9-15
	 *   month = 1 -> bits 5-8
	 *   day = 1 -> bits 0-4
	 *   date = (20 << 9) | (1 << 5) | 1 = 0x2821
	 *
	 * DOS time for 00:00:00:
	 *   hour = 0, min = 0, sec/2 = 0 -> 0
	 */
	__le16 date = cpu_to_le16((20 << 9) | (1 << 5) | 1);
	__le16 time = cpu_to_le16(0);
	time64_t ts;

	ts = dos_date_time_to_unix(date, time);
	/* 2000-01-01 00:00:00 UTC = 946684800 */
	KUNIT_EXPECT_EQ(test, ts, (time64_t)946684800);
}

static void test_dos_datetime_1980_01_01(struct kunit *test)
{
	/* DOS epoch: 1980-01-01 00:00:00 */
	__le16 date = cpu_to_le16((0 << 9) | (1 << 5) | 1);
	__le16 time = cpu_to_le16(0);
	time64_t ts;

	ts = dos_date_time_to_unix(date, time);
	/* 1980-01-01 00:00:00 UTC = 315532800 */
	KUNIT_EXPECT_EQ(test, ts, (time64_t)315532800);
}

static void test_dos_datetime_with_time(struct kunit *test)
{
	/*
	 * 2000-06-15 13:30:22
	 * date: year=20, month=6, day=15
	 *   (20<<9) | (6<<5) | 15 = 0x28CF
	 * time: hour=13, min=30, sec=22/2=11
	 *   (13<<11) | (30<<5) | 11 = 0x6BCB
	 */
	__le16 date = cpu_to_le16((20 << 9) | (6 << 5) | 15);
	__le16 time = cpu_to_le16((13 << 11) | (30 << 5) | 11);
	time64_t ts;

	ts = dos_date_time_to_unix(date, time);
	KUNIT_EXPECT_GT(test, ts, (time64_t)0);
	/* Should be sometime in June 2000 */
	KUNIT_EXPECT_GT(test, ts, (time64_t)960000000);
}

static void test_dos_datetime_invalid_month_zero(struct kunit *test)
{
	/* month=0 is invalid */
	__le16 date = cpu_to_le16((20 << 9) | (0 << 5) | 1);
	__le16 time = cpu_to_le16(0);
	time64_t ts;

	ts = dos_date_time_to_unix(date, time);
	KUNIT_EXPECT_EQ(test, ts, (time64_t)0);
}

static void test_dos_datetime_invalid_day_zero(struct kunit *test)
{
	/* day=0 is invalid */
	__le16 date = cpu_to_le16((20 << 9) | (1 << 5) | 0);
	__le16 time = cpu_to_le16(0);
	time64_t ts;

	ts = dos_date_time_to_unix(date, time);
	KUNIT_EXPECT_EQ(test, ts, (time64_t)0);
}

/* ================================================================
 * smb1_req_struct_size() tests (smb1misc.c)
 * ================================================================ */

static void test_req_struct_negotiate(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_NEGOTIATE;
	hdr.WordCount = 0;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0);
}

static void test_req_struct_negotiate_bad_wc(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_NEGOTIATE;
	hdr.WordCount = 1;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), -EINVAL);
}

static void test_req_struct_close(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_CLOSE;
	hdr.WordCount = 3;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 3);
}

static void test_req_struct_echo(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_ECHO;
	hdr.WordCount = 1;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 1);
}

static void test_req_struct_session_setup_12(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_SESSION_SETUP_ANDX;
	hdr.WordCount = 0xc;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0xc);
}

static void test_req_struct_session_setup_13(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_SESSION_SETUP_ANDX;
	hdr.WordCount = 0xd;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0xd);
}

static void test_req_struct_session_setup_bad(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_SESSION_SETUP_ANDX;
	hdr.WordCount = 0xe;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), -EINVAL);
}

static void test_req_struct_nt_create(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_NT_CREATE_ANDX;
	hdr.WordCount = 0x18;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0x18);
}

static void test_req_struct_locking(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_LOCKING_ANDX;
	hdr.WordCount = 8;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 8);
}

static void test_req_struct_trans2(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_TRANSACTION2;
	hdr.WordCount = 0xf;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0xf);
}

static void test_req_struct_write(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_WRITE;
	hdr.WordCount = 5;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 5);
}

static void test_req_struct_tree_connect(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_TREE_CONNECT_ANDX;
	hdr.WordCount = 4;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 4);
}

static void test_req_struct_logoff(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_LOGOFF_ANDX;
	hdr.WordCount = 2;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 2);
}

static void test_req_struct_unknown_cmd(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = 0xFE;  /* Not a supported command */
	hdr.WordCount = 0;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), -EOPNOTSUPP);
}

static void test_req_struct_nt_transact(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_NT_TRANSACT;
	hdr.WordCount = 0x13;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0x13);
}

static void test_req_struct_nt_transact_too_small(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_NT_TRANSACT;
	hdr.WordCount = 0x12;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), -EINVAL);
}

static void test_req_struct_read_andx_10(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_READ_ANDX;
	hdr.WordCount = 0xa;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0xa);
}

static void test_req_struct_read_andx_12(struct kunit *test)
{
	struct smb_hdr hdr = {};

	hdr.Command = SMB_COM_READ_ANDX;
	hdr.WordCount = 0xc;
	KUNIT_EXPECT_EQ(test, smb1_req_struct_size(&hdr), 0xc);
}

/* ================================================================
 * smb1_get_byte_count() tests (smb1misc.c)
 * ================================================================ */

static void test_byte_count_close_zero(struct kunit *test)
{
	/*
	 * Build a minimal CLOSE request: hdr.WordCount=3, ByteCount=0
	 * The buffer must be large enough to hold the header + words + BC.
	 */
	char buf[64];
	struct smb_hdr *hdr = (struct smb_hdr *)buf;
	__le16 *bc_ptr;
	int bc;

	memset(buf, 0, sizeof(buf));
	hdr->Command = SMB_COM_CLOSE;
	hdr->WordCount = 3;
	/* ByteCount is at offset = sizeof(smb_hdr) + 3*2 */
	bc_ptr = (__le16 *)(buf + sizeof(struct smb_hdr) + 3 * 2);
	*bc_ptr = cpu_to_le16(0);

	bc = smb1_get_byte_count(hdr, sizeof(buf));
	KUNIT_EXPECT_EQ(test, bc, 0);
}

static void test_byte_count_close_nonzero(struct kunit *test)
{
	/* CLOSE requires ByteCount=0 */
	char buf[64];
	struct smb_hdr *hdr = (struct smb_hdr *)buf;
	__le16 *bc_ptr;
	int bc;

	memset(buf, 0, sizeof(buf));
	hdr->Command = SMB_COM_CLOSE;
	hdr->WordCount = 3;
	bc_ptr = (__le16 *)(buf + sizeof(struct smb_hdr) + 3 * 2);
	*bc_ptr = cpu_to_le16(5);

	bc = smb1_get_byte_count(hdr, sizeof(buf));
	KUNIT_EXPECT_EQ(test, bc, -EINVAL);
}

static void test_byte_count_negotiate_min(struct kunit *test)
{
	/* NEGOTIATE requires ByteCount >= 2 */
	char buf[64];
	struct smb_hdr *hdr = (struct smb_hdr *)buf;
	__le16 *bc_ptr;
	int bc;

	memset(buf, 0, sizeof(buf));
	hdr->Command = SMB_COM_NEGOTIATE;
	hdr->WordCount = 0;
	bc_ptr = (__le16 *)(buf + sizeof(struct smb_hdr) + 0 * 2);
	*bc_ptr = cpu_to_le16(2);

	bc = smb1_get_byte_count(hdr, sizeof(buf));
	KUNIT_EXPECT_EQ(test, bc, 2);
}

static void test_byte_count_negotiate_too_small(struct kunit *test)
{
	/* NEGOTIATE requires ByteCount >= 2, providing 1 */
	char buf[64];
	struct smb_hdr *hdr = (struct smb_hdr *)buf;
	__le16 *bc_ptr;
	int bc;

	memset(buf, 0, sizeof(buf));
	hdr->Command = SMB_COM_NEGOTIATE;
	hdr->WordCount = 0;
	bc_ptr = (__le16 *)(buf + sizeof(struct smb_hdr) + 0 * 2);
	*bc_ptr = cpu_to_le16(1);

	bc = smb1_get_byte_count(hdr, sizeof(buf));
	KUNIT_EXPECT_EQ(test, bc, -EINVAL);
}

static void test_byte_count_write_andx_min(struct kunit *test)
{
	/* WRITE_ANDX requires ByteCount >= 1 */
	char buf[128];
	struct smb_hdr *hdr = (struct smb_hdr *)buf;
	__le16 *bc_ptr;
	int bc;

	memset(buf, 0, sizeof(buf));
	hdr->Command = SMB_COM_WRITE_ANDX;
	hdr->WordCount = 0xc;
	bc_ptr = (__le16 *)(buf + sizeof(struct smb_hdr) + 0xc * 2);
	*bc_ptr = cpu_to_le16(1);

	bc = smb1_get_byte_count(hdr, sizeof(buf));
	KUNIT_EXPECT_EQ(test, bc, 1);
}

static void test_byte_count_truncated_buffer(struct kunit *test)
{
	/* Buffer too small to hold byte count field */
	char buf[38]; /* sizeof(smb_hdr) = 37, need 37 + 2 = 39 for bc */
	struct smb_hdr *hdr = (struct smb_hdr *)buf;
	int bc;

	memset(buf, 0, sizeof(buf));
	hdr->Command = SMB_COM_NEGOTIATE;
	hdr->WordCount = 0;

	/* buflen = 38 < offset(37) + 2 = 39 */
	bc = smb1_get_byte_count(hdr, sizeof(buf));
	KUNIT_EXPECT_EQ(test, bc, -EINVAL);
}

/* ================================================================
 * Test suite registration
 * ================================================================ */

static struct kunit_case ksmbd_smb1_helpers_test_cases[] = {
	/* smb_cmd_to_str */
	KUNIT_CASE(test_cmd_to_str_negotiate),
	KUNIT_CASE(test_cmd_to_str_close),
	KUNIT_CASE(test_cmd_to_str_session_setup),
	KUNIT_CASE(test_cmd_to_str_echo),
	KUNIT_CASE(test_cmd_to_str_unknown),
	KUNIT_CASE(test_cmd_to_str_null_entry),
	/* smb_trans2_cmd_to_str */
	KUNIT_CASE(test_trans2_cmd_to_str_find_first),
	KUNIT_CASE(test_trans2_cmd_to_str_query_path),
	KUNIT_CASE(test_trans2_cmd_to_str_unknown),
	/* is_smbreq_unicode */
	KUNIT_CASE(test_is_smbreq_unicode_set),
	KUNIT_CASE(test_is_smbreq_unicode_clear),
	KUNIT_CASE(test_is_smbreq_unicode_other_flags),
	KUNIT_CASE(test_is_smbreq_unicode_all_flags),
	/* ksmbd_openflags_to_mayflags */
	KUNIT_CASE(test_mayflags_rdonly),
	KUNIT_CASE(test_mayflags_wronly),
	KUNIT_CASE(test_mayflags_rdwr),
	KUNIT_CASE(test_mayflags_rdonly_with_extra),
	/* convert_open_flags */
	KUNIT_CASE(test_convert_open_flags_read_present),
	KUNIT_CASE(test_convert_open_flags_write_present),
	KUNIT_CASE(test_convert_open_flags_readwrite),
	KUNIT_CASE(test_convert_open_flags_write_through),
	KUNIT_CASE(test_convert_open_flags_file_absent_no_create),
	KUNIT_CASE(test_convert_open_flags_file_absent_create),
	KUNIT_CASE(test_convert_open_flags_present_trunc),
	KUNIT_CASE(test_convert_open_flags_present_append),
	KUNIT_CASE(test_convert_open_flags_present_none),
	/* smb_posix_convert_flags */
	KUNIT_CASE(test_posix_flags_rdonly),
	KUNIT_CASE(test_posix_flags_wronly),
	KUNIT_CASE(test_posix_flags_rdwr),
	KUNIT_CASE(test_posix_flags_creat),
	KUNIT_CASE(test_posix_flags_append),
	KUNIT_CASE(test_posix_flags_sync),
	KUNIT_CASE(test_posix_flags_directory),
	KUNIT_CASE(test_posix_flags_nofollow),
	/* smb_get_disposition */
	KUNIT_CASE(test_get_disposition_creat_excl),
	KUNIT_CASE(test_get_disposition_creat_excl_present),
	KUNIT_CASE(test_get_disposition_creat_trunc),
	KUNIT_CASE(test_get_disposition_plain_open),
	KUNIT_CASE(test_get_disposition_plain_open_absent),
	KUNIT_CASE(test_get_disposition_creat_only),
	KUNIT_CASE(test_get_disposition_trunc_only),
	/* convert_ace_to_cifs_ace */
	KUNIT_CASE(test_ace_to_cifs_basic),
	KUNIT_CASE(test_ace_to_cifs_negative_one_id),
	KUNIT_CASE(test_ace_to_cifs_zero),
	/* smb1_readdir_info_level_struct_sz */
	KUNIT_CASE(test_info_level_standard),
	KUNIT_CASE(test_info_level_both_dir),
	KUNIT_CASE(test_info_level_unix),
	KUNIT_CASE(test_info_level_names),
	KUNIT_CASE(test_info_level_directory),
	KUNIT_CASE(test_info_level_id_full),
	KUNIT_CASE(test_info_level_id_both),
	KUNIT_CASE(test_info_level_invalid),
	/* dos_date_time_to_unix */
	KUNIT_CASE(test_dos_datetime_2000_01_01),
	KUNIT_CASE(test_dos_datetime_1980_01_01),
	KUNIT_CASE(test_dos_datetime_with_time),
	KUNIT_CASE(test_dos_datetime_invalid_month_zero),
	KUNIT_CASE(test_dos_datetime_invalid_day_zero),
	/* smb1_req_struct_size */
	KUNIT_CASE(test_req_struct_negotiate),
	KUNIT_CASE(test_req_struct_negotiate_bad_wc),
	KUNIT_CASE(test_req_struct_close),
	KUNIT_CASE(test_req_struct_echo),
	KUNIT_CASE(test_req_struct_session_setup_12),
	KUNIT_CASE(test_req_struct_session_setup_13),
	KUNIT_CASE(test_req_struct_session_setup_bad),
	KUNIT_CASE(test_req_struct_nt_create),
	KUNIT_CASE(test_req_struct_locking),
	KUNIT_CASE(test_req_struct_trans2),
	KUNIT_CASE(test_req_struct_write),
	KUNIT_CASE(test_req_struct_tree_connect),
	KUNIT_CASE(test_req_struct_logoff),
	KUNIT_CASE(test_req_struct_unknown_cmd),
	KUNIT_CASE(test_req_struct_nt_transact),
	KUNIT_CASE(test_req_struct_nt_transact_too_small),
	KUNIT_CASE(test_req_struct_read_andx_10),
	KUNIT_CASE(test_req_struct_read_andx_12),
	/* smb1_get_byte_count */
	KUNIT_CASE(test_byte_count_close_zero),
	KUNIT_CASE(test_byte_count_close_nonzero),
	KUNIT_CASE(test_byte_count_negotiate_min),
	KUNIT_CASE(test_byte_count_negotiate_too_small),
	KUNIT_CASE(test_byte_count_write_andx_min),
	KUNIT_CASE(test_byte_count_truncated_buffer),
	{}
};

static struct kunit_suite ksmbd_smb1_helpers_test_suite = {
	.name = "ksmbd_smb1_helpers",
	.test_cases = ksmbd_smb1_helpers_test_cases,
};

kunit_test_suite(ksmbd_smb1_helpers_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB1 newly-exported helper functions");
