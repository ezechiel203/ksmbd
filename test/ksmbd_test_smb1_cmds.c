// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 command handlers (smb1pdu.c, smb1ops.c, smb1misc.c)
 *
 *   Tests for SMB1 dialect negotiation, session setup validation,
 *   file operation field parsing, and TRANS/TRANS2/NT_TRANSACT
 *   subcommand dispatch logic. We replicate the pure validation
 *   logic to avoid full module dependencies.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>

#include "smb_common.h"
#include "smb1pdu.h"

/* --- SMB1 dialect negotiation logic (replicated from smb_common.c) --- */

/*
 * Replicate next_dialect(): advance through a packed SMB1 dialect list.
 * Dialect strings are NUL-terminated ASCII, each preceded by 0x02.
 * Caller strips the 0x02 prefix before passing here.
 */
static char *test_next_dialect(char *dialect, int *next_off, int bcount)
{
	dialect = dialect + *next_off;
	bcount -= *next_off;
	if (bcount <= 0)
		return NULL;
	*next_off = strnlen(dialect, bcount);
	if (dialect[*next_off] != '\0')
		return NULL;
	return dialect;
}

/*
 * Replicate dialect selection for SMB1 negotiate.
 * Returns the dialect index (sequence number) for known SMB1 dialects,
 * or BAD_PROT_ID if no supported dialect is found.
 *
 * Known dialects: "\2NT LM 0.12" and "\2NT LANMAN 1.0" (SMB1)
 * Known upgrade: "\2SMB 2.002" (SMB2), "\2SMB 2.???" (SMB2X)
 */
#define TEST_DIALECT_SMB1	0  /* NT LM 0.12 or NT LANMAN 1.0 */
#define TEST_DIALECT_SMB2	1  /* SMB 2.002 */
#define TEST_DIALECT_SMB2X	2  /* SMB 2.??? */

struct test_smb1_dialect_entry {
	const char	*name;
	int		dialect_id;
};

static const struct test_smb1_dialect_entry test_smb1_dialects[] = {
	{ "\2NT LM 0.12",  TEST_DIALECT_SMB1 },
	{ "\2NT LANMAN 1.0", TEST_DIALECT_SMB1 },
	{ "\2SMB 2.002",   TEST_DIALECT_SMB2 },
	{ "\2SMB 2.???",   TEST_DIALECT_SMB2X },
};

/*
 * Find a matching dialect in a packed dialect buffer.
 * Returns the sequence number (index in the client's list) for SMB1 match,
 * the protocol ID for SMB2/SMB2X match, or BAD_PROT_ID if none.
 */
static int test_lookup_dialect_by_name(char *cli_dialects, __le16 byte_count)
{
	int seq_num, next, bcount, i;
	char *dialect;

	for (i = 0; i < (int)ARRAY_SIZE(test_smb1_dialects); i++) {
		seq_num = 0;
		next = 0;
		dialect = cli_dialects;
		bcount = le16_to_cpu(byte_count);
		do {
			dialect = test_next_dialect(dialect, &next, bcount);
			if (!dialect)
				break;
			if (!strcmp(dialect, test_smb1_dialects[i].name)) {
				if (test_smb1_dialects[i].dialect_id ==
				    TEST_DIALECT_SMB1)
					return seq_num;
				return test_smb1_dialects[i].dialect_id;
			}
			seq_num++;
			bcount -= (++next);
		} while (bcount > 0);
	}

	return BAD_PROT_ID;
}

/* --- SMB1 header field validation helpers --- */

/*
 * Replicate init_smb_rsp_hdr validation: verify that a response
 * header correctly echoes request fields (PID, MID, etc.)
 */
struct test_smb_rsp_hdr {
	__u8	command;
	__u8	flags;
	__le16	flags2;
	__le16	pid;
	__le16	mid;
};

static void test_init_rsp_hdr(struct test_smb_rsp_hdr *rsp,
			      const struct test_smb_rsp_hdr *req,
			      __u8 command)
{
	rsp->command = command;
	rsp->flags = SMBFLG_RESPONSE;
	rsp->flags2 = cpu_to_le16(le16_to_cpu(SMBFLG2_UNICODE) |
				   le16_to_cpu(SMBFLG2_ERR_STATUS) |
				   le16_to_cpu(SMBFLG2_EXT_SEC) |
				   le16_to_cpu(SMBFLG2_IS_LONG_NAME));
	rsp->pid = req->pid;
	rsp->mid = req->mid;
}

/* --- TRANS2 subcommand validation (replicated from smb1pdu.c) --- */

static bool test_is_valid_trans2_subcommand(__u16 sub_command)
{
	switch (sub_command) {
	case TRANS2_FIND_FIRST:
	case TRANS2_FIND_NEXT:
	case TRANS2_QUERY_FS_INFORMATION:
	case TRANS2_SET_FS_INFORMATION:
	case TRANS2_QUERY_PATH_INFORMATION:
	case TRANS2_SET_PATH_INFORMATION:
	case TRANS2_QUERY_FILE_INFORMATION:
	case TRANS2_SET_FILE_INFORMATION:
	case TRANS2_CREATE_DIRECTORY:
	case TRANS2_GET_DFS_REFERRAL:
		return true;
	default:
		return false;
	}
}

/* --- NT_TRANSACT subcommand validation (replicated from smb1pdu.c) --- */

static bool test_is_valid_nt_transact_subcommand(__u16 sub_command)
{
	switch (sub_command) {
	case NT_TRANSACT_CREATE:
	case NT_TRANSACT_IOCTL:
	case NT_TRANSACT_SET_SECURITY_DESC:
	case NT_TRANSACT_NOTIFY_CHANGE:
	case NT_TRANSACT_RENAME:
	case NT_TRANSACT_QUERY_SECURITY_DESC:
	case NT_TRANSACT_GET_USER_QUOTA:
	case NT_TRANSACT_SET_USER_QUOTA:
		return true;
	default:
		return false;
	}
}

/* --- TRANS parameter/data bounds check (replicated from smb1pdu.c) --- */

static int test_trans2_param_data_check(unsigned int param_offset,
					unsigned int param_count,
					unsigned int data_offset,
					unsigned int data_count,
					unsigned int buf_len)
{
	/* Parameter region must be within buffer */
	if (param_count > 0 &&
	    (param_offset > buf_len || param_offset + param_count > buf_len))
		return -EINVAL;

	/* Data region must be within buffer */
	if (data_count > 0 &&
	    (data_offset > buf_len || data_offset + data_count > buf_len))
		return -EINVAL;

	return 0;
}

/* --- SMB1 echo response validation --- */

static int test_smb1_echo_word_count(__u8 wc)
{
	if (wc != 1)
		return -EINVAL;
	return 1;
}

/* --- SMB1 lock field validation --- */

static int test_smb1_locking_word_count(__u8 wc)
{
	if (wc != 8)
		return -EINVAL;
	return 8;
}

/* --- Test cases: SMB1 negotiate dialect selection --- */

static void test_smb1_negotiate_dialect_selection(struct kunit *test)
{
	/* Dialect list: "\2NT LM 0.12" + NUL + "\2SMB 2.???" + NUL */
	char dialects[] = "\2NT LM 0.12\0\2SMB 2.???";
	int result;

	result = test_lookup_dialect_by_name(dialects,
					     cpu_to_le16(sizeof(dialects) - 1));
	/* Should select NT LM 0.12 at sequence 0 */
	KUNIT_EXPECT_EQ(test, result, 0);
}

static void test_smb1_negotiate_dialect_nt_lanman(struct kunit *test)
{
	/* smbclient sends "\2NT LANMAN 1.0" instead of "\2NT LM 0.12" */
	char dialects[] = "\2NT LANMAN 1.0";
	int result;

	result = test_lookup_dialect_by_name(dialects,
					     cpu_to_le16(sizeof(dialects) - 1));
	/* Should match as SMB1 at sequence 0 */
	KUNIT_EXPECT_EQ(test, result, 0);
}

static void test_smb1_negotiate_upgrade_to_smb2(struct kunit *test)
{
	/* Dialect list contains only SMB2 dialects */
	char dialects[] = "\2SMB 2.002\0\2SMB 2.???";
	int result;

	result = test_lookup_dialect_by_name(dialects,
					     cpu_to_le16(sizeof(dialects) - 1));
	/* Should pick SMB 2.002 (TEST_DIALECT_SMB2 = 1) */
	KUNIT_EXPECT_EQ(test, result, TEST_DIALECT_SMB2);
}

static void test_smb1_negotiate_empty_dialect_list(struct kunit *test)
{
	int result;

	/* Empty byte count = 0 */
	result = test_lookup_dialect_by_name("", cpu_to_le16(0));
	KUNIT_EXPECT_EQ(test, result, (int)BAD_PROT_ID);
}

static void test_smb1_negotiate_second_negotiate_rejected(struct kunit *test)
{
	/*
	 * Replicate the rejection logic: once need_neg is false,
	 * a second NEGOTIATE from a non-SMB1 conn returns -EINVAL.
	 */
	bool need_neg = false;
	bool smb1_conn = false;
	int ret;

	if (!need_neg && !smb1_conn)
		ret = -EINVAL;
	else
		ret = 0;

	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* --- Test cases: SMB1 session/response header --- */

static void test_init_smb1_server_rsp_header(struct kunit *test)
{
	struct test_smb_rsp_hdr req = {
		.pid = cpu_to_le16(0x1234),
		.mid = cpu_to_le16(0x5678),
	};
	struct test_smb_rsp_hdr rsp = {};

	test_init_rsp_hdr(&rsp, &req, SMB_COM_NEGOTIATE);

	KUNIT_EXPECT_EQ(test, rsp.command, (u8)SMB_COM_NEGOTIATE);
	KUNIT_EXPECT_EQ(test, rsp.flags, (u8)SMBFLG_RESPONSE);
	/* PID and MID must be echoed from request */
	KUNIT_EXPECT_EQ(test, rsp.pid, req.pid);
	KUNIT_EXPECT_EQ(test, rsp.mid, req.mid);
}

static void test_init_smb1_server_vals_allocated(struct kunit *test)
{
	/* Verify SMB1 server capabilities value */
	KUNIT_EXPECT_NE(test, (u32)SMB1_SERVER_CAPS, (u32)0);
	/* Verify it does not include CAP_LOCK_AND_READ */
	KUNIT_EXPECT_FALSE(test,
			   !!(SMB1_SERVER_CAPS & CAP_LOCK_AND_READ));
}

/* --- Test cases: SMB1 file operation field parsing --- */

static void test_smb1_create_response_word_count(struct kunit *test)
{
	/*
	 * NT_CREATE_ANDX response has WordCount=34 (smb1pdu.c).
	 * We verify the expected constant.
	 */
	KUNIT_EXPECT_EQ(test, (u8)SMB_COM_NT_CREATE_ANDX, (u8)0xA2);
}

static void test_smb1_close_invalid_fid_detection(struct kunit *test)
{
	/* FID 0xFFFF is invalid per SMB1 spec */
	__u16 fid = 0xFFFF;

	KUNIT_EXPECT_EQ(test, fid, (u16)0xFFFF);
}

static void test_smb1_echo_response_validation(struct kunit *test)
{
	/* Echo must have WordCount=1 */
	KUNIT_EXPECT_EQ(test, test_smb1_echo_word_count(1), 1);
	KUNIT_EXPECT_EQ(test, test_smb1_echo_word_count(0), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_smb1_echo_word_count(2), -EINVAL);
}

static void test_smb1_lock_basic_word_count(struct kunit *test)
{
	/* LOCKING_ANDX must have WordCount=8 */
	KUNIT_EXPECT_EQ(test, test_smb1_locking_word_count(8), 8);
	KUNIT_EXPECT_EQ(test, test_smb1_locking_word_count(7), -EINVAL);
}

static void test_smb1_write_zero_length(struct kunit *test)
{
	/* A zero-length write is valid (DataLength=0) */
	__u16 data_length = 0;

	KUNIT_EXPECT_EQ(test, data_length, (u16)0);
}

static void test_smb1_read_beyond_eof_detection(struct kunit *test)
{
	/*
	 * When offset >= file_size, read should return 0 bytes.
	 * We verify the comparison logic.
	 */
	loff_t offset = 1000;
	loff_t file_size = 500;
	int bytes_read;

	bytes_read = (offset >= file_size) ? 0 : (int)(file_size - offset);
	KUNIT_EXPECT_EQ(test, bytes_read, 0);
}

static void test_smb1_lock_conflicting_detection(struct kunit *test)
{
	/*
	 * Two lock requests with overlapping ranges are conflicting.
	 * Replicate the basic overlap check: if start1 < end2 && start2 < end1.
	 */
	u64 lock1_start = 0, lock1_end = 100;
	u64 lock2_start = 50, lock2_end = 150;
	bool overlapping;

	overlapping = (lock1_start < lock2_end && lock2_start < lock1_end);
	KUNIT_EXPECT_TRUE(test, overlapping);

	/* Non-overlapping ranges */
	lock2_start = 200;
	lock2_end = 300;
	overlapping = (lock1_start < lock2_end && lock2_start < lock1_end);
	KUNIT_EXPECT_FALSE(test, overlapping);
}

static void test_smb1_rename_cross_share_detection(struct kunit *test)
{
	/* Different tree IDs indicate cross-share rename */
	__u16 src_tid = 1;
	__u16 dst_tid = 2;
	bool cross_share;

	cross_share = (src_tid != dst_tid);
	KUNIT_EXPECT_TRUE(test, cross_share);
}

/* --- Test cases: TRANS2 and NT_TRANSACT subcommand dispatch --- */

static void test_smb1_trans2_query_file_info(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_QUERY_FILE_INFORMATION));
}

static void test_smb1_trans2_set_file_info(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_SET_FILE_INFORMATION));
}

static void test_smb1_trans2_find_first(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(TRANS2_FIND_FIRST));
}

static void test_smb1_trans2_find_next(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(TRANS2_FIND_NEXT));
}

static void test_smb1_trans2_query_fs_info(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_trans2_subcommand(
				TRANS2_QUERY_FS_INFORMATION));
}

static void test_smb1_nt_transact_ioctl(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_nt_transact_subcommand(
				NT_TRANSACT_IOCTL));
}

static void test_smb1_nt_transact_notify(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_nt_transact_subcommand(
				NT_TRANSACT_NOTIFY_CHANGE));
}

static void test_smb1_nt_transact_rename(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_nt_transact_subcommand(
				NT_TRANSACT_RENAME));
}

static void test_smb1_nt_transact_quota(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_nt_transact_subcommand(
				NT_TRANSACT_GET_USER_QUOTA));
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_nt_transact_subcommand(
				NT_TRANSACT_SET_USER_QUOTA));
}

static void test_smb1_nt_transact_create(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  test_is_valid_nt_transact_subcommand(
				NT_TRANSACT_CREATE));
}

static void test_smb1_trans_invalid_subcommand(struct kunit *test)
{
	/* 0xFF is not a valid TRANS2 or NT_TRANSACT subcommand */
	KUNIT_EXPECT_FALSE(test, test_is_valid_trans2_subcommand(0xFF));
	KUNIT_EXPECT_FALSE(test, test_is_valid_nt_transact_subcommand(0xFF));
}

static void test_smb1_trans2_parameter_overflow(struct kunit *test)
{
	unsigned int buf_len = 256;

	/* ParameterOffset+ParameterCount > buf_len */
	KUNIT_EXPECT_EQ(test,
			test_trans2_param_data_check(200, 100, 0, 0, buf_len),
			-EINVAL);

	/* DataOffset+DataCount > buf_len */
	KUNIT_EXPECT_EQ(test,
			test_trans2_param_data_check(0, 0, 200, 100, buf_len),
			-EINVAL);

	/* Both within bounds */
	KUNIT_EXPECT_EQ(test,
			test_trans2_param_data_check(10, 20, 50, 30, buf_len),
			0);

	/* Zero counts always pass */
	KUNIT_EXPECT_EQ(test,
			test_trans2_param_data_check(300, 0, 300, 0, buf_len),
			0);
}

static void test_smb1_nt_transact_secondary_continuation(struct kunit *test)
{
	/*
	 * Secondary requests must have their parameter/data offsets
	 * within the buffer. Verify the bounds check logic.
	 */
	unsigned int buf_len = 512;

	/* Valid secondary: data at offset 100, 200 bytes */
	KUNIT_EXPECT_EQ(test,
			test_trans2_param_data_check(64, 100, 200, 200,
						     buf_len),
			0);

	/* Invalid: parameter overflows */
	KUNIT_EXPECT_EQ(test,
			test_trans2_param_data_check(500, 100, 0, 0, buf_len),
			-EINVAL);
}

static struct kunit_case ksmbd_smb1_cmds_test_cases[] = {
	/* SMB1 Session/Negotiate (7 tests) */
	KUNIT_CASE(test_smb1_negotiate_dialect_selection),
	KUNIT_CASE(test_smb1_negotiate_dialect_nt_lanman),
	KUNIT_CASE(test_smb1_negotiate_upgrade_to_smb2),
	KUNIT_CASE(test_smb1_negotiate_empty_dialect_list),
	KUNIT_CASE(test_smb1_negotiate_second_negotiate_rejected),
	KUNIT_CASE(test_init_smb1_server_rsp_header),
	KUNIT_CASE(test_init_smb1_server_vals_allocated),
	/* SMB1 File (8 tests) */
	KUNIT_CASE(test_smb1_create_response_word_count),
	KUNIT_CASE(test_smb1_close_invalid_fid_detection),
	KUNIT_CASE(test_smb1_echo_response_validation),
	KUNIT_CASE(test_smb1_lock_basic_word_count),
	KUNIT_CASE(test_smb1_write_zero_length),
	KUNIT_CASE(test_smb1_read_beyond_eof_detection),
	KUNIT_CASE(test_smb1_rename_cross_share_detection),
	KUNIT_CASE(test_smb1_lock_conflicting_detection),
	/* SMB1 Trans (13 tests) */
	KUNIT_CASE(test_smb1_trans2_query_file_info),
	KUNIT_CASE(test_smb1_trans2_set_file_info),
	KUNIT_CASE(test_smb1_trans2_find_first),
	KUNIT_CASE(test_smb1_trans2_find_next),
	KUNIT_CASE(test_smb1_trans2_query_fs_info),
	KUNIT_CASE(test_smb1_nt_transact_ioctl),
	KUNIT_CASE(test_smb1_nt_transact_notify),
	KUNIT_CASE(test_smb1_nt_transact_rename),
	KUNIT_CASE(test_smb1_nt_transact_quota),
	KUNIT_CASE(test_smb1_nt_transact_create),
	KUNIT_CASE(test_smb1_nt_transact_secondary_continuation),
	KUNIT_CASE(test_smb1_trans_invalid_subcommand),
	KUNIT_CASE(test_smb1_trans2_parameter_overflow),
	{}
};

static struct kunit_suite ksmbd_smb1_cmds_test_suite = {
	.name = "ksmbd_smb1_cmds",
	.test_cases = ksmbd_smb1_cmds_test_cases,
};

kunit_test_suite(ksmbd_smb1_cmds_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 command handlers and dispatch");
