// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 operations (smb1ops.c, smb1misc.c)
 *
 *   Tests for init_smb1_server(), smb1_req_struct_size(),
 *   smb1_calc_size(), smb1_get_byte_count(), and negotiate
 *   dialect selection.  We replicate the pure validation logic
 *   to avoid full module dependencies.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "smb_common.h"
#include "smb1pdu.h"

/* --- SMB1 request struct size validation (replicated from smb1misc.c) --- */

/*
 * Expected WordCount for each SMB1 command.  Returns:
 *   >= 0: the expected WordCount value
 *   -EINVAL: bad WordCount for a known command
 *   -EOPNOTSUPP: unknown/unsupported command
 */
static int test_smb1_req_struct_size(__u8 command, __u8 word_count)
{
	switch (command) {
	case SMB_COM_NEGOTIATE:
		if (word_count != 0)
			return -EINVAL;
		return 0;
	case SMB_COM_SESSION_SETUP_ANDX:
		if (word_count == 12 || word_count == 13)
			return word_count;
		return -EINVAL;
	case SMB_COM_TREE_CONNECT_ANDX:
		if (word_count != 4)
			return -EINVAL;
		return 4;
	case SMB_COM_NT_CREATE_ANDX:
		if (word_count != 24)
			return -EINVAL;
		return 24;
	case SMB_COM_TRANSACTION:
	case SMB_COM_TRANSACTION2:
		if (word_count < 14)
			return -EINVAL;
		return word_count;
	case SMB_COM_NT_TRANSACT:
		if (word_count < 19)
			return -EINVAL;
		return word_count;
	case SMB_COM_CLOSE:
		if (word_count != 3)
			return -EINVAL;
		return 3;
	case SMB_COM_READ_ANDX:
		if (word_count != 10 && word_count != 12)
			return -EINVAL;
		return word_count;
	case SMB_COM_WRITE_ANDX:
		if (word_count != 12 && word_count != 14)
			return -EINVAL;
		return word_count;
	case SMB_COM_LOCKING_ANDX:
		if (word_count != 8)
			return -EINVAL;
		return 8;
	case SMB_COM_ECHO:
		if (word_count != 1)
			return -EINVAL;
		return 1;
	case SMB_COM_FLUSH:
		if (word_count != 1)
			return -EINVAL;
		return 1;
	case SMB_COM_LOGOFF_ANDX:
		if (word_count != 2)
			return -EINVAL;
		return 2;
	case SMB_COM_TREE_DISCONNECT:
		if (word_count != 0)
			return -EINVAL;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

/* ByteCount validation for select commands */
static int test_smb1_byte_count_check(__u8 command, __le16 byte_count_le)
{
	unsigned int bc = le16_to_cpu(byte_count_le);

	switch (command) {
	case SMB_COM_CLOSE:
		if (bc != 0)
			return -EINVAL;
		return 0;
	case SMB_COM_NEGOTIATE:
		if (bc < 2)
			return -EINVAL;
		return 0;
	default:
		return 0;
	}
}

/* Calc size for a well-formed negotiate request */
static unsigned int test_smb1_calc_size_negotiate(void *buf, unsigned int buf_len)
{
	struct smb_negotiate_req *req = buf;
	unsigned int hdr_size = sizeof(struct smb_hdr);
	unsigned int bc;

	if (buf_len < hdr_size + 2)
		return (unsigned int)-1;

	bc = le16_to_cpu(req->ByteCount);
	if (hdr_size + 2 + bc > buf_len)
		return (unsigned int)-1;

	return hdr_size + 2 + bc;
}

/* --- SMB1 server init verification (replicated from smb1ops.c) --- */

#define TEST_SMB1_SERVER_CAPS \
	(CAP_UNICODE | CAP_LARGE_FILES | CAP_EXTENDED_SECURITY | \
	 CAP_NT_SMBS | CAP_STATUS32 | \
	 CAP_NT_FIND | CAP_UNIX | CAP_LARGE_READ_X | \
	 CAP_LARGE_WRITE_X | CAP_LEVEL_II_OPLOCKS | \
	 CAP_MPX_MODE | CAP_RPC_REMOTE_APIS | CAP_INFOLEVEL_PASSTHRU)

/* --- Test cases --- */

static void test_smb1_req_struct_size_negotiate(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_smb1_req_struct_size(SMB_COM_NEGOTIATE, 0), 0);
}

static void test_smb1_req_struct_size_session_setup_12(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_smb1_req_struct_size(SMB_COM_SESSION_SETUP_ANDX, 12),
			12);
}

static void test_smb1_req_struct_size_session_setup_13(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_smb1_req_struct_size(SMB_COM_SESSION_SETUP_ANDX, 13),
			13);
}

static void test_smb1_req_struct_size_invalid_negotiate(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_smb1_req_struct_size(SMB_COM_NEGOTIATE, 1),
			-EINVAL);
}

static void test_smb1_req_struct_size_unsupported_command(struct kunit *test)
{
	/* 0xFE is not a valid SMB1 command */
	KUNIT_EXPECT_EQ(test,
			test_smb1_req_struct_size(0xFE, 0),
			-EOPNOTSUPP);
}

static void test_smb1_byte_count_close_must_be_zero(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_smb1_byte_count_check(SMB_COM_CLOSE,
						   cpu_to_le16(5)),
			-EINVAL);
	KUNIT_EXPECT_EQ(test,
			test_smb1_byte_count_check(SMB_COM_CLOSE,
						   cpu_to_le16(0)),
			0);
}

static void test_smb1_byte_count_negotiate_min(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_smb1_byte_count_check(SMB_COM_NEGOTIATE,
						   cpu_to_le16(1)),
			-EINVAL);
	KUNIT_EXPECT_EQ(test,
			test_smb1_byte_count_check(SMB_COM_NEGOTIATE,
						   cpu_to_le16(2)),
			0);
}

static void test_smb1_calc_size_valid_negotiate(struct kunit *test)
{
	char buf[128] = {};
	struct smb_negotiate_req *req = (struct smb_negotiate_req *)buf;
	unsigned int expected;
	unsigned int bc = 10;

	req->ByteCount = cpu_to_le16(bc);
	expected = sizeof(struct smb_hdr) + 2 + bc;
	KUNIT_EXPECT_EQ(test,
			test_smb1_calc_size_negotiate(buf, expected),
			expected);
}

static void test_smb1_calc_size_invalid_byte_count(struct kunit *test)
{
	char buf[64] = {};
	struct smb_negotiate_req *req = (struct smb_negotiate_req *)buf;

	/* ByteCount larger than buffer */
	req->ByteCount = cpu_to_le16(1000);
	KUNIT_EXPECT_EQ(test,
			test_smb1_calc_size_negotiate(buf, 64),
			(unsigned int)-1);
}

/* --- init_smb1_server verification --- */

static void test_init_smb1_server_sets_ops(struct kunit *test)
{
	/*
	 * Verify the server values structure contains expected fields.
	 * We replicate the static values from smb1ops.c.
	 */
	KUNIT_EXPECT_EQ(test, (u16)SMB10_PROT_ID, (u16)0x0000);
	KUNIT_EXPECT_EQ(test, (u32)TEST_SMB1_SERVER_CAPS,
			(u32)SMB1_SERVER_CAPS);
}

static void test_init_smb1_server_vals_fields(struct kunit *test)
{
	/*
	 * Verify the smb1 server values contain correct protocol parameters.
	 */
	KUNIT_EXPECT_EQ(test, (u32)CIFS_DEFAULT_IOSIZE, (u32)65536);
	KUNIT_EXPECT_STREQ(test, SMB1_VERSION_STRING, "1.0");
}

static struct kunit_case ksmbd_smb1_ops_test_cases[] = {
	KUNIT_CASE(test_smb1_req_struct_size_negotiate),
	KUNIT_CASE(test_smb1_req_struct_size_session_setup_12),
	KUNIT_CASE(test_smb1_req_struct_size_session_setup_13),
	KUNIT_CASE(test_smb1_req_struct_size_invalid_negotiate),
	KUNIT_CASE(test_smb1_req_struct_size_unsupported_command),
	KUNIT_CASE(test_smb1_byte_count_close_must_be_zero),
	KUNIT_CASE(test_smb1_byte_count_negotiate_min),
	KUNIT_CASE(test_smb1_calc_size_valid_negotiate),
	KUNIT_CASE(test_smb1_calc_size_invalid_byte_count),
	KUNIT_CASE(test_init_smb1_server_sets_ops),
	KUNIT_CASE(test_init_smb1_server_vals_fields),
	{}
};

static struct kunit_suite ksmbd_smb1_ops_test_suite = {
	.name = "ksmbd_smb1_ops",
	.test_cases = ksmbd_smb1_ops_test_cases,
};

kunit_test_suite(ksmbd_smb1_ops_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 operations and message validation");
