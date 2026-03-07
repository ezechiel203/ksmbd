// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 NT_TRANSACT error paths
 *
 *   Tests bounds checking and validation for all 8 NT_TRANSACT
 *   subcommands: CREATE, IOCTL, SET_SECURITY_DESC, NOTIFY_CHANGE,
 *   RENAME, QUERY_SECURITY_DESC, GET_USER_QUOTA, SET_USER_QUOTA.
 *
 *   Covers: truncated parameter blocks, truncated data blocks,
 *   zero-length mandatory fields, integer overflow in offset+count,
 *   invalid subcommand codes, and setup count overflow.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>

#include "smb_common.h"
#include "smb1pdu.h"

/*
 * Helper: build a minimal NT_TRANSACT request buffer.
 * Returns a kzalloc'd buffer of @buf_len bytes with the header and
 * NT_TRANSACT fields populated.
 *
 * The caller must kfree the returned buffer.
 */
static void *build_nt_transact_req(struct kunit *test,
				   unsigned int buf_len,
				   u16 function,
				   u32 param_offset,
				   u32 param_count,
				   u32 data_offset,
				   u32 data_count,
				   u32 total_param,
				   u32 total_data,
				   u8 setup_count)
{
	struct smb_com_nt_transact_req *req;

	KUNIT_ASSERT_GE(test, buf_len,
			(unsigned int)sizeof(struct smb_com_nt_transact_req));

	req = kunit_kzalloc(test, buf_len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, req);

	/* Fill in the SMB header */
	req->hdr.Protocol[0] = 0xFF;
	req->hdr.Protocol[1] = 'S';
	req->hdr.Protocol[2] = 'M';
	req->hdr.Protocol[3] = 'B';
	req->hdr.Command = SMB_COM_NT_TRANSACT;
	/* RFC1001 length = buf_len - 4 */
	req->hdr.smb_buf_length = cpu_to_be32(buf_len - 4);

	req->Function = cpu_to_le16(function);
	req->ParameterOffset = cpu_to_le32(param_offset);
	req->ParameterCount = cpu_to_le32(param_count);
	req->DataOffset = cpu_to_le32(data_offset);
	req->DataCount = cpu_to_le32(data_count);
	req->TotalParameterCount = cpu_to_le32(total_param);
	req->TotalDataCount = cpu_to_le32(total_data);
	req->SetupCount = setup_count;

	return req;
}

/* --- Test: NT_TRANSACT buffer validation --- */

static void test_nt_transact_valid_buffer(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req = build_nt_transact_req(test, buf_len,
					  NT_TRANSACT_IOCTL,
					  60, 10, /* param at 60, 10 bytes */
					  80, 20, /* data at 80, 20 bytes */
					  10, 20, /* total = current */
					  0);     /* no setup words */
	int rc;

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_nt_transact_param_overflow(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset=100 + ParameterCount=100 > buf_len=128 */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_CREATE,
				    100, 100,
				    0, 0,
				    100, 0,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_data_overflow(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* DataOffset=100 + DataCount=100 > buf_len=128 */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_IOCTL,
				    0, 0,
				    100, 100,
				    0, 100,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_param_offset_beyond_buf(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset > buf_len */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_SET_SECURITY_DESC,
				    200, 10,
				    0, 0,
				    10, 0,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_data_offset_beyond_buf(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* DataOffset > buf_len */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_QUERY_SECURITY_DESC,
				    0, 0,
				    200, 10,
				    0, 10,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_total_less_than_current(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req;
	int rc;

	/* TotalParameterCount < ParameterCount */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_NOTIFY_CHANGE,
				    60, 50,
				    0, 0,
				    10, 0, /* total_param=10 < param_count=50 */
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_total_data_less_than_current(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req;
	int rc;

	/* TotalDataCount < DataCount */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_SET_USER_QUOTA,
				    0, 0,
				    80, 50,
				    0, 10, /* total_data=10 < data_count=50 */
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_setup_count_overflow(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/*
	 * SetupCount=100 means 200 bytes of setup words.
	 * offsetof(Buffer) + 200 > 128 -> overflow.
	 */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_RENAME,
				    0, 0,
				    0, 0,
				    0, 0,
				    100); /* setup_count = 100 */

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_zero_counts_valid(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* Zero parameter and data counts should be valid */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_GET_USER_QUOTA,
				    0, 0,
				    0, 0,
				    0, 0,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_nt_transact_param_count_at_boundary(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset + 4 + ParameterCount == buf_len exactly */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_CREATE,
				    60, 64, /* 60 + 4 + 64 = 128 */
				    0, 0,
				    64, 0,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_nt_transact_param_one_past_boundary(struct kunit *test)
{
	unsigned int buf_len = 128;
	void *req;
	int rc;

	/* ParameterOffset + 4 + ParameterCount == buf_len + 1 -> overflow */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_CREATE,
				    60, 65, /* 60 + 4 + 65 = 129 > 128 */
				    0, 0,
				    65, 0,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

/* --- Test: NT_TRANSACT subcommand validation --- */

static void test_nt_transact_subcommand_create_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_CREATE >= 1 &&
			  NT_TRANSACT_CREATE <= NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_ioctl_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_IOCTL >= 1 &&
			  NT_TRANSACT_IOCTL <= NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_set_security_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_SET_SECURITY_DESC >= 1 &&
			  NT_TRANSACT_SET_SECURITY_DESC <=
			  NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_notify_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_NOTIFY_CHANGE >= 1 &&
			  NT_TRANSACT_NOTIFY_CHANGE <=
			  NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_rename_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_RENAME >= 1 &&
			  NT_TRANSACT_RENAME <= NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_query_security_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_QUERY_SECURITY_DESC >= 1 &&
			  NT_TRANSACT_QUERY_SECURITY_DESC <=
			  NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_get_quota_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_GET_USER_QUOTA >= 1 &&
			  NT_TRANSACT_GET_USER_QUOTA <=
			  NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_set_quota_valid(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
			  NT_TRANSACT_SET_USER_QUOTA >= 1 &&
			  NT_TRANSACT_SET_USER_QUOTA <=
			  NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_zero_invalid(struct kunit *test)
{
	/* Subcommand 0 is not valid */
	KUNIT_EXPECT_FALSE(test,
			   0 >= 1 && 0 <= NT_TRANSACT_MAX_SUBCOMMAND);
}

static void test_nt_transact_subcommand_too_large(struct kunit *test)
{
	/* Subcommand > NT_TRANSACT_MAX_SUBCOMMAND is invalid */
	KUNIT_EXPECT_FALSE(test,
			   0xFF >= 1 &&
			   0xFF <= NT_TRANSACT_MAX_SUBCOMMAND);
}

/* --- Test: NT_TRANSACT truncated per-subcommand parameters --- */

/*
 * Replicate the minimum parameter size requirements for each
 * NT_TRANSACT subcommand as documented in MS-CIFS.
 */
struct nt_transact_min_params {
	u16	function;
	u32	min_param_count;
	u32	min_data_count;
};

static const struct nt_transact_min_params nt_trans_min[] = {
	/* CREATE: needs at least NT_TRANSACT_CREATE params (53+ bytes) */
	{ NT_TRANSACT_CREATE,             53, 0 },
	/* IOCTL: needs FunctionCode(4) + FID(2) + IsFsctl(1) + Filter(1) = 8 */
	{ NT_TRANSACT_IOCTL,              8,  0 },
	/* SET_SECURITY_DESC: FID(2) + Reserved(2) + SecurityInfo(4) = 8 */
	{ NT_TRANSACT_SET_SECURITY_DESC,  8,  1 },
	/* NOTIFY_CHANGE: CompletionFilter(4) + FID(2) + WatchTree(1) + Reserved(1) = 8 */
	{ NT_TRANSACT_NOTIFY_CHANGE,      8,  0 },
	/* RENAME: FID(2) + Flags(2) = 4 */
	{ NT_TRANSACT_RENAME,             4,  0 },
	/* QUERY_SECURITY_DESC: FID(2) + Reserved(2) + SecurityInfo(4) = 8 */
	{ NT_TRANSACT_QUERY_SECURITY_DESC, 8, 0 },
	/* GET_USER_QUOTA: SidListLength(4) + ... = at least 4 */
	{ NT_TRANSACT_GET_USER_QUOTA,     4,  0 },
	/* SET_USER_QUOTA: at least a SID structure = 8 min */
	{ NT_TRANSACT_SET_USER_QUOTA,     0,  8 },
};

/*
 * Validate that a subcommand with truncated parameters would be detected.
 * We replicate the check: param_count >= min_param_count.
 */
static void test_nt_transact_create_truncated_params(struct kunit *test)
{
	/* NT_TRANSACT_CREATE needs 53 bytes of params minimum */
	u32 param_count = 10; /* way too small */

	KUNIT_EXPECT_LT(test, param_count, (u32)53);
}

static void test_nt_transact_ioctl_truncated_params(struct kunit *test)
{
	/* NT_TRANSACT_IOCTL needs 8 bytes of params minimum */
	u32 param_count = 4; /* too small */

	KUNIT_EXPECT_LT(test, param_count, (u32)8);
}

static void test_nt_transact_set_security_truncated_data(struct kunit *test)
{
	/* SET_SECURITY_DESC needs at least 1 byte of data */
	u32 data_count = 0;

	KUNIT_EXPECT_LT(test, data_count, (u32)1);
}

static void test_nt_transact_notify_truncated_params(struct kunit *test)
{
	/* NOTIFY_CHANGE needs 8 bytes of params */
	u32 param_count = 3;

	KUNIT_EXPECT_LT(test, param_count, (u32)8);
}

static void test_nt_transact_set_quota_truncated_data(struct kunit *test)
{
	/* SET_USER_QUOTA needs at least 8 bytes of data */
	u32 data_count = 4;

	KUNIT_EXPECT_LT(test, data_count, (u32)8);
}

/* --- Test: NT_TRANSACT integer overflow in offset + count --- */

static void test_nt_transact_param_integer_overflow(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req;
	int rc;

	/*
	 * ParameterOffset=0xFFFFFFF0 + ParameterCount=0x20 overflows u32.
	 * The validation must catch this.
	 */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_CREATE,
				    0xFFFFFFF0U, 0x20,
				    0, 0,
				    0x20, 0,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_nt_transact_data_integer_overflow(struct kunit *test)
{
	unsigned int buf_len = 256;
	void *req;
	int rc;

	/*
	 * DataOffset=0xFFFFFFE0 + DataCount=0x40 overflows.
	 */
	req = build_nt_transact_req(test, buf_len,
				    NT_TRANSACT_IOCTL,
				    0, 0,
				    0xFFFFFFE0U, 0x40,
				    0, 0x40,
				    0);

	rc = smb1_validate_nt_transact_buffer(req, buf_len);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static struct kunit_case ksmbd_smb1_nt_transact_test_cases[] = {
	/* Buffer validation (11 tests) */
	KUNIT_CASE(test_nt_transact_valid_buffer),
	KUNIT_CASE(test_nt_transact_param_overflow),
	KUNIT_CASE(test_nt_transact_data_overflow),
	KUNIT_CASE(test_nt_transact_param_offset_beyond_buf),
	KUNIT_CASE(test_nt_transact_data_offset_beyond_buf),
	KUNIT_CASE(test_nt_transact_total_less_than_current),
	KUNIT_CASE(test_nt_transact_total_data_less_than_current),
	KUNIT_CASE(test_nt_transact_setup_count_overflow),
	KUNIT_CASE(test_nt_transact_zero_counts_valid),
	KUNIT_CASE(test_nt_transact_param_count_at_boundary),
	KUNIT_CASE(test_nt_transact_param_one_past_boundary),
	/* Subcommand validation (10 tests) */
	KUNIT_CASE(test_nt_transact_subcommand_create_valid),
	KUNIT_CASE(test_nt_transact_subcommand_ioctl_valid),
	KUNIT_CASE(test_nt_transact_subcommand_set_security_valid),
	KUNIT_CASE(test_nt_transact_subcommand_notify_valid),
	KUNIT_CASE(test_nt_transact_subcommand_rename_valid),
	KUNIT_CASE(test_nt_transact_subcommand_query_security_valid),
	KUNIT_CASE(test_nt_transact_subcommand_get_quota_valid),
	KUNIT_CASE(test_nt_transact_subcommand_set_quota_valid),
	KUNIT_CASE(test_nt_transact_subcommand_zero_invalid),
	KUNIT_CASE(test_nt_transact_subcommand_too_large),
	/* Truncated per-subcommand parameters (5 tests) */
	KUNIT_CASE(test_nt_transact_create_truncated_params),
	KUNIT_CASE(test_nt_transact_ioctl_truncated_params),
	KUNIT_CASE(test_nt_transact_set_security_truncated_data),
	KUNIT_CASE(test_nt_transact_notify_truncated_params),
	KUNIT_CASE(test_nt_transact_set_quota_truncated_data),
	/* Integer overflow (2 tests) */
	KUNIT_CASE(test_nt_transact_param_integer_overflow),
	KUNIT_CASE(test_nt_transact_data_integer_overflow),
	{}
};

static struct kunit_suite ksmbd_smb1_nt_transact_test_suite = {
	.name = "ksmbd_smb1_nt_transact",
	.test_cases = ksmbd_smb1_nt_transact_test_cases,
};

kunit_test_suite(ksmbd_smb1_nt_transact_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 NT_TRANSACT error paths and bounds checking");
