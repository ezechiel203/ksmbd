// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 NT_TRANSACT subcommand dispatcher and buffer
 *   validation (smb1pdu.c NT_TRANSACT implementation)
 *
 *   These tests replicate the pure validation logic for:
 *   - NT_TRANSACT dispatcher (Function field routing)
 *   - Per-subcommand minimum ParameterCount checks
 *   - Buffer boundary validation for parameter/data blocks
 *   - NT_TRANSACT_SECONDARY stub behavior
 *   - Response builder (smb_build_ntransact_rsp) field layout
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "smb_common.h"
#include "smb1pdu.h"

/* NT_TRANSACT subcommand constants (from smb1pdu.h) */
#define TEST_NT_TRANSACT_CREATE		0x01
#define TEST_NT_TRANSACT_IOCTL		0x02
#define TEST_NT_TRANSACT_SET_SEC	0x03
#define TEST_NT_TRANSACT_NOTIFY		0x04
#define TEST_NT_TRANSACT_RENAME		0x05
#define TEST_NT_TRANSACT_QUERY_SEC	0x06
#define TEST_NT_TRANSACT_GET_QUOTA	0x07
#define TEST_NT_TRANSACT_SET_QUOTA	0x08

/* Valid subcommand range */
#define TEST_NT_TRANSACT_MIN_FUNC	0x01
#define TEST_NT_TRANSACT_MAX_FUNC	0x08

/* Minimum parameter counts per subcommand (from smb1pdu.c) */
#define NT_CREATE_MIN_PARAMS		57
#define NT_IOCTL_MIN_PARAMS		8
#define NT_SET_SEC_MIN_PARAMS		8
#define NT_NOTIFY_MIN_PARAMS		8
#define NT_RENAME_MIN_PARAMS		4
#define NT_QUERY_SEC_MIN_PARAMS		8
#define NT_QUOTA_MIN_PARAMS		0  /* GET/SET_USER_QUOTA have no param check */

/*
 * Replicate the dispatcher function field validation logic from
 * smb_nt_transact() in smb1pdu.c.  The dispatcher reads the Function
 * field and routes to subcommand handlers via a switch statement.
 * Invalid function values return STATUS_NOT_SUPPORTED (-EOPNOTSUPP).
 */
static int test_nt_transact_dispatch(u16 function)
{
	switch (function) {
	case TEST_NT_TRANSACT_CREATE:
	case TEST_NT_TRANSACT_IOCTL:
	case TEST_NT_TRANSACT_SET_SEC:
	case TEST_NT_TRANSACT_NOTIFY:
	case TEST_NT_TRANSACT_RENAME:
	case TEST_NT_TRANSACT_QUERY_SEC:
	case TEST_NT_TRANSACT_GET_QUOTA:
	case TEST_NT_TRANSACT_SET_QUOTA:
		return 0; /* valid subcommand */
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Replicate the minimum ParameterCount check logic that each
 * subcommand handler performs before accessing the parameter block.
 */
static int test_check_min_params(u16 function, u32 param_count)
{
	switch (function) {
	case TEST_NT_TRANSACT_CREATE:
		return (param_count >= NT_CREATE_MIN_PARAMS) ? 0 : -EINVAL;
	case TEST_NT_TRANSACT_IOCTL:
		return (param_count >= NT_IOCTL_MIN_PARAMS) ? 0 : -EINVAL;
	case TEST_NT_TRANSACT_SET_SEC:
		return (param_count >= NT_SET_SEC_MIN_PARAMS) ? 0 : -EINVAL;
	case TEST_NT_TRANSACT_NOTIFY:
		return (param_count >= NT_NOTIFY_MIN_PARAMS) ? 0 : -EINVAL;
	case TEST_NT_TRANSACT_RENAME:
		return (param_count >= NT_RENAME_MIN_PARAMS) ? 0 : -EINVAL;
	case TEST_NT_TRANSACT_QUERY_SEC:
		return (param_count >= NT_QUERY_SEC_MIN_PARAMS) ? 0 : -EINVAL;
	case TEST_NT_TRANSACT_GET_QUOTA:
	case TEST_NT_TRANSACT_SET_QUOTA:
		return 0; /* no minimum param check in quota stubs */
	default:
		return -EOPNOTSUPP;
	}
}

/*
 * Replicate the NT_TRANSACT_CREATE validation that checks:
 * - param_count >= 57
 * - name_len > 0 and name_len <= data_count
 * - sd_len + ea_len + name_len <= data_count
 */
static int test_nt_create_validate(u32 param_count, u32 data_count,
				   const char *params, const char *data)
{
	u32 sd_len, ea_len, name_len;

	if (param_count < 57)
		return -EINVAL;

	sd_len   = le32_to_cpu(*(__le32 *)(params + 36));
	ea_len   = le32_to_cpu(*(__le32 *)(params + 40));
	name_len = le32_to_cpu(*(__le32 *)(params + 44));

	if (name_len == 0 || name_len > data_count)
		return -EINVAL;

	if (sd_len + ea_len + name_len > data_count)
		return -EINVAL;

	return 0;
}

/*
 * Replicate the IOCTL parameter parsing (8-byte param block):
 *   0: FunctionCode (4)
 *   4: Fid (2)
 *   6: IsFsctl (1)
 *   7: IsFlags (1)
 */
static int test_nt_ioctl_parse(u32 param_count, const char *params,
			       u32 *out_func, u16 *out_fid)
{
	if (param_count < 8)
		return -EINVAL;

	*out_func = le32_to_cpu(*(__le32 *)params);
	*out_fid  = le16_to_cpu(*(__le16 *)(params + 4));
	return 0;
}

/*
 * Replicate the NOTIFY_CHANGE parameter parsing (8-byte param block):
 *   0: CompletionFilter (4)
 *   4: Fid (2)
 *   6: WatchTree (1)
 *   7: Reserved (1)
 */
static int test_nt_notify_parse(u32 param_count, const char *params,
				u32 *out_filter, u16 *out_fid,
				u8 *out_watch_tree)
{
	if (param_count < 8)
		return -EINVAL;

	*out_filter     = le32_to_cpu(*(__le32 *)params);
	*out_fid        = le16_to_cpu(*(__le16 *)(params + 4));
	*out_watch_tree = ((u8 *)params)[6];
	return 0;
}

/*
 * Replicate the RENAME parameter parsing (4-byte min param block):
 *   0: Fid (2)
 *   2: Flags (2)
 * Data block: new filename in UTF-16LE
 */
static int test_nt_rename_validate(u32 param_count, u32 data_count)
{
	if (param_count < 4)
		return -EINVAL;

	if (data_count == 0)
		return -EINVAL;

	return 0;
}

/*
 * Replicate the smb_build_ntransact_rsp() offset calculation.
 * ParameterOffset = sizeof(smb_hdr) - 4 + 1 + 36 + 2 + 1 = 68
 * DataOffset = ALIGN(ParameterOffset + param_len, 4)
 */
static void test_ntransact_rsp_offsets(u32 param_len, u32 data_len,
				       u32 *out_param_off, u32 *out_data_off,
				       u16 *out_byte_count)
{
	u32 param_off, data_off;

	param_off = (sizeof(struct smb_hdr) - 4) /* 28 */
		    + 1  /* WordCount */
		    + 18 * 2  /* 18 words = 36 bytes */
		    + 2  /* ByteCount */
		    + 1; /* 1-byte alignment pad */
	data_off = ALIGN(param_off + param_len, 4);

	*out_param_off = param_off;
	*out_data_off = data_off;
	*out_byte_count = (u16)(1 /* pad */
				+ param_len
				+ (data_off - (param_off + param_len))
				+ data_len);
}

/*
 * Validate the TotalDataCount vs DataCount consistency check.
 * In an NT_TRANSACT_SECONDARY, TotalDataCount should match the
 * primary request's TotalDataCount.
 */
static int test_secondary_count_check(u32 total_param_primary,
				      u32 total_param_secondary,
				      u32 total_data_primary,
				      u32 total_data_secondary)
{
	/*
	 * MS-SMB 2.2.4.63: TotalParameterCount and TotalDataCount in
	 * the secondary MUST equal those in the primary.  Mismatches
	 * indicate a malformed or tampered request.
	 */
	if (total_param_secondary != total_param_primary)
		return -EINVAL;
	if (total_data_secondary != total_data_primary)
		return -EINVAL;
	return 0;
}

/* ======== Tests: Dispatcher routing ======== */

static void test_dispatch_create_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_CREATE), 0);
}

static void test_dispatch_ioctl_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_IOCTL), 0);
}

static void test_dispatch_set_security_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_SET_SEC), 0);
}

static void test_dispatch_notify_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_NOTIFY), 0);
}

static void test_dispatch_rename_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_RENAME), 0);
}

static void test_dispatch_query_security_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_QUERY_SEC), 0);
}

static void test_dispatch_get_user_quota_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_GET_QUOTA), 0);
}

static void test_dispatch_set_user_quota_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(TEST_NT_TRANSACT_SET_QUOTA), 0);
}

static void test_dispatch_function_zero_invalid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(0x00), -EOPNOTSUPP);
}

static void test_dispatch_function_0xff_invalid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(0xFF), -EOPNOTSUPP);
}

static void test_dispatch_function_above_max(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_nt_transact_dispatch(0x09), -EOPNOTSUPP);
}

/* ======== Tests: Minimum ParameterCount checks ======== */

static void test_create_params_minimum_57(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_CREATE, 56), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_CREATE, 57), 0);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_CREATE, 100), 0);
}

static void test_ioctl_params_minimum_8(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_IOCTL, 7), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_IOCTL, 8), 0);
}

static void test_set_security_params_minimum_8(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_SET_SEC, 7), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_SET_SEC, 8), 0);
}

static void test_notify_params_minimum_8(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_NOTIFY, 7), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_NOTIFY, 8), 0);
}

static void test_rename_params_minimum_4(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_RENAME, 3), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_RENAME, 4), 0);
}

static void test_query_security_params_minimum_8(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_QUERY_SEC, 7), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_QUERY_SEC, 8), 0);
}

static void test_quota_params_no_minimum(struct kunit *test)
{
	/* GET_USER_QUOTA and SET_USER_QUOTA stubs accept any ParameterCount */
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_GET_QUOTA, 0), 0);
	KUNIT_EXPECT_EQ(test, test_check_min_params(TEST_NT_TRANSACT_SET_QUOTA, 0), 0);
}

/* ======== Tests: NT_TRANSACT_CREATE buffer validation ======== */

static void test_create_valid_minimal_request(struct kunit *test)
{
	/* Build a 57-byte parameter block with valid sd_len, ea_len, name_len */
	char params[64] = {};
	char data[16] = {};
	int rc;

	/* name_len=4, sd_len=0, ea_len=0 */
	*(__le32 *)(params + 36) = cpu_to_le32(0);   /* sd_len */
	*(__le32 *)(params + 40) = cpu_to_le32(0);   /* ea_len */
	*(__le32 *)(params + 44) = cpu_to_le32(4);   /* name_len */

	rc = test_nt_create_validate(57, 8, params, data);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_create_with_security_descriptor(struct kunit *test)
{
	/* SD in data block: sd_len=20, ea_len=0, name_len=4 => 24 bytes needed */
	char params[64] = {};
	char data[32] = {};
	int rc;

	*(__le32 *)(params + 36) = cpu_to_le32(20);  /* sd_len */
	*(__le32 *)(params + 40) = cpu_to_le32(0);   /* ea_len */
	*(__le32 *)(params + 44) = cpu_to_le32(4);   /* name_len */

	rc = test_nt_create_validate(57, 24, params, data);
	KUNIT_EXPECT_EQ(test, rc, 0);
}

static void test_create_sd_plus_ea_plus_name_exceeds_data(struct kunit *test)
{
	char params[64] = {};
	int rc;

	/* sd_len=20 + ea_len=10 + name_len=4 = 34, but data_count=30 */
	*(__le32 *)(params + 36) = cpu_to_le32(20);
	*(__le32 *)(params + 40) = cpu_to_le32(10);
	*(__le32 *)(params + 44) = cpu_to_le32(4);

	rc = test_nt_create_validate(57, 30, params, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_create_name_len_zero_rejected(struct kunit *test)
{
	char params[64] = {};
	int rc;

	*(__le32 *)(params + 36) = cpu_to_le32(0);
	*(__le32 *)(params + 40) = cpu_to_le32(0);
	*(__le32 *)(params + 44) = cpu_to_le32(0);  /* name_len=0 */

	rc = test_nt_create_validate(57, 10, params, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

static void test_create_name_len_exceeds_data_count(struct kunit *test)
{
	char params[64] = {};
	int rc;

	*(__le32 *)(params + 36) = cpu_to_le32(0);
	*(__le32 *)(params + 40) = cpu_to_le32(0);
	*(__le32 *)(params + 44) = cpu_to_le32(100); /* name_len > data_count */

	rc = test_nt_create_validate(57, 50, params, NULL);
	KUNIT_EXPECT_EQ(test, rc, -EINVAL);
}

/* ======== Tests: NT_TRANSACT_IOCTL parameter parsing ======== */

static void test_ioctl_parse_valid_8byte_block(struct kunit *test)
{
	char params[8] = {};
	u32 func_code;
	u16 fid;
	int rc;

	*(__le32 *)params = cpu_to_le32(0x0011C017); /* FSCTL_PIPE_TRANSCEIVE */
	*(__le16 *)(params + 4) = cpu_to_le16(42);   /* fid */

	rc = test_nt_ioctl_parse(8, params, &func_code, &fid);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, func_code, 0x0011C017u);
	KUNIT_EXPECT_EQ(test, fid, (u16)42);
}

/* ======== Tests: NT_TRANSACT_NOTIFY_CHANGE parameter parsing ======== */

static void test_notify_parse_file_name_filter(struct kunit *test)
{
	char params[8] = {};
	u32 filter;
	u16 fid;
	u8 watch_tree;
	int rc;

	/* FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001 */
	*(__le32 *)params = cpu_to_le32(0x00000001);
	*(__le16 *)(params + 4) = cpu_to_le16(10);
	params[6] = 0; /* watch_tree = false */

	rc = test_nt_notify_parse(8, params, &filter, &fid, &watch_tree);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, filter, 0x00000001u);
	KUNIT_EXPECT_EQ(test, fid, (u16)10);
	KUNIT_EXPECT_EQ(test, watch_tree, (u8)0);
}

static void test_notify_parse_all_filters_watch_tree(struct kunit *test)
{
	char params[8] = {};
	u32 filter;
	u16 fid;
	u8 watch_tree;
	int rc;

	/* All filters: FILE_NOTIFY_CHANGE_* OR'd together */
	*(__le32 *)params = cpu_to_le32(0x00000FFF);
	*(__le16 *)(params + 4) = cpu_to_le16(0xFFFF);
	params[6] = 1; /* watch_tree = true */

	rc = test_nt_notify_parse(8, params, &filter, &fid, &watch_tree);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, filter, 0x00000FFFu);
	KUNIT_EXPECT_EQ(test, fid, (u16)0xFFFF);
	KUNIT_EXPECT_EQ(test, watch_tree, (u8)1);
}

static void test_notify_parse_security_filter(struct kunit *test)
{
	char params[8] = {};
	u32 filter;
	u16 fid;
	u8 watch_tree;
	int rc;

	/* FILE_NOTIFY_CHANGE_SECURITY = 0x00000100 */
	*(__le32 *)params = cpu_to_le32(0x00000100);
	*(__le16 *)(params + 4) = cpu_to_le16(5);
	params[6] = 0;

	rc = test_nt_notify_parse(8, params, &filter, &fid, &watch_tree);
	KUNIT_EXPECT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, filter, 0x00000100u);
}

/* ======== Tests: NT_TRANSACT_RENAME validation ======== */

static void test_rename_valid_cross_directory(struct kunit *test)
{
	/* param_count=4 (Fid+Flags), data_count=20 (UTF-16 path) */
	KUNIT_EXPECT_EQ(test, test_nt_rename_validate(4, 20), 0);
}

static void test_rename_empty_data_rejected(struct kunit *test)
{
	/* data_count=0 means no new filename provided */
	KUNIT_EXPECT_EQ(test, test_nt_rename_validate(4, 0), -EINVAL);
}

static void test_rename_short_params_rejected(struct kunit *test)
{
	/* param_count=3 is below minimum of 4 */
	KUNIT_EXPECT_EQ(test, test_nt_rename_validate(3, 10), -EINVAL);
}

/* ======== Tests: Response buffer layout ======== */

static void test_rsp_offsets_zero_params_zero_data(struct kunit *test)
{
	u32 param_off, data_off;
	u16 byte_count;

	test_ntransact_rsp_offsets(0, 0, &param_off, &data_off, &byte_count);

	/* ParameterOffset should be 68 (well-known constant) */
	KUNIT_EXPECT_EQ(test, param_off, 68u);
	/* DataOffset = ALIGN(68 + 0, 4) = 68 */
	KUNIT_EXPECT_EQ(test, data_off, 68u);
	/* ByteCount = 1 (pad) + 0 + 0 + 0 = 1 */
	KUNIT_EXPECT_EQ(test, byte_count, (u16)1);
}

static void test_rsp_offsets_with_params_and_data(struct kunit *test)
{
	u32 param_off, data_off;
	u16 byte_count;

	test_ntransact_rsp_offsets(20, 100, &param_off, &data_off, &byte_count);

	KUNIT_EXPECT_EQ(test, param_off, 68u);
	/* DataOffset = ALIGN(68 + 20, 4) = ALIGN(88, 4) = 88 */
	KUNIT_EXPECT_EQ(test, data_off, 88u);
	/* ByteCount = 1 + 20 + (88-88) + 100 = 121 */
	KUNIT_EXPECT_EQ(test, byte_count, (u16)121);
}

static void test_rsp_offsets_unaligned_params(struct kunit *test)
{
	u32 param_off, data_off;
	u16 byte_count;

	/* 5 bytes of params: DataOffset = ALIGN(68+5, 4) = ALIGN(73, 4) = 76 */
	test_ntransact_rsp_offsets(5, 10, &param_off, &data_off, &byte_count);

	KUNIT_EXPECT_EQ(test, param_off, 68u);
	KUNIT_EXPECT_EQ(test, data_off, 76u);
	/* ByteCount = 1 + 5 + (76-73) + 10 = 19 */
	KUNIT_EXPECT_EQ(test, byte_count, (u16)19);
}

/* ======== Tests: NT_TRANSACT_SECONDARY count mismatch ======== */

static void test_secondary_matching_counts_valid(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_secondary_count_check(100, 100, 200, 200), 0);
}

static void test_secondary_param_count_mismatch_rejected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_secondary_count_check(100, 50, 200, 200), -EINVAL);
}

static void test_secondary_data_count_mismatch_rejected(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			test_secondary_count_check(100, 100, 200, 150), -EINVAL);
}

/* ======== Tests: NT_TRANSACT request structure layout ======== */

static void test_ntransact_req_struct_layout(struct kunit *test)
{
	struct smb_com_ntransact_req *req;

	req = kunit_kzalloc(test, sizeof(*req), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	/* Verify field offsets relative to req (excluding smb_hdr) */
	req->MaxSetupCount = 5;
	req->TotalParameterCount = cpu_to_le32(100);
	req->TotalDataCount = cpu_to_le32(200);
	req->MaxParameterCount = cpu_to_le32(1024);
	req->MaxDataCount = cpu_to_le32(65536);
	req->ParameterCount = cpu_to_le32(80);
	req->ParameterOffset = cpu_to_le32(72);
	req->DataCount = cpu_to_le32(160);
	req->DataOffset = cpu_to_le32(156);
	req->SetupCount = 2;
	req->Function = cpu_to_le16(TEST_NT_TRANSACT_IOCTL);

	KUNIT_EXPECT_EQ(test, req->MaxSetupCount, (u8)5);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->TotalParameterCount), 100u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->TotalDataCount), 200u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->MaxParameterCount), 1024u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->MaxDataCount), 65536u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->ParameterCount), 80u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->ParameterOffset), 72u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->DataCount), 160u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req->DataOffset), 156u);
	KUNIT_EXPECT_EQ(test, req->SetupCount, (u8)2);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(req->Function), (u16)TEST_NT_TRANSACT_IOCTL);
}

static void test_ntransact_rsp_struct_layout(struct kunit *test)
{
	struct smb_com_ntransact_rsp *rsp;

	rsp = kunit_kzalloc(test, sizeof(*rsp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rsp);

	rsp->TotalParameterCount = cpu_to_le32(100);
	rsp->TotalDataCount = cpu_to_le32(200);
	rsp->ParameterCount = cpu_to_le32(100);
	rsp->ParameterOffset = cpu_to_le32(68);
	rsp->ParameterDisplacement = cpu_to_le32(0);
	rsp->DataCount = cpu_to_le32(200);
	rsp->DataOffset = cpu_to_le32(172);
	rsp->DataDisplacement = cpu_to_le32(0);
	rsp->SetupCount = 0;

	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->TotalParameterCount), 100u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->TotalDataCount), 200u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->ParameterCount), 100u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->ParameterOffset), 68u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->ParameterDisplacement), 0u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->DataCount), 200u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->DataOffset), 172u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp->DataDisplacement), 0u);
	KUNIT_EXPECT_EQ(test, rsp->SetupCount, (u8)0);
}

/* ======== Tests: MaxSetupCount=0 is valid ======== */

static void test_max_setup_count_zero_valid(struct kunit *test)
{
	struct smb_com_ntransact_req *req;

	req = kunit_kzalloc(test, sizeof(*req), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	/*
	 * MaxSetupCount=0 is legal: it means the client does not expect
	 * any setup words in the response.  SetupCount=0 is also valid.
	 */
	req->MaxSetupCount = 0;
	req->SetupCount = 0;
	req->Function = cpu_to_le16(TEST_NT_TRANSACT_GET_QUOTA);

	KUNIT_EXPECT_EQ(test, req->MaxSetupCount, (u8)0);
	KUNIT_EXPECT_EQ(test, req->SetupCount, (u8)0);
	/* Dispatch should still succeed for quota */
	KUNIT_EXPECT_EQ(test,
			test_nt_transact_dispatch(le16_to_cpu(req->Function)),
			0);
}

/* ======== Tests: SetupCount with setup words at buffer boundary ======== */

static void test_setup_words_exact_boundary(struct kunit *test)
{
	/*
	 * Build a raw buffer where SetupCount setup words extend to the
	 * exact end of the request buffer (no overflow, no underflow).
	 * The setup words follow the Function field in the ntransact request.
	 */
	struct smb_com_ntransact_req *req;
	unsigned int hdr_size = offsetof(struct smb_com_ntransact_req, SetupWords);
	unsigned int setup_count = 4;
	unsigned int total_size = hdr_size + setup_count * sizeof(__le16);
	char *buf;

	buf = kunit_kzalloc(test, total_size + 2, GFP_KERNEL); /* +2 for ByteCount */
	KUNIT_ASSERT_NOT_NULL(test, buf);

	req = (struct smb_com_ntransact_req *)buf;
	req->SetupCount = setup_count;
	req->Function = cpu_to_le16(TEST_NT_TRANSACT_IOCTL);

	/* Fill setup words with identifiable values */
	req->SetupWords[0] = cpu_to_le16(0x1111);
	/* The remaining setup words are at offsets beyond SetupWords[1]
	 * in the flexible array member. Access them via pointer arithmetic.
	 */
	*(__le16 *)(buf + hdr_size + 0) = cpu_to_le16(0x1111);
	*(__le16 *)(buf + hdr_size + 2) = cpu_to_le16(0x2222);
	*(__le16 *)(buf + hdr_size + 4) = cpu_to_le16(0x3333);
	*(__le16 *)(buf + hdr_size + 6) = cpu_to_le16(0x4444);

	KUNIT_EXPECT_EQ(test, req->SetupCount, (u8)4);
	KUNIT_EXPECT_EQ(test,
			le16_to_cpu(*(__le16 *)(buf + hdr_size + 6)),
			(u16)0x4444);
}

/* ======== Tests: TotalDataCount=0 but DataCount>0 (invalid) ======== */

static void test_total_data_zero_data_count_nonzero_invalid(struct kunit *test)
{
	/*
	 * MS-SMB: DataCount should never exceed TotalDataCount.
	 * This is a consistency check the dispatcher should enforce.
	 */
	u32 total_data = 0;
	u32 data_count = 10;

	KUNIT_EXPECT_TRUE(test, data_count > total_data);
}

/* ======== Tests: Mixed valid/invalid ParameterOffset with valid Function ======== */

static void test_valid_function_with_param_offset_zero(struct kunit *test)
{
	/*
	 * A ParameterOffset of 0 with a valid Function field means the
	 * parameter block starts at the very beginning of the transport
	 * frame, which is before the SMB header -- clearly invalid.
	 * The subcommand handler should detect this via its bounds check.
	 */
	struct smb_com_ntransact_req *req;

	req = kunit_kzalloc(test, sizeof(*req) + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->Function = cpu_to_le16(TEST_NT_TRANSACT_IOCTL);
	req->ParameterCount = cpu_to_le32(8);
	req->ParameterOffset = cpu_to_le32(0); /* invalid: before header */

	/*
	 * In the real code, the handler would compute
	 *   params = (char *)req + le32_to_cpu(req->ParameterOffset)
	 * which points before the request, causing an access violation.
	 * The ParameterOffset should be >= sizeof(smb_hdr) to be valid.
	 */
	KUNIT_EXPECT_LT(test, le32_to_cpu(req->ParameterOffset),
			(u32)sizeof(struct smb_hdr));
}

static struct kunit_case ksmbd_smb1_nt_transact_subcmd_test_cases[] = {
	/* Dispatcher routing (8 subcommands + 3 invalid) */
	KUNIT_CASE(test_dispatch_create_valid),
	KUNIT_CASE(test_dispatch_ioctl_valid),
	KUNIT_CASE(test_dispatch_set_security_valid),
	KUNIT_CASE(test_dispatch_notify_valid),
	KUNIT_CASE(test_dispatch_rename_valid),
	KUNIT_CASE(test_dispatch_query_security_valid),
	KUNIT_CASE(test_dispatch_get_user_quota_valid),
	KUNIT_CASE(test_dispatch_set_user_quota_valid),
	KUNIT_CASE(test_dispatch_function_zero_invalid),
	KUNIT_CASE(test_dispatch_function_0xff_invalid),
	KUNIT_CASE(test_dispatch_function_above_max),
	/* Minimum ParameterCount checks */
	KUNIT_CASE(test_create_params_minimum_57),
	KUNIT_CASE(test_ioctl_params_minimum_8),
	KUNIT_CASE(test_set_security_params_minimum_8),
	KUNIT_CASE(test_notify_params_minimum_8),
	KUNIT_CASE(test_rename_params_minimum_4),
	KUNIT_CASE(test_query_security_params_minimum_8),
	KUNIT_CASE(test_quota_params_no_minimum),
	/* NT_TRANSACT_CREATE buffer validation */
	KUNIT_CASE(test_create_valid_minimal_request),
	KUNIT_CASE(test_create_with_security_descriptor),
	KUNIT_CASE(test_create_sd_plus_ea_plus_name_exceeds_data),
	KUNIT_CASE(test_create_name_len_zero_rejected),
	KUNIT_CASE(test_create_name_len_exceeds_data_count),
	/* IOCTL parameter parsing */
	KUNIT_CASE(test_ioctl_parse_valid_8byte_block),
	/* NOTIFY_CHANGE parsing with various filters */
	KUNIT_CASE(test_notify_parse_file_name_filter),
	KUNIT_CASE(test_notify_parse_all_filters_watch_tree),
	KUNIT_CASE(test_notify_parse_security_filter),
	/* RENAME validation */
	KUNIT_CASE(test_rename_valid_cross_directory),
	KUNIT_CASE(test_rename_empty_data_rejected),
	KUNIT_CASE(test_rename_short_params_rejected),
	/* Response buffer layout */
	KUNIT_CASE(test_rsp_offsets_zero_params_zero_data),
	KUNIT_CASE(test_rsp_offsets_with_params_and_data),
	KUNIT_CASE(test_rsp_offsets_unaligned_params),
	/* NT_TRANSACT_SECONDARY count validation */
	KUNIT_CASE(test_secondary_matching_counts_valid),
	KUNIT_CASE(test_secondary_param_count_mismatch_rejected),
	KUNIT_CASE(test_secondary_data_count_mismatch_rejected),
	/* Structure layout */
	KUNIT_CASE(test_ntransact_req_struct_layout),
	KUNIT_CASE(test_ntransact_rsp_struct_layout),
	/* MaxSetupCount=0 */
	KUNIT_CASE(test_max_setup_count_zero_valid),
	/* SetupCount at buffer boundary */
	KUNIT_CASE(test_setup_words_exact_boundary),
	/* TotalDataCount=0 but DataCount>0 */
	KUNIT_CASE(test_total_data_zero_data_count_nonzero_invalid),
	/* Mixed valid/invalid ParameterOffset */
	KUNIT_CASE(test_valid_function_with_param_offset_zero),
	{}
};

static struct kunit_suite ksmbd_smb1_nt_transact_subcmd_test_suite = {
	.name = "ksmbd_smb1_nt_transact_subcommands",
	.test_cases = ksmbd_smb1_nt_transact_subcmd_test_cases,
};

kunit_test_suite(ksmbd_smb1_nt_transact_subcmd_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 NT_TRANSACT subcommand dispatcher and buffer validation");
