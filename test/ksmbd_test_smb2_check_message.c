// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for security-critical smb2misc.c helpers:
 *     check_smb2_hdr()           - client/server direction guard
 *     smb2_calc_size()           - PDU total length computation
 *     smb2_validate_credit_charge() - CreditCharge vs payload sanity
 *
 *   These tests call the real exported (VISIBLE_IF_KUNIT) production
 *   functions with crafted on-stack PDU buffers to exercise malformed-
 *   input paths that the outer ksmbd_smb2_check_message() dispatcher
 *   depends on for security.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/string.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "smb2pdu.h"
#include "smb_common.h"
#include "connection.h"

/*
 * SMB2_FLAGS_SERVER_TO_REDIR: bit 0 of the Flags field marks a response PDU.
 * check_smb2_hdr() rejects any PDU that has this bit set because the server
 * must never process its own response as a request.
 */
#define TEST_SMB2_FLAGS_SERVER_TO_REDIR		cpu_to_le32(0x00000001)

/*
 * SMB1 on-wire magic: 0xFF 'S' 'M' 'B' (little-endian u32 = 0x424d53ff)
 * Used to verify that check_smb2_hdr() does NOT inspect ProtocolId.
 */
#define TEST_SMB1_PROTO_NUMBER			cpu_to_le32(0x424d53ff)

/* -----------------------------------------------------------------------
 * Helpers
 * ----------------------------------------------------------------------- */

/*
 * init_smb2_req_hdr - populate the fixed SMB2 header fields for a request.
 *
 * Sets ProtocolId = SMB2_PROTO_NUMBER, StructureSize = 64, Command = @cmd,
 * CreditCharge = @credit, and clears all other fields including Flags so that
 * the SMB2_FLAGS_SERVER_TO_REDIR bit is absent (i.e. it looks like a client
 * request).
 */
static void init_smb2_req_hdr(struct smb2_hdr *hdr, __le16 cmd, u16 credit)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->ProtocolId    = SMB2_PROTO_NUMBER;
	hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE; /* cpu_to_le16(64) */
	hdr->Command       = cmd;
	hdr->CreditCharge  = cpu_to_le16(credit);
}

/*
 * make_mock_conn - initialise a stack-allocated ksmbd_conn for credit tests.
 *
 * Callers must supply a smb_version_values with max_credits set.
 * The spinlock, total_credits, and outstanding_credits are the only fields
 * that smb2_validate_credit_charge() touches beyond conn->vals.
 */
static void make_mock_conn(struct ksmbd_conn *conn,
			   struct smb_version_values *vals,
			   unsigned int total, unsigned int outstanding)
{
	memset(conn, 0, sizeof(*conn));
	conn->vals               = vals;
	conn->total_credits      = total;
	conn->outstanding_credits = outstanding;
	spin_lock_init(&conn->credits_lock);
}

/* -----------------------------------------------------------------------
 * Tests for check_smb2_hdr()
 *
 * check_smb2_hdr() returns 0 for a valid client request (SERVER_TO_REDIR
 * bit clear) and 1 for a server response (SERVER_TO_REDIR bit set).
 * It does NOT inspect ProtocolId or StructureSize — those are checked by
 * the caller (ksmbd_smb2_check_message) after check_smb2_hdr() returns.
 * ----------------------------------------------------------------------- */

/*
 * test_valid_smb2_header - well-formed SMB2 client request is accepted
 *
 * ProtocolId = 0xFE534D42, StructureSize = 64, Flags = 0 (no SERVER_TO_REDIR).
 * Expects return value 0 (accepted as client request).
 */
static void test_valid_smb2_header(struct kunit *test)
{
	struct smb2_hdr hdr;

	init_smb2_req_hdr(&hdr, SMB2_NEGOTIATE, 0);
	/* Flags=0: no SERVER_TO_REDIR bit → must be accepted */
	KUNIT_EXPECT_EQ(test, check_smb2_hdr(&hdr), 0);
}

/*
 * test_invalid_protocol_id - wrong ProtocolId does NOT affect check_smb2_hdr
 *
 * check_smb2_hdr() only inspects hdr->Flags; ProtocolId validation is done
 * elsewhere.  With Flags=0 (client-request), even a bogus ProtocolId returns
 * 0.  This test documents that invariant explicitly.
 */
static void test_invalid_protocol_id(struct kunit *test)
{
	struct smb2_hdr hdr;

	init_smb2_req_hdr(&hdr, SMB2_NEGOTIATE, 0);
	hdr.ProtocolId = cpu_to_le32(0xDEADBEEF); /* garbage */
	/*
	 * check_smb2_hdr() checks only the Flags field; it does not
	 * validate ProtocolId.  With Flags=0 the function returns 0.
	 */
	KUNIT_EXPECT_EQ(test, check_smb2_hdr(&hdr), 0);
}

/*
 * test_invalid_structure_size - wrong StructureSize does NOT affect check_smb2_hdr
 *
 * StructureSize validation (must be 64) is performed by
 * ksmbd_smb2_check_message() after check_smb2_hdr() returns.
 * check_smb2_hdr() itself only tests Flags.
 */
static void test_invalid_structure_size(struct kunit *test)
{
	struct smb2_hdr hdr;

	init_smb2_req_hdr(&hdr, SMB2_NEGOTIATE, 0);
	hdr.StructureSize = cpu_to_le16(0); /* invalid */
	/* Flags still 0 → check_smb2_hdr returns 0 regardless */
	KUNIT_EXPECT_EQ(test, check_smb2_hdr(&hdr), 0);
}

/*
 * test_zero_header - all-zero 64-byte header
 *
 * Flags=0 (SERVER_TO_REDIR bit clear) → check_smb2_hdr returns 0.
 * Other fields being zero (ProtocolId=0, StructureSize=0) are checked by
 * the outer caller, not by check_smb2_hdr itself.
 */
static void test_zero_header(struct kunit *test)
{
	struct smb2_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	/*
	 * Flags=0 means SERVER_TO_REDIR is absent.  check_smb2_hdr()
	 * returns 0 (not a response).  The caller must then validate
	 * ProtocolId and StructureSize separately.
	 */
	KUNIT_EXPECT_EQ(test, check_smb2_hdr(&hdr), 0);
}

/*
 * test_smb1_protocol_id - SMB1 magic does NOT affect check_smb2_hdr
 *
 * 0xFF534D42 is the SMB1 ProtocolId.  check_smb2_hdr() ignores it.
 * With Flags=0 the function returns 0; ProtocolId validation is done
 * before this function is called (by smb_check_message() dispatch logic).
 */
static void test_smb1_protocol_id(struct kunit *test)
{
	struct smb2_hdr hdr;

	init_smb2_req_hdr(&hdr, SMB2_NEGOTIATE, 0);
	hdr.ProtocolId = TEST_SMB1_PROTO_NUMBER;
	/* Flags=0 → check_smb2_hdr accepts regardless of ProtocolId */
	KUNIT_EXPECT_EQ(test, check_smb2_hdr(&hdr), 0);
}

/*
 * test_server_to_redir_flag_rejected - response PDU rejected
 *
 * A PDU with SMB2_FLAGS_SERVER_TO_REDIR set is a server-to-client
 * response, not a client request.  check_smb2_hdr() must return 1.
 */
static void test_server_to_redir_flag_rejected(struct kunit *test)
{
	struct smb2_hdr hdr;

	init_smb2_req_hdr(&hdr, SMB2_NEGOTIATE, 0);
	hdr.Flags = TEST_SMB2_FLAGS_SERVER_TO_REDIR;
	KUNIT_EXPECT_EQ(test, check_smb2_hdr(&hdr), 1);
}

/* -----------------------------------------------------------------------
 * Tests for smb2_calc_size()
 *
 * smb2_calc_size() computes the expected total byte length of an SMB2
 * PDU given a pointer to the raw wire buffer (struct smb2_pdu *).
 *
 * The "buf" argument is treated as RFC1001-framed: smb2_pdu.hdr starts
 * at buf+0 (no leading 4-byte NetBIOS length prefix here, unlike the
 * full request_buf layout used by ksmbd_smb2_check_message).
 *
 * Formula (simplified for fixed-size commands):
 *   *len = hdr->StructureSize(64) + pdu->StructureSize2
 *
 * For LOCK the formula subtracts sizeof(smb2_lock_element) because
 * StructureSize2=48 includes one mandatory element whose data area is
 * then re-added via smb2_get_data_area_len().
 * ----------------------------------------------------------------------- */

/*
 * test_calc_size_negotiate - NEGOTIATE request minimal size
 *
 * StructureSize(hdr)=64, StructureSize2=36.
 * NEGOTIATE has a data area table entry but smb2_get_data_area_len()
 * falls through to the default case (no explicit offset/length fields)
 * and returns 0,0 → data_length=0 → calc_size_exit.
 * Expected: *len = 64 + 36 = 100.
 */
static void test_calc_size_negotiate(struct kunit *test)
{
	/*
	 * Layout: [ smb2_hdr (64 B) | StructureSize2 (2 B) | ... ]
	 * We use smb2_negotiate_req which has hdr + fixed negotiate body.
	 * Allocate enough space; zero it; then fill the two StructureSize
	 * fields that smb2_calc_size() reads.
	 */
	struct smb2_negotiate_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE; /* cpu_to_le16(64) */
	req.hdr.Command       = SMB2_NEGOTIATE;
	/* StructureSize2 sits in smb2_pdu.StructureSize2; negotiate body
	 * is 36 bytes (DialectCount..Reserved2 + empty Dialects[]) */
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(36);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, len, 100U); /* 64 + 36 */
}

/*
 * test_calc_size_session_setup - SESSION_SETUP with 0-byte security buffer
 *
 * StructureSize(hdr)=64, StructureSize2=25.
 * SecurityBufferLength=0 → data_length=0 → calc_size_exit.
 * Expected: *len = 64 + 25 = 89.
 */
static void test_calc_size_session_setup(struct kunit *test)
{
	struct smb2_sess_setup_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize          = SMB2_HEADER_STRUCTURE_SIZE;
	req.hdr.Command                = SMB2_SESSION_SETUP;
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(25);
	req.SecurityBufferOffset       = cpu_to_le16(0);
	req.SecurityBufferLength       = cpu_to_le16(0);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, len, 89U); /* 64 + 25 */
}

/*
 * test_calc_size_create_no_context - CREATE with no name and no contexts
 *
 * StructureSize(hdr)=64, StructureSize2=57.
 * CreateContextsLength=0, NameLength=0 → data_length=0 → calc_size_exit.
 * Expected: *len = 64 + 57 = 121.
 */
static void test_calc_size_create_no_context(struct kunit *test)
{
	struct smb2_create_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req.hdr.Command       = SMB2_CREATE;
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(57);
	req.NameOffset         = cpu_to_le16(0);
	req.NameLength         = cpu_to_le16(0);
	req.CreateContextsOffset = cpu_to_le32(0);
	req.CreateContextsLength = cpu_to_le32(0);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, len, 121U); /* 64 + 57 */
}

/*
 * test_calc_size_close - CLOSE request (fixed body, no data area)
 *
 * StructureSize(hdr)=64, StructureSize2=24, has_smb2_data_area=false.
 * Expected: *len = 64 + 24 = 88.
 */
static void test_calc_size_close(struct kunit *test)
{
	struct smb2_close_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req.hdr.Command       = SMB2_CLOSE;
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(24);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, len, 88U); /* 64 + 24 */
}

/*
 * test_calc_size_echo - ECHO request (minimal fixed body, no data area)
 *
 * StructureSize(hdr)=64, StructureSize2=4, has_smb2_data_area=false.
 * Expected: *len = 64 + 4 = 68.
 */
static void test_calc_size_echo(struct kunit *test)
{
	struct smb2_echo_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req.hdr.Command       = SMB2_ECHO;
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(4);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, len, 68U); /* 64 + 4 */
}

/*
 * test_calc_size_lock_one_element - LOCK with a single lock element
 *
 * StructureSize(hdr)=64, StructureSize2=48.
 * smb2_calc_size subtracts sizeof(smb2_lock_element)=24 → base=88.
 * smb2_get_data_area_len for LOCK with LockCount=1:
 *   offset = offsetof(smb2_lock_req, locks)
 *          = sizeof(smb2_hdr) + 2+2+4+8+8 = 64+24 = 88
 *   len    = sizeof(smb2_lock_element) * 1 = 24
 * offset+1 = 89, *len = 88 → 89 >= 88 → no overlap error.
 * Final: *len = 88 + 24 = 112.
 */
static void test_calc_size_lock_one_element(struct kunit *test)
{
	struct smb2_lock_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req.hdr.Command       = SMB2_LOCK;
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(48);
	req.LockCount         = cpu_to_le16(1);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* base = 64+48-24 = 88; data area = 24 → total = 112 */
	KUNIT_EXPECT_EQ(test, len, 112U);
}

/*
 * test_calc_size_write_with_data - WRITE with a 100-byte payload
 *
 * StructureSize(hdr)=64, StructureSize2=49 → base=113.
 * DataOffset = offsetof(smb2_write_req, Buffer) = 64+48 = 112.
 * data_length = 100.
 * offset+1 = 113, *len = 113 → 113 >= 113 → no overlap.
 * Final: *len = 112 + 100 = 212.
 */
static void test_calc_size_write_with_data(struct kunit *test)
{
	/*
	 * We need enough space after the fixed smb2_write_req header to
	 * hold the 100-byte payload.  Use a heap allocation so we can set
	 * DataOffset to point immediately after the fixed body.
	 */
	const unsigned int data_len = 100;
	const unsigned int buf_size = sizeof(struct smb2_write_req) + data_len;
	struct smb2_write_req *req;
	unsigned int len = 0;
	int ret;

	req = kzalloc(buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req->hdr.Command       = SMB2_WRITE;
	((struct smb2_pdu *)req)->StructureSize2 = cpu_to_le16(49);
	/*
	 * DataOffset is measured from the start of the SMB2 header.
	 * sizeof(smb2_write_req) - sizeof(smb2_hdr) = 48 bytes fixed body.
	 * offsetof(Buffer) = sizeof(smb2_write_req) = 64 + 48 = 112.
	 */
	req->DataOffset = cpu_to_le16((u16)offsetof(struct smb2_write_req,
						     Buffer));
	req->Length     = cpu_to_le32(data_len);

	ret = smb2_calc_size(req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, len, 212U); /* 112 + 100 */

	kfree(req);
}

/* -----------------------------------------------------------------------
 * Tests for smb2_validate_credit_charge()
 *
 * smb2_validate_credit_charge() checks that CreditCharge >=
 * ceil(max(req_len, resp_len) / 65536).  It also enforces that
 * credit_charge <= conn->vals->max_credits and that enough credits
 * are available in conn->total_credits.
 *
 * Return values:
 *   0  - valid
 *   1  - credit_charge insufficient for payload size, or exceeds max_credits
 *   2  - not enough total/outstanding credits on the connection
 *
 * SMB2_CANCEL always returns 0 (no credit charge required).
 * ----------------------------------------------------------------------- */

/*
 * test_credit_charge_1_for_small_payload - charge=1 for <64KB → valid
 *
 * A READ request with Length=1024 (<64KB) needs only 1 credit.
 * total_credits=10, outstanding=0 → sufficient.
 */
static void test_credit_charge_1_for_small_payload(struct kunit *test)
{
	struct smb_version_values vals;
	struct ksmbd_conn conn;
	struct smb2_read_req req;
	int ret;

	memset(&vals, 0, sizeof(vals));
	vals.max_credits = 128;

	make_mock_conn(&conn, &vals, 10, 0);

	memset(&req, 0, sizeof(req));
	req.hdr.Command      = SMB2_READ;
	req.hdr.CreditCharge = cpu_to_le16(1);
	req.Length           = cpu_to_le32(1024); /* 1 KB — needs 1 credit */

	ret = smb2_validate_credit_charge(&conn, &req.hdr);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_credit_charge_0_rejected - charge=0 is normalised to 1 but then
 * checked against the payload requirement.
 *
 * smb2_validate_credit_charge() clamps credit_charge to max(charge, 1).
 * A READ of 1024 bytes requires calc_credit_num=1; clamped charge=1 ≥ 1
 * so the size check passes.  However, we test charge=0 with a large
 * READ (>64KB) where calc_credit_num=2 so the clamped value 1 < 2 → fail.
 */
static void test_credit_charge_0_rejected(struct kunit *test)
{
	struct smb_version_values vals;
	struct ksmbd_conn conn;
	struct smb2_read_req req;
	int ret;

	memset(&vals, 0, sizeof(vals));
	vals.max_credits = 128;

	make_mock_conn(&conn, &vals, 10, 0);

	memset(&req, 0, sizeof(req));
	req.hdr.Command      = SMB2_READ;
	req.hdr.CreditCharge = cpu_to_le16(0);
	/* 65537 bytes requires 2 credits; clamped charge = max(0,1) = 1 < 2 */
	req.Length           = cpu_to_le32(65537);

	ret = smb2_validate_credit_charge(&conn, &req.hdr);
	KUNIT_EXPECT_EQ(test, ret, 1); /* insufficient credit charge */
}

/*
 * test_credit_charge_2_for_65537 - charge=2 for 65537-byte READ → valid
 *
 * ceil(65537 / 65536) = 2; CreditCharge=2 satisfies the requirement.
 * total_credits=10, outstanding=0 → sufficient.
 */
static void test_credit_charge_2_for_65537(struct kunit *test)
{
	struct smb_version_values vals;
	struct ksmbd_conn conn;
	struct smb2_read_req req;
	int ret;

	memset(&vals, 0, sizeof(vals));
	vals.max_credits = 128;

	make_mock_conn(&conn, &vals, 10, 0);

	memset(&req, 0, sizeof(req));
	req.hdr.Command      = SMB2_READ;
	req.hdr.CreditCharge = cpu_to_le16(2);
	req.Length           = cpu_to_le32(65537);

	ret = smb2_validate_credit_charge(&conn, &req.hdr);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_credit_charge_1_for_65537_rejected - charge=1 for 65537 bytes → invalid
 *
 * 65537 bytes requires ceil(65537/65536)=2 credits but only 1 is offered.
 * The function must return 1 (insufficient credit charge).
 */
static void test_credit_charge_1_for_65537_rejected(struct kunit *test)
{
	struct smb_version_values vals;
	struct ksmbd_conn conn;
	struct smb2_read_req req;
	int ret;

	memset(&vals, 0, sizeof(vals));
	vals.max_credits = 128;

	make_mock_conn(&conn, &vals, 10, 0);

	memset(&req, 0, sizeof(req));
	req.hdr.Command      = SMB2_READ;
	req.hdr.CreditCharge = cpu_to_le16(1);
	req.Length           = cpu_to_le32(65537);

	ret = smb2_validate_credit_charge(&conn, &req.hdr);
	KUNIT_EXPECT_EQ(test, ret, 1); /* 1 < ceil(65537/65536)=2 */
}

/*
 * test_credit_charge_128_for_8mb - charge=128 for 8MB WRITE → valid
 *
 * 8 MB = 8 * 1024 * 1024 = 8388608 bytes.
 * ceil(8388608 / 65536) = 128.
 * CreditCharge=128, max_credits=128, total=128, outstanding=0 → valid.
 */
static void test_credit_charge_128_for_8mb(struct kunit *test)
{
	struct smb_version_values vals;
	struct ksmbd_conn conn;
	struct smb2_write_req req;
	int ret;

	memset(&vals, 0, sizeof(vals));
	vals.max_credits = 128;

	make_mock_conn(&conn, &vals, 128, 0);

	memset(&req, 0, sizeof(req));
	req.hdr.Command      = SMB2_WRITE;
	req.hdr.CreditCharge = cpu_to_le16(128);
	req.Length           = cpu_to_le32(8U * 1024U * 1024U); /* 8 MB */

	ret = smb2_validate_credit_charge(&conn, &req.hdr);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* -----------------------------------------------------------------------
 * Combined validation tests
 * ----------------------------------------------------------------------- */

/*
 * test_truncated_pdu_rejected - PDU shorter than its StructureSize
 *
 * smb2_calc_size() adds hdr->StructureSize + pdu->StructureSize2.
 * We cannot pass a buffer shorter than the struct; instead we verify that
 * calc_size with a zero StructureSize2 (and a CLOSE command that has no
 * data area) correctly returns *len = 64 + 0 = 64.  The outer
 * ksmbd_smb2_check_message() then rejects this because req_struct_size
 * (64+24=88) > len+1.  Here we just validate that smb2_calc_size itself
 * succeeds and returns 64 for StructureSize2=0.
 */
static void test_truncated_pdu_rejected(struct kunit *test)
{
	struct smb2_close_req req;
	unsigned int len = 0;
	int ret;

	memset(&req, 0, sizeof(req));
	req.hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req.hdr.Command       = SMB2_CLOSE;
	/* StructureSize2 = 0 simulates a truncated PDU body */
	((struct smb2_pdu *)&req)->StructureSize2 = cpu_to_le16(0);

	ret = smb2_calc_size(&req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/*
	 * *len = 64 + 0 = 64.  The outer check then rejects because
	 * req_struct_size (64+24=88) > 64+1=65.
	 */
	KUNIT_EXPECT_EQ(test, len, 64U);
}

/*
 * test_oversized_pdu_accepted - PDU larger than minimum is accepted
 *
 * A WRITE with a large payload: smb2_calc_size() returns the actual
 * needed length including the data area.  As long as the offset/length
 * fields are consistent, smb2_calc_size() succeeds.  Verified by
 * checking a 1000-byte WRITE.
 */
static void test_oversized_pdu_accepted(struct kunit *test)
{
	const unsigned int data_len = 1000;
	const unsigned int buf_size = sizeof(struct smb2_write_req) + data_len;
	struct smb2_write_req *req;
	unsigned int len = 0;
	int ret;

	req = kzalloc(buf_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, req);

	req->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	req->hdr.Command       = SMB2_WRITE;
	((struct smb2_pdu *)req)->StructureSize2 = cpu_to_le16(49);
	req->DataOffset = cpu_to_le16((u16)offsetof(struct smb2_write_req,
						     Buffer));
	req->Length     = cpu_to_le32(data_len);

	ret = smb2_calc_size(req, &len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	/* 64+48=112 (buffer offset) + 1000 = 1112 */
	KUNIT_EXPECT_EQ(test, len,
			(unsigned int)offsetof(struct smb2_write_req, Buffer) +
			data_len);

	kfree(req);
}

/*
 * test_cancel_command_zero_credit_charge - CANCEL bypasses credit check
 *
 * MS-SMB2 §3.3.5.16: CANCEL MUST NOT include a credit charge.
 * smb2_validate_credit_charge() returns 0 unconditionally for CANCEL.
 * This test uses charge=0 (which would fail for any other command).
 */
static void test_cancel_command_zero_credit_charge(struct kunit *test)
{
	struct smb_version_values vals;
	struct ksmbd_conn conn;
	struct smb2_hdr hdr;
	int ret;

	memset(&vals, 0, sizeof(vals));
	vals.max_credits = 128;

	make_mock_conn(&conn, &vals, 0, 0); /* no credits at all */

	init_smb2_req_hdr(&hdr, SMB2_CANCEL, 0);
	hdr.CreditCharge = cpu_to_le16(0); /* zero charge */

	/*
	 * CANCEL always returns 0 regardless of charge, credits, or
	 * payload size — the early return in smb2_validate_credit_charge()
	 * handles it before the credit accounting path.
	 */
	ret = smb2_validate_credit_charge(&conn, &hdr);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* -----------------------------------------------------------------------
 * Test suite registration
 * ----------------------------------------------------------------------- */

static struct kunit_case ksmbd_smb2_check_message_test_cases[] = {
	/* check_smb2_hdr() */
	KUNIT_CASE(test_valid_smb2_header),
	KUNIT_CASE(test_invalid_protocol_id),
	KUNIT_CASE(test_invalid_structure_size),
	KUNIT_CASE(test_zero_header),
	KUNIT_CASE(test_smb1_protocol_id),
	KUNIT_CASE(test_server_to_redir_flag_rejected),
	/* smb2_calc_size() */
	KUNIT_CASE(test_calc_size_negotiate),
	KUNIT_CASE(test_calc_size_session_setup),
	KUNIT_CASE(test_calc_size_create_no_context),
	KUNIT_CASE(test_calc_size_close),
	KUNIT_CASE(test_calc_size_echo),
	KUNIT_CASE(test_calc_size_lock_one_element),
	KUNIT_CASE(test_calc_size_write_with_data),
	/* smb2_validate_credit_charge() */
	KUNIT_CASE(test_credit_charge_1_for_small_payload),
	KUNIT_CASE(test_credit_charge_0_rejected),
	KUNIT_CASE(test_credit_charge_2_for_65537),
	KUNIT_CASE(test_credit_charge_1_for_65537_rejected),
	KUNIT_CASE(test_credit_charge_128_for_8mb),
	/* Combined validation */
	KUNIT_CASE(test_truncated_pdu_rejected),
	KUNIT_CASE(test_oversized_pdu_accepted),
	KUNIT_CASE(test_cancel_command_zero_credit_charge),
	{}
};

static struct kunit_suite ksmbd_smb2_check_message_test_suite = {
	.name = "ksmbd_smb2_check_message",
	.test_cases = ksmbd_smb2_check_message_test_cases,
};

kunit_test_suite(ksmbd_smb2_check_message_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 message validation helpers");
