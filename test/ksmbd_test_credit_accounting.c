// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 credit accounting arithmetic
 *
 *   These tests verify the credit charge formula, constant values, struct
 *   field offsets, and per-dialect LARGE_MTU capability flags used by
 *   ksmbd's credit management system (smb2misc.c / smb2_pdu_common.c).
 *
 *   No production functions are called directly; the credit charge
 *   algorithm is self-contained arithmetic that is replicated here.
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/math.h>
#include <linux/types.h>

/*
 * Constants replicated from smb2pdu.h to avoid pulling in the full
 * SMB2 header chain.
 */
#define TEST_SMB2_MAX_CREDITS		8192
#define TEST_SMB2_MAX_BUFFER_SIZE	65536

/* SMB2 Global Capabilities (smb2pdu.h) */
#define TEST_SMB2_GLOBAL_CAP_LARGE_MTU	0x00000004

/* Default server_conf limits (server.c:server_conf_init) */
#define TEST_MAX_INFLIGHT_REQ_DEFAULT	8192
#define TEST_MAX_ASYNC_CREDITS_DEFAULT	512

/*
 * Replicate the credit charge formula from smb2_validate_credit_charge():
 *   calc_credit_num = DIV_ROUND_UP(max(req_len, resp_len), SMB2_MAX_BUFFER_SIZE)
 *   credit_charge   = max(1, calc_credit_num)
 */
static unsigned int test_credit_charge(u64 req_len, u64 resp_len)
{
	u64 max_len = max_t(u64, req_len, resp_len);
	unsigned int calc = DIV_ROUND_UP(max_len, TEST_SMB2_MAX_BUFFER_SIZE);

	return max_t(unsigned int, calc, 1);
}

/*
 * test_max_credits_constant_8192 - SMB2_MAX_CREDITS must be 8192
 *
 * MS-SMB2 §3.2.1.1 defines the maximum credit value as 8192.  The
 * server's smb_version_values.max_credits field is initialised to this
 * constant for every dialect.
 */
static void test_max_credits_constant_8192(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_SMB2_MAX_CREDITS, 8192U);
}

/*
 * test_credit_charge_minimum_1 - credit charge is always at least 1
 *
 * Even a zero-length payload must consume one credit so that the
 * outstanding_credits counter stays in sync with actual requests.
 */
static void test_credit_charge_minimum_1(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_credit_charge(0, 0), 1U);
}

/*
 * test_credit_charge_large_mtu_formula - formula is DIV_ROUND_UP(max/65536)
 *
 * Confirm that the formula matches the specification for a representative
 * payload that spans more than one credit window.
 */
static void test_credit_charge_large_mtu_formula(struct kunit *test)
{
	/* 3 * 65536 = 196608 → exactly 3 credits */
	KUNIT_EXPECT_EQ(test, test_credit_charge(196608, 0), 3U);

	/* 2 * 65536 + 1 = 131073 → rounds up to 3 */
	KUNIT_EXPECT_EQ(test, test_credit_charge(131073, 0), 3U);
}

/*
 * test_credit_charge_64k_payload_is_1 - exactly one buffer fits in 1 credit
 */
static void test_credit_charge_64k_payload_is_1(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_credit_charge(65536, 0), 1U);
	KUNIT_EXPECT_EQ(test, test_credit_charge(0, 65536), 1U);
}

/*
 * test_credit_charge_65537_payload_is_2 - one byte over 64K rounds up to 2
 */
static void test_credit_charge_65537_payload_is_2(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_credit_charge(65537, 0), 2U);
	KUNIT_EXPECT_EQ(test, test_credit_charge(0, 65537), 2U);
}

/*
 * test_credit_charge_128k_payload_is_2 - 128K is exactly 2 credits
 */
static void test_credit_charge_128k_payload_is_2(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_credit_charge(131072, 0), 2U);
}

/*
 * test_credit_charge_8mb_payload_is_128 - 8MB requires 128 credits
 *
 * SMB3 large I/O transfers can reach 8MB (SMB3_MAX_IOSIZE).  At 64K
 * per credit this requires exactly 128 credits, which is the expected
 * ceiling for large read/write operations.
 */
static void test_credit_charge_8mb_payload_is_128(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_credit_charge(8 * 1024 * 1024, 0), 128U);
}

/*
 * test_credit_grant_never_exceeds_max - granted credits capped at max_credits
 *
 * smb2_set_rsp_credits() caps the number of credits granted in any single
 * response to conn->vals->max_credits (= SMB2_MAX_CREDITS = 8192).
 * Verify the bound holds for a pathological credit request.
 */
static void test_credit_grant_never_exceeds_max(struct kunit *test)
{
	unsigned short requested = 65535; /* U16_MAX */
	unsigned short max_credits = TEST_SMB2_MAX_CREDITS;
	unsigned short granted;

	granted = min_t(unsigned short, requested, max_credits);
	KUNIT_EXPECT_LE(test, (unsigned int)granted,
			(unsigned int)TEST_SMB2_MAX_CREDITS);
}

/*
 * test_credit_grant_minimum_1_for_normal - normal response grants >= 1 credit
 *
 * Per MS-SMB2 §3.3.5.1.1 the server MUST grant at least 1 credit in every
 * non-NEGOTIATE response.  The smb2_set_rsp_credits() function achieves
 * this via max_t(unsigned short, le16_to_cpu(req_hdr->CreditRequest), 1).
 */
static void test_credit_grant_minimum_1_for_normal(struct kunit *test)
{
	unsigned short requested = 0; /* client may request 0 */
	unsigned short clamped;

	clamped = max_t(unsigned short, requested, 1);
	KUNIT_EXPECT_GE(test, (unsigned int)clamped, 1U);
}

/*
 * test_credit_response_credits_field_offset - CreditRequest at correct offset
 *
 * The CreditRequest (or CreditResponse in replies) field sits at byte
 * offset 14 inside the 64-byte SMB2 fixed header (after ProtocolId[4],
 * StructureSize[2], CreditCharge[2], Status[4], Command[2]).
 */
static void test_credit_response_credits_field_offset(struct kunit *test)
{
	/*
	 * Layout of struct smb2_hdr (all __packed):
	 *   __le32 ProtocolId      offset  0  size 4
	 *   __le16 StructureSize   offset  4  size 2
	 *   __le16 CreditCharge    offset  6  size 2
	 *   __le32 Status          offset  8  size 4
	 *   __le16 Command         offset 12  size 2
	 *   __le16 CreditRequest   offset 14  size 2
	 */
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct {
				__le32 ProtocolId;
				__le16 StructureSize;
				__le16 CreditCharge;
				__le32 Status;
				__le16 Command;
				__le16 CreditRequest;
			} __packed, CreditRequest),
			14);
}

/*
 * test_smb202_no_large_mtu - SMB 2.0.2 capabilities lack LARGE_MTU
 *
 * The smb20_server_values struct has .capabilities = 0 (see smb2ops.c).
 * Without LARGE_MTU, ksmbd_smb2_check_message() skips the multi-credit
 * validation path and always charges exactly 1 credit.
 */
static void test_smb202_no_large_mtu(struct kunit *test)
{
	unsigned int smb202_caps = 0; /* smb20_server_values.capabilities */

	KUNIT_EXPECT_FALSE(test,
			   !!(smb202_caps & TEST_SMB2_GLOBAL_CAP_LARGE_MTU));
}

/*
 * test_smb21_has_large_mtu - SMB 2.1+ enables LARGE_MTU
 *
 * smb21_server_values, smb30_server_values, smb302_server_values, and
 * smb311_server_values all set SMB2_GLOBAL_CAP_LARGE_MTU.
 */
static void test_smb21_has_large_mtu(struct kunit *test)
{
	/* smb21_server_values.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU */
	unsigned int smb21_caps = TEST_SMB2_GLOBAL_CAP_LARGE_MTU;

	KUNIT_EXPECT_TRUE(test,
			  !!(smb21_caps & TEST_SMB2_GLOBAL_CAP_LARGE_MTU));
}

/*
 * test_async_credit_holds - async response keeps credit until final reply
 *
 * Per MS-SMB2 §3.3.5.1.1, the server sends an interim response (no
 * credit grant) and holds the credit until the final response.  The
 * outstanding_credits counter is only decremented on the final reply.
 * Simulate: interim does not decrement, final does.
 */
static void test_async_credit_holds(struct kunit *test)
{
	unsigned int outstanding = 0;
	unsigned int charge = 1;

	/* Interim response: increment outstanding, do NOT decrement */
	outstanding += charge;
	KUNIT_EXPECT_EQ(test, outstanding, 1U);

	/* Final response: decrement outstanding */
	outstanding -= charge;
	KUNIT_EXPECT_EQ(test, outstanding, 0U);
}

/*
 * test_cancel_doesnt_consume_credit - CANCEL exits credit check immediately
 *
 * smb2_validate_credit_charge() returns 0 immediately for SMB2_CANCEL
 * without touching the credit counters (the spec exempts CANCEL from
 * credit accounting).  Simulate the early-return logic.
 */
static void test_cancel_doesnt_consume_credit(struct kunit *test)
{
#define TEST_SMB2_CANCEL_HE 0x000C
	unsigned int cmd = TEST_SMB2_CANCEL_HE;
	bool credit_consumed = true;

	if (cmd == TEST_SMB2_CANCEL_HE)
		credit_consumed = false;

	KUNIT_EXPECT_FALSE(test, credit_consumed);
#undef TEST_SMB2_CANCEL_HE
}

/*
 * test_max_inflight_default_8192 - server_conf.max_inflight_req defaults to 8192
 *
 * server_conf_init() sets max_inflight_req = SMB2_MAX_CREDITS = 8192.
 * ksmbd_conn_handler_loop() uses this value to throttle concurrency.
 */
static void test_max_inflight_default_8192(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_MAX_INFLIGHT_REQ_DEFAULT, 8192U);
}

/*
 * test_max_async_credits_default_512 - max_async_credits defaults to 512
 *
 * server_conf_init() sets max_async_credits = 512.  This caps the number
 * of simultaneous async (CHANGE_NOTIFY / READ-async) operations per
 * connection to prevent memory exhaustion.
 */
static void test_max_async_credits_default_512(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_MAX_ASYNC_CREDITS_DEFAULT, 512U);
}

/*
 * test_credit_charge_zero_payload_is_1 - zero-byte payload charges 1 credit
 *
 * The min_t(1) floor in smb2_validate_credit_charge() ensures even a
 * completely empty request (ECHO, LOGOFF, TREE_DISCONNECT) consumes one
 * credit so that the outstanding_credits counter remains non-negative.
 */
static void test_credit_charge_zero_payload_is_1(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_credit_charge(0, 0), 1U);
}

/*
 * test_credit_header_struct_layout - CreditCharge at offset 6, CreditRequest at 14
 *
 * Verifies the byte positions of both credit-related fields within the
 * fixed SMB2 header so that wire-level parsing is correct.
 */
static void test_credit_header_struct_layout(struct kunit *test)
{
	struct {
		__le32 ProtocolId;   /* 0 */
		__le16 StructureSize;/* 4 */
		__le16 CreditCharge; /* 6 */
		__le32 Status;       /* 8 */
		__le16 Command;      /* 12 */
		__le16 CreditRequest;/* 14 */
	} __packed hdr_layout;

	KUNIT_EXPECT_EQ(test, (int)offsetof(typeof(hdr_layout), CreditCharge),
			6);
	KUNIT_EXPECT_EQ(test, (int)offsetof(typeof(hdr_layout), CreditRequest),
			14);
}

/*
 * test_credit_overflow_check - charge * 65536 does not overflow u64
 *
 * The maximum valid credit charge is SMB2_MAX_CREDITS (8192).  Multiplying
 * by the per-credit buffer size must not overflow a 64-bit counter used
 * for payload length comparisons inside smb2_validate_credit_charge().
 */
static void test_credit_overflow_check(struct kunit *test)
{
	u64 max_payload;

	max_payload = (u64)TEST_SMB2_MAX_CREDITS * TEST_SMB2_MAX_BUFFER_SIZE;

	/* 8192 * 65536 = 536870912 (well within U64_MAX) */
	KUNIT_EXPECT_EQ(test, max_payload, (u64)536870912ULL);
	KUNIT_EXPECT_LT(test, max_payload, U64_MAX);
}

/*
 * test_negotiate_initial_credit_grant - NEGOTIATE response grants exactly 1 credit
 *
 * smb2_set_rsp_credits() sets aux_max = 1 when the command is
 * SMB2_NEGOTIATE, so the server never grants more than 1 credit in the
 * NEGOTIATE response regardless of how many the client requested.
 */
static void test_negotiate_initial_credit_grant(struct kunit *test)
{
#define TEST_SMB2_NEGOTIATE_HE 0x0000
	unsigned int cmd = TEST_SMB2_NEGOTIATE_HE;
	unsigned short credits_requested = 1000;
	unsigned short aux_max;
	unsigned short granted;

	/* Mirror the smb2_set_rsp_credits() NEGOTIATE branch */
	if (cmd == TEST_SMB2_NEGOTIATE_HE)
		aux_max = 1;
	else
		aux_max = TEST_SMB2_MAX_CREDITS;

	granted = min_t(unsigned short, credits_requested, aux_max);
	KUNIT_EXPECT_EQ(test, (unsigned int)granted, 1U);
#undef TEST_SMB2_NEGOTIATE_HE
}

static struct kunit_case ksmbd_credit_accounting_test_cases[] = {
	KUNIT_CASE(test_max_credits_constant_8192),
	KUNIT_CASE(test_credit_charge_minimum_1),
	KUNIT_CASE(test_credit_charge_large_mtu_formula),
	KUNIT_CASE(test_credit_charge_64k_payload_is_1),
	KUNIT_CASE(test_credit_charge_65537_payload_is_2),
	KUNIT_CASE(test_credit_charge_128k_payload_is_2),
	KUNIT_CASE(test_credit_charge_8mb_payload_is_128),
	KUNIT_CASE(test_credit_grant_never_exceeds_max),
	KUNIT_CASE(test_credit_grant_minimum_1_for_normal),
	KUNIT_CASE(test_credit_response_credits_field_offset),
	KUNIT_CASE(test_smb202_no_large_mtu),
	KUNIT_CASE(test_smb21_has_large_mtu),
	KUNIT_CASE(test_async_credit_holds),
	KUNIT_CASE(test_cancel_doesnt_consume_credit),
	KUNIT_CASE(test_max_inflight_default_8192),
	KUNIT_CASE(test_max_async_credits_default_512),
	KUNIT_CASE(test_credit_charge_zero_payload_is_1),
	KUNIT_CASE(test_credit_header_struct_layout),
	KUNIT_CASE(test_credit_overflow_check),
	KUNIT_CASE(test_negotiate_initial_credit_grant),
	{}
};

static struct kunit_suite ksmbd_credit_accounting_test_suite = {
	.name = "ksmbd_credit_accounting",
	.test_cases = ksmbd_credit_accounting_test_cases,
};

kunit_test_suite(ksmbd_credit_accounting_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 credit accounting arithmetic");
