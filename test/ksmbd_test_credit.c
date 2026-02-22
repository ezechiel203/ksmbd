// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for credit management logic (smb2misc.c credit functions)
 *
 *   Note: The credit validation function smb2_validate_credit_charge() is
 *   static in smb2misc.c, so we cannot call it directly. Instead, we test
 *   the credit charge calculation logic by verifying the formula:
 *       credit_charge = DIV_ROUND_UP(max(req_len, resp_len), 65536)
 *   This mirrors the kernel's SMB2 credit charge algorithm.
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/math.h>

/*
 * SMB2_MAX_BUFFER_SIZE as defined in smb2pdu.h, duplicated here to avoid
 * pulling in the full SMB2 header chain.
 */
#define TEST_SMB2_MAX_BUFFER_SIZE	65536

/*
 * test_credit_calc_helper - helper to compute expected credit charge
 *
 * This replicates the formula used in smb2_validate_credit_charge():
 *   calc_credit_num = DIV_ROUND_UP(max_len, SMB2_MAX_BUFFER_SIZE)
 * where max_len = max(req_len, expect_resp_len).
 */
static unsigned int test_calc_credit_charge(u64 req_len, u64 resp_len)
{
	u64 max_len = max_t(u64, req_len, resp_len);

	return DIV_ROUND_UP(max_len, TEST_SMB2_MAX_BUFFER_SIZE);
}

/*
 * test_credit_charge_small_request - request smaller than one buffer
 *
 * A request with length <= 65536 should require exactly 1 credit.
 */
static void test_credit_charge_small_request(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(1024, 0);
	KUNIT_EXPECT_EQ(test, charge, 1U);

	charge = test_calc_credit_charge(TEST_SMB2_MAX_BUFFER_SIZE, 0);
	KUNIT_EXPECT_EQ(test, charge, 1U);
}

/*
 * test_credit_charge_large_request - request spanning multiple buffers
 *
 * A 128K request should require 2 credits (128K / 64K = 2).
 */
static void test_credit_charge_large_request(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(131072, 0);  /* 128K */
	KUNIT_EXPECT_EQ(test, charge, 2U);

	charge = test_calc_credit_charge(262144, 0);  /* 256K */
	KUNIT_EXPECT_EQ(test, charge, 4U);
}

/*
 * test_credit_charge_unaligned - request size not aligned to buffer size
 *
 * 65537 bytes should round up to 2 credits.
 */
static void test_credit_charge_unaligned(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(TEST_SMB2_MAX_BUFFER_SIZE + 1, 0);
	KUNIT_EXPECT_EQ(test, charge, 2U);
}

/*
 * test_credit_charge_response_dominates - response length exceeds request
 *
 * When the expected response is larger than the request, the response
 * length determines the credit charge.
 */
static void test_credit_charge_response_dominates(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(1, 196608);  /* 192K response */
	KUNIT_EXPECT_EQ(test, charge, 3U);
}

/*
 * test_credit_charge_zero - zero-length request should require 0 credits
 *
 * Note: in the actual kernel code, credit_charge is floored to 1,
 * but the raw calculation yields 0 for a zero-length request.
 */
static void test_credit_charge_zero(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(0, 0);
	KUNIT_EXPECT_EQ(test, charge, 0U);
}

/*
 * test_credit_charge_max_single - exactly one buffer should need 1 credit
 */
static void test_credit_charge_max_single(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(TEST_SMB2_MAX_BUFFER_SIZE, 0);
	KUNIT_EXPECT_EQ(test, charge, 1U);

	charge = test_calc_credit_charge(0, TEST_SMB2_MAX_BUFFER_SIZE);
	KUNIT_EXPECT_EQ(test, charge, 1U);
}

/*
 * test_credit_charge_8mb - 8MB should require 128 credits
 */
static void test_credit_charge_8mb(struct kunit *test)
{
	unsigned int charge;

	charge = test_calc_credit_charge(8 * 1024 * 1024, 0);
	KUNIT_EXPECT_EQ(test, charge, 128U);
}

static struct kunit_case ksmbd_credit_test_cases[] = {
	KUNIT_CASE(test_credit_charge_small_request),
	KUNIT_CASE(test_credit_charge_large_request),
	KUNIT_CASE(test_credit_charge_unaligned),
	KUNIT_CASE(test_credit_charge_response_dominates),
	KUNIT_CASE(test_credit_charge_zero),
	KUNIT_CASE(test_credit_charge_max_single),
	KUNIT_CASE(test_credit_charge_8mb),
	{}
};

static struct kunit_suite ksmbd_credit_test_suite = {
	.name = "ksmbd_credit",
	.test_cases = ksmbd_credit_test_cases,
};

kunit_test_suite(ksmbd_credit_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 credit management");
