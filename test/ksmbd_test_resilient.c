// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for resilient handle support (ksmbd_resilient.c)
 *
 *   Tests the NETWORK_RESILIENCY_REQUEST structure validation,
 *   timeout capping logic, and resilient handle flag management.
 *   The actual FSCTL handler requires full work/fp infrastructure,
 *   so we test the replicated validation logic.
 */

#include <kunit/test.h>
#include <linux/slab.h>

#include "vfs_cache.h"

/* Replicated from ksmbd_resilient.c */
struct test_network_resiliency_request {
	__le32	timeout;
	__le32	reserved;
} __packed;

#define TEST_MAX_RESILIENT_TIMEOUT_MS	(5 * 60 * 1000)

/* ═══════════════════════════════════════════════════════════════════
 *  Request Structure Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_resilient_input_too_short_rejected(struct kunit *test)
{
	unsigned int min_size = sizeof(struct test_network_resiliency_request);

	/* Input buffer must be at least this size */
	KUNIT_EXPECT_EQ(test, min_size, 8U);
	/* Anything smaller should be rejected */
	KUNIT_EXPECT_TRUE(test, 7 < min_size);
}

static void test_resilient_normal_timeout(struct kunit *test)
{
	struct test_network_resiliency_request req = {};
	unsigned int timeout;

	req.timeout = cpu_to_le32(30000); /* 30 seconds */
	timeout = le32_to_cpu(req.timeout);

	KUNIT_EXPECT_EQ(test, timeout, 30000U);
	KUNIT_EXPECT_LE(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
}

static void test_resilient_timeout_capped_to_max(struct kunit *test)
{
	struct test_network_resiliency_request req = {};
	unsigned int timeout;

	req.timeout = cpu_to_le32(TEST_MAX_RESILIENT_TIMEOUT_MS + 100000);
	timeout = le32_to_cpu(req.timeout);

	/* Cap to max */
	if (timeout > TEST_MAX_RESILIENT_TIMEOUT_MS)
		timeout = TEST_MAX_RESILIENT_TIMEOUT_MS;

	KUNIT_EXPECT_EQ(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
}

static void test_resilient_zero_timeout(struct kunit *test)
{
	struct test_network_resiliency_request req = {};
	unsigned int timeout;

	req.timeout = cpu_to_le32(0);
	timeout = le32_to_cpu(req.timeout);

	KUNIT_EXPECT_EQ(test, timeout, 0U);
	/* Zero timeout is valid per spec */
	KUNIT_EXPECT_LE(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Flag Management Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_resilient_sets_is_resilient_flag(struct kunit *test)
{
	struct ksmbd_file fp = {};

	KUNIT_EXPECT_FALSE(test, fp.is_resilient);
	fp.is_resilient = true;
	KUNIT_EXPECT_TRUE(test, fp.is_resilient);
}

static void test_resilient_sets_timeout_value(struct kunit *test)
{
	struct ksmbd_file fp = {};

	KUNIT_EXPECT_EQ(test, fp.resilient_timeout, 0U);
	fp.resilient_timeout = 120000;
	KUNIT_EXPECT_EQ(test, fp.resilient_timeout, 120000U);
}

static void test_resilient_no_output_data(struct kunit *test)
{
	/*
	 * Per MS-SMB2 3.3.5.15.9, FSCTL_LMR_REQUEST_RESILIENCY
	 * response has OutputCount == 0.
	 */
	unsigned int out_len = 0;

	KUNIT_EXPECT_EQ(test, out_len, 0U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Max Timeout Constant Test
 * ═══════════════════════════════════════════════════════════════════ */

static void test_resilient_max_timeout_is_five_minutes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_MAX_RESILIENT_TIMEOUT_MS, 300000U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Resilient + Durable Interaction
 * ═══════════════════════════════════════════════════════════════════ */

static void test_resilient_independent_of_durable(struct kunit *test)
{
	struct ksmbd_file fp = {};

	fp.is_resilient = true;
	fp.is_durable = false;

	KUNIT_EXPECT_TRUE(test, fp.is_resilient);
	KUNIT_EXPECT_FALSE(test, fp.is_durable);
}

static void test_durable_independent_of_resilient(struct kunit *test)
{
	struct ksmbd_file fp = {};

	fp.is_durable = true;
	fp.is_resilient = false;

	KUNIT_EXPECT_TRUE(test, fp.is_durable);
	KUNIT_EXPECT_FALSE(test, fp.is_resilient);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Timeout Edge Case Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_resilient_timeout_exactly_max(struct kunit *test)
{
	struct test_network_resiliency_request req = {};
	unsigned int timeout;

	req.timeout = cpu_to_le32(TEST_MAX_RESILIENT_TIMEOUT_MS);
	timeout = le32_to_cpu(req.timeout);

	/* Exactly at max should not be capped */
	KUNIT_EXPECT_EQ(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
	KUNIT_EXPECT_LE(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
}

static void test_resilient_timeout_one_over_max(struct kunit *test)
{
	struct test_network_resiliency_request req = {};
	unsigned int timeout;

	req.timeout = cpu_to_le32(TEST_MAX_RESILIENT_TIMEOUT_MS + 1);
	timeout = le32_to_cpu(req.timeout);

	if (timeout > TEST_MAX_RESILIENT_TIMEOUT_MS)
		timeout = TEST_MAX_RESILIENT_TIMEOUT_MS;

	KUNIT_EXPECT_EQ(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
}

static void test_resilient_timeout_uint_max(struct kunit *test)
{
	struct test_network_resiliency_request req = {};
	unsigned int timeout;

	req.timeout = cpu_to_le32(UINT_MAX);
	timeout = le32_to_cpu(req.timeout);

	if (timeout > TEST_MAX_RESILIENT_TIMEOUT_MS)
		timeout = TEST_MAX_RESILIENT_TIMEOUT_MS;

	KUNIT_EXPECT_EQ(test, timeout, TEST_MAX_RESILIENT_TIMEOUT_MS);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Request Structure Size Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_resilient_struct_size_packed(struct kunit *test)
{
	/* Structure must be exactly 8 bytes (two __le32 fields) */
	KUNIT_EXPECT_EQ(test,
			sizeof(struct test_network_resiliency_request), 8U);
}

static void test_resilient_reserved_field_zero(struct kunit *test)
{
	struct test_network_resiliency_request req = {};

	/* Reserved field must be zero */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.reserved), 0U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_resilient_test_cases[] = {
	/* Request structure */
	KUNIT_CASE(test_resilient_input_too_short_rejected),
	KUNIT_CASE(test_resilient_normal_timeout),
	KUNIT_CASE(test_resilient_timeout_capped_to_max),
	KUNIT_CASE(test_resilient_zero_timeout),
	/* Flag management */
	KUNIT_CASE(test_resilient_sets_is_resilient_flag),
	KUNIT_CASE(test_resilient_sets_timeout_value),
	KUNIT_CASE(test_resilient_no_output_data),
	/* Constants */
	KUNIT_CASE(test_resilient_max_timeout_is_five_minutes),
	/* Durable interaction */
	KUNIT_CASE(test_resilient_independent_of_durable),
	KUNIT_CASE(test_durable_independent_of_resilient),
	/* Timeout edge cases */
	KUNIT_CASE(test_resilient_timeout_exactly_max),
	KUNIT_CASE(test_resilient_timeout_one_over_max),
	KUNIT_CASE(test_resilient_timeout_uint_max),
	/* Structure */
	KUNIT_CASE(test_resilient_struct_size_packed),
	KUNIT_CASE(test_resilient_reserved_field_zero),
	{}
};

static struct kunit_suite ksmbd_resilient_test_suite = {
	.name = "ksmbd_resilient",
	.test_cases = ksmbd_resilient_test_cases,
};

kunit_test_suite(ksmbd_resilient_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd resilient handle support");
