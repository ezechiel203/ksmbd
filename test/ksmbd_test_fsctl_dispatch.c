// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for the FSCTL dispatch table (ksmbd_fsctl.c)
 *
 *   Uses VISIBLE_IF_KUNIT-exported functions from ksmbd_fsctl.c directly,
 *   plus the real ksmbd_register_fsctl/ksmbd_dispatch_fsctl API.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/jhash.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "ksmbd_fsctl.h"
#include "smb2pdu.h"

/* --- odx_nonce_hash() tests using real production function --- */

static void test_odx_nonce_hash_deterministic(struct kunit *test)
{
	u8 nonce[16];
	u32 h1, h2;

	memset(nonce, 0xAB, 16);
	h1 = odx_nonce_hash(nonce);
	h2 = odx_nonce_hash(nonce);

	KUNIT_EXPECT_EQ(test, h1, h2);
}

static void test_odx_nonce_hash_different_inputs(struct kunit *test)
{
	u8 nonce1[16], nonce2[16];
	u32 h1, h2;

	memset(nonce1, 0xAA, 16);
	memset(nonce2, 0xBB, 16);

	h1 = odx_nonce_hash(nonce1);
	h2 = odx_nonce_hash(nonce2);

	/* Different inputs should produce different hashes (extremely likely) */
	KUNIT_EXPECT_NE(test, h1, h2);
}

static void test_odx_nonce_hash_zero(struct kunit *test)
{
	u8 nonce[16];
	u32 h;

	memset(nonce, 0, 16);
	h = odx_nonce_hash(nonce);

	/* Should produce a valid hash value (may be 0 but should not crash) */
	KUNIT_SUCCEED(test);
	(void)h;
}

static void test_odx_nonce_hash_single_bit_diff(struct kunit *test)
{
	u8 nonce1[16], nonce2[16];
	u32 h1, h2;

	memset(nonce1, 0, 16);
	memset(nonce2, 0, 16);
	nonce2[15] = 1;  /* Only last byte differs */

	h1 = odx_nonce_hash(nonce1);
	h2 = odx_nonce_hash(nonce2);

	/* Good hash function should produce different outputs for 1-bit diff */
	KUNIT_EXPECT_NE(test, h1, h2);
}

/* --- fsctl_is_pathname_valid_handler() tests --- */

static void test_pathname_valid_always_succeeds(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = fsctl_is_pathname_valid_handler(NULL, 0, NULL, 0, 0, NULL,
					      &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

/* --- Dispatch table registration tests (using real API) --- */

static int test_handler_success(struct ksmbd_work *work, u64 id,
				void *in_buf, unsigned int in_buf_len,
				unsigned int max_out_len,
				struct smb2_ioctl_rsp *rsp,
				unsigned int *out_len)
{
	*out_len = 42;
	return 0;
}

/*
 * Use a unique ctl_code unlikely to conflict with built-in handlers.
 * We use an invalid-looking code in a test-only range.
 */
#define TEST_FSCTL_CODE_A	0xFFFFF001
#define TEST_FSCTL_CODE_B	0xFFFFF002

static void test_register_dispatch_real(struct kunit *test)
{
	struct ksmbd_fsctl_handler h = {
		.ctl_code = TEST_FSCTL_CODE_A,
		.handler = test_handler_success,
		.owner = THIS_MODULE,
	};
	unsigned int out_len = 0;
	int ret;

	ret = ksmbd_register_fsctl(&h);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = ksmbd_dispatch_fsctl(NULL, TEST_FSCTL_CODE_A, 0,
				   NULL, 0, 0, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)42);

	ksmbd_unregister_fsctl(&h);
}

static void test_dispatch_unregistered_code(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = ksmbd_dispatch_fsctl(NULL, 0xDEADDEAD, 0,
				   NULL, 0, 0, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_duplicate_registration(struct kunit *test)
{
	struct ksmbd_fsctl_handler h1 = {
		.ctl_code = TEST_FSCTL_CODE_B,
		.handler = test_handler_success,
		.owner = THIS_MODULE,
	};
	struct ksmbd_fsctl_handler h2 = {
		.ctl_code = TEST_FSCTL_CODE_B,
		.handler = test_handler_success,
		.owner = THIS_MODULE,
	};
	int ret;

	ret = ksmbd_register_fsctl(&h1);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = ksmbd_register_fsctl(&h2);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);

	ksmbd_unregister_fsctl(&h1);
}

static struct kunit_case ksmbd_fsctl_dispatch_test_cases[] = {
	KUNIT_CASE(test_odx_nonce_hash_deterministic),
	KUNIT_CASE(test_odx_nonce_hash_different_inputs),
	KUNIT_CASE(test_odx_nonce_hash_zero),
	KUNIT_CASE(test_odx_nonce_hash_single_bit_diff),
	KUNIT_CASE(test_pathname_valid_always_succeeds),
	KUNIT_CASE(test_register_dispatch_real),
	KUNIT_CASE(test_dispatch_unregistered_code),
	KUNIT_CASE(test_duplicate_registration),
	{}
};

static struct kunit_suite ksmbd_fsctl_dispatch_test_suite = {
	.name = "ksmbd_fsctl_dispatch",
	.test_cases = ksmbd_fsctl_dispatch_test_cases,
};

kunit_test_suite(ksmbd_fsctl_dispatch_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FSCTL dispatch table operations");
