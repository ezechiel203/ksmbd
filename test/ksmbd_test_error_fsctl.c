// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit error-path tests for FSCTL subsystem (ksmbd_fsctl.c).
 *
 *   These tests exercise the exported helper functions with crafted
 *   inputs to validate error handling, boundary checks, and pure-logic
 *   paths that do not require VFS or network state.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/jhash.h>
#include <linux/errno.h>

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

#include "ksmbd_fsctl.h"
#include "smb2pdu.h"

/* ================================================================
 * odx_nonce_hash tests
 *
 * odx_nonce_hash() is a pure function: jhash(nonce, 16, 0).
 * We verify determinism, sensitivity to input changes, and
 * expected collision resistance properties.
 * ================================================================ */

/*
 * test_odx_hash_all_zeros - all-zero nonce produces a valid hash
 */
static void test_odx_hash_all_zeros(struct kunit *test)
{
	u8 nonce[16] = {};
	u32 h;

	h = odx_nonce_hash(nonce);
	/* Verify it matches direct jhash call */
	KUNIT_EXPECT_EQ(test, h, jhash(nonce, 16, 0));
}

/*
 * test_odx_hash_all_ones - all-0xFF nonce
 */
static void test_odx_hash_all_ones(struct kunit *test)
{
	u8 nonce[16];
	u32 h;

	memset(nonce, 0xFF, 16);
	h = odx_nonce_hash(nonce);
	KUNIT_EXPECT_EQ(test, h, jhash(nonce, 16, 0));
}

/*
 * test_odx_hash_deterministic - same input always yields same hash
 */
static void test_odx_hash_deterministic(struct kunit *test)
{
	u8 nonce[16];
	u32 h1, h2;

	memset(nonce, 0xAB, 16);
	h1 = odx_nonce_hash(nonce);
	h2 = odx_nonce_hash(nonce);
	KUNIT_EXPECT_EQ(test, h1, h2);
}

/*
 * test_odx_hash_first_byte_varies - changing first byte changes hash
 */
static void test_odx_hash_first_byte_varies(struct kunit *test)
{
	u8 nonce_a[16] = {};
	u8 nonce_b[16] = {};

	nonce_b[0] = 1;
	KUNIT_EXPECT_NE(test, odx_nonce_hash(nonce_a),
			odx_nonce_hash(nonce_b));
}

/*
 * test_odx_hash_last_byte_varies - changing last byte changes hash
 *
 * Verifies that the hash function uses all 16 bytes, not just the
 * first few.  This was the bug described in P1-ODX-01.
 */
static void test_odx_hash_last_byte_varies(struct kunit *test)
{
	u8 nonce_a[16] = {};
	u8 nonce_b[16] = {};

	nonce_b[15] = 1;
	KUNIT_EXPECT_NE(test, odx_nonce_hash(nonce_a),
			odx_nonce_hash(nonce_b));
}

/*
 * test_odx_hash_middle_byte_varies - changing middle byte changes hash
 */
static void test_odx_hash_middle_byte_varies(struct kunit *test)
{
	u8 nonce_a[16] = {};
	u8 nonce_b[16] = {};

	nonce_b[8] = 0x42;
	KUNIT_EXPECT_NE(test, odx_nonce_hash(nonce_a),
			odx_nonce_hash(nonce_b));
}

/*
 * test_odx_hash_sequential - sequential nonces produce distinct hashes
 */
static void test_odx_hash_sequential(struct kunit *test)
{
	u8 nonce[16] = {};
	u32 prev, curr;
	int i;

	prev = odx_nonce_hash(nonce);
	for (i = 1; i <= 10; i++) {
		nonce[0] = (u8)i;
		curr = odx_nonce_hash(nonce);
		KUNIT_EXPECT_NE(test, prev, curr);
		prev = curr;
	}
}

/* ================================================================
 * fsctl_is_pathname_valid_handler tests
 *
 * This handler always returns 0 and sets *out_len = 0.
 * We verify this contract with various inputs.
 * ================================================================ */

/*
 * test_pathname_valid_null_work - NULL work pointer still returns 0
 */
static void test_pathname_valid_null_work(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = fsctl_is_pathname_valid_handler(NULL, 0, NULL, 0, 0, NULL,
					      &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, 0U);
}

/*
 * test_pathname_valid_max_id - maximum file ID still returns 0
 */
static void test_pathname_valid_max_id(struct kunit *test)
{
	unsigned int out_len = 42;
	int ret;

	ret = fsctl_is_pathname_valid_handler(NULL, 0xFFFFFFFFFFFFFFFFULL,
					      NULL, 0, 0, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, 0U);
}

/*
 * test_pathname_valid_with_buf - non-NULL buffer still returns 0
 */
static void test_pathname_valid_with_buf(struct kunit *test)
{
	unsigned int out_len = 99;
	char buf[] = "C:\\test\\path";
	int ret;

	ret = fsctl_is_pathname_valid_handler(NULL, 0, buf, sizeof(buf),
					      256, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, 0U);
}

/*
 * test_pathname_valid_preserves_out_len - out_len always overwritten to 0
 */
static void test_pathname_valid_preserves_out_len(struct kunit *test)
{
	unsigned int out_len = 0xFFFFFFFF;
	int ret;

	ret = fsctl_is_pathname_valid_handler(NULL, 0, NULL, 0, 0, NULL,
					      &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, 0U);
}

/* ================================================================
 * Dispatch table error paths
 * ================================================================ */

/*
 * test_dispatch_invalid_code - unregistered FSCTL returns -EOPNOTSUPP
 */
static void test_dispatch_invalid_code(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = ksmbd_dispatch_fsctl(NULL, 0xBADBADBA, 0,
				   NULL, 0, 0, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

/*
 * test_dispatch_zero_code - zero FSCTL code returns -EOPNOTSUPP
 */
static void test_dispatch_zero_code(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = ksmbd_dispatch_fsctl(NULL, 0, 0,
				   NULL, 0, 0, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

/*
 * test_dispatch_max_code - max FSCTL code returns -EOPNOTSUPP
 */
static void test_dispatch_max_code(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = ksmbd_dispatch_fsctl(NULL, 0xFFFFFFFF, 0,
				   NULL, 0, 0, NULL, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EOPNOTSUPP);
}

/*
 * test_register_unregister - register/unregister cycle does not crash
 */
static void test_register_unregister(struct kunit *test)
{
	struct ksmbd_fsctl_handler h = {
		.ctl_code = 0xFFFFF099,
		.handler = NULL,
		.owner = THIS_MODULE,
	};
	int ret;

	ret = ksmbd_register_fsctl(&h);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ksmbd_unregister_fsctl(&h);
	KUNIT_SUCCEED(test);
}

static struct kunit_case error_fsctl_cases[] = {
	KUNIT_CASE(test_odx_hash_all_zeros),
	KUNIT_CASE(test_odx_hash_all_ones),
	KUNIT_CASE(test_odx_hash_deterministic),
	KUNIT_CASE(test_odx_hash_first_byte_varies),
	KUNIT_CASE(test_odx_hash_last_byte_varies),
	KUNIT_CASE(test_odx_hash_middle_byte_varies),
	KUNIT_CASE(test_odx_hash_sequential),
	KUNIT_CASE(test_pathname_valid_null_work),
	KUNIT_CASE(test_pathname_valid_max_id),
	KUNIT_CASE(test_pathname_valid_with_buf),
	KUNIT_CASE(test_pathname_valid_preserves_out_len),
	KUNIT_CASE(test_dispatch_invalid_code),
	KUNIT_CASE(test_dispatch_zero_code),
	KUNIT_CASE(test_dispatch_max_code),
	KUNIT_CASE(test_register_unregister),
	{}
};

static struct kunit_suite error_fsctl_suite = {
	.name = "ksmbd_error_fsctl",
	.test_cases = error_fsctl_cases,
};

kunit_test_suites(&error_fsctl_suite);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error-path tests for ksmbd FSCTL subsystem");
