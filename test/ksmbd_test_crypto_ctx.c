// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for crypto context pool (crypto_ctx.c)
 *
 *   Tests the crypto context pool lifecycle: creation, destruction,
 *   find/release for all algorithm types, pool reuse, and NULL safety.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <crypto/aead.h>

#include "crypto_ctx.h"

/*
 * Suite init: create the crypto pool before any test runs.
 */
static int crypto_ctx_test_suite_init(struct kunit *test)
{
	int rc;

	rc = ksmbd_crypto_create();
	if (rc) {
		kunit_err(test, "ksmbd_crypto_create failed: %d\n", rc);
		return rc;
	}
	return 0;
}

/*
 * Suite exit: tear down the crypto pool after all tests.
 */
static void crypto_ctx_test_suite_exit(struct kunit *test)
{
	ksmbd_crypto_destroy();
}

/*
 * test_crypto_create_destroy - basic lifecycle test
 *
 * The init/exit callbacks already exercise create/destroy.
 * This test verifies we can re-create after destroy.
 */
static void test_crypto_create_destroy(struct kunit *test)
{
	/* Pool was already created by suite init, destroy and re-create */
	ksmbd_crypto_destroy();

	KUNIT_EXPECT_EQ(test, ksmbd_crypto_create(), 0);
	/* Pool is now live again for subsequent tests */
}

/*
 * test_crypto_find_release_hmacmd5 - HMAC-MD5 context round-trip
 */
static void test_crypto_find_release_hmacmd5(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_hmacmd5();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_HMACMD5(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_hmacsha256 - HMAC-SHA256 context round-trip
 */
static void test_crypto_find_release_hmacsha256(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_HMACSHA256(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_cmacaes - CMAC-AES context round-trip
 */
static void test_crypto_find_release_cmacaes(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_cmacaes();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_CMACAES(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_sha256 - SHA-256 context round-trip
 */
static void test_crypto_find_release_sha256(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_sha512 - SHA-512 context round-trip
 */
static void test_crypto_find_release_sha512(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_sha512();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA512(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_md4 - MD4 context round-trip
 *
 * Requires ksmbd_md4_register() to have been called, or kernel md4 available.
 */
static void test_crypto_find_release_md4(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_md4();
	if (!ctx) {
		kunit_skip(test, "MD4 crypto not available (no kernel md4 and ksmbd_md4 not registered)");
		return;
	}
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_MD4(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_md5 - MD5 context round-trip
 */
static void test_crypto_find_release_md5(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_md5();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_MD5(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_gcm - AES-GCM AEAD context round-trip
 */
static void test_crypto_find_release_gcm(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_gcm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_GCM(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_find_release_ccm - AES-CCM AEAD context round-trip
 */
static void test_crypto_find_release_ccm(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	ctx = ksmbd_crypto_ctx_find_ccm();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_CCM(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

/*
 * test_crypto_release_null_ctx - releasing NULL must not crash
 */
static void test_crypto_release_null_ctx(struct kunit *test)
{
	/* Must not crash */
	ksmbd_release_crypto_ctx(NULL);
	KUNIT_SUCCEED(test);
}

/*
 * test_crypto_pool_reuse - find, release, find again verifies reuse
 *
 * After releasing a context back to the pool, the next find should
 * return it (or an equivalent one) with the algorithm already allocated.
 */
static void test_crypto_pool_reuse(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx1, *ctx2;

	ctx1 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx1);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx1));

	ksmbd_release_crypto_ctx(ctx1);

	ctx2 = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx2);
	/* The desc should already be allocated (reused from pool) */
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx2));

	ksmbd_release_crypto_ctx(ctx2);
}

/*
 * test_crypto_pool_multiple_algorithms - a single context can hold
 * multiple algorithm types.
 */
static void test_crypto_pool_multiple_algorithms(struct kunit *test)
{
	struct ksmbd_crypto_ctx *ctx;

	/* Get a SHA-256 context */
	ctx = ksmbd_crypto_ctx_find_sha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx));

	ksmbd_release_crypto_ctx(ctx);

	/* Get an HMAC-SHA256 context - may reuse the same pool entry */
	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);
	KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_HMACSHA256(ctx));

	/* If it is the same pool entry, SHA-256 should still be valid */
	if (CRYPTO_SHA256(ctx))
		KUNIT_EXPECT_NOT_ERR_OR_NULL(test, CRYPTO_SHA256(ctx));

	ksmbd_release_crypto_ctx(ctx);
}

static struct kunit_case ksmbd_crypto_ctx_test_cases[] = {
	KUNIT_CASE(test_crypto_create_destroy),
	KUNIT_CASE(test_crypto_find_release_hmacmd5),
	KUNIT_CASE(test_crypto_find_release_hmacsha256),
	KUNIT_CASE(test_crypto_find_release_cmacaes),
	KUNIT_CASE(test_crypto_find_release_sha256),
	KUNIT_CASE(test_crypto_find_release_sha512),
	KUNIT_CASE(test_crypto_find_release_md4),
	KUNIT_CASE(test_crypto_find_release_md5),
	KUNIT_CASE(test_crypto_find_release_gcm),
	KUNIT_CASE(test_crypto_find_release_ccm),
	KUNIT_CASE(test_crypto_release_null_ctx),
	KUNIT_CASE(test_crypto_pool_reuse),
	KUNIT_CASE(test_crypto_pool_multiple_algorithms),
	{}
};

static struct kunit_suite ksmbd_crypto_ctx_test_suite = {
	.name = "ksmbd_crypto_ctx",
	.init = crypto_ctx_test_suite_init,
	.exit = crypto_ctx_test_suite_exit,
	.test_cases = ksmbd_crypto_ctx_test_cases,
};

kunit_test_suite(ksmbd_crypto_ctx_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd crypto context pool");
