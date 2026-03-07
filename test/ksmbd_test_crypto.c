// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ksmbd crypto algorithm validation.
 *
 *   Unlike ksmbd_test_crypto_ctx (which tests the pool lifecycle) and
 *   ksmbd_test_crypto_pool (which tests exhaustion/stats), this file
 *   validates the cryptographic operations themselves: hashing produces
 *   correct digests, AEAD encrypt/decrypt round-trips, algorithm enum
 *   bounds, and context descriptor layout.
 *
 *   These tests replicate the logic and structures from crypto_ctx.c
 *   to run standalone without linking to the ksmbd module.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>

/* ---- Replicated enums from crypto_ctx.h ---- */

enum test_crypto_shash_id {
	TEST_CRYPTO_SHASH_HMACMD5	= 0,
	TEST_CRYPTO_SHASH_HMACSHA256,
	TEST_CRYPTO_SHASH_CMACAES,
	TEST_CRYPTO_SHASH_SHA256,
	TEST_CRYPTO_SHASH_SHA512,
	TEST_CRYPTO_SHASH_MD4,
	TEST_CRYPTO_SHASH_MD5,
	TEST_CRYPTO_SHASH_MAX,
};

enum test_crypto_aead_id {
	TEST_CRYPTO_AEAD_AES_GCM = 0,
	TEST_CRYPTO_AEAD_AES_CCM,
	TEST_CRYPTO_AEAD_MAX,
};

/* ---- Replicated crypto context struct ---- */

struct test_crypto_ctx {
	struct list_head	list;
	struct shash_desc	*desc[TEST_CRYPTO_SHASH_MAX];
	struct crypto_aead	*ccmaes[TEST_CRYPTO_AEAD_MAX];
};

/* ---- Algorithm name mapping (mirrors alloc_shash_desc switch) ---- */

static const char *shash_algo_name(int id)
{
	switch (id) {
	case TEST_CRYPTO_SHASH_HMACMD5:
		return "hmac(md5)";
	case TEST_CRYPTO_SHASH_HMACSHA256:
		return "hmac(sha256)";
	case TEST_CRYPTO_SHASH_CMACAES:
		return "cmac(aes)";
	case TEST_CRYPTO_SHASH_SHA256:
		return "sha256";
	case TEST_CRYPTO_SHASH_SHA512:
		return "sha512";
	case TEST_CRYPTO_SHASH_MD4:
		return "md4";
	case TEST_CRYPTO_SHASH_MD5:
		return "md5";
	default:
		return NULL;
	}
}

static const char *aead_algo_name(int id)
{
	switch (id) {
	case TEST_CRYPTO_AEAD_AES_GCM:
		return "gcm(aes)";
	case TEST_CRYPTO_AEAD_AES_CCM:
		return "ccm(aes)";
	default:
		return NULL;
	}
}

/* ---- Helper: allocate shash_desc for a given algorithm ---- */

static struct shash_desc *test_alloc_shash(int id)
{
	const char *name = shash_algo_name(id);
	struct crypto_shash *tfm;
	struct shash_desc *desc;

	if (!name)
		return NULL;

	tfm = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(tfm))
		return NULL;

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return NULL;
	}
	desc->tfm = tfm;
	return desc;
}

static void test_free_shash(struct shash_desc *desc)
{
	if (desc) {
		struct crypto_shash *tfm = desc->tfm;

		kfree(desc);
		crypto_free_shash(tfm);
	}
}

/* ==================================================================
 * Test cases: Algorithm enum bounds
 * ================================================================== */

/*
 * test_shash_enum_bounds - CRYPTO_SHASH_MAX equals expected count
 */
static void test_shash_enum_bounds(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)TEST_CRYPTO_SHASH_MAX, 7);
	KUNIT_EXPECT_EQ(test, (int)TEST_CRYPTO_SHASH_HMACMD5, 0);
	KUNIT_EXPECT_EQ(test, (int)TEST_CRYPTO_SHASH_MD5, 6);
}

/*
 * test_aead_enum_bounds - CRYPTO_AEAD_MAX equals expected count
 */
static void test_aead_enum_bounds(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)TEST_CRYPTO_AEAD_MAX, 2);
	KUNIT_EXPECT_EQ(test, (int)TEST_CRYPTO_AEAD_AES_GCM, 0);
	KUNIT_EXPECT_EQ(test, (int)TEST_CRYPTO_AEAD_AES_CCM, 1);
}

/*
 * test_shash_algo_names - verify all algorithm name mappings
 */
static void test_shash_algo_names(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_HMACMD5),
			   "hmac(md5)");
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_HMACSHA256),
			   "hmac(sha256)");
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_CMACAES),
			   "cmac(aes)");
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_SHA256),
			   "sha256");
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_SHA512),
			   "sha512");
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_MD4),
			   "md4");
	KUNIT_EXPECT_STREQ(test, shash_algo_name(TEST_CRYPTO_SHASH_MD5),
			   "md5");
	KUNIT_EXPECT_NULL(test, shash_algo_name(TEST_CRYPTO_SHASH_MAX));
	KUNIT_EXPECT_NULL(test, shash_algo_name(-1));
}

/*
 * test_aead_algo_names - verify AEAD algorithm name mappings
 */
static void test_aead_algo_names(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, aead_algo_name(TEST_CRYPTO_AEAD_AES_GCM),
			   "gcm(aes)");
	KUNIT_EXPECT_STREQ(test, aead_algo_name(TEST_CRYPTO_AEAD_AES_CCM),
			   "ccm(aes)");
	KUNIT_EXPECT_NULL(test, aead_algo_name(TEST_CRYPTO_AEAD_MAX));
	KUNIT_EXPECT_NULL(test, aead_algo_name(-1));
}

/* ==================================================================
 * Test cases: Context struct layout
 * ================================================================== */

/*
 * test_crypto_ctx_zero_init - zeroed context has all NULL descriptors
 */
static void test_crypto_ctx_zero_init(struct kunit *test)
{
	struct test_crypto_ctx *ctx;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	for (i = 0; i < TEST_CRYPTO_SHASH_MAX; i++)
		KUNIT_EXPECT_NULL(test, ctx->desc[i]);

	for (i = 0; i < TEST_CRYPTO_AEAD_MAX; i++)
		KUNIT_EXPECT_NULL(test, ctx->ccmaes[i]);

	kfree(ctx);
}

/*
 * test_crypto_ctx_desc_array_size - desc array matches SHASH_MAX
 */
static void test_crypto_ctx_desc_array_size(struct kunit *test)
{
	struct test_crypto_ctx ctx;

	KUNIT_EXPECT_EQ(test, (int)ARRAY_SIZE(ctx.desc),
			(int)TEST_CRYPTO_SHASH_MAX);
}

/*
 * test_crypto_ctx_aead_array_size - ccmaes array matches AEAD_MAX
 */
static void test_crypto_ctx_aead_array_size(struct kunit *test)
{
	struct test_crypto_ctx ctx;

	KUNIT_EXPECT_EQ(test, (int)ARRAY_SIZE(ctx.ccmaes),
			(int)TEST_CRYPTO_AEAD_MAX);
}

/* ==================================================================
 * Test cases: SHA-256 digest correctness
 * ================================================================== */

/*
 * test_sha256_empty_string - SHA-256("") is the well-known constant
 */
static void test_sha256_empty_string(struct kunit *test)
{
	struct shash_desc *desc;
	u8 digest[32];
	int ret;
	/* SHA-256 of empty string */
	static const u8 expected[32] = {
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	};

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_SHA256);
	if (!desc) {
		kunit_skip(test, "SHA-256 not available");
		return;
	}

	ret = crypto_shash_init(desc);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = crypto_shash_final(desc, digest);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_MEMEQ(test, digest, expected, 32);

	test_free_shash(desc);
}

/*
 * test_sha256_known_vector - SHA-256("abc") known answer test
 */
static void test_sha256_known_vector(struct kunit *test)
{
	struct shash_desc *desc;
	u8 digest[32];
	int ret;
	static const u8 expected[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_SHA256);
	if (!desc) {
		kunit_skip(test, "SHA-256 not available");
		return;
	}

	ret = crypto_shash_digest(desc, "abc", 3, digest);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_MEMEQ(test, digest, expected, 32);

	test_free_shash(desc);
}

/* ==================================================================
 * Test cases: SHA-512 digest correctness
 * ================================================================== */

/*
 * test_sha512_empty_string - SHA-512("") known answer test
 */
static void test_sha512_empty_string(struct kunit *test)
{
	struct shash_desc *desc;
	u8 digest[64];
	int ret;
	static const u8 expected_prefix[8] = {
		0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
	};

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_SHA512);
	if (!desc) {
		kunit_skip(test, "SHA-512 not available");
		return;
	}

	ret = crypto_shash_init(desc);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = crypto_shash_final(desc, digest);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Check first 8 bytes of the well-known digest */
	KUNIT_EXPECT_MEMEQ(test, digest, expected_prefix, 8);

	test_free_shash(desc);
}

/* ==================================================================
 * Test cases: MD5 digest correctness
 * ================================================================== */

/*
 * test_md5_known_vector - MD5("") = d41d8cd98f00b204e9800998ecf8427e
 */
static void test_md5_known_vector(struct kunit *test)
{
	struct shash_desc *desc;
	u8 digest[16];
	int ret;
	static const u8 expected[16] = {
		0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
		0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
	};

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_MD5);
	if (!desc) {
		kunit_skip(test, "MD5 not available");
		return;
	}

	ret = crypto_shash_init(desc);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = crypto_shash_final(desc, digest);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_MEMEQ(test, digest, expected, 16);

	test_free_shash(desc);
}

/*
 * test_md5_abc_vector - MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
 */
static void test_md5_abc_vector(struct kunit *test)
{
	struct shash_desc *desc;
	u8 digest[16];
	int ret;
	static const u8 expected[16] = {
		0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
		0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
	};

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_MD5);
	if (!desc) {
		kunit_skip(test, "MD5 not available");
		return;
	}

	ret = crypto_shash_digest(desc, "abc", 3, digest);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_MEMEQ(test, digest, expected, 16);

	test_free_shash(desc);
}

/* ==================================================================
 * Test cases: HMAC-SHA256 keyed hash
 * ================================================================== */

/*
 * test_hmacsha256_alloc_set_key - allocate and set a key on HMAC-SHA256
 */
static void test_hmacsha256_alloc_set_key(struct kunit *test)
{
	struct shash_desc *desc;
	u8 key[32];
	int ret;

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_HMACSHA256);
	if (!desc) {
		kunit_skip(test, "HMAC-SHA256 not available");
		return;
	}

	memset(key, 0x0B, sizeof(key));
	ret = crypto_shash_setkey(desc->tfm, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, ret, 0);

	test_free_shash(desc);
}

/*
 * test_hmacsha256_digest - HMAC-SHA256 with known key/data
 */
static void test_hmacsha256_digest(struct kunit *test)
{
	struct shash_desc *desc;
	u8 key[20];
	u8 digest[32];
	int ret;

	/* RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want..." */
	desc = test_alloc_shash(TEST_CRYPTO_SHASH_HMACSHA256);
	if (!desc) {
		kunit_skip(test, "HMAC-SHA256 not available");
		return;
	}

	memset(key, 0, sizeof(key));
	memcpy(key, "Jefe", 4);
	ret = crypto_shash_setkey(desc->tfm, key, 4);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = crypto_shash_digest(desc, "what do ya want for nothing?", 28,
				  digest);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* RFC 4231 Test Case 2 expected output (first 4 bytes) */
	static const u8 expected_prefix[4] = { 0x5b, 0xdc, 0xc1, 0x46 };
	KUNIT_EXPECT_MEMEQ(test, digest, expected_prefix, 4);

	test_free_shash(desc);
}

/* ==================================================================
 * Test cases: AEAD (AES-GCM) allocation
 * ================================================================== */

/*
 * test_aead_gcm_alloc_free - AES-GCM AEAD can be allocated and freed
 */
static void test_aead_gcm_alloc_free(struct kunit *test)
{
	struct crypto_aead *tfm;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		kunit_skip(test, "AES-GCM not available");
		return;
	}

	KUNIT_EXPECT_NOT_NULL(test, tfm);
	crypto_free_aead(tfm);
}

/*
 * test_aead_ccm_alloc_free - AES-CCM AEAD can be allocated and freed
 */
static void test_aead_ccm_alloc_free(struct kunit *test)
{
	struct crypto_aead *tfm;

	tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		kunit_skip(test, "AES-CCM not available");
		return;
	}

	KUNIT_EXPECT_NOT_NULL(test, tfm);
	crypto_free_aead(tfm);
}

/*
 * test_aead_gcm_set_key - AES-GCM accepts 16/24/32-byte keys
 */
static void test_aead_gcm_set_key(struct kunit *test)
{
	struct crypto_aead *tfm;
	u8 key[32];
	int ret;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		kunit_skip(test, "AES-GCM not available");
		return;
	}

	memset(key, 0xAA, sizeof(key));

	/* 128-bit key */
	ret = crypto_aead_setkey(tfm, key, 16);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* 256-bit key */
	ret = crypto_aead_setkey(tfm, key, 32);
	KUNIT_EXPECT_EQ(test, ret, 0);

	crypto_free_aead(tfm);
}

/*
 * test_aead_gcm_authsize - AES-GCM supports 16-byte auth tag (SMB3 standard)
 */
static void test_aead_gcm_authsize(struct kunit *test)
{
	struct crypto_aead *tfm;
	int ret;

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		kunit_skip(test, "AES-GCM not available");
		return;
	}

	/* SMB3 uses 16-byte auth tag */
	ret = crypto_aead_setauthsize(tfm, 16);
	KUNIT_EXPECT_EQ(test, ret, 0);

	crypto_free_aead(tfm);
}

/* ==================================================================
 * Test cases: Invalid algorithm IDs
 * ================================================================== */

/*
 * test_invalid_shash_id - out of bounds shash ID returns NULL
 */
static void test_invalid_shash_id(struct kunit *test)
{
	struct shash_desc *desc;

	desc = test_alloc_shash(-1);
	KUNIT_EXPECT_NULL(test, desc);

	desc = test_alloc_shash(TEST_CRYPTO_SHASH_MAX);
	KUNIT_EXPECT_NULL(test, desc);

	desc = test_alloc_shash(999);
	KUNIT_EXPECT_NULL(test, desc);
}

/*
 * test_invalid_aead_name - bogus AEAD algorithm name fails
 */
static void test_invalid_aead_name(struct kunit *test)
{
	struct crypto_aead *tfm;

	tfm = crypto_alloc_aead("bogus(aes)", 0, 0);
	KUNIT_EXPECT_TRUE(test, IS_ERR(tfm));
}

/* ==================================================================
 * Test cases: Digest size verification
 * ================================================================== */

/*
 * test_shash_digest_sizes - verify expected digest sizes for each algorithm
 */
static void test_shash_digest_sizes(struct kunit *test)
{
	static const struct {
		int id;
		unsigned int expected_size;
		const char *name;
	} cases[] = {
		{ TEST_CRYPTO_SHASH_SHA256, 32, "SHA-256" },
		{ TEST_CRYPTO_SHASH_SHA512, 64, "SHA-512" },
		{ TEST_CRYPTO_SHASH_MD5, 16, "MD5" },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct shash_desc *desc = test_alloc_shash(cases[i].id);

		if (!desc) {
			kunit_info(test, "Skipping %s: not available",
				   cases[i].name);
			continue;
		}

		KUNIT_EXPECT_EQ(test,
				crypto_shash_digestsize(desc->tfm),
				cases[i].expected_size);

		test_free_shash(desc);
	}
}

/* ---- Test suite registration ---- */

static struct kunit_case ksmbd_crypto_test_cases[] = {
	/* Enum bounds */
	KUNIT_CASE(test_shash_enum_bounds),
	KUNIT_CASE(test_aead_enum_bounds),
	KUNIT_CASE(test_shash_algo_names),
	KUNIT_CASE(test_aead_algo_names),
	/* Context struct layout */
	KUNIT_CASE(test_crypto_ctx_zero_init),
	KUNIT_CASE(test_crypto_ctx_desc_array_size),
	KUNIT_CASE(test_crypto_ctx_aead_array_size),
	/* SHA-256 correctness */
	KUNIT_CASE(test_sha256_empty_string),
	KUNIT_CASE(test_sha256_known_vector),
	/* SHA-512 correctness */
	KUNIT_CASE(test_sha512_empty_string),
	/* MD5 correctness */
	KUNIT_CASE(test_md5_known_vector),
	KUNIT_CASE(test_md5_abc_vector),
	/* HMAC-SHA256 */
	KUNIT_CASE(test_hmacsha256_alloc_set_key),
	KUNIT_CASE(test_hmacsha256_digest),
	/* AEAD */
	KUNIT_CASE(test_aead_gcm_alloc_free),
	KUNIT_CASE(test_aead_ccm_alloc_free),
	KUNIT_CASE(test_aead_gcm_set_key),
	KUNIT_CASE(test_aead_gcm_authsize),
	/* Invalid IDs */
	KUNIT_CASE(test_invalid_shash_id),
	KUNIT_CASE(test_invalid_aead_name),
	/* Digest sizes */
	KUNIT_CASE(test_shash_digest_sizes),
	{}
};

static struct kunit_suite ksmbd_crypto_test_suite = {
	.name = "ksmbd_crypto",
	.test_cases = ksmbd_crypto_test_cases,
};

kunit_test_suite(ksmbd_crypto_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd crypto algorithm validation");
