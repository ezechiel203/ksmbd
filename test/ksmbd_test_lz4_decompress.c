// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit tests for smb2_lz4_decompress() in smb2_compress.c
 *
 *   These tests call the production smb2_lz4_decompress() function
 *   directly (not through smb2_decompress_data dispatch). They
 *   compress data with the kernel LZ4 API, then decompress with the
 *   production function and verify correctness.
 */

#include <kunit/test.h>
#include <kunit/visibility.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/lz4.h>

#include "smb2_compress.h"
#include "smb2pdu.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

/*
 * test_lz4_decompress_roundtrip - compress with kernel LZ4, decompress
 * with smb2_lz4_decompress, verify match.
 */
static void test_lz4_decompress_roundtrip(struct kunit *test)
{
	unsigned char *src, *compressed, *decompressed;
	char *wrkmem;
	int compressed_size, rc;
	unsigned int src_len = 256;

	src = kunit_kzalloc(test, src_len, GFP_KERNEL);
	compressed = kunit_kzalloc(test, LZ4_compressBound(src_len), GFP_KERNEL);
	decompressed = kunit_kzalloc(test, src_len, GFP_KERNEL);
	wrkmem = kunit_kzalloc(test, LZ4_MEM_COMPRESS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, src);
	KUNIT_ASSERT_NOT_NULL(test, compressed);
	KUNIT_ASSERT_NOT_NULL(test, decompressed);
	KUNIT_ASSERT_NOT_NULL(test, wrkmem);

	/* Fill with repeating pattern for good compression */
	memset(src, 0xBB, src_len);

	compressed_size = LZ4_compress_default(src, compressed, src_len,
					       LZ4_compressBound(src_len),
					       wrkmem);
	KUNIT_ASSERT_GT(test, compressed_size, 0);

	/* Call production code to decompress */
	rc = smb2_lz4_decompress(compressed, compressed_size,
				 decompressed, src_len, src_len);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, memcmp(src, decompressed, src_len), 0);
}

/*
 * test_lz4_decompress_mixed_data - compress mixed data, decompress
 */
static void test_lz4_decompress_mixed_data(struct kunit *test)
{
	unsigned char *src, *compressed, *decompressed;
	char *wrkmem;
	int compressed_size, rc;
	unsigned int i, src_len = 512;

	src = kunit_kzalloc(test, src_len, GFP_KERNEL);
	compressed = kunit_kzalloc(test, LZ4_compressBound(src_len), GFP_KERNEL);
	decompressed = kunit_kzalloc(test, src_len, GFP_KERNEL);
	wrkmem = kunit_kzalloc(test, LZ4_MEM_COMPRESS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, src);
	KUNIT_ASSERT_NOT_NULL(test, compressed);
	KUNIT_ASSERT_NOT_NULL(test, decompressed);
	KUNIT_ASSERT_NOT_NULL(test, wrkmem);

	/* Mixed: repeating 4-byte pattern */
	for (i = 0; i < src_len; i++)
		src[i] = (unsigned char)(i % 4);

	compressed_size = LZ4_compress_default(src, compressed, src_len,
					       LZ4_compressBound(src_len),
					       wrkmem);
	KUNIT_ASSERT_GT(test, compressed_size, 0);

	rc = smb2_lz4_decompress(compressed, compressed_size,
				 decompressed, src_len, src_len);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, memcmp(src, decompressed, src_len), 0);
}

/*
 * test_lz4_decompress_large - 4K buffer round-trip
 */
static void test_lz4_decompress_large(struct kunit *test)
{
	unsigned char *src, *compressed, *decompressed;
	char *wrkmem;
	int compressed_size, rc;
	unsigned int i, src_len = 4096;

	src = kunit_kzalloc(test, src_len, GFP_KERNEL);
	compressed = kunit_kzalloc(test, LZ4_compressBound(src_len), GFP_KERNEL);
	decompressed = kunit_kzalloc(test, src_len, GFP_KERNEL);
	wrkmem = kunit_kzalloc(test, LZ4_MEM_COMPRESS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, src);
	KUNIT_ASSERT_NOT_NULL(test, compressed);
	KUNIT_ASSERT_NOT_NULL(test, decompressed);
	KUNIT_ASSERT_NOT_NULL(test, wrkmem);

	/* Repeating 8-byte pattern */
	for (i = 0; i < src_len; i++)
		src[i] = (unsigned char)(i % 8);

	compressed_size = LZ4_compress_default(src, compressed, src_len,
					       LZ4_compressBound(src_len),
					       wrkmem);
	KUNIT_ASSERT_GT(test, compressed_size, 0);

	rc = smb2_lz4_decompress(compressed, compressed_size,
				 decompressed, src_len, src_len);
	KUNIT_ASSERT_EQ(test, rc, 0);
	KUNIT_EXPECT_EQ(test, memcmp(src, decompressed, src_len), 0);
}

/*
 * test_lz4_decompress_size_mismatch - wrong original_size fails
 */
static void test_lz4_decompress_size_mismatch(struct kunit *test)
{
	unsigned char *src, *compressed, *decompressed;
	char *wrkmem;
	int compressed_size, rc;
	unsigned int src_len = 128;

	src = kunit_kzalloc(test, src_len, GFP_KERNEL);
	compressed = kunit_kzalloc(test, LZ4_compressBound(src_len), GFP_KERNEL);
	decompressed = kunit_kzalloc(test, src_len * 2, GFP_KERNEL);
	wrkmem = kunit_kzalloc(test, LZ4_MEM_COMPRESS, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, src);
	KUNIT_ASSERT_NOT_NULL(test, compressed);
	KUNIT_ASSERT_NOT_NULL(test, decompressed);
	KUNIT_ASSERT_NOT_NULL(test, wrkmem);

	memset(src, 0xCC, src_len);

	compressed_size = LZ4_compress_default(src, compressed, src_len,
					       LZ4_compressBound(src_len),
					       wrkmem);
	KUNIT_ASSERT_GT(test, compressed_size, 0);

	/* Pass wrong original_size (64 instead of 128) */
	rc = smb2_lz4_decompress(compressed, compressed_size,
				 decompressed, src_len * 2, 64);
	KUNIT_EXPECT_NE(test, rc, 0);
}

/*
 * test_lz4_decompress_dst_too_small - dst_len < original_size -> -ENOSPC
 */
static void test_lz4_decompress_dst_too_small(struct kunit *test)
{
	unsigned char compressed[16] = { 0 };
	unsigned char decompressed[32];
	int rc;

	/* original_size > dst_len should return -ENOSPC immediately */
	rc = smb2_lz4_decompress(compressed, sizeof(compressed),
				 decompressed, 32, 64);
	KUNIT_EXPECT_EQ(test, rc, -ENOSPC);
}

/*
 * test_lz4_decompress_corrupted - corrupted LZ4 data fails gracefully
 */
static void test_lz4_decompress_corrupted(struct kunit *test)
{
	unsigned char garbage[32];
	unsigned char decompressed[256];
	int rc;

	memset(garbage, 0xFF, sizeof(garbage));

	rc = smb2_lz4_decompress(garbage, sizeof(garbage),
				 decompressed, sizeof(decompressed),
				 sizeof(decompressed));
	/* LZ4_decompress_safe should fail on garbage data */
	KUNIT_EXPECT_NE(test, rc, 0);
}

static struct kunit_case ksmbd_lz4_decompress_test_cases[] = {
	KUNIT_CASE(test_lz4_decompress_roundtrip),
	KUNIT_CASE(test_lz4_decompress_mixed_data),
	KUNIT_CASE(test_lz4_decompress_large),
	KUNIT_CASE(test_lz4_decompress_size_mismatch),
	KUNIT_CASE(test_lz4_decompress_dst_too_small),
	KUNIT_CASE(test_lz4_decompress_corrupted),
	{}
};

static struct kunit_suite ksmbd_lz4_decompress_test_suite = {
	.name = "ksmbd_lz4_decompress",
	.test_cases = ksmbd_lz4_decompress_test_cases,
};

kunit_test_suite(ksmbd_lz4_decompress_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd smb2_lz4_decompress()");
