// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit micro-benchmark tests for ksmbd compression algorithms.
 *
 *   Measures throughput of LZNT1, LZ77, and LZ77+Huffman compression
 *   and decompression operations, plus compression ratio comparisons.
 *   All compression calls go through real production exports:
 *     smb2_compress_data(), smb2_decompress_data(),
 *     smb2_pattern_v1_compress(), smb2_pattern_v1_decompress().
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/kernel.h>

/* Production compression API */
#include "smb2_compress.h"
#include "smb2pdu.h"

/* ========================================================================
 * Configurable iteration counts
 * ======================================================================== */

#define COMP_ITERS		5000
#define COMP_ITERS_LIGHT	10000

/* ========================================================================
 * Benchmark reporting macros
 * ======================================================================== */

#define BENCH_REPORT_THROUGHPUT(test, name, iters, total_ns, bytes)	\
	do {								\
		u64 __mbps = 0;						\
		if ((total_ns) > 0)					\
			__mbps = ((u64)(bytes) * (u64)(iters) * 1000ULL) / \
				 (total_ns);				\
		kunit_info(test,					\
			   "BENCHMARK: %s iters=%u total_ns=%llu "	\
			   "per_iter_ns=%llu throughput_MBps=%llu\n",	\
			   (name), (unsigned int)(iters),		\
			   (unsigned long long)(total_ns),		\
			   (unsigned long long)((total_ns) / (iters)),	\
			   (unsigned long long)__mbps);			\
	} while (0)

#define BENCH_REPORT(test, name, iters, total_ns, extra)		\
	kunit_info(test,						\
		   "BENCHMARK: %s iters=%u total_ns=%llu "		\
		   "per_iter_ns=%llu %s\n",				\
		   (name), (unsigned int)(iters),			\
		   (unsigned long long)(total_ns),			\
		   (unsigned long long)((total_ns) / (iters)),		\
		   (extra))

/* ========================================================================
 * Test data generators
 * ======================================================================== */

/* Generate compressible data (repeating patterns) */
static void generate_compressible(u8 *buf, unsigned int size)
{
	unsigned int i;
	/* Repeating 16-byte pattern gives ~16:1 match opportunity */
	u8 pattern[16];

	get_random_bytes(pattern, sizeof(pattern));
	for (i = 0; i < size; i++)
		buf[i] = pattern[i % 16];
}

/* Generate uniform data (all same byte) */
static void generate_uniform(u8 *buf, unsigned int size)
{
	memset(buf, 0xAA, size);
}

/* ========================================================================
 * Benchmark 1: LZNT1 compress throughput -- 4K/64K
 * ======================================================================== */

static void bench_lznt1_compress(struct kunit *test, unsigned int size,
				 const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size;
	int comp_len, ret;
	u64 start, elapsed;
	int i;

	comp_buf_size = size + size / 2 + 256;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	generate_compressible(src, size);

	/* Verify correctness */
	comp_len = smb2_compress_data(SMB3_COMPRESS_LZNT1, src, size,
				      compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	ret = smb2_decompress_data(SMB3_COMPRESS_LZNT1, compressed, comp_len,
				   decompressed, size, size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	kunit_info(test,
		   "BENCHMARK: %s_ratio orig=%u compressed=%d ratio=%.1u%%\n",
		   label, size, comp_len,
		   (unsigned int)((u64)comp_len * 100 / size));

	/* Benchmark compress */
	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++)
		smb2_compress_data(SMB3_COMPRESS_LZNT1, src, size,
				   compressed, comp_buf_size);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, COMP_ITERS, elapsed, size);

	vfree(decompressed);
	vfree(compressed);
	vfree(src);
}

static void test_perf_lznt1_compress_4k(struct kunit *test)
{
	bench_lznt1_compress(test, 4096, "lznt1_compress_4K");
}

static void test_perf_lznt1_compress_64k(struct kunit *test)
{
	bench_lznt1_compress(test, 65536, "lznt1_compress_64K");
}

/* ========================================================================
 * Benchmark 2: LZNT1 decompress throughput
 * ======================================================================== */

static void bench_lznt1_decompress(struct kunit *test, unsigned int size,
				   const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size;
	int comp_len;
	u64 start, elapsed;
	int i;

	comp_buf_size = size + size / 2 + 256;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	generate_compressible(src, size);

	comp_len = smb2_compress_data(SMB3_COMPRESS_LZNT1, src, size,
				      compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);

	/* Benchmark decompress */
	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++)
		smb2_decompress_data(SMB3_COMPRESS_LZNT1, compressed,
				     comp_len, decompressed, size, size);
	elapsed = ktime_get_ns() - start;

	/* Verify last iteration */
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	BENCH_REPORT_THROUGHPUT(test, label, COMP_ITERS, elapsed, size);

	vfree(decompressed);
	vfree(compressed);
	vfree(src);
}

static void test_perf_lznt1_decompress_4k(struct kunit *test)
{
	bench_lznt1_decompress(test, 4096, "lznt1_decompress_4K");
}

static void test_perf_lznt1_decompress_64k(struct kunit *test)
{
	bench_lznt1_decompress(test, 65536, "lznt1_decompress_64K");
}

/* ========================================================================
 * Benchmark 3: LZ77 compress throughput
 * ======================================================================== */

static void bench_lz77_compress(struct kunit *test, unsigned int size,
				const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size;
	int comp_len, ret;
	u64 start, elapsed;
	int i;

	comp_buf_size = size + (size / 32 + 1) * 4 + 64;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);

	/* Verify */
	comp_len = smb2_compress_data(SMB3_COMPRESS_LZ77, src, size,
				      compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	ret = smb2_decompress_data(SMB3_COMPRESS_LZ77, compressed, comp_len,
				   decompressed, size, size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++)
		smb2_compress_data(SMB3_COMPRESS_LZ77, src, size,
				   compressed, comp_buf_size);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, COMP_ITERS, elapsed, size);

	vfree(decompressed);
	vfree(compressed);
	vfree(src);
}

static void test_perf_lz77_compress_4k(struct kunit *test)
{
	bench_lz77_compress(test, 4096, "lz77_compress_4K");
}

static void test_perf_lz77_compress_64k(struct kunit *test)
{
	bench_lz77_compress(test, 65536, "lz77_compress_64K");
}

/* ========================================================================
 * Benchmark 4: LZ77 decompress throughput
 * ======================================================================== */

static void bench_lz77_decompress(struct kunit *test, unsigned int size,
				  const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size;
	int comp_len;
	u64 start, elapsed;
	int i;

	comp_buf_size = size + (size / 32 + 1) * 4 + 64;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);
	comp_len = smb2_compress_data(SMB3_COMPRESS_LZ77, src, size,
				      compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++)
		smb2_decompress_data(SMB3_COMPRESS_LZ77, compressed,
				     comp_len, decompressed, size, size);
	elapsed = ktime_get_ns() - start;

	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	BENCH_REPORT_THROUGHPUT(test, label, COMP_ITERS, elapsed, size);

	vfree(decompressed);
	vfree(compressed);
	vfree(src);
}

static void test_perf_lz77_decompress_4k(struct kunit *test)
{
	bench_lz77_decompress(test, 4096, "lz77_decompress_4K");
}

static void test_perf_lz77_decompress_64k(struct kunit *test)
{
	bench_lz77_decompress(test, 65536, "lz77_decompress_64K");
}

/* ========================================================================
 * Benchmark 5: LZ77+Huffman compress throughput
 * ======================================================================== */

static void bench_lz77huff_compress(struct kunit *test, unsigned int size,
				    const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size = size * 2 + 512;
	int comp_len, ret;
	u64 start, elapsed;
	int i;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);

	comp_len = smb2_compress_data(SMB3_COMPRESS_LZ77_HUFF, src, size,
				      compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	ret = smb2_decompress_data(SMB3_COMPRESS_LZ77_HUFF, compressed,
				   comp_len, decompressed, size, size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++)
		smb2_compress_data(SMB3_COMPRESS_LZ77_HUFF, src, size,
				   compressed, comp_buf_size);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, COMP_ITERS, elapsed, size);

	vfree(decompressed);
	vfree(compressed);
	vfree(src);
}

static void test_perf_lz77huff_compress_4k(struct kunit *test)
{
	bench_lz77huff_compress(test, 4096, "lz77huff_compress_4K");
}

static void test_perf_lz77huff_compress_64k(struct kunit *test)
{
	bench_lz77huff_compress(test, 65536, "lz77huff_compress_64K");
}

/* ========================================================================
 * Benchmark 6: LZ77+Huffman decompress throughput
 * ======================================================================== */

static void bench_lz77huff_decompress(struct kunit *test, unsigned int size,
				      const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size = size * 2 + 512;
	int comp_len;
	u64 start, elapsed;
	int i;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);
	comp_len = smb2_compress_data(SMB3_COMPRESS_LZ77_HUFF, src, size,
				      compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);

	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++)
		smb2_decompress_data(SMB3_COMPRESS_LZ77_HUFF, compressed,
				     comp_len, decompressed, size, size);
	elapsed = ktime_get_ns() - start;

	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	BENCH_REPORT_THROUGHPUT(test, label, COMP_ITERS, elapsed, size);

	vfree(decompressed);
	vfree(compressed);
	vfree(src);
}

static void test_perf_lz77huff_decompress_4k(struct kunit *test)
{
	bench_lz77huff_decompress(test, 4096, "lz77huff_decompress_4K");
}

static void test_perf_lz77huff_decompress_64k(struct kunit *test)
{
	bench_lz77huff_decompress(test, 65536, "lz77huff_decompress_64K");
}

/* ========================================================================
 * Benchmark 7: Pattern_V1 compress throughput (uniform data)
 * ======================================================================== */

/*
 * Pattern_V1 compressed payload is 8 bytes (struct pattern_v1_payload
 * in smb2_compress.c). We use a fixed size here for allocation.
 */
#define PATTERN_V1_OUTPUT_SIZE	8

static void test_perf_pattern_v1_compress(struct kunit *test)
{
	u8 *src, *compressed, *decompressed;
	unsigned int size = 65536;
	int comp_len, ret;
	u64 start, elapsed;
	int i;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = kzalloc(PATTERN_V1_OUTPUT_SIZE + 64, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	generate_uniform(src, size);

	/* Verify */
	comp_len = smb2_pattern_v1_compress(src, size, compressed,
					    PATTERN_V1_OUTPUT_SIZE + 64);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	ret = smb2_pattern_v1_decompress(compressed, comp_len,
					 decompressed, size, size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	kunit_info(test,
		   "BENCHMARK: pattern_v1_ratio orig=%u compressed=%d "
		   "ratio=%u:1\n",
		   size, comp_len, size / comp_len);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS_LIGHT; i++)
		smb2_pattern_v1_compress(src, size, compressed,
					 PATTERN_V1_OUTPUT_SIZE + 64);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, "pattern_v1_compress_64K",
				COMP_ITERS_LIGHT, elapsed, size);

	vfree(decompressed);
	kfree(compressed);
	vfree(src);
}

/* ========================================================================
 * Benchmark 8: Compression ratio comparison across algorithms
 * ======================================================================== */

static void test_perf_compression_ratio_comparison(struct kunit *test)
{
	u8 *src, *comp_buf;
	unsigned int size = 4096;
	unsigned int comp_buf_size = size * 2 + 512;
	int lznt1_len, lz77_len, lz77huff_len;
	u64 start, elapsed;
	int i;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	comp_buf = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, comp_buf);

	/* Use compressible data for meaningful comparison */
	generate_compressible(src, size);

	/* Measure each algorithm */
	lznt1_len = smb2_compress_data(SMB3_COMPRESS_LZNT1, src, size,
				       comp_buf, comp_buf_size);
	KUNIT_ASSERT_GT(test, lznt1_len, 0);

	lz77_len = smb2_compress_data(SMB3_COMPRESS_LZ77, src, size,
				      comp_buf, comp_buf_size);
	KUNIT_ASSERT_GT(test, lz77_len, 0);

	lz77huff_len = smb2_compress_data(SMB3_COMPRESS_LZ77_HUFF, src, size,
					  comp_buf, comp_buf_size);
	KUNIT_ASSERT_GT(test, lz77huff_len, 0);

	kunit_info(test,
		   "BENCHMARK: compression_ratio_4K_compressible "
		   "lznt1=%d lz77=%d lz77huff=%d original=%u\n",
		   lznt1_len, lz77_len, lz77huff_len, size);

	/* Also benchmark random (incompressible) data */
	get_random_bytes(src, size);

	lznt1_len = smb2_compress_data(SMB3_COMPRESS_LZNT1, src, size,
				       comp_buf, comp_buf_size);
	lz77_len = smb2_compress_data(SMB3_COMPRESS_LZ77, src, size,
				      comp_buf, comp_buf_size);
	lz77huff_len = smb2_compress_data(SMB3_COMPRESS_LZ77_HUFF, src, size,
					  comp_buf, comp_buf_size);

	kunit_info(test,
		   "BENCHMARK: compression_ratio_4K_random "
		   "lznt1=%d lz77=%d lz77huff=%d original=%u\n",
		   lznt1_len, lz77_len, lz77huff_len, size);

	/* Timing comparison: compress compressible data with all 3 */
	generate_compressible(src, size);

	start = ktime_get_ns();
	for (i = 0; i < COMP_ITERS; i++) {
		smb2_compress_data(SMB3_COMPRESS_LZNT1, src, size,
				   comp_buf, comp_buf_size);
		smb2_compress_data(SMB3_COMPRESS_LZ77, src, size,
				   comp_buf, comp_buf_size);
		smb2_compress_data(SMB3_COMPRESS_LZ77_HUFF, src, size,
				   comp_buf, comp_buf_size);
	}
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT(test, "compress_all_3_algorithms_4K",
		     COMP_ITERS, elapsed, "3_algorithms_per_iter");

	vfree(comp_buf);
	vfree(src);
}

/* ========================================================================
 * Test suite registration
 * ======================================================================== */

static struct kunit_case ksmbd_perf_compression_cases[] = {
	KUNIT_CASE(test_perf_lznt1_compress_4k),
	KUNIT_CASE(test_perf_lznt1_compress_64k),
	KUNIT_CASE(test_perf_lznt1_decompress_4k),
	KUNIT_CASE(test_perf_lznt1_decompress_64k),
	KUNIT_CASE(test_perf_lz77_compress_4k),
	KUNIT_CASE(test_perf_lz77_compress_64k),
	KUNIT_CASE(test_perf_lz77_decompress_4k),
	KUNIT_CASE(test_perf_lz77_decompress_64k),
	KUNIT_CASE(test_perf_lz77huff_compress_4k),
	KUNIT_CASE(test_perf_lz77huff_compress_64k),
	KUNIT_CASE(test_perf_lz77huff_decompress_4k),
	KUNIT_CASE(test_perf_lz77huff_decompress_64k),
	KUNIT_CASE(test_perf_pattern_v1_compress),
	KUNIT_CASE(test_perf_compression_ratio_comparison),
	{}
};

static struct kunit_suite ksmbd_perf_compression_suite = {
	.name = "ksmbd_perf_compression",
	.test_cases = ksmbd_perf_compression_cases,
};

kunit_test_suite(ksmbd_perf_compression_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit micro-benchmarks for ksmbd compression algorithms");
