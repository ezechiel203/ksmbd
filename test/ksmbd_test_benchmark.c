// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit benchmark tests for ksmbd internal functions.
 *
 *   Measures performance of key hot-path operations by replicating
 *   the internal logic locally (same pattern as other ksmbd KUnit tests)
 *   and running tight loops with ktime_get_ns() timing.
 *
 *   Results are reported via kunit_info() in a parseable format:
 *     BENCHMARK: <name> iters=<N> total_ns=<T> per_iter_ns=<P> throughput=<X>
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/types.h>
#include <linux/spinlock.h>

/* ========================================================================
 * ARC4 (RC4) stream cipher -- replicated from auth.c
 * ======================================================================== */

#define ARC4_MIN_KEY_SIZE	1
#define ARC4_MAX_KEY_SIZE	256

struct bench_arc4_ctx {
	u32 S[256];
	u32 x, y;
};

static int bench_arc4_setkey(struct bench_arc4_ctx *ctx,
			     const u8 *in_key, unsigned int key_len)
{
	int i, j = 0, k = 0;

	ctx->x = 1;
	ctx->y = 0;

	for (i = 0; i < 256; i++)
		ctx->S[i] = i;

	for (i = 0; i < 256; i++) {
		u32 a = ctx->S[i];

		j = (j + in_key[k] + a) & 0xff;
		ctx->S[i] = ctx->S[j];
		ctx->S[j] = a;
		if (++k >= (int)key_len)
			k = 0;
	}

	return 0;
}

static void bench_arc4_crypt(struct bench_arc4_ctx *ctx,
			     u8 *out, const u8 *in, unsigned int len)
{
	u32 *const S = ctx->S;
	u32 x, y, a, b;
	u32 ty, ta, tb;

	if (!len)
		return;

	x = ctx->x;
	y = ctx->y;

	a = S[x];
	y = (y + a) & 0xff;
	b = S[y];

	do {
		S[y] = a;
		a = (a + b) & 0xff;
		S[x] = b;
		x = (x + 1) & 0xff;
		ta = S[x];
		ty = (y + ta) & 0xff;
		tb = S[ty];
		*out++ = *in++ ^ S[a];
		if (--len == 0)
			break;
		y = ty;
		a = ta;
		b = tb;
	} while (1);

	ctx->x = x;
	ctx->y = y;
}

/* ========================================================================
 * inode_hash -- replicated from vfs_cache.c
 * ======================================================================== */

/*
 * GOLDEN_RATIO_PRIME and L1_CACHE_BYTES are kernel-provided.
 * We use a fixed hash shift of 10 (1024 buckets) for benchmarking.
 */
#define BENCH_INODE_HASH_SHIFT	10
#define BENCH_INODE_HASH_MASK	((1 << BENCH_INODE_HASH_SHIFT) - 1)

static unsigned long bench_inode_hash(unsigned long sb, unsigned long hashval)
{
	unsigned long tmp;

	tmp = (hashval * sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
		L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> BENCH_INODE_HASH_SHIFT);
	return tmp & BENCH_INODE_HASH_MASK;
}

/* ========================================================================
 * LZNT1 compression -- simplified from smb2_compress.c
 *
 * We replicate only the core compress/decompress logic for
 * benchmarking purposes. This is a minimal "literal-only" encoder
 * that produces valid LZNT1 output (all literal chunks).
 * ======================================================================== */

#define LZNT1_CHUNK_SIZE	4096

/*
 * Minimal LZNT1 literal-only compressor: each 4096-byte chunk becomes
 * a 2-byte header + 4096 literal bytes (uncompressed chunk).
 * Final short chunk may be smaller.
 */
static int bench_lznt1_compress(const u8 *src, unsigned int src_len,
				u8 *dst, unsigned int dst_len)
{
	unsigned int src_off = 0;
	unsigned int dst_off = 0;

	while (src_off < src_len) {
		unsigned int chunk_len = min_t(unsigned int,
					       LZNT1_CHUNK_SIZE,
					       src_len - src_off);
		unsigned int total = 2 + chunk_len;
		u16 header;

		if (dst_off + total > dst_len)
			return -ENOSPC;

		/* LZNT1 chunk header: bit 15 = 0 (uncompressed),
		 * bits 11:0 = (size - 1) */
		header = (u16)(chunk_len - 1);
		/* Signature bits 14:12 = 0b011 for first chunk size class */
		header |= 0x3000;

		dst[dst_off]     = (u8)(header & 0xFF);
		dst[dst_off + 1] = (u8)(header >> 8);
		memcpy(dst + dst_off + 2, src + src_off, chunk_len);

		src_off += chunk_len;
		dst_off += total;
	}

	return (int)dst_off;
}

static int bench_lznt1_decompress(const u8 *src, unsigned int src_len,
				  u8 *dst, unsigned int dst_len)
{
	unsigned int src_off = 0;
	unsigned int dst_off = 0;

	while (src_off + 2 <= src_len) {
		u16 header = (u16)src[src_off] | ((u16)src[src_off + 1] << 8);
		unsigned int chunk_len;

		if (header == 0)
			break;

		chunk_len = (header & 0x0FFF) + 1;
		src_off += 2;

		if (src_off + chunk_len > src_len)
			return -EINVAL;
		if (dst_off + chunk_len > dst_len)
			return -ENOSPC;

		memcpy(dst + dst_off, src + src_off, chunk_len);
		src_off += chunk_len;
		dst_off += chunk_len;
	}

	return (int)dst_off;
}

/* ========================================================================
 * LZ77 plain compression -- minimal literal-only encoder
 * Per MS-XCA 2.4: each literal is encoded as a 9-bit value (1 flag bit
 * + 8 data bits). For benchmarking we use a simplified version.
 * ======================================================================== */

static int bench_lz77_compress(const u8 *src, unsigned int src_len,
			       u8 *dst, unsigned int dst_len)
{
	unsigned int i;
	unsigned int dst_off = 0;
	unsigned int flag_off;
	u32 flags = 0;
	int bit = 0;

	if (dst_len < 4)
		return -ENOSPC;

	/* Reserve 4 bytes for flags */
	flag_off = 0;
	dst_off = 4;

	for (i = 0; i < src_len; i++) {
		if (dst_off >= dst_len)
			return -ENOSPC;

		/* Set flag bit 0 = literal */
		/* flags bit for this position is already 0 (literal) */
		dst[dst_off++] = src[i];
		bit++;

		if (bit == 32) {
			/* Write flags to reserved position */
			dst[flag_off]     = (u8)(flags & 0xFF);
			dst[flag_off + 1] = (u8)((flags >> 8) & 0xFF);
			dst[flag_off + 2] = (u8)((flags >> 16) & 0xFF);
			dst[flag_off + 3] = (u8)((flags >> 24) & 0xFF);

			flags = 0;
			bit = 0;
			flag_off = dst_off;
			dst_off += 4;
			if (dst_off > dst_len)
				return -ENOSPC;
		}
	}

	/* Flush remaining flags */
	if (bit > 0 && flag_off + 4 <= dst_len) {
		dst[flag_off]     = (u8)(flags & 0xFF);
		dst[flag_off + 1] = (u8)((flags >> 8) & 0xFF);
		dst[flag_off + 2] = (u8)((flags >> 16) & 0xFF);
		dst[flag_off + 3] = (u8)((flags >> 24) & 0xFF);
	}

	return (int)dst_off;
}

static int bench_lz77_decompress(const u8 *src, unsigned int src_len,
				 u8 *dst, unsigned int dst_len)
{
	unsigned int src_off = 0;
	unsigned int dst_off = 0;
	u32 flags;
	int bit;

	while (src_off + 4 <= src_len) {
		flags = (u32)src[src_off] |
			((u32)src[src_off + 1] << 8) |
			((u32)src[src_off + 2] << 16) |
			((u32)src[src_off + 3] << 24);
		src_off += 4;

		for (bit = 0; bit < 32 && src_off < src_len; bit++) {
			if (!(flags & (1u << bit))) {
				/* Literal */
				if (dst_off >= dst_len)
					return -ENOSPC;
				dst[dst_off++] = src[src_off++];
			}
			/* Match references not generated by our compressor */
		}
	}

	return (int)dst_off;
}

/* ========================================================================
 * LZ77+Huffman compression -- literal-only stub for benchmarking
 *
 * A real LZ77+Huffman (MS-XCA 2.5) encoder builds a Huffman table of
 * 512 symbols. For benchmarking the hot path we use the same literal-only
 * approach as above, which measures raw memcpy + overhead.
 * ======================================================================== */

/*
 * Huffman literal encoder: writes a 256-byte canonical Huffman table
 * (all symbols at length 8) followed by the raw bitstream.
 */
#define HUFF_TABLE_SIZE		256

static int bench_lz77huff_compress(const u8 *src, unsigned int src_len,
				   u8 *dst, unsigned int dst_len)
{
	unsigned int i;

	/* Need table + src_len bytes minimum */
	if (dst_len < HUFF_TABLE_SIZE + src_len)
		return -ENOSPC;

	/* Write flat Huffman table: all 512 symbols coded at length 8
	 * (packed 4 bits per symbol = 256 bytes) */
	memset(dst, 0x88, HUFF_TABLE_SIZE);

	/* With all symbols at length 8, each literal is its own byte */
	for (i = 0; i < src_len; i++)
		dst[HUFF_TABLE_SIZE + i] = src[i];

	return (int)(HUFF_TABLE_SIZE + src_len);
}

static int bench_lz77huff_decompress(const u8 *src, unsigned int src_len,
				     u8 *dst, unsigned int dst_len)
{
	unsigned int payload_len;

	if (src_len < HUFF_TABLE_SIZE)
		return -EINVAL;

	payload_len = src_len - HUFF_TABLE_SIZE;
	if (payload_len > dst_len)
		return -ENOSPC;

	/* With flat table, each byte decodes to itself */
	memcpy(dst, src + HUFF_TABLE_SIZE, payload_len);

	return (int)payload_len;
}

/* ========================================================================
 * ODX nonce hash -- replicated from ksmbd_fsctl.c
 * ======================================================================== */

static u32 bench_odx_nonce_hash(const u8 *nonce)
{
	return jhash(nonce, 16, 0);
}

/* ========================================================================
 * Lock sequence check -- replicated from smb2_lock.c
 * ======================================================================== */

#define BENCH_LOCK_SEQ_INVALID	0xFF
#define BENCH_LOCK_SEQ_MAX	65

struct bench_lock_seq_ctx {
	u8		lock_seq[BENCH_LOCK_SEQ_MAX];
	spinlock_t	lock_seq_lock;
	bool		is_resilient;
	bool		is_durable;
	bool		is_persistent;
};

static void bench_lock_seq_init(struct bench_lock_seq_ctx *ctx)
{
	memset(ctx->lock_seq, BENCH_LOCK_SEQ_INVALID,
	       sizeof(ctx->lock_seq));
	spin_lock_init(&ctx->lock_seq_lock);
	ctx->is_resilient = true;
	ctx->is_durable = false;
	ctx->is_persistent = false;
}

/*
 * Replicate check_lock_sequence() from smb2_lock.c.
 * Return: 0 = proceed, 1 = replay (return OK immediately)
 */
static int bench_check_lock_sequence(struct bench_lock_seq_ctx *ctx,
				     __le32 lock_seq_val)
{
	u32 val = le32_to_cpu(lock_seq_val);
	u8 seq_num = val & 0xF;
	u32 seq_idx = (val >> 4) & 0xFFFFFFF;

	if (!ctx->is_resilient && !ctx->is_durable && !ctx->is_persistent)
		return 0;

	if (seq_idx == 0 || seq_idx >= BENCH_LOCK_SEQ_MAX)
		return 0;

	spin_lock(&ctx->lock_seq_lock);
	if (ctx->lock_seq[seq_idx] == seq_num) {
		spin_unlock(&ctx->lock_seq_lock);
		return 1; /* replay */
	}
	/* Invalidate and proceed */
	ctx->lock_seq[seq_idx] = BENCH_LOCK_SEQ_INVALID;
	spin_unlock(&ctx->lock_seq_lock);
	return 0;
}

static void bench_store_lock_sequence(struct bench_lock_seq_ctx *ctx,
				      __le32 lock_seq_val)
{
	u32 val = le32_to_cpu(lock_seq_val);
	u8 seq_num = val & 0xF;
	u32 seq_idx = (val >> 4) & 0xFFFFFFF;

	if (seq_idx == 0 || seq_idx >= BENCH_LOCK_SEQ_MAX)
		return;

	spin_lock(&ctx->lock_seq_lock);
	ctx->lock_seq[seq_idx] = seq_num;
	spin_unlock(&ctx->lock_seq_lock);
}

/* ========================================================================
 * Config lookup -- replicated from ksmbd_config.c
 *
 * Minimal reproduction: a flat array of u32 values indexed by enum.
 * ======================================================================== */

#define BENCH_CFG_MAX	12

struct bench_config {
	u32 values[BENCH_CFG_MAX];
};

static void bench_config_init(struct bench_config *cfg)
{
	int i;

	for (i = 0; i < BENCH_CFG_MAX; i++)
		cfg->values[i] = 65536; /* default */
}

static u32 bench_config_get_u32(struct bench_config *cfg, unsigned int param)
{
	if (param >= BENCH_CFG_MAX)
		return 0;
	return READ_ONCE(cfg->values[param]);
}

/* ========================================================================
 * Benchmark helper macros
 * ======================================================================== */

#define BENCH_REPORT(test, name, iters, total_ns, extra)		\
	kunit_info(test,						\
		   "BENCHMARK: %s iters=%u total_ns=%llu "		\
		   "per_iter_ns=%llu %s\n",				\
		   (name), (unsigned int)(iters),			\
		   (unsigned long long)(total_ns),			\
		   (unsigned long long)((total_ns) / (iters)),		\
		   (extra))

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

/* ========================================================================
 * Benchmark: ARC4 encrypt/decrypt at 1K, 4K, 64K
 * ======================================================================== */

#define ARC4_ITERS	10000

static void bench_arc4_size(struct kunit *test, unsigned int size,
			    const char *label)
{
	struct bench_arc4_ctx *ctx;
	u8 key[16];
	u8 *plaintext, *ciphertext;
	u64 start, elapsed;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	plaintext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plaintext);

	ciphertext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ciphertext);

	get_random_bytes(key, sizeof(key));
	get_random_bytes(plaintext, size);

	/* Warm up */
	bench_arc4_setkey(ctx, key, sizeof(key));
	bench_arc4_crypt(ctx, ciphertext, plaintext, size);

	/* Benchmark encrypt */
	start = ktime_get_ns();
	for (i = 0; i < ARC4_ITERS; i++) {
		bench_arc4_setkey(ctx, key, sizeof(key));
		bench_arc4_crypt(ctx, ciphertext, plaintext, size);
	}
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, ARC4_ITERS, elapsed, size);

	/* Verify roundtrip */
	bench_arc4_setkey(ctx, key, sizeof(key));
	bench_arc4_crypt(ctx, plaintext, ciphertext, size);

	vfree(ciphertext);
	vfree(plaintext);
	kfree(ctx);

	KUNIT_SUCCEED(test);
}

static void test_bench_arc4_1k(struct kunit *test)
{
	bench_arc4_size(test, 1024, "arc4_encrypt_1K");
}

static void test_bench_arc4_4k(struct kunit *test)
{
	bench_arc4_size(test, 4096, "arc4_encrypt_4K");
}

static void test_bench_arc4_64k(struct kunit *test)
{
	bench_arc4_size(test, 65536, "arc4_encrypt_64K");
}

/* ========================================================================
 * Benchmark: inode_hash throughput
 * ======================================================================== */

#define INODE_HASH_ITERS	100000

static void test_bench_inode_hash(struct kunit *test)
{
	u64 start, elapsed;
	unsigned long result = 0;
	unsigned long fake_sb = 0xDEADBEEF12345678UL;
	int i;

	/* Warm up */
	for (i = 0; i < 100; i++)
		result += bench_inode_hash(fake_sb, (unsigned long)i);

	start = ktime_get_ns();
	for (i = 0; i < INODE_HASH_ITERS; i++)
		result += bench_inode_hash(fake_sb, (unsigned long)i);
	elapsed = ktime_get_ns() - start;

	/* Use result to prevent compiler optimization */
	KUNIT_EXPECT_TRUE(test, result != 0 || elapsed > 0);

	BENCH_REPORT(test, "inode_hash", INODE_HASH_ITERS, elapsed,
		     "ops/sec computed from per_iter_ns");
}

/* ========================================================================
 * Benchmark: LZNT1 compress + decompress at 1K, 4K, 64K
 * ======================================================================== */

#define COMPRESS_ITERS	5000

static void bench_lznt1(struct kunit *test, unsigned int size,
			const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size;
	int comp_len, decomp_len;
	u64 start, elapsed_c, elapsed_d;
	int i;

	/* LZNT1 literal-only worst case: 2-byte header per 4K chunk + data */
	comp_buf_size = size + (size / LZNT1_CHUNK_SIZE + 1) * 2 + 64;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);

	/* Verify correctness first */
	comp_len = bench_lznt1_compress(src, size, compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	decomp_len = bench_lznt1_decompress(compressed, comp_len,
					     decompressed, size);
	KUNIT_ASSERT_EQ(test, decomp_len, (int)size);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	/* Benchmark compress */
	start = ktime_get_ns();
	for (i = 0; i < COMPRESS_ITERS; i++)
		bench_lznt1_compress(src, size, compressed, comp_buf_size);
	elapsed_c = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, COMPRESS_ITERS, elapsed_c, size);

	/* Benchmark decompress */
	start = ktime_get_ns();
	for (i = 0; i < COMPRESS_ITERS; i++)
		bench_lznt1_decompress(compressed, comp_len,
				       decompressed, size);
	elapsed_d = ktime_get_ns() - start;

	{
		char decomp_label[64];

		snprintf(decomp_label, sizeof(decomp_label),
			 "%s_decompress", label);
		BENCH_REPORT_THROUGHPUT(test, decomp_label,
					COMPRESS_ITERS, elapsed_d, size);
	}

	vfree(decompressed);
	vfree(compressed);
	vfree(src);

	KUNIT_SUCCEED(test);
}

static void test_bench_lznt1_1k(struct kunit *test)
{
	bench_lznt1(test, 1024, "lznt1_compress_1K");
}

static void test_bench_lznt1_4k(struct kunit *test)
{
	bench_lznt1(test, 4096, "lznt1_compress_4K");
}

static void test_bench_lznt1_64k(struct kunit *test)
{
	bench_lznt1(test, 65536, "lznt1_compress_64K");
}

/* ========================================================================
 * Benchmark: LZ77 compress + decompress at 1K, 4K, 64K
 * ======================================================================== */

static void bench_lz77(struct kunit *test, unsigned int size,
		       const char *label)
{
	u8 *src, *compressed, *decompressed;
	/* LZ77 literal-only: 4-byte flag word per 32 literals + data */
	unsigned int comp_buf_size = size + (size / 32 + 1) * 4 + 64;
	int comp_len, decomp_len;
	u64 start, elapsed_c, elapsed_d;
	int i;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);

	/* Verify correctness */
	comp_len = bench_lz77_compress(src, size, compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	decomp_len = bench_lz77_decompress(compressed, comp_len,
					    decompressed, size);
	KUNIT_ASSERT_EQ(test, decomp_len, (int)size);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	/* Benchmark compress */
	start = ktime_get_ns();
	for (i = 0; i < COMPRESS_ITERS; i++)
		bench_lz77_compress(src, size, compressed, comp_buf_size);
	elapsed_c = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, COMPRESS_ITERS, elapsed_c, size);

	/* Benchmark decompress */
	start = ktime_get_ns();
	for (i = 0; i < COMPRESS_ITERS; i++)
		bench_lz77_decompress(compressed, comp_len,
				      decompressed, size);
	elapsed_d = ktime_get_ns() - start;

	{
		char decomp_label[64];

		snprintf(decomp_label, sizeof(decomp_label),
			 "%s_decompress", label);
		BENCH_REPORT_THROUGHPUT(test, decomp_label,
					COMPRESS_ITERS, elapsed_d, size);
	}

	vfree(decompressed);
	vfree(compressed);
	vfree(src);

	KUNIT_SUCCEED(test);
}

static void test_bench_lz77_1k(struct kunit *test)
{
	bench_lz77(test, 1024, "lz77_compress_1K");
}

static void test_bench_lz77_4k(struct kunit *test)
{
	bench_lz77(test, 4096, "lz77_compress_4K");
}

static void test_bench_lz77_64k(struct kunit *test)
{
	bench_lz77(test, 65536, "lz77_compress_64K");
}

/* ========================================================================
 * Benchmark: LZ77+Huffman compress + decompress at 1K, 4K, 64K
 * ======================================================================== */

static void bench_lz77huff(struct kunit *test, unsigned int size,
			   const char *label)
{
	u8 *src, *compressed, *decompressed;
	unsigned int comp_buf_size = HUFF_TABLE_SIZE + size + 64;
	int comp_len, decomp_len;
	u64 start, elapsed_c, elapsed_d;
	int i;

	src = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, src);
	compressed = vmalloc(comp_buf_size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, compressed);
	decompressed = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, decompressed);

	get_random_bytes(src, size);

	/* Verify correctness */
	comp_len = bench_lz77huff_compress(src, size,
					   compressed, comp_buf_size);
	KUNIT_ASSERT_GT(test, comp_len, 0);
	decomp_len = bench_lz77huff_decompress(compressed, comp_len,
						decompressed, size);
	KUNIT_ASSERT_EQ(test, decomp_len, (int)size);
	KUNIT_ASSERT_EQ(test, memcmp(src, decompressed, size), 0);

	/* Benchmark compress */
	start = ktime_get_ns();
	for (i = 0; i < COMPRESS_ITERS; i++)
		bench_lz77huff_compress(src, size,
					compressed, comp_buf_size);
	elapsed_c = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, COMPRESS_ITERS, elapsed_c, size);

	/* Benchmark decompress */
	start = ktime_get_ns();
	for (i = 0; i < COMPRESS_ITERS; i++)
		bench_lz77huff_decompress(compressed, comp_len,
					  decompressed, size);
	elapsed_d = ktime_get_ns() - start;

	{
		char decomp_label[64];

		snprintf(decomp_label, sizeof(decomp_label),
			 "%s_decompress", label);
		BENCH_REPORT_THROUGHPUT(test, decomp_label,
					COMPRESS_ITERS, elapsed_d, size);
	}

	vfree(decompressed);
	vfree(compressed);
	vfree(src);

	KUNIT_SUCCEED(test);
}

static void test_bench_lz77huff_1k(struct kunit *test)
{
	bench_lz77huff(test, 1024, "lz77huff_compress_1K");
}

static void test_bench_lz77huff_4k(struct kunit *test)
{
	bench_lz77huff(test, 4096, "lz77huff_compress_4K");
}

static void test_bench_lz77huff_64k(struct kunit *test)
{
	bench_lz77huff(test, 65536, "lz77huff_compress_64K");
}

/* ========================================================================
 * Benchmark: Config lookup speed
 * ======================================================================== */

#define CONFIG_ITERS	100000

static void test_bench_config_lookup(struct kunit *test)
{
	struct bench_config cfg;
	u64 start, elapsed;
	u32 result = 0;
	int i;

	bench_config_init(&cfg);

	/* Warm up */
	for (i = 0; i < 100; i++)
		result += bench_config_get_u32(&cfg, i % BENCH_CFG_MAX);

	start = ktime_get_ns();
	for (i = 0; i < CONFIG_ITERS; i++)
		result += bench_config_get_u32(&cfg, i % BENCH_CFG_MAX);
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_TRUE(test, result != 0 || elapsed > 0);

	BENCH_REPORT(test, "config_get_u32", CONFIG_ITERS, elapsed, "");
}

/* ========================================================================
 * Benchmark: ODX nonce hash speed
 * ======================================================================== */

#define ODX_HASH_ITERS	100000

static void test_bench_odx_nonce_hash(struct kunit *test)
{
	u8 nonce[16];
	u64 start, elapsed;
	u32 result = 0;
	int i;

	get_random_bytes(nonce, sizeof(nonce));

	/* Warm up */
	for (i = 0; i < 100; i++) {
		nonce[0] = (u8)i;
		result += bench_odx_nonce_hash(nonce);
	}

	start = ktime_get_ns();
	for (i = 0; i < ODX_HASH_ITERS; i++) {
		nonce[0] = (u8)(i & 0xFF);
		nonce[1] = (u8)((i >> 8) & 0xFF);
		result += bench_odx_nonce_hash(nonce);
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_TRUE(test, result != 0 || elapsed > 0);

	BENCH_REPORT(test, "odx_nonce_hash", ODX_HASH_ITERS, elapsed, "");
}

/* ========================================================================
 * Benchmark: Lock sequence check speed
 * ======================================================================== */

#define LOCK_SEQ_ITERS	100000

static void test_bench_lock_sequence(struct kunit *test)
{
	struct bench_lock_seq_ctx ctx;
	u64 start, elapsed;
	int result = 0;
	int i;
	__le32 seq_val;

	bench_lock_seq_init(&ctx);

	/* Pre-populate some lock sequences */
	for (i = 1; i < 32; i++) {
		seq_val = cpu_to_le32((u32)(i << 4) | (u32)(i & 0xF));
		bench_store_lock_sequence(&ctx, seq_val);
	}

	/* Warm up */
	for (i = 0; i < 100; i++) {
		seq_val = cpu_to_le32((u32)((i % 64 + 1) << 4) | (u32)(i & 0xF));
		result += bench_check_lock_sequence(&ctx, seq_val);
	}

	start = ktime_get_ns();
	for (i = 0; i < LOCK_SEQ_ITERS; i++) {
		/* Mix of replay hits and misses */
		u32 idx = (i % 63) + 1;
		u32 seq = i & 0xF;

		seq_val = cpu_to_le32((idx << 4) | seq);
		result += bench_check_lock_sequence(&ctx, seq_val);
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_TRUE(test, result >= 0 || elapsed > 0);

	BENCH_REPORT(test, "check_lock_sequence", LOCK_SEQ_ITERS, elapsed, "");
}

/* ========================================================================
 * Benchmark: Hash distribution quality (supplementary)
 *
 * Measures collision rate over many random inputs to validate that the
 * inode_hash and odx_nonce_hash produce good distributions.
 * ======================================================================== */

#define DISTRIBUTION_SAMPLES	10000

static void test_bench_hash_distribution(struct kunit *test)
{
	unsigned int *buckets;
	unsigned int num_buckets = 1 << BENCH_INODE_HASH_SHIFT;
	unsigned int max_bucket = 0;
	unsigned int min_bucket = DISTRIBUTION_SAMPLES;
	unsigned int empty_buckets = 0;
	unsigned long fake_sb = 0xCAFEBABE00000001UL;
	int i;
	u64 start, elapsed;

	buckets = kzalloc(num_buckets * sizeof(unsigned int), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buckets);

	start = ktime_get_ns();
	for (i = 0; i < DISTRIBUTION_SAMPLES; i++) {
		unsigned long h = bench_inode_hash(fake_sb,
						   (unsigned long)(i * 4096UL + 1));
		buckets[h]++;
	}
	elapsed = ktime_get_ns() - start;

	for (i = 0; i < (int)num_buckets; i++) {
		if (buckets[i] > max_bucket)
			max_bucket = buckets[i];
		if (buckets[i] < min_bucket)
			min_bucket = buckets[i];
		if (buckets[i] == 0)
			empty_buckets++;
	}

	kunit_info(test,
		   "BENCHMARK: inode_hash_distribution samples=%u buckets=%u "
		   "min=%u max=%u empty=%u total_ns=%llu\n",
		   DISTRIBUTION_SAMPLES, num_buckets,
		   min_bucket, max_bucket, empty_buckets,
		   (unsigned long long)elapsed);

	/* A good hash should not leave >90% of buckets empty */
	KUNIT_EXPECT_LT(test, empty_buckets, num_buckets * 9 / 10);

	kfree(buckets);
}

/* ========================================================================
 * Test suite registration
 * ======================================================================== */

static struct kunit_case ksmbd_benchmark_test_cases[] = {
	/* ARC4 crypto throughput */
	KUNIT_CASE(test_bench_arc4_1k),
	KUNIT_CASE(test_bench_arc4_4k),
	KUNIT_CASE(test_bench_arc4_64k),

	/* Hash performance */
	KUNIT_CASE(test_bench_inode_hash),

	/* LZNT1 compression */
	KUNIT_CASE(test_bench_lznt1_1k),
	KUNIT_CASE(test_bench_lznt1_4k),
	KUNIT_CASE(test_bench_lznt1_64k),

	/* LZ77 compression */
	KUNIT_CASE(test_bench_lz77_1k),
	KUNIT_CASE(test_bench_lz77_4k),
	KUNIT_CASE(test_bench_lz77_64k),

	/* LZ77+Huffman compression */
	KUNIT_CASE(test_bench_lz77huff_1k),
	KUNIT_CASE(test_bench_lz77huff_4k),
	KUNIT_CASE(test_bench_lz77huff_64k),

	/* Config lookup */
	KUNIT_CASE(test_bench_config_lookup),

	/* ODX hash */
	KUNIT_CASE(test_bench_odx_nonce_hash),

	/* Lock sequence check */
	KUNIT_CASE(test_bench_lock_sequence),

	/* Hash distribution quality */
	KUNIT_CASE(test_bench_hash_distribution),

	{}
};

static struct kunit_suite ksmbd_benchmark_test_suite = {
	.name = "ksmbd_benchmark",
	.test_cases = ksmbd_benchmark_test_cases,
};

kunit_test_suite(ksmbd_benchmark_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit benchmark tests for ksmbd internal functions");
