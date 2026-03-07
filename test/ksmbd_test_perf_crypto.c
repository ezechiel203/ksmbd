// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit micro-benchmark tests for ksmbd cryptographic operations.
 *
 *   All crypto primitives are replicated locally (same self-contained
 *   pattern as ksmbd_test_benchmark.c) to avoid live module dependencies.
 *   Each benchmark uses ktime_get_ns() for high-resolution timing and
 *   reports results via kunit_info() in the standard parseable format.
 *
 *   NOTE: These mirrors are intentionally kept. The production crypto
 *   wrappers in auth.c and crypto_ctx.c are tightly coupled to the
 *   kernel crypto API (crypto_shash_alloc/setkey/init/update/final
 *   lifecycle, ksmbd_crypto_ctx pool management) and require full
 *   module initialization. Wiring benchmarks to those would test
 *   kernel crypto API latency, not the algorithmic structure overhead
 *   that these benchmarks are designed to measure.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/byteorder/generic.h>

/* ========================================================================
 * Configurable iteration counts
 * ======================================================================== */

#define CRYPTO_ITERS		10000
#define CRYPTO_ITERS_HEAVY	2000

/* ========================================================================
 * Benchmark reporting macros (same as ksmbd_test_benchmark.c)
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
 * ARC4 (RC4) -- replicated from auth.c
 * ======================================================================== */

struct perf_arc4_ctx {
	u32 S[256];
	u32 x, y;
};

static int perf_arc4_setkey(struct perf_arc4_ctx *ctx,
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

static void perf_arc4_crypt(struct perf_arc4_ctx *ctx,
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
 * HMAC-MD5 -- simplified replicated hash
 *
 * Real HMAC-MD5 uses crypto API; we replicate the computational structure
 * with a simplified hash to measure the algorithmic overhead.
 * ======================================================================== */

struct perf_md5_state {
	u32 a, b, c, d;
	u64 count;
	u8 buffer[64];
};

/* MD5 round functions */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define MD5_ROUND(f, a, b, c, d, x, s, k)	\
	do {					\
		(a) += f((b), (c), (d)) + (x) + (u32)(k);	\
		(a) = ROL32((a), (s));		\
		(a) += (b);			\
	} while (0)

static void perf_md5_transform(u32 *state, const u8 *block)
{
	u32 a, b, c, d;
	u32 M[16];
	int i;

	for (i = 0; i < 16; i++)
		M[i] = (u32)block[i * 4] | ((u32)block[i * 4 + 1] << 8) |
		       ((u32)block[i * 4 + 2] << 16) | ((u32)block[i * 4 + 3] << 24);

	a = state[0]; b = state[1]; c = state[2]; d = state[3];

	/* Round 1 */
	MD5_ROUND(F, a, b, c, d, M[0],  7,  0xd76aa478);
	MD5_ROUND(F, d, a, b, c, M[1],  12, 0xe8c7b756);
	MD5_ROUND(F, c, d, a, b, M[2],  17, 0x242070db);
	MD5_ROUND(F, b, c, d, a, M[3],  22, 0xc1bdceee);
	MD5_ROUND(F, a, b, c, d, M[4],  7,  0xf57c0faf);
	MD5_ROUND(F, d, a, b, c, M[5],  12, 0x4787c62a);
	MD5_ROUND(F, c, d, a, b, M[6],  17, 0xa8304613);
	MD5_ROUND(F, b, c, d, a, M[7],  22, 0xfd469501);
	MD5_ROUND(F, a, b, c, d, M[8],  7,  0x698098d8);
	MD5_ROUND(F, d, a, b, c, M[9],  12, 0x8b44f7af);
	MD5_ROUND(F, c, d, a, b, M[10], 17, 0xffff5bb1);
	MD5_ROUND(F, b, c, d, a, M[11], 22, 0x895cd7be);
	MD5_ROUND(F, a, b, c, d, M[12], 7,  0x6b901122);
	MD5_ROUND(F, d, a, b, c, M[13], 12, 0xfd987193);
	MD5_ROUND(F, c, d, a, b, M[14], 17, 0xa679438e);
	MD5_ROUND(F, b, c, d, a, M[15], 22, 0x49b40821);

	/* Round 2 */
	MD5_ROUND(G, a, b, c, d, M[1],  5,  0xf61e2562);
	MD5_ROUND(G, d, a, b, c, M[6],  9,  0xc040b340);
	MD5_ROUND(G, c, d, a, b, M[11], 14, 0x265e5a51);
	MD5_ROUND(G, b, c, d, a, M[0],  20, 0xe9b6c7aa);
	MD5_ROUND(G, a, b, c, d, M[5],  5,  0xd62f105d);
	MD5_ROUND(G, d, a, b, c, M[10], 9,  0x02441453);
	MD5_ROUND(G, c, d, a, b, M[15], 14, 0xd8a1e681);
	MD5_ROUND(G, b, c, d, a, M[4],  20, 0xe7d3fbc8);
	MD5_ROUND(G, a, b, c, d, M[9],  5,  0x21e1cde6);
	MD5_ROUND(G, d, a, b, c, M[14], 9,  0xc33707d6);
	MD5_ROUND(G, c, d, a, b, M[3],  14, 0xf4d50d87);
	MD5_ROUND(G, b, c, d, a, M[8],  20, 0x455a14ed);
	MD5_ROUND(G, a, b, c, d, M[13], 5,  0xa9e3e905);
	MD5_ROUND(G, d, a, b, c, M[2],  9,  0xfcefa3f8);
	MD5_ROUND(G, c, d, a, b, M[7],  14, 0x676f02d9);
	MD5_ROUND(G, b, c, d, a, M[12], 20, 0x8d2a4c8a);

	/* Round 3 */
	MD5_ROUND(H, a, b, c, d, M[5],  4,  0xfffa3942);
	MD5_ROUND(H, d, a, b, c, M[8],  11, 0x8771f681);
	MD5_ROUND(H, c, d, a, b, M[11], 16, 0x6d9d6122);
	MD5_ROUND(H, b, c, d, a, M[14], 23, 0xfde5380c);
	MD5_ROUND(H, a, b, c, d, M[1],  4,  0xa4beea44);
	MD5_ROUND(H, d, a, b, c, M[4],  11, 0x4bdecfa9);
	MD5_ROUND(H, c, d, a, b, M[7],  16, 0xf6bb4b60);
	MD5_ROUND(H, b, c, d, a, M[10], 23, 0xbebfbc70);
	MD5_ROUND(H, a, b, c, d, M[13], 4,  0x289b7ec6);
	MD5_ROUND(H, d, a, b, c, M[0],  11, 0xeaa127fa);
	MD5_ROUND(H, c, d, a, b, M[3],  16, 0xd4ef3085);
	MD5_ROUND(H, b, c, d, a, M[6],  23, 0x04881d05);
	MD5_ROUND(H, a, b, c, d, M[9],  4,  0xd9d4d039);
	MD5_ROUND(H, d, a, b, c, M[12], 11, 0xe6db99e5);
	MD5_ROUND(H, c, d, a, b, M[15], 16, 0x1fa27cf8);
	MD5_ROUND(H, b, c, d, a, M[2],  23, 0xc4ac5665);

	/* Round 4 */
	MD5_ROUND(I, a, b, c, d, M[0],  6,  0xf4292244);
	MD5_ROUND(I, d, a, b, c, M[7],  10, 0x432aff97);
	MD5_ROUND(I, c, d, a, b, M[14], 15, 0xab9423a7);
	MD5_ROUND(I, b, c, d, a, M[5],  21, 0xfc93a039);
	MD5_ROUND(I, a, b, c, d, M[12], 6,  0x655b59c3);
	MD5_ROUND(I, d, a, b, c, M[3],  10, 0x8f0ccc92);
	MD5_ROUND(I, c, d, a, b, M[10], 15, 0xffeff47d);
	MD5_ROUND(I, b, c, d, a, M[1],  21, 0x85845dd1);
	MD5_ROUND(I, a, b, c, d, M[8],  6,  0x6fa87e4f);
	MD5_ROUND(I, d, a, b, c, M[15], 10, 0xfe2ce6e0);
	MD5_ROUND(I, c, d, a, b, M[6],  15, 0xa3014314);
	MD5_ROUND(I, b, c, d, a, M[13], 21, 0x4e0811a1);
	MD5_ROUND(I, a, b, c, d, M[4],  6,  0xf7537e82);
	MD5_ROUND(I, d, a, b, c, M[11], 10, 0xbd3af235);
	MD5_ROUND(I, c, d, a, b, M[2],  15, 0x2ad7d2bb);
	MD5_ROUND(I, b, c, d, a, M[9],  21, 0xeb86d391);

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void perf_md5_init(struct perf_md5_state *s)
{
	s->a = 0x67452301;
	s->b = 0xefcdab89;
	s->c = 0x98badcfe;
	s->d = 0x10325476;
	s->count = 0;
}

static void perf_md5_update(struct perf_md5_state *s, const u8 *data,
			    unsigned int len)
{
	u32 state[4] = { s->a, s->b, s->c, s->d };
	unsigned int off = 0;

	while (off + 64 <= len) {
		perf_md5_transform(state, data + off);
		off += 64;
	}
	s->a = state[0]; s->b = state[1];
	s->c = state[2]; s->d = state[3];
	s->count += len;
}

static void perf_md5_final(struct perf_md5_state *s, u8 *digest)
{
	/* Simplified: just copy state as digest */
	digest[0]  = (u8)(s->a);       digest[1]  = (u8)(s->a >> 8);
	digest[2]  = (u8)(s->a >> 16); digest[3]  = (u8)(s->a >> 24);
	digest[4]  = (u8)(s->b);       digest[5]  = (u8)(s->b >> 8);
	digest[6]  = (u8)(s->b >> 16); digest[7]  = (u8)(s->b >> 24);
	digest[8]  = (u8)(s->c);       digest[9]  = (u8)(s->c >> 8);
	digest[10] = (u8)(s->c >> 16); digest[11] = (u8)(s->c >> 24);
	digest[12] = (u8)(s->d);       digest[13] = (u8)(s->d >> 8);
	digest[14] = (u8)(s->d >> 16); digest[15] = (u8)(s->d >> 24);
}

/* HMAC-MD5: key XOR ipad/opad + inner/outer MD5 */
static void perf_hmac_md5(const u8 *key, unsigned int key_len,
			  const u8 *data, unsigned int data_len,
			  u8 *digest)
{
	struct perf_md5_state ctx;
	u8 ipad[64], opad[64];
	u8 inner_digest[16];
	unsigned int i;

	memset(ipad, 0, 64);
	memset(opad, 0, 64);
	memcpy(ipad, key, min_t(unsigned int, key_len, 64));
	memcpy(opad, key, min_t(unsigned int, key_len, 64));

	for (i = 0; i < 64; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	/* Inner hash */
	perf_md5_init(&ctx);
	perf_md5_update(&ctx, ipad, 64);
	perf_md5_update(&ctx, data, data_len);
	perf_md5_final(&ctx, inner_digest);

	/* Outer hash */
	perf_md5_init(&ctx);
	perf_md5_update(&ctx, opad, 64);
	perf_md5_update(&ctx, inner_digest, 16);
	perf_md5_final(&ctx, digest);
}

/* ========================================================================
 * AES-CMAC -- simplified CMAC over replicated AES-like round function
 *
 * We replicate the CMAC structure (subkey derivation + CBC-MAC) using
 * a simplified 128-bit block cipher to measure the algorithmic overhead
 * of CMAC signing, which mirrors ksmbd_sign_smb2_pdu / ksmbd_sign_smb3_pdu.
 * ======================================================================== */

/* Simplified 128-bit block mix (not real AES, but same structure overhead) */
static void perf_block_encrypt(const u8 *key, const u8 *in, u8 *out)
{
	unsigned int i;

	for (i = 0; i < 16; i++)
		out[i] = in[i] ^ key[i];

	/* 4 rounds of byte mixing for realistic timing */
	for (i = 0; i < 16; i++)
		out[i] = (out[i] << 1) ^ (out[(i + 1) & 0xF] >> 3) ^ key[i];
	for (i = 0; i < 16; i++)
		out[i] ^= out[(i + 5) & 0xF] + key[(i + 7) & 0xF];
	for (i = 0; i < 16; i++)
		out[i] = (out[i] * 0x1B) ^ key[(i + 3) & 0xF];
	for (i = 0; i < 16; i++)
		out[i] ^= ROL32(out[(i + 11) & 0xF], 5) & 0xFF;
}

/* CMAC: CBC-MAC with subkey derivation */
static void perf_cmac_sign(const u8 *key, const u8 *data,
			   unsigned int data_len, u8 *mac)
{
	u8 state[16];
	u8 block[16];
	unsigned int off = 0;

	memset(state, 0, 16);

	while (off + 16 <= data_len) {
		unsigned int j;

		for (j = 0; j < 16; j++)
			block[j] = state[j] ^ data[off + j];
		perf_block_encrypt(key, block, state);
		off += 16;
	}

	/* Handle final partial block */
	if (off < data_len) {
		unsigned int remaining = data_len - off;
		unsigned int j;

		memset(block, 0, 16);
		for (j = 0; j < remaining; j++)
			block[j] = state[j] ^ data[off + j];
		block[remaining] ^= 0x80; /* padding */
		for (j = remaining + 1; j < 16; j++)
			block[j] = state[j];
		perf_block_encrypt(key, block, state);
	}

	memcpy(mac, state, 16);
}

/* ========================================================================
 * SHA-512 -- simplified replicated hash for preauth integrity
 *
 * We replicate the core SHA-512 compression structure (80 rounds of
 * mixing on 64-bit state words) to benchmark the preauth hash path.
 * ======================================================================== */

static const u64 sha512_K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
	0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
	0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
	0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
	0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
	0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
	0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
	0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
	0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
	0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
	0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
	0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
	0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
	0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define SHA512_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_S0(x) (ROR64(x, 28) ^ ROR64(x, 34) ^ ROR64(x, 39))
#define SHA512_S1(x) (ROR64(x, 14) ^ ROR64(x, 18) ^ ROR64(x, 41))
#define SHA512_s0(x) (ROR64(x, 1)  ^ ROR64(x, 8)  ^ ((x) >> 7))
#define SHA512_s1(x) (ROR64(x, 19) ^ ROR64(x, 61) ^ ((x) >> 6))

static void perf_sha512_transform(u64 *state, const u8 *block)
{
	u64 W[80];
	u64 a, b, c, d, e, f, g, h;
	int t;

	for (t = 0; t < 16; t++) {
		W[t] = 0;
		W[t] |= ((u64)block[t * 8 + 0] << 56);
		W[t] |= ((u64)block[t * 8 + 1] << 48);
		W[t] |= ((u64)block[t * 8 + 2] << 40);
		W[t] |= ((u64)block[t * 8 + 3] << 32);
		W[t] |= ((u64)block[t * 8 + 4] << 24);
		W[t] |= ((u64)block[t * 8 + 5] << 16);
		W[t] |= ((u64)block[t * 8 + 6] << 8);
		W[t] |= ((u64)block[t * 8 + 7]);
	}
	for (t = 16; t < 80; t++)
		W[t] = SHA512_s1(W[t - 2]) + W[t - 7] +
		       SHA512_s0(W[t - 15]) + W[t - 16];

	a = state[0]; b = state[1]; c = state[2]; d = state[3];
	e = state[4]; f = state[5]; g = state[6]; h = state[7];

	for (t = 0; t < 80; t++) {
		u64 T1 = h + SHA512_S1(e) + SHA512_CH(e, f, g) +
			 sha512_K[t] + W[t];
		u64 T2 = SHA512_S0(a) + SHA512_MAJ(a, b, c);

		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void perf_sha512_hash(const u8 *data, unsigned int len, u8 *digest)
{
	u64 state[8] = {
		0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
		0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
		0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
	};
	unsigned int off = 0;
	int i;

	while (off + 128 <= len) {
		perf_sha512_transform(state, data + off);
		off += 128;
	}

	/* Copy state to digest (first 64 bytes) */
	for (i = 0; i < 8; i++) {
		digest[i * 8 + 0] = (u8)(state[i] >> 56);
		digest[i * 8 + 1] = (u8)(state[i] >> 48);
		digest[i * 8 + 2] = (u8)(state[i] >> 40);
		digest[i * 8 + 3] = (u8)(state[i] >> 32);
		digest[i * 8 + 4] = (u8)(state[i] >> 24);
		digest[i * 8 + 5] = (u8)(state[i] >> 16);
		digest[i * 8 + 6] = (u8)(state[i] >> 8);
		digest[i * 8 + 7] = (u8)(state[i]);
	}
}

/* ========================================================================
 * AES-CCM/GCM encrypt -- simplified AEAD structure
 *
 * We measure the computational overhead of the AEAD envelope
 * (nonce construction + counter-mode XOR + tag computation) using
 * a simplified block cipher to isolate the algorithmic overhead.
 * ======================================================================== */

static void perf_aes_ctr_encrypt(const u8 *key, const u8 *nonce,
				 unsigned int nonce_len,
				 const u8 *in, u8 *out, unsigned int len)
{
	u8 ctr_block[16];
	u8 keystream[16];
	u32 counter = 1;
	unsigned int off = 0;

	memset(ctr_block, 0, 16);
	memcpy(ctr_block, nonce, min_t(unsigned int, nonce_len, 12));

	while (off < len) {
		unsigned int chunk = min_t(unsigned int, 16, len - off);
		unsigned int j;

		/* Set counter in last 4 bytes */
		ctr_block[12] = (u8)(counter >> 24);
		ctr_block[13] = (u8)(counter >> 16);
		ctr_block[14] = (u8)(counter >> 8);
		ctr_block[15] = (u8)(counter);

		perf_block_encrypt(key, ctr_block, keystream);

		for (j = 0; j < chunk; j++)
			out[off + j] = in[off + j] ^ keystream[j];

		off += chunk;
		counter++;
	}
}

/* Compute GHASH-like tag for GCM */
static void perf_gcm_tag(const u8 *key, const u8 *data, unsigned int len,
			 u8 *tag)
{
	u8 state[16];
	unsigned int off = 0;

	memset(state, 0, 16);

	while (off + 16 <= len) {
		unsigned int j;

		for (j = 0; j < 16; j++)
			state[j] ^= data[off + j];
		perf_block_encrypt(key, state, state);
		off += 16;
	}

	/* Final partial block */
	if (off < len) {
		unsigned int j;

		for (j = 0; off + j < len; j++)
			state[j] ^= data[off + j];
		perf_block_encrypt(key, state, state);
	}

	memcpy(tag, state, 16);
}

/* CCM: similar structure but with CBC-MAC for authentication */
static void perf_ccm_encrypt(const u8 *key, const u8 *nonce,
			     const u8 *in, u8 *out, unsigned int len,
			     u8 *tag)
{
	perf_aes_ctr_encrypt(key, nonce, 11, in, out, len);
	perf_cmac_sign(key, out, len, tag);
}

static void perf_gcm_encrypt(const u8 *key, const u8 *nonce,
			     const u8 *in, u8 *out, unsigned int len,
			     u8 *tag)
{
	perf_aes_ctr_encrypt(key, nonce, 12, in, out, len);
	perf_gcm_tag(key, out, len, tag);
}

/* ========================================================================
 * MD4 -- replicated from auth.c (legacy NTLM password hashing)
 * ======================================================================== */

#define MD4_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))

static void perf_md4_transform(u32 *state, const u8 *block)
{
	u32 a, b, c, d;
	u32 M[16];
	int i;

	for (i = 0; i < 16; i++)
		M[i] = (u32)block[i * 4] | ((u32)block[i * 4 + 1] << 8) |
		       ((u32)block[i * 4 + 2] << 16) | ((u32)block[i * 4 + 3] << 24);

	a = state[0]; b = state[1]; c = state[2]; d = state[3];

	/* Round 1 */
	for (i = 0; i < 16; i++) {
		static const int r1_shift[4] = { 3, 7, 11, 19 };
		u32 f = MD4_F(b, c, d) + a + M[i];

		a = d; d = c; c = b;
		b = ROL32(f, r1_shift[i & 3]);
	}

	/* Round 2 */
	for (i = 0; i < 16; i++) {
		static const int r2_order[16] = {
			0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
		};
		static const int r2_shift[4] = { 3, 5, 9, 13 };
		u32 g = MD4_G(b, c, d) + a + M[r2_order[i]] + 0x5A827999u;

		a = d; d = c; c = b;
		b = ROL32(g, r2_shift[i & 3]);
	}

	/* Round 3 */
	for (i = 0; i < 16; i++) {
		static const int r3_order[16] = {
			0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15
		};
		static const int r3_shift[4] = { 3, 9, 11, 15 };
		u32 h = MD4_H(b, c, d) + a + M[r3_order[i]] + 0x6ED9EBA1u;

		a = d; d = c; c = b;
		b = ROL32(h, r3_shift[i & 3]);
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void perf_md4_hash(const u8 *data, unsigned int len, u8 *digest)
{
	u32 state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	unsigned int off = 0;

	while (off + 64 <= len) {
		perf_md4_transform(state, data + off);
		off += 64;
	}

	digest[0]  = (u8)(state[0]);       digest[1]  = (u8)(state[0] >> 8);
	digest[2]  = (u8)(state[0] >> 16); digest[3]  = (u8)(state[0] >> 24);
	digest[4]  = (u8)(state[1]);       digest[5]  = (u8)(state[1] >> 8);
	digest[6]  = (u8)(state[1] >> 16); digest[7]  = (u8)(state[1] >> 24);
	digest[8]  = (u8)(state[2]);       digest[9]  = (u8)(state[2] >> 8);
	digest[10] = (u8)(state[2] >> 16); digest[11] = (u8)(state[2] >> 24);
	digest[12] = (u8)(state[3]);       digest[13] = (u8)(state[3] >> 8);
	digest[14] = (u8)(state[3] >> 16); digest[15] = (u8)(state[3] >> 24);
}

/* ========================================================================
 * SMB3 Key Derivation -- replicated KDF chain
 *
 * MS-SMB2 3.1.4.2: SP800-108 KDF in Counter Mode with HMAC-SHA256.
 * We replicate the structure using our simplified HMAC-MD5 to measure
 * the KDF chain overhead (label + context + counter iteration).
 * ======================================================================== */

static void perf_kdf_derive(const u8 *session_key, unsigned int key_len,
			    const char *label, unsigned int label_len,
			    const char *context, unsigned int context_len,
			    u8 *derived_key)
{
	/*
	 * SP800-108 Counter Mode:
	 *   PRF(Ki, [i] || Label || 0x00 || Context || [L])
	 * We use our HMAC-MD5 as the PRF for benchmarking.
	 */
	u8 input[256];
	unsigned int off = 0;
	u32 counter = 1;
	u32 key_bits = key_len * 8;

	/* [i] = counter (4 bytes, big-endian) */
	input[off++] = (u8)(counter >> 24);
	input[off++] = (u8)(counter >> 16);
	input[off++] = (u8)(counter >> 8);
	input[off++] = (u8)(counter);

	/* Label */
	memcpy(input + off, label, min_t(unsigned int, label_len, 128));
	off += min_t(unsigned int, label_len, 128);

	/* Separator 0x00 */
	input[off++] = 0x00;

	/* Context */
	memcpy(input + off, context, min_t(unsigned int, context_len, 64));
	off += min_t(unsigned int, context_len, 64);

	/* [L] = key length in bits (4 bytes, big-endian) */
	input[off++] = (u8)(key_bits >> 24);
	input[off++] = (u8)(key_bits >> 16);
	input[off++] = (u8)(key_bits >> 8);
	input[off++] = (u8)(key_bits);

	perf_hmac_md5(session_key, key_len, input, off, derived_key);
}

/* ========================================================================
 * Benchmark 1: ARC4 encrypt throughput -- 1K/4K/64K
 * ======================================================================== */

static void bench_arc4_throughput(struct kunit *test, unsigned int size,
				  const char *label)
{
	struct perf_arc4_ctx *ctx;
	u8 key[16];
	u8 *plaintext, *ciphertext, *roundtrip;
	u64 start, elapsed;
	int i;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	plaintext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plaintext);
	ciphertext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ciphertext);
	roundtrip = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, roundtrip);

	get_random_bytes(key, sizeof(key));
	get_random_bytes(plaintext, size);

	/* Verify correctness */
	perf_arc4_setkey(ctx, key, sizeof(key));
	perf_arc4_crypt(ctx, ciphertext, plaintext, size);
	perf_arc4_setkey(ctx, key, sizeof(key));
	perf_arc4_crypt(ctx, roundtrip, ciphertext, size);
	KUNIT_ASSERT_EQ(test, memcmp(plaintext, roundtrip, size), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS; i++) {
		perf_arc4_setkey(ctx, key, sizeof(key));
		perf_arc4_crypt(ctx, ciphertext, plaintext, size);
	}
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, CRYPTO_ITERS, elapsed, size);

	vfree(roundtrip);
	vfree(ciphertext);
	vfree(plaintext);
	kfree(ctx);
}

static void test_perf_arc4_1k(struct kunit *test)
{
	bench_arc4_throughput(test, 1024, "arc4_encrypt_1K");
}

static void test_perf_arc4_4k(struct kunit *test)
{
	bench_arc4_throughput(test, 4096, "arc4_encrypt_4K");
}

static void test_perf_arc4_64k(struct kunit *test)
{
	bench_arc4_throughput(test, 65536, "arc4_encrypt_64K");
}

/* ========================================================================
 * Benchmark 2: HMAC-MD5 hash throughput -- 1K/4K
 * ======================================================================== */

static void bench_hmac_md5_throughput(struct kunit *test, unsigned int size,
				      const char *label)
{
	u8 key[16];
	u8 *data;
	u8 digest[16], prev_digest[16];
	u64 start, elapsed;
	int i;

	data = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data);

	get_random_bytes(key, sizeof(key));
	get_random_bytes(data, size);

	/* Verify determinism: same input produces same output */
	perf_hmac_md5(key, sizeof(key), data, size, digest);
	perf_hmac_md5(key, sizeof(key), data, size, prev_digest);
	KUNIT_ASSERT_EQ(test, memcmp(digest, prev_digest, 16), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS; i++)
		perf_hmac_md5(key, sizeof(key), data, size, digest);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label, CRYPTO_ITERS, elapsed, size);

	vfree(data);
}

static void test_perf_hmac_md5_1k(struct kunit *test)
{
	bench_hmac_md5_throughput(test, 1024, "hmac_md5_hash_1K");
}

static void test_perf_hmac_md5_4k(struct kunit *test)
{
	bench_hmac_md5_throughput(test, 4096, "hmac_md5_hash_4K");
}

/* ========================================================================
 * Benchmark 3: AES-CMAC signing throughput -- 1K SMB2 PDU
 * ======================================================================== */

static void test_perf_cmac_sign_1k(struct kunit *test)
{
	u8 key[16];
	u8 *pdu;
	u8 signature[16], prev_sig[16];
	u64 start, elapsed;
	int i;

	pdu = vmalloc(1024);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, pdu);

	get_random_bytes(key, sizeof(key));
	get_random_bytes(pdu, 1024);

	/* Verify determinism */
	perf_cmac_sign(key, pdu, 1024, signature);
	perf_cmac_sign(key, pdu, 1024, prev_sig);
	KUNIT_ASSERT_EQ(test, memcmp(signature, prev_sig, 16), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS; i++)
		perf_cmac_sign(key, pdu, 1024, signature);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, "cmac_sign_1K_pdu",
				CRYPTO_ITERS, elapsed, 1024);

	vfree(pdu);
}

/* ========================================================================
 * Benchmark 4: SHA-512 preauth hash throughput -- 4K negotiate context
 * ======================================================================== */

static void test_perf_sha512_4k(struct kunit *test)
{
	u8 *data;
	u8 digest[64], prev_digest[64];
	u64 start, elapsed;
	int i;

	data = vmalloc(4096);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, data);

	get_random_bytes(data, 4096);

	/* Verify determinism */
	perf_sha512_hash(data, 4096, digest);
	perf_sha512_hash(data, 4096, prev_digest);
	KUNIT_ASSERT_EQ(test, memcmp(digest, prev_digest, 64), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS; i++)
		perf_sha512_hash(data, 4096, digest);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, "sha512_preauth_4K",
				CRYPTO_ITERS, elapsed, 4096);

	vfree(data);
}

/* ========================================================================
 * Benchmark 5: AES-CCM encrypt throughput -- 1K/64K
 * ======================================================================== */

static void bench_ccm_throughput(struct kunit *test, unsigned int size,
				 const char *label)
{
	u8 key[16], nonce[11], tag[16];
	u8 *plaintext, *ciphertext;
	u64 start, elapsed;
	int i;

	plaintext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plaintext);
	ciphertext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ciphertext);

	get_random_bytes(key, sizeof(key));
	get_random_bytes(nonce, sizeof(nonce));
	get_random_bytes(plaintext, size);

	/* Verify it produces output */
	perf_ccm_encrypt(key, nonce, plaintext, ciphertext, size, tag);
	KUNIT_EXPECT_NE(test, memcmp(plaintext, ciphertext, size), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS_HEAVY; i++)
		perf_ccm_encrypt(key, nonce, plaintext, ciphertext, size, tag);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label,
				CRYPTO_ITERS_HEAVY, elapsed, size);

	vfree(ciphertext);
	vfree(plaintext);
}

static void test_perf_ccm_1k(struct kunit *test)
{
	bench_ccm_throughput(test, 1024, "aes_ccm_encrypt_1K");
}

static void test_perf_ccm_64k(struct kunit *test)
{
	bench_ccm_throughput(test, 65536, "aes_ccm_encrypt_64K");
}

/* ========================================================================
 * Benchmark 6: AES-GCM encrypt throughput -- 1K/64K
 * ======================================================================== */

static void bench_gcm_throughput(struct kunit *test, unsigned int size,
				 const char *label)
{
	u8 key[16], nonce[12], tag[16];
	u8 *plaintext, *ciphertext;
	u64 start, elapsed;
	int i;

	plaintext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, plaintext);
	ciphertext = vmalloc(size);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ciphertext);

	get_random_bytes(key, sizeof(key));
	get_random_bytes(nonce, sizeof(nonce));
	get_random_bytes(plaintext, size);

	/* Verify it produces output */
	perf_gcm_encrypt(key, nonce, plaintext, ciphertext, size, tag);
	KUNIT_EXPECT_NE(test, memcmp(plaintext, ciphertext, size), 0);

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS_HEAVY; i++)
		perf_gcm_encrypt(key, nonce, plaintext, ciphertext, size, tag);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, label,
				CRYPTO_ITERS_HEAVY, elapsed, size);

	vfree(ciphertext);
	vfree(plaintext);
}

static void test_perf_gcm_1k(struct kunit *test)
{
	bench_gcm_throughput(test, 1024, "aes_gcm_encrypt_1K");
}

static void test_perf_gcm_64k(struct kunit *test)
{
	bench_gcm_throughput(test, 65536, "aes_gcm_encrypt_64K");
}

/* ========================================================================
 * Benchmark 7: MD4 hash throughput (legacy NTLM password hashing)
 * ======================================================================== */

static void test_perf_md4_hash(struct kunit *test)
{
	u8 password[64]; /* typical UTF-16LE password */
	u8 digest[16], prev_digest[16];
	u64 start, elapsed;
	int i;

	get_random_bytes(password, sizeof(password));

	/* Verify determinism */
	perf_md4_hash(password, sizeof(password), digest);
	perf_md4_hash(password, sizeof(password), prev_digest);
	KUNIT_ASSERT_EQ(test, memcmp(digest, prev_digest, 16), 0);

	/* Benchmark: typical NTLM password hash (short input) */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS; i++)
		perf_md4_hash(password, sizeof(password), digest);
	elapsed = ktime_get_ns() - start;

	BENCH_REPORT_THROUGHPUT(test, "md4_ntlm_password_hash",
				CRYPTO_ITERS, elapsed, sizeof(password));
}

/* ========================================================================
 * Benchmark 8: SMB3 KDF chain timing
 * ======================================================================== */

static void test_perf_kdf_derive(struct kunit *test)
{
	u8 session_key[16];
	u8 derived[16], prev_derived[16];
	const char *label = "SMB2AESCCM";
	const char *context = "ServerIn ";
	u64 start, elapsed;
	int i;

	get_random_bytes(session_key, sizeof(session_key));

	/* Verify determinism */
	perf_kdf_derive(session_key, 16, label, strlen(label),
			context, strlen(context), derived);
	perf_kdf_derive(session_key, 16, label, strlen(label),
			context, strlen(context), prev_derived);
	KUNIT_ASSERT_EQ(test, memcmp(derived, prev_derived, 16), 0);

	/* Benchmark: full KDF chain (signing + encryption + decryption) */
	start = ktime_get_ns();
	for (i = 0; i < CRYPTO_ITERS; i++) {
		perf_kdf_derive(session_key, 16,
				"SMB2AESCCM", 10,
				"ServerIn ", 9, derived);
		perf_kdf_derive(session_key, 16,
				"SMB2AESCCM", 10,
				"ServerOut", 9, derived);
		perf_kdf_derive(session_key, 16,
				"SMB2AESCMAC", 11,
				"SmbSign", 7, derived);
	}
	elapsed = ktime_get_ns() - start;

	/* 3 derivations per iteration */
	BENCH_REPORT(test, "kdf_chain_3_derivations",
		     CRYPTO_ITERS, elapsed, "3_keys_per_iter");
}

/* ========================================================================
 * Test suite registration
 * ======================================================================== */

static struct kunit_case ksmbd_perf_crypto_cases[] = {
	KUNIT_CASE(test_perf_arc4_1k),
	KUNIT_CASE(test_perf_arc4_4k),
	KUNIT_CASE(test_perf_arc4_64k),
	KUNIT_CASE(test_perf_hmac_md5_1k),
	KUNIT_CASE(test_perf_hmac_md5_4k),
	KUNIT_CASE(test_perf_cmac_sign_1k),
	KUNIT_CASE(test_perf_sha512_4k),
	KUNIT_CASE(test_perf_ccm_1k),
	KUNIT_CASE(test_perf_ccm_64k),
	KUNIT_CASE(test_perf_gcm_1k),
	KUNIT_CASE(test_perf_gcm_64k),
	KUNIT_CASE(test_perf_md4_hash),
	KUNIT_CASE(test_perf_kdf_derive),
	{}
};

static struct kunit_suite ksmbd_perf_crypto_suite = {
	.name = "ksmbd_perf_crypto",
	.test_cases = ksmbd_perf_crypto_cases,
};

kunit_test_suite(ksmbd_perf_crypto_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit micro-benchmarks for ksmbd cryptographic operations");
