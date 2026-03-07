// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MD4 Message Digest Algorithm (RFC 1320) - self-contained fallback.
 *
 * Registers a crypto_shash algorithm named "md4" within the ksmbd
 * module so that NTLMv1 authentication works on kernels where the
 * in-tree md4 module has been removed (Linux >= 6.6).
 *
 * Implementation derived from Andrew Tridgell and Steve French's
 * CIFS MD4 implementation, and the cryptoapi implementation
 * originally based on the public domain implementation written
 * by Colin Plumb in 1993.
 *
 * Copyright (c) Andrew Tridgell 1997-1998.
 * Modified by Steve French (sfrench@us.ibm.com) 2002
 * Modified by Namjae Jeon (namjae.jeon@samsung.com) 2015
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 David S. Miller (davem@redhat.com)
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <crypto/internal/hash.h>
#include <asm/byteorder.h>

#include "ksmbd_md4.h"

#define MD4_DIGEST_SIZE		16
#define MD4_BLOCK_SIZE		64
#define MD4_BLOCK_WORDS		16
#define MD4_HASH_WORDS		4

struct ksmbd_md4_ctx {
	u32	hash[MD4_HASH_WORDS];
	u32	block[MD4_BLOCK_WORDS];
	u64	byte_count;
};

static bool md4_registered;

static inline u32 lshift(u32 x, unsigned int s)
{
	x &= 0xFFFFFFFF;
	return ((x << s) & 0xFFFFFFFF) | (x >> (32 - s));
}

static inline u32 F(u32 x, u32 y, u32 z)
{
	return (x & y) | ((~x) & z);
}

static inline u32 G(u32 x, u32 y, u32 z)
{
	return (x & y) | (x & z) | (y & z);
}

static inline u32 H(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static inline void ROUND1(u32 *a, u32 b, u32 c, u32 d, u32 k, u32 s)
{
	*a = lshift(*a + F(b, c, d) + k, s);
}

static inline void ROUND2(u32 *a, u32 b, u32 c, u32 d, u32 k, u32 s)
{
	*a = lshift(*a + G(b, c, d) + k + (u32)0x5A827999, s);
}

static inline void ROUND3(u32 *a, u32 b, u32 c, u32 d, u32 k, u32 s)
{
	*a = lshift(*a + H(b, c, d) + k + (u32)0x6ED9EBA1, s);
}

static void md4_transform(u32 *hash, const u32 *in)
{
	u32 a, b, c, d;

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];

	ROUND1(&a, b, c, d, in[0], 3);
	ROUND1(&d, a, b, c, in[1], 7);
	ROUND1(&c, d, a, b, in[2], 11);
	ROUND1(&b, c, d, a, in[3], 19);
	ROUND1(&a, b, c, d, in[4], 3);
	ROUND1(&d, a, b, c, in[5], 7);
	ROUND1(&c, d, a, b, in[6], 11);
	ROUND1(&b, c, d, a, in[7], 19);
	ROUND1(&a, b, c, d, in[8], 3);
	ROUND1(&d, a, b, c, in[9], 7);
	ROUND1(&c, d, a, b, in[10], 11);
	ROUND1(&b, c, d, a, in[11], 19);
	ROUND1(&a, b, c, d, in[12], 3);
	ROUND1(&d, a, b, c, in[13], 7);
	ROUND1(&c, d, a, b, in[14], 11);
	ROUND1(&b, c, d, a, in[15], 19);

	ROUND2(&a, b, c, d, in[0], 3);
	ROUND2(&d, a, b, c, in[4], 5);
	ROUND2(&c, d, a, b, in[8], 9);
	ROUND2(&b, c, d, a, in[12], 13);
	ROUND2(&a, b, c, d, in[1], 3);
	ROUND2(&d, a, b, c, in[5], 5);
	ROUND2(&c, d, a, b, in[9], 9);
	ROUND2(&b, c, d, a, in[13], 13);
	ROUND2(&a, b, c, d, in[2], 3);
	ROUND2(&d, a, b, c, in[6], 5);
	ROUND2(&c, d, a, b, in[10], 9);
	ROUND2(&b, c, d, a, in[14], 13);
	ROUND2(&a, b, c, d, in[3], 3);
	ROUND2(&d, a, b, c, in[7], 5);
	ROUND2(&c, d, a, b, in[11], 9);
	ROUND2(&b, c, d, a, in[15], 13);

	ROUND3(&a, b, c, d, in[0], 3);
	ROUND3(&d, a, b, c, in[8], 9);
	ROUND3(&c, d, a, b, in[4], 11);
	ROUND3(&b, c, d, a, in[12], 15);
	ROUND3(&a, b, c, d, in[2], 3);
	ROUND3(&d, a, b, c, in[10], 9);
	ROUND3(&c, d, a, b, in[6], 11);
	ROUND3(&b, c, d, a, in[14], 15);
	ROUND3(&a, b, c, d, in[1], 3);
	ROUND3(&d, a, b, c, in[9], 9);
	ROUND3(&c, d, a, b, in[5], 11);
	ROUND3(&b, c, d, a, in[13], 15);
	ROUND3(&a, b, c, d, in[3], 3);
	ROUND3(&d, a, b, c, in[11], 9);
	ROUND3(&c, d, a, b, in[7], 11);
	ROUND3(&b, c, d, a, in[15], 15);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

static inline void md4_transform_helper(struct ksmbd_md4_ctx *ctx)
{
	le32_to_cpu_array(ctx->block, ARRAY_SIZE(ctx->block));
	md4_transform(ctx->hash, ctx->block);
}

/* --- crypto_shash callbacks --- */

static int ksmbd_md4_shash_init(struct shash_desc *desc)
{
	struct ksmbd_md4_ctx *mctx = shash_desc_ctx(desc);

	mctx->hash[0] = 0x67452301;
	mctx->hash[1] = 0xefcdab89;
	mctx->hash[2] = 0x98badcfe;
	mctx->hash[3] = 0x10325476;
	mctx->byte_count = 0;
	return 0;
}

static int ksmbd_md4_shash_update(struct shash_desc *desc,
				  const u8 *data, unsigned int len)
{
	struct ksmbd_md4_ctx *mctx = shash_desc_ctx(desc);
	const u32 avail = sizeof(mctx->block) - (mctx->byte_count & 0x3f);

	mctx->byte_count += len;

	if (avail > len) {
		memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
		       data, len);
		return 0;
	}

	memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
	       data, avail);
	md4_transform_helper(mctx);
	data += avail;
	len -= avail;

	while (len >= sizeof(mctx->block)) {
		memcpy(mctx->block, data, sizeof(mctx->block));
		md4_transform_helper(mctx);
		data += sizeof(mctx->block);
		len -= sizeof(mctx->block);
	}

	memcpy(mctx->block, data, len);
	return 0;
}

static int ksmbd_md4_shash_final(struct shash_desc *desc, u8 *out)
{
	struct ksmbd_md4_ctx *mctx = shash_desc_ctx(desc);
	const unsigned int offset = mctx->byte_count & 0x3f;
	char *p = (char *)mctx->block + offset;
	int padding = 56 - (offset + 1);

	*p++ = 0x80;
	if (padding < 0) {
		memset(p, 0x00, padding + sizeof(u64));
		md4_transform_helper(mctx);
		p = (char *)mctx->block;
		padding = 56;
	}

	memset(p, 0, padding);
	mctx->block[14] = mctx->byte_count << 3;
	mctx->block[15] = mctx->byte_count >> 29;
	le32_to_cpu_array(mctx->block,
			  (sizeof(mctx->block) - sizeof(u64)) / sizeof(u32));
	md4_transform(mctx->hash, mctx->block);
	cpu_to_le32_array(mctx->hash, ARRAY_SIZE(mctx->hash));
	memcpy(out, mctx->hash, sizeof(mctx->hash));
	memzero_explicit(mctx, sizeof(*mctx));
	return 0;
}

static struct shash_alg ksmbd_md4_alg = {
	.digestsize	= MD4_DIGEST_SIZE,
	.descsize	= sizeof(struct ksmbd_md4_ctx),
	.init		= ksmbd_md4_shash_init,
	.update		= ksmbd_md4_shash_update,
	.final		= ksmbd_md4_shash_final,
	.base		= {
		.cra_name	 = "md4",
		.cra_driver_name = "md4-ksmbd",
		.cra_priority	 = 50,
		.cra_blocksize	 = MD4_BLOCK_SIZE,
		.cra_module	 = THIS_MODULE,
	}
};

int ksmbd_md4_register(void)
{
	int ret;

	if (crypto_has_shash("md4", 0, 0)) {
		pr_info("ksmbd: kernel provides md4, skipping built-in registration\n");
		return 0;
	}

	ret = crypto_register_shash(&ksmbd_md4_alg);
	if (ret) {
		pr_err("ksmbd: failed to register md4-ksmbd shash: %d\n", ret);
		return ret;
	}

	md4_registered = true;
	pr_info("ksmbd: registered built-in md4 (md4-ksmbd) for NTLMv1 support\n");
	return 0;
}

void ksmbd_md4_unregister(void)
{
	if (md4_registered) {
		crypto_unregister_shash(&ksmbd_md4_alg);
		md4_registered = false;
	}
}
