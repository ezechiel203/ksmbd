# Line-by-line Review: src/core/ksmbd_md4.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * MD4 Message Digest Algorithm (RFC 1320) - self-contained fallback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` * Registers a crypto_shash algorithm named "md4" within the ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` * module so that NTLMv1 authentication works on kernels where the`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` * in-tree md4 module has been removed (Linux >= 6.6).`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` * Implementation derived from Andrew Tridgell and Steve French's`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` * CIFS MD4 implementation, and the cryptoapi implementation`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` * originally based on the public domain implementation written`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` * by Colin Plumb in 1993.`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * Copyright (c) Andrew Tridgell 1997-1998.`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * Modified by Steve French (sfrench@us.ibm.com) 2002`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * Modified by Namjae Jeon (namjae.jeon@samsung.com) 2015`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * Copyright (c) Cryptoapi developers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * Copyright (c) 2002 David S. Miller (davem@redhat.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <crypto/internal/hash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include <asm/byteorder.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "ksmbd_md4.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define MD4_DIGEST_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define MD4_BLOCK_SIZE		64`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define MD4_BLOCK_WORDS		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define MD4_HASH_WORDS		4`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `struct ksmbd_md4_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	u32	hash[MD4_HASH_WORDS];`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	u32	block[MD4_BLOCK_WORDS];`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	u64	byte_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static bool md4_registered;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `static inline u32 lshift(u32 x, unsigned int s)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	x &= 0xFFFFFFFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	return ((x << s) & 0xFFFFFFFF) | (x >> (32 - s));`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `static inline u32 F(u32 x, u32 y, u32 z)`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	return (x & y) | ((~x) & z);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `static inline u32 G(u32 x, u32 y, u32 z)`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	return (x & y) | (x & z) | (y & z);`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `static inline u32 H(u32 x, u32 y, u32 z)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	return x ^ y ^ z;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `static inline void ROUND1(u32 *a, u32 b, u32 c, u32 d, u32 k, u32 s)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	*a = lshift(*a + F(b, c, d) + k, s);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `static inline void ROUND2(u32 *a, u32 b, u32 c, u32 d, u32 k, u32 s)`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	*a = lshift(*a + G(b, c, d) + k + (u32)0x5A827999, s);`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `static inline void ROUND3(u32 *a, u32 b, u32 c, u32 d, u32 k, u32 s)`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	*a = lshift(*a + H(b, c, d) + k + (u32)0x6ED9EBA1, s);`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `VISIBLE_IF_KUNIT void md4_transform(u32 *hash, const u32 *in)`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	u32 a, b, c, d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	a = hash[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	b = hash[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	c = hash[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	d = hash[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	ROUND1(&a, b, c, d, in[0], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	ROUND1(&d, a, b, c, in[1], 7);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	ROUND1(&c, d, a, b, in[2], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	ROUND1(&b, c, d, a, in[3], 19);`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	ROUND1(&a, b, c, d, in[4], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	ROUND1(&d, a, b, c, in[5], 7);`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	ROUND1(&c, d, a, b, in[6], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	ROUND1(&b, c, d, a, in[7], 19);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	ROUND1(&a, b, c, d, in[8], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	ROUND1(&d, a, b, c, in[9], 7);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	ROUND1(&c, d, a, b, in[10], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	ROUND1(&b, c, d, a, in[11], 19);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	ROUND1(&a, b, c, d, in[12], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	ROUND1(&d, a, b, c, in[13], 7);`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	ROUND1(&c, d, a, b, in[14], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	ROUND1(&b, c, d, a, in[15], 19);`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	ROUND2(&a, b, c, d, in[0], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	ROUND2(&d, a, b, c, in[4], 5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	ROUND2(&c, d, a, b, in[8], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	ROUND2(&b, c, d, a, in[12], 13);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	ROUND2(&a, b, c, d, in[1], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	ROUND2(&d, a, b, c, in[5], 5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	ROUND2(&c, d, a, b, in[9], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	ROUND2(&b, c, d, a, in[13], 13);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	ROUND2(&a, b, c, d, in[2], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	ROUND2(&d, a, b, c, in[6], 5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	ROUND2(&c, d, a, b, in[10], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	ROUND2(&b, c, d, a, in[14], 13);`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	ROUND2(&a, b, c, d, in[3], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	ROUND2(&d, a, b, c, in[7], 5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	ROUND2(&c, d, a, b, in[11], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	ROUND2(&b, c, d, a, in[15], 13);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	ROUND3(&a, b, c, d, in[0], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	ROUND3(&d, a, b, c, in[8], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	ROUND3(&c, d, a, b, in[4], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	ROUND3(&b, c, d, a, in[12], 15);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	ROUND3(&a, b, c, d, in[2], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	ROUND3(&d, a, b, c, in[10], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	ROUND3(&c, d, a, b, in[6], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	ROUND3(&b, c, d, a, in[14], 15);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	ROUND3(&a, b, c, d, in[1], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	ROUND3(&d, a, b, c, in[9], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	ROUND3(&c, d, a, b, in[5], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	ROUND3(&b, c, d, a, in[13], 15);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	ROUND3(&a, b, c, d, in[3], 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	ROUND3(&d, a, b, c, in[11], 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	ROUND3(&c, d, a, b, in[7], 11);`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	ROUND3(&b, c, d, a, in[15], 15);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	hash[0] += a;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	hash[1] += b;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	hash[2] += c;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	hash[3] += d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `EXPORT_SYMBOL_IF_KUNIT(md4_transform);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `static inline void md4_transform_helper(struct ksmbd_md4_ctx *ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	le32_to_cpu_array(ctx->block, ARRAY_SIZE(ctx->block));`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	md4_transform(ctx->hash, ctx->block);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `/* --- crypto_shash callbacks --- */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `static int ksmbd_md4_shash_init(struct shash_desc *desc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	struct ksmbd_md4_ctx *mctx = shash_desc_ctx(desc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	mctx->hash[0] = 0x67452301;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	mctx->hash[1] = 0xefcdab89;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	mctx->hash[2] = 0x98badcfe;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	mctx->hash[3] = 0x10325476;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	mctx->byte_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `static int ksmbd_md4_shash_update(struct shash_desc *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `				  const u8 *data, unsigned int len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	struct ksmbd_md4_ctx *mctx = shash_desc_ctx(desc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	const u32 avail = sizeof(mctx->block) - (mctx->byte_count & 0x3f);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	mctx->byte_count += len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	if (avail > len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [MEM_BOUNDS|] `		memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00183 [NONE] `		       data, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [MEM_BOUNDS|] `	memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00188 [NONE] `	       data, avail);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	md4_transform_helper(mctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	data += avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	len -= avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	while (len >= sizeof(mctx->block)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [MEM_BOUNDS|] `		memcpy(mctx->block, data, sizeof(mctx->block));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00195 [NONE] `		md4_transform_helper(mctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		data += sizeof(mctx->block);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		len -= sizeof(mctx->block);`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [MEM_BOUNDS|] `	memcpy(mctx->block, data, len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00201 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `static int ksmbd_md4_shash_final(struct shash_desc *desc, u8 *out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	struct ksmbd_md4_ctx *mctx = shash_desc_ctx(desc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	const unsigned int offset = mctx->byte_count & 0x3f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	char *p = (char *)mctx->block + offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	int padding = 56 - (offset + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	*p++ = 0x80;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	if (padding < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `		memset(p, 0x00, padding + sizeof(u64));`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		md4_transform_helper(mctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		p = (char *)mctx->block;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		padding = 56;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	memset(p, 0, padding);`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	mctx->block[14] = mctx->byte_count << 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	mctx->block[15] = mctx->byte_count >> 29;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	le32_to_cpu_array(mctx->block,`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `			  (sizeof(mctx->block) - sizeof(u64)) / sizeof(u32));`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	md4_transform(mctx->hash, mctx->block);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	cpu_to_le32_array(mctx->hash, ARRAY_SIZE(mctx->hash));`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [MEM_BOUNDS|] `	memcpy(out, mctx->hash, sizeof(mctx->hash));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00227 [NONE] `	memzero_explicit(mctx, sizeof(*mctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `static struct shash_alg ksmbd_md4_alg = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	.digestsize	= MD4_DIGEST_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	.descsize	= sizeof(struct ksmbd_md4_ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	.init		= ksmbd_md4_shash_init,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	.update		= ksmbd_md4_shash_update,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	.final		= ksmbd_md4_shash_final,`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	.base		= {`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		.cra_name	 = "md4",`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		.cra_driver_name = "md4-ksmbd",`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		.cra_priority	 = 50,`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		.cra_blocksize	 = MD4_BLOCK_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		.cra_module	 = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `int ksmbd_md4_register(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	if (crypto_has_shash("md4", 0, 0)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		pr_info("ksmbd: kernel provides md4, skipping built-in registration\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	ret = crypto_register_shash(&ksmbd_md4_alg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [ERROR_PATH|] `		pr_err("ksmbd: failed to register md4-ksmbd shash: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00258 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	md4_registered = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	pr_info("ksmbd: registered built-in md4 (md4-ksmbd) for NTLMv1 support\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `void ksmbd_md4_unregister(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	if (md4_registered) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		crypto_unregister_shash(&ksmbd_md4_alg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		md4_registered = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
