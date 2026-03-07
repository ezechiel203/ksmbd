# Line-by-line Review: src/include/core/crypto_ctx.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2019 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __CRYPTO_CTX_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __CRYPTO_CTX_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <crypto/hash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <crypto/aead.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/atomic.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `	CRYPTO_SHASH_HMACMD5	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `	CRYPTO_SHASH_HMACSHA256,`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `	CRYPTO_SHASH_CMACAES,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	CRYPTO_SHASH_SHA256,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `	CRYPTO_SHASH_SHA512,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	CRYPTO_SHASH_MD4,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	CRYPTO_SHASH_MD5,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	CRYPTO_SHASH_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	CRYPTO_AEAD_AES_GCM = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	CRYPTO_AEAD_AES_CCM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	CRYPTO_AEAD_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	CRYPTO_BLK_ECBDES	= 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	CRYPTO_BLK_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `struct ksmbd_crypto_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	struct list_head		list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	struct shash_desc		*desc[CRYPTO_SHASH_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	struct crypto_aead		*ccmaes[CRYPTO_AEAD_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * Pool statistics for monitoring crypto context usage.`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * All fields are snapshots and may be slightly stale under concurrency.`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `struct ksmbd_crypto_pool_stats {`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	int	pool_total;	/* total contexts currently allocated */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	int	pool_in_use;	/* contexts currently checked out */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	int	pool_peak;	/* high-water mark of in_use */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `/* Default maximum pool size; prevents unbounded allocation under DoS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#define KSMBD_CRYPTO_CTX_MAX_POOL_SIZE	1024`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define CRYPTO_HMACMD5(c)	((c)->desc[CRYPTO_SHASH_HMACMD5])`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define CRYPTO_HMACSHA256(c)	((c)->desc[CRYPTO_SHASH_HMACSHA256])`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#define CRYPTO_CMACAES(c)	((c)->desc[CRYPTO_SHASH_CMACAES])`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define CRYPTO_SHA256(c)	((c)->desc[CRYPTO_SHASH_SHA256])`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#define CRYPTO_SHA512(c)	((c)->desc[CRYPTO_SHASH_SHA512])`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define CRYPTO_MD4(c)		((c)->desc[CRYPTO_SHASH_MD4])`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#define CRYPTO_MD5(c)		((c)->desc[CRYPTO_SHASH_MD5])`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define CRYPTO_HMACMD5_TFM(c)	((c)->desc[CRYPTO_SHASH_HMACMD5]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define CRYPTO_HMACSHA256_TFM(c)\`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `			((c)->desc[CRYPTO_SHASH_HMACSHA256]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define CRYPTO_CMACAES_TFM(c)	((c)->desc[CRYPTO_SHASH_CMACAES]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#define CRYPTO_SHA256_TFM(c)	((c)->desc[CRYPTO_SHASH_SHA256]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `#define CRYPTO_SHA512_TFM(c)	((c)->desc[CRYPTO_SHASH_SHA512]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#define CRYPTO_MD4_TFM(c)	((c)->desc[CRYPTO_SHASH_MD4]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define CRYPTO_MD5_TFM(c)	((c)->desc[CRYPTO_SHASH_MD5]->tfm)`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#define CRYPTO_GCM(c)		((c)->ccmaes[CRYPTO_AEAD_AES_GCM])`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define CRYPTO_CCM(c)		((c)->ccmaes[CRYPTO_AEAD_AES_CCM])`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `void ksmbd_release_crypto_ctx(struct ksmbd_crypto_ctx *ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacmd5(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacsha256(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_cmacaes(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha512(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha256(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md4(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md5(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_gcm(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_ccm(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `void ksmbd_crypto_destroy(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `int ksmbd_crypto_create(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/* Pool exhaustion protection and monitoring */`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `int ksmbd_crypto_ctx_pool_available(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `void ksmbd_crypto_ctx_pool_stats(struct ksmbd_crypto_pool_stats *stats);`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `void ksmbd_crypto_ctx_set_max_pool_size(int max_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `int ksmbd_crypto_ctx_get_max_pool_size(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `#endif /* __CRYPTO_CTX_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
