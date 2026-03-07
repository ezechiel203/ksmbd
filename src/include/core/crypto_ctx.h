/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#ifndef __CRYPTO_CTX_H__
#define __CRYPTO_CTX_H__

#include <crypto/hash.h>
#include <crypto/aead.h>
#include <linux/atomic.h>

enum {
	CRYPTO_SHASH_HMACMD5	= 0,
	CRYPTO_SHASH_HMACSHA256,
	CRYPTO_SHASH_CMACAES,
	CRYPTO_SHASH_SHA256,
	CRYPTO_SHASH_SHA512,
	CRYPTO_SHASH_MD4,
	CRYPTO_SHASH_MD5,
	CRYPTO_SHASH_MAX,
};

enum {
	CRYPTO_AEAD_AES_GCM = 0,
	CRYPTO_AEAD_AES_CCM,
	CRYPTO_AEAD_MAX,
};

enum {
	CRYPTO_BLK_ECBDES	= 32,
	CRYPTO_BLK_MAX,
};

struct ksmbd_crypto_ctx {
	struct list_head		list;

	struct shash_desc		*desc[CRYPTO_SHASH_MAX];
	struct crypto_aead		*ccmaes[CRYPTO_AEAD_MAX];
};

/*
 * Pool statistics for monitoring crypto context usage.
 * All fields are snapshots and may be slightly stale under concurrency.
 */
struct ksmbd_crypto_pool_stats {
	int	pool_total;	/* total contexts currently allocated */
	int	pool_in_use;	/* contexts currently checked out */
	int	pool_peak;	/* high-water mark of in_use */
};

/* Default maximum pool size; prevents unbounded allocation under DoS */
#define KSMBD_CRYPTO_CTX_MAX_POOL_SIZE	1024

#define CRYPTO_HMACMD5(c)	((c)->desc[CRYPTO_SHASH_HMACMD5])
#define CRYPTO_HMACSHA256(c)	((c)->desc[CRYPTO_SHASH_HMACSHA256])
#define CRYPTO_CMACAES(c)	((c)->desc[CRYPTO_SHASH_CMACAES])
#define CRYPTO_SHA256(c)	((c)->desc[CRYPTO_SHASH_SHA256])
#define CRYPTO_SHA512(c)	((c)->desc[CRYPTO_SHASH_SHA512])
#define CRYPTO_MD4(c)		((c)->desc[CRYPTO_SHASH_MD4])
#define CRYPTO_MD5(c)		((c)->desc[CRYPTO_SHASH_MD5])

#define CRYPTO_HMACMD5_TFM(c)	((c)->desc[CRYPTO_SHASH_HMACMD5]->tfm)
#define CRYPTO_HMACSHA256_TFM(c)\
			((c)->desc[CRYPTO_SHASH_HMACSHA256]->tfm)
#define CRYPTO_CMACAES_TFM(c)	((c)->desc[CRYPTO_SHASH_CMACAES]->tfm)
#define CRYPTO_SHA256_TFM(c)	((c)->desc[CRYPTO_SHASH_SHA256]->tfm)
#define CRYPTO_SHA512_TFM(c)	((c)->desc[CRYPTO_SHASH_SHA512]->tfm)
#define CRYPTO_MD4_TFM(c)	((c)->desc[CRYPTO_SHASH_MD4]->tfm)
#define CRYPTO_MD5_TFM(c)	((c)->desc[CRYPTO_SHASH_MD5]->tfm)

#define CRYPTO_GCM(c)		((c)->ccmaes[CRYPTO_AEAD_AES_GCM])
#define CRYPTO_CCM(c)		((c)->ccmaes[CRYPTO_AEAD_AES_CCM])

void ksmbd_release_crypto_ctx(struct ksmbd_crypto_ctx *ctx);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacmd5(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacsha256(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_cmacaes(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha512(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha256(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md4(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md5(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_gcm(void);
struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_ccm(void);
void ksmbd_crypto_destroy(void);
int ksmbd_crypto_create(void);

/* Pool exhaustion protection and monitoring */
int ksmbd_crypto_ctx_pool_available(void);
void ksmbd_crypto_ctx_pool_stats(struct ksmbd_crypto_pool_stats *stats);
void ksmbd_crypto_ctx_set_max_pool_size(int max_size);
int ksmbd_crypto_ctx_get_max_pool_size(void);

#endif /* __CRYPTO_CTX_H__ */
