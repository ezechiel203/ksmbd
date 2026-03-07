# Line-by-line Review: src/core/crypto_ctx.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2019 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/err.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/wait.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/sched.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "crypto_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `struct crypto_ctx_list {`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	spinlock_t		ctx_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `	int			avail_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	struct list_head	idle_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	wait_queue_head_t	ctx_wait;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `static struct crypto_ctx_list ctx_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `static inline void free_aead(struct crypto_aead *aead)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	if (aead)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `		crypto_free_aead(aead);`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `static void free_shash(struct shash_desc *shash)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	if (shash) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `		struct crypto_shash *tfm = shash->tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `		size_t shash_size = sizeof(*shash) + crypto_shash_descsize(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `		memzero_explicit(shash, shash_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `		kfree(shash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `		crypto_free_shash(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `static struct crypto_aead *alloc_aead(int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	struct crypto_aead *tfm = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	switch (id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	case CRYPTO_AEAD_AES_GCM:`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `		tfm = crypto_alloc_aead("gcm(aes)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	case CRYPTO_AEAD_AES_CCM:`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `		tfm = crypto_alloc_aead("ccm(aes)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [ERROR_PATH|] `		pr_err("Does not support encrypt ahead(id : %d)\n", id);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00056 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	if (IS_ERR(tfm)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [ERROR_PATH|] `		pr_err("Failed to alloc encrypt aead : %ld\n", PTR_ERR(tfm));`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00061 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	return tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `static struct shash_desc *alloc_shash_desc(int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	struct crypto_shash *tfm = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	struct shash_desc *shash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	switch (id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	case CRYPTO_SHASH_HMACMD5:`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `		 * Weak algorithm: Required by SMB protocol for backward`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		 * compatibility (NTLMv1/NTLMv2 authentication).`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `		 * Not used when SMB3.1.1 with AES is negotiated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `		tfm = crypto_alloc_shash("hmac(md5)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	case CRYPTO_SHASH_HMACSHA256:`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	case CRYPTO_SHASH_CMACAES:`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		tfm = crypto_alloc_shash("cmac(aes)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	case CRYPTO_SHASH_SHA256:`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		tfm = crypto_alloc_shash("sha256", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	case CRYPTO_SHASH_SHA512:`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		tfm = crypto_alloc_shash("sha512", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	case CRYPTO_SHASH_MD4:`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		 * Weak algorithm: Required by SMB protocol for backward`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		 * compatibility (NTLM password hashing).`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		 * Not used when SMB3.1.1 with AES is negotiated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		tfm = crypto_alloc_shash("md4", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	case CRYPTO_SHASH_MD5:`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `		 * Weak algorithm: Required by SMB protocol for backward`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `		 * compatibility (NTLMv1 authentication).`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `		 * Not used when SMB3.1.1 with AES is negotiated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		tfm = crypto_alloc_shash("md5", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	if (IS_ERR(tfm))`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [MEM_BOUNDS|] `	shash = kzalloc(sizeof(*shash) + crypto_shash_descsize(tfm),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00117 [NONE] `			KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	if (!shash)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		crypto_free_shash(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		shash->tfm = tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	return shash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `static void ctx_free(struct ksmbd_crypto_ctx *ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	for (i = 0; i < CRYPTO_SHASH_MAX; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		free_shash(ctx->desc[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	for (i = 0; i < CRYPTO_AEAD_MAX; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		free_aead(ctx->ccmaes[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	kfree(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * Crypto context pool limit: the pool is capped at num_online_cpus()`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` * contexts to prevent unbounded allocation under heavy load.  When`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * all contexts are in use, new requests wait with a timeout and retry`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` * up to KSMBD_CRYPTO_CTX_MAX_RETRIES times before failing, which`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * mitigates potential denial-of-service via crypto context exhaustion.`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `#define KSMBD_CRYPTO_CTX_MAX_RETRIES	3`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `#define KSMBD_CRYPTO_CTX_TIMEOUT	(5 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `static struct ksmbd_crypto_ctx *ksmbd_find_crypto_ctx(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	int retries = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	while (retries < KSMBD_CRYPTO_CTX_MAX_RETRIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [LOCK|] `		spin_lock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00153 [NONE] `		if (!list_empty(&ctx_list.idle_ctx)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `			ctx = list_entry(ctx_list.idle_ctx.next,`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `					 struct ksmbd_crypto_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `					 list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `			list_del(&ctx->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [LOCK|] `			spin_unlock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00159 [NONE] `			return ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		if (ctx_list.avail_ctx > num_online_cpus()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [LOCK|] `			spin_unlock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00164 [WAIT_LOOP|] `			if (!wait_event_timeout(ctx_list.ctx_wait,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00165 [NONE] `						!list_empty(&ctx_list.idle_ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `						KSMBD_CRYPTO_CTX_TIMEOUT)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `				retries++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		ctx_list.avail_ctx++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [LOCK|] `		spin_unlock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [MEM_BOUNDS|] `		ctx = kzalloc(sizeof(struct ksmbd_crypto_ctx),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00177 [NONE] `			      KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [LOCK|] `			spin_lock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00180 [NONE] `			ctx_list.avail_ctx--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [LOCK|] `			spin_unlock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00182 [WAIT_LOOP|] `			if (!wait_event_timeout(ctx_list.ctx_wait,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00183 [NONE] `						!list_empty(&ctx_list.idle_ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `						KSMBD_CRYPTO_CTX_TIMEOUT)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `				retries++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		return ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [ERROR_PATH|] `	pr_err_ratelimited("Failed to get crypto context after %d retries\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00194 [NONE] `			   KSMBD_CRYPTO_CTX_MAX_RETRIES);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `void ksmbd_release_crypto_ctx(struct ksmbd_crypto_ctx *ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	if (!ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [LOCK|] `	spin_lock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00204 [NONE] `	if (ctx_list.avail_ctx <= num_online_cpus()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `		list_add(&ctx->list, &ctx_list.idle_ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [LOCK|] `		spin_unlock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00207 [NONE] `		wake_up(&ctx_list.ctx_wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	ctx_list.avail_ctx--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [LOCK|] `	spin_unlock(&ctx_list.ctx_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00213 [NONE] `	ctx_free(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `static struct ksmbd_crypto_ctx *____crypto_shash_ctx_find(int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	if (id < 0 || id >= CRYPTO_SHASH_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	ctx = ksmbd_find_crypto_ctx();`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	if (!ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	if (ctx->desc[id])`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		return ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	ctx->desc[id] = alloc_shash_desc(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	if (ctx->desc[id])`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		return ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacmd5(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_HMACMD5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_hmacsha256(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_HMACSHA256);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_cmacaes(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_CMACAES);`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha256(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_SHA256);`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_sha512(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_SHA512);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md4(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_MD4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_md5(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	return ____crypto_shash_ctx_find(CRYPTO_SHASH_MD5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `static struct ksmbd_crypto_ctx *____crypto_aead_ctx_find(int id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	if (id < 0 || id >= CRYPTO_AEAD_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	ctx = ksmbd_find_crypto_ctx();`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	if (!ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	if (ctx->ccmaes[id])`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		return ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	ctx->ccmaes[id] = alloc_aead(id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	if (ctx->ccmaes[id])`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		return ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_gcm(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	return ____crypto_aead_ctx_find(CRYPTO_AEAD_AES_GCM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `struct ksmbd_crypto_ctx *ksmbd_crypto_ctx_find_ccm(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	return ____crypto_aead_ctx_find(CRYPTO_AEAD_AES_CCM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `void ksmbd_crypto_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	while (!list_empty(&ctx_list.idle_ctx)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `		ctx = list_entry(ctx_list.idle_ctx.next,`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `				 struct ksmbd_crypto_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `				 list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		list_del(&ctx->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		ctx_free(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	ctx_list.avail_ctx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	INIT_LIST_HEAD(&ctx_list.idle_ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `int ksmbd_crypto_create(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	spin_lock_init(&ctx_list.ctx_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	INIT_LIST_HEAD(&ctx_list.idle_ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	init_waitqueue_head(&ctx_list.ctx_wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	ctx_list.avail_ctx = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [MEM_BOUNDS|] `	ctx = kzalloc(sizeof(struct ksmbd_crypto_ctx), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00328 [NONE] `	if (!ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00330 [NONE] `	list_add(&ctx->list, &ctx_list.idle_ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
