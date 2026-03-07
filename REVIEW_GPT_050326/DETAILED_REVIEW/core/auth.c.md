# Line-by-line Review: src/core/auth.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/uaccess.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/backing-dev.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/writeback.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/uio.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/xattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <crypto/hash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <crypto/aead.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/random.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/scatterlist.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include <linux/fips.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include <crypto/des.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "crypto_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * Fixed format data defining GSS header and fixed string`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * "not_defined_in_RFC4178@please_ignore".`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * So sec blob data in neg phase could be generated statically.`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static char NEGOTIATE_GSS_HEADER[AUTH_GSS_LENGTH] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	0x60, 0x5e, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	0x05, 0x02, 0xa0, 0x54, 0x30, 0x52, 0xa0, 0x24,`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2a,`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31,`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `void ksmbd_copy_gss_neg_header(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [MEM_BOUNDS|] `	memcpy(buf, NEGOTIATE_GSS_HEADER, AUTH_GSS_LENGTH);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00066 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * DES-based functions below (str_to_key, smbhash, ksmbd_enc_p24):`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * Weak algorithm required by SMB protocol for backward compatibility`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * (NTLMv1 LanMan-style response computation).`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * Not used when SMB3.1.1 with AES is negotiated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `static void`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `str_to_key(unsigned char *str, unsigned char *key)`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	key[0] = str[0] >> 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	key[7] = str[6] & 0x7F;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	for (i = 0; i < 8; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		key[i] = (key[i] << 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `static int`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `smbhash(unsigned char *out, const unsigned char *in, unsigned char *key)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	unsigned char key2[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	struct des_ctx ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	if (fips_enabled) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		ksmbd_debug(AUTH, "FIPS compliance enabled: DES not permitted\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00100 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	str_to_key(key, key2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	des_expand_key(&ctx, key2, DES_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	des_encrypt(&ctx, out, in);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	memzero_explicit(&ctx, sizeof(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `static int ksmbd_enc_p24(unsigned char *p21, const unsigned char *c8, unsigned char *p24)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	rc = smbhash(p24, c8, p21);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	rc = smbhash(p24 + 8, c8, p21 + 7);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	return smbhash(p24 + 16, c8, p21 + 14);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `/* produce a md4 message digest from data of length n bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `static int ksmbd_enc_md4(unsigned char *md4_hash, unsigned char *link_str,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `			 int link_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	ctx = ksmbd_crypto_ctx_find_md4();`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `		ksmbd_debug(AUTH, "Crypto md4 allocation error\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00133 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	rc = crypto_shash_init(CRYPTO_MD4(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		ksmbd_debug(AUTH, "Could not init md4 shash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00139 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	rc = crypto_shash_update(CRYPTO_MD4(ctx), link_str, link_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		ksmbd_debug(AUTH, "Could not update with link_str\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00145 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	rc = crypto_shash_final(CRYPTO_MD4(ctx), md4_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `		ksmbd_debug(AUTH, "Could not generate md4 hash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `static int ksmbd_enc_update_sess_key(unsigned char *md5_hash, char *nonce,`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `				     char *server_challenge, int len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	ctx = ksmbd_crypto_ctx_find_md5();`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		ksmbd_debug(AUTH, "Crypto md5 allocation error\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00165 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	rc = crypto_shash_init(CRYPTO_MD5(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		ksmbd_debug(AUTH, "Could not init md5 shash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00171 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	rc = crypto_shash_update(CRYPTO_MD5(ctx), server_challenge, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		ksmbd_debug(AUTH, "Could not update with challenge\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00177 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	rc = crypto_shash_update(CRYPTO_MD5(ctx), nonce, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		ksmbd_debug(AUTH, "Could not update with nonce\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00183 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	rc = crypto_shash_final(CRYPTO_MD5(ctx), md5_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		ksmbd_debug(AUTH, "Could not generate md5 hash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ` * ksmbd_gen_sess_key() - function to generate session key`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` * @sess:	session of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * @hash:	source hash value to be used for find session key`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` * @hmac:	source hmac value to be used for finding session key`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `static int ksmbd_gen_sess_key(struct ksmbd_session *sess, char *hash,`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `			      char *hmac)`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	ctx = ksmbd_crypto_ctx_find_hmacmd5();`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc hmacmd5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00214 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	rc = crypto_shash_setkey(CRYPTO_HMACMD5_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `				 hash,`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `				 CIFS_HMAC_MD5_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		ksmbd_debug(AUTH, "hmacmd5 set key fail error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00222 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	rc = crypto_shash_init(CRYPTO_HMACMD5(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		ksmbd_debug(AUTH, "could not init hmacmd5 error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00228 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACMD5(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `				 hmac,`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [PROTO_GATE|] `				 SMB2_NTLMV2_SESSKEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00233 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		ksmbd_debug(AUTH, "Could not update with response error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00236 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	rc = crypto_shash_final(CRYPTO_HMACMD5(ctx), sess->sess_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		ksmbd_debug(AUTH, "Could not generate hmacmd5 hash error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00242 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `static int calc_ntlmv2_hash(struct ksmbd_conn *conn, struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			    char *ntlmv2_hash, char *dname)`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	int ret, len, conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	wchar_t *domain = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	__le16 *uniname = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	ctx = ksmbd_crypto_ctx_find_hmacmd5();`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		ksmbd_debug(AUTH, "can't generate ntlmv2 hash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00261 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	ret = crypto_shash_setkey(CRYPTO_HMACMD5_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `				  user_passkey(sess->user),`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `				  CIFS_ENCPWD_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		ksmbd_debug(AUTH, "Could not set NT Hash as a key\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00269 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	ret = crypto_shash_init(CRYPTO_HMACMD5(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		ksmbd_debug(AUTH, "could not init hmacmd5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00275 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	/* convert user_name to unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	len = strlen(user_name(sess->user));`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [MEM_BOUNDS|] `	uniname = kzalloc(2 + UNICODE_LEN(len), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00280 [NONE] `	if (!uniname) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00283 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	conv_len = smb_strtoUTF16(uniname, user_name(sess->user), len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `				  conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	if (conv_len < 0 || conv_len > len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00290 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	UniStrupr(uniname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	ret = crypto_shash_update(CRYPTO_HMACMD5(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `				  (char *)uniname,`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `				  UNICODE_LEN(conv_len));`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `		ksmbd_debug(AUTH, "Could not update with user\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00299 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	/* Convert domain name or conn name to unicode and uppercase */`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	len = strlen(dname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [MEM_BOUNDS|] `	domain = kzalloc(2 + UNICODE_LEN(len), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00304 [NONE] `	if (!domain) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00307 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	conv_len = smb_strtoUTF16((__le16 *)domain, dname, len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `				  conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	if (conv_len < 0 || conv_len > len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00314 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	ret = crypto_shash_update(CRYPTO_HMACMD5(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `				  (char *)domain,`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `				  UNICODE_LEN(conv_len));`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		ksmbd_debug(AUTH, "Could not update with domain\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00322 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	ret = crypto_shash_final(CRYPTO_HMACMD5(ctx), ntlmv2_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		ksmbd_debug(AUTH, "Could not generate md5 hash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	kfree_sensitive(uniname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	kfree_sensitive(domain);`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ` * ksmbd_auth_ntlm() - NTLM authentication handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` * @sess:	session of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` * @pw_buf:	NTLM challenge response`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` * @passkey:	user password`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * Return:	0 on success, error number on error`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `int ksmbd_auth_ntlm(struct ksmbd_session *sess, char *pw_buf, char *cryptkey)`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	unsigned char p21[21];`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	char key[CIFS_AUTH_RESP_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	memset(p21, '\0', 21);`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [MEM_BOUNDS|] `	memcpy(p21, user_passkey(sess->user), CIFS_NTHASH_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00351 [NONE] `	rc = ksmbd_enc_p24(p21, cryptkey, key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [ERROR_PATH|] `		pr_err("password processing failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00354 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00355 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	ksmbd_enc_md4(sess->sess_key, user_passkey(sess->user),`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		      CIFS_SMB1_SESSKEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [MEM_BOUNDS|] `	memcpy(sess->sess_key + CIFS_SMB1_SESSKEY_SIZE, key,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00360 [NONE] `	       CIFS_AUTH_RESP_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	sess->sequence_number = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	if (crypto_memneq(pw_buf, key, CIFS_AUTH_RESP_SIZE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		ksmbd_debug(AUTH, "ntlmv1 authentication failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00367 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	ksmbd_debug(AUTH, "ntlmv1 authentication pass\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	memzero_explicit(p21, sizeof(p21));`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	memzero_explicit(key, sizeof(key));`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_auth_ntlm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * ksmbd_auth_ntlmv2() - NTLMv2 authentication handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` * @conn:		connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` * @sess:		session of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * @ntlmv2:		NTLMv2 challenge response`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * @blen:		NTLMv2 blob length`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` * @domain_name:	domain name`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` * @cryptkey:		session crypto key`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` * Return:	0 on success, error number on error`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `int ksmbd_auth_ntlmv2(struct ksmbd_conn *conn, struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `		      struct ntlmv2_resp *ntlmv2, int blen, char *domain_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `		      char *cryptkey)`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	char ntlmv2_hash[CIFS_ENCPWD_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	char ntlmv2_rsp[CIFS_HMAC_MD5_HASH_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	struct ksmbd_crypto_ctx *ctx = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	char *construct = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	int rc, len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	if (blen <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	rc = calc_ntlmv2_hash(conn, sess, ntlmv2_hash, domain_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		ksmbd_debug(AUTH, "could not get v2 hash rc %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00406 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	ctx = ksmbd_crypto_ctx_find_hmacmd5();`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc hmacmd5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00412 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	rc = crypto_shash_setkey(CRYPTO_HMACMD5_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `				 ntlmv2_hash,`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `				 CIFS_HMAC_MD5_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		ksmbd_debug(AUTH, "Could not set NTLMV2 Hash as a key\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00420 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	rc = crypto_shash_init(CRYPTO_HMACMD5(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		ksmbd_debug(AUTH, "Could not init hmacmd5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00426 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [MEM_BOUNDS|] `	if (check_add_overflow(CIFS_CRYPTO_KEY_SIZE, blen, &len)) {`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00429 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00431 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [MEM_BOUNDS|] `	construct = kzalloc(len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00433 [NONE] `	if (!construct) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00436 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [MEM_BOUNDS|] `	memcpy(construct, cryptkey, CIFS_CRYPTO_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00439 [MEM_BOUNDS|] `	memcpy(construct + CIFS_CRYPTO_KEY_SIZE, &ntlmv2->blob_signature, blen);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACMD5(ctx), construct, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		ksmbd_debug(AUTH, "Could not update with response\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00445 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	rc = crypto_shash_final(CRYPTO_HMACMD5(ctx), ntlmv2_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `		ksmbd_debug(AUTH, "Could not generate md5 hash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00451 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	ctx = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	/* Verify password FIRST before generating session key */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	if (crypto_memneq(ntlmv2->ntlmv2_hash, ntlmv2_rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `			  CIFS_HMAC_MD5_HASH_SIZE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00460 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	/* Only generate session key after successful auth */`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	rc = ksmbd_gen_sess_key(sess, ntlmv2_hash, ntlmv2_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		ksmbd_debug(AUTH, "Could not generate sess key\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00467 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	if (ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	kfree_sensitive(construct);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	memzero_explicit(ntlmv2_hash, sizeof(ntlmv2_hash));`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	memzero_explicit(ntlmv2_rsp, sizeof(ntlmv2_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_auth_ntlmv2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ` * __ksmbd_auth_ntlmv2() - NTLM2(extended security) authentication handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ` * @sess:	session of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] ` * @client_nonce:	client nonce from LM response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ` * @ntlm_resp:		ntlm response data from client.`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ` * Return:	0 on success, error number on error`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `static int __ksmbd_auth_ntlmv2(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `			       char *client_nonce,`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `			       char *ntlm_resp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `			       char *cryptkey)`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	char sess_key[CIFS_SMB1_SESSKEY_SIZE] = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	unsigned char p21[21];`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	char key[CIFS_AUTH_RESP_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	rc = ksmbd_enc_update_sess_key(sess_key, client_nonce, cryptkey, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [ERROR_PATH|] `		pr_err("password processing failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00500 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00501 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	memset(p21, '\0', 21);`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [MEM_BOUNDS|] `	memcpy(p21, user_passkey(sess->user), CIFS_NTHASH_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00505 [NONE] `	rc = ksmbd_enc_p24(p21, sess_key, key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [ERROR_PATH|] `		pr_err("password processing failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00508 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00509 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	if (crypto_memneq(ntlm_resp, key, CIFS_AUTH_RESP_SIZE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	memzero_explicit(sess_key, sizeof(sess_key));`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	memzero_explicit(p21, sizeof(p21));`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	memzero_explicit(key, sizeof(key));`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ` * ARC4 (RC4) stream cipher implementation:`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` * Weak algorithm required by SMB protocol for backward compatibility`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` * (NTLMv2 session key encryption during authentication).`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` * Not used when SMB3.1.1 with AES is negotiated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `static int cifs_arc4_setkey(struct arc4_ctx *ctx, const u8 *in_key, unsigned int key_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	int i, j = 0, k = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	ctx->x = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	ctx->y = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	for (i = 0; i < 256; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `		ctx->S[i] = i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	for (i = 0; i < 256; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `		u32 a = ctx->S[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `		j = (j + in_key[k] + a) & 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `		ctx->S[i] = ctx->S[j];`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `		ctx->S[j] = a;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `		if (++k >= key_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `			k = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `static void cifs_arc4_crypt(struct arc4_ctx *ctx, u8 *out, const u8 *in, unsigned int len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	u32 *const S = ctx->S;`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	u32 x, y, a, b;`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	u32 ty, ta, tb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	if (len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	x = ctx->x;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	y = ctx->y;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	a = S[x];`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	y = (y + a) & 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	b = S[y];`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		S[y] = a;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		a = (a + b) & 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		S[x] = b;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		x = (x + 1) & 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `		ta = S[x];`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `		ty = (y + ta) & 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		tb = S[ty];`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `		*out++ = *in++ ^ S[a];`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		if (--len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `		y = ty;`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `		a = ta;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `		b = tb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	} while (true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	ctx->x = x;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	ctx->y = y;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ` * ksmbd_decode_ntlmssp_auth_blob() - helper function to construct`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ` * authenticate blob`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ` * @authblob:	authenticate blob source pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ` * @blob_len:	length of the @authblob message`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] ` * @conn:	connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ` * @sess:	session of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ` * Return:	0 on success, error number on error`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `int ksmbd_decode_ntlmssp_auth_blob(struct authenticate_message *authblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `				   int blob_len, struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `				   struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	char *domain_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	unsigned int nt_off, dn_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	unsigned short nt_len, dn_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	unsigned int lm_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	unsigned short lm_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	if (blob_len < sizeof(struct authenticate_message)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		ksmbd_debug(AUTH, "negotiate blob len %d too small\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `			    blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00613 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	if (memcmp(authblob->Signature, "NTLMSSP", 8)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `		ksmbd_debug(AUTH, "blob signature incorrect %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `			    authblob->Signature);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00619 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `	nt_off = le32_to_cpu(authblob->NtChallengeResponse.BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	nt_len = le16_to_cpu(authblob->NtChallengeResponse.Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	dn_off = le32_to_cpu(authblob->DomainName.BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	dn_len = le16_to_cpu(authblob->DomainName.Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	if (blob_len < (u64)dn_off + dn_len || blob_len < (u64)nt_off + nt_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	 * MS-NLMP 3.3.2: anonymous/null NTLMSSP Authenticate has`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	 * NtChallengeResponse length == 0 and NTLMSSP_ANONYMOUS flag`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	 * set.  Accept it without password verification - the caller`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	 * handles anonymous session semantics.`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	if (nt_len == 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	    (le32_to_cpu(authblob->NegotiateFlags) & NTLMSSP_ANONYMOUS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	if (nt_len < CIFS_ENCPWD_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	lm_off = le32_to_cpu(authblob->LmChallengeResponse.BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	lm_len = le16_to_cpu(authblob->LmChallengeResponse.Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	if (blob_len < (u64)lm_off + lm_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	/* process NTLM authentication */`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	if (nt_len == CIFS_AUTH_RESP_SIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `		if (le32_to_cpu(authblob->NegotiateFlags) &`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		    NTLMSSP_NEGOTIATE_EXTENDED_SEC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `			return __ksmbd_auth_ntlmv2(sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `						   (char *)authblob + lm_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `						   (char *)authblob + nt_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `						   conn->ntlmssp.cryptkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `			return ksmbd_auth_ntlm(sess, (char *)authblob +`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `				nt_off, conn->ntlmssp.cryptkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	 * Validate NTLMv2_CLIENT_CHALLENGE structure (MS-NLMP 2.2.2.7).`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `	 * The blob after the 16-byte NTLMv2 hash must have a 28-byte fixed`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	 * header followed by an AvPairs list terminated by MsvAvEOL.`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [PROTO_GATE|] `	 * Reject malformed blobs with -EINVAL (STATUS_INVALID_PARAMETER).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00668 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `		unsigned int blen = nt_len - CIFS_ENCPWD_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `		unsigned int avpair_off = sizeof(struct ntlmv2_resp) -`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `					  CIFS_ENCPWD_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		const char *bstart = (const char *)authblob + nt_off +`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `				     CIFS_ENCPWD_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `		unsigned int pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `		bool found_eol = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `		if (blen < avpair_off + 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `			ksmbd_debug(AUTH,`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `				    "NTLMv2 blob too small for AvPairs\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00682 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `		pos = avpair_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `		while (pos + 4 <= blen) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `			__le16 av_id, av_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [MEM_BOUNDS|] `			memcpy(&av_id, bstart + pos, sizeof(av_id));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00689 [MEM_BOUNDS|] `			memcpy(&av_len, bstart + pos + 2, sizeof(av_len));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00690 [NONE] `			if (av_id == 0 && av_len == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `				found_eol = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `			pos += 4 + le16_to_cpu(av_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		if (!found_eol) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `			ksmbd_debug(AUTH,`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `				    "NTLMv2 blob missing MsvAvEOL\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00700 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `	/* TODO : use domain name that imported from configuration file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `	domain_name = smb_strndup_from_utf16((const char *)authblob + dn_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `					     dn_len, true, conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	if (IS_ERR(domain_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `		return PTR_ERR(domain_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	/* process NTLMv2 authentication */`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	ksmbd_debug(AUTH, "decode_ntlmssp_authenticate_blob dname%s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `		    domain_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	ret = ksmbd_auth_ntlmv2(conn, sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `				(struct ntlmv2_resp *)((char *)authblob + nt_off),`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `				nt_len - CIFS_ENCPWD_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `				domain_name, conn->ntlmssp.cryptkey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	kfree_sensitive(domain_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	/* Session key exchange only after successful auth */`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	if (conn->ntlmssp.client_flags & NTLMSSP_NEGOTIATE_KEY_XCH) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `		struct arc4_ctx *ctx_arc4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `		unsigned int sess_key_off, sess_key_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `		sess_key_off = le32_to_cpu(authblob->SessionKey.BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `		sess_key_len = le16_to_cpu(authblob->SessionKey.Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `		if (blob_len < (u64)sess_key_off + sess_key_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00730 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		if (sess_key_len > CIFS_KEY_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [PROTO_GATE|] `		if (sess_key_len < SMB2_NTLMV2_SESSKEY_SIZE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00735 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00736 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [MEM_BOUNDS|] `		ctx_arc4 = kmalloc(sizeof(*ctx_arc4), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00738 [NONE] `		if (!ctx_arc4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00740 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `		cifs_arc4_setkey(ctx_arc4, sess->sess_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [PROTO_GATE|] `				 SMB2_NTLMV2_SESSKEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00743 [NONE] `		cifs_arc4_crypt(ctx_arc4, sess->sess_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `				(char *)authblob + sess_key_off, sess_key_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `		kfree_sensitive(ctx_arc4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `		memzero_explicit((void *)ctx_arc4, sizeof(*ctx_arc4));`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `		kfree(ctx_arc4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_decode_ntlmssp_auth_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] ` * ksmbd_decode_ntlmssp_neg_blob() - helper function to construct`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ` * negotiate blob`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] ` * @negblob: negotiate blob source pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] ` * @blob_len:	length of the @authblob message`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ` * @conn:	connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `int ksmbd_decode_ntlmssp_neg_blob(struct negotiate_message *negblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `				  int blob_len, struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	if (blob_len < sizeof(struct negotiate_message)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `		ksmbd_debug(AUTH, "negotiate blob len %d too small\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `			    blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00772 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	if (memcmp(negblob->Signature, "NTLMSSP", 8)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `		ksmbd_debug(AUTH, "blob signature incorrect %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `			    negblob->Signature);`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00778 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	conn->ntlmssp.client_flags = le32_to_cpu(negblob->NegotiateFlags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_decode_ntlmssp_neg_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] ` * ksmbd_build_ntlmssp_challenge_blob() - helper function to construct`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ` * challenge blob`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] ` * @chgblob: challenge blob source pointer to initialize`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] ` * @max_blob_sz: maximum size of the output buffer in bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] ` * @conn:	connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `int`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `ksmbd_build_ntlmssp_challenge_blob(struct challenge_message *chgblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `				   unsigned int max_blob_sz,`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `				   struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	struct target_info *tinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	wchar_t *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	__u8 *target_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `	unsigned int flags, blob_off, blob_len, type, target_info_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	int len, uni_len, conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `	int cflags = conn->ntlmssp.client_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [MEM_BOUNDS|] `	memcpy(chgblob->Signature, NTLMSSP_SIGNATURE, 8);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00806 [NONE] `	chgblob->MessageType = NtLmChallenge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	flags = NTLMSSP_NEGOTIATE_UNICODE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `		NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_TARGET_TYPE_SERVER |`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `		NTLMSSP_NEGOTIATE_TARGET_INFO;`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	if (cflags & NTLMSSP_NEGOTIATE_SIGN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `		flags |= NTLMSSP_NEGOTIATE_SIGN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `		flags |= cflags & (NTLMSSP_NEGOTIATE_128 |`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `				   NTLMSSP_NEGOTIATE_56);`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	if (cflags & NTLMSSP_NEGOTIATE_SEAL && smb3_encryption_negotiated(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		flags |= NTLMSSP_NEGOTIATE_SEAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	if (cflags & NTLMSSP_NEGOTIATE_ALWAYS_SIGN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `		flags |= NTLMSSP_NEGOTIATE_ALWAYS_SIGN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	if (cflags & NTLMSSP_REQUEST_TARGET)`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `		flags |= NTLMSSP_REQUEST_TARGET;`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `	if (conn->use_spnego &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	    (cflags & NTLMSSP_NEGOTIATE_EXTENDED_SEC))`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `		flags |= NTLMSSP_NEGOTIATE_EXTENDED_SEC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	if (cflags & NTLMSSP_NEGOTIATE_KEY_XCH)`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		flags |= NTLMSSP_NEGOTIATE_KEY_XCH;`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	chgblob->NegotiateFlags = cpu_to_le32(flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	len = strlen(ksmbd_netbios_name());`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [MEM_BOUNDS|] `	name = kmalloc(2 + UNICODE_LEN(len), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00837 [NONE] `	if (!name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00839 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	conv_len = smb_strtoUTF16((__le16 *)name, ksmbd_netbios_name(), len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `				  conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	if (conv_len < 0 || conv_len > len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00845 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	uni_len = UNICODE_LEN(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `	blob_off = sizeof(struct challenge_message);`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	blob_len = blob_off + uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	 * Pre-compute maximum blob size:`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `	 * blob_off + uni_len (target name) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	 * 4 target info entries * (4 + uni_len) each + 4 terminator`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `	target_info_len = 4 * (4 + uni_len) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	if (max_blob_sz < blob_len + target_info_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		ksmbd_debug(AUTH,`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `			    "challenge blob too large (%u) for buffer (%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `			    blob_len + target_info_len, max_blob_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00864 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	target_info_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	chgblob->TargetName.Length = cpu_to_le16(uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `	chgblob->TargetName.MaximumLength = cpu_to_le16(uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `	chgblob->TargetName.BufferOffset = cpu_to_le32(blob_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	/* Initialize random conn challenge */`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	get_random_bytes(conn->ntlmssp.cryptkey, CIFS_CRYPTO_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [MEM_BOUNDS|] `	memcpy(chgblob->Challenge, conn->ntlmssp.cryptkey,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00874 [NONE] `	       CIFS_CRYPTO_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `	/* Add Target Information to security buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `	chgblob->TargetInfoArray.BufferOffset = cpu_to_le32(blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	target_name = (__u8 *)chgblob + blob_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [MEM_BOUNDS|] `	memcpy(target_name, name, uni_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00881 [NONE] `	tinfo = (struct target_info *)(target_name + uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	chgblob->TargetInfoArray.Length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `	/* Add target info list for NetBIOS/DNS settings */`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	for (type = NTLMSSP_AV_NB_COMPUTER_NAME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	     type <= NTLMSSP_AV_DNS_DOMAIN_NAME; type++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `		tinfo->Type = cpu_to_le16(type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `		tinfo->Length = cpu_to_le16(uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [MEM_BOUNDS|] `		memcpy(tinfo->Content, name, uni_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00890 [NONE] `		tinfo = (struct target_info *)((char *)tinfo + 4 + uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		target_info_len += 4 + uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `	/* Add terminator subblock */`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	tinfo->Type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	tinfo->Length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	target_info_len += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `	chgblob->TargetInfoArray.Length = cpu_to_le16(target_info_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	chgblob->TargetInfoArray.MaximumLength = cpu_to_le16(target_info_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	blob_len += target_info_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `	ksmbd_debug(AUTH, "NTLMSSP SecurityBufferLength %d\n", blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	return blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `int ksmbd_krb5_authenticate(struct ksmbd_session *sess, char *in_blob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `			    int in_len, char *out_blob, int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	struct ksmbd_spnego_authen_response *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `	struct ksmbd_login_response_ext *resp_ext = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	struct ksmbd_user *user = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	int retval;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	resp = ksmbd_ipc_spnego_authen_request(in_blob, in_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	if (!resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `		ksmbd_debug(AUTH, "SPNEGO_AUTHEN_REQUEST failure\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00919 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	if (!(resp->login_response.status & KSMBD_USER_FLAG_OK)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `		ksmbd_debug(AUTH, "krb5 authentication failure\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `		retval = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00925 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `	if (*out_len < resp->spnego_blob_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `		ksmbd_debug(AUTH, "buf len %d, but blob len %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `			    *out_len, resp->spnego_blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		retval = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00932 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `	if (resp->session_key_len > sizeof(sess->sess_key)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `		ksmbd_debug(AUTH, "session key is too long\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `		retval = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00938 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	if (resp->login_response.status & KSMBD_USER_FLAG_EXTENSION)`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `		resp_ext = ksmbd_ipc_login_request_ext(resp->login_response.account);`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	user = ksmbd_alloc_user(&resp->login_response, resp_ext);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	if (!user) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `		ksmbd_debug(AUTH, "login failure\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `		retval = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00948 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	if (!sess->user) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `		/* First successful authentication */`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `		sess->user = user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `		 * Re-authentication on a valid SMB session can switch identity`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `		 * (including anonymous). Keep existing user object when creds`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `		 * are the same; otherwise replace it with the newly authenticated`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `		 * user context.`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `		if (ksmbd_compare_user(sess->user, user)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `			ksmbd_free_user(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `			ksmbd_free_user(sess->user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `			sess->user = user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	memzero_explicit(sess->sess_key, sizeof(sess->sess_key));`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [MEM_BOUNDS|] `	memcpy(sess->sess_key, resp->payload, resp->session_key_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00970 [MEM_BOUNDS|] `	memcpy(out_blob, resp->payload + resp->session_key_len,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00971 [NONE] `	       resp->spnego_blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	*out_len = resp->spnego_blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	retval = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `	if (resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `		memzero_explicit(resp->payload,`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `				 resp->session_key_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `		kvfree(resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	kvfree(resp_ext);`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	return retval;`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] ` * ksmbd_sign_smb1_pdu() - function to generate SMB1 packet signing`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] ` * @sess:	session of connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] ` * @iov:        buffer iov array`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] ` * @n_vec:	number of iovecs`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] ` * @sig:        signature value generated for client request packet`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `int ksmbd_sign_smb1_pdu(struct ksmbd_session *sess, struct kvec *iov, int n_vec,`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `			char *sig)`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `	int rc, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `	ctx = ksmbd_crypto_ctx_find_md5();`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc md5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01003 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `	rc = crypto_shash_init(CRYPTO_MD5(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `		ksmbd_debug(AUTH, "md5 init error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01009 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	rc = crypto_shash_update(CRYPTO_MD5(ctx), sess->sess_key, 40);`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `		ksmbd_debug(AUTH, "md5 update error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01015 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `	for (i = 0; i < n_vec; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		rc = crypto_shash_update(CRYPTO_MD5(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `					 iov[i].iov_base,`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `					 iov[i].iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `			ksmbd_debug(AUTH, "md5 update error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01024 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	rc = crypto_shash_final(CRYPTO_MD5(ctx), sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `		ksmbd_debug(AUTH, "md5 generation error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] ` * ksmbd_sign_smb2_pdu() - function to generate packet signing`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] ` * @conn:	connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] ` * @key:	signing key`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] ` * @iov:        buffer iov array`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] ` * @n_vec:	number of iovecs`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ` * @sig:	signature value generated for client request packet`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `int ksmbd_sign_smb2_pdu(struct ksmbd_conn *conn, char *key, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `			int n_vec, char *sig)`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	int rc, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	ctx = ksmbd_crypto_ctx_find_hmacsha256();`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc hmacmd5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01056 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `				 key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [PROTO_GATE|] `				 SMB2_NTLMV2_SESSKEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01061 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `		ksmbd_debug(AUTH, "hmacsha256 init error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01068 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	for (i = 0; i < n_vec; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `		rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `					 iov[i].iov_base,`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `					 iov[i].iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `			ksmbd_debug(AUTH, "hmacsha256 update error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01077 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `		ksmbd_debug(AUTH, "hmacsha256 generation error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] ` * ksmbd_sign_smb3_pdu() - function to generate packet signing`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] ` * @conn:	connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] ` * @key:	signing key`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] ` * @iov:        buffer iov array`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] ` * @n_vec:	number of iovecs`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] ` * @sig:	signature value generated for client request packet`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `int ksmbd_sign_smb3_pdu(struct ksmbd_conn *conn, char *key, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `			int n_vec, char *sig)`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	int rc, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `	ctx = ksmbd_crypto_ctx_find_cmacaes();`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc cmac\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01107 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `	rc = crypto_shash_setkey(CRYPTO_CMACAES_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `				 key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [PROTO_GATE|] `				 SMB2_CMACAES_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01112 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `	rc = crypto_shash_init(CRYPTO_CMACAES(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `		ksmbd_debug(AUTH, "cmaces init error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01119 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	for (i = 0; i < n_vec; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `		rc = crypto_shash_update(CRYPTO_CMACAES(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `					 iov[i].iov_base,`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `					 iov[i].iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `			ksmbd_debug(AUTH, "cmaces update error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01128 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	rc = crypto_shash_final(CRYPTO_CMACAES(ctx), sig);`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `		ksmbd_debug(AUTH, "cmaces generation error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] ` * ksmbd_sign_smb3_pdu_gmac() - generate AES-GMAC packet signature`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ` * @conn:	connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] ` * @key:	signing key`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] ` * @iov:	buffer iov array`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] ` * @n_vec:	number of iovecs`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] ` * @sig:	signature value generated for client request packet`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] ` * AES-GMAC is GCM mode with zero-length plaintext. The SMB2 message`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] ` * (with zeroed signature field) is the AAD. The 16-byte authentication`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] ` * tag becomes the signature. The 12-byte nonce is constructed from the`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] ` * MessageId field (8 bytes, little-endian) followed by 4 bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] ` * containing the SERVER_TO_REDIR flag from the Flags field (and`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] ` * ASYNC_COMMAND for CANCEL requests).`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `int ksmbd_sign_smb3_pdu_gmac(struct ksmbd_conn *conn, char *key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `			      struct kvec *iov, int n_vec, char *sig)`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	struct crypto_aead *tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `	struct aead_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	struct scatterlist *sg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `	u8 nonce[SMB3_AES_GMAC_NONCE] = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `	int rc, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `	unsigned int total_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `	u8 *aad_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [PROTO_GATE|] `	u8 tag[SMB2_SIGNATURE_SIZE] = {};`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `	if (n_vec < 1 || !iov[0].iov_base)`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	 * Construct the 12-byte GMAC nonce (MS-SMB2 2.2.3.1.7):`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	 *   nonce[0..7]  = MessageId (8 bytes, little-endian)`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	 *   nonce[8..11] = high_bits (4 bytes, little-endian)`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `	 * high_bits contains the SERVER_TO_REDIR flag (bit 0) from Flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `	 * For CANCEL requests, the ASYNC_COMMAND flag (bit 1) is also included.`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `	hdr = (struct smb2_hdr *)iov[0].iov_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [MEM_BOUNDS|] `	memcpy(nonce, &hdr->MessageId, sizeof(hdr->MessageId));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01181 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `		__le32 high_bits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [PROTO_GATE|] `		__le32 flag_mask = SMB2_FLAGS_SERVER_TO_REDIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [PROTO_GATE|] `		if (hdr->Command == SMB2_CANCEL)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01186 [PROTO_GATE|] `			flag_mask |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01187 [NONE] `		high_bits = hdr->Flags & flag_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [MEM_BOUNDS|] `		memcpy(nonce + 8, &high_bits, sizeof(high_bits));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01189 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	ctx = ksmbd_crypto_ctx_find_gcm();`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc gcm for gmac\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01195 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `	tfm = CRYPTO_GCM(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [PROTO_GATE|] `	rc = crypto_aead_setkey(tfm, key, SMB2_CMACAES_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01200 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `		ksmbd_debug(AUTH, "Failed to set aead key for gmac %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [ERROR_PATH|] `		goto free_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01203 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [PROTO_GATE|] `	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01206 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `		ksmbd_debug(AUTH, "Failed to set authsize for gmac %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [ERROR_PATH|] `		goto free_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01209 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	req = aead_request_alloc(tfm, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `	if (!req) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [ERROR_PATH|] `		goto free_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01215 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `	/* Calculate total AAD length from all iovecs */`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	for (i = 0; i < n_vec; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `		total_len += iov[i].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `	 * Linearize the iov data into a single buffer for the AAD.`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	 * GCM with zero-length plaintext (GMAC) requires the message`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	 * to be passed entirely as AAD.`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `	 * Performance note (I.6): this linearization copies all iovecs into`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `	 * a single contiguous allocation.  For large compound requests or READ`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [MEM_BOUNDS|] `	 * responses with total_len > 64 KiB, kzalloc() may fail under memory`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01229 [MEM_BOUNDS|] `	 * pressure (order-4+ allocation).  Use kvzalloc() which falls back to`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01230 [MEM_BOUNDS|] `	 * vmalloc() for large allocations, avoiding high-order kmalloc failures.`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01231 [NONE] `	 * kvfree() is used to release the buffer regardless of whether`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	 * kmalloc or vmalloc backed it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	if (total_len > 65536)`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `		ksmbd_debug(AUTH,`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `			    "AES-GMAC signing large buffer: %u bytes (n_vec=%d), using kvzalloc\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `			    total_len, n_vec);`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [MEM_BOUNDS|] `	aad_buf = kvzalloc(total_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01240 [NONE] `	if (!aad_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [ERROR_PATH|] `		goto free_req;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01243 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `		unsigned int offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `		for (i = 0; i < n_vec; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [MEM_BOUNDS|] `			memcpy(aad_buf + offset, iov[i].iov_base,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01250 [NONE] `			       iov[i].iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `			offset += iov[i].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	 * We need 2 scatterlist entries:`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	 *   sg[0] = AAD (the SMB2 message)`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `	 *   sg[1] = tag output (authentication tag / signature)`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `	sg = kmalloc_array(2, sizeof(struct scatterlist), KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	if (!sg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [ERROR_PATH|] `		goto free_aad;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01264 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	sg_init_table(sg, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `	sg_set_buf(&sg[0], aad_buf, total_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [PROTO_GATE|] `	sg_set_buf(&sg[1], tag, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `	aead_request_set_crypt(req, sg, sg, 0, nonce);`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	aead_request_set_ad(req, total_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	rc = crypto_aead_encrypt(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `		ksmbd_debug(AUTH, "gmac generation error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [ERROR_PATH|] `		goto free_sg;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01278 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(sig, tag, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `free_sg:`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `	kfree(sg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `free_aad:`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `	kvfree(aad_buf);  /* I.6: use kvfree since aad_buf may be vmalloc-backed */`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `free_req:`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	aead_request_free(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `free_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `struct derivation {`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `	struct kvec label;`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	struct kvec context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	bool binding;`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `static int generate_key(struct ksmbd_conn *conn, struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `			struct kvec label, struct kvec context, __u8 *key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `			unsigned int key_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	unsigned char zero = 0x0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `	__u8 i[4] = {0, 0, 0, 1};`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `	__u8 L128[4] = {0, 0, 0, 128};`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `	__u8 L256[4] = {0, 0, 1, 0};`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [PROTO_GATE|] `	unsigned char prfhash[SMB2_HMACSHA256_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01309 [NONE] `	unsigned char *hashptr = prfhash;`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [PROTO_GATE|] `	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01313 [NONE] `	memset(key, 0x0, key_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `	ctx = ksmbd_crypto_ctx_find_hmacsha256();`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `		ksmbd_debug(AUTH, "could not crypto alloc hmacmd5\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01319 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `				 sess->sess_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [PROTO_GATE|] `				 SMB2_NTLMV2_SESSKEY_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01324 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `		ksmbd_debug(AUTH, "hmacsha256 init error %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), i, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `		ksmbd_debug(AUTH, "could not update with n\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01337 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `				 label.iov_base,`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `				 label.iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `		ksmbd_debug(AUTH, "could not update with label\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01345 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), &zero, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `		ksmbd_debug(AUTH, "could not update with zero\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01351 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `				 context.iov_base,`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `				 context.iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `		ksmbd_debug(AUTH, "could not update with context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01359 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	if (key_size == SMB3_ENC_DEC_KEY_SIZE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [PROTO_GATE|] `	    (conn->cipher_type == SMB2_ENCRYPTION_AES256_CCM ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01363 [PROTO_GATE|] `	     conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01364 [NONE] `		rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), L256, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `		rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), L128, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `		ksmbd_debug(AUTH, "could not update with L\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01370 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), hashptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `		ksmbd_debug(AUTH, "Could not generate hmacmd5 hash error %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `			    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [ERROR_PATH|] `		goto smb3signkey_ret;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01377 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [MEM_BOUNDS|] `	memcpy(key, hashptr, key_size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `smb3signkey_ret:`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `	memzero_explicit(prfhash, sizeof(prfhash));`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `static int generate_smb3signingkey(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `				   struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `				   const struct derivation *signing)`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	struct channel *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `	char *key;`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	chann = lookup_chann_list(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `	if (!chann)`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `	if (conn->dialect >= SMB30_PROT_ID && signing->binding)`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `		key = chann->smb3signingkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `		key = sess->smb3signingkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `	rc = generate_key(conn, sess, signing->label, signing->context, key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `			  SMB3_SIGN_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	if (!(conn->dialect >= SMB30_PROT_ID && signing->binding))`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [MEM_BOUNDS|] `		memcpy(chann->smb3signingkey, key, SMB3_SIGN_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01411 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `	ksmbd_debug(AUTH, "generated signing key for session %llu\n", sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `int ksmbd_gen_smb30_signingkey(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `			       struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `	struct derivation d;`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `	d.label.iov_base = "SMB2AESCMAC";`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `	d.label.iov_len = 12;`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `	d.context.iov_base = "SmbSign";`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `	d.context.iov_len = 8;`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `	d.binding = conn->binding;`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `	return generate_smb3signingkey(sess, conn, &d);`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `int ksmbd_gen_smb311_signingkey(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `				struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `	struct derivation d;`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `	u8 preauth_hash[PREAUTH_HASHVALUE_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `	d.label.iov_base = "SMBSigningKey";`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `	d.label.iov_len = 14;`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `	if (conn->binding) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `		struct preauth_session *preauth_sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [LOCK|] `		down_read(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01442 [NONE] `		preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `		if (!preauth_sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `			up_read(&conn->session_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01446 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [MEM_BOUNDS|] `		memcpy(preauth_hash, preauth_sess->Preauth_HashValue,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01448 [NONE] `		       PREAUTH_HASHVALUE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `		up_read(&conn->session_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `		d.context.iov_base = preauth_hash;`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `		d.context.iov_base = sess->Preauth_HashValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `	d.context.iov_len = 64;`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `	d.binding = conn->binding;`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `	return generate_smb3signingkey(sess, conn, &d);`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `struct derivation_twin {`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `	struct derivation encryption;`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `	struct derivation decryption;`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `static int generate_smb3encryptionkey(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `				      struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `				      const struct derivation_twin *ptwin)`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `	rc = generate_key(conn, sess, ptwin->encryption.label,`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `			  ptwin->encryption.context, sess->smb3encryptionkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `			  SMB3_ENC_DEC_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `	rc = generate_key(conn, sess, ptwin->decryption.label,`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `			  ptwin->decryption.context,`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `			  sess->smb3decryptionkey, SMB3_ENC_DEC_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `	ksmbd_debug(AUTH, "generated encryption keys for session %llu, cipher type %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `		    sess->id, conn->cipher_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `int ksmbd_gen_smb30_encryptionkey(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `				  struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `	struct derivation_twin twin;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `	struct derivation *d;`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `	d = &twin.encryption;`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	d->label.iov_base = "SMB2AESCCM";`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `	d->label.iov_len = 11;`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `	d->context.iov_base = "ServerOut";`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `	d->context.iov_len = 10;`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `	d = &twin.decryption;`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `	d->label.iov_base = "SMB2AESCCM";`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `	d->label.iov_len = 11;`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `	d->context.iov_base = "ServerIn ";`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `	d->context.iov_len = 10;`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `	return generate_smb3encryptionkey(conn, sess, &twin);`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `int ksmbd_gen_smb311_encryptionkey(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `				   struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `	struct derivation_twin twin;`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `	struct derivation *d;`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `	d = &twin.encryption;`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `	d->label.iov_base = "SMBS2CCipherKey";`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `	d->label.iov_len = 16;`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `	d->context.iov_base = sess->Preauth_HashValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `	d->context.iov_len = 64;`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `	d = &twin.decryption;`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `	d->label.iov_base = "SMBC2SCipherKey";`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	d->label.iov_len = 16;`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `	d->context.iov_base = sess->Preauth_HashValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `	d->context.iov_len = 64;`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `	return generate_smb3encryptionkey(conn, sess, &twin);`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `int ksmbd_gen_preauth_integrity_hash(struct ksmbd_conn *conn, char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `				     __u8 *pi_hash)`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `	struct smb2_hdr *rcv_hdr = smb2_get_msg(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [PROTO_GATE|] `	char *all_bytes_msg = (char *)&rcv_hdr->ProtocolId;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01536 [NONE] `	int msg_size = get_rfc1002_len(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `	struct ksmbd_crypto_ctx *ctx = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `	if (msg_size < sizeof(struct smb2_hdr) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	    msg_size > MAX_STREAM_PROT_LEN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [ERROR_PATH|] `		pr_err("Invalid preauth message size: %d\n", msg_size);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01542 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01543 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	if (conn->preauth_info->Preauth_HashId !=`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [PROTO_GATE|] `	    SMB2_PREAUTH_INTEGRITY_SHA512)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01547 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01548 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `	ctx = ksmbd_crypto_ctx_find_sha512();`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] `		ksmbd_debug(AUTH, "could not alloc sha512\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01553 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `	rc = crypto_shash_init(CRYPTO_SHA512(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `		ksmbd_debug(AUTH, "could not init shash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01559 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `	rc = crypto_shash_update(CRYPTO_SHA512(ctx), pi_hash, 64);`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `		ksmbd_debug(AUTH, "could not update with n\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01565 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `	rc = crypto_shash_update(CRYPTO_SHA512(ctx), all_bytes_msg, msg_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] `		ksmbd_debug(AUTH, "could not update with n\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01571 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `	rc = crypto_shash_final(CRYPTO_SHA512(ctx), pi_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `		ksmbd_debug(AUTH, "Could not generate hash err : %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01577 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `int ksmbd_gen_sd_hash(struct ksmbd_conn *conn, char *sd_buf, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `		      __u8 *pi_hash)`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `	struct ksmbd_crypto_ctx *ctx = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `	ctx = ksmbd_crypto_ctx_find_sha256();`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `		ksmbd_debug(AUTH, "could not alloc sha256\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01593 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `	rc = crypto_shash_init(CRYPTO_SHA256(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `		ksmbd_debug(AUTH, "could not init shash\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01599 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `	rc = crypto_shash_update(CRYPTO_SHA256(ctx), sd_buf, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `		ksmbd_debug(AUTH, "could not update with n\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01605 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `	rc = crypto_shash_final(CRYPTO_SHA256(ctx), pi_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `		ksmbd_debug(AUTH, "Could not generate hash err : %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01611 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `static int ksmbd_get_encryption_key(struct ksmbd_work *work, __u64 ses_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `				    int enc, u8 *key)`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `	u8 *ses_enc_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `	if (enc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `		sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `		 * Use ksmbd_session_lookup() (not _all) so that`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `		 * expired sessions can still be used for decryption.`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `		 * After logoff, the session state is EXPIRED but the`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `		 * decryption key is still valid.  This allows in-flight`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `		 * encrypted requests to be decrypted and processed,`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [PROTO_GATE|] `		 * returning STATUS_USER_SESSION_DELETED via the normal`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01633 [NONE] `		 * session check path.`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `		sess = ksmbd_session_lookup(work->conn, ses_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `	if (!sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01639 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `	ses_enc_key = enc ? sess->smb3encryptionkey :`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `		sess->smb3decryptionkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [MEM_BOUNDS|] `	memcpy(key, ses_enc_key, SMB3_ENC_DEC_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01643 [NONE] `	if (!enc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `		ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `static inline void smb2_sg_set_buf(struct scatterlist *sg, const void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `				   unsigned int buflen)`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `	void *addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `	if (is_vmalloc_addr(buf))`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `		addr = vmalloc_to_page(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `		addr = virt_to_page(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `	sg_set_page(sg, addr, buflen, offset_in_page(buf));`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `static struct scatterlist *ksmbd_init_sg(struct kvec *iov, unsigned int nvec,`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `					 u8 *sign)`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `	struct scatterlist *sg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 20;`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `	int i, *nr_entries, total_entries = 0, sg_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `	if (!nvec)`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `	nr_entries = kcalloc(nvec, sizeof(int), KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `	if (!nr_entries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `	for (i = 0; i < nvec - 1; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `		unsigned long kaddr = (unsigned long)iov[i + 1].iov_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `		if (is_vmalloc_addr(iov[i + 1].iov_base)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `			nr_entries[i] = ((kaddr + iov[i + 1].iov_len +`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [NONE] `					PAGE_SIZE - 1) >> PAGE_SHIFT) -`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] `				(kaddr >> PAGE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `			nr_entries[i]++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [MEM_BOUNDS|] `		if (check_add_overflow(total_entries, nr_entries[i],`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01686 [NONE] `				       &total_entries)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `			kfree(nr_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `			return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `	/* Add two entries for transform header and signature */`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [MEM_BOUNDS|] `	if (check_add_overflow(total_entries, 2, &total_entries)) {`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01694 [NONE] `		kfree(nr_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `	sg = kmalloc_array(total_entries, sizeof(struct scatterlist),`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `			   KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `	if (!sg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `		kfree(nr_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `	sg_init_table(sg, total_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `	if (sg_idx >= total_entries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [ERROR_PATH|] `		goto err_free_sg;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01708 [NONE] `	smb2_sg_set_buf(&sg[sg_idx++], iov[0].iov_base + 24, assoc_data_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `	for (i = 0; i < nvec - 1; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `		void *data = iov[i + 1].iov_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `		int len = iov[i + 1].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `		if (is_vmalloc_addr(data)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `			int j, offset = offset_in_page(data);`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `			for (j = 0; j < nr_entries[i]; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `				unsigned int bytes = PAGE_SIZE - offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `				if (!len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `				if (bytes > len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `					bytes = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `				if (sg_idx >= total_entries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [ERROR_PATH|] `					goto err_free_sg;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01727 [NONE] `				sg_set_page(&sg[sg_idx++],`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `					    vmalloc_to_page(data), bytes,`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `					    offset_in_page(data));`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `				data += bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `				len -= bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `				offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `			if (sg_idx >= total_entries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [ERROR_PATH|] `				goto err_free_sg;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01738 [NONE] `			sg_set_page(&sg[sg_idx++], virt_to_page(data), len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] `				    offset_in_page(data));`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `	if (sg_idx >= total_entries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [ERROR_PATH|] `		goto err_free_sg;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01744 [PROTO_GATE|] `	smb2_sg_set_buf(&sg[sg_idx], sign, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01745 [NONE] `	kfree(nr_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `	return sg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `err_free_sg:`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `	kfree(sg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `	kfree(nr_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `int ksmbd_crypt_message(struct ksmbd_work *work, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `			unsigned int nvec, int enc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `	struct smb2_transform_hdr *tr_hdr = smb2_get_msg(iov[0].iov_base);`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 20;`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `	struct scatterlist *sg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [PROTO_GATE|] `	u8 sign[SMB2_SIGNATURE_SIZE] = {};`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01763 [NONE] `	u8 key[SMB3_ENC_DEC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `	struct aead_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `	char *iv;`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `	unsigned int iv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `	struct crypto_aead *tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `	unsigned int crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `	rc = ksmbd_get_encryption_key(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `				      le64_to_cpu(tr_hdr->SessionId),`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `				      enc,`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `				      key);`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [ERROR_PATH|] `		pr_err("Could not get %scryption key\n", enc ? "en" : "de");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01777 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [PROTO_GATE|] `	if (conn->cipher_type == SMB2_ENCRYPTION_AES128_GCM ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01781 [PROTO_GATE|] `	    conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01782 [NONE] `		ctx = ksmbd_crypto_ctx_find_gcm();`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `		ctx = ksmbd_crypto_ctx_find_ccm();`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [ERROR_PATH|] `		pr_err("crypto alloc failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01787 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01788 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [PROTO_GATE|] `	if (conn->cipher_type == SMB2_ENCRYPTION_AES128_GCM ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01791 [PROTO_GATE|] `	    conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01792 [NONE] `		tfm = CRYPTO_GCM(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `		tfm = CRYPTO_CCM(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [PROTO_GATE|] `	if (conn->cipher_type == SMB2_ENCRYPTION_AES256_CCM ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01797 [PROTO_GATE|] `	    conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01798 [NONE] `		rc = crypto_aead_setkey(tfm, key, SMB3_GCM256_CRYPTKEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `		rc = crypto_aead_setkey(tfm, key, SMB3_GCM128_CRYPTKEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [ERROR_PATH|] `		pr_err("Failed to set aead key %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01803 [ERROR_PATH|] `		goto free_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01804 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [PROTO_GATE|] `	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01807 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [ERROR_PATH|] `		pr_err("Failed to set authsize %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01809 [ERROR_PATH|] `		goto free_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01810 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `	req = aead_request_alloc(tfm, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `	if (!req) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [ERROR_PATH|] `		goto free_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01816 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `	if (!enc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(sign, &tr_hdr->Signature, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01820 [PROTO_GATE|] `		crypt_len += SMB2_SIGNATURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01821 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `	sg = ksmbd_init_sg(iov, nvec, sign);`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `	if (!sg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [ERROR_PATH|] `		pr_err("Failed to init sg\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01826 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [ERROR_PATH|] `		goto free_req;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01828 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `	iv_len = crypto_aead_ivsize(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [MEM_BOUNDS|] `	iv = kzalloc(iv_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01832 [NONE] `	if (!iv) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [ERROR_PATH|] `		goto free_sg;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01835 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [PROTO_GATE|] `	if (conn->cipher_type == SMB2_ENCRYPTION_AES128_GCM ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01838 [PROTO_GATE|] `	    conn->cipher_type == SMB2_ENCRYPTION_AES256_GCM) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01839 [MEM_BOUNDS|] `		memcpy(iv, (char *)tr_hdr->Nonce, SMB3_AES_GCM_NONCE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01840 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `		 * I.5 (GCM path): The GCM nonce counter is incremented and`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `		 * monitored in fill_transform_hdr() (smb2_pdu_common.c) using`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `		 * sess->gcm_nonce_counter.  No additional tracking needed here.`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `		 * I.5: AES-CCM nonce birthday bound monitoring.`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `		 * CCM uses a random 11-byte nonce per message.  The birthday-`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `		 * bound collision probability reaches 2^-32 after ~2^44 messages`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `		 * with the same session key (per NIST SP 800-38C and MS-SMB2).`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `		 * We track CCM nonce usage using sess->gcm_nonce_counter (which`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `		 * is only incremented for GCM in smb2_pdu_common.c, so it is`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `		 * safe to reuse for CCM counting when the cipher is CCM).`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `		 * On the encrypt path (enc=1), increment the counter and warn`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `		 * when approaching the birthday bound.`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `		if (enc && work->sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `			u64 cnt = (u64)atomic64_inc_return(`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `					&work->sess->gcm_nonce_counter);`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `			if (cnt >= (1ULL << 44))`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [ERROR_PATH|] `				pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01865 [NONE] `					"ksmbd: AES-CCM nonce counter near birthday bound for session %llu (count=%llu)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `					work->sess->id, cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `		iv[0] = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [MEM_BOUNDS|] `		memcpy(iv + 1, (char *)tr_hdr->Nonce, SMB3_AES_CCM_NONCE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01870 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `	aead_request_set_crypt(req, sg, sg, crypt_len, iv);`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `	aead_request_set_ad(req, assoc_data_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `	if (enc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] `		rc = crypto_aead_encrypt(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `		rc = crypto_aead_decrypt(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [ERROR_PATH|] `		goto free_iv;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01882 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `	if (enc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(&tr_hdr->Signature, sign, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01885 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `free_iv:`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `	memzero_explicit(iv, iv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `	kfree(iv);`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `free_sg:`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `	kfree(sg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `free_req:`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `	aead_request_free(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `free_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `	memzero_explicit(key, sizeof(key));`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `	memzero_explicit(sign, sizeof(sign));`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] ` * smb2_encrypt_resp_if_needed - Encrypt SMB2 response if session requires it`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] ` * @work: ksmbd_work for the current request/response`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] ` * This helper is called from interim/async response paths that bypass the`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] ` * main __handle_ksmbd_work() encryption gate.  It checks whether the`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] ` * session has encryption active and, if so, calls smb3_encrypt_resp().`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] ` * The per-session encryption flag (sess->enc) is set when encryption keys`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] ` * were generated during SESSION_SETUP and the global SMB2 encryption flag`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] ` * is enabled.  When both conditions are met, all responses on that session`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] ` * must be encrypted.`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] ` * Returns 0 if no encryption is needed or encryption succeeds;`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] ` * negative errno on encryption failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `int smb2_encrypt_resp_if_needed(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `	if (!work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `	if (!work->sess->enc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `	return smb3_encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `EXPORT_SYMBOL_GPL(smb2_encrypt_resp_if_needed);`
  Review: Low-risk line; verify in surrounding control flow.
