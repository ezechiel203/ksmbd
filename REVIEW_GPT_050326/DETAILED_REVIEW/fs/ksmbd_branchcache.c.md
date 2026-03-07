# Line-by-line Review: src/fs/ksmbd_branchcache.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   BranchCache (MS-PCCRC) content information support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Copyright (C) 2024`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   Implements FSCTL_SRV_READ_HASH for Content Information Version 1 (V1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   using SHA-256 hashing over 64KB segments, per MS-PCCRC specification.`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   Hash results are cached in file extended attributes to avoid recomputation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/xattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/random.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/ktime.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <crypto/hash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "ksmbd_branchcache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "crypto_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `/* xattr names for cached BranchCache hashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define XATTR_PCCRC_V1_NAME	"user.ksmbd.pccrc.v1"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * Server secret (Ks) for HMAC-SHA256 segment secret computation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * Per MS-PCCRC, SegmentSecret = HMAC-SHA256(Ks, HoD).`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * Generated at module init via get_random_bytes() to avoid a`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * hardcoded key that would be identical across all deployments.`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * Security note: This secret is generated once at module load and`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * never rotated during the lifetime of the module.  A long-lived`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * server secret increases the window for offline brute-force`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * attacks against the HMAC key.  In production deployments the`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * module should be periodically reloaded, or a rotation mechanism`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * should be implemented that regenerates the secret and invalidates`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * all cached hashes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * TODO: Implement periodic secret rotation (e.g. via a timer or`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * a configurable rotation interval) and bulk-invalidate cached`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * xattr hashes when the secret changes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `static u8 pccrc_server_secret[PCCRC_V1_HASH_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `static time64_t pccrc_secret_generated_at;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `void ksmbd_branchcache_generate_secret(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	get_random_bytes(pccrc_server_secret, sizeof(pccrc_server_secret));`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	pccrc_secret_generated_at = ktime_get_real_seconds();`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `/* MS-PCCRC V1 hash algorithm identifier (SHA-256) per MS-PCCRC */`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#define PCCRC_V1_HASH_ALGO	0x0000800C`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/* MS-PCCRC V1 content info version field value */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#define PCCRC_V1_VERSION	0x0100`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * Cache header stored in xattr, followed by hash data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * Used to validate cached hashes against file modification time.`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `struct pccrc_cache_header {`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	__le64 mtime_sec;	/* file mtime seconds at cache time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	__le32 mtime_nsec;	/* file mtime nanoseconds at cache time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	__le64 file_size;	/* file size at cache time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	__le64 hash_offset;	/* starting offset for the hashed range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	__le32 hash_length;	/* length of the hashed range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	__le32 num_segments;	/* number of cached segment hashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	/* Followed by: num_segments * PCCRC_V1_HASH_SIZE bytes of hashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * compute_block_hash - Compute SHA-256 hash of a single 64KB block`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * @filp:	kernel file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * @offset:	starting offset of the block`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * @length:	number of bytes in this block (<= PCCRC_SEGMENT_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` * @read_buf:	pre-allocated read buffer (PCCRC_READ_BUF_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` * @hash_out:	output buffer for the 32-byte SHA-256 digest`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `static int compute_block_hash(struct file *filp, loff_t offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `			      size_t length, u8 *read_buf, u8 *hash_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	loff_t pos = offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	size_t remaining = length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	ctx = ksmbd_crypto_ctx_find_sha256();`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [ERROR_PATH|] `		pr_err("branchcache: failed to allocate SHA-256 context\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00099 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00100 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	rc = crypto_shash_init(CRYPTO_SHA256(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [ERROR_PATH|] `		pr_err("branchcache: SHA-256 init failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00105 [ERROR_PATH|] `		goto out_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00106 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	while (remaining > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `		size_t to_read = min_t(size_t, remaining, PCCRC_READ_BUF_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `		ssize_t nread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `		nread = kernel_read(filp, read_buf, to_read, &pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		if (nread < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `			rc = (int)nread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [ERROR_PATH|] `			pr_err("branchcache: file read failed at offset %lld: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00116 [NONE] `			       pos, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [ERROR_PATH|] `			goto out_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00118 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		if (nread == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		rc = crypto_shash_update(CRYPTO_SHA256(ctx), read_buf, nread);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [ERROR_PATH|] `			pr_err("branchcache: SHA-256 update failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00125 [ERROR_PATH|] `			goto out_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00126 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		remaining -= nread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	rc = crypto_shash_final(CRYPTO_SHA256(ctx), hash_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [ERROR_PATH|] `		pr_err("branchcache: SHA-256 final failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `out_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * compute_segment_hash_v1 - Compute HoD for a file segment (two-level hash)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` * @filp:	kernel file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * @offset:	starting offset of the segment`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` * @length:	number of bytes to hash in this segment`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` * @hash_out:	output buffer for the 32-byte SHA-256 HoD digest`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * Per MS-PCCRC, HoD is computed as:`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` *   1. For each 64KB block: BlockHash = SHA-256(block_data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` *   2. HoD = SHA-256(BlockHash1 || BlockHash2 || ... || BlockHashN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `static int compute_segment_hash_v1(struct file *filp, loff_t offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `				   size_t length, u8 *hash_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	u8 *read_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	u8 block_hash[PCCRC_V1_HASH_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	unsigned int num_blocks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	num_blocks = DIV_ROUND_UP(length, PCCRC_SEGMENT_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	if (num_blocks == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		num_blocks = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [MEM_BOUNDS|] `	read_buf = kmalloc(PCCRC_READ_BUF_SIZE, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00168 [NONE] `	if (!read_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	 * Step 1 & 2: Compute each block hash and feed into outer SHA-256.`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	 * Instead of allocating a BlockHashList array, we incrementally`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	 * update the outer hash with each block hash as it is computed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	ctx = ksmbd_crypto_ctx_find_sha256();`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [ERROR_PATH|] `		pr_err("branchcache: failed to allocate SHA-256 context for HoD\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00179 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [ERROR_PATH|] `		goto out_buf;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00181 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	rc = crypto_shash_init(CRYPTO_SHA256(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [ERROR_PATH|] `		pr_err("branchcache: HoD SHA-256 init failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00186 [ERROR_PATH|] `		goto out_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	for (i = 0; i < num_blocks; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		loff_t blk_offset = offset + (loff_t)i * PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		size_t blk_len = min_t(size_t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `				       PCCRC_SEGMENT_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `				       length - (size_t)i * PCCRC_SEGMENT_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		/* Step 1: BlockHash = SHA-256(block_data) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		rc = compute_block_hash(filp, blk_offset, blk_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `					read_buf, block_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [ERROR_PATH|] `			goto out_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		/* Feed block hash into outer HoD computation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		rc = crypto_shash_update(CRYPTO_SHA256(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `					 block_hash, PCCRC_V1_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [ERROR_PATH|] `			pr_err("branchcache: HoD update failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00206 [ERROR_PATH|] `			goto out_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00207 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	/* Step 2: HoD = SHA-256(BlockHash1 || ... || BlockHashN) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	rc = crypto_shash_final(CRYPTO_SHA256(ctx), hash_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [ERROR_PATH|] `		pr_err("branchcache: HoD final failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `out_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `out_buf:`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	kfree(read_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` * compute_segment_secret_v1 - Compute segment secret via HMAC-SHA256`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * @segment_hash:	32-byte HoD (hash of data) for the segment`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * @secret_out:		output buffer for 32-byte segment secret`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` * Per MS-PCCRC, SegmentSecret = HMAC-SHA256(Ks, HoD) where Ks is a`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ` * server secret key. This ensures the secret is not trivially derivable`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ` * from the publicly shared HoD.`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `static int compute_segment_secret_v1(const u8 *segment_hash, u8 *secret_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	struct ksmbd_crypto_ctx *ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	ctx = ksmbd_crypto_ctx_find_hmacsha256();`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	if (!ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [ERROR_PATH|] `		pr_err("branchcache: failed to allocate HMAC-SHA256 context\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00241 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00242 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx),`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `				 pccrc_server_secret, PCCRC_V1_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [ERROR_PATH|] `		pr_err("branchcache: HMAC-SHA256 setkey failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00248 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00249 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [ERROR_PATH|] `		pr_err("branchcache: HMAC-SHA256 init failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00254 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00255 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), segment_hash,`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `				 PCCRC_V1_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [ERROR_PATH|] `		pr_err("branchcache: HMAC-SHA256 update failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00261 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00262 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), secret_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [ERROR_PATH|] `		pr_err("branchcache: HMAC-SHA256 final failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00267 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	ksmbd_release_crypto_ctx(ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ` * get_file_mtime - Retrieve the modification time of a file`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ` * @filp:	kernel file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ` * @sec:	output for mtime seconds`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ` * @nsec:	output for mtime nanoseconds`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `static void get_file_mtime(struct file *filp, u64 *sec, u32 *nsec)`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	struct inode *inode = file_inode(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	*sec = inode_get_mtime(inode).tv_sec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	*nsec = inode_get_mtime(inode).tv_nsec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	*sec = inode_get_mtime(inode).tv_sec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	*nsec = inode_get_mtime(inode).tv_nsec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	*sec = inode->i_mtime.tv_sec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	*nsec = inode->i_mtime.tv_nsec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ` * try_load_cached_hashes - Attempt to load cached segment hashes from xattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ` * @fp:			ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ` * @offset:		starting offset of the hashed range`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ` * @length:		length of the hashed range`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ` * @num_segments:	expected number of segments`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` * @hashes:		output buffer for segment hashes (pre-allocated)`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` * Checks the pccrc xattr cache for valid hash data. Validates that`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` * file mtime, size, offset, and length match the cached values.`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ` * Return: 0 on success (cache hit), negative errno on failure (cache miss)`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `static int try_load_cached_hashes(struct ksmbd_file *fp, loff_t offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `				  u32 length, unsigned int num_segments,`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `				  u8 *hashes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	struct file *filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	struct dentry *dentry = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	struct pccrc_cache_header *cache_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	char *xattr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	ssize_t xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	size_t expected_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	u64 mtime_sec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	u32 mtime_nsec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	loff_t file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	int rc = -ENODATA;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `					dentry, XATTR_PCCRC_V1_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `					&xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `					dentry, XATTR_PCCRC_V1_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `					&xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	if (xattr_len <= 0 || !xattr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [ERROR_PATH|] `		return -ENODATA;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	if ((size_t)xattr_len < sizeof(struct pccrc_cache_header)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00337 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	cache_hdr = (struct pccrc_cache_header *)xattr_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	/* Validate segment count matches expectation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	if (le32_to_cpu(cache_hdr->num_segments) != num_segments) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00345 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	expected_len = sizeof(struct pccrc_cache_header) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		       (size_t)num_segments * PCCRC_V1_HASH_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	if ((size_t)xattr_len < expected_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00352 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	/* Validate mtime and file size to detect modifications */`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	get_file_mtime(filp, &mtime_sec, &mtime_nsec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	file_size = i_size_read(file_inode(filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	if (le64_to_cpu(cache_hdr->mtime_sec) != mtime_sec ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	    le32_to_cpu(cache_hdr->mtime_nsec) != mtime_nsec ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	    le64_to_cpu(cache_hdr->file_size) != (u64)file_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	    le64_to_cpu(cache_hdr->hash_offset) != (u64)offset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	    le32_to_cpu(cache_hdr->hash_length) != length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `		rc = -ESTALE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00365 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	/* Cache hit: copy the hash data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [MEM_BOUNDS|] `	memcpy(hashes, xattr_buf + sizeof(struct pccrc_cache_header),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00369 [NONE] `	       (size_t)num_segments * PCCRC_V1_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	kfree(xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ` * save_cached_hashes - Store computed segment hashes in xattr cache`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * @fp:			ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` * @offset:		starting offset of the hashed range`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` * @length:		length of the hashed range`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * @num_segments:	number of segments`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * @hashes:		segment hash data to cache`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` * Stores segment hashes along with file mtime, size, offset, and length`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` * for validation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ` * Return: 0 on success, negative errno on failure (non-fatal)`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `static int save_cached_hashes(struct ksmbd_file *fp, loff_t offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			      u32 length, unsigned int num_segments,`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `			      const u8 *hashes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	struct file *filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	struct pccrc_cache_header *cache_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	size_t cache_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	u64 mtime_sec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	u32 mtime_nsec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	cache_size = sizeof(struct pccrc_cache_header) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		     (size_t)num_segments * PCCRC_V1_HASH_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [MEM_BOUNDS|] `	cache_hdr = kzalloc(cache_size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00405 [NONE] `	if (!cache_hdr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00407 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	get_file_mtime(filp, &mtime_sec, &mtime_nsec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	cache_hdr->mtime_sec = cpu_to_le64(mtime_sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	cache_hdr->mtime_nsec = cpu_to_le32(mtime_nsec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	cache_hdr->file_size = cpu_to_le64(i_size_read(file_inode(filp)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	cache_hdr->hash_offset = cpu_to_le64(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	cache_hdr->hash_length = cpu_to_le32(length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	cache_hdr->num_segments = cpu_to_le32(num_segments);`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [MEM_BOUNDS|] `	memcpy((u8 *)cache_hdr + sizeof(struct pccrc_cache_header),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00418 [NONE] `	       hashes, (size_t)num_segments * PCCRC_V1_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	rc = ksmbd_vfs_setxattr(file_mnt_idmap(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `				&filp->f_path, XATTR_PCCRC_V1_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `				cache_hdr, cache_size, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	rc = ksmbd_vfs_setxattr(file_mnt_user_ns(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `				&filp->f_path, XATTR_PCCRC_V1_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `				cache_hdr, cache_size, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	kfree(cache_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ` * compute_file_hashes_v1 - Compute SHA-256 hashes for file segments`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ` * @fp:			ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ` * @offset:		starting offset in file`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ` * @length:		number of bytes to hash`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ` * @hashes:		output buffer for hash data (pre-allocated)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ` * @num_segments:	number of segments to hash`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ` * Computes SHA-256 hashes for each 64KB segment within the specified range.`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ` * Attempts to load from xattr cache first; computes and caches on miss.`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `static int compute_file_hashes_v1(struct ksmbd_file *fp, loff_t offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `				  u32 length, u8 *hashes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `				  unsigned int num_segments)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	struct file *filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	loff_t file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	/* Try loading from xattr cache first */`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	rc = try_load_cached_hashes(fp, offset, length, num_segments, hashes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	if (rc == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `		ksmbd_debug(VFS, "branchcache: using cached hashes\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	file_size = i_size_read(file_inode(filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	for (i = 0; i < num_segments; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		loff_t seg_offset = offset + (loff_t)i * PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		size_t seg_len = PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `		/* Clamp last segment to actual data length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		if (seg_offset + seg_len > offset + length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `			seg_len = offset + length - seg_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `		if (seg_offset + seg_len > file_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `			seg_len = file_size - seg_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `		rc = compute_segment_hash_v1(filp, seg_offset, seg_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `					     hashes + i * PCCRC_V1_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	/* Cache the computed hashes (best effort, ignore failures) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	save_cached_hashes(fp, offset, length, num_segments, hashes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ` * build_content_info_v1 - Build MS-PCCRC V1 Content Information response`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ` * @offset:	starting offset in file`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ` * @length:	length of data range`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ` * @out_buf:	output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ` * @out_len:	available output buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] ` * Constructs the Content Information Data Structure Version 1 per MS-PCCRC`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] ` * section 2.3. The structure contains a header followed by segment`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ` * descriptions (each with a hash-of-data and a segment secret).`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ` * Return: number of bytes written on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `static int build_content_info_v1(struct ksmbd_file *fp, loff_t offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `				 u32 length, void *out_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `				 unsigned int out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	struct srv_read_hash_rsp *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	struct pccrc_content_info_v1 *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	struct pccrc_segment_desc_v1 *seg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	u8 *segment_hashes = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	unsigned int num_segments;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	unsigned int first_seg_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	unsigned int last_seg_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	size_t ci_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	size_t total_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	/* Calculate number of segments for the requested range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	num_segments = DIV_ROUND_UP(length, PCCRC_SEGMENT_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	if (num_segments == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `		num_segments = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	/* Offset within the first segment */`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	first_seg_offset = offset % PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	/* Bytes to read in the last segment */`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	last_seg_bytes = length - (num_segments - 1) * PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	if (last_seg_bytes == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		last_seg_bytes = PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	/* Calculate total response size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	ci_size = sizeof(struct pccrc_content_info_v1) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `		  (size_t)num_segments * sizeof(struct pccrc_segment_desc_v1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	total_size = sizeof(struct srv_read_hash_rsp) + ci_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	if (total_size > out_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `		ksmbd_debug(SMB, "branchcache: output buffer too small (%u < %zu)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `			    out_len, total_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [ERROR_PATH|] `		return -E2BIG;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00539 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	/* Compute segment hashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `		size_t hash_alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `		if (check_mul_overflow((size_t)num_segments,`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `				       (size_t)PCCRC_V1_HASH_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `				       &hash_alloc_size))`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [ERROR_PATH|] `			return -EOVERFLOW;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00549 [MEM_BOUNDS|] `		segment_hashes = kvzalloc(hash_alloc_size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00550 [NONE] `					  KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	if (!segment_hashes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	rc = compute_file_hashes_v1(fp, offset, length, segment_hashes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `				    num_segments);`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `		kvfree(segment_hashes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	/* Build the SRV_READ_HASH response header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	memset(out_buf, 0, total_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	rsp_hdr = (struct srv_read_hash_rsp *)out_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	rsp_hdr->Offset = cpu_to_le64(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	rsp_hdr->BufferLength = cpu_to_le32(ci_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	/* Build the Content Information V1 header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	ci = (struct pccrc_content_info_v1 *)(rsp_hdr->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	ci->Version = cpu_to_le16(PCCRC_V1_VERSION);`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	ci->Padding = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	ci->HashAlgo = cpu_to_le32(PCCRC_V1_HASH_ALGO);`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	ci->Padding2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	ci->dwOffsetInFirstSegment = cpu_to_le32(first_seg_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	ci->dwReadBytesInLastSegment = cpu_to_le32(last_seg_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	ci->cSegments = cpu_to_le32(num_segments);`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	/* Build segment descriptions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	seg = (struct pccrc_segment_desc_v1 *)((u8 *)ci +`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `			sizeof(struct pccrc_content_info_v1));`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	for (i = 0; i < num_segments; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `		u8 *hash = segment_hashes + i * PCCRC_V1_HASH_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `		u8 secret[PCCRC_V1_HASH_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		loff_t seg_offset = offset + (loff_t)i * PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `		u32 seg_len = PCCRC_SEGMENT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `		/* Clamp last segment length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `		if (seg_offset + seg_len > offset + length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `			seg_len = (u32)(offset + length - seg_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `		seg[i].ullOffsetInContent = cpu_to_le64(seg_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `		seg[i].cbSegment = cpu_to_le32(seg_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		seg[i].cbBlockSize = cpu_to_le32(PCCRC_SEGMENT_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		/* Copy segment hash of data (HoD) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [MEM_BOUNDS|] `		memcpy(seg[i].SegmentHashOfData, hash, PCCRC_V1_HASH_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `		/* Compute segment secret = HMAC-SHA256(Ks, HoD) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `		rc = compute_segment_secret_v1(hash, secret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `			kvfree(segment_hashes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [MEM_BOUNDS|] `		memcpy(seg[i].SegmentSecret, secret, PCCRC_V1_HASH_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00606 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	kvfree(segment_hashes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	return (int)total_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] ` * ksmbd_branchcache_read_hash - Handle FSCTL_SRV_READ_HASH`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] ` * @work:	ksmbd work structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] ` * @fp:		file pointer for the target file`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] ` * @in_buf:	input buffer containing srv_read_hash_req`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] ` * @in_len:	input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] ` * @out_buf:	output buffer for Content Information response`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] ` * @out_len:	available output buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ` * Validates the request parameters and dispatches to the appropriate`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] ` * hash version handler. Currently supports V1 (SHA-256) only.`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ` * Return: number of bytes written to out_buf on success, negative errno`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `int ksmbd_branchcache_read_hash(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `				const void *in_buf, unsigned int in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `				void *out_buf, unsigned int out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	const struct srv_read_hash_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	u32 hash_type, hash_version, hash_retrieval;`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	u32 length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	u64 offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	loff_t file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	if (in_len < sizeof(struct srv_read_hash_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		ksmbd_debug(SMB, "branchcache: input buffer too small (%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `			    in_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00641 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	req = (const struct srv_read_hash_req *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	hash_type = le32_to_cpu(req->HashType);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	hash_version = le32_to_cpu(req->HashVersion);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	hash_retrieval = le32_to_cpu(req->HashRetrievalType);`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	length = le32_to_cpu(req->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	offset = le64_to_cpu(req->Offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	ksmbd_debug(SMB, "branchcache: type=%u ver=%u retrieval=%u "`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `		    "off=%llu len=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		    hash_type, hash_version, hash_retrieval, offset, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	/* Validate HashType - must be SRV_HASH_TYPE_PEER_DIST */`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	if (hash_type != SRV_HASH_TYPE_PEER_DIST) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `		ksmbd_debug(SMB, "branchcache: unsupported hash type %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `			    hash_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00659 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	/* Validate HashVersion - only V1 supported */`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	if (hash_version != SRV_HASH_VER_1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `		ksmbd_debug(SMB, "branchcache: unsupported hash version %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `			    hash_version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00666 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	 * Validate HashRetrievalType.`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	 * We support FILE_BASED retrieval. HASH_BASED would require`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	 * a content hash lookup, which is not currently implemented.`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	if (hash_retrieval != SRV_HASH_RETRIEVE_FILE_BASED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		ksmbd_debug(SMB, "branchcache: unsupported retrieval type %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `			    hash_retrieval);`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00677 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	/* Validate range against file size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	file_size = i_size_read(file_inode(fp->filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	if (offset >= (u64)file_size || length == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `		ksmbd_debug(SMB, "branchcache: invalid range off=%llu len=%u "`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `			    "filesize=%lld\n", offset, length, file_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00685 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	/* Clamp length to file extent */`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	if (offset + length > (u64)file_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `		length = (u32)(file_size - offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	return build_content_info_v1(fp, (loff_t)offset, length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `				     out_buf, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] ` * ksmbd_branchcache_invalidate - Invalidate cached hashes on file write`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ` * @fp:		ksmbd file pointer whose cache should be cleared`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ` * Removes the pccrc xattr to force recomputation on next hash request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] ` * Failures are silently ignored since cache invalidation is best-effort.`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `void ksmbd_branchcache_invalidate(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	if (!fp || !fp->filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	ksmbd_vfs_remove_xattr(file_mnt_idmap(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `			       &filp->f_path, XATTR_PCCRC_V1_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `			       true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	ksmbd_vfs_remove_xattr(file_mnt_user_ns(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `			       &filp->f_path, XATTR_PCCRC_V1_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `			       true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
