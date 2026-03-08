// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   BranchCache (MS-PCCRC) content information support for ksmbd
 *
 *   Copyright (C) 2024
 *
 *   Implements FSCTL_SRV_READ_HASH for Content Information Version 1 (V1)
 *   using SHA-256 hashing over 64KB segments, per MS-PCCRC specification.
 *   Hash results are cached in file extended attributes to avoid recomputation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/overflow.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <crypto/hash.h>

#include "glob.h"
#include "smb2pdu.h"
#include "ksmbd_branchcache.h"
#include "crypto_ctx.h"
#include "vfs_cache.h"
#include "vfs.h"

/* xattr names for cached BranchCache hashes */
#define XATTR_PCCRC_V1_NAME	"user.ksmbd.pccrc.v1"

/*
 * Server secret (Ks) for HMAC-SHA256 segment secret computation.
 * Per MS-PCCRC, SegmentSecret = HMAC-SHA256(Ks, HoD).
 * Generated at module init via get_random_bytes() to avoid a
 * hardcoded key that would be identical across all deployments.
 *
 * Security note: The server secret is rotated periodically via a
 * delayed_work timer (default: every 24 hours). When the secret
 * is rotated, all cached xattr hashes become stale and will be
 * recomputed on the next FSCTL_SRV_READ_HASH request (the mtime
 * check in try_load_cached_hashes serves as the invalidation
 * mechanism, since the server secret used to compute segment
 * secrets will differ).
 */
static u8 pccrc_server_secret[PCCRC_V1_HASH_SIZE];
static time64_t pccrc_secret_generated_at;
static DEFINE_MUTEX(pccrc_secret_lock);

/* Default rotation interval: 24 hours */
#define PCCRC_SECRET_ROTATION_INTERVAL	(86400 * HZ)

static struct delayed_work pccrc_secret_rotation_work;

static void pccrc_rotate_secret(struct work_struct *work)
{
	mutex_lock(&pccrc_secret_lock);
	get_random_bytes(pccrc_server_secret, sizeof(pccrc_server_secret));
	pccrc_secret_generated_at = ktime_get_real_seconds();
	mutex_unlock(&pccrc_secret_lock);

	pr_info("branchcache: server secret rotated\n");

	/* Schedule next rotation */
	schedule_delayed_work(&pccrc_secret_rotation_work,
			      PCCRC_SECRET_ROTATION_INTERVAL);
}

void ksmbd_branchcache_generate_secret(void)
{
	get_random_bytes(pccrc_server_secret, sizeof(pccrc_server_secret));
	pccrc_secret_generated_at = ktime_get_real_seconds();

	/* Start periodic secret rotation */
	INIT_DELAYED_WORK(&pccrc_secret_rotation_work, pccrc_rotate_secret);
	schedule_delayed_work(&pccrc_secret_rotation_work,
			      PCCRC_SECRET_ROTATION_INTERVAL);
}

/**
 * ksmbd_branchcache_cleanup - Stop secret rotation timer
 *
 * Must be called during module cleanup to cancel the periodic
 * secret rotation delayed_work.
 */
void ksmbd_branchcache_cleanup(void)
{
	cancel_delayed_work_sync(&pccrc_secret_rotation_work);
}

/* MS-PCCRC V1 hash algorithm identifier (SHA-256) per MS-PCCRC */
#define PCCRC_V1_HASH_ALGO	0x0000800C

/* MS-PCCRC V1 content info version field value */
#define PCCRC_V1_VERSION	0x0100

/*
 * Cache header stored in xattr, followed by hash data.
 * Used to validate cached hashes against file modification time.
 */
struct pccrc_cache_header {
	__le64 mtime_sec;	/* file mtime seconds at cache time */
	__le32 mtime_nsec;	/* file mtime nanoseconds at cache time */
	__le64 file_size;	/* file size at cache time */
	__le64 hash_offset;	/* starting offset for the hashed range */
	__le32 hash_length;	/* length of the hashed range */
	__le32 num_segments;	/* number of cached segment hashes */
	/* Followed by: num_segments * PCCRC_V1_HASH_SIZE bytes of hashes */
} __packed;

/**
 * compute_block_hash - Compute SHA-256 hash of a single 64KB block
 * @filp:	kernel file pointer
 * @offset:	starting offset of the block
 * @length:	number of bytes in this block (<= PCCRC_SEGMENT_SIZE)
 * @read_buf:	pre-allocated read buffer (PCCRC_READ_BUF_SIZE)
 * @hash_out:	output buffer for the 32-byte SHA-256 digest
 *
 * Return: 0 on success, negative errno on failure
 */
static int compute_block_hash(struct file *filp, loff_t offset,
			      size_t length, u8 *read_buf, u8 *hash_out)
{
	struct ksmbd_crypto_ctx *ctx;
	loff_t pos = offset;
	size_t remaining = length;
	int rc;

	ctx = ksmbd_crypto_ctx_find_sha256();
	if (!ctx) {
		pr_err("branchcache: failed to allocate SHA-256 context\n");
		return -ENOMEM;
	}

	rc = crypto_shash_init(CRYPTO_SHA256(ctx));
	if (rc) {
		pr_err("branchcache: SHA-256 init failed: %d\n", rc);
		goto out_ctx;
	}

	while (remaining > 0) {
		size_t to_read = min_t(size_t, remaining, PCCRC_READ_BUF_SIZE);
		ssize_t nread;

		nread = kernel_read(filp, read_buf, to_read, &pos);
		if (nread < 0) {
			rc = (int)nread;
			pr_err("branchcache: file read failed at offset %lld: %d\n",
			       pos, rc);
			goto out_ctx;
		}
		if (nread == 0)
			break;

		rc = crypto_shash_update(CRYPTO_SHA256(ctx), read_buf, nread);
		if (rc) {
			pr_err("branchcache: SHA-256 update failed: %d\n", rc);
			goto out_ctx;
		}

		remaining -= nread;
	}

	rc = crypto_shash_final(CRYPTO_SHA256(ctx), hash_out);
	if (rc)
		pr_err("branchcache: SHA-256 final failed: %d\n", rc);

out_ctx:
	ksmbd_release_crypto_ctx(ctx);
	return rc;
}

/**
 * compute_segment_hash_v1 - Compute HoD for a file segment (two-level hash)
 * @filp:	kernel file pointer
 * @offset:	starting offset of the segment
 * @length:	number of bytes to hash in this segment
 * @hash_out:	output buffer for the 32-byte SHA-256 HoD digest
 *
 * Per MS-PCCRC, HoD is computed as:
 *   1. For each 64KB block: BlockHash = SHA-256(block_data)
 *   2. HoD = SHA-256(BlockHash1 || BlockHash2 || ... || BlockHashN)
 *
 * Return: 0 on success, negative errno on failure
 */
static int compute_segment_hash_v1(struct file *filp, loff_t offset,
				   size_t length, u8 *hash_out)
{
	struct ksmbd_crypto_ctx *ctx;
	u8 *read_buf;
	u8 block_hash[PCCRC_V1_HASH_SIZE];
	unsigned int num_blocks;
	unsigned int i;
	int rc;

	num_blocks = DIV_ROUND_UP(length, PCCRC_SEGMENT_SIZE);
	if (num_blocks == 0)
		num_blocks = 1;

	read_buf = kmalloc(PCCRC_READ_BUF_SIZE, KSMBD_DEFAULT_GFP);
	if (!read_buf)
		return -ENOMEM;

	/*
	 * Step 1 & 2: Compute each block hash and feed into outer SHA-256.
	 * Instead of allocating a BlockHashList array, we incrementally
	 * update the outer hash with each block hash as it is computed.
	 */
	ctx = ksmbd_crypto_ctx_find_sha256();
	if (!ctx) {
		pr_err("branchcache: failed to allocate SHA-256 context for HoD\n");
		rc = -ENOMEM;
		goto out_buf;
	}

	rc = crypto_shash_init(CRYPTO_SHA256(ctx));
	if (rc) {
		pr_err("branchcache: HoD SHA-256 init failed: %d\n", rc);
		goto out_ctx;
	}

	for (i = 0; i < num_blocks; i++) {
		loff_t blk_offset = offset + (loff_t)i * PCCRC_SEGMENT_SIZE;
		size_t blk_len = min_t(size_t,
				       PCCRC_SEGMENT_SIZE,
				       length - (size_t)i * PCCRC_SEGMENT_SIZE);

		/* Step 1: BlockHash = SHA-256(block_data) */
		rc = compute_block_hash(filp, blk_offset, blk_len,
					read_buf, block_hash);
		if (rc)
			goto out_ctx;

		/* Feed block hash into outer HoD computation */
		rc = crypto_shash_update(CRYPTO_SHA256(ctx),
					 block_hash, PCCRC_V1_HASH_SIZE);
		if (rc) {
			pr_err("branchcache: HoD update failed: %d\n", rc);
			goto out_ctx;
		}
	}

	/* Step 2: HoD = SHA-256(BlockHash1 || ... || BlockHashN) */
	rc = crypto_shash_final(CRYPTO_SHA256(ctx), hash_out);
	if (rc)
		pr_err("branchcache: HoD final failed: %d\n", rc);

out_ctx:
	ksmbd_release_crypto_ctx(ctx);
out_buf:
	kfree(read_buf);
	return rc;
}

/**
 * compute_segment_secret_v1 - Compute segment secret via HMAC-SHA256
 * @segment_hash:	32-byte HoD (hash of data) for the segment
 * @secret_out:		output buffer for 32-byte segment secret
 *
 * Per MS-PCCRC, SegmentSecret = HMAC-SHA256(Ks, HoD) where Ks is a
 * server secret key. This ensures the secret is not trivially derivable
 * from the publicly shared HoD.
 *
 * Return: 0 on success, negative errno on failure
 */
static int compute_segment_secret_v1(const u8 *segment_hash, u8 *secret_out)
{
	struct ksmbd_crypto_ctx *ctx;
	int rc;

	ctx = ksmbd_crypto_ctx_find_hmacsha256();
	if (!ctx) {
		pr_err("branchcache: failed to allocate HMAC-SHA256 context\n");
		return -ENOMEM;
	}

	rc = crypto_shash_setkey(CRYPTO_HMACSHA256_TFM(ctx),
				 pccrc_server_secret, PCCRC_V1_HASH_SIZE);
	if (rc) {
		pr_err("branchcache: HMAC-SHA256 setkey failed: %d\n", rc);
		goto out;
	}

	rc = crypto_shash_init(CRYPTO_HMACSHA256(ctx));
	if (rc) {
		pr_err("branchcache: HMAC-SHA256 init failed: %d\n", rc);
		goto out;
	}

	rc = crypto_shash_update(CRYPTO_HMACSHA256(ctx), segment_hash,
				 PCCRC_V1_HASH_SIZE);
	if (rc) {
		pr_err("branchcache: HMAC-SHA256 update failed: %d\n", rc);
		goto out;
	}

	rc = crypto_shash_final(CRYPTO_HMACSHA256(ctx), secret_out);
	if (rc)
		pr_err("branchcache: HMAC-SHA256 final failed: %d\n", rc);
out:
	ksmbd_release_crypto_ctx(ctx);
	return rc;
}

/**
 * get_file_mtime - Retrieve the modification time of a file
 * @filp:	kernel file pointer
 * @sec:	output for mtime seconds
 * @nsec:	output for mtime nanoseconds
 */
static void get_file_mtime(struct file *filp, u64 *sec, u32 *nsec)
{
	struct inode *inode = file_inode(filp);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	*sec = inode_get_mtime(inode).tv_sec;
	*nsec = inode_get_mtime(inode).tv_nsec;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	*sec = inode_get_mtime(inode).tv_sec;
	*nsec = inode_get_mtime(inode).tv_nsec;
#else
	*sec = inode->i_mtime.tv_sec;
	*nsec = inode->i_mtime.tv_nsec;
#endif
}

/**
 * try_load_cached_hashes - Attempt to load cached segment hashes from xattr
 * @fp:			ksmbd file pointer
 * @offset:		starting offset of the hashed range
 * @length:		length of the hashed range
 * @num_segments:	expected number of segments
 * @hashes:		output buffer for segment hashes (pre-allocated)
 *
 * Checks the pccrc xattr cache for valid hash data. Validates that
 * file mtime, size, offset, and length match the cached values.
 *
 * Return: 0 on success (cache hit), negative errno on failure (cache miss)
 */
static int try_load_cached_hashes(struct ksmbd_file *fp, loff_t offset,
				  u32 length, unsigned int num_segments,
				  u8 *hashes)
{
	struct file *filp = fp->filp;
	struct dentry *dentry = filp->f_path.dentry;
	struct pccrc_cache_header *cache_hdr;
	char *xattr_buf = NULL;
	ssize_t xattr_len;
	size_t expected_len;
	u64 mtime_sec;
	u32 mtime_nsec;
	loff_t file_size;
	int rc = -ENODATA;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(filp),
					dentry, XATTR_PCCRC_V1_NAME,
					&xattr_buf);
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(filp),
					dentry, XATTR_PCCRC_V1_NAME,
					&xattr_buf);
#endif
	if (xattr_len <= 0 || !xattr_buf)
		return -ENODATA;

	if ((size_t)xattr_len < sizeof(struct pccrc_cache_header)) {
		rc = -EINVAL;
		goto out;
	}

	cache_hdr = (struct pccrc_cache_header *)xattr_buf;

	/* Validate segment count matches expectation */
	if (le32_to_cpu(cache_hdr->num_segments) != num_segments) {
		rc = -EINVAL;
		goto out;
	}

	expected_len = sizeof(struct pccrc_cache_header) +
		       (size_t)num_segments * PCCRC_V1_HASH_SIZE;
	if ((size_t)xattr_len < expected_len) {
		rc = -EINVAL;
		goto out;
	}

	/* Validate mtime and file size to detect modifications */
	get_file_mtime(filp, &mtime_sec, &mtime_nsec);
	file_size = i_size_read(file_inode(filp));

	if (le64_to_cpu(cache_hdr->mtime_sec) != mtime_sec ||
	    le32_to_cpu(cache_hdr->mtime_nsec) != mtime_nsec ||
	    le64_to_cpu(cache_hdr->file_size) != (u64)file_size ||
	    le64_to_cpu(cache_hdr->hash_offset) != (u64)offset ||
	    le32_to_cpu(cache_hdr->hash_length) != length) {
		rc = -ESTALE;
		goto out;
	}

	/* Cache hit: copy the hash data */
	memcpy(hashes, xattr_buf + sizeof(struct pccrc_cache_header),
	       (size_t)num_segments * PCCRC_V1_HASH_SIZE);
	rc = 0;

out:
	kfree(xattr_buf);
	return rc;
}

/**
 * save_cached_hashes - Store computed segment hashes in xattr cache
 * @fp:			ksmbd file pointer
 * @offset:		starting offset of the hashed range
 * @length:		length of the hashed range
 * @num_segments:	number of segments
 * @hashes:		segment hash data to cache
 *
 * Stores segment hashes along with file mtime, size, offset, and length
 * for validation.
 *
 * Return: 0 on success, negative errno on failure (non-fatal)
 */
static int save_cached_hashes(struct ksmbd_file *fp, loff_t offset,
			      u32 length, unsigned int num_segments,
			      const u8 *hashes)
{
	struct file *filp = fp->filp;
	struct pccrc_cache_header *cache_hdr;
	size_t cache_size;
	u64 mtime_sec;
	u32 mtime_nsec;
	int rc;

	cache_size = sizeof(struct pccrc_cache_header) +
		     (size_t)num_segments * PCCRC_V1_HASH_SIZE;

	cache_hdr = kzalloc(cache_size, KSMBD_DEFAULT_GFP);
	if (!cache_hdr)
		return -ENOMEM;

	get_file_mtime(filp, &mtime_sec, &mtime_nsec);

	cache_hdr->mtime_sec = cpu_to_le64(mtime_sec);
	cache_hdr->mtime_nsec = cpu_to_le32(mtime_nsec);
	cache_hdr->file_size = cpu_to_le64(i_size_read(file_inode(filp)));
	cache_hdr->hash_offset = cpu_to_le64(offset);
	cache_hdr->hash_length = cpu_to_le32(length);
	cache_hdr->num_segments = cpu_to_le32(num_segments);

	memcpy((u8 *)cache_hdr + sizeof(struct pccrc_cache_header),
	       hashes, (size_t)num_segments * PCCRC_V1_HASH_SIZE);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	rc = ksmbd_vfs_setxattr(file_mnt_idmap(filp),
				&filp->f_path, XATTR_PCCRC_V1_NAME,
				cache_hdr, cache_size, 0, true);
#else
	rc = ksmbd_vfs_setxattr(file_mnt_user_ns(filp),
				&filp->f_path, XATTR_PCCRC_V1_NAME,
				cache_hdr, cache_size, 0, true);
#endif

	kfree(cache_hdr);
	return rc;
}

/**
 * compute_file_hashes_v1 - Compute SHA-256 hashes for file segments
 * @fp:			ksmbd file pointer
 * @offset:		starting offset in file
 * @length:		number of bytes to hash
 * @hashes:		output buffer for hash data (pre-allocated)
 * @num_segments:	number of segments to hash
 *
 * Computes SHA-256 hashes for each 64KB segment within the specified range.
 * Attempts to load from xattr cache first; computes and caches on miss.
 *
 * Return: 0 on success, negative errno on failure
 */
static int compute_file_hashes_v1(struct ksmbd_file *fp, loff_t offset,
				  u32 length, u8 *hashes,
				  unsigned int num_segments)
{
	struct file *filp = fp->filp;
	loff_t file_size;
	unsigned int i;
	int rc;

	/* Try loading from xattr cache first */
	rc = try_load_cached_hashes(fp, offset, length, num_segments, hashes);
	if (rc == 0) {
		ksmbd_debug(VFS, "branchcache: using cached hashes\n");
		return 0;
	}

	file_size = i_size_read(file_inode(filp));

	for (i = 0; i < num_segments; i++) {
		loff_t seg_offset = offset + (loff_t)i * PCCRC_SEGMENT_SIZE;
		size_t seg_len = PCCRC_SEGMENT_SIZE;

		/* Clamp last segment to actual data length */
		if (seg_offset + seg_len > offset + length)
			seg_len = offset + length - seg_offset;
		if (seg_offset + seg_len > file_size)
			seg_len = file_size - seg_offset;

		rc = compute_segment_hash_v1(filp, seg_offset, seg_len,
					     hashes + i * PCCRC_V1_HASH_SIZE);
		if (rc)
			return rc;
	}

	/* Cache the computed hashes (best effort, ignore failures) */
	save_cached_hashes(fp, offset, length, num_segments, hashes);

	return 0;
}

/**
 * build_content_info_v1 - Build MS-PCCRC V1 Content Information response
 * @fp:		ksmbd file pointer
 * @offset:	starting offset in file
 * @length:	length of data range
 * @out_buf:	output buffer
 * @out_len:	available output buffer length
 *
 * Constructs the Content Information Data Structure Version 1 per MS-PCCRC
 * section 2.3. The structure contains a header followed by segment
 * descriptions (each with a hash-of-data and a segment secret).
 *
 * Return: number of bytes written on success, negative errno on failure
 */
static int build_content_info_v1(struct ksmbd_file *fp, loff_t offset,
				 u32 length, void *out_buf,
				 unsigned int out_len)
{
	struct srv_read_hash_rsp *rsp_hdr;
	struct pccrc_content_info_v1 *ci;
	struct pccrc_segment_desc_v1 *seg;
	u8 *segment_hashes = NULL;
	unsigned int num_segments;
	unsigned int first_seg_offset;
	unsigned int last_seg_bytes;
	size_t ci_size;
	size_t total_size;
	unsigned int i;
	int rc;

	/* Calculate number of segments for the requested range */
	num_segments = DIV_ROUND_UP(length, PCCRC_SEGMENT_SIZE);
	if (num_segments == 0)
		num_segments = 1;

	/* Offset within the first segment */
	first_seg_offset = offset % PCCRC_SEGMENT_SIZE;

	/* Bytes to read in the last segment */
	last_seg_bytes = length - (num_segments - 1) * PCCRC_SEGMENT_SIZE;
	if (last_seg_bytes == 0)
		last_seg_bytes = PCCRC_SEGMENT_SIZE;

	/* Calculate total response size */
	ci_size = sizeof(struct pccrc_content_info_v1) +
		  (size_t)num_segments * sizeof(struct pccrc_segment_desc_v1);
	total_size = sizeof(struct srv_read_hash_rsp) + ci_size;

	if (total_size > out_len) {
		ksmbd_debug(SMB, "branchcache: output buffer too small (%u < %zu)\n",
			    out_len, total_size);
		return -E2BIG;
	}

	/* Compute segment hashes */
	{
		size_t hash_alloc_size;

		if (check_mul_overflow((size_t)num_segments,
				       (size_t)PCCRC_V1_HASH_SIZE,
				       &hash_alloc_size))
			return -EOVERFLOW;
		segment_hashes = kvzalloc(hash_alloc_size,
					  KSMBD_DEFAULT_GFP);
	}
	if (!segment_hashes)
		return -ENOMEM;

	rc = compute_file_hashes_v1(fp, offset, length, segment_hashes,
				    num_segments);
	if (rc) {
		kvfree(segment_hashes);
		return rc;
	}

	/* Build the SRV_READ_HASH response header */
	memset(out_buf, 0, total_size);
	rsp_hdr = (struct srv_read_hash_rsp *)out_buf;
	rsp_hdr->Offset = cpu_to_le64(offset);
	rsp_hdr->BufferLength = cpu_to_le32(ci_size);

	/* Build the Content Information V1 header */
	ci = (struct pccrc_content_info_v1 *)(rsp_hdr->Buffer);
	ci->Version = cpu_to_le16(PCCRC_V1_VERSION);
	ci->Padding = 0;
	ci->HashAlgo = cpu_to_le32(PCCRC_V1_HASH_ALGO);
	ci->Padding2 = 0;
	ci->dwOffsetInFirstSegment = cpu_to_le32(first_seg_offset);
	ci->dwReadBytesInLastSegment = cpu_to_le32(last_seg_bytes);
	ci->cSegments = cpu_to_le32(num_segments);

	/* Build segment descriptions */
	seg = (struct pccrc_segment_desc_v1 *)((u8 *)ci +
			sizeof(struct pccrc_content_info_v1));

	for (i = 0; i < num_segments; i++) {
		u8 *hash = segment_hashes + i * PCCRC_V1_HASH_SIZE;
		u8 secret[PCCRC_V1_HASH_SIZE];
		loff_t seg_offset = offset + (loff_t)i * PCCRC_SEGMENT_SIZE;
		u32 seg_len = PCCRC_SEGMENT_SIZE;

		/* Clamp last segment length */
		if (seg_offset + seg_len > offset + length)
			seg_len = (u32)(offset + length - seg_offset);

		seg[i].ullOffsetInContent = cpu_to_le64(seg_offset);
		seg[i].cbSegment = cpu_to_le32(seg_len);
		seg[i].cbBlockSize = cpu_to_le32(PCCRC_SEGMENT_SIZE);

		/* Copy segment hash of data (HoD) */
		memcpy(seg[i].SegmentHashOfData, hash, PCCRC_V1_HASH_SIZE);

		/* Compute segment secret = HMAC-SHA256(Ks, HoD) */
		rc = compute_segment_secret_v1(hash, secret);
		if (rc) {
			kvfree(segment_hashes);
			return rc;
		}
		memcpy(seg[i].SegmentSecret, secret, PCCRC_V1_HASH_SIZE);
	}

	kvfree(segment_hashes);
	return (int)total_size;
}

/**
 * ksmbd_branchcache_read_hash - Handle FSCTL_SRV_READ_HASH
 * @work:	ksmbd work structure
 * @fp:		file pointer for the target file
 * @in_buf:	input buffer containing srv_read_hash_req
 * @in_len:	input buffer length
 * @out_buf:	output buffer for Content Information response
 * @out_len:	available output buffer length
 *
 * Validates the request parameters and dispatches to the appropriate
 * hash version handler. Currently supports V1 (SHA-256) only.
 *
 * Return: number of bytes written to out_buf on success, negative errno
 */
int ksmbd_branchcache_read_hash(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				const void *in_buf, unsigned int in_len,
				void *out_buf, unsigned int out_len)
{
	const struct srv_read_hash_req *req;
	u32 hash_type, hash_version, hash_retrieval;
	u64 length;
	u64 offset;
	loff_t file_size;

	if (in_len < sizeof(struct srv_read_hash_req)) {
		ksmbd_debug(SMB, "branchcache: input buffer too small (%u)\n",
			    in_len);
		return -EINVAL;
	}

	req = (const struct srv_read_hash_req *)in_buf;
	hash_type = le32_to_cpu(req->HashType);
	hash_version = le32_to_cpu(req->HashVersion);
	hash_retrieval = le32_to_cpu(req->HashRetrievalType);
	length = le64_to_cpu(req->Length);
	offset = le64_to_cpu(req->Offset);

	ksmbd_debug(SMB, "branchcache: type=%u ver=%u retrieval=%u "
		    "off=%llu len=%llu\n",
		    hash_type, hash_version, hash_retrieval, offset, length);

	/* Validate HashType - must be SRV_HASH_TYPE_PEER_DIST */
	if (hash_type != SRV_HASH_TYPE_PEER_DIST) {
		ksmbd_debug(SMB, "branchcache: unsupported hash type %u\n",
			    hash_type);
		return -EOPNOTSUPP;
	}

	/* Validate HashVersion - only V1 supported */
	if (hash_version != SRV_HASH_VER_1) {
		ksmbd_debug(SMB, "branchcache: unsupported hash version %u\n",
			    hash_version);
		return -EOPNOTSUPP;
	}

	/*
	 * Validate HashRetrievalType.
	 * We support FILE_BASED retrieval. HASH_BASED would require
	 * a content hash lookup, which is not currently implemented.
	 */
	if (hash_retrieval != SRV_HASH_RETRIEVE_FILE_BASED) {
		ksmbd_debug(SMB, "branchcache: unsupported retrieval type %u\n",
			    hash_retrieval);
		return -EOPNOTSUPP;
	}

	/* Validate range against file size */
	file_size = i_size_read(file_inode(fp->filp));
	if (offset >= (u64)file_size || length == 0) {
		ksmbd_debug(SMB, "branchcache: invalid range off=%llu len=%llu "
			    "filesize=%lld\n", offset, length, file_size);
		return -EINVAL;
	}

	/* Clamp length to file extent */
	if (offset + length > (u64)file_size)
		length = (u64)file_size - offset;
	if (length > U32_MAX)
		length = U32_MAX;

	return build_content_info_v1(fp, (loff_t)offset, (u32)length,
				     out_buf, out_len);
}

/**
 * ksmbd_branchcache_invalidate - Invalidate cached hashes on file write
 * @fp:		ksmbd file pointer whose cache should be cleared
 *
 * Removes the pccrc xattr to force recomputation on next hash request.
 * Failures are silently ignored since cache invalidation is best-effort.
 */
void ksmbd_branchcache_invalidate(struct ksmbd_file *fp)
{
	struct file *filp;

	if (!fp || !fp->filp)
		return;

	filp = fp->filp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ksmbd_vfs_remove_xattr(file_mnt_idmap(filp),
			       &filp->f_path, XATTR_PCCRC_V1_NAME,
			       true);
#else
	ksmbd_vfs_remove_xattr(file_mnt_user_ns(filp),
			       &filp->f_path, XATTR_PCCRC_V1_NAME,
			       true);
#endif
}
