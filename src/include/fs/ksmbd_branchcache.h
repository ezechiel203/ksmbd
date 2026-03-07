/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   BranchCache (MS-PCCRC) content information support for ksmbd
 *
 *   Copyright (C) 2024
 *
 *   Implements Content Information retrieval for FSCTL_SRV_READ_HASH,
 *   enabling peer-to-peer content caching in branch offices per MS-PCCRC.
 */

#ifndef __KSMBD_BRANCHCACHE_H__
#define __KSMBD_BRANCHCACHE_H__

#include <linux/types.h>

struct ksmbd_file;
struct ksmbd_work;

/* SRV_READ_HASH constants per MS-SMB2 section 2.2.31.2 */
#define SRV_HASH_VER_1			0x00000001
#define SRV_HASH_VER_2			0x00000002
#define SRV_HASH_TYPE_PEER_DIST		0x00000001
#define SRV_HASH_RETRIEVE_HASH_BASED	0x00000001
#define SRV_HASH_RETRIEVE_FILE_BASED	0x00000002

/* MS-PCCRC segment size: 64KB per block/segment for hashing */
#define PCCRC_SEGMENT_SIZE		(64 * 1024)

/* SHA-256 digest output size in bytes */
#define PCCRC_V1_HASH_SIZE		32

/* Read buffer size for kernel_read() during hashing */
#define PCCRC_READ_BUF_SIZE		4096

/*
 * SRV_READ_HASH request structure (MS-SMB2 2.2.31.2)
 *
 * This is the input buffer within FSCTL_SRV_READ_HASH.
 */
struct srv_read_hash_req {
	__le32 HashType;		/* Must be SRV_HASH_TYPE_PEER_DIST */
	__le32 HashVersion;		/* SRV_HASH_VER_1 or SRV_HASH_VER_2 */
	__le32 HashRetrievalType;	/* FILE_BASED or HASH_BASED */
	__le32 Length;			/* Length of data range to hash */
	__le64 Offset;			/* Starting offset in file */
} __packed;

/*
 * SRV_HASH_RETRIEVE_FILE_BASED response header (MS-SMB2 2.2.32.4.1)
 *
 * Followed by the Content Information data (MS-PCCRC format).
 */
struct srv_read_hash_rsp {
	__le64 Offset;			/* Offset of content info in file */
	__le32 BufferLength;		/* Length of Content Information */
	__u8   Buffer[];		/* Content Information (PCCRC) */
} __packed;

/*
 * Content Information Data Structure Version 1 header (MS-PCCRC 2.3)
 *
 * This precedes the segment hash array in the response.
 */
struct pccrc_content_info_v1 {
	__le16 Version;			/* 0x0100 for V1 */
	__le16 Padding;			/* Must be zero */
	__le32 HashAlgo;		/* 0x0000800C = SHA-256 */
	__le32 Padding2;		/* Must be zero */
	__le32 dwOffsetInFirstSegment;	/* Offset in first segment */
	__le32 dwReadBytesInLastSegment;/* Bytes to read in last segment */
	__le32 cSegments;		/* Number of segments */
	/* Followed by: segment descriptions, then segment hashes */
} __packed;

/*
 * Segment description entry for V1 content info (MS-PCCRC 2.3)
 */
struct pccrc_segment_desc_v1 {
	__le64 ullOffsetInContent;	/* Offset of segment in content */
	__le32 cbSegment;		/* Length of segment in bytes */
	__le32 cbBlockSize;		/* Block size (PCCRC_SEGMENT_SIZE) */
	u8     SegmentHashOfData[32];	/* SHA-256 HoD of segment */
	u8     SegmentSecret[32];	/* HMAC-SHA256(Ks, HoD) */
} __packed;

/**
 * ksmbd_branchcache_read_hash - Handle FSCTL_SRV_READ_HASH request
 * @work:	ksmbd work structure
 * @fp:		file pointer for the target file
 * @in_buf:	input buffer (srv_read_hash_req)
 * @in_len:	input buffer length
 * @out_buf:	output buffer for response
 * @out_len:	available output buffer length
 *
 * Computes content hashes for the requested file range and returns
 * Content Information per MS-PCCRC specification.
 *
 * Return: number of bytes written to out_buf on success, negative errno
 *         on failure. Special return values:
 *         -EOPNOTSUPP: unsupported hash version or type
 *         -EINVAL: invalid request parameters
 */
int ksmbd_branchcache_read_hash(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				const void *in_buf, unsigned int in_len,
				void *out_buf, unsigned int out_len);

/**
 * ksmbd_branchcache_generate_secret - Generate random server secret
 *
 * Must be called once during module initialization to populate
 * the HMAC-SHA256 server secret key with random bytes.
 */
void ksmbd_branchcache_generate_secret(void);

/**
 * ksmbd_branchcache_cleanup - Stop periodic secret rotation
 *
 * Must be called during module cleanup to cancel the delayed_work
 * timer that rotates the BranchCache server secret.
 */
void ksmbd_branchcache_cleanup(void);

/**
 * ksmbd_branchcache_invalidate - Invalidate cached hashes for a file
 * @fp:		file pointer whose cached hashes should be cleared
 *
 * Called on write operations to ensure stale hash data is not served.
 */
void ksmbd_branchcache_invalidate(struct ksmbd_file *fp);

#endif /* __KSMBD_BRANCHCACHE_H__ */
