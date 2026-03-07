# Line-by-line Review: src/include/fs/ksmbd_branchcache.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
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
- L00007 [NONE] ` *   Implements Content Information retrieval for FSCTL_SRV_READ_HASH,`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   enabling peer-to-peer content caching in branch offices per MS-PCCRC.`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#ifndef __KSMBD_BRANCHCACHE_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#define __KSMBD_BRANCHCACHE_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `/* SRV_READ_HASH constants per MS-SMB2 section 2.2.31.2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define SRV_HASH_VER_1			0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define SRV_HASH_VER_2			0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define SRV_HASH_TYPE_PEER_DIST		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define SRV_HASH_RETRIEVE_HASH_BASED	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define SRV_HASH_RETRIEVE_FILE_BASED	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `/* MS-PCCRC segment size: 64KB per block/segment for hashing */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define PCCRC_SEGMENT_SIZE		(64 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `/* SHA-256 digest output size in bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define PCCRC_V1_HASH_SIZE		32`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `/* Read buffer size for kernel_read() during hashing */`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define PCCRC_READ_BUF_SIZE		4096`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` * SRV_READ_HASH request structure (MS-SMB2 2.2.31.2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * This is the input buffer within FSCTL_SRV_READ_HASH.`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `struct srv_read_hash_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	__le32 HashType;		/* Must be SRV_HASH_TYPE_PEER_DIST */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	__le32 HashVersion;		/* SRV_HASH_VER_1 or SRV_HASH_VER_2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	__le32 HashRetrievalType;	/* FILE_BASED or HASH_BASED */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	__le32 Length;			/* Length of data range to hash */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	__le64 Offset;			/* Starting offset in file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * SRV_HASH_RETRIEVE_FILE_BASED response header (MS-SMB2 2.2.32.4.1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * Followed by the Content Information data (MS-PCCRC format).`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `struct srv_read_hash_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	__le64 Offset;			/* Offset of content info in file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	__le32 BufferLength;		/* Length of Content Information */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	__u8   Buffer[];		/* Content Information (PCCRC) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` * Content Information Data Structure Version 1 header (MS-PCCRC 2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * This precedes the segment hash array in the response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `struct pccrc_content_info_v1 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	__le16 Version;			/* 0x0100 for V1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	__le16 Padding;			/* Must be zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__le32 HashAlgo;		/* 0x0000800C = SHA-256 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__le32 Padding2;		/* Must be zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	__le32 dwOffsetInFirstSegment;	/* Offset in first segment */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	__le32 dwReadBytesInLastSegment;/* Bytes to read in last segment */`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	__le32 cSegments;		/* Number of segments */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	/* Followed by: segment descriptions, then segment hashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * Segment description entry for V1 content info (MS-PCCRC 2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `struct pccrc_segment_desc_v1 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	__le64 ullOffsetInContent;	/* Offset of segment in content */`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	__le32 cbSegment;		/* Length of segment in bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	__le32 cbBlockSize;		/* Block size (PCCRC_SEGMENT_SIZE) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	u8     SegmentHashOfData[32];	/* SHA-256 HoD of segment */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	u8     SegmentSecret[32];	/* HMAC-SHA256(Ks, HoD) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` * ksmbd_branchcache_read_hash - Handle FSCTL_SRV_READ_HASH request`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * @work:	ksmbd work structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * @fp:		file pointer for the target file`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * @in_buf:	input buffer (srv_read_hash_req)`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * @in_len:	input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * @out_buf:	output buffer for response`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * @out_len:	available output buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` * Computes content hashes for the requested file range and returns`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * Content Information per MS-PCCRC specification.`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` * Return: number of bytes written to out_buf on success, negative errno`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` *         on failure. Special return values:`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ` *         -EOPNOTSUPP: unsupported hash version or type`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ` *         -EINVAL: invalid request parameters`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `int ksmbd_branchcache_read_hash(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `				const void *in_buf, unsigned int in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `				void *out_buf, unsigned int out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * ksmbd_branchcache_generate_secret - Generate random server secret`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * Must be called once during module initialization to populate`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * the HMAC-SHA256 server secret key with random bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `void ksmbd_branchcache_generate_secret(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * ksmbd_branchcache_invalidate - Invalidate cached hashes for a file`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * @fp:		file pointer whose cached hashes should be cleared`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * Called on write operations to ensure stale hash data is not served.`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `void ksmbd_branchcache_invalidate(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `#endif /* __KSMBD_BRANCHCACHE_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
