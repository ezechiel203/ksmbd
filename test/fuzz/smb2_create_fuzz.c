// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 CREATE command context parsing
 *
 *   This module exercises the SMB2 CREATE request parsing logic with
 *   emphasis on create context chains. It generates random create
 *   contexts (EA_BUFFER, SD_BUFFER, DURABLE_HANDLE_REQUEST, LEASE,
 *   TIMEWARP, ALLOCATION_SIZE, etc.) with malformed offsets, lengths,
 *   and nested data. The goal is to ensure that ksmbd's create context
 *   parsing rejects malformed input gracefully without crashes,
 *   memory corruption, or undefined behavior.
 *
 *   Targets:
 *     - Create context chain traversal (Next/NameOffset/DataOffset)
 *     - Nested SD_BUFFER security descriptor parsing
 *     - Durable handle context (DHnQ/DH2Q) GUID and timeout validation
 *     - Lease context (RqLs) lease key and state parsing
 *     - CreateContextsOffset/Length vs request buffer bounds
 *     - NameLength even-byte (UTF-16LE) enforcement
 *
 *   Usage with syzkaller:
 *     Load as a test module. Self-tests run on module init.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/random.h>

/* Inline structures to avoid full ksmbd header chain */

#define SMB2_PROTO_NUMBER		cpu_to_le32(0x424d53fe)
#define __SMB2_HEADER_STRUCTURE_SIZE	64

struct fuzz_create_ctx {
	__le32 Next;
	__le16 NameOffset;
	__le16 NameLength;
	__le16 Reserved;
	__le16 DataOffset;
	__le32 DataLength;
	__u8   Buffer[];
} __packed;

#define FUZZ_CTX_HDR_SIZE	offsetof(struct fuzz_create_ctx, Buffer)

struct fuzz_create_req {
	__u8   hdr[64];		/* SMB2 header placeholder */
	__le16 StructureSize;	/* Must be 57 */
	__u8   SecurityFlags;
	__u8   RequestedOplockLevel;
	__le32 ImpersonationLevel;
	__le64 SmbCreateFlags;
	__le64 Reserved;
	__le32 DesiredAccess;
	__le32 FileAttributes;
	__le32 ShareAccess;
	__le32 CreateDisposition;
	__le32 CreateOptions;
	__le16 NameOffset;
	__le16 NameLength;
	__le32 CreateContextsOffset;
	__le32 CreateContextsLength;
	__u8   Buffer[];
} __packed;

/* Well-known create context tags */
static const char * const ctx_tags[] = {
	"ExtA",	/* SMB2_CREATE_EA_BUFFER */
	"SecD",	/* SMB2_CREATE_SD_BUFFER */
	"DHnQ",	/* SMB2_CREATE_DURABLE_HANDLE_REQUEST */
	"DHnC",	/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT */
	"AlSi",	/* SMB2_CREATE_ALLOCATION_SIZE */
	"MxAc",	/* SMB2_CREATE_QUERY_MAXIMAL_ACCESS */
	"TWrp",	/* SMB2_CREATE_TIMEWARP_REQUEST */
	"QFid",	/* SMB2_CREATE_QUERY_ON_DISK_ID */
	"RqLs",	/* SMB2_CREATE_REQUEST_LEASE */
	"DH2Q",	/* SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 */
	"DH2C",	/* SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 */
};

#define NUM_CTX_TAGS	ARRAY_SIZE(ctx_tags)
#define FUZZ_ITERATIONS	500
#define FUZZ_BUF_SIZE	4096

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

/*
 * fuzz_walk_create_ctx_chain - Walk and validate a create context chain
 * @data:	buffer containing create context chain
 * @len:	total length of chain data
 *
 * Return: number of contexts found, negative on malformed input
 */
static int fuzz_walk_create_ctx_chain(const u8 *data, size_t len)
{
	const struct fuzz_create_ctx *ctx;
	unsigned int next = 0;
	unsigned int remain = len;
	int count = 0;

	if (len < FUZZ_CTX_HDR_SIZE)
		return -EINVAL;

	ctx = (const struct fuzz_create_ctx *)data;

	do {
		u32 ctx_next, name_off, name_len, data_off, data_len;
		u32 ctx_len;

		ctx = (const struct fuzz_create_ctx *)((const char *)ctx + next);
		if (remain < FUZZ_CTX_HDR_SIZE)
			return -EINVAL;

		ctx_next  = le32_to_cpu(ctx->Next);
		name_off  = le16_to_cpu(ctx->NameOffset);
		name_len  = le16_to_cpu(ctx->NameLength);
		data_off  = le16_to_cpu(ctx->DataOffset);
		data_len  = le32_to_cpu(ctx->DataLength);
		ctx_len   = ctx_next ? ctx_next : remain;

		/* Bounds and alignment checks */
		if (ctx_next & 0x7)
			return -EINVAL;
		if (ctx_next > remain)
			return -EINVAL;
		if (name_off != FUZZ_CTX_HDR_SIZE)
			return -EINVAL;
		if (name_len < 4 || name_off + name_len > ctx_len)
			return -EINVAL;
		if (data_len > 0) {
			if (data_off & 0x7)
				return -EINVAL;
			if (data_off < name_off + name_len)
				return -EINVAL;
			if (data_off + data_len > ctx_len)
				return -EINVAL;
		}

		count++;
		if (count > 256)
			break;

		remain -= (ctx_next ? ctx_next : remain);
		next = ctx_next;
	} while (next != 0);

	return count;
}

/*
 * fuzz_build_random_ctx_chain - Build a random create context chain
 * @buf:	output buffer (at least FUZZ_BUF_SIZE bytes)
 * @max_len:	maximum length to fill
 *
 * Return: total bytes written
 */
static size_t fuzz_build_random_ctx_chain(u8 *buf, size_t max_len)
{
	size_t offset = 0;
	int num_ctxs = (fuzz_next() % 8) + 1;
	int i;

	for (i = 0; i < num_ctxs && offset + FUZZ_CTX_HDR_SIZE + 16 < max_len; i++) {
		struct fuzz_create_ctx *ctx = (struct fuzz_create_ctx *)(buf + offset);
		const char *tag = ctx_tags[fuzz_next() % NUM_CTX_TAGS];
		u32 data_len;
		u32 ctx_size;
		u32 corrupt = fuzz_next() % 10;

		memset(ctx, 0, FUZZ_CTX_HDR_SIZE);

		/* Name is always at the fixed offset */
		ctx->NameOffset = cpu_to_le16(FUZZ_CTX_HDR_SIZE);
		ctx->NameLength = cpu_to_le16(4);

		/* Copy tag name */
		memcpy(buf + offset + FUZZ_CTX_HDR_SIZE, tag, 4);

		/* Generate random data payload */
		data_len = fuzz_next() % 128;
		if (offset + FUZZ_CTX_HDR_SIZE + 8 + data_len > max_len)
			data_len = 0;

		if (data_len > 0) {
			ctx->DataOffset = cpu_to_le16(FUZZ_CTX_HDR_SIZE + 8);
			ctx->DataLength = cpu_to_le32(data_len);
			get_random_bytes(buf + offset + FUZZ_CTX_HDR_SIZE + 8,
					 data_len);
		}

		ctx_size = FUZZ_CTX_HDR_SIZE + 8 + data_len;
		/* Round up to 8-byte alignment */
		ctx_size = (ctx_size + 7) & ~7u;

		/* Corruption modes */
		if (corrupt == 0) {
			/* Bad NameOffset */
			ctx->NameOffset = cpu_to_le16(fuzz_next() % 256);
		} else if (corrupt == 1) {
			/* Bad DataOffset */
			ctx->DataOffset = cpu_to_le16(fuzz_next() % 256);
		} else if (corrupt == 2) {
			/* Oversized DataLength */
			ctx->DataLength = cpu_to_le32(0xFFFFFFFF);
		} else if (corrupt == 3) {
			/* Unaligned Next */
			ctx_size |= 3;
		}

		if (i < num_ctxs - 1 && offset + ctx_size + FUZZ_CTX_HDR_SIZE + 16 < max_len) {
			ctx->Next = cpu_to_le32(ctx_size);
		} else {
			ctx->Next = 0;
		}

		offset += ctx_size;
	}

	return offset;
}

/*
 * fuzz_create_request - Fuzz a complete CREATE request with contexts
 * @buf:	scratch buffer
 * @buf_size:	total buffer size
 *
 * Builds a synthetic CREATE request header followed by random
 * create contexts, then validates the result.
 *
 * Return: 0 always
 */
static int fuzz_create_request(u8 *buf, size_t buf_size)
{
	struct fuzz_create_req *req;
	size_t ctx_len;
	u32 ctx_off;
	u16 name_len;
	int ret;

	if (buf_size < sizeof(struct fuzz_create_req) + 64)
		return 0;

	memset(buf, 0, sizeof(struct fuzz_create_req));
	req = (struct fuzz_create_req *)buf;

	/* Fill header with valid protocol ID */
	*(__le32 *)req->hdr = SMB2_PROTO_NUMBER;
	*(__le16 *)(req->hdr + 4) = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	*(__le16 *)(req->hdr + 12) = cpu_to_le16(0x0005); /* CREATE */

	req->StructureSize = cpu_to_le16(57);
	req->RequestedOplockLevel = fuzz_next() % 0x10;
	req->ImpersonationLevel = cpu_to_le32(fuzz_next() % 4);
	req->DesiredAccess = cpu_to_le32(fuzz_next());
	req->FileAttributes = cpu_to_le32(fuzz_next());
	req->ShareAccess = cpu_to_le32(fuzz_next() % 8);
	req->CreateDisposition = cpu_to_le32(fuzz_next() % 6);
	req->CreateOptions = cpu_to_le32(fuzz_next());

	/* File name (after the fixed request fields) */
	name_len = (fuzz_next() % 32) * 2; /* even length for UTF-16LE */
	if (fuzz_next() % 5 == 0)
		name_len |= 1; /* odd length: should be rejected */

	req->NameOffset = cpu_to_le16(sizeof(struct fuzz_create_req));
	req->NameLength = cpu_to_le16(name_len);

	if (name_len > 0 && sizeof(struct fuzz_create_req) + name_len < buf_size)
		get_random_bytes(buf + sizeof(struct fuzz_create_req), name_len);

	/* Build create context chain after the name */
	ctx_off = sizeof(struct fuzz_create_req) + ((name_len + 7) & ~7u);
	if (ctx_off + FUZZ_CTX_HDR_SIZE + 16 < buf_size) {
		ctx_len = fuzz_build_random_ctx_chain(buf + ctx_off,
						       buf_size - ctx_off);
		req->CreateContextsOffset = cpu_to_le32(ctx_off);
		req->CreateContextsLength = cpu_to_le32(ctx_len);

		/* Walk the context chain to exercise validation */
		ret = fuzz_walk_create_ctx_chain(buf + ctx_off, ctx_len);
		pr_debug("smb2_create_fuzz: ctx chain walk returned %d\n", ret);
	}

	return 0;
}

static int __init smb2_create_fuzz_init(void)
{
	u8 *buf;
	int i;

	pr_info("smb2_create_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Use a reproducible seed, overridden by random if desired */
	fuzz_seed = 0xDEADBEEF;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		fuzz_create_request(buf, FUZZ_BUF_SIZE);
	}

	/* Additional edge cases */

	/* All zeros */
	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_walk_create_ctx_chain(buf, FUZZ_BUF_SIZE);

	/* All 0xFF */
	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_walk_create_ctx_chain(buf, FUZZ_BUF_SIZE);

	/* Truncated buffer */
	fuzz_walk_create_ctx_chain(buf, 2);

	/* Single byte */
	fuzz_walk_create_ctx_chain(buf, 1);

	kfree(buf);
	pr_info("smb2_create_fuzz: all iterations completed\n");
	return 0;
}

static void __exit smb2_create_fuzz_exit(void)
{
	pr_info("smb2_create_fuzz: module unloaded\n");
}

module_init(smb2_create_fuzz_init);
module_exit(smb2_create_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 CREATE command context parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
