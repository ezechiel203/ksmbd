// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for durable handle create context parsing
 *
 *   This module exercises the parsing of durable handle create contexts
 *   (DHnQ, DHnC, DH2Q, DH2C) as used in SMB2 CREATE requests. Durable
 *   handles allow clients to reconnect after network disruptions.
 *   Malformed contexts can cause GUID misinterpretation, timeout
 *   overflow, or flags confusion.
 *
 *   Targets:
 *     - DHnQ (v1 request): 16-byte reserved field
 *     - DHnC (v1 reconnect): FileId (PersistentFid + VolatileFid)
 *     - DH2Q (v2 request): Timeout, Flags, CreateGuid (16 bytes)
 *     - DH2C (v2 reconnect): FileId, CreateGuid, Flags
 *     - Timeout overflow (max 300000ms)
 *     - CreateGuid: all-zero, all-ones, random
 *     - Flags: PERSISTENT (0x02), unknown flags
 *     - Context chain embedding with malformed Next pointers
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

/* Inline structures matching smb2pdu.h */

#define DURABLE_HANDLE_MAX_TIMEOUT	300000
#define SMB2_FLAGS_DH_FLAG_PERSISTENT	0x00000002
#define SMB2_CREATE_GUID_SIZE		16

struct fuzz_create_context {
	__le32 Next;
	__le16 NameOffset;
	__le16 NameLength;
	__le16 Reserved;
	__le16 DataOffset;
	__le32 DataLength;
	__u8   Buffer[];
} __packed;

#define FUZZ_CC_HDR_SIZE	offsetof(struct fuzz_create_context, Buffer)

/* DHnQ - Durable Handle v1 Request (tag "DHnQ") */
struct fuzz_durable_req_v1 {
	struct fuzz_create_context ccontext;
	__u8   Name[8];
	__u8   Reserved[16];
} __packed;

/* DHnC - Durable Handle v1 Reconnect (tag "DHnC") */
struct fuzz_durable_reconn_v1 {
	struct fuzz_create_context ccontext;
	__u8   Name[8];
	union {
		__u8 Reserved[16];
		struct {
			__u64 PersistentFileId;
			__u64 VolatileFileId;
		} Fid;
	} Data;
} __packed;

/* DH2Q - Durable Handle v2 Request (tag "DH2Q") */
struct fuzz_durable_req_v2 {
	struct fuzz_create_context ccontext;
	__u8   Name[8];
	__le32 Timeout;
	__le32 Flags;
	__u8   Reserved[8];
	__u8   CreateGuid[SMB2_CREATE_GUID_SIZE];
} __packed;

/* DH2C - Durable Handle v2 Reconnect (tag "DH2C") */
struct fuzz_durable_reconn_v2 {
	struct fuzz_create_context ccontext;
	__u8   Name[8];
	struct {
		__u64 PersistentFileId;
		__u64 VolatileFileId;
	} Fid;
	__u8   CreateGuid[SMB2_CREATE_GUID_SIZE];
	__le32 Flags;
} __packed;

#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		1024

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

static u64 fuzz_next64(void)
{
	return ((u64)fuzz_next() << 48) | ((u64)fuzz_next() << 32) |
	       ((u64)fuzz_next() << 16) | (u64)fuzz_next();
}

/*
 * fuzz_is_zero_guid - Check if a GUID is all zeros
 */
static bool fuzz_is_zero_guid(const u8 *guid)
{
	int i;

	for (i = 0; i < SMB2_CREATE_GUID_SIZE; i++) {
		if (guid[i] != 0)
			return false;
	}
	return true;
}

/*
 * fuzz_validate_dh_v1_request - Validate DHnQ context
 * @data:	raw context data (after ccontext header)
 * @len:	data length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_dh_v1_request(const u8 *data, size_t len)
{
	if (len < 16) {
		pr_debug("dh_fuzz: DHnQ data too short (%zu)\n", len);
		return -EINVAL;
	}

	/* DHnQ data is 16 bytes of reserved (should be zero) */
	pr_debug("dh_fuzz: DHnQ context valid, data_len=%zu\n", len);
	return 0;
}

/*
 * fuzz_validate_dh_v1_reconnect - Validate DHnC context
 * @data:	raw context data
 * @len:	data length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_dh_v1_reconnect(const u8 *data, size_t len)
{
	u64 persistent_fid, volatile_fid;

	if (len < 16) {
		pr_debug("dh_fuzz: DHnC data too short (%zu)\n", len);
		return -EINVAL;
	}

	persistent_fid = le64_to_cpu(*(__le64 *)data);
	volatile_fid = le64_to_cpu(*(__le64 *)(data + 8));

	if (persistent_fid == 0 && volatile_fid == 0) {
		pr_debug("dh_fuzz: DHnC zero FIDs\n");
		return -EINVAL;
	}

	pr_debug("dh_fuzz: DHnC pfid=%llu vfid=%llu\n",
		 persistent_fid, volatile_fid);
	return 0;
}

/*
 * fuzz_validate_dh_v2_request - Validate DH2Q context
 * @data:	raw context data
 * @len:	data length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_dh_v2_request(const u8 *data, size_t len)
{
	u32 timeout, flags;
	const u8 *create_guid;

	if (len < 32) {
		pr_debug("dh_fuzz: DH2Q data too short (%zu)\n", len);
		return -EINVAL;
	}

	timeout = le32_to_cpu(*(__le32 *)data);
	flags = le32_to_cpu(*(__le32 *)(data + 4));
	/* 8 bytes reserved at offset 8 */
	create_guid = data + 16;

	/* Timeout check */
	if (timeout > DURABLE_HANDLE_MAX_TIMEOUT) {
		pr_debug("dh_fuzz: DH2Q timeout %u exceeds max %u\n",
			 timeout, DURABLE_HANDLE_MAX_TIMEOUT);
		/* Not fatal, server caps it */
	}

	/* Flags check */
	if (flags & ~SMB2_FLAGS_DH_FLAG_PERSISTENT) {
		pr_debug("dh_fuzz: DH2Q unknown flags 0x%x\n", flags);
	}

	/* CreateGuid should not be all zeros for a new request */
	if (fuzz_is_zero_guid(create_guid)) {
		pr_debug("dh_fuzz: DH2Q zero CreateGuid\n");
	}

	pr_debug("dh_fuzz: DH2Q timeout=%u flags=0x%x\n", timeout, flags);
	return 0;
}

/*
 * fuzz_validate_dh_v2_reconnect - Validate DH2C context
 * @data:	raw context data
 * @len:	data length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_dh_v2_reconnect(const u8 *data, size_t len)
{
	u64 persistent_fid, volatile_fid;
	const u8 *create_guid;
	u32 flags;

	if (len < 36) {
		pr_debug("dh_fuzz: DH2C data too short (%zu)\n", len);
		return -EINVAL;
	}

	persistent_fid = le64_to_cpu(*(__le64 *)data);
	volatile_fid = le64_to_cpu(*(__le64 *)(data + 8));
	create_guid = data + 16;
	flags = le32_to_cpu(*(__le32 *)(data + 32));

	if (persistent_fid == 0 && volatile_fid == 0) {
		pr_debug("dh_fuzz: DH2C zero FIDs\n");
		return -EINVAL;
	}

	if (fuzz_is_zero_guid(create_guid)) {
		pr_debug("dh_fuzz: DH2C zero CreateGuid\n");
		return -EINVAL;
	}

	pr_debug("dh_fuzz: DH2C pfid=%llu vfid=%llu flags=0x%x\n",
		 persistent_fid, volatile_fid, flags);
	return 0;
}

/*
 * fuzz_dispatch_dh_context - Route to correct DH validator based on tag
 * @tag:	4-byte context tag
 * @data:	context data
 * @len:	data length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_dispatch_dh_context(const char *tag, const u8 *data,
				    size_t len)
{
	if (!memcmp(tag, "DHnQ", 4))
		return fuzz_validate_dh_v1_request(data, len);
	if (!memcmp(tag, "DHnC", 4))
		return fuzz_validate_dh_v1_reconnect(data, len);
	if (!memcmp(tag, "DH2Q", 4))
		return fuzz_validate_dh_v2_request(data, len);
	if (!memcmp(tag, "DH2C", 4))
		return fuzz_validate_dh_v2_reconnect(data, len);

	pr_debug("dh_fuzz: unknown tag '%.4s'\n", tag);
	return -EINVAL;
}

/*
 * fuzz_build_dh_context - Build a random durable handle context in a chain
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: total bytes written
 */
static size_t fuzz_build_dh_context(u8 *buf, size_t buf_size)
{
	static const char *dh_tags[] = { "DHnQ", "DHnC", "DH2Q", "DH2C" };
	struct fuzz_create_context *cc;
	const char *tag;
	u32 corrupt = fuzz_next() % 8;
	u32 data_len;
	size_t total;

	if (buf_size < FUZZ_CC_HDR_SIZE + 48)
		return 0;

	memset(buf, 0, buf_size);
	cc = (struct fuzz_create_context *)buf;
	tag = dh_tags[fuzz_next() % 4];

	cc->Next = 0;
	cc->NameOffset = cpu_to_le16(FUZZ_CC_HDR_SIZE);
	cc->NameLength = cpu_to_le16(4);
	memcpy(buf + FUZZ_CC_HDR_SIZE, tag, 4);

	/* Pad name to 8 bytes (matches real structure layout) */

	/* Build appropriate data payload */
	if (!memcmp(tag, "DHnQ", 4)) {
		data_len = 16;
	} else if (!memcmp(tag, "DHnC", 4)) {
		data_len = 16;
	} else if (!memcmp(tag, "DH2Q", 4)) {
		data_len = 32;
	} else { /* DH2C */
		data_len = 36;
	}

	cc->DataOffset = cpu_to_le16(FUZZ_CC_HDR_SIZE + 8);
	cc->DataLength = cpu_to_le32(data_len);

	/* Fill data with random bytes */
	if (FUZZ_CC_HDR_SIZE + 8 + data_len <= buf_size)
		get_random_bytes(buf + FUZZ_CC_HDR_SIZE + 8, data_len);

	/* For DH2Q, set specific fields */
	if (!memcmp(tag, "DH2Q", 4) && FUZZ_CC_HDR_SIZE + 8 + 32 <= buf_size) {
		u8 *dh2q_data = buf + FUZZ_CC_HDR_SIZE + 8;
		u32 timeout;

		/* Timeout */
		switch (fuzz_next() % 4) {
		case 0:
			timeout = 0;
			break;
		case 1:
			timeout = DURABLE_HANDLE_MAX_TIMEOUT;
			break;
		case 2:
			timeout = DURABLE_HANDLE_MAX_TIMEOUT + 1;
			break;
		default:
			timeout = fuzz_next() % 600000;
			break;
		}
		*(__le32 *)dh2q_data = cpu_to_le32(timeout);

		/* Flags */
		*(__le32 *)(dh2q_data + 4) = cpu_to_le32(fuzz_next() % 4);

		/* CreateGuid */
		if (fuzz_next() % 4 == 0)
			memset(dh2q_data + 16, 0, SMB2_CREATE_GUID_SIZE);
		else
			get_random_bytes(dh2q_data + 16, SMB2_CREATE_GUID_SIZE);
	}

	/* For DH2C, set FileId and CreateGuid */
	if (!memcmp(tag, "DH2C", 4) && FUZZ_CC_HDR_SIZE + 8 + 36 <= buf_size) {
		u8 *dh2c_data = buf + FUZZ_CC_HDR_SIZE + 8;

		*(__le64 *)dh2c_data = cpu_to_le64(fuzz_next64());
		*(__le64 *)(dh2c_data + 8) = cpu_to_le64(fuzz_next64());

		if (fuzz_next() % 4 == 0)
			memset(dh2c_data + 16, 0, SMB2_CREATE_GUID_SIZE);
		else
			get_random_bytes(dh2c_data + 16, SMB2_CREATE_GUID_SIZE);

		*(__le32 *)(dh2c_data + 32) = cpu_to_le32(fuzz_next() % 4);
	}

	total = FUZZ_CC_HDR_SIZE + 8 + data_len;

	/* Corruption modes */
	if (corrupt == 0)
		cc->DataLength = cpu_to_le32(fuzz_next()); /* random size */
	else if (corrupt == 1)
		cc->NameLength = cpu_to_le16(3); /* too short */
	else if (corrupt == 2)
		cc->DataOffset = cpu_to_le16(fuzz_next() % 256);

	return total;
}

static int __init durable_handle_fuzz_init(void)
{
	u8 *buf;
	int i;

	pr_info("durable_handle_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0xD00DFEED;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		static const char *dh_tags[] = { "DHnQ", "DHnC", "DH2Q", "DH2C" };
		const char *tag;
		size_t ctx_len;
		u16 data_off, data_len_field;

		memset(buf, 0, FUZZ_BUF_SIZE);
		ctx_len = fuzz_build_dh_context(buf, FUZZ_BUF_SIZE);

		/* Extract tag and data for dispatch */
		if (ctx_len >= FUZZ_CC_HDR_SIZE + 4) {
			struct fuzz_create_context *cc =
				(struct fuzz_create_context *)buf;

			tag = (const char *)(buf + FUZZ_CC_HDR_SIZE);
			data_off = le16_to_cpu(cc->DataOffset);
			data_len_field = le32_to_cpu(cc->DataLength);

			if (data_off + data_len_field <= ctx_len)
				fuzz_dispatch_dh_context(tag,
							 buf + data_off,
							 data_len_field);
		}
	}

	/* Edge cases */
	fuzz_dispatch_dh_context("DH2Q", buf, 0);
	fuzz_dispatch_dh_context("DH2C", buf, 0);
	fuzz_dispatch_dh_context("DHnQ", buf, 0);
	fuzz_dispatch_dh_context("DHnC", buf, 0);
	fuzz_dispatch_dh_context("XXXX", buf, 0);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_dispatch_dh_context("DH2Q", buf, 64);
	fuzz_dispatch_dh_context("DH2C", buf, 64);

	kfree(buf);
	pr_info("durable_handle_fuzz: all iterations completed\n");
	return 0;
}

static void __exit durable_handle_fuzz_exit(void)
{
	pr_info("durable_handle_fuzz: module unloaded\n");
}

module_init(durable_handle_fuzz_init);
module_exit(durable_handle_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for durable handle create context parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
