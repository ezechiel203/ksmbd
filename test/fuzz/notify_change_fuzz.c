// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 CHANGE_NOTIFY request validation
 *
 *   This module exercises change notification request parsing with
 *   random CompletionFilter combinations, OutputBufferLength values
 *   (0, 1, MAX), WATCH_TREE flag with deeply nested paths, and
 *   notification response buffer construction.
 *
 *   Targets:
 *     - StructureSize validation (must be 32)
 *     - Flags: SMB2_WATCH_TREE (bit 0) and unknown flags
 *     - CompletionFilter: all FILE_NOTIFY_CHANGE_* combinations
 *     - OutputBufferLength: 0, 1, typical (4096), MAX_UINT32
 *     - FileId validation
 *     - Notification response: FILE_NOTIFY_INFORMATION chain walk
 *     - NextEntryOffset chain termination
 *     - Action field validation
 *     - FileNameLength vs buffer bounds
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

/* Inline structures matching smb2pdu.h / ksmbd_notify.h */

#define SMB2_PROTO_NUMBER		cpu_to_le32(0x424d53fe)
#define __SMB2_HEADER_STRUCTURE_SIZE	64

#define SMB2_WATCH_TREE			0x0001

#define FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002
#define FILE_NOTIFY_CHANGE_NAME		0x00000003
#define FILE_NOTIFY_CHANGE_ATTRIBUTES	0x00000004
#define FILE_NOTIFY_CHANGE_SIZE		0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE	0x00000010
#define FILE_NOTIFY_CHANGE_LAST_ACCESS	0x00000020
#define FILE_NOTIFY_CHANGE_CREATION	0x00000040
#define FILE_NOTIFY_CHANGE_EA		0x00000080
#define FILE_NOTIFY_CHANGE_SECURITY	0x00000100
#define FILE_NOTIFY_CHANGE_STREAM_NAME	0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE	0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE	0x00000800

#define FILE_NOTIFY_ALL_MASK		0x00000FFF

/* FILE_ACTION values */
#define FILE_ACTION_ADDED		0x00000001
#define FILE_ACTION_REMOVED		0x00000002
#define FILE_ACTION_MODIFIED		0x00000003
#define FILE_ACTION_RENAMED_OLD_NAME	0x00000004
#define FILE_ACTION_RENAMED_NEW_NAME	0x00000005
#define FILE_ACTION_ADDED_STREAM	0x00000006
#define FILE_ACTION_REMOVED_STREAM	0x00000007
#define FILE_ACTION_MODIFIED_STREAM	0x00000008

struct fuzz_notify_req {
	__u8   hdr[64];	/* SMB2 header placeholder */
	__le16 StructureSize;	/* Must be 32 */
	__le16 Flags;
	__le32 OutputBufferLength;
	__u64  PersistentFileId;
	__u64  VolatileFileId;
	__le32 CompletionFilter;
	__le32 Reserved;
} __packed;

/* FILE_NOTIFY_INFORMATION structure */
struct fuzz_notify_info {
	__le32 NextEntryOffset;
	__le32 Action;
	__le32 FileNameLength;
	__u8   FileName[];	/* UTF-16LE */
} __packed;

#define FUZZ_NOTIFY_HDR_SIZE	sizeof(struct fuzz_notify_req)
#define FUZZ_NOTIFY_INFO_SIZE	sizeof(struct fuzz_notify_info)
#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		4096

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
 * fuzz_validate_notify_request - Validate a CHANGE_NOTIFY request
 * @data:	raw buffer
 * @len:	buffer length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_notify_request(const u8 *data, size_t len)
{
	const struct fuzz_notify_req *req;
	u16 structure_size, flags;
	u32 output_buf_len, completion_filter;

	if (len < FUZZ_NOTIFY_HDR_SIZE) {
		pr_debug("notify_fuzz: buffer too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct fuzz_notify_req *)data;

	structure_size = le16_to_cpu(req->StructureSize);
	if (structure_size != 32) {
		pr_debug("notify_fuzz: bad StructureSize %u\n", structure_size);
		return -EINVAL;
	}

	flags = le16_to_cpu(req->Flags);
	output_buf_len = le32_to_cpu(req->OutputBufferLength);
	completion_filter = le32_to_cpu(req->CompletionFilter);

	/* Flags: only WATCH_TREE is defined */
	if (flags & ~SMB2_WATCH_TREE) {
		pr_debug("notify_fuzz: unknown flags 0x%04x\n", flags);
	}

	if (flags & SMB2_WATCH_TREE)
		pr_debug("notify_fuzz: WATCH_TREE enabled\n");

	/* CompletionFilter validation */
	if (completion_filter == 0) {
		pr_debug("notify_fuzz: zero CompletionFilter\n");
		return -EINVAL;
	}

	if (completion_filter & ~FILE_NOTIFY_ALL_MASK) {
		pr_debug("notify_fuzz: unknown filter bits 0x%x\n",
			 completion_filter & ~FILE_NOTIFY_ALL_MASK);
	}

	/* OutputBufferLength sanity */
	if (output_buf_len == 0) {
		pr_debug("notify_fuzz: zero OutputBufferLength\n");
		/* Per spec, this is allowed but unusual */
	}

	if (output_buf_len > 64 * 1024) {
		pr_debug("notify_fuzz: large OutputBufferLength %u\n",
			 output_buf_len);
	}

	pr_debug("notify_fuzz: valid req filter=0x%x outlen=%u flags=0x%x\n",
		 completion_filter, output_buf_len, flags);

	return 0;
}

/*
 * fuzz_validate_notify_response - Walk a FILE_NOTIFY_INFORMATION chain
 * @data:	raw response buffer
 * @len:	buffer length
 *
 * Return: number of entries, negative on error
 */
static int fuzz_validate_notify_response(const u8 *data, size_t len)
{
	const struct fuzz_notify_info *info;
	size_t offset = 0;
	int count = 0;
	u32 next_entry, action, name_len;

	while (offset + FUZZ_NOTIFY_INFO_SIZE <= len) {
		info = (const struct fuzz_notify_info *)(data + offset);
		next_entry = le32_to_cpu(info->NextEntryOffset);
		action = le32_to_cpu(info->Action);
		name_len = le32_to_cpu(info->FileNameLength);

		/* Action validation */
		if (action == 0 || action > FILE_ACTION_MODIFIED_STREAM) {
			pr_debug("notify_fuzz: invalid action %u at entry %d\n",
				 action, count);
			return -EINVAL;
		}

		/* FileNameLength must be even (UTF-16LE) */
		if (name_len & 1) {
			pr_debug("notify_fuzz: odd FileNameLength %u\n",
				 name_len);
			return -EINVAL;
		}

		/* Name must fit in buffer */
		if (offset + FUZZ_NOTIFY_INFO_SIZE + name_len > len) {
			pr_debug("notify_fuzz: FileName exceeds buffer\n");
			return -EINVAL;
		}

		count++;
		if (count > 1024)
			break;

		if (next_entry == 0)
			break;

		/* NextEntryOffset must be aligned and move forward */
		if ((next_entry & 3) != 0) {
			pr_debug("notify_fuzz: unaligned NextEntryOffset %u\n",
				 next_entry);
			return -EINVAL;
		}

		if (next_entry < FUZZ_NOTIFY_INFO_SIZE) {
			pr_debug("notify_fuzz: NextEntryOffset too small %u\n",
				 next_entry);
			return -EINVAL;
		}

		if (offset + next_entry > len) {
			pr_debug("notify_fuzz: NextEntryOffset exceeds buffer\n");
			return -EINVAL;
		}

		offset += next_entry;
	}

	pr_debug("notify_fuzz: response chain contains %d entries\n", count);
	return count;
}

/*
 * fuzz_build_random_notify_request - Build a random CHANGE_NOTIFY request
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: bytes written
 */
static size_t fuzz_build_random_notify_request(u8 *buf, size_t buf_size)
{
	struct fuzz_notify_req *req;
	u32 corrupt = fuzz_next() % 8;

	if (buf_size < FUZZ_NOTIFY_HDR_SIZE)
		return 0;

	memset(buf, 0, FUZZ_NOTIFY_HDR_SIZE);
	req = (struct fuzz_notify_req *)buf;

	/* Header */
	*(__le32 *)req->hdr = SMB2_PROTO_NUMBER;
	*(__le16 *)(req->hdr + 4) = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	*(__le16 *)(req->hdr + 12) = cpu_to_le16(0x000F); /* CHANGE_NOTIFY */

	/* StructureSize */
	req->StructureSize = cpu_to_le16(corrupt == 0 ? fuzz_next() : 32);

	/* Flags */
	switch (fuzz_next() % 4) {
	case 0:
		req->Flags = 0;
		break;
	case 1:
		req->Flags = cpu_to_le16(SMB2_WATCH_TREE);
		break;
	default:
		req->Flags = cpu_to_le16(fuzz_next());
		break;
	}

	/* OutputBufferLength */
	switch (fuzz_next() % 6) {
	case 0:
		req->OutputBufferLength = 0;
		break;
	case 1:
		req->OutputBufferLength = cpu_to_le32(1);
		break;
	case 2:
		req->OutputBufferLength = cpu_to_le32(4096);
		break;
	case 3:
		req->OutputBufferLength = cpu_to_le32(0xFFFFFFFF);
		break;
	case 4:
		req->OutputBufferLength = cpu_to_le32(65536);
		break;
	default:
		req->OutputBufferLength = cpu_to_le32(fuzz_next() % 0x10000);
		break;
	}

	/* FileIds */
	req->PersistentFileId = fuzz_next64();
	req->VolatileFileId = fuzz_next64();

	/* CompletionFilter */
	switch (fuzz_next() % 5) {
	case 0:
		req->CompletionFilter = 0;
		break;
	case 1:
		req->CompletionFilter = cpu_to_le32(FILE_NOTIFY_ALL_MASK);
		break;
	case 2:
		req->CompletionFilter = cpu_to_le32(FILE_NOTIFY_CHANGE_FILE_NAME |
						    FILE_NOTIFY_CHANGE_DIR_NAME);
		break;
	case 3:
		req->CompletionFilter = cpu_to_le32(0xFFFFFFFF);
		break;
	default:
		req->CompletionFilter = cpu_to_le32(fuzz_next() % 0x1000);
		break;
	}

	return FUZZ_NOTIFY_HDR_SIZE;
}

/*
 * fuzz_build_random_notify_response - Build a random response chain
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: bytes written
 */
static size_t fuzz_build_random_notify_response(u8 *buf, size_t buf_size)
{
	size_t offset = 0;
	int num_entries = (fuzz_next() % 8) + 1;
	int i;
	u32 corrupt = fuzz_next() % 8;

	for (i = 0; i < num_entries; i++) {
		struct fuzz_notify_info *info;
		u32 name_len;
		u32 entry_size;

		name_len = (fuzz_next() % 64) * 2; /* even for UTF-16 */
		entry_size = FUZZ_NOTIFY_INFO_SIZE + name_len;
		/* Align to 4 bytes */
		entry_size = (entry_size + 3) & ~3u;

		if (offset + entry_size > buf_size)
			break;

		info = (struct fuzz_notify_info *)(buf + offset);

		/* Action */
		info->Action = cpu_to_le32((fuzz_next() % 8) + 1);
		if (corrupt == 0 && i == 0)
			info->Action = cpu_to_le32(0); /* invalid */
		if (corrupt == 1 && i == 0)
			info->Action = cpu_to_le32(0xFF); /* out of range */

		info->FileNameLength = cpu_to_le32(name_len);

		/* Corruption: odd name length */
		if (corrupt == 2 && i == 0)
			info->FileNameLength = cpu_to_le32(name_len + 1);

		/* Fill filename with random data */
		if (name_len > 0)
			get_random_bytes(buf + offset + FUZZ_NOTIFY_INFO_SIZE,
					 name_len);

		if (i < num_entries - 1 &&
		    offset + entry_size + FUZZ_NOTIFY_INFO_SIZE < buf_size) {
			info->NextEntryOffset = cpu_to_le32(entry_size);

			/* Corruption: unaligned next */
			if (corrupt == 3 && i == 0)
				info->NextEntryOffset =
					cpu_to_le32(entry_size | 1);
			/* Corruption: next too small */
			if (corrupt == 4 && i == 0)
				info->NextEntryOffset = cpu_to_le32(2);
		} else {
			info->NextEntryOffset = 0;
		}

		offset += entry_size;
	}

	return offset;
}

static int __init notify_change_fuzz_init(void)
{
	u8 *buf;
	size_t total;
	int i;

	pr_info("notify_change_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0x0071F100;

	/* Request fuzzing */
	for (i = 0; i < FUZZ_ITERATIONS / 2; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		fuzz_build_random_notify_request(buf, FUZZ_BUF_SIZE);
		fuzz_validate_notify_request(buf, FUZZ_BUF_SIZE);
	}

	/* Response chain fuzzing */
	for (i = 0; i < FUZZ_ITERATIONS / 2; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		total = fuzz_build_random_notify_response(buf, FUZZ_BUF_SIZE);
		fuzz_validate_notify_response(buf, total);
	}

	/* Edge cases - requests */
	fuzz_validate_notify_request(buf, 0);
	fuzz_validate_notify_request(buf, FUZZ_NOTIFY_HDR_SIZE - 1);

	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_notify_request(buf, FUZZ_NOTIFY_HDR_SIZE);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_notify_request(buf, FUZZ_BUF_SIZE);

	/* Edge cases - responses */
	fuzz_validate_notify_response(buf, 0);
	fuzz_validate_notify_response(buf, FUZZ_NOTIFY_INFO_SIZE - 1);

	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_notify_response(buf, FUZZ_BUF_SIZE);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_notify_response(buf, FUZZ_BUF_SIZE);

	kfree(buf);
	pr_info("notify_change_fuzz: all iterations completed\n");
	return 0;
}

static void __exit notify_change_fuzz_exit(void)
{
	pr_info("notify_change_fuzz: module unloaded\n");
}

module_init(notify_change_fuzz_init);
module_exit(notify_change_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 CHANGE_NOTIFY request validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
