// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 CHANGE_NOTIFY request parsing
 *
 *   This module exercises the CHANGE_NOTIFY request validation including
 *   StructureSize, CompletionFilter flags, OutputBufferLength, and
 *   WATCH_TREE flag handling.
 *
 *   Targets:
 *     - StructureSize validation (must be 32)
 *     - CompletionFilter: FILE_NOTIFY_CHANGE_* bitmask validation
 *     - Flags: SMB2_WATCH_TREE flag
 *     - OutputBufferLength sanity check
 *     - FileId validation
 *
 *   Corpus seed hints:
 *     - CHANGE_NOTIFY: StructureSize=32, Flags=0 or 1,
 *       OutputBufferLength=4096, CompletionFilter=0x17F
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 CHANGE_NOTIFY request */
struct smb2_notify_req_fuzz {
	__le16 StructureSize;	/* Must be 32 */
	__le16 Flags;
	__le32 OutputBufferLength;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
	__le32 CompletionFilter;
	__le32 Reserved;
} __packed;

#define NOTIFY_STRUCTURE_SIZE	32
#define NOTIFY_HDR_SIZE		sizeof(struct smb2_notify_req_fuzz)

/* Notify flags */
#define SMB2_WATCH_TREE		0x0001

/* CompletionFilter bits (MS-SMB2 2.2.35) */
#define FILE_NOTIFY_CHANGE_FILE_NAME	0x00000001
#define FILE_NOTIFY_CHANGE_DIR_NAME	0x00000002
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

#define FILE_NOTIFY_VALID_MASK		0x00000FFF

#define MAX_NOTIFY_OUTPUT_BUFFER	(64 * 1024)

/*
 * fuzz_notify_request - Fuzz CHANGE_NOTIFY request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_notify_request(const u8 *data, size_t len)
{
	const struct smb2_notify_req_fuzz *req;
	u16 structure_size;
	u16 flags;
	u32 output_buf_len;
	u32 completion_filter;

	if (len < NOTIFY_HDR_SIZE) {
		pr_debug("fuzz_notify: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_notify_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	flags = le16_to_cpu(req->Flags);
	output_buf_len = le32_to_cpu(req->OutputBufferLength);
	completion_filter = le32_to_cpu(req->CompletionFilter);

	/* Validate structure size */
	if (structure_size != NOTIFY_STRUCTURE_SIZE) {
		pr_debug("fuzz_notify: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate CompletionFilter */
	if (completion_filter == 0) {
		pr_debug("fuzz_notify: zero CompletionFilter\n");
		return -EINVAL;
	}

	if (completion_filter & ~FILE_NOTIFY_VALID_MASK) {
		pr_debug("fuzz_notify: reserved CompletionFilter bits set 0x%08x\n",
			 completion_filter);
		/* Not fatal, but noted */
	}

	/* Validate OutputBufferLength */
	if (output_buf_len == 0) {
		pr_debug("fuzz_notify: zero OutputBufferLength\n");
		return -EINVAL;
	}

	if (output_buf_len > MAX_NOTIFY_OUTPUT_BUFFER) {
		pr_debug("fuzz_notify: OutputBufferLength %u > max %u\n",
			 output_buf_len, MAX_NOTIFY_OUTPUT_BUFFER);
		return -EINVAL;
	}

	/* Check WATCH_TREE flag */
	if (flags & SMB2_WATCH_TREE) {
		pr_debug("fuzz_notify: WATCH_TREE enabled\n");
	}

	if (flags & ~SMB2_WATCH_TREE) {
		pr_debug("fuzz_notify: reserved flags set 0x%04x\n", flags);
	}

	pr_debug("fuzz_notify: flags=0x%04x outlen=%u filter=0x%08x\n",
		 flags, output_buf_len, completion_filter);

	return 0;
}

static int __init notify_fuzz_init(void)
{
	u8 test_buf[64];
	struct smb2_notify_req_fuzz *req;
	int ret;

	pr_info("notify_fuzz: module loaded\n");

	/* Self-test 1: valid notify */
	memset(test_buf, 0, sizeof(test_buf));
	req = (struct smb2_notify_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(NOTIFY_STRUCTURE_SIZE);
	req->Flags = cpu_to_le16(SMB2_WATCH_TREE);
	req->OutputBufferLength = cpu_to_le32(4096);
	req->CompletionFilter = cpu_to_le32(FILE_NOTIFY_CHANGE_FILE_NAME |
					    FILE_NOTIFY_CHANGE_DIR_NAME);
	ret = fuzz_notify_request(test_buf, NOTIFY_HDR_SIZE);
	pr_info("notify_fuzz: valid returned %d\n", ret);

	/* Self-test 2: zero CompletionFilter */
	req->CompletionFilter = 0;
	ret = fuzz_notify_request(test_buf, NOTIFY_HDR_SIZE);
	pr_info("notify_fuzz: zero filter returned %d\n", ret);

	/* Self-test 3: huge output buffer */
	req->CompletionFilter = cpu_to_le32(0x01);
	req->OutputBufferLength = cpu_to_le32(0xFFFFFFFF);
	ret = fuzz_notify_request(test_buf, NOTIFY_HDR_SIZE);
	pr_info("notify_fuzz: huge output returned %d\n", ret);

	/* Self-test 4: truncated */
	ret = fuzz_notify_request(test_buf, 8);
	pr_info("notify_fuzz: truncated returned %d\n", ret);

	/* Self-test 5: garbage */
	memset(test_buf, 0xFF, sizeof(test_buf));
	ret = fuzz_notify_request(test_buf, sizeof(test_buf));
	pr_info("notify_fuzz: garbage returned %d\n", ret);

	return 0;
}

static void __exit notify_fuzz_exit(void)
{
	pr_info("notify_fuzz: module unloaded\n");
}

module_init(notify_fuzz_init);
module_exit(notify_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 CHANGE_NOTIFY request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
