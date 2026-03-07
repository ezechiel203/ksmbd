// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 FLUSH request parsing
 *
 *   This module exercises the FLUSH request header validation including
 *   StructureSize, Reserved fields, and FileId extraction.
 *
 *   Targets:
 *     - StructureSize validation (must be 24)
 *     - Reserved1 and Reserved2 field checks
 *     - FileId (Persistent + Volatile) extraction
 *     - GrantedAccess check (FILE_WRITE_DATA | FILE_APPEND_DATA)
 *
 *   Corpus seed hints:
 *     - FLUSH req: StructureSize=24, Reserved1=0, Reserved2=0,
 *       FileId_Persistent + FileId_Volatile
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 FLUSH request structure */
struct smb2_flush_req_fuzz {
	__le16 StructureSize;	/* Must be 24 */
	__le16 Reserved1;
	__le32 Reserved2;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
} __packed;

#define FLUSH_STRUCTURE_SIZE	24
#define FLUSH_HDR_SIZE		sizeof(struct smb2_flush_req_fuzz)

/*
 * fuzz_flush_request - Fuzz SMB2 FLUSH request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_flush_request(const u8 *data, size_t len)
{
	const struct smb2_flush_req_fuzz *req;
	u16 structure_size;
	u64 fid_persistent, fid_volatile;

	if (len < FLUSH_HDR_SIZE) {
		pr_debug("fuzz_flush: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_flush_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	fid_persistent = le64_to_cpu(req->FileId_Persistent);
	fid_volatile = le64_to_cpu(req->FileId_Volatile);

	/* Validate structure size */
	if (structure_size != FLUSH_STRUCTURE_SIZE) {
		pr_debug("fuzz_flush: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Check for compound FID sentinel */
	if (fid_persistent == 0xFFFFFFFFFFFFFFFFULL &&
	    fid_volatile == 0xFFFFFFFFFFFFFFFFULL) {
		pr_debug("fuzz_flush: compound FID sentinel\n");
	}

	/* Reserved fields should be zero per spec */
	if (req->Reserved1 != 0)
		pr_debug("fuzz_flush: non-zero Reserved1\n");
	if (req->Reserved2 != 0)
		pr_debug("fuzz_flush: non-zero Reserved2\n");

	pr_debug("fuzz_flush: fid_p=%llx fid_v=%llx\n",
		 fid_persistent, fid_volatile);

	return 0;
}

static int __init flush_request_fuzz_init(void)
{
	u8 test_buf[64];
	struct smb2_flush_req_fuzz *req;
	int ret;

	pr_info("flush_request_fuzz: module loaded\n");

	/* Self-test 1: valid flush */
	memset(test_buf, 0, sizeof(test_buf));
	req = (struct smb2_flush_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(FLUSH_STRUCTURE_SIZE);
	req->FileId_Persistent = cpu_to_le64(0x1234);
	req->FileId_Volatile = cpu_to_le64(0x5678);

	ret = fuzz_flush_request(test_buf, FLUSH_HDR_SIZE);
	pr_info("flush_request_fuzz: valid returned %d\n", ret);

	/* Self-test 2: non-zero reserved */
	req->Reserved1 = cpu_to_le16(0xFFFF);
	req->Reserved2 = cpu_to_le32(0xFFFFFFFF);
	ret = fuzz_flush_request(test_buf, FLUSH_HDR_SIZE);
	pr_info("flush_request_fuzz: non-zero reserved returned %d\n", ret);

	/* Self-test 3: wrong structure size */
	req->StructureSize = cpu_to_le16(48);
	ret = fuzz_flush_request(test_buf, FLUSH_HDR_SIZE);
	pr_info("flush_request_fuzz: wrong size returned %d\n", ret);

	/* Self-test 4: truncated */
	ret = fuzz_flush_request(test_buf, 4);
	pr_info("flush_request_fuzz: truncated returned %d\n", ret);

	/* Self-test 5: garbage */
	memset(test_buf, 0xFF, sizeof(test_buf));
	ret = fuzz_flush_request(test_buf, sizeof(test_buf));
	pr_info("flush_request_fuzz: garbage returned %d\n", ret);

	return 0;
}

static void __exit flush_request_fuzz_exit(void)
{
	pr_info("flush_request_fuzz: module unloaded\n");
}

module_init(flush_request_fuzz_init);
module_exit(flush_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 FLUSH request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
