// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 CLOSE request parsing
 *
 *   This module exercises the CLOSE request header validation including
 *   StructureSize, Flags (SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB), and
 *   FileId extraction.
 *
 *   Targets:
 *     - StructureSize validation (must be 24)
 *     - Flags: SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
 *     - FileId (Persistent + Volatile) extraction
 *     - FileId sentinel values (0xFFFFFFFFFFFFFFFF for compound)
 *
 *   Corpus seed hints:
 *     - CLOSE req: StructureSize=24, Flags=0 or 1,
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

/* SMB2 CLOSE request structure */
struct smb2_close_req_fuzz {
	__le16 StructureSize;	/* Must be 24 */
	__le16 Flags;
	__le32 Reserved;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
} __packed;

#define CLOSE_STRUCTURE_SIZE	24
#define CLOSE_HDR_SIZE		sizeof(struct smb2_close_req_fuzz)

/* Close flags */
#define SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB	0x0001

/*
 * fuzz_close_request - Fuzz SMB2 CLOSE request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_close_request(const u8 *data, size_t len)
{
	const struct smb2_close_req_fuzz *req;
	u16 structure_size;
	u16 flags;
	u64 fid_persistent, fid_volatile;

	if (len < CLOSE_HDR_SIZE) {
		pr_debug("fuzz_close: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_close_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	flags = le16_to_cpu(req->Flags);
	fid_persistent = le64_to_cpu(req->FileId_Persistent);
	fid_volatile = le64_to_cpu(req->FileId_Volatile);

	/* Validate structure size */
	if (structure_size != CLOSE_STRUCTURE_SIZE) {
		pr_debug("fuzz_close: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate flags */
	if (flags & ~SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB) {
		pr_debug("fuzz_close: reserved flags set 0x%04x\n", flags);
	}

	/* Check for compound FID sentinel */
	if (fid_persistent == 0xFFFFFFFFFFFFFFFFULL &&
	    fid_volatile == 0xFFFFFFFFFFFFFFFFULL) {
		pr_debug("fuzz_close: compound FID sentinel\n");
	} else if (fid_persistent == 0 && fid_volatile == 0) {
		pr_debug("fuzz_close: zero FID\n");
	}

	if (flags & SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB)
		pr_debug("fuzz_close: POSTQUERY_ATTRIB requested\n");

	pr_debug("fuzz_close: flags=0x%04x fid_p=%llx fid_v=%llx\n",
		 flags, fid_persistent, fid_volatile);

	return 0;
}

static int __init close_request_fuzz_init(void)
{
	u8 test_buf[64];
	struct smb2_close_req_fuzz *req;
	int ret;

	pr_info("close_request_fuzz: module loaded\n");

	/* Self-test 1: valid close */
	memset(test_buf, 0, sizeof(test_buf));
	req = (struct smb2_close_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(CLOSE_STRUCTURE_SIZE);
	req->Flags = cpu_to_le16(SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB);
	req->FileId_Persistent = cpu_to_le64(0x1234);
	req->FileId_Volatile = cpu_to_le64(0x5678);

	ret = fuzz_close_request(test_buf, CLOSE_HDR_SIZE);
	pr_info("close_request_fuzz: valid returned %d\n", ret);

	/* Self-test 2: compound sentinel */
	req->FileId_Persistent = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	req->FileId_Volatile = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	ret = fuzz_close_request(test_buf, CLOSE_HDR_SIZE);
	pr_info("close_request_fuzz: compound FID returned %d\n", ret);

	/* Self-test 3: zero FID */
	req->FileId_Persistent = 0;
	req->FileId_Volatile = 0;
	ret = fuzz_close_request(test_buf, CLOSE_HDR_SIZE);
	pr_info("close_request_fuzz: zero FID returned %d\n", ret);

	/* Self-test 4: truncated */
	ret = fuzz_close_request(test_buf, 4);
	pr_info("close_request_fuzz: truncated returned %d\n", ret);

	/* Self-test 5: garbage */
	memset(test_buf, 0xFF, sizeof(test_buf));
	ret = fuzz_close_request(test_buf, sizeof(test_buf));
	pr_info("close_request_fuzz: garbage returned %d\n", ret);

	return 0;
}

static void __exit close_request_fuzz_exit(void)
{
	pr_info("close_request_fuzz: module unloaded\n");
}

module_init(close_request_fuzz_init);
module_exit(close_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 CLOSE request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
