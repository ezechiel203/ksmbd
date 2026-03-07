// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 create context parsing
 *
 *   This module exercises the create context parsing logic used in
 *   SMB2 CREATE requests. Create contexts carry durable handles,
 *   leases, security descriptors, and other extended attributes.
 *   Malformed create contexts can lead to out-of-bounds reads or
 *   infinite loops if not properly validated.
 *
 *   Targets:
 *     - smb2_find_context_vals: iterates over chained create contexts
 *     - Create context chain traversal (Next field following)
 *     - NameOffset, NameLength, DataOffset, DataLength validation
 *     - Alignment checks (8-byte alignment of Next field)
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_create_context() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/err.h>

/*
 * Inline the create_context structure to avoid full header dependencies.
 * This matches the structure defined in smb2pdu.h.
 */
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

/*
 * Inline a minimal smb2_create_req structure with just the fields
 * needed for create context parsing.
 */
struct fuzz_smb2_create_req {
	__u8   hdr[64];		/* placeholder for SMB2 header */
	__le16 StructureSize;
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

/*
 * fuzz_find_context_vals - Fuzz create context chain traversal
 * @data:	raw input containing a create context chain
 * @data_len:	total length of the context chain data
 * @tag:	4-byte context tag to search for
 *
 * Simulates the smb2_find_context_vals() function from oplock.c.
 * Walks the chained create context list, validating offsets and lengths
 * at each step.
 *
 * Return: pointer to matching context, NULL if not found,
 *         ERR_PTR(-EINVAL) on malformed input
 */
static struct fuzz_create_context *fuzz_find_context_vals(const u8 *data,
							  size_t data_len,
							  const char *tag,
							  int tag_len)
{
	struct fuzz_create_context *cc;
	unsigned int next = 0;
	unsigned int remain_len;
	unsigned int name_off, name_len, value_off, value_len, cc_len;
	char *name;

	if (data_len < FUZZ_CC_HDR_SIZE)
		return ERR_PTR(-EINVAL);

	remain_len = data_len;
	cc = (struct fuzz_create_context *)data;

	do {
		cc = (struct fuzz_create_context *)((char *)cc + next);
		if (remain_len < FUZZ_CC_HDR_SIZE)
			return ERR_PTR(-EINVAL);

		next = le32_to_cpu(cc->Next);
		name_off = le16_to_cpu(cc->NameOffset);
		name_len = le16_to_cpu(cc->NameLength);
		value_off = le16_to_cpu(cc->DataOffset);
		value_len = le32_to_cpu(cc->DataLength);
		cc_len = next ? next : remain_len;

		/* Validate alignment and bounds */
		if ((next & 0x7) != 0 ||
		    next > remain_len ||
		    name_off != FUZZ_CC_HDR_SIZE ||
		    name_len < tag_len ||
		    name_off + name_len > cc_len ||
		    (value_off & 0x7) != 0 ||
		    (value_len && (value_off < name_off + name_len ||
				   value_off + value_len > cc_len))) {
			pr_debug("fuzz_cc: invalid context entry\n");
			return ERR_PTR(-EINVAL);
		}

		name = (char *)cc + name_off;
		if (!memcmp(name, tag, tag_len)) {
			pr_debug("fuzz_cc: found context tag '%.4s'\n", tag);
			return cc;
		}

		remain_len -= next;
	} while (next != 0);

	return NULL;
}

/*
 * fuzz_create_context - Main fuzzing entry point for create contexts
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Constructs a synthetic SMB2 CREATE request with the fuzz input
 * placed in the create contexts area, then attempts to find various
 * well-known context tags.
 *
 * Return: 0 always (errors are handled gracefully)
 */
static int fuzz_create_context(const u8 *data, size_t len)
{
	struct fuzz_create_context *result;
	static const char *tags[] = {
		"DH2Q",		/* Durable Handle V2 Request */
		"DH2C",		/* Durable Handle V2 Reconnect */
		"DHnQ",		/* Durable Handle Request */
		"DHnC",		/* Durable Handle Reconnect */
		"MxAc",		/* Maximum Access */
		"QFid",		/* Query on Disk ID */
		"RqLs",		/* Request Lease */
		"AAPL",		/* Apple Extensions */
	};
	int i;

	if (len < FUZZ_CC_HDR_SIZE) {
		pr_debug("fuzz_cc: input too small (%zu bytes)\n", len);
		return 0;
	}

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	/* Try to find each well-known tag in the fuzz data */
	for (i = 0; i < ARRAY_SIZE(tags); i++) {
		result = fuzz_find_context_vals(data, len, tags[i], 4);
		if (IS_ERR(result)) {
			pr_debug("fuzz_cc: tag '%.4s' -> error %ld\n",
				 tags[i], PTR_ERR(result));
		} else if (result) {
			pr_debug("fuzz_cc: tag '%.4s' -> found\n", tags[i]);
		} else {
			pr_debug("fuzz_cc: tag '%.4s' -> not found\n",
				 tags[i]);
		}
	}

	return 0;
}

/*
 * fuzz_create_context_chain - Fuzz a multi-entry create context chain
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Attempts to walk the entire create context chain, counting entries
 * and accumulating data sizes. Tests the chain traversal logic for
 * robustness against circular references and oversized chains.
 *
 * Return: number of entries parsed, or negative on error
 */
static int fuzz_create_context_chain(const u8 *data, size_t len)
{
	struct fuzz_create_context *cc;
	unsigned int next;
	unsigned int remain_len;
	int count = 0;

	if (len < FUZZ_CC_HDR_SIZE)
		return -EINVAL;

	remain_len = len;
	cc = (struct fuzz_create_context *)data;
	next = 0;

	do {
		cc = (struct fuzz_create_context *)((char *)cc + next);
		if (remain_len < FUZZ_CC_HDR_SIZE)
			break;

		next = le32_to_cpu(cc->Next);

		/* Prevent infinite loops */
		if (next != 0 && next > remain_len)
			break;
		if (next != 0 && (next & 0x7) != 0)
			break;

		count++;
		remain_len -= (next ? next : remain_len);

		/* Safety limit */
		if (count > 256)
			break;
	} while (next != 0);

	pr_debug("fuzz_cc: chain contains %d entries\n", count);
	return count;
}

static int __init create_context_fuzz_init(void)
{
	u8 *test_buf;
	struct fuzz_create_context *cc;
	int ret;

	pr_info("create_context_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test: single valid create context with tag "DH2Q" */
	cc = (struct fuzz_create_context *)test_buf;
	cc->Next = 0;
	cc->NameOffset = cpu_to_le16(FUZZ_CC_HDR_SIZE);
	cc->NameLength = cpu_to_le16(4);
	cc->DataOffset = cpu_to_le16(FUZZ_CC_HDR_SIZE + 8); /* 8-byte aligned */
	cc->DataLength = cpu_to_le32(16);
	memcpy(cc->Buffer, "DH2Q", 4);

	ret = fuzz_create_context(test_buf, FUZZ_CC_HDR_SIZE + 8 + 16);
	pr_info("create_context_fuzz: valid context test returned %d\n", ret);

	/* Self-test: empty input */
	ret = fuzz_create_context(test_buf, 0);
	pr_info("create_context_fuzz: empty test returned %d\n", ret);

	/* Self-test: garbage data */
	memset(test_buf, 0xff, 256);
	ret = fuzz_create_context(test_buf, 256);
	pr_info("create_context_fuzz: garbage test returned %d\n", ret);

	/* Self-test: chain walk */
	memset(test_buf, 0, 256);
	ret = fuzz_create_context_chain(test_buf, 256);
	pr_info("create_context_fuzz: chain test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit create_context_fuzz_exit(void)
{
	pr_info("create_context_fuzz: module unloaded\n");
}

module_init(create_context_fuzz_init);
module_exit(create_context_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 create context parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
