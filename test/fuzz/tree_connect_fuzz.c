// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 TREE_CONNECT request path parsing
 *
 *   This module exercises the tree connect request parsing including
 *   share path extraction, UTF-16LE path conversion, share name
 *   extraction, and TREE_CONNECT_Request_Extension parsing.
 *
 *   Targets:
 *     - StructureSize, PathOffset, PathLength validation
 *     - Flag validation (CLUSTER_RECONNECT, REDIRECT_TO_OWNER,
 *       EXTENSION_PRESENT)
 *     - Extension parsing: PathOffset relative to Buffer[0]
 *     - ksmbd_extract_sharename(): splits \\server\share
 *     - Share name length limit (>= 80 chars rejected)
 *
 *   Corpus seed hints:
 *     - TREE_CONNECT: StructureSize=9, Flags=0, PathOffset=72,
 *       PathLength=28, "\\\\server\\share" in UTF-16LE
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 TREE_CONNECT request structure */
struct smb2_tree_connect_req_fuzz {
	__le16 StructureSize;	/* Must be 9 */
	__le16 Flags;
	__le16 PathOffset;
	__le16 PathLength;
	__u8   Buffer[];
} __packed;

#define TREE_CONNECT_STRUCTURE_SIZE	9
#define TREE_CONNECT_HDR_SIZE		offsetof(struct smb2_tree_connect_req_fuzz, Buffer)

/* Tree connect flags */
#define SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT	0x0001
#define SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER	0x0002
#define SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT	0x0004

#define MAX_SHARE_NAME_LEN	80

/*
 * fuzz_extract_sharename - Extract share name from UNC path
 * @path:	UTF-8 UNC path (e.g., "\\server\share")
 * @path_len:	length of path
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_extract_sharename(const char *path, size_t path_len)
{
	const char *p;
	const char *share_start;
	size_t share_len;

	if (path_len == 0 || !path)
		return -EINVAL;

	/* Skip leading backslashes */
	p = path;
	while (*p == '\\' && p < path + path_len)
		p++;

	/* Find server name */
	while (*p && *p != '\\' && p < path + path_len)
		p++;

	if (*p != '\\' || p >= path + path_len) {
		pr_debug("fuzz_tree: no share separator found\n");
		return -EINVAL;
	}
	p++; /* skip backslash */

	share_start = p;

	/* Find end of share name */
	while (*p && *p != '\\' && p < path + path_len)
		p++;

	share_len = p - share_start;

	if (share_len == 0) {
		pr_debug("fuzz_tree: empty share name\n");
		return -EINVAL;
	}

	if (share_len >= MAX_SHARE_NAME_LEN) {
		pr_debug("fuzz_tree: share name too long (%zu >= %u)\n",
			 share_len, MAX_SHARE_NAME_LEN);
		return -EINVAL;
	}

	pr_debug("fuzz_tree: share name '%.*s' (len=%zu)\n",
		 (int)min(share_len, (size_t)32), share_start, share_len);

	return 0;
}

/*
 * fuzz_tree_connect_request - Fuzz TREE_CONNECT request body
 * @data:	raw request body (after SMB2 header)
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_tree_connect_request(const u8 *data, size_t len)
{
	const struct smb2_tree_connect_req_fuzz *req;
	u16 structure_size;
	u16 flags;
	u16 path_offset;
	u16 path_length;

	if (len < TREE_CONNECT_HDR_SIZE) {
		pr_debug("fuzz_tree: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_tree_connect_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	flags = le16_to_cpu(req->Flags);
	path_offset = le16_to_cpu(req->PathOffset);
	path_length = le16_to_cpu(req->PathLength);

	/* Validate structure size */
	if (structure_size != TREE_CONNECT_STRUCTURE_SIZE) {
		pr_debug("fuzz_tree: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate path length is even (UTF-16LE) */
	if (path_length & 1) {
		pr_debug("fuzz_tree: odd PathLength %u\n", path_length);
		return -EINVAL;
	}

	/* Validate flags */
	if (flags & ~(SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT |
		      SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER |
		      SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT)) {
		pr_debug("fuzz_tree: reserved flags set 0x%04x\n", flags);
	}

	/* Handle EXTENSION_PRESENT */
	if (flags & SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT) {
		/* PathOffset is relative to Buffer[0] */
		size_t base = TREE_CONNECT_HDR_SIZE;

		if (base + path_offset + path_length > len) {
			pr_debug("fuzz_tree: extension path out of bounds "
				 "(base=%zu off=%u len=%u buf=%zu)\n",
				 base, path_offset, path_length, len);
			return -EINVAL;
		}
		pr_debug("fuzz_tree: extension present, path at base+%u\n",
			 path_offset);
	} else {
		/* PathOffset is absolute from start of SMB2 packet;
		 * in our fuzzer context, treat relative to start of data */
		if (path_offset + path_length > len) {
			pr_debug("fuzz_tree: path out of bounds (off=%u len=%u buf=%zu)\n",
				 path_offset, path_length, len);
			return -EINVAL;
		}
	}

	/* If we have valid path data, try to extract share name */
	if (path_length > 0 && path_length <= 512) {
		/* Simple conversion: just read as bytes for validation */
		char path_buf[256];
		size_t i;
		size_t num_chars;
		const u8 *path_data;

		if (flags & SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT)
			path_data = data + TREE_CONNECT_HDR_SIZE + path_offset;
		else
			path_data = data + path_offset;

		num_chars = path_length / 2;
		if (num_chars > sizeof(path_buf) - 1)
			num_chars = sizeof(path_buf) - 1;

		for (i = 0; i < num_chars; i++) {
			u16 cu = (u16)path_data[i * 2] |
				 ((u16)path_data[i * 2 + 1] << 8);
			if (cu == 0)
				break;
			if (cu < 0x80)
				path_buf[i] = (char)cu;
			else
				path_buf[i] = '?';
		}
		path_buf[i] = '\0';

		fuzz_extract_sharename(path_buf, i);
	}

	pr_debug("fuzz_tree: flags=0x%04x path_off=%u path_len=%u\n",
		 flags, path_offset, path_length);

	return 0;
}

static int __init tree_connect_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_tree_connect_req_fuzz *req;
	int ret;

	pr_info("tree_connect_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid tree connect */
	req = (struct smb2_tree_connect_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(TREE_CONNECT_STRUCTURE_SIZE);
	req->Flags = 0;
	req->PathOffset = cpu_to_le16(TREE_CONNECT_HDR_SIZE);
	req->PathLength = cpu_to_le16(28);
	/* "\\server\share" in UTF-16LE */
	{
		u8 *p = test_buf + TREE_CONNECT_HDR_SIZE;
		const char *unc = "\\\\server\\share";
		int i;

		for (i = 0; unc[i]; i++) {
			p[i * 2] = unc[i];
			p[i * 2 + 1] = 0;
		}
	}
	ret = fuzz_tree_connect_request(test_buf, TREE_CONNECT_HDR_SIZE + 28);
	pr_info("tree_connect_fuzz: valid returned %d\n", ret);

	/* Self-test 2: odd PathLength */
	req->PathLength = cpu_to_le16(27);
	ret = fuzz_tree_connect_request(test_buf, TREE_CONNECT_HDR_SIZE + 28);
	pr_info("tree_connect_fuzz: odd length returned %d\n", ret);

	/* Self-test 3: path out of bounds */
	req->PathLength = cpu_to_le16(28);
	req->PathOffset = cpu_to_le16(0xFFFF);
	ret = fuzz_tree_connect_request(test_buf, TREE_CONNECT_HDR_SIZE + 28);
	pr_info("tree_connect_fuzz: oob path returned %d\n", ret);

	/* Self-test 4: extension present */
	req->Flags = cpu_to_le16(SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT);
	req->PathOffset = cpu_to_le16(0);
	req->PathLength = cpu_to_le16(28);
	ret = fuzz_tree_connect_request(test_buf, TREE_CONNECT_HDR_SIZE + 28);
	pr_info("tree_connect_fuzz: extension returned %d\n", ret);

	/* Self-test 5: share name extraction */
	ret = fuzz_extract_sharename("\\\\server\\share", 14);
	pr_info("tree_connect_fuzz: extract share returned %d\n", ret);

	/* Self-test 6: long share name */
	{
		char long_path[200];

		memset(long_path, 0, sizeof(long_path));
		memcpy(long_path, "\\\\s\\", 4);
		memset(long_path + 4, 'A', 100);
		ret = fuzz_extract_sharename(long_path, 104);
		pr_info("tree_connect_fuzz: long share returned %d\n", ret);
	}

	/* Self-test 7: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_tree_connect_request(test_buf, 512);
	pr_info("tree_connect_fuzz: garbage returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit tree_connect_fuzz_exit(void)
{
	pr_info("tree_connect_fuzz: module unloaded\n");
}

module_init(tree_connect_fuzz_init);
module_exit(tree_connect_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 TREE_CONNECT path parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
