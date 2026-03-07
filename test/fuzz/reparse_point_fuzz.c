// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for reparse data buffer parsing
 *
 *   This module exercises the reparse point data parsing logic used in
 *   ksmbd for symbolic links, mount points, and other reparse types.
 *   Malformed reparse buffers can lead to out-of-bounds reads or writes
 *   when processing SubstituteName and PrintName offsets.
 *
 *   Targets:
 *     - ReparseDataLength vs actual buffer validation
 *     - SubstituteNameOffset/Length bounds checking
 *     - PrintNameOffset/Length bounds checking
 *     - Reparse tag validation
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_reparse_point() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the reparse structures to avoid full header dependencies.
 */

struct reparse_data_buffer {
	__le32 ReparseTag;
	__le16 ReparseDataLength;
	__le16 Reserved;
	__u8   DataBuffer[];
} __packed;

struct reparse_symlink_data {
	__le32 ReparseTag;
	__le16 ReparseDataLength;
	__le16 Reserved;
	__le16 SubstituteNameOffset;
	__le16 SubstituteNameLength;
	__le16 PrintNameOffset;
	__le16 PrintNameLength;
	__le32 Flags;
	__u8   PathBuffer[];
} __packed;

struct reparse_mount_point_data {
	__le32 ReparseTag;
	__le16 ReparseDataLength;
	__le16 Reserved;
	__le16 SubstituteNameOffset;
	__le16 SubstituteNameLength;
	__le16 PrintNameOffset;
	__le16 PrintNameLength;
	__u8   PathBuffer[];
} __packed;

/* Well-known reparse tags */
#define IO_REPARSE_TAG_SYMLINK		0xA000000CU
#define IO_REPARSE_TAG_MOUNT_POINT	0xA0000003U
#define IO_REPARSE_TAG_NFS		0x80000014U

/* Reparse header size (before variable data) */
#define REPARSE_HDR_SIZE	offsetof(struct reparse_data_buffer, DataBuffer)
#define SYMLINK_HDR_SIZE	offsetof(struct reparse_symlink_data, PathBuffer)
#define MOUNT_HDR_SIZE		offsetof(struct reparse_mount_point_data, PathBuffer)

/* Symlink data fields size (after common reparse header) */
#define SYMLINK_FIELDS_SIZE	(SYMLINK_HDR_SIZE - REPARSE_HDR_SIZE)
#define MOUNT_FIELDS_SIZE	(MOUNT_HDR_SIZE - REPARSE_HDR_SIZE)

/*
 * fuzz_validate_symlink - Validate a symbolic link reparse buffer
 * @data:	raw input starting at the reparse buffer
 * @len:	total buffer length
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_symlink(const u8 *data, size_t len)
{
	const struct reparse_symlink_data *sym;
	u16 reparse_data_len;
	u16 sub_name_off, sub_name_len;
	u16 print_name_off, print_name_len;
	u16 path_buffer_len;

	if (len < SYMLINK_HDR_SIZE) {
		pr_debug("fuzz_reparse: symlink header too small (%zu)\n", len);
		return -EINVAL;
	}

	sym = (const struct reparse_symlink_data *)data;
	reparse_data_len = le16_to_cpu(sym->ReparseDataLength);
	sub_name_off = le16_to_cpu(sym->SubstituteNameOffset);
	sub_name_len = le16_to_cpu(sym->SubstituteNameLength);
	print_name_off = le16_to_cpu(sym->PrintNameOffset);
	print_name_len = le16_to_cpu(sym->PrintNameLength);

	/* Validate ReparseDataLength vs buffer */
	if (REPARSE_HDR_SIZE + reparse_data_len > len) {
		pr_debug("fuzz_reparse: ReparseDataLength %u exceeds buffer %zu\n",
			 reparse_data_len, len);
		return -EINVAL;
	}

	/* ReparseDataLength must account for the symlink-specific fields */
	if (reparse_data_len < SYMLINK_FIELDS_SIZE) {
		pr_debug("fuzz_reparse: ReparseDataLength %u too small for symlink fields\n",
			 reparse_data_len);
		return -EINVAL;
	}

	/* Path buffer length available */
	path_buffer_len = reparse_data_len - SYMLINK_FIELDS_SIZE;

	/* Validate SubstituteName bounds within PathBuffer */
	if ((u32)sub_name_off + sub_name_len > path_buffer_len) {
		pr_debug("fuzz_reparse: SubstituteName at %u+%u exceeds PathBuffer %u\n",
			 sub_name_off, sub_name_len, path_buffer_len);
		return -EINVAL;
	}

	/* Validate PrintName bounds within PathBuffer */
	if ((u32)print_name_off + print_name_len > path_buffer_len) {
		pr_debug("fuzz_reparse: PrintName at %u+%u exceeds PathBuffer %u\n",
			 print_name_off, print_name_len, path_buffer_len);
		return -EINVAL;
	}

	pr_debug("fuzz_reparse: valid symlink sub=%u+%u print=%u+%u flags=0x%x\n",
		 sub_name_off, sub_name_len, print_name_off, print_name_len,
		 le32_to_cpu(sym->Flags));

	return 0;
}

/*
 * fuzz_validate_mount_point - Validate a mount point reparse buffer
 * @data:	raw input starting at the reparse buffer
 * @len:	total buffer length
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_mount_point(const u8 *data, size_t len)
{
	const struct reparse_mount_point_data *mp;
	u16 reparse_data_len;
	u16 sub_name_off, sub_name_len;
	u16 print_name_off, print_name_len;
	u16 path_buffer_len;

	if (len < MOUNT_HDR_SIZE) {
		pr_debug("fuzz_reparse: mount point header too small (%zu)\n",
			 len);
		return -EINVAL;
	}

	mp = (const struct reparse_mount_point_data *)data;
	reparse_data_len = le16_to_cpu(mp->ReparseDataLength);
	sub_name_off = le16_to_cpu(mp->SubstituteNameOffset);
	sub_name_len = le16_to_cpu(mp->SubstituteNameLength);
	print_name_off = le16_to_cpu(mp->PrintNameOffset);
	print_name_len = le16_to_cpu(mp->PrintNameLength);

	/* Validate ReparseDataLength vs buffer */
	if (REPARSE_HDR_SIZE + reparse_data_len > len) {
		pr_debug("fuzz_reparse: mount ReparseDataLength %u exceeds buffer %zu\n",
			 reparse_data_len, len);
		return -EINVAL;
	}

	if (reparse_data_len < MOUNT_FIELDS_SIZE) {
		pr_debug("fuzz_reparse: mount ReparseDataLength %u too small\n",
			 reparse_data_len);
		return -EINVAL;
	}

	path_buffer_len = reparse_data_len - MOUNT_FIELDS_SIZE;

	if ((u32)sub_name_off + sub_name_len > path_buffer_len) {
		pr_debug("fuzz_reparse: mount SubstituteName at %u+%u exceeds PathBuffer %u\n",
			 sub_name_off, sub_name_len, path_buffer_len);
		return -EINVAL;
	}

	if ((u32)print_name_off + print_name_len > path_buffer_len) {
		pr_debug("fuzz_reparse: mount PrintName at %u+%u exceeds PathBuffer %u\n",
			 print_name_off, print_name_len, path_buffer_len);
		return -EINVAL;
	}

	pr_debug("fuzz_reparse: valid mount point sub=%u+%u print=%u+%u\n",
		 sub_name_off, sub_name_len, print_name_off, print_name_len);

	return 0;
}

/*
 * fuzz_reparse_point - Fuzz reparse data buffer parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the reparse buffer validation that ksmbd performs when
 * processing FSCTL_SET_REPARSE_POINT requests.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_reparse_point(const u8 *data, size_t len)
{
	const struct reparse_data_buffer *rdb;
	u32 reparse_tag;
	u16 reparse_data_len;

	if (len < REPARSE_HDR_SIZE) {
		pr_debug("fuzz_reparse: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	rdb = (const struct reparse_data_buffer *)data;
	reparse_tag = le32_to_cpu(rdb->ReparseTag);
	reparse_data_len = le16_to_cpu(rdb->ReparseDataLength);

	/* Validate ReparseDataLength fits in buffer */
	if (REPARSE_HDR_SIZE + reparse_data_len > len) {
		pr_debug("fuzz_reparse: ReparseDataLength %u exceeds buffer %zu\n",
			 reparse_data_len, len);
		return -EINVAL;
	}

	pr_debug("fuzz_reparse: tag=0x%08x datalen=%u\n",
		 reparse_tag, reparse_data_len);

	/* Dispatch based on reparse tag */
	switch (reparse_tag) {
	case IO_REPARSE_TAG_SYMLINK:
		return fuzz_validate_symlink(data, len);
	case IO_REPARSE_TAG_MOUNT_POINT:
		return fuzz_validate_mount_point(data, len);
	default:
		/* Unknown tag - just validate basic header consistency */
		pr_debug("fuzz_reparse: unknown tag 0x%08x, basic validation only\n",
			 reparse_tag);
		return 0;
	}
}

static int __init reparse_point_fuzz_init(void)
{
	u8 *test_buf;
	struct reparse_symlink_data *sym;
	int ret;

	pr_info("reparse_point_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid symlink reparse buffer */
	sym = (struct reparse_symlink_data *)test_buf;
	sym->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	sym->ReparseDataLength = cpu_to_le16(SYMLINK_FIELDS_SIZE + 20);
	sym->SubstituteNameOffset = cpu_to_le16(0);
	sym->SubstituteNameLength = cpu_to_le16(10);
	sym->PrintNameOffset = cpu_to_le16(10);
	sym->PrintNameLength = cpu_to_le16(10);
	sym->Flags = 0;

	ret = fuzz_reparse_point(test_buf,
		SYMLINK_HDR_SIZE + 20);
	pr_info("reparse_point_fuzz: valid symlink test returned %d\n", ret);

	/* Self-test 2: truncated reparse buffer */
	ret = fuzz_reparse_point(test_buf, 4);
	pr_info("reparse_point_fuzz: truncated test returned %d\n", ret);

	/* Self-test 3: offsets past end of buffer */
	memset(test_buf, 0, 256);
	sym = (struct reparse_symlink_data *)test_buf;
	sym->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	sym->ReparseDataLength = cpu_to_le16(SYMLINK_FIELDS_SIZE + 10);
	sym->SubstituteNameOffset = cpu_to_le16(0);
	sym->SubstituteNameLength = cpu_to_le16(100); /* way past end */
	sym->PrintNameOffset = cpu_to_le16(0);
	sym->PrintNameLength = cpu_to_le16(0);

	ret = fuzz_reparse_point(test_buf,
		SYMLINK_HDR_SIZE + 10);
	pr_info("reparse_point_fuzz: offsets past end test returned %d\n", ret);

	/* Self-test 4: zero-length target */
	memset(test_buf, 0, 256);
	sym = (struct reparse_symlink_data *)test_buf;
	sym->ReparseTag = cpu_to_le32(IO_REPARSE_TAG_SYMLINK);
	sym->ReparseDataLength = cpu_to_le16(SYMLINK_FIELDS_SIZE);
	sym->SubstituteNameOffset = 0;
	sym->SubstituteNameLength = 0;
	sym->PrintNameOffset = 0;
	sym->PrintNameLength = 0;

	ret = fuzz_reparse_point(test_buf, SYMLINK_HDR_SIZE);
	pr_info("reparse_point_fuzz: zero-length target test returned %d\n", ret);

	/* Self-test 5: garbage data */
	memset(test_buf, 0xff, 256);
	ret = fuzz_reparse_point(test_buf, 256);
	pr_info("reparse_point_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit reparse_point_fuzz_exit(void)
{
	pr_info("reparse_point_fuzz: module unloaded\n");
}

module_init(reparse_point_fuzz_init);
module_exit(reparse_point_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for reparse data buffer parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
