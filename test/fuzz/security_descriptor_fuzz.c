// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for NT security descriptor parsing
 *
 *   This module exercises the NT security descriptor parsing logic used
 *   in ksmbd's ACL handling. Security descriptors carry owner/group SIDs,
 *   DACLs, and SACLs. Malformed descriptors can lead to out-of-bounds
 *   reads, integer overflows, or privilege escalation if not properly
 *   validated.
 *
 *   Targets:
 *     - struct smb_ntsd offset validation (osidoffset, gsidoffset, etc.)
 *     - SID num_subauth bounds checking
 *     - ACL size vs actual ACE count validation
 *     - Nested offset overflow detection
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_security_descriptor() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the structures we need to avoid pulling in the full ksmbd
 * header chain, which has complex kernel dependencies.
 */

#define SID_MAX_SUB_AUTHORITIES	15

struct smb_sid {
	__u8 revision;
	__u8 num_subauth;
	__u8 authority[6];
	__le32 sub_auth[];
} __packed;

struct smb_acl {
	__le16 revision;
	__le16 size;
	__le32 num_aces;
	__le16 reserved;
} __packed;

struct smb_ace {
	__u8 type;
	__u8 flags;
	__le16 size;
	__le32 access_req;
	struct smb_sid sid;
} __packed;

struct smb_ntsd {
	__le16 revision;
	__le16 type;
	__le32 osidoffset;
	__le32 gsidoffset;
	__le32 sacloffset;
	__le32 dacloffset;
} __packed;

/*
 * fuzz_validate_sid - Validate a SID at a given offset in the buffer
 * @data:	buffer base
 * @len:	total buffer length
 * @offset:	offset to the SID within the buffer
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_sid(const u8 *data, size_t len, u32 offset)
{
	const struct smb_sid *sid;
	size_t sid_size;

	/* Check that the SID header fits */
	if (offset + sizeof(struct smb_sid) > len) {
		pr_debug("fuzz_sd: SID header at offset %u exceeds buffer\n",
			 offset);
		return -EINVAL;
	}

	sid = (const struct smb_sid *)(data + offset);

	/* Validate revision */
	if (sid->revision != 1) {
		pr_debug("fuzz_sd: SID revision %u != 1\n", sid->revision);
		return -EINVAL;
	}

	/* Validate num_subauth bounds */
	if (sid->num_subauth > SID_MAX_SUB_AUTHORITIES) {
		pr_debug("fuzz_sd: SID num_subauth %u exceeds max %u\n",
			 sid->num_subauth, SID_MAX_SUB_AUTHORITIES);
		return -EINVAL;
	}

	/* Check that all sub-authorities fit in the buffer */
	sid_size = sizeof(struct smb_sid) +
		   sid->num_subauth * sizeof(__le32);
	if (offset + sid_size > len) {
		pr_debug("fuzz_sd: SID at offset %u with %u sub_auth exceeds buffer\n",
			 offset, sid->num_subauth);
		return -EINVAL;
	}

	pr_debug("fuzz_sd: valid SID rev=%u num_subauth=%u\n",
		 sid->revision, sid->num_subauth);
	return 0;
}

/*
 * fuzz_validate_acl - Validate an ACL at a given offset in the buffer
 * @data:	buffer base
 * @len:	total buffer length
 * @offset:	offset to the ACL within the buffer
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_acl(const u8 *data, size_t len, u32 offset)
{
	const struct smb_acl *acl;
	const struct smb_ace *ace;
	u16 acl_size;
	u32 num_aces;
	u32 ace_offset;
	u32 i;
	u16 ace_size;

	/* Check that the ACL header fits */
	if (offset + sizeof(struct smb_acl) > len) {
		pr_debug("fuzz_sd: ACL header at offset %u exceeds buffer\n",
			 offset);
		return -EINVAL;
	}

	acl = (const struct smb_acl *)(data + offset);
	acl_size = le16_to_cpu(acl->size);
	num_aces = le32_to_cpu(acl->num_aces);

	/* Validate ACL size fits in buffer */
	if (offset + acl_size > len) {
		pr_debug("fuzz_sd: ACL size %u at offset %u exceeds buffer\n",
			 acl_size, offset);
		return -EINVAL;
	}

	/* Validate ACL size is at least the header */
	if (acl_size < sizeof(struct smb_acl)) {
		pr_debug("fuzz_sd: ACL size %u smaller than header\n",
			 acl_size);
		return -EINVAL;
	}

	/* Cap num_aces to prevent excessive processing */
	if (num_aces > 1024) {
		pr_debug("fuzz_sd: ACL num_aces %u exceeds safety limit\n",
			 num_aces);
		return -EINVAL;
	}

	/* Walk ACE entries */
	ace_offset = offset + sizeof(struct smb_acl);
	for (i = 0; i < num_aces; i++) {
		/* Check ACE header fits */
		if (ace_offset + sizeof(struct smb_ace) > len ||
		    ace_offset + sizeof(struct smb_ace) > offset + acl_size) {
			pr_debug("fuzz_sd: ACE %u header at %u exceeds bounds\n",
				 i, ace_offset);
			return -EINVAL;
		}

		ace = (const struct smb_ace *)(data + ace_offset);
		ace_size = le16_to_cpu(ace->size);

		/* Validate ACE size */
		if (ace_size < sizeof(struct smb_ace)) {
			pr_debug("fuzz_sd: ACE %u size %u too small\n",
				 i, ace_size);
			return -EINVAL;
		}

		if (ace_offset + ace_size > offset + acl_size) {
			pr_debug("fuzz_sd: ACE %u overflows ACL boundary\n", i);
			return -EINVAL;
		}

		/* Validate the embedded SID in this ACE */
		if (ace->sid.num_subauth > SID_MAX_SUB_AUTHORITIES) {
			pr_debug("fuzz_sd: ACE %u SID num_subauth %u too large\n",
				 i, ace->sid.num_subauth);
			return -EINVAL;
		}

		ace_offset += ace_size;
	}

	pr_debug("fuzz_sd: valid ACL size=%u num_aces=%u\n",
		 acl_size, num_aces);
	return 0;
}

/*
 * fuzz_security_descriptor - Fuzz NT security descriptor parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the security descriptor validation that ksmbd performs
 * when processing SET_INFO requests with security information.
 *
 * Return: 0 on success (valid or gracefully rejected), negative on error
 */
static int fuzz_security_descriptor(const u8 *data, size_t len)
{
	const struct smb_ntsd *ntsd;
	u32 osidoffset, gsidoffset, sacloffset, dacloffset;
	int ret;

	if (len < sizeof(struct smb_ntsd)) {
		pr_debug("fuzz_sd: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	/* Cap input to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	ntsd = (const struct smb_ntsd *)data;

	/* Extract offsets */
	osidoffset = le32_to_cpu(ntsd->osidoffset);
	gsidoffset = le32_to_cpu(ntsd->gsidoffset);
	sacloffset = le32_to_cpu(ntsd->sacloffset);
	dacloffset = le32_to_cpu(ntsd->dacloffset);

	pr_debug("fuzz_sd: rev=%u type=0x%04x osid=%u gsid=%u sacl=%u dacl=%u\n",
		 le16_to_cpu(ntsd->revision), le16_to_cpu(ntsd->type),
		 osidoffset, gsidoffset, sacloffset, dacloffset);

	/* Validate owner SID if present */
	if (osidoffset != 0) {
		if (osidoffset < sizeof(struct smb_ntsd)) {
			pr_debug("fuzz_sd: osidoffset %u overlaps header\n",
				 osidoffset);
			return -EINVAL;
		}
		ret = fuzz_validate_sid(data, len, osidoffset);
		if (ret < 0)
			return ret;
	}

	/* Validate group SID if present */
	if (gsidoffset != 0) {
		if (gsidoffset < sizeof(struct smb_ntsd)) {
			pr_debug("fuzz_sd: gsidoffset %u overlaps header\n",
				 gsidoffset);
			return -EINVAL;
		}
		ret = fuzz_validate_sid(data, len, gsidoffset);
		if (ret < 0)
			return ret;
	}

	/* Validate SACL if present */
	if (sacloffset != 0) {
		if (sacloffset < sizeof(struct smb_ntsd)) {
			pr_debug("fuzz_sd: sacloffset %u overlaps header\n",
				 sacloffset);
			return -EINVAL;
		}
		ret = fuzz_validate_acl(data, len, sacloffset);
		if (ret < 0)
			return ret;
	}

	/* Validate DACL if present */
	if (dacloffset != 0) {
		if (dacloffset < sizeof(struct smb_ntsd)) {
			pr_debug("fuzz_sd: dacloffset %u overlaps header\n",
				 dacloffset);
			return -EINVAL;
		}
		ret = fuzz_validate_acl(data, len, dacloffset);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int __init security_descriptor_fuzz_init(void)
{
	u8 *test_buf;
	struct smb_ntsd *ntsd;
	struct smb_sid *sid;
	int ret;

	pr_info("security_descriptor_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid minimal security descriptor with owner SID */
	ntsd = (struct smb_ntsd *)test_buf;
	ntsd->revision = cpu_to_le16(1);
	ntsd->type = cpu_to_le16(0);
	ntsd->osidoffset = cpu_to_le32(sizeof(struct smb_ntsd));
	ntsd->gsidoffset = 0;
	ntsd->sacloffset = 0;
	ntsd->dacloffset = 0;

	sid = (struct smb_sid *)(test_buf + sizeof(struct smb_ntsd));
	sid->revision = 1;
	sid->num_subauth = 1;
	memset(sid->authority, 0, 6);
	sid->authority[5] = 5; /* NT Authority */
	sid->sub_auth[0] = cpu_to_le32(18); /* Local System */

	ret = fuzz_security_descriptor(test_buf,
		sizeof(struct smb_ntsd) + sizeof(struct smb_sid) + sizeof(__le32));
	pr_info("security_descriptor_fuzz: valid SD test returned %d\n", ret);

	/* Self-test 2: truncated security descriptor */
	ret = fuzz_security_descriptor(test_buf, 4);
	pr_info("security_descriptor_fuzz: truncated SD test returned %d\n", ret);

	/* Self-test 3: zero-offset security descriptor (all offsets zero) */
	memset(test_buf, 0, 256);
	ntsd = (struct smb_ntsd *)test_buf;
	ntsd->revision = cpu_to_le16(1);
	ret = fuzz_security_descriptor(test_buf, sizeof(struct smb_ntsd));
	pr_info("security_descriptor_fuzz: zero-offset SD test returned %d\n", ret);

	/* Self-test 4: huge num_subauth in SID */
	memset(test_buf, 0, 256);
	ntsd = (struct smb_ntsd *)test_buf;
	ntsd->revision = cpu_to_le16(1);
	ntsd->osidoffset = cpu_to_le32(sizeof(struct smb_ntsd));
	sid = (struct smb_sid *)(test_buf + sizeof(struct smb_ntsd));
	sid->revision = 1;
	sid->num_subauth = 255; /* way over the limit */
	ret = fuzz_security_descriptor(test_buf, 256);
	pr_info("security_descriptor_fuzz: huge num_subauth test returned %d\n", ret);

	/* Self-test 5: garbage data */
	memset(test_buf, 0xff, 256);
	ret = fuzz_security_descriptor(test_buf, 256);
	pr_info("security_descriptor_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit security_descriptor_fuzz_exit(void)
{
	pr_info("security_descriptor_fuzz: module unloaded\n");
}

module_init(security_descriptor_fuzz_init);
module_exit(security_descriptor_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for NT security descriptor parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
