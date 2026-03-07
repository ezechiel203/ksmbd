// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for security descriptor construction and parsing
 *
 *   This module exercises both construction and parsing of NT security
 *   descriptors with randomly generated DACL/SACL entries containing
 *   malformed ACE entries, invalid SID sub-authority counts, oversized
 *   ACLs, and corrupted offsets. It complements security_descriptor_fuzz.c
 *   by focusing on the builder (construction) path in addition to parsing.
 *
 *   Targets:
 *     - DACL/SACL construction with random ACE counts
 *     - ACE type validation (ACCESS_ALLOWED, ACCESS_DENIED, SYSTEM_AUDIT)
 *     - SID sub-authority count bounds (0-15, with overflow attempts)
 *     - ACL size consistency: declared vs actual
 *     - Overlapping DACL/SACL offsets
 *     - Owner/Group SID pointing into DACL/SACL region
 *     - Self-relative security descriptor flag
 *     - Round-trip: build then parse
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

/* Inline structures matching smbacl.c */

#define SID_MAX_SUB_AUTHORITIES		15
#define SELF_RELATIVE			0x8000
#define DACL_PRESENT			0x0004
#define SACL_PRESENT			0x0010

/* ACE types */
#define ACCESS_ALLOWED_ACE_TYPE		0x00
#define ACCESS_DENIED_ACE_TYPE		0x01
#define SYSTEM_AUDIT_ACE_TYPE		0x02
#define SYSTEM_ALARM_ACE_TYPE		0x03

/* ACE flags */
#define OBJECT_INHERIT_ACE		0x01
#define CONTAINER_INHERIT_ACE		0x02
#define INHERIT_ONLY_ACE		0x08
#define INHERITED_ACE			0x10

struct fuzz_sid {
	__u8   revision;
	__u8   num_subauth;
	__u8   authority[6];
	__le32 sub_auth[];
} __packed;

struct fuzz_acl {
	__le16 revision;
	__le16 size;
	__le32 num_aces;
	__le16 reserved;
} __packed;

struct fuzz_ace {
	__u8   type;
	__u8   flags;
	__le16 size;
	__le32 access_req;
	struct fuzz_sid sid;
} __packed;

struct fuzz_ntsd {
	__le16 revision;
	__le16 type;
	__le32 osidoffset;
	__le32 gsidoffset;
	__le32 sacloffset;
	__le32 dacloffset;
} __packed;

#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		4096
#define MAX_ACES_PER_ACL	32

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

/*
 * fuzz_build_sid - Build a random SID at the given offset
 * @buf:	buffer base
 * @offset:	write offset
 * @max_len:	buffer size
 *
 * Return: bytes written, or 0 if no space
 */
static size_t fuzz_build_sid(u8 *buf, size_t offset, size_t max_len)
{
	struct fuzz_sid *sid;
	u8 num_subauth;
	size_t sid_size;
	u32 i;

	num_subauth = fuzz_next() % (SID_MAX_SUB_AUTHORITIES + 3);
	/* Cap to actual max for non-corrupt cases */
	if (fuzz_next() % 4 != 0 && num_subauth > SID_MAX_SUB_AUTHORITIES)
		num_subauth = fuzz_next() % (SID_MAX_SUB_AUTHORITIES + 1);

	sid_size = sizeof(struct fuzz_sid) + num_subauth * sizeof(__le32);
	if (offset + sid_size > max_len)
		return 0;

	sid = (struct fuzz_sid *)(buf + offset);
	sid->revision = (fuzz_next() % 5 == 0) ? fuzz_next() % 3 : 1;
	sid->num_subauth = num_subauth;

	/* Authority: NT Authority (5) or random */
	memset(sid->authority, 0, 6);
	if (fuzz_next() % 3 == 0)
		get_random_bytes(sid->authority, 6);
	else
		sid->authority[5] = 5;

	for (i = 0; i < num_subauth && i < SID_MAX_SUB_AUTHORITIES; i++)
		sid->sub_auth[i] = cpu_to_le32(fuzz_next());

	return sid_size;
}

/*
 * fuzz_build_acl - Build a random ACL at the given offset
 * @buf:	buffer base
 * @offset:	write offset
 * @max_len:	buffer size
 * @is_sacl:	true for SACL (uses SYSTEM_AUDIT type)
 *
 * Return: bytes written, or 0 if no space
 */
static size_t fuzz_build_acl(u8 *buf, size_t offset, size_t max_len,
			     bool is_sacl)
{
	struct fuzz_acl *acl;
	u32 num_aces;
	size_t acl_offset;
	u32 i;
	u32 corrupt = fuzz_next() % 8;

	if (offset + sizeof(struct fuzz_acl) > max_len)
		return 0;

	acl = (struct fuzz_acl *)(buf + offset);
	num_aces = fuzz_next() % (MAX_ACES_PER_ACL + 1);
	acl->revision = cpu_to_le16(2);
	acl->num_aces = cpu_to_le32(num_aces);
	acl->reserved = 0;

	acl_offset = offset + sizeof(struct fuzz_acl);

	for (i = 0; i < num_aces; i++) {
		struct fuzz_ace *ace;
		u8 ace_num_subauth;
		size_t ace_size;

		ace_num_subauth = fuzz_next() % 5;
		ace_size = sizeof(struct fuzz_ace) +
			   ace_num_subauth * sizeof(__le32);

		if (acl_offset + ace_size > max_len)
			break;

		ace = (struct fuzz_ace *)(buf + acl_offset);

		/* ACE type */
		if (is_sacl)
			ace->type = (fuzz_next() % 2) ?
				SYSTEM_AUDIT_ACE_TYPE : SYSTEM_ALARM_ACE_TYPE;
		else
			ace->type = (fuzz_next() % 2) ?
				ACCESS_ALLOWED_ACE_TYPE : ACCESS_DENIED_ACE_TYPE;

		/* Sometimes use invalid type */
		if (fuzz_next() % 10 == 0)
			ace->type = fuzz_next() % 256;

		ace->flags = fuzz_next() % 256;
		ace->size = cpu_to_le16(ace_size);
		ace->access_req = cpu_to_le32(fuzz_next());

		/* Embedded SID */
		ace->sid.revision = 1;
		ace->sid.num_subauth = ace_num_subauth;
		memset(ace->sid.authority, 0, 6);
		ace->sid.authority[5] = 5;

		{
			u32 j;

			for (j = 0; j < ace_num_subauth; j++)
				ace->sid.sub_auth[j] = cpu_to_le32(fuzz_next());
		}

		/* Corruption: sometimes wrong ACE size */
		if (corrupt == 0 && i == 0)
			ace->size = cpu_to_le16(fuzz_next() % 256);

		acl_offset += ace_size;
	}

	/* Set ACL size */
	if (corrupt == 1)
		acl->size = cpu_to_le16(fuzz_next()); /* random size */
	else if (corrupt == 2)
		acl->size = cpu_to_le16(4); /* too small */
	else
		acl->size = cpu_to_le16(acl_offset - offset);

	/* Corruption: wrong num_aces */
	if (corrupt == 3)
		acl->num_aces = cpu_to_le32(i + 100);

	return acl_offset - offset;
}

/*
 * fuzz_validate_built_sd - Parse and validate a security descriptor
 * @data:	buffer
 * @len:	buffer length
 *
 * Return: 0 on valid, negative on malformed
 */
static int fuzz_validate_built_sd(const u8 *data, size_t len)
{
	const struct fuzz_ntsd *ntsd;
	u32 osid, gsid, sacl, dacl;

	if (len < sizeof(struct fuzz_ntsd))
		return -EINVAL;

	ntsd = (const struct fuzz_ntsd *)data;
	osid = le32_to_cpu(ntsd->osidoffset);
	gsid = le32_to_cpu(ntsd->gsidoffset);
	sacl = le32_to_cpu(ntsd->sacloffset);
	dacl = le32_to_cpu(ntsd->dacloffset);

	/* Owner SID */
	if (osid != 0) {
		const struct fuzz_sid *sid;

		if (osid + sizeof(struct fuzz_sid) > len)
			return -EINVAL;
		sid = (const struct fuzz_sid *)(data + osid);
		if (sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
			return -EINVAL;
		if (osid + sizeof(struct fuzz_sid) +
		    sid->num_subauth * sizeof(__le32) > len)
			return -EINVAL;
	}

	/* Group SID */
	if (gsid != 0) {
		const struct fuzz_sid *sid;

		if (gsid + sizeof(struct fuzz_sid) > len)
			return -EINVAL;
		sid = (const struct fuzz_sid *)(data + gsid);
		if (sid->num_subauth > SID_MAX_SUB_AUTHORITIES)
			return -EINVAL;
	}

	/* DACL */
	if (dacl != 0) {
		const struct fuzz_acl *acl;

		if (dacl + sizeof(struct fuzz_acl) > len)
			return -EINVAL;
		acl = (const struct fuzz_acl *)(data + dacl);
		if (dacl + le16_to_cpu(acl->size) > len)
			return -EINVAL;
	}

	/* SACL */
	if (sacl != 0) {
		const struct fuzz_acl *acl;

		if (sacl + sizeof(struct fuzz_acl) > len)
			return -EINVAL;
		acl = (const struct fuzz_acl *)(data + sacl);
		if (sacl + le16_to_cpu(acl->size) > len)
			return -EINVAL;
	}

	return 0;
}

/*
 * fuzz_build_security_descriptor - Build a random security descriptor
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: total bytes written
 */
static size_t fuzz_build_security_descriptor(u8 *buf, size_t buf_size)
{
	struct fuzz_ntsd *ntsd;
	size_t offset;
	size_t sid_len, acl_len;
	u16 type_flags = SELF_RELATIVE;
	u32 corrupt = fuzz_next() % 10;

	if (buf_size < sizeof(struct fuzz_ntsd) + 64)
		return 0;

	memset(buf, 0, buf_size);
	ntsd = (struct fuzz_ntsd *)buf;
	ntsd->revision = cpu_to_le16(1);
	offset = sizeof(struct fuzz_ntsd);

	/* Owner SID */
	if (fuzz_next() % 4 != 0) {
		ntsd->osidoffset = cpu_to_le32(offset);
		sid_len = fuzz_build_sid(buf, offset, buf_size);
		offset += sid_len;
	}

	/* Group SID */
	if (fuzz_next() % 4 != 0) {
		ntsd->gsidoffset = cpu_to_le32(offset);
		sid_len = fuzz_build_sid(buf, offset, buf_size);
		offset += sid_len;
	}

	/* DACL */
	if (fuzz_next() % 3 != 0) {
		type_flags |= DACL_PRESENT;
		ntsd->dacloffset = cpu_to_le32(offset);
		acl_len = fuzz_build_acl(buf, offset, buf_size, false);
		offset += acl_len;
	}

	/* SACL */
	if (fuzz_next() % 3 != 0) {
		type_flags |= SACL_PRESENT;
		ntsd->sacloffset = cpu_to_le32(offset);
		acl_len = fuzz_build_acl(buf, offset, buf_size, true);
		offset += acl_len;
	}

	ntsd->type = cpu_to_le16(type_flags);

	/* Corruption: overlapping offsets */
	if (corrupt == 0 && ntsd->dacloffset && ntsd->osidoffset)
		ntsd->osidoffset = ntsd->dacloffset;
	else if (corrupt == 1)
		ntsd->dacloffset = cpu_to_le32(buf_size + 100);
	else if (corrupt == 2)
		ntsd->osidoffset = cpu_to_le32(2); /* inside header */

	return offset;
}

static int __init acl_builder_fuzz_init(void)
{
	u8 *buf;
	size_t sd_len;
	int i, ret;

	pr_info("acl_builder_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0xBAADF00D;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		sd_len = fuzz_build_security_descriptor(buf, FUZZ_BUF_SIZE);
		ret = fuzz_validate_built_sd(buf, sd_len);
		pr_debug("acl_builder_fuzz: iter %d build=%zu validate=%d\n",
			 i, sd_len, ret);
	}

	/* Edge cases */
	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_built_sd(buf, 0);
	fuzz_validate_built_sd(buf, 4);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_built_sd(buf, FUZZ_BUF_SIZE);

	kfree(buf);
	pr_info("acl_builder_fuzz: all iterations completed\n");
	return 0;
}

static void __exit acl_builder_fuzz_exit(void)
{
	pr_info("acl_builder_fuzz: module unloaded\n");
}

module_init(acl_builder_fuzz_init);
module_exit(acl_builder_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for security descriptor construction/parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
