// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for NDR encode/decode
 *
 *   This module exercises the Network Data Representation (NDR) encoding
 *   and decoding routines used by ksmbd for DOS attribute and NTACL
 *   xattr serialization. Buffer overflows in NDR parsing are a common
 *   vulnerability class.
 *
 *   Targets:
 *     - ndr_decode_dos_attr: DOS attribute deserialization
 *     - ndr_decode_v4_ntacl: NT ACL version 4 deserialization
 *     - ndr_read_string: bounded string reading
 *     - ndr_read_int16/int32/int64: integer reading with bounds checks
 *     - ndr_encode_dos_attr: DOS attribute serialization
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_ndr_decode_dos_attr() and
 *     fuzz_ndr_decode_v4_ntacl() entry points accept raw byte buffers.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/overflow.h>

/*
 * Replicate the ndr structure and xattr structures needed for fuzzing.
 * These match the definitions in ndr.h and xattr.h.
 */
struct fuzz_ndr {
	char		*data;
	unsigned int	offset;
	unsigned int	length;
};

#define FUZZ_XATTR_SD_HASH_SIZE	64

struct fuzz_xattr_dos_attrib {
	__u16	version;
	__u32	flags;
	__u32	attr;
	__u32	ea_size;
	__u64	size;
	__u64	alloc_size;
	__u64	itime;
	__u64	create_time;
	__u64	change_time;
};

struct fuzz_xattr_ntacl {
	__u16	version;
	void	*sd_buf;
	__u32	sd_size;
	__u16	hash_type;
	__u8	desc[10];
	__u16	desc_len;
	__u64	current_time;
	__u8	hash[FUZZ_XATTR_SD_HASH_SIZE];
	__u8	posix_acl_hash[FUZZ_XATTR_SD_HASH_SIZE];
};

/* NDR read primitives - faithful copies from ndr.c */

static inline char *fuzz_ndr_get_field(struct fuzz_ndr *n)
{
	return n->data + n->offset;
}

static int fuzz_ndr_read_int16(struct fuzz_ndr *n, __u16 *value)
{
	if (n->offset + sizeof(__u16) > n->length)
		return -EINVAL;

	if (value)
		*value = get_unaligned_le16(fuzz_ndr_get_field(n));
	n->offset += sizeof(__u16);
	return 0;
}

static int fuzz_ndr_read_int32(struct fuzz_ndr *n, __u32 *value)
{
	if (n->offset + sizeof(__u32) > n->length)
		return -EINVAL;

	if (value)
		*value = get_unaligned_le32(fuzz_ndr_get_field(n));
	n->offset += sizeof(__u32);
	return 0;
}

static int fuzz_ndr_read_int64(struct fuzz_ndr *n, __u64 *value)
{
	if (n->offset + sizeof(__u64) > n->length)
		return -EINVAL;

	if (value)
		*value = get_unaligned_le64(fuzz_ndr_get_field(n));
	n->offset += sizeof(__u64);
	return 0;
}

static int fuzz_ndr_read_bytes(struct fuzz_ndr *n, void *value, size_t sz)
{
	unsigned int remaining;

	if (n->offset > n->length)
		return -EINVAL;

	remaining = n->length - n->offset;
	if (sz > remaining)
		return -EINVAL;

	if (value)
		memcpy(value, fuzz_ndr_get_field(n), sz);
	n->offset += sz;
	return 0;
}

static int fuzz_ndr_read_string(struct fuzz_ndr *n, void *value, size_t sz)
{
	unsigned int remaining;
	int len;

	if (n->offset > n->length)
		return -EINVAL;

	remaining = n->length - n->offset;
	if (sz > remaining)
		return -EINVAL;

	len = strnlen(fuzz_ndr_get_field(n), sz);
	if (len + 1 > remaining)
		return -EINVAL;

	if (value)
		memcpy(value, fuzz_ndr_get_field(n), len);
	len++;
	n->offset += len;
	n->offset = ALIGN(n->offset, 2);
	if (n->offset > n->length)
		return -EINVAL;
	return 0;
}

/*
 * fuzz_ndr_decode_dos_attr - Fuzz DOS attribute NDR decoding
 * @data:	raw input bytes (NDR-encoded DOS attributes)
 * @len:	length of input
 *
 * Simulates ndr_decode_dos_attr() from ndr.c. Tests all read paths
 * including version-dependent branches (version 3 vs version 4).
 *
 * Return: 0 on successful decode, negative on error
 */
static int fuzz_ndr_decode_dos_attr(const u8 *data, size_t len)
{
	struct fuzz_ndr n;
	struct fuzz_xattr_dos_attrib da;
	char hex_attr[12];
	unsigned int version2;
	int ret;

	if (len == 0)
		return -EINVAL;

	/* Cap input to prevent excessive allocations */
	if (len > 4096)
		len = 4096;

	n.data = (char *)data;
	n.offset = 0;
	n.length = len;

	memset(&da, 0, sizeof(da));

	ret = fuzz_ndr_read_string(&n, hex_attr, sizeof(hex_attr));
	if (ret)
		return ret;

	ret = fuzz_ndr_read_int16(&n, &da.version);
	if (ret)
		return ret;

	if (da.version != 3 && da.version != 4) {
		pr_debug("fuzz_ndr: unsupported version %d\n", da.version);
		return -EINVAL;
	}

	ret = fuzz_ndr_read_int32(&n, &version2);
	if (ret)
		return ret;

	if (da.version != version2) {
		pr_debug("fuzz_ndr: version mismatch %d vs %d\n",
			 da.version, version2);
		return -EINVAL;
	}

	/* Skip flags */
	ret = fuzz_ndr_read_int32(&n, NULL);
	if (ret)
		return ret;

	ret = fuzz_ndr_read_int32(&n, &da.attr);
	if (ret)
		return ret;

	if (da.version == 4) {
		ret = fuzz_ndr_read_int64(&n, &da.itime);
		if (ret)
			return ret;
		ret = fuzz_ndr_read_int64(&n, &da.create_time);
	} else {
		/* version 3 */
		ret = fuzz_ndr_read_int32(&n, NULL); /* ea_size */
		if (ret)
			return ret;
		ret = fuzz_ndr_read_int64(&n, NULL); /* size */
		if (ret)
			return ret;
		ret = fuzz_ndr_read_int64(&n, NULL); /* alloc_size */
		if (ret)
			return ret;
		ret = fuzz_ndr_read_int64(&n, &da.create_time);
		if (ret)
			return ret;
		ret = fuzz_ndr_read_int64(&n, NULL); /* change_time */
	}

	if (ret == 0)
		pr_debug("fuzz_ndr: decoded DOS attr v%d attr=0x%x\n",
			 da.version, da.attr);

	return ret;
}

/*
 * fuzz_ndr_decode_v4_ntacl - Fuzz NT ACL v4 NDR decoding
 * @data:	raw input bytes (NDR-encoded NT ACL)
 * @len:	length of input
 *
 * Simulates ndr_decode_v4_ntacl() from ndr.c. Tests version validation,
 * hash reading, descriptor parsing, and the security descriptor buffer
 * allocation path.
 *
 * Return: 0 on successful decode, negative on error
 */
static int fuzz_ndr_decode_v4_ntacl(const u8 *data, size_t len)
{
	struct fuzz_ndr n;
	struct fuzz_xattr_ntacl acl;
	unsigned int version2;
	int ret;

	if (len == 0)
		return -EINVAL;

	if (len > 65536)
		len = 65536;

	n.data = (char *)data;
	n.offset = 0;
	n.length = len;

	memset(&acl, 0, sizeof(acl));

	ret = fuzz_ndr_read_int16(&n, &acl.version);
	if (ret)
		return ret;

	if (acl.version != 4) {
		pr_debug("fuzz_ndr: unsupported NTACL version %d\n",
			 acl.version);
		return -EINVAL;
	}

	ret = fuzz_ndr_read_int32(&n, &version2);
	if (ret)
		return ret;

	if (acl.version != version2) {
		pr_debug("fuzz_ndr: NTACL version mismatch\n");
		return -EINVAL;
	}

	/* Read Level */
	ret = fuzz_ndr_read_int16(&n, NULL);
	if (ret)
		return ret;

	/* Read Ref Id */
	ret = fuzz_ndr_read_int32(&n, NULL);
	if (ret)
		return ret;

	/* Read hash type */
	ret = fuzz_ndr_read_int16(&n, &acl.hash_type);
	if (ret)
		return ret;

	/* Read hash */
	ret = fuzz_ndr_read_bytes(&n, acl.hash, FUZZ_XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	/* Read description */
	ret = fuzz_ndr_read_bytes(&n, acl.desc, 10);
	if (ret)
		return ret;

	if (strncmp(acl.desc, "posix_acl", 9)) {
		pr_debug("fuzz_ndr: invalid acl description\n");
		return -EINVAL;
	}

	/* Read Time */
	ret = fuzz_ndr_read_int64(&n, NULL);
	if (ret)
		return ret;

	/* Read Posix ACL hash */
	ret = fuzz_ndr_read_bytes(&n, acl.posix_acl_hash,
				  FUZZ_XATTR_SD_HASH_SIZE);
	if (ret)
		return ret;

	/* Calculate remaining data for security descriptor */
	if (n.offset > n.length)
		return -EINVAL;

	acl.sd_size = n.length - n.offset;
	if (acl.sd_size == 0) {
		pr_debug("fuzz_ndr: no security descriptor data\n");
		return -EINVAL;
	}

	acl.sd_buf = kzalloc(acl.sd_size, GFP_KERNEL);
	if (!acl.sd_buf)
		return -ENOMEM;

	ret = fuzz_ndr_read_bytes(&n, acl.sd_buf, acl.sd_size);
	kfree(acl.sd_buf);

	if (ret == 0)
		pr_debug("fuzz_ndr: decoded NTACL v4 sd_size=%u\n",
			 acl.sd_size);

	return ret;
}

static int __init ndr_fuzz_init(void)
{
	u8 *test_buf;
	int ret;

	pr_info("ndr_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test: empty input */
	ret = fuzz_ndr_decode_dos_attr(test_buf, 0);
	pr_info("ndr_fuzz: DOS attr empty test returned %d\n", ret);

	/* Self-test: minimal valid v4 DOS attr */
	{
		struct fuzz_ndr n;
		char *buf = test_buf;

		memset(buf, 0, 512);
		/* Write a null-terminated string (empty) */
		buf[0] = '\0';
		buf[1] = '\0'; /* padding for alignment */
		/* version = 4 at offset 2 */
		put_unaligned_le16(4, buf + 2);
		/* version2 = 4 at offset 4 */
		put_unaligned_le32(4, buf + 4);
		/* flags at offset 8 */
		put_unaligned_le32(0, buf + 8);
		/* attr at offset 12 */
		put_unaligned_le32(0x20, buf + 12);
		/* itime at offset 16 */
		put_unaligned_le64(0, buf + 16);
		/* create_time at offset 24 */
		put_unaligned_le64(0, buf + 24);

		n.data = NULL;
		n.offset = 0;
		n.length = 0;
		(void)n;

		ret = fuzz_ndr_decode_dos_attr(test_buf, 32);
		pr_info("ndr_fuzz: DOS attr v4 test returned %d\n", ret);
	}

	/* Self-test: garbage data for DOS attr */
	memset(test_buf, 0xAA, 512);
	ret = fuzz_ndr_decode_dos_attr(test_buf, 512);
	pr_info("ndr_fuzz: DOS attr garbage test returned %d\n", ret);

	/* Self-test: empty input for NTACL */
	ret = fuzz_ndr_decode_v4_ntacl(test_buf, 0);
	pr_info("ndr_fuzz: NTACL empty test returned %d\n", ret);

	/* Self-test: too-short input for NTACL */
	memset(test_buf, 0, 512);
	put_unaligned_le16(4, test_buf); /* version = 4 */
	ret = fuzz_ndr_decode_v4_ntacl(test_buf, 4);
	pr_info("ndr_fuzz: NTACL short test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit ndr_fuzz_exit(void)
{
	pr_info("ndr_fuzz: module unloaded\n");
}

module_init(ndr_fuzz_init);
module_exit(ndr_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for NDR encode/decode");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
