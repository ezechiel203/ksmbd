// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for NDR encoding/decoding (ndr.c)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "xattr.h"
#include "ndr.h"

/*
 * test_ndr_encode_decode_dos_attr_v4 - roundtrip test for version 4
 *
 * Encode a version 4 xattr_dos_attrib, then decode it and verify all
 * fields match.
 */
static void test_ndr_encode_decode_dos_attr_v4(struct kunit *test)
{
	struct ndr n = {};
	struct xattr_dos_attrib da_in = {};
	struct xattr_dos_attrib da_out = {};
	int ret;

	da_in.version = 4;
	da_in.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_ITIME;
	da_in.attr = 0x20;
	da_in.itime = 132500000000000000ULL;
	da_in.create_time = 132500000000000000ULL;

	ret = ndr_encode_dos_attr(&n, &da_in);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, n.data);

	/* Reset offset for decode, preserve length and data */
	n.length = n.offset;
	n.offset = 0;

	ret = ndr_decode_dos_attr(&n, &da_out);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, da_out.version, (__u16)4);
	KUNIT_EXPECT_EQ(test, da_out.attr, da_in.attr);
	KUNIT_EXPECT_EQ(test, da_out.itime, da_in.itime);
	KUNIT_EXPECT_EQ(test, da_out.create_time, da_in.create_time);

	kfree(n.data);
}

/*
 * test_ndr_encode_decode_dos_attr_v3 - roundtrip test for version 3
 *
 * Encode a version 3 xattr_dos_attrib, then decode it and verify
 * the fields that are readable in version 3.
 */
static void test_ndr_encode_decode_dos_attr_v3(struct kunit *test)
{
	struct ndr n = {};
	struct xattr_dos_attrib da_in = {};
	struct xattr_dos_attrib da_out = {};
	int ret;

	da_in.version = 3;
	da_in.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME;
	da_in.attr = 0x10;
	da_in.ea_size = 256;
	da_in.size = 4096;
	da_in.alloc_size = 8192;
	da_in.create_time = 132500000000000000ULL;
	da_in.change_time = 132500000000000000ULL;

	ret = ndr_encode_dos_attr(&n, &da_in);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, n.data);

	/* Reset for decode */
	n.length = n.offset;
	n.offset = 0;

	ret = ndr_decode_dos_attr(&n, &da_out);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, da_out.version, (__u16)3);
	KUNIT_EXPECT_EQ(test, da_out.attr, da_in.attr);
	KUNIT_EXPECT_EQ(test, da_out.create_time, da_in.create_time);

	kfree(n.data);
}

/*
 * test_ndr_decode_dos_attr_truncated - decode should fail on truncated buffer
 *
 * Provide a buffer that is too short for a valid NDR-encoded dos_attrib
 * and verify that the decoder returns an error.
 */
static void test_ndr_decode_dos_attr_truncated(struct kunit *test)
{
	struct ndr n = {};
	struct xattr_dos_attrib da_out = {};
	int ret;

	/* Allocate a tiny buffer with just a few bytes */
	n.data = kzalloc(4, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4;
	n.offset = 0;

	/* Write a short string (empty) to make ndr_read_string pass */
	n.data[0] = '\0';

	ret = ndr_decode_dos_attr(&n, &da_out);
	KUNIT_EXPECT_NE(test, ret, 0);

	kfree(n.data);
}

/*
 * test_ndr_decode_dos_attr_bad_version - decode should reject invalid versions
 *
 * Encode a valid structure but patch the version field to 5 (unsupported).
 * The decoder should return -EINVAL.
 */
static void test_ndr_decode_dos_attr_bad_version(struct kunit *test)
{
	struct ndr n = {};
	struct xattr_dos_attrib da_in = {};
	struct xattr_dos_attrib da_out = {};
	int ret;

	da_in.version = 4;
	da_in.flags = 0;
	da_in.attr = 0x20;
	da_in.itime = 0;
	da_in.create_time = 0;

	ret = ndr_encode_dos_attr(&n, &da_in);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, n.data);

	n.length = n.offset;
	n.offset = 0;

	/*
	 * The version is encoded as: empty string (2 bytes aligned),
	 * then int16 version. Patch both the int16 and int32 version
	 * fields to 5.
	 */
	/* Find and patch: after the empty string "\0\0" at offset 0,
	 * the int16 version is at offset 2, int32 version at offset 4.
	 */
	*(__le16 *)(n.data + 2) = cpu_to_le16(5);
	*(__le32 *)(n.data + 4) = cpu_to_le32(5);

	ret = ndr_decode_dos_attr(&n, &da_out);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	kfree(n.data);
}

/*
 * test_ndr_decode_dos_attr_version_mismatch - version fields don't agree
 *
 * Patch the second version field to differ from the first.
 */
static void test_ndr_decode_dos_attr_version_mismatch(struct kunit *test)
{
	struct ndr n = {};
	struct xattr_dos_attrib da_in = {};
	struct xattr_dos_attrib da_out = {};
	int ret;

	da_in.version = 4;
	da_in.flags = 0;
	da_in.attr = 0x20;
	da_in.itime = 0;
	da_in.create_time = 0;

	ret = ndr_encode_dos_attr(&n, &da_in);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, n.data);

	n.length = n.offset;
	n.offset = 0;

	/*
	 * Patch only the int32 version (at offset 4) to differ from
	 * the int16 version (at offset 2), so version != version2.
	 */
	*(__le32 *)(n.data + 4) = cpu_to_le32(3);

	ret = ndr_decode_dos_attr(&n, &da_out);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	kfree(n.data);
}

static struct kunit_case ksmbd_ndr_test_cases[] = {
	KUNIT_CASE(test_ndr_encode_decode_dos_attr_v4),
	KUNIT_CASE(test_ndr_encode_decode_dos_attr_v3),
	KUNIT_CASE(test_ndr_decode_dos_attr_truncated),
	KUNIT_CASE(test_ndr_decode_dos_attr_bad_version),
	KUNIT_CASE(test_ndr_decode_dos_attr_version_mismatch),
	{}
};

static struct kunit_suite ksmbd_ndr_test_suite = {
	.name = "ksmbd_ndr",
	.test_cases = ksmbd_ndr_test_cases,
};

kunit_test_suite(ksmbd_ndr_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd NDR encoding/decoding");
