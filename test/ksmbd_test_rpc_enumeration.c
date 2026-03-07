// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for RPC enumeration service structures and NDR encoding.
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure encoding/decoding
 *   logic under test.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/align.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

/* ---- Inlined NDR encoding/decoding primitives from ndr.c ---- */

struct ndr {
	char		*data;
	unsigned int	offset;
	unsigned int	length;
};

static inline char *ndr_get_field(struct ndr *n)
{
	return n->data + n->offset;
}

static int try_to_realloc_ndr_blob(struct ndr *n, size_t sz)
{
	char *data;
	size_t needed = n->offset + sz;
	size_t new_sz = needed + 1024;

	if (new_sz < needed)
		return -EOVERFLOW;

	data = krealloc(n->data, new_sz, GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	n->data = data;
	n->length = new_sz;
	memset(n->data + n->offset, 0, new_sz - n->offset);
	return 0;
}

static int ndr_write_int16(struct ndr *n, __u16 value)
{
	if (n->length <= n->offset + sizeof(value)) {
		int ret = try_to_realloc_ndr_blob(n, sizeof(value));

		if (ret)
			return ret;
	}
	put_unaligned_le16(value, ndr_get_field(n));
	n->offset += sizeof(value);
	return 0;
}

static int ndr_write_int32(struct ndr *n, __u32 value)
{
	if (n->length <= n->offset + sizeof(value)) {
		int ret = try_to_realloc_ndr_blob(n, sizeof(value));

		if (ret)
			return ret;
	}
	put_unaligned_le32(value, ndr_get_field(n));
	n->offset += sizeof(value);
	return 0;
}

static int ndr_write_int64(struct ndr *n, __u64 value)
{
	if (n->length <= n->offset + sizeof(value)) {
		int ret = try_to_realloc_ndr_blob(n, sizeof(value));

		if (ret)
			return ret;
	}
	put_unaligned_le64(value, ndr_get_field(n));
	n->offset += sizeof(value);
	return 0;
}

static int ndr_write_bytes(struct ndr *n, void *value, size_t sz)
{
	if (n->length <= n->offset + sz) {
		int ret = try_to_realloc_ndr_blob(n, sz);

		if (ret)
			return ret;
	}
	memcpy(ndr_get_field(n), value, sz);
	n->offset += sz;
	return 0;
}

static int ndr_write_string(struct ndr *n, char *value)
{
	int raw_len = strlen(value) + 1;
	int sz = ALIGN(raw_len, 2);

	if (n->length <= n->offset + sz) {
		int ret = try_to_realloc_ndr_blob(n, sz);

		if (ret)
			return ret;
	}
	memcpy(ndr_get_field(n), value, raw_len);
	if (sz > raw_len)
		memset((char *)ndr_get_field(n) + raw_len, 0, sz - raw_len);
	n->offset += sz;
	n->offset = ALIGN(n->offset, 2);
	return 0;
}

static int ndr_read_int16(struct ndr *n, __u16 *value)
{
	if (n->offset + sizeof(__u16) > n->length)
		return -EINVAL;
	if (value)
		*value = get_unaligned_le16(ndr_get_field(n));
	n->offset += sizeof(__u16);
	return 0;
}

static int ndr_read_int32(struct ndr *n, __u32 *value)
{
	if (n->offset + sizeof(__u32) > n->length)
		return -EINVAL;
	if (value)
		*value = get_unaligned_le32(ndr_get_field(n));
	n->offset += sizeof(__u32);
	return 0;
}

static int ndr_read_int64(struct ndr *n, __u64 *value)
{
	if (n->offset + sizeof(__u64) > n->length)
		return -EINVAL;
	if (value)
		*value = get_unaligned_le64(ndr_get_field(n));
	n->offset += sizeof(__u64);
	return 0;
}

/* ---- Inlined DCE/RPC structure definitions from rpc.h ---- */

#define DCERPC_PTYPE_RPC_REQUEST	0x00
#define DCERPC_PTYPE_RPC_RESPONSE	0x02
#define DCERPC_PTYPE_RPC_BIND		0x0B
#define DCERPC_PTYPE_RPC_BINDACK	0x0C

#define DCERPC_PFC_FIRST_FRAG		0x01
#define DCERPC_PFC_LAST_FRAG		0x02

struct dcerpc_header {
	__u8	rpc_vers;
	__u8	rpc_vers_minor;
	__u8	ptype;
	__u8	pfc_flags;
	__s8	packed_drep[4];
	__u16	frag_length;
	__u16	auth_length;
	__u32	call_id;
} __packed;

struct dcerpc_request_header {
	__u32	alloc_hint;
	__u16	context_id;
	__u16	opnum;
} __packed;

struct dcerpc_response_header {
	__u32	alloc_hint;
	__u16	context_id;
	__u8	cancel_count;
	__u8	reserved;
} __packed;

/* Share type constants from MS-SRVS */
#define SHARE_TYPE_DISKTREE		0x00000000
#define SHARE_TYPE_PRINTQ		0x00000001
#define SHARE_TYPE_DEVICE		0x00000002
#define SHARE_TYPE_IPC			0x00000003
#define SHARE_TYPE_TEMP			0x40000000
#define SHARE_TYPE_HIDDEN		0x80000000

#define SRVSVC_OPNUM_SHARE_ENUM_ALL	15
#define SRVSVC_OPNUM_GET_SHARE_INFO	16

/* NDR referent ID starting value (ksmbd convention) */
#define NDR_REFERENT_ID_BASE		0x00020000

/* ---- Helpers for building simulated NetShareEnum / NetServerGetInfo ---- */

/*
 * Build a simplified NDR-encoded NetShareInfo level 1 entry.
 * Layout: [referent_id(4)] [share_type(4)] [comment_referent_id(4)]
 * Then deferred: [name_conformant_array] [comment_conformant_array]
 *
 * Conformant varying string: [max_count(4)] [offset(4)] [actual_count(4)] [UTF-16LE data]
 */
static int ndr_write_conformant_string(struct ndr *n, const char *str)
{
	size_t len = strlen(str) + 1; /* include null */
	size_t i;
	int ret;

	/* max_count */
	ret = ndr_write_int32(n, len);
	if (ret)
		return ret;
	/* offset */
	ret = ndr_write_int32(n, 0);
	if (ret)
		return ret;
	/* actual_count */
	ret = ndr_write_int32(n, len);
	if (ret)
		return ret;

	/* UTF-16LE encoding (ASCII subset) */
	for (i = 0; i < len; i++) {
		ret = ndr_write_int16(n, (__u16)str[i]);
		if (ret)
			return ret;
	}

	/* 4-byte alignment padding */
	while (n->offset & 3) {
		if (n->length <= n->offset + 1) {
			ret = try_to_realloc_ndr_blob(n, 1);
			if (ret)
				return ret;
		}
		n->data[n->offset++] = 0;
	}

	return 0;
}

/*
 * NDR union discriminant encoding: write the discriminant value as int32.
 */
static int ndr_write_union_int32(struct ndr *n, __u32 value)
{
	return ndr_write_int32(n, value);
}

/* ---- Test cases ---- */

/*
 * test_ndr_write_read_u32 - write and read back a u32 value
 */
static void test_ndr_write_read_u32(struct kunit *test)
{
	struct ndr n = {};
	__u32 val = 0;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0xDEADBEEF), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &val), 0);
	KUNIT_EXPECT_EQ(test, val, (__u32)0xDEADBEEF);

	kfree(n.data);
}

/*
 * test_ndr_write_read_u16 - write and read back a u16 value
 */
static void test_ndr_write_read_u16(struct kunit *test)
{
	struct ndr n = {};
	__u16 val = 0;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	KUNIT_EXPECT_EQ(test, ndr_write_int16(&n, 0xCAFE), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int16(&n, &val), 0);
	KUNIT_EXPECT_EQ(test, val, (__u16)0xCAFE);

	kfree(n.data);
}

/*
 * test_ndr_write_read_u64 - write and read back a u64 value
 */
static void test_ndr_write_read_u64(struct kunit *test)
{
	struct ndr n = {};
	__u64 val = 0;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	KUNIT_EXPECT_EQ(test, ndr_write_int64(&n, 0x0102030405060708ULL), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int64(&n, &val), 0);
	KUNIT_EXPECT_EQ(test, val, (__u64)0x0102030405060708ULL);

	kfree(n.data);
}

/*
 * test_ndr_string_encoding - NDR string is null-terminated and 2-byte aligned
 */
static void test_ndr_string_encoding(struct kunit *test)
{
	struct ndr n = {};
	int ret;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	ret = ndr_write_string(&n, "AB");
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* "AB\0" = 3 bytes, aligned to 4 bytes (ALIGN(3,2)=4) */
	KUNIT_EXPECT_TRUE(test, (n.offset % 2) == 0);
	/* Verify the string data */
	KUNIT_EXPECT_EQ(test, n.data[0], 'A');
	KUNIT_EXPECT_EQ(test, n.data[1], 'B');
	KUNIT_EXPECT_EQ(test, n.data[2], '\0');

	kfree(n.data);
}

/*
 * test_ndr_conformant_array_encoding - conformant varying string format
 */
static void test_ndr_conformant_array_encoding(struct kunit *test)
{
	struct ndr n = {};
	__u32 max_count, offset, actual_count;

	n.data = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4096;

	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "Test"), 0);

	/* Read back: max_count, offset, actual_count */
	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &max_count), 0);
	KUNIT_EXPECT_EQ(test, max_count, (__u32)5); /* "Test\0" = 5 chars */

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &offset), 0);
	KUNIT_EXPECT_EQ(test, offset, (__u32)0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &actual_count), 0);
	KUNIT_EXPECT_EQ(test, actual_count, (__u32)5);

	/* Verify UTF-16LE encoding of 'T' */
	{
		__u16 ch = 0;

		KUNIT_EXPECT_EQ(test, ndr_read_int16(&n, &ch), 0);
		KUNIT_EXPECT_EQ(test, ch, (__u16)'T');
	}

	kfree(n.data);
}

/*
 * test_share_info_level1_layout - NetShareInfo1 entry layout
 *
 * A level 1 share entry consists of:
 *   [name_referent_id(4)] [share_type(4)] [comment_referent_id(4)]
 * followed by deferred name and comment strings.
 */
static void test_share_info_level1_layout(struct kunit *test)
{
	struct ndr n = {};
	__u32 name_ref, share_type, comment_ref;
	unsigned int ref_id = NDR_REFERENT_ID_BASE;

	n.data = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4096;

	/* Write the fixed part of a share info level 1 entry */
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);    /* name ref */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, SHARE_TYPE_DISKTREE), 0);
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);    /* comment ref */

	/* Write deferred name and comment */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "TestShare"), 0);
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "A test share"), 0);

	/* Read back and verify */
	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &name_ref), 0);
	KUNIT_EXPECT_NE(test, name_ref, (__u32)0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &share_type), 0);
	KUNIT_EXPECT_EQ(test, share_type, (__u32)SHARE_TYPE_DISKTREE);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &comment_ref), 0);
	KUNIT_EXPECT_NE(test, comment_ref, (__u32)0);

	kfree(n.data);
}

/*
 * test_server_info_100_layout - NetServerGetInfo level 100 response
 *
 * Level 100 contains: [platform_id(4)] [server_name_ref(4)]
 */
static void test_server_info_100_layout(struct kunit *test)
{
	struct ndr n = {};
	__u32 platform_id, name_ref;

	n.data = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4096;

	/* platform_id: 500 = SV_PLATFORM_ID_NT */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 500), 0);
	/* server_name referent id */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, NDR_REFERENT_ID_BASE + 1), 0);
	/* deferred server name */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "KSMBD"), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &platform_id), 0);
	KUNIT_EXPECT_EQ(test, platform_id, (__u32)500);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &name_ref), 0);
	KUNIT_EXPECT_NE(test, name_ref, (__u32)0);

	kfree(n.data);
}

/*
 * test_server_info_101_layout - NetServerGetInfo level 101 response
 *
 * Level 101 contains:
 *   [platform_id(4)] [server_name_ref(4)] [version_major(4)]
 *   [version_minor(4)] [server_type(4)] [comment_ref(4)]
 */
static void test_server_info_101_layout(struct kunit *test)
{
	struct ndr n = {};
	__u32 platform_id, name_ref, ver_major, ver_minor, srv_type, comment_ref;

	n.data = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4096;

	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 500), 0);       /* platform_id */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0x00020001), 0); /* name ref */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 10), 0);        /* major */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0), 0);         /* minor */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0x00009003), 0); /* server type */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0x00020002), 0); /* comment ref */

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &platform_id), 0);
	KUNIT_EXPECT_EQ(test, platform_id, (__u32)500);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &name_ref), 0);
	KUNIT_EXPECT_NE(test, name_ref, (__u32)0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &ver_major), 0);
	KUNIT_EXPECT_EQ(test, ver_major, (__u32)10);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &ver_minor), 0);
	KUNIT_EXPECT_EQ(test, ver_minor, (__u32)0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &srv_type), 0);
	KUNIT_EXPECT_EQ(test, srv_type, (__u32)0x00009003);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &comment_ref), 0);
	KUNIT_EXPECT_NE(test, comment_ref, (__u32)0);

	kfree(n.data);
}

/*
 * test_share_enum_zero_shares - empty share enumeration response
 *
 * When no shares are available: union_discriminant(4), ref_ptr(4),
 * count(4), null_array_ptr(4)
 */
static void test_share_enum_zero_shares(struct kunit *test)
{
	struct ndr n = {};
	__u32 disc, ref, count, arr_ptr;
	unsigned int ref_id = 1;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	/* Encode response for 0 shares at info level 1 */
	KUNIT_EXPECT_EQ(test, ndr_write_union_int32(&n, 1), 0);    /* level */
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);     /* ref ptr */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0), 0);          /* count = 0 */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0), 0);          /* null array ptr */

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &disc), 0);
	KUNIT_EXPECT_EQ(test, disc, (__u32)1);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &ref), 0);
	KUNIT_EXPECT_NE(test, ref, (__u32)0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &count), 0);
	KUNIT_EXPECT_EQ(test, count, (__u32)0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &arr_ptr), 0);
	KUNIT_EXPECT_EQ(test, arr_ptr, (__u32)0);

	kfree(n.data);
}

/*
 * test_share_enum_one_share - single share enumeration response
 */
static void test_share_enum_one_share(struct kunit *test)
{
	struct ndr n = {};
	__u32 disc, count, arr_count;
	unsigned int ref_id = 0;

	n.data = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4096;

	/* union discriminant: level 1 */
	KUNIT_EXPECT_EQ(test, ndr_write_union_int32(&n, 1), 0);

	/* container ref ptr */
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);

	/* count = 1 */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 1), 0);

	/* array ref ptr */
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);

	/* array max_count (conformant) */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 1), 0);

	/* share entry: name_ref, type, comment_ref */
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, SHARE_TYPE_DISKTREE), 0);
	ref_id++;
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, ref_id), 0);

	/* deferred strings */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "data"), 0);
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "Data share"), 0);

	/* Verify layout: read back discriminant, count */
	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &disc), 0);
	KUNIT_EXPECT_EQ(test, disc, (__u32)1);

	/* skip ref ptr */
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, NULL), 0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &count), 0);
	KUNIT_EXPECT_EQ(test, count, (__u32)1);

	/* skip array ref ptr */
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, NULL), 0);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &arr_count), 0);
	KUNIT_EXPECT_EQ(test, arr_count, (__u32)1);

	kfree(n.data);
}

/*
 * test_share_enum_max_shares_boundary - buffer boundary with many shares
 *
 * Verify that encoding multiple share entries does not corrupt the
 * NDR buffer by checking total offset stays within bounds.
 */
static void test_share_enum_max_shares_boundary(struct kunit *test)
{
	struct ndr n = {};
	int i, ret;
	/* Simulate encoding 32 share entries (fixed parts only) */
	int nr_shares = 32;
	unsigned int ref_id = 0;

	n.data = kzalloc(256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 256;

	for (i = 0; i < nr_shares; i++) {
		ref_id++;
		ret = ndr_write_int32(&n, ref_id);       /* name ref */
		KUNIT_ASSERT_EQ(test, ret, 0);
		ret = ndr_write_int32(&n, SHARE_TYPE_DISKTREE);
		KUNIT_ASSERT_EQ(test, ret, 0);
		ref_id++;
		ret = ndr_write_int32(&n, ref_id);       /* comment ref */
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	/* 32 entries * 12 bytes each = 384 bytes, buffer should have grown */
	KUNIT_EXPECT_GE(test, n.length, (unsigned int)(nr_shares * 12));
	KUNIT_EXPECT_EQ(test, n.offset, (unsigned int)(nr_shares * 12));

	kfree(n.data);
}

/*
 * test_buffer_overflow_protection - read past buffer boundary fails
 */
static void test_buffer_overflow_protection(struct kunit *test)
{
	struct ndr n = {};
	__u32 val = 0;

	n.data = kzalloc(2, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 2;
	n.offset = 0;

	/* Trying to read 4 bytes from a 2-byte buffer should fail */
	KUNIT_EXPECT_NE(test, ndr_read_int32(&n, &val), 0);

	/* Reading 2 bytes should succeed */
	KUNIT_EXPECT_EQ(test, ndr_read_int16(&n, NULL), 0);

	/* Now at offset 2, reading another int16 should fail */
	KUNIT_EXPECT_NE(test, ndr_read_int16(&n, NULL), 0);

	kfree(n.data);
}

/*
 * test_share_type_constants - share type constant values match MS-SRVS spec
 */
static void test_share_type_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SHARE_TYPE_DISKTREE, 0x00000000);
	KUNIT_EXPECT_EQ(test, SHARE_TYPE_PRINTQ, 0x00000001);
	KUNIT_EXPECT_EQ(test, SHARE_TYPE_DEVICE, 0x00000002);
	KUNIT_EXPECT_EQ(test, SHARE_TYPE_IPC, 0x00000003);
	KUNIT_EXPECT_EQ(test, SHARE_TYPE_TEMP, 0x40000000);
	KUNIT_EXPECT_EQ(test, SHARE_TYPE_HIDDEN, (int)0x80000000);

	/* Combined types */
	KUNIT_EXPECT_EQ(test, (SHARE_TYPE_IPC | SHARE_TYPE_HIDDEN),
			(int)0x80000003);
}

/*
 * test_ndr_unicode_alignment - UTF-16LE strings are 4-byte aligned
 */
static void test_ndr_unicode_alignment(struct kunit *test)
{
	struct ndr n = {};

	n.data = kzalloc(4096, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 4096;

	/* Write a conformant string with odd-length name */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "A"), 0);

	/* After writing, offset should be 4-byte aligned */
	KUNIT_EXPECT_EQ(test, n.offset & 3, (unsigned int)0);

	/* Write another with even-length name */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, "AB"), 0);
	KUNIT_EXPECT_EQ(test, n.offset & 3, (unsigned int)0);

	kfree(n.data);
}

/*
 * test_null_share_comment - NULL comment is encoded as null referent
 */
static void test_null_share_comment(struct kunit *test)
{
	struct ndr n = {};
	__u32 ref;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	/* A null pointer in NDR is encoded as referent ID = 0 */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &ref), 0);
	KUNIT_EXPECT_EQ(test, ref, (__u32)0);

	kfree(n.data);
}

/*
 * test_empty_share_name - empty string is valid in NDR encoding
 */
static void test_empty_share_name(struct kunit *test)
{
	struct ndr n = {};
	__u32 max_count;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	/* Empty string "" has 1 char (the null terminator) */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, ""), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &max_count), 0);
	KUNIT_EXPECT_EQ(test, max_count, (__u32)1);

	kfree(n.data);
}

/*
 * test_ndr_union_discriminant - union discriminant is written as int32
 */
static void test_ndr_union_discriminant(struct kunit *test)
{
	struct ndr n = {};
	__u32 disc;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	KUNIT_EXPECT_EQ(test, ndr_write_union_int32(&n, 1), 0);
	KUNIT_EXPECT_EQ(test, n.offset, (unsigned int)4);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &disc), 0);
	KUNIT_EXPECT_EQ(test, disc, (__u32)1);

	kfree(n.data);
}

/*
 * test_rpc_bind_pdu_size - DCE/RPC bind PDU header is 16 bytes
 */
static void test_rpc_bind_pdu_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct dcerpc_header), 16);
}

/*
 * test_rpc_response_header_fields - response header is 8 bytes
 */
static void test_rpc_response_header_fields(struct kunit *test)
{
	struct dcerpc_response_header rsp = {};

	KUNIT_EXPECT_EQ(test, (int)sizeof(rsp), 8);
	KUNIT_EXPECT_EQ(test, rsp.alloc_hint, (__u32)0);
	KUNIT_EXPECT_EQ(test, rsp.context_id, (__u16)0);
	KUNIT_EXPECT_EQ(test, rsp.cancel_count, (__u8)0);
	KUNIT_EXPECT_EQ(test, rsp.reserved, (__u8)0);
}

/*
 * test_dcerpc_version_numbers - DCE/RPC version is 5.0
 */
static void test_dcerpc_version_numbers(struct kunit *test)
{
	struct dcerpc_header hdr = {};

	hdr.rpc_vers = 5;
	hdr.rpc_vers_minor = 0;
	hdr.ptype = DCERPC_PTYPE_RPC_BIND;
	hdr.pfc_flags = DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG;

	KUNIT_EXPECT_EQ(test, hdr.rpc_vers, (__u8)5);
	KUNIT_EXPECT_EQ(test, hdr.rpc_vers_minor, (__u8)0);
	KUNIT_EXPECT_EQ(test, hdr.ptype, (__u8)DCERPC_PTYPE_RPC_BIND);
	KUNIT_EXPECT_EQ(test, hdr.pfc_flags,
			(__u8)(DCERPC_PFC_FIRST_FRAG | DCERPC_PFC_LAST_FRAG));
}

/*
 * test_ndr_pointer_referent_id - non-null pointer uses non-zero referent ID
 */
static void test_ndr_pointer_referent_id(struct kunit *test)
{
	struct ndr n = {};
	__u32 ref;

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	/* Non-null pointer: write non-zero referent ID (ksmbd convention) */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, NDR_REFERENT_ID_BASE), 0);

	/* Null pointer: write zero */
	KUNIT_EXPECT_EQ(test, ndr_write_int32(&n, 0), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &ref), 0);
	KUNIT_EXPECT_EQ(test, ref, (__u32)NDR_REFERENT_ID_BASE);

	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &ref), 0);
	KUNIT_EXPECT_EQ(test, ref, (__u32)0);

	kfree(n.data);
}

/*
 * test_share_path_max_length - long share name encoding succeeds
 *
 * Verify that a share name close to the maximum practical length (256 chars)
 * encodes correctly in the conformant string format.
 */
static void test_share_path_max_length(struct kunit *test)
{
	struct ndr n = {};
	char long_name[257];
	__u32 max_count;

	memset(long_name, 'X', 256);
	long_name[256] = '\0';

	n.data = kzalloc(128, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 128;

	/* This will trigger realloc since 257 UTF-16 chars > 128 bytes */
	KUNIT_EXPECT_EQ(test, ndr_write_conformant_string(&n, long_name), 0);

	n.offset = 0;
	KUNIT_EXPECT_EQ(test, ndr_read_int32(&n, &max_count), 0);
	KUNIT_EXPECT_EQ(test, max_count, (__u32)257);

	kfree(n.data);
}

/*
 * test_ndr_bytes_encoding - raw byte writing and reading
 */
static void test_ndr_bytes_encoding(struct kunit *test)
{
	struct ndr n = {};
	__u8 data_in[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	__u8 data_out[8] = {};

	n.data = kzalloc(1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, n.data);
	n.length = 1024;

	KUNIT_EXPECT_EQ(test, ndr_write_bytes(&n, data_in, 8), 0);
	KUNIT_EXPECT_EQ(test, n.offset, (unsigned int)8);

	n.offset = 0;
	memcpy(data_out, ndr_get_field(&n), 8);
	KUNIT_EXPECT_EQ(test, memcmp(data_in, data_out, 8), 0);

	kfree(n.data);
}

static struct kunit_case ksmbd_rpc_enum_test_cases[] = {
	KUNIT_CASE(test_ndr_write_read_u32),
	KUNIT_CASE(test_ndr_write_read_u16),
	KUNIT_CASE(test_ndr_write_read_u64),
	KUNIT_CASE(test_ndr_string_encoding),
	KUNIT_CASE(test_ndr_conformant_array_encoding),
	KUNIT_CASE(test_share_info_level1_layout),
	KUNIT_CASE(test_server_info_100_layout),
	KUNIT_CASE(test_server_info_101_layout),
	KUNIT_CASE(test_share_enum_zero_shares),
	KUNIT_CASE(test_share_enum_one_share),
	KUNIT_CASE(test_share_enum_max_shares_boundary),
	KUNIT_CASE(test_buffer_overflow_protection),
	KUNIT_CASE(test_share_type_constants),
	KUNIT_CASE(test_ndr_unicode_alignment),
	KUNIT_CASE(test_null_share_comment),
	KUNIT_CASE(test_empty_share_name),
	KUNIT_CASE(test_ndr_union_discriminant),
	KUNIT_CASE(test_rpc_bind_pdu_size),
	KUNIT_CASE(test_rpc_response_header_fields),
	KUNIT_CASE(test_dcerpc_version_numbers),
	KUNIT_CASE(test_ndr_pointer_referent_id),
	KUNIT_CASE(test_share_path_max_length),
	KUNIT_CASE(test_ndr_bytes_encoding),
	{}
};

static struct kunit_suite ksmbd_rpc_enum_test_suite = {
	.name = "ksmbd_rpc_enumeration",
	.test_cases = ksmbd_rpc_enum_test_cases,
};

kunit_test_suite(ksmbd_rpc_enum_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd RPC enumeration and NDR encoding");
