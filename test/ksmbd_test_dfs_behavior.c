// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for DFS referral structures and behavior.
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure logic under test.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/align.h>

/* ---- Inlined DFS structures from ksmbd_dfs.c ---- */

#define DFS_REFERRAL_V2		2
#define DFS_REFERRAL_V3		3
#define DFS_REFERRAL_V4		4

#define DFSREF_REFERRAL_SERVER	0x00000001
#define DFSREF_STORAGE_SERVER	0x00000002
#define DFSREF_TARGET_FAILBACK	0x00000004

#define DFS_TARGET_SET_BOUNDARY	0x0400
#define DFS_DEFAULT_TTL		300

#define DFS_SERVER_ROOT		0x0001
#define DFS_SERVER_LINK		0x0000

/* Max path component length in bytes */
#define DFS_MAX_PATH_COMPONENT_LEN	255

struct req_get_dfs_referral {
	__le16	max_referral_level;
	__u8	request_file_name[];
} __packed;

struct req_get_dfs_referral_ex {
	__le16	max_referral_level;
	__le16	request_flags;
	__le32	request_data_length;
	__u8	request_data[];
} __packed;

struct resp_get_dfs_referral {
	__le16	path_consumed;
	__le16	number_of_referrals;
	__le32	referral_header_flags;
} __packed;

struct dfs_referral_level_2 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	proximity;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
} __packed;

struct dfs_referral_level_3 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
} __packed;

struct dfs_referral_level_4 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
	__u8	service_site_guid[16];
} __packed;

/* ---- Inlined helpers from ksmbd_dfs.c ---- */

static unsigned int dfs_referral_fixed_size(u16 version)
{
	switch (version) {
	case DFS_REFERRAL_V4:
		return sizeof(struct dfs_referral_level_4);
	case DFS_REFERRAL_V3:
		return sizeof(struct dfs_referral_level_3);
	case DFS_REFERRAL_V2:
	default:
		return sizeof(struct dfs_referral_level_2);
	}
}

static u16 dfs_select_referral_version(u16 max_level)
{
	if (max_level >= DFS_REFERRAL_V4)
		return DFS_REFERRAL_V4;
	if (max_level >= DFS_REFERRAL_V3)
		return DFS_REFERRAL_V3;
	if (max_level >= DFS_REFERRAL_V2)
		return DFS_REFERRAL_V2;
	return 0;
}

/*
 * Compute the length of a null-terminated UTF-16LE string in bytes
 * (not including the null terminator).
 */
static int dfs_utf16_name_len(const __u8 *name, unsigned int max_len)
{
	unsigned int i;

	if (max_len < sizeof(__le16))
		return -EINVAL;

	for (i = 0; i + 1 < max_len; i += sizeof(__le16)) {
		if (!name[i] && !name[i + 1])
			return i;
	}

	return -EINVAL;
}

/*
 * Normalize a path: convert forward slashes to backslashes.
 */
static void dfs_normalize_path(char *path)
{
	while (*path) {
		if (*path == '/')
			*path = '\\';
		path++;
	}
}

/*
 * Validate that a path component is not too long (max 255 characters).
 */
static int dfs_validate_path_component(const char *component, size_t len)
{
	if (len > DFS_MAX_PATH_COMPONENT_LEN)
		return -ENAMETOOLONG;
	return 0;
}

/* ---- Test cases ---- */

/*
 * test_dfs_request_structure_layout - REQ_GET_DFS_REFERRAL is packed
 *
 * The request structure has: max_referral_level (2 bytes) followed
 * by a variable-length request_file_name.
 */
static void test_dfs_request_structure_layout(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct req_get_dfs_referral), 2);
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct req_get_dfs_referral,
				      request_file_name),
			2);
}

/*
 * test_dfs_response_structure_layout - RESP_GET_DFS_REFERRAL is 8 bytes
 *
 * Layout: path_consumed(2) + number_of_referrals(2) +
 *         referral_header_flags(4) = 8 bytes
 */
static void test_dfs_response_structure_layout(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct resp_get_dfs_referral), 8);
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct resp_get_dfs_referral,
				      path_consumed),
			0);
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct resp_get_dfs_referral,
				      number_of_referrals),
			2);
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct resp_get_dfs_referral,
				      referral_header_flags),
			4);
}

/*
 * test_referral_entry_flags - DFSREF flag constants
 */
static void test_referral_entry_flags(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, DFSREF_REFERRAL_SERVER, 0x00000001);
	KUNIT_EXPECT_EQ(test, DFSREF_STORAGE_SERVER, 0x00000002);
	KUNIT_EXPECT_EQ(test, DFSREF_TARGET_FAILBACK, 0x00000004);

	/* Combined flags for root referral (referral + storage) */
	KUNIT_EXPECT_EQ(test,
			DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER,
			0x00000003);

	/* V4 additionally sets TARGET_FAILBACK */
	KUNIT_EXPECT_EQ(test,
			DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER |
			DFSREF_TARGET_FAILBACK,
			0x00000007);
}

/*
 * test_path_normalization - backslash/forward slash normalization
 */
static void test_path_normalization(struct kunit *test)
{
	char path1[] = "\\\\server\\share";
	char path2[] = "//server/share";
	char path3[] = "\\\\server/mixed\\path";

	/* Path 1 already uses backslashes, should be unchanged */
	dfs_normalize_path(path1);
	KUNIT_EXPECT_STREQ(test, path1, "\\\\server\\share");

	/* Path 2 uses forward slashes, should be converted */
	dfs_normalize_path(path2);
	KUNIT_EXPECT_STREQ(test, path2, "\\\\server\\share");

	/* Path 3 is mixed */
	dfs_normalize_path(path3);
	KUNIT_EXPECT_STREQ(test, path3, "\\\\server\\mixed\\path");
}

/*
 * test_long_path_component_rejected - components > 255 chars rejected
 */
static void test_long_path_component_rejected(struct kunit *test)
{
	char long_component[300];
	int ret;

	memset(long_component, 'A', 256);
	long_component[256] = '\0';

	ret = dfs_validate_path_component(long_component, 256);
	KUNIT_EXPECT_EQ(test, ret, -ENAMETOOLONG);

	/* 255 chars is OK */
	ret = dfs_validate_path_component(long_component, 255);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * test_empty_path_in_referral_request - zero-length path is invalid
 *
 * A UTF-16LE name with max_len < 2 should fail in dfs_utf16_name_len.
 */
static void test_empty_path_in_referral_request(struct kunit *test)
{
	__u8 empty[2] = {0, 0};

	/*
	 * max_len = 0: too small for even a single UTF-16LE char
	 */
	KUNIT_EXPECT_EQ(test, dfs_utf16_name_len(empty, 0), -EINVAL);
	KUNIT_EXPECT_EQ(test, dfs_utf16_name_len(empty, 1), -EINVAL);

	/*
	 * max_len = 2 with null terminator: valid empty string, length = 0
	 */
	KUNIT_EXPECT_EQ(test, dfs_utf16_name_len(empty, 2), 0);
}

/*
 * test_root_vs_link_referral - server_type constants
 *
 * Root referral: DFS_SERVER_ROOT (0x0001)
 * Link referral: DFS_SERVER_LINK (0x0000)
 */
static void test_root_vs_link_referral(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, DFS_SERVER_ROOT, 0x0001);
	KUNIT_EXPECT_EQ(test, DFS_SERVER_LINK, 0x0000);

	/* These are distinct values */
	KUNIT_EXPECT_NE(test, DFS_SERVER_ROOT, DFS_SERVER_LINK);
}

/*
 * test_referral_entry_version_fields - version field sizes
 *
 * V2 has an extra proximity field, V4 has a GUID.
 */
static void test_referral_entry_version_fields(struct kunit *test)
{
	/* V2: 22 bytes */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct dfs_referral_level_2), 22);

	/* V3: 18 bytes (no proximity field) */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct dfs_referral_level_3), 18);

	/* V4: 34 bytes (V3 + 16 byte GUID) */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct dfs_referral_level_4), 34);

	/* V2 fixed size matches */
	KUNIT_EXPECT_EQ(test, dfs_referral_fixed_size(DFS_REFERRAL_V2),
			(unsigned int)sizeof(struct dfs_referral_level_2));

	KUNIT_EXPECT_EQ(test, dfs_referral_fixed_size(DFS_REFERRAL_V3),
			(unsigned int)sizeof(struct dfs_referral_level_3));

	KUNIT_EXPECT_EQ(test, dfs_referral_fixed_size(DFS_REFERRAL_V4),
			(unsigned int)sizeof(struct dfs_referral_level_4));
}

/*
 * test_dfs_header_flag_referral_svr - REFERRAL_SERVER flag in header
 */
static void test_dfs_header_flag_referral_svr(struct kunit *test)
{
	struct resp_get_dfs_referral rsp = {};
	__u32 flags;

	rsp.referral_header_flags = cpu_to_le32(DFSREF_REFERRAL_SERVER);
	flags = le32_to_cpu(rsp.referral_header_flags);

	KUNIT_EXPECT_TRUE(test, !!(flags & DFSREF_REFERRAL_SERVER));
	KUNIT_EXPECT_FALSE(test, !!(flags & DFSREF_STORAGE_SERVER));
}

/*
 * test_dfs_header_flag_storage_svr - STORAGE_SERVER flag in header
 */
static void test_dfs_header_flag_storage_svr(struct kunit *test)
{
	struct resp_get_dfs_referral rsp = {};
	__u32 flags;

	rsp.referral_header_flags =
		cpu_to_le32(DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER);
	flags = le32_to_cpu(rsp.referral_header_flags);

	KUNIT_EXPECT_TRUE(test, !!(flags & DFSREF_REFERRAL_SERVER));
	KUNIT_EXPECT_TRUE(test, !!(flags & DFSREF_STORAGE_SERVER));
}

/*
 * test_max_referral_level_validation - version selection logic
 *
 * dfs_select_referral_version() clamps to the highest supported version.
 */
static void test_max_referral_level_validation(struct kunit *test)
{
	/* Level 0 or 1: unsupported, returns 0 */
	KUNIT_EXPECT_EQ(test, dfs_select_referral_version(0), (u16)0);
	KUNIT_EXPECT_EQ(test, dfs_select_referral_version(1), (u16)0);

	/* Level 2: returns V2 */
	KUNIT_EXPECT_EQ(test, dfs_select_referral_version(2),
			(u16)DFS_REFERRAL_V2);

	/* Level 3: returns V3 */
	KUNIT_EXPECT_EQ(test, dfs_select_referral_version(3),
			(u16)DFS_REFERRAL_V3);

	/* Level 4 or higher: returns V4 */
	KUNIT_EXPECT_EQ(test, dfs_select_referral_version(4),
			(u16)DFS_REFERRAL_V4);
	KUNIT_EXPECT_EQ(test, dfs_select_referral_version(10),
			(u16)DFS_REFERRAL_V4);
}

/*
 * test_referral_response_zero_entries - response with 0 referrals
 */
static void test_referral_response_zero_entries(struct kunit *test)
{
	struct resp_get_dfs_referral rsp = {};

	rsp.path_consumed = cpu_to_le16(0);
	rsp.number_of_referrals = cpu_to_le16(0);
	rsp.referral_header_flags = cpu_to_le32(0);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.number_of_referrals), (__u16)0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.path_consumed), (__u16)0);
}

/*
 * test_referral_response_multiple_entries - response with 3 referrals
 *
 * Build a response header followed by 3 V3 referral entries and verify
 * the layout is correct.
 */
static void test_referral_response_multiple_entries(struct kunit *test)
{
	__u8 *buf;
	struct resp_get_dfs_referral *rsp;
	struct dfs_referral_level_3 *ref;
	unsigned int total_size;
	int i;

	total_size = sizeof(*rsp) + 3 * sizeof(struct dfs_referral_level_3);
	buf = kzalloc(total_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	rsp = (struct resp_get_dfs_referral *)buf;
	rsp->path_consumed = cpu_to_le16(20);
	rsp->number_of_referrals = cpu_to_le16(3);
	rsp->referral_header_flags =
		cpu_to_le32(DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER);

	for (i = 0; i < 3; i++) {
		ref = (struct dfs_referral_level_3 *)
			(buf + sizeof(*rsp) +
			 i * sizeof(struct dfs_referral_level_3));
		ref->version_number = cpu_to_le16(DFS_REFERRAL_V3);
		ref->size = cpu_to_le16(sizeof(*ref));
		ref->server_type = cpu_to_le16(DFS_SERVER_ROOT);
		ref->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);
	}

	/* Verify */
	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp->number_of_referrals), (__u16)3);

	for (i = 0; i < 3; i++) {
		ref = (struct dfs_referral_level_3 *)
			(buf + sizeof(*rsp) +
			 i * sizeof(struct dfs_referral_level_3));
		KUNIT_EXPECT_EQ(test, le16_to_cpu(ref->version_number),
				(__u16)DFS_REFERRAL_V3);
		KUNIT_EXPECT_EQ(test, le32_to_cpu(ref->time_to_live),
				(__u32)DFS_DEFAULT_TTL);
		KUNIT_EXPECT_EQ(test, le16_to_cpu(ref->server_type),
				(__u16)DFS_SERVER_ROOT);
	}

	kfree(buf);
}

/*
 * test_path_consumed_nested_shares - path consumed for nested path
 *
 * For a path like \\server\share\subfolder, PathConsumed should
 * reflect the number of bytes consumed from the request path.
 * The value is the byte length of the Unicode path prefix up to
 * and including the share name.
 */
static void test_path_consumed_nested_shares(struct kunit *test)
{
	/*
	 * \\server\share encoded in UTF-16LE:
	 * Each char is 2 bytes. "\\server\share" = 14 chars = 28 bytes
	 * (not counting null terminator)
	 */
	const char *path = "\\\\server\\share";
	u16 path_consumed_bytes;

	/* 14 characters * 2 bytes per UTF-16LE character = 28 bytes */
	path_consumed_bytes = strlen(path) * sizeof(__le16);
	KUNIT_EXPECT_EQ(test, path_consumed_bytes, (u16)28);

	/* Path consumed fits in a __le16 field */
	{
		struct resp_get_dfs_referral rsp = {};

		rsp.path_consumed = cpu_to_le16(path_consumed_bytes);
		KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.path_consumed),
				(u16)28);
	}
}

/*
 * test_request_filename_utf16_encoding - request path is null-terminated UTF-16
 *
 * Verify that dfs_utf16_name_len correctly measures a UTF-16LE path.
 */
static void test_request_filename_utf16_encoding(struct kunit *test)
{
	/* "\\A" in UTF-16LE: 0x5C00 0x5C00 0x4100 0x0000 */
	__u8 utf16_path[] = {
		0x5C, 0x00,  /* backslash */
		0x5C, 0x00,  /* backslash */
		0x41, 0x00,  /* 'A' */
		0x00, 0x00   /* null terminator */
	};
	int len;

	len = dfs_utf16_name_len(utf16_path, sizeof(utf16_path));
	KUNIT_EXPECT_EQ(test, len, 6); /* 3 chars * 2 bytes = 6 */

	/* Path without null terminator should fail */
	{
		__u8 no_null[] = {0x41, 0x00, 0x42, 0x00};

		len = dfs_utf16_name_len(no_null, sizeof(no_null));
		KUNIT_EXPECT_EQ(test, len, -EINVAL);
	}
}

static struct kunit_case ksmbd_dfs_behavior_test_cases[] = {
	KUNIT_CASE(test_dfs_request_structure_layout),
	KUNIT_CASE(test_dfs_response_structure_layout),
	KUNIT_CASE(test_referral_entry_flags),
	KUNIT_CASE(test_path_normalization),
	KUNIT_CASE(test_long_path_component_rejected),
	KUNIT_CASE(test_empty_path_in_referral_request),
	KUNIT_CASE(test_root_vs_link_referral),
	KUNIT_CASE(test_referral_entry_version_fields),
	KUNIT_CASE(test_dfs_header_flag_referral_svr),
	KUNIT_CASE(test_dfs_header_flag_storage_svr),
	KUNIT_CASE(test_max_referral_level_validation),
	KUNIT_CASE(test_referral_response_zero_entries),
	KUNIT_CASE(test_referral_response_multiple_entries),
	KUNIT_CASE(test_path_consumed_nested_shares),
	KUNIT_CASE(test_request_filename_utf16_encoding),
	{}
};

static struct kunit_suite ksmbd_dfs_behavior_test_suite = {
	.name = "ksmbd_dfs_behavior",
	.test_cases = ksmbd_dfs_behavior_test_cases,
};

kunit_test_suite(ksmbd_dfs_behavior_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd DFS referral behavior");
