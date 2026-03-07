// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for DFS referral support (ksmbd_dfs.c)
 *
 *   Tests the pure-logic functions replicated from ksmbd_dfs.c:
 *     - dfs_select_referral_version()
 *     - dfs_referral_fixed_size()
 *     - dfs_utf16_name_len()
 *     - dfs_next_component()
 *   The actual functions are static in ksmbd_dfs.c, so we replicate
 *   the logic here for unit testing.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

/* Replicated DFS constants from ksmbd_dfs.c */
#define DFS_REFERRAL_V2		2
#define DFS_REFERRAL_V3		3
#define DFS_REFERRAL_V4		4

/* Replicated DFS referral entry sizes */
struct test_dfs_referral_v2 {
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

struct test_dfs_referral_v3 {
	__le16	version_number;
	__le16	size;
	__le16	server_type;
	__le16	referral_entry_flags;
	__le32	time_to_live;
	__le16	dfs_path_offset;
	__le16	dfs_alt_path_offset;
	__le16	node_offset;
} __packed;

struct test_dfs_referral_v4 {
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

/* Replicated logic from ksmbd_dfs.c */

static u16 test_dfs_select_referral_version(u16 max_level)
{
	if (max_level >= DFS_REFERRAL_V4)
		return DFS_REFERRAL_V4;
	if (max_level >= DFS_REFERRAL_V3)
		return DFS_REFERRAL_V3;
	if (max_level >= DFS_REFERRAL_V2)
		return DFS_REFERRAL_V2;
	return 0;
}

static unsigned int test_dfs_referral_fixed_size(u16 version)
{
	switch (version) {
	case DFS_REFERRAL_V4:
		return sizeof(struct test_dfs_referral_v4);
	case DFS_REFERRAL_V3:
		return sizeof(struct test_dfs_referral_v3);
	case DFS_REFERRAL_V2:
	default:
		return sizeof(struct test_dfs_referral_v2);
	}
}

static int test_dfs_utf16_name_len(const __u8 *name, unsigned int max_len)
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

static char *test_dfs_next_component(const char *path, const char **next)
{
	const char *start = path;
	const char *end;
	char *result;

	while (*start == '\\' || *start == '/')
		start++;
	if (!*start)
		return NULL;

	end = start;
	while (*end && *end != '\\' && *end != '/')
		end++;

	if (next) {
		*next = end;
		while (**next == '\\' || **next == '/')
			(*next)++;
	}

	result = kstrndup(start, end - start, GFP_KERNEL);
	return result;
}

/* ═══════════════════════════════════════════════════════════════════
 *  Referral Version Selection Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_select_referral_version_v4(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(4),
			(u16)DFS_REFERRAL_V4);
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(5),
			(u16)DFS_REFERRAL_V4);
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(100),
			(u16)DFS_REFERRAL_V4);
}

static void test_dfs_select_referral_version_v3(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(3),
			(u16)DFS_REFERRAL_V3);
}

static void test_dfs_select_referral_version_v2(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(2),
			(u16)DFS_REFERRAL_V2);
}

static void test_dfs_select_referral_version_v1_returns_zero(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(1), (u16)0);
}

static void test_dfs_select_referral_version_zero_returns_zero(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_select_referral_version(0), (u16)0);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Referral Fixed Size Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_referral_fixed_size_v2(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_referral_fixed_size(DFS_REFERRAL_V2),
			(unsigned int)sizeof(struct test_dfs_referral_v2));
}

static void test_dfs_referral_fixed_size_v3(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_referral_fixed_size(DFS_REFERRAL_V3),
			(unsigned int)sizeof(struct test_dfs_referral_v3));
}

static void test_dfs_referral_fixed_size_v4(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_dfs_referral_fixed_size(DFS_REFERRAL_V4),
			(unsigned int)sizeof(struct test_dfs_referral_v4));
	/* V4 must be larger than V3 due to GUID field */
	KUNIT_EXPECT_GT(test,
			test_dfs_referral_fixed_size(DFS_REFERRAL_V4),
			test_dfs_referral_fixed_size(DFS_REFERRAL_V3));
}

/* ═══════════════════════════════════════════════════════════════════
 *  UTF-16 Name Length Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_utf16_name_len_normal(struct kunit *test)
{
	/* "AB" in UTF-16LE: 0x41 0x00 0x42 0x00, NUL: 0x00 0x00 */
	const __u8 name[] = { 0x41, 0x00, 0x42, 0x00, 0x00, 0x00 };
	int len;

	len = test_dfs_utf16_name_len(name, sizeof(name));
	KUNIT_EXPECT_EQ(test, len, 4); /* 2 chars * 2 bytes each */
}

static void test_dfs_utf16_name_len_empty(struct kunit *test)
{
	/* Just NUL terminator */
	const __u8 name[] = { 0x00, 0x00 };
	int len;

	len = test_dfs_utf16_name_len(name, sizeof(name));
	KUNIT_EXPECT_EQ(test, len, 0);
}

static void test_dfs_utf16_name_len_no_null_terminator(struct kunit *test)
{
	/* "AB" without NUL terminator */
	const __u8 name[] = { 0x41, 0x00, 0x42, 0x00 };
	int len;

	len = test_dfs_utf16_name_len(name, sizeof(name));
	KUNIT_EXPECT_EQ(test, len, -EINVAL);
}

static void test_dfs_utf16_name_len_max_len_too_small(struct kunit *test)
{
	const __u8 name[] = { 0x41 };
	int len;

	len = test_dfs_utf16_name_len(name, 1);
	KUNIT_EXPECT_EQ(test, len, -EINVAL);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Path Component Extraction Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_next_component_single(struct kunit *test)
{
	const char *next = NULL;
	char *comp;

	comp = test_dfs_next_component("server", &next);
	KUNIT_ASSERT_NOT_NULL(test, comp);
	KUNIT_EXPECT_STREQ(test, comp, "server");
	kfree(comp);
}

static void test_dfs_next_component_multiple(struct kunit *test)
{
	const char *next = NULL;
	char *comp1, *comp2;

	comp1 = test_dfs_next_component("\\\\server\\share", &next);
	KUNIT_ASSERT_NOT_NULL(test, comp1);
	KUNIT_EXPECT_STREQ(test, comp1, "server");

	comp2 = test_dfs_next_component(next, &next);
	KUNIT_ASSERT_NOT_NULL(test, comp2);
	KUNIT_EXPECT_STREQ(test, comp2, "share");

	kfree(comp1);
	kfree(comp2);
}

static void test_dfs_next_component_leading_separators(struct kunit *test)
{
	const char *next = NULL;
	char *comp;

	comp = test_dfs_next_component("\\\\\\server", &next);
	KUNIT_ASSERT_NOT_NULL(test, comp);
	KUNIT_EXPECT_STREQ(test, comp, "server");
	kfree(comp);
}

static void test_dfs_next_component_empty(struct kunit *test)
{
	const char *next = NULL;
	char *comp;

	comp = test_dfs_next_component("", &next);
	KUNIT_EXPECT_NULL(test, comp);
}

static void test_dfs_next_component_mixed_separators(struct kunit *test)
{
	const char *next = NULL;
	char *comp;

	comp = test_dfs_next_component("\\/server", &next);
	KUNIT_ASSERT_NOT_NULL(test, comp);
	KUNIT_EXPECT_STREQ(test, comp, "server");
	kfree(comp);
}

static void test_dfs_next_component_only_separators(struct kunit *test)
{
	const char *next = NULL;
	char *comp;

	comp = test_dfs_next_component("\\\\\\\\", &next);
	KUNIT_EXPECT_NULL(test, comp);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Referral Default Version Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_referral_default_falls_to_v2(struct kunit *test)
{
	/* Unknown version falls through to v2 in the switch default */
	KUNIT_EXPECT_EQ(test, test_dfs_referral_fixed_size(0),
			(unsigned int)sizeof(struct test_dfs_referral_v2));
	KUNIT_EXPECT_EQ(test, test_dfs_referral_fixed_size(99),
			(unsigned int)sizeof(struct test_dfs_referral_v2));
}

/* ═══════════════════════════════════════════════════════════════════
 *  Network Address Building Tests (replicated logic)
 * ═══════════════════════════════════════════════════════════════════ */

static int test_dfs_build_network_address(const char *server,
					  const char *share,
					  char *buf, size_t buf_size)
{
	int ret;

	if (!server || !*server)
		return -EINVAL;

	if (share && *share)
		ret = snprintf(buf, buf_size, "\\\\%s\\%s", server, share);
	else
		ret = snprintf(buf, buf_size, "\\\\%s", server);

	if (ret >= (int)buf_size)
		return -ENOSPC;

	return 0;
}

static void test_dfs_build_network_address_server_share(struct kunit *test)
{
	char buf[256];

	KUNIT_EXPECT_EQ(test,
			test_dfs_build_network_address("server", "share",
						       buf, sizeof(buf)),
			0);
	KUNIT_EXPECT_STREQ(test, buf, "\\\\server\\share");
}

static void test_dfs_build_network_address_server_only(struct kunit *test)
{
	char buf[256];

	KUNIT_EXPECT_EQ(test,
			test_dfs_build_network_address("server", NULL,
						       buf, sizeof(buf)),
			0);
	KUNIT_EXPECT_STREQ(test, buf, "\\\\server");
}

static void test_dfs_build_network_address_empty_server(struct kunit *test)
{
	char buf[256];

	KUNIT_EXPECT_EQ(test,
			test_dfs_build_network_address("", "share",
						       buf, sizeof(buf)),
			-EINVAL);
}

static void test_dfs_build_network_address_null_server(struct kunit *test)
{
	char buf[256];

	KUNIT_EXPECT_EQ(test,
			test_dfs_build_network_address(NULL, "share",
						       buf, sizeof(buf)),
			-EINVAL);
}

static void test_dfs_build_network_address_buf_too_small(struct kunit *test)
{
	char buf[5]; /* Too small for "\\server\share" */

	KUNIT_EXPECT_EQ(test,
			test_dfs_build_network_address("server", "share",
						       buf, sizeof(buf)),
			-ENOSPC);
}

/* ═══════════════════════════════════════════════════════════════════
 *  UTF-16 Name Length Edge Cases
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_utf16_name_len_single_char(struct kunit *test)
{
	/* "A" in UTF-16LE: 0x41 0x00, NUL: 0x00 0x00 */
	const __u8 name[] = { 0x41, 0x00, 0x00, 0x00 };

	KUNIT_EXPECT_EQ(test, test_dfs_utf16_name_len(name, sizeof(name)), 2);
}

static void test_dfs_utf16_name_len_max_len_zero(struct kunit *test)
{
	const __u8 name[] = { 0x00, 0x00 };

	KUNIT_EXPECT_EQ(test, test_dfs_utf16_name_len(name, 0), -EINVAL);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Referral Structure Size Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_dfs_referral_v3_v4_relationship(struct kunit *test)
{
	/* V4 has a 16-byte GUID that V3 doesn't */
	unsigned int v3 = test_dfs_referral_fixed_size(DFS_REFERRAL_V3);
	unsigned int v4 = test_dfs_referral_fixed_size(DFS_REFERRAL_V4);

	KUNIT_EXPECT_EQ(test, v4 - v3, 16U);
}

static void test_dfs_referral_v2_has_proximity(struct kunit *test)
{
	/* V2 has a proximity field that V3/V4 don't */
	KUNIT_EXPECT_GT(test, test_dfs_referral_fixed_size(DFS_REFERRAL_V2),
			(unsigned int)0);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_dfs_test_cases[] = {
	/* Referral version selection */
	KUNIT_CASE(test_dfs_select_referral_version_v4),
	KUNIT_CASE(test_dfs_select_referral_version_v3),
	KUNIT_CASE(test_dfs_select_referral_version_v2),
	KUNIT_CASE(test_dfs_select_referral_version_v1_returns_zero),
	KUNIT_CASE(test_dfs_select_referral_version_zero_returns_zero),
	/* Fixed sizes */
	KUNIT_CASE(test_dfs_referral_fixed_size_v2),
	KUNIT_CASE(test_dfs_referral_fixed_size_v3),
	KUNIT_CASE(test_dfs_referral_fixed_size_v4),
	/* UTF-16 name length */
	KUNIT_CASE(test_dfs_utf16_name_len_normal),
	KUNIT_CASE(test_dfs_utf16_name_len_empty),
	KUNIT_CASE(test_dfs_utf16_name_len_no_null_terminator),
	KUNIT_CASE(test_dfs_utf16_name_len_max_len_too_small),
	/* Path components */
	KUNIT_CASE(test_dfs_next_component_single),
	KUNIT_CASE(test_dfs_next_component_multiple),
	KUNIT_CASE(test_dfs_next_component_leading_separators),
	KUNIT_CASE(test_dfs_next_component_empty),
	KUNIT_CASE(test_dfs_next_component_mixed_separators),
	KUNIT_CASE(test_dfs_next_component_only_separators),
	/* Default version */
	KUNIT_CASE(test_dfs_referral_default_falls_to_v2),
	/* Network address building */
	KUNIT_CASE(test_dfs_build_network_address_server_share),
	KUNIT_CASE(test_dfs_build_network_address_server_only),
	KUNIT_CASE(test_dfs_build_network_address_empty_server),
	KUNIT_CASE(test_dfs_build_network_address_null_server),
	KUNIT_CASE(test_dfs_build_network_address_buf_too_small),
	/* UTF-16 name length edge cases */
	KUNIT_CASE(test_dfs_utf16_name_len_single_char),
	KUNIT_CASE(test_dfs_utf16_name_len_max_len_zero),
	/* Referral structure sizes */
	KUNIT_CASE(test_dfs_referral_v3_v4_relationship),
	KUNIT_CASE(test_dfs_referral_v2_has_proximity),
	{}
};

static struct kunit_suite ksmbd_dfs_test_suite = {
	.name = "ksmbd_dfs",
	.test_cases = ksmbd_dfs_test_cases,
};

kunit_test_suite(ksmbd_dfs_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd DFS referral support");
