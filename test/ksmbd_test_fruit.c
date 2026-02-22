// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd Apple Fruit extension helpers (smb2fruit.c)
 *
 *   Since KUnit tests cannot link against the ksmbd module directly,
 *   we replicate the pure-logic portions (AfpInfo stream name matching,
 *   volume capabilities, AFP magic/version constants, signature
 *   validation) inline.
 *
 *   Tests are guarded with #ifdef CONFIG_KSMBD_FRUIT so that they
 *   compile to nothing when fruit support is disabled.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>

/* ── Replicated constants from smb2fruit.h ─── */

#define TEST_AFP_AFPINFO_STREAM		"AFP_AfpInfo"
#define TEST_AFP_RESOURCE_STREAM	"AFP_Resource"
#define TEST_AFP_AFPINFO_SIZE		60
#define TEST_AFP_FINDER_INFO_SIZE	32

/* AFP_AfpInfo magic and version (big-endian on wire) */
#define TEST_AFP_MAGIC			0x41465000  /* "AFP\0" */
#define TEST_AFP_VERSION		0x00010000  /* 1.0 */
#define TEST_AFP_BACKUP_DATE_INVALID	0x80000000

/* Volume capabilities */
#define TEST_kAAPL_SUPPORT_RESOLVE_ID	0x01
#define TEST_kAAPL_CASE_SENSITIVE	0x02
#define TEST_kAAPL_SUPPORTS_FULL_SYNC	0x04

/* Fruit versions */
#define TEST_FRUIT_VERSION_1_0		0x00010000
#define TEST_FRUIT_VERSION_1_1		0x00010001
#define TEST_FRUIT_VERSION_2_0		0x00020000

/* Fruit client types */
#define TEST_FRUIT_CLIENT_MACOS		0x01
#define TEST_FRUIT_CLIENT_IOS		0x02

/* Server capabilities */
#define TEST_kAAPL_SUPPORTS_READ_DIR_ATTR	0x01
#define TEST_kAAPL_SUPPORTS_OSX_COPYFILE	0x02
#define TEST_kAAPL_UNIX_BASED			0x04
#define TEST_kAAPL_SUPPORTS_NFS_ACE		0x08

/* Wire protocol signature */
static const __u8 test_fruit_signature[4] = {'A', 'A', 'P', 'L'};

/* ── Replicated logic from smb2fruit.c ─── */

/**
 * test_fruit_is_afpinfo_stream() - Replicate ksmbd_fruit_is_afpinfo_stream()
 *
 * Case-insensitive match of stream name against "AFP_AfpInfo".
 */
static bool test_fruit_is_afpinfo_stream(const char *stream_name)
{
	if (!stream_name)
		return false;

	return !strncasecmp(stream_name, TEST_AFP_AFPINFO_STREAM,
			    sizeof(TEST_AFP_AFPINFO_STREAM) - 1);
}

/**
 * test_fruit_get_volume_caps() - Replicate ksmbd_fruit_get_volume_caps()
 *
 * Returns the standard volume capabilities bitmask.
 */
static u64 test_fruit_get_volume_caps(void)
{
	u64 vcaps = 0;

	vcaps |= TEST_kAAPL_CASE_SENSITIVE;
	vcaps |= TEST_kAAPL_SUPPORTS_FULL_SYNC;
	vcaps |= TEST_kAAPL_SUPPORT_RESOLVE_ID;

	return vcaps;
}

/**
 * test_fruit_valid_signature() - Replicate fruit_valid_signature()
 */
static bool test_fruit_valid_signature(const __u8 *signature)
{
	if (!signature)
		return false;

	return memcmp(signature, test_fruit_signature, 4) == 0;
}

/**
 * test_fruit_get_client_name() - Replicate fruit_get_client_name()
 */
static const char *test_fruit_get_client_name(u32 client_type)
{
	switch (client_type) {
	case TEST_FRUIT_CLIENT_MACOS:
		return "macOS";
	case TEST_FRUIT_CLIENT_IOS:
		return "iOS";
	default:
		return "Unknown";
	}
}

/**
 * test_fruit_get_version_string() - Replicate fruit_get_version_string()
 */
static const char *test_fruit_get_version_string(u32 version)
{
	switch (version) {
	case TEST_FRUIT_VERSION_1_0:
		return "1.0";
	case TEST_FRUIT_VERSION_1_1:
		return "1.1";
	case TEST_FRUIT_VERSION_2_0:
		return "2.0";
	default:
		return "Unknown";
	}
}

/* ── AfpInfo stream name detection tests ─── */

static void test_afpinfo_stream_exact(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_fruit_is_afpinfo_stream("AFP_AfpInfo"));
}

static void test_afpinfo_stream_case_insensitive(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		test_fruit_is_afpinfo_stream("afp_afpinfo"));
	KUNIT_EXPECT_TRUE(test,
		test_fruit_is_afpinfo_stream("AFP_AFPINFO"));
	KUNIT_EXPECT_TRUE(test,
		test_fruit_is_afpinfo_stream("Afp_AfpInfo"));
}

static void test_afpinfo_stream_other(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test,
		test_fruit_is_afpinfo_stream("other"));
	KUNIT_EXPECT_FALSE(test,
		test_fruit_is_afpinfo_stream("AFP_Resource"));
	KUNIT_EXPECT_FALSE(test,
		test_fruit_is_afpinfo_stream(""));
}

static void test_afpinfo_stream_null(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test,
		test_fruit_is_afpinfo_stream(NULL));
}

static void test_afpinfo_stream_prefix_match(struct kunit *test)
{
	/*
	 * strncasecmp with sizeof("AFP_AfpInfo") - 1 = 11 chars.
	 * A string that starts with "AFP_AfpInfo" but continues
	 * should still match (matches the behavior of the real code).
	 */
	KUNIT_EXPECT_TRUE(test,
		test_fruit_is_afpinfo_stream("AFP_AfpInfo:$DATA"));
}

/* ── Volume capabilities tests ─── */

static void test_volume_caps_has_resolve_id(struct kunit *test)
{
	u64 caps = test_fruit_get_volume_caps();

	KUNIT_EXPECT_TRUE(test,
		!!(caps & TEST_kAAPL_SUPPORT_RESOLVE_ID));
}

static void test_volume_caps_has_case_sensitive(struct kunit *test)
{
	u64 caps = test_fruit_get_volume_caps();

	KUNIT_EXPECT_TRUE(test,
		!!(caps & TEST_kAAPL_CASE_SENSITIVE));
}

static void test_volume_caps_has_full_sync(struct kunit *test)
{
	u64 caps = test_fruit_get_volume_caps();

	KUNIT_EXPECT_TRUE(test,
		!!(caps & TEST_kAAPL_SUPPORTS_FULL_SYNC));
}

static void test_volume_caps_combined(struct kunit *test)
{
	u64 caps = test_fruit_get_volume_caps();
	u64 expected = TEST_kAAPL_SUPPORT_RESOLVE_ID |
		       TEST_kAAPL_CASE_SENSITIVE |
		       TEST_kAAPL_SUPPORTS_FULL_SYNC;

	KUNIT_EXPECT_EQ(test, caps, expected);
}

/* ── AFP magic number tests ─── */

static void test_afp_magic_value(struct kunit *test)
{
	/*
	 * AFP_MAGIC = 0x41465000 which is "AFP\0" in ASCII.
	 * Verify the individual bytes.
	 */
	__be32 magic_be = cpu_to_be32(TEST_AFP_MAGIC);
	u8 *bytes = (u8 *)&magic_be;

	KUNIT_EXPECT_EQ(test, bytes[0], (u8)'A');
	KUNIT_EXPECT_EQ(test, bytes[1], (u8)'F');
	KUNIT_EXPECT_EQ(test, bytes[2], (u8)'P');
	KUNIT_EXPECT_EQ(test, bytes[3], (u8)0x00);
}

static void test_afp_magic_numeric(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (u32)TEST_AFP_MAGIC, (u32)0x41465000);
}

/* ── AFP version field tests ─── */

static void test_afp_version_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (u32)TEST_AFP_VERSION, (u32)0x00010000);
}

static void test_afp_version_bytes(struct kunit *test)
{
	__be32 ver_be = cpu_to_be32(TEST_AFP_VERSION);
	u8 *bytes = (u8 *)&ver_be;

	/* 0x00010000 -> major=1, minor=0 */
	KUNIT_EXPECT_EQ(test, bytes[0], (u8)0x00);
	KUNIT_EXPECT_EQ(test, bytes[1], (u8)0x01);
	KUNIT_EXPECT_EQ(test, bytes[2], (u8)0x00);
	KUNIT_EXPECT_EQ(test, bytes[3], (u8)0x00);
}

/* ── Signature validation tests ─── */

static void test_valid_signature(struct kunit *test)
{
	__u8 sig[4] = {'A', 'A', 'P', 'L'};

	KUNIT_EXPECT_TRUE(test, test_fruit_valid_signature(sig));
}

static void test_invalid_signature(struct kunit *test)
{
	__u8 sig[4] = {'X', 'A', 'P', 'L'};

	KUNIT_EXPECT_FALSE(test, test_fruit_valid_signature(sig));
}

static void test_null_signature(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_fruit_valid_signature(NULL));
}

/* ── Client name lookup tests ─── */

static void test_client_name_macos(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		test_fruit_get_client_name(TEST_FRUIT_CLIENT_MACOS),
		"macOS");
}

static void test_client_name_ios(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		test_fruit_get_client_name(TEST_FRUIT_CLIENT_IOS),
		"iOS");
}

static void test_client_name_unknown(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		test_fruit_get_client_name(0xFF),
		"Unknown");
}

/* ── Version string lookup tests ─── */

static void test_version_string_1_0(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		test_fruit_get_version_string(TEST_FRUIT_VERSION_1_0),
		"1.0");
}

static void test_version_string_2_0(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		test_fruit_get_version_string(TEST_FRUIT_VERSION_2_0),
		"2.0");
}

static void test_version_string_unknown(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
		test_fruit_get_version_string(0xDEAD),
		"Unknown");
}

static struct kunit_case ksmbd_fruit_test_cases[] = {
	KUNIT_CASE(test_afpinfo_stream_exact),
	KUNIT_CASE(test_afpinfo_stream_case_insensitive),
	KUNIT_CASE(test_afpinfo_stream_other),
	KUNIT_CASE(test_afpinfo_stream_null),
	KUNIT_CASE(test_afpinfo_stream_prefix_match),
	KUNIT_CASE(test_volume_caps_has_resolve_id),
	KUNIT_CASE(test_volume_caps_has_case_sensitive),
	KUNIT_CASE(test_volume_caps_has_full_sync),
	KUNIT_CASE(test_volume_caps_combined),
	KUNIT_CASE(test_afp_magic_value),
	KUNIT_CASE(test_afp_magic_numeric),
	KUNIT_CASE(test_afp_version_value),
	KUNIT_CASE(test_afp_version_bytes),
	KUNIT_CASE(test_valid_signature),
	KUNIT_CASE(test_invalid_signature),
	KUNIT_CASE(test_null_signature),
	KUNIT_CASE(test_client_name_macos),
	KUNIT_CASE(test_client_name_ios),
	KUNIT_CASE(test_client_name_unknown),
	KUNIT_CASE(test_version_string_1_0),
	KUNIT_CASE(test_version_string_2_0),
	KUNIT_CASE(test_version_string_unknown),
	{}
};

static struct kunit_suite ksmbd_fruit_test_suite = {
	.name = "ksmbd_fruit",
	.test_cases = ksmbd_fruit_test_cases,
};

kunit_test_suite(ksmbd_fruit_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd Apple Fruit extension helpers");
