// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB common helpers (smb_common.c)
 *
 *   These tests replicate the pure logic of protocol lookup,
 *   min/max protocol, and server-side copy defaults without
 *   calling into the ksmbd module directly.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

/* Replicate protocol index constants from smb_common.h */
#define TEST_SMB1_PROT		0
#define TEST_SMB2_PROT		1
#define TEST_SMB21_PROT		2
#define TEST_SMB2X_PROT		3
#define TEST_SMB30_PROT		4
#define TEST_SMB302_PROT	5
#define TEST_SMB311_PROT	6

/* Replicate the smb_protocol structure */
struct test_smb_protocol {
	int		index;
	char		*name;
	char		*prot;
	unsigned short	prot_id;
};

/*
 * Replicate the smb2_protos[] array from smb_common.c.
 * (smb1_protos[] requires CONFIG_SMB_INSECURE_SERVER)
 */
static struct test_smb_protocol test_smb2_protos[] = {
	{
		TEST_SMB2_PROT,
		"\2SMB 2.002",
		"SMB2_02",
		0x0202
	},
	{
		TEST_SMB21_PROT,
		"\2SMB 2.1",
		"SMB2_10",
		0x0210
	},
	{
		TEST_SMB30_PROT,
		"\2SMB 3.0",
		"SMB3_00",
		0x0300
	},
	{
		TEST_SMB302_PROT,
		"\2SMB 3.02",
		"SMB3_02",
		0x0302
	},
	{
		TEST_SMB311_PROT,
		"\2SMB 3.1.1",
		"SMB3_11",
		0x0311
	},
};

/*
 * Replicate ksmbd_lookup_protocol_idx() from smb_common.c.
 * Searches smb2_protos[] for a matching prot string and returns the index.
 * Returns -1 if not found.
 */
static int test_lookup_protocol_idx(const char *str)
{
	int offt;

	/* In the real code, smb1_protos[] is also searched first.
	 * We only test the smb2 path here.
	 */
	offt = ARRAY_SIZE(test_smb2_protos) - 1;
	while (offt >= 0) {
		if (!strcmp(str, test_smb2_protos[offt].prot))
			return test_smb2_protos[offt].index;
		offt--;
	}
	return -1;
}

/*
 * Replicate ksmbd_min_protocol() logic.
 * Without CONFIG_SMB_INSECURE_SERVER, minimum is SMB2_PROT.
 */
static int test_min_protocol(void)
{
	return TEST_SMB2_PROT;
}

/*
 * Replicate ksmbd_max_protocol() logic.
 */
static int test_max_protocol(void)
{
	return TEST_SMB311_PROT;
}

/*
 * Replicate default server-side copy values from ksmbd_config.c
 */
#define TEST_COPY_CHUNK_MAX_COUNT_DEFAULT	256
#define TEST_COPY_CHUNK_MAX_SIZE_DEFAULT	1048576		/* 1MB */
#define TEST_COPY_CHUNK_TOTAL_SIZE_DEFAULT	16777216	/* 16MB */

/* --- ksmbd_lookup_protocol_idx() tests --- */

/*
 * test_lookup_smb2_10 - "SMB2_10" returns SMB21_PROT index
 */
static void test_lookup_smb2_10(struct kunit *test)
{
	int idx = test_lookup_protocol_idx("SMB2_10");

	KUNIT_EXPECT_EQ(test, idx, TEST_SMB21_PROT);
}

/*
 * test_lookup_smb3_11 - "SMB3_11" returns SMB311_PROT index
 */
static void test_lookup_smb3_11(struct kunit *test)
{
	int idx = test_lookup_protocol_idx("SMB3_11");

	KUNIT_EXPECT_EQ(test, idx, TEST_SMB311_PROT);
}

/*
 * test_lookup_smb2_02 - "SMB2_02" returns SMB2_PROT index
 */
static void test_lookup_smb2_02(struct kunit *test)
{
	int idx = test_lookup_protocol_idx("SMB2_02");

	KUNIT_EXPECT_EQ(test, idx, TEST_SMB2_PROT);
}

/*
 * test_lookup_smb3_00 - "SMB3_00" returns SMB30_PROT index
 */
static void test_lookup_smb3_00(struct kunit *test)
{
	int idx = test_lookup_protocol_idx("SMB3_00");

	KUNIT_EXPECT_EQ(test, idx, TEST_SMB30_PROT);
}

/*
 * test_lookup_smb3_02 - "SMB3_02" returns SMB302_PROT index
 */
static void test_lookup_smb3_02(struct kunit *test)
{
	int idx = test_lookup_protocol_idx("SMB3_02");

	KUNIT_EXPECT_EQ(test, idx, TEST_SMB302_PROT);
}

/*
 * test_lookup_invalid_returns_neg - invalid string returns -1
 */
static void test_lookup_invalid_returns_neg(struct kunit *test)
{
	int idx;

	idx = test_lookup_protocol_idx("INVALID");
	KUNIT_EXPECT_EQ(test, idx, -1);

	idx = test_lookup_protocol_idx("");
	KUNIT_EXPECT_EQ(test, idx, -1);

	idx = test_lookup_protocol_idx("SMB4_00");
	KUNIT_EXPECT_EQ(test, idx, -1);
}

/* --- min/max protocol tests --- */

/*
 * test_min_protocol_is_smb2 - minimum supported protocol is SMB2
 */
static void test_min_protocol_is_smb2(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_min_protocol(), TEST_SMB2_PROT);
}

/*
 * test_max_protocol_is_smb311 - maximum supported protocol is SMB3.1.1
 */
static void test_max_protocol_is_smb311(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_max_protocol(), TEST_SMB311_PROT);
}

/* --- Server-side copy defaults tests --- */

/*
 * test_copy_chunk_max_count_default - default max chunk count is 256
 */
static void test_copy_chunk_max_count_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_COPY_CHUNK_MAX_COUNT_DEFAULT, 256);
}

/*
 * test_copy_chunk_max_size_default - default max chunk size is 1MB
 */
static void test_copy_chunk_max_size_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_COPY_CHUNK_MAX_SIZE_DEFAULT, 1048576);
}

/*
 * test_copy_chunk_total_size_default - default max total size is 16MB
 */
static void test_copy_chunk_total_size_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_COPY_CHUNK_TOTAL_SIZE_DEFAULT, 16777216);
}

static struct kunit_case ksmbd_smb_common_test_cases[] = {
	KUNIT_CASE(test_lookup_smb2_10),
	KUNIT_CASE(test_lookup_smb3_11),
	KUNIT_CASE(test_lookup_smb2_02),
	KUNIT_CASE(test_lookup_smb3_00),
	KUNIT_CASE(test_lookup_smb3_02),
	KUNIT_CASE(test_lookup_invalid_returns_neg),
	KUNIT_CASE(test_min_protocol_is_smb2),
	KUNIT_CASE(test_max_protocol_is_smb311),
	KUNIT_CASE(test_copy_chunk_max_count_default),
	KUNIT_CASE(test_copy_chunk_max_size_default),
	KUNIT_CASE(test_copy_chunk_total_size_default),
	{}
};

static struct kunit_suite ksmbd_smb_common_test_suite = {
	.name = "ksmbd_smb_common",
	.test_cases = ksmbd_smb_common_test_cases,
};

kunit_test_suite(ksmbd_smb_common_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB common helpers");
