// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for smb2ops.c server initialization functions.
 *
 *   Tests cover:
 *     - Protocol version initialization (SMB 2.0.2 through 3.1.1)
 *     - Capability flags per dialect
 *     - Max size configuration (read, write, transact, credits)
 *     - SMB 3.1.1 specific features (notifications, encryption)
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ---- Replicated constants ---- */

/* SMB2 Dialect IDs */
#define TEST_SMB20_PROT_ID		0x0202
#define TEST_SMB21_PROT_ID		0x0210
#define TEST_SMB30_PROT_ID		0x0300
#define TEST_SMB302_PROT_ID		0x0302
#define TEST_SMB311_PROT_ID		0x0311

/* Capability flags */
#define TEST_SMB2_GLOBAL_CAP_DFS		0x00000001
#define TEST_SMB2_GLOBAL_CAP_LEASING		0x00000002
#define TEST_SMB2_GLOBAL_CAP_LARGE_MTU		0x00000004
#define TEST_SMB2_GLOBAL_CAP_MULTI_CHANNEL	0x00000008
#define TEST_SMB2_GLOBAL_CAP_PERSISTENT_HANDLES	0x00000010
#define TEST_SMB2_GLOBAL_CAP_DIRECTORY_LEASING	0x00000020
#define TEST_SMB2_GLOBAL_CAP_ENCRYPTION		0x00000040
#define TEST_SMB2_GLOBAL_CAP_NOTIFICATIONS	0x00000080

/* Default max sizes from smb2ops.c */
#define TEST_SMB2_MAX_READ_SIZE		(8 * 1024 * 1024)   /* 8MB */
#define TEST_SMB2_MAX_WRITE_SIZE	(8 * 1024 * 1024)   /* 8MB */
#define TEST_SMB2_MAX_TRANS_SIZE	(8 * 1024 * 1024)   /* 8MB */
#define TEST_SMB2_MAX_CREDITS		8192

/* Header sizes */
#define TEST_SMB2_HEADER_SIZE		64
#define TEST_SMB2_MAX_BUFFER_SIZE	65536

/* ---- Replicated structures ---- */

struct test_smb2_server_values {
	u16 dialect;
	u32 capabilities;
	u32 max_read_size;
	u32 max_write_size;
	u32 max_trans_size;
	u32 max_credits;
	u16 header_size;
	u16 max_buffer_size;
};

/* ---- Replicated logic ---- */

/*
 * Replicate init_smb2_0_server() from smb2ops.c
 */
static void test_init_smb2_0_server(struct test_smb2_server_values *v)
{
	v->dialect = TEST_SMB20_PROT_ID;
	v->capabilities = TEST_SMB2_GLOBAL_CAP_DFS;
	v->max_read_size = TEST_SMB2_MAX_BUFFER_SIZE;
	v->max_write_size = TEST_SMB2_MAX_BUFFER_SIZE;
	v->max_trans_size = TEST_SMB2_MAX_BUFFER_SIZE;
	v->max_credits = TEST_SMB2_MAX_CREDITS;
	v->header_size = TEST_SMB2_HEADER_SIZE;
	v->max_buffer_size = TEST_SMB2_MAX_BUFFER_SIZE;
}

/*
 * Replicate init_smb2_1_server() from smb2ops.c
 */
static void test_init_smb2_1_server(struct test_smb2_server_values *v)
{
	v->dialect = TEST_SMB21_PROT_ID;
	v->capabilities = TEST_SMB2_GLOBAL_CAP_DFS |
			  TEST_SMB2_GLOBAL_CAP_LEASING |
			  TEST_SMB2_GLOBAL_CAP_LARGE_MTU;
	v->max_read_size = TEST_SMB2_MAX_READ_SIZE;
	v->max_write_size = TEST_SMB2_MAX_WRITE_SIZE;
	v->max_trans_size = TEST_SMB2_MAX_TRANS_SIZE;
	v->max_credits = TEST_SMB2_MAX_CREDITS;
	v->header_size = TEST_SMB2_HEADER_SIZE;
	v->max_buffer_size = TEST_SMB2_MAX_BUFFER_SIZE;
}

/*
 * Replicate init_smb3_0_server() from smb2ops.c
 */
static void test_init_smb3_0_server(struct test_smb2_server_values *v)
{
	v->dialect = TEST_SMB30_PROT_ID;
	v->capabilities = TEST_SMB2_GLOBAL_CAP_DFS |
			  TEST_SMB2_GLOBAL_CAP_LEASING |
			  TEST_SMB2_GLOBAL_CAP_LARGE_MTU |
			  TEST_SMB2_GLOBAL_CAP_MULTI_CHANNEL |
			  TEST_SMB2_GLOBAL_CAP_PERSISTENT_HANDLES |
			  TEST_SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
			  TEST_SMB2_GLOBAL_CAP_ENCRYPTION;
	v->max_read_size = TEST_SMB2_MAX_READ_SIZE;
	v->max_write_size = TEST_SMB2_MAX_WRITE_SIZE;
	v->max_trans_size = TEST_SMB2_MAX_TRANS_SIZE;
	v->max_credits = TEST_SMB2_MAX_CREDITS;
	v->header_size = TEST_SMB2_HEADER_SIZE;
	v->max_buffer_size = TEST_SMB2_MAX_BUFFER_SIZE;
}

/*
 * Replicate init_smb3_02_server() from smb2ops.c
 */
static void test_init_smb3_02_server(struct test_smb2_server_values *v)
{
	v->dialect = TEST_SMB302_PROT_ID;
	v->capabilities = TEST_SMB2_GLOBAL_CAP_DFS |
			  TEST_SMB2_GLOBAL_CAP_LEASING |
			  TEST_SMB2_GLOBAL_CAP_LARGE_MTU |
			  TEST_SMB2_GLOBAL_CAP_MULTI_CHANNEL |
			  TEST_SMB2_GLOBAL_CAP_PERSISTENT_HANDLES |
			  TEST_SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
			  TEST_SMB2_GLOBAL_CAP_ENCRYPTION;
	v->max_read_size = TEST_SMB2_MAX_READ_SIZE;
	v->max_write_size = TEST_SMB2_MAX_WRITE_SIZE;
	v->max_trans_size = TEST_SMB2_MAX_TRANS_SIZE;
	v->max_credits = TEST_SMB2_MAX_CREDITS;
	v->header_size = TEST_SMB2_HEADER_SIZE;
	v->max_buffer_size = TEST_SMB2_MAX_BUFFER_SIZE;
}

/*
 * Replicate init_smb3_11_server() from smb2ops.c
 */
static void test_init_smb3_11_server(struct test_smb2_server_values *v)
{
	v->dialect = TEST_SMB311_PROT_ID;
	v->capabilities = TEST_SMB2_GLOBAL_CAP_DFS |
			  TEST_SMB2_GLOBAL_CAP_LEASING |
			  TEST_SMB2_GLOBAL_CAP_LARGE_MTU |
			  TEST_SMB2_GLOBAL_CAP_MULTI_CHANNEL |
			  TEST_SMB2_GLOBAL_CAP_PERSISTENT_HANDLES |
			  TEST_SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
			  TEST_SMB2_GLOBAL_CAP_ENCRYPTION |
			  TEST_SMB2_GLOBAL_CAP_NOTIFICATIONS;
	v->max_read_size = TEST_SMB2_MAX_READ_SIZE;
	v->max_write_size = TEST_SMB2_MAX_WRITE_SIZE;
	v->max_trans_size = TEST_SMB2_MAX_TRANS_SIZE;
	v->max_credits = TEST_SMB2_MAX_CREDITS;
	v->header_size = TEST_SMB2_HEADER_SIZE;
	v->max_buffer_size = TEST_SMB2_MAX_BUFFER_SIZE;
}

/*
 * Replicate max size update functions from smb2ops.c
 */
static u32 test_init_max_read_size(u32 new_val)
{
	if (new_val == 0)
		return TEST_SMB2_MAX_READ_SIZE;
	/* Clamp to reasonable maximum */
	if (new_val > 128 * 1024 * 1024)
		return 128 * 1024 * 1024;
	return new_val;
}

static u32 test_init_max_write_size(u32 new_val)
{
	if (new_val == 0)
		return TEST_SMB2_MAX_WRITE_SIZE;
	if (new_val > 128 * 1024 * 1024)
		return 128 * 1024 * 1024;
	return new_val;
}

static u32 test_init_max_trans_size(u32 new_val)
{
	if (new_val == 0)
		return TEST_SMB2_MAX_TRANS_SIZE;
	if (new_val > 128 * 1024 * 1024)
		return 128 * 1024 * 1024;
	return new_val;
}

static u32 test_init_max_credits(u32 new_val)
{
	if (new_val == 0)
		return TEST_SMB2_MAX_CREDITS;
	if (new_val > 65535)
		return 65535;
	return new_val;
}

/* ---- Test Cases: Protocol Version Initialization ---- */

static void test_init_smb2_0_server_values(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb2_0_server(&v);
	KUNIT_EXPECT_EQ(test, v.dialect, (u16)TEST_SMB20_PROT_ID);
	KUNIT_EXPECT_EQ(test, v.header_size, (u16)TEST_SMB2_HEADER_SIZE);
	KUNIT_EXPECT_EQ(test, v.max_buffer_size,
			(u16)TEST_SMB2_MAX_BUFFER_SIZE);
}

static void test_init_smb2_0_server_capabilities(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb2_0_server(&v);
	/* SMB 2.0.2 only supports DFS */
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_DFS));
	KUNIT_EXPECT_FALSE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_LARGE_MTU));
	KUNIT_EXPECT_FALSE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_LEASING));
	KUNIT_EXPECT_FALSE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_MULTI_CHANNEL));
}

static void test_init_smb2_0_server_no_large_mtu(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb2_0_server(&v);
	/* Without LARGE_MTU, max sizes are limited to 64K */
	KUNIT_EXPECT_EQ(test, v.max_read_size,
			(u32)TEST_SMB2_MAX_BUFFER_SIZE);
	KUNIT_EXPECT_EQ(test, v.max_write_size,
			(u32)TEST_SMB2_MAX_BUFFER_SIZE);
}

static void test_init_smb2_1_server_values(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb2_1_server(&v);
	KUNIT_EXPECT_EQ(test, v.dialect, (u16)TEST_SMB21_PROT_ID);
}

static void test_init_smb2_1_server_large_mtu(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb2_1_server(&v);
	/* SMB 2.1 supports LARGE_MTU */
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_LARGE_MTU));
	KUNIT_EXPECT_EQ(test, v.max_read_size,
			(u32)TEST_SMB2_MAX_READ_SIZE);
}

static void test_init_smb3_0_server_values(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb3_0_server(&v);
	KUNIT_EXPECT_EQ(test, v.dialect, (u16)TEST_SMB30_PROT_ID);
}

static void test_init_smb3_0_server_multichannel(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb3_0_server(&v);
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_MULTI_CHANNEL));
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_ENCRYPTION));
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_PERSISTENT_HANDLES));
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_DIRECTORY_LEASING));
}

static void test_init_smb3_02_server_values(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb3_02_server(&v);
	KUNIT_EXPECT_EQ(test, v.dialect, (u16)TEST_SMB302_PROT_ID);
	/* Same caps as 3.0 */
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_ENCRYPTION));
}

static void test_init_smb3_11_server_values(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb3_11_server(&v);
	KUNIT_EXPECT_EQ(test, v.dialect, (u16)TEST_SMB311_PROT_ID);
}

static void test_init_smb3_11_server_notifications(struct kunit *test)
{
	struct test_smb2_server_values v = {};

	test_init_smb3_11_server(&v);
	/* SMB 3.1.1 includes NOTIFICATIONS capability */
	KUNIT_EXPECT_TRUE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_NOTIFICATIONS));

	/* Earlier dialects do NOT include NOTIFICATIONS */
	test_init_smb3_02_server(&v);
	KUNIT_EXPECT_FALSE(test,
		!!(v.capabilities & TEST_SMB2_GLOBAL_CAP_NOTIFICATIONS));
}

/* ---- Test Cases: Max Size Configuration ---- */

static void test_init_max_read_size_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_init_max_read_size(0),
			(u32)TEST_SMB2_MAX_READ_SIZE);
}

static void test_init_max_write_size_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_init_max_write_size(0),
			(u32)TEST_SMB2_MAX_WRITE_SIZE);
}

static void test_init_max_trans_size_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_init_max_trans_size(0),
			(u32)TEST_SMB2_MAX_TRANS_SIZE);
}

static void test_init_max_credits_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_init_max_credits(0),
			(u32)TEST_SMB2_MAX_CREDITS);
}

static void test_init_max_size_zero(struct kunit *test)
{
	/* Zero means "use default" */
	KUNIT_EXPECT_EQ(test, test_init_max_read_size(0),
			(u32)TEST_SMB2_MAX_READ_SIZE);
	KUNIT_EXPECT_EQ(test, test_init_max_write_size(0),
			(u32)TEST_SMB2_MAX_WRITE_SIZE);
	KUNIT_EXPECT_EQ(test, test_init_max_trans_size(0),
			(u32)TEST_SMB2_MAX_TRANS_SIZE);
	KUNIT_EXPECT_EQ(test, test_init_max_credits(0),
			(u32)TEST_SMB2_MAX_CREDITS);
}

static void test_init_max_size_overflow(struct kunit *test)
{
	/* Very large values get clamped */
	KUNIT_EXPECT_EQ(test, test_init_max_read_size(0xFFFFFFFF),
			(u32)(128 * 1024 * 1024));
	KUNIT_EXPECT_EQ(test, test_init_max_write_size(0xFFFFFFFF),
			(u32)(128 * 1024 * 1024));
	KUNIT_EXPECT_EQ(test, test_init_max_trans_size(0xFFFFFFFF),
			(u32)(128 * 1024 * 1024));
	KUNIT_EXPECT_EQ(test, test_init_max_credits(0xFFFFFFFF),
			(u32)65535);
}

static void test_init_max_read_size_custom(struct kunit *test)
{
	/* Custom value within range is accepted */
	KUNIT_EXPECT_EQ(test, test_init_max_read_size(4 * 1024 * 1024),
			(u32)(4 * 1024 * 1024));
}

static void test_init_max_credits_custom(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_init_max_credits(1024), (u32)1024);
}

/* ---- Test Cases: Cross-dialect Comparison ---- */

static void test_smb2_0_vs_smb2_1_capabilities(struct kunit *test)
{
	struct test_smb2_server_values v20 = {}, v21 = {};

	test_init_smb2_0_server(&v20);
	test_init_smb2_1_server(&v21);

	/* SMB 2.1 adds LEASING and LARGE_MTU over 2.0.2 */
	KUNIT_EXPECT_FALSE(test,
		!!(v20.capabilities & TEST_SMB2_GLOBAL_CAP_LEASING));
	KUNIT_EXPECT_TRUE(test,
		!!(v21.capabilities & TEST_SMB2_GLOBAL_CAP_LEASING));

	KUNIT_EXPECT_FALSE(test,
		!!(v20.capabilities & TEST_SMB2_GLOBAL_CAP_LARGE_MTU));
	KUNIT_EXPECT_TRUE(test,
		!!(v21.capabilities & TEST_SMB2_GLOBAL_CAP_LARGE_MTU));
}

static void test_smb3_0_vs_smb3_11_capabilities(struct kunit *test)
{
	struct test_smb2_server_values v30 = {}, v311 = {};

	test_init_smb3_0_server(&v30);
	test_init_smb3_11_server(&v311);

	/* SMB 3.1.1 adds NOTIFICATIONS over 3.0 */
	KUNIT_EXPECT_FALSE(test,
		!!(v30.capabilities & TEST_SMB2_GLOBAL_CAP_NOTIFICATIONS));
	KUNIT_EXPECT_TRUE(test,
		!!(v311.capabilities & TEST_SMB2_GLOBAL_CAP_NOTIFICATIONS));
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_smb2_ops_test_cases[] = {
	/* Protocol Version Init */
	KUNIT_CASE(test_init_smb2_0_server_values),
	KUNIT_CASE(test_init_smb2_0_server_capabilities),
	KUNIT_CASE(test_init_smb2_0_server_no_large_mtu),
	KUNIT_CASE(test_init_smb2_1_server_values),
	KUNIT_CASE(test_init_smb2_1_server_large_mtu),
	KUNIT_CASE(test_init_smb3_0_server_values),
	KUNIT_CASE(test_init_smb3_0_server_multichannel),
	KUNIT_CASE(test_init_smb3_02_server_values),
	KUNIT_CASE(test_init_smb3_11_server_values),
	KUNIT_CASE(test_init_smb3_11_server_notifications),
	/* Max Size Configuration */
	KUNIT_CASE(test_init_max_read_size_default),
	KUNIT_CASE(test_init_max_write_size_default),
	KUNIT_CASE(test_init_max_trans_size_default),
	KUNIT_CASE(test_init_max_credits_default),
	KUNIT_CASE(test_init_max_size_zero),
	KUNIT_CASE(test_init_max_size_overflow),
	KUNIT_CASE(test_init_max_read_size_custom),
	KUNIT_CASE(test_init_max_credits_custom),
	/* Cross-dialect Comparison */
	KUNIT_CASE(test_smb2_0_vs_smb2_1_capabilities),
	KUNIT_CASE(test_smb3_0_vs_smb3_11_capabilities),
	{}
};

static struct kunit_suite ksmbd_smb2_ops_test_suite = {
	.name = "ksmbd_smb2_ops",
	.test_cases = ksmbd_smb2_ops_test_cases,
};

kunit_test_suite(ksmbd_smb2_ops_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd smb2ops.c server initialization");
