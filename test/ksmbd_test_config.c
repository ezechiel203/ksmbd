// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for configuration framework (ksmbd_config.c)
 */

#include <kunit/test.h>

#include "ksmbd_config.h"

/*
 * test_config_init_and_defaults - verify init sets default values
 */
static void test_config_init_and_defaults(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Check known default values from the config descriptors */
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)65536);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_WRITE_SIZE), (u32)65536);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_TRANS_SIZE), (u32)65536);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_CREDITS), (u32)8192);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS), (u32)0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_IPC_TIMEOUT), (u32)10);

	ksmbd_config_exit();
}

/*
 * test_config_set_get_roundtrip - set a value and read it back
 */
static void test_config_set_get_roundtrip(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 131072);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)131072);

	/* Set max connections */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_CONNECTIONS, 100);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_CONNECTIONS), (u32)100);

	ksmbd_config_exit();
}

/*
 * test_config_set_clamp_above_max - values exceeding max are clamped
 */
static void test_config_set_clamp_above_max(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/*
	 * KSMBD_CFG_MAX_READ_SIZE has max_val = 8388608 (8MB).
	 * Setting 16MB should be clamped to 8MB.
	 */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 16777216);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)8388608);

	ksmbd_config_exit();
}

/*
 * test_config_set_clamp_below_min - values below min are clamped
 */
static void test_config_set_clamp_below_min(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/*
	 * KSMBD_CFG_MAX_READ_SIZE has min_val = 4096.
	 * Setting 1024 should be clamped to 4096.
	 */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 1024);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)4096);

	ksmbd_config_exit();
}

/*
 * test_config_set_invalid_param - invalid parameter returns -EINVAL
 */
static void test_config_set_invalid_param(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = ksmbd_config_set_u32(__KSMBD_CFG_MAX, 42);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	ksmbd_config_exit();
}

/*
 * test_config_get_invalid_param - invalid parameter returns 0
 */
static void test_config_get_invalid_param(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(__KSMBD_CFG_MAX), (u32)0);

	ksmbd_config_exit();
}

/*
 * test_config_param_name - verify human-readable parameter names
 */
static void test_config_param_name(struct kunit *test)
{
	const char *name;
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	name = ksmbd_config_param_name(KSMBD_CFG_MAX_READ_SIZE);
	KUNIT_EXPECT_STREQ(test, name, "max read size");

	name = ksmbd_config_param_name(KSMBD_CFG_MAX_CREDITS);
	KUNIT_EXPECT_STREQ(test, name, "max credits");

	name = ksmbd_config_param_name(KSMBD_CFG_IPC_TIMEOUT);
	KUNIT_EXPECT_STREQ(test, name, "ipc timeout");

	/* Invalid parameter should return "(invalid)" */
	name = ksmbd_config_param_name(__KSMBD_CFG_MAX);
	KUNIT_EXPECT_STREQ(test, name, "(invalid)");

	ksmbd_config_exit();
}

/*
 * test_config_set_boundary_values - set exactly the min and max boundaries
 */
static void test_config_set_boundary_values(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Set to exact minimum (4096 for MAX_READ_SIZE) */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 4096);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)4096);

	/* Set to exact maximum (8388608 for MAX_READ_SIZE) */
	ret = ksmbd_config_set_u32(KSMBD_CFG_MAX_READ_SIZE, 8388608);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_MAX_READ_SIZE), (u32)8388608);

	ksmbd_config_exit();
}

/*
 * test_config_ipc_timeout_range - IPC timeout range [1, 300]
 */
static void test_config_ipc_timeout_range(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Within range */
	ret = ksmbd_config_set_u32(KSMBD_CFG_IPC_TIMEOUT, 60);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_IPC_TIMEOUT), (u32)60);

	/* Below minimum: clamped to 1 */
	ret = ksmbd_config_set_u32(KSMBD_CFG_IPC_TIMEOUT, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_IPC_TIMEOUT), (u32)1);

	/* Above maximum: clamped to 300 */
	ret = ksmbd_config_set_u32(KSMBD_CFG_IPC_TIMEOUT, 999);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_IPC_TIMEOUT), (u32)300);

	ksmbd_config_exit();
}

/*
 * test_config_deadtime - deadtime with max_val=86400 (24h)
 */
static void test_config_deadtime(struct kunit *test)
{
	int ret;

	ret = ksmbd_config_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Default is 0 */
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_DEADTIME), (u32)0);

	/* Set a valid value */
	ret = ksmbd_config_set_u32(KSMBD_CFG_DEADTIME, 3600);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_DEADTIME), (u32)3600);

	/* Exceed 86400 should be clamped */
	ret = ksmbd_config_set_u32(KSMBD_CFG_DEADTIME, 100000);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test,
		ksmbd_config_get_u32(KSMBD_CFG_DEADTIME), (u32)86400);

	ksmbd_config_exit();
}

static struct kunit_case ksmbd_config_test_cases[] = {
	KUNIT_CASE(test_config_init_and_defaults),
	KUNIT_CASE(test_config_set_get_roundtrip),
	KUNIT_CASE(test_config_set_clamp_above_max),
	KUNIT_CASE(test_config_set_clamp_below_min),
	KUNIT_CASE(test_config_set_invalid_param),
	KUNIT_CASE(test_config_get_invalid_param),
	KUNIT_CASE(test_config_param_name),
	KUNIT_CASE(test_config_set_boundary_values),
	KUNIT_CASE(test_config_ipc_timeout_range),
	KUNIT_CASE(test_config_deadtime),
	{}
};

static struct kunit_suite ksmbd_config_test_suite = {
	.name = "ksmbd_config",
	.test_cases = ksmbd_config_test_cases,
};

kunit_test_suite(ksmbd_config_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd configuration framework");
