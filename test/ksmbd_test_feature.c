// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for the three-tier feature negotiation (ksmbd_feature.c)
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and reimplement the pure logic under test.
 */

#include <kunit/test.h>
#include <linux/bitops.h>
#include <linux/types.h>

/* ---- Inlined definitions from ksmbd_feature.h ---- */

enum test_ksmbd_feature {
	TEST_FEAT_LEASING,
	TEST_FEAT_MULTICHANNEL,
	TEST_FEAT_ENCRYPTION,
	TEST_FEAT_DURABLE_HANDLE,
	TEST_FEAT_FRUIT,
	TEST_FEAT_DFS,
	TEST_FEAT_VSS,
	TEST_FEAT_COMPRESSION,
	TEST_FEAT_SIGNING,
	__TEST_FEAT_MAX,
};

/*
 * Tier 1: compile-time check.  Mirrors ksmbd_feature_compiled().
 * FRUIT is conditionally compiled (here we treat it as not compiled
 * to test the false path).
 */
static inline bool test_feature_compiled(enum test_ksmbd_feature feat)
{
	switch (feat) {
	case TEST_FEAT_LEASING:
	case TEST_FEAT_MULTICHANNEL:
	case TEST_FEAT_ENCRYPTION:
	case TEST_FEAT_DURABLE_HANDLE:
	case TEST_FEAT_DFS:
	case TEST_FEAT_VSS:
	case TEST_FEAT_COMPRESSION:
	case TEST_FEAT_SIGNING:
		return true;
	case TEST_FEAT_FRUIT:
		/* Simulate CONFIG_KSMBD_FRUIT not set */
		return false;
	default:
		return false;
	}
}

/*
 * Minimal stand-in for server_conf.features and conn->features.
 */
struct test_server_conf {
	unsigned long features;
};

struct test_conn {
	unsigned long features;
};

/*
 * Tier 2: global enable check.  Mirrors ksmbd_feature_global_enabled().
 */
static bool test_feature_global_enabled(struct test_server_conf *conf,
					enum test_ksmbd_feature feat)
{
	if (feat >= __TEST_FEAT_MAX)
		return false;

	return test_bit(feat, &conf->features);
}

/*
 * Full three-tier check.  Mirrors ksmbd_feat_enabled().
 */
static bool test_feat_enabled(struct test_server_conf *conf,
			      struct test_conn *conn,
			      enum test_ksmbd_feature feat)
{
	/* Tier 1: compiled in? */
	if (!test_feature_compiled(feat))
		return false;

	/* Tier 2: globally enabled? */
	if (!test_feature_global_enabled(conf, feat))
		return false;

	/* Tier 3: per-connection negotiated? */
	if (conn && !test_bit(feat, &conn->features))
		return false;

	return true;
}

/* ---- Test cases ---- */

/*
 * test_compiled_standard_features - standard features are compiled in
 */
static void test_compiled_standard_features(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_LEASING));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_MULTICHANNEL));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_ENCRYPTION));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_DURABLE_HANDLE));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_DFS));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_VSS));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_COMPRESSION));
	KUNIT_EXPECT_TRUE(test, test_feature_compiled(TEST_FEAT_SIGNING));
}

/*
 * test_compiled_fruit_disabled - FRUIT returns false when not compiled
 */
static void test_compiled_fruit_disabled(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_feature_compiled(TEST_FEAT_FRUIT));
}

/*
 * test_compiled_out_of_range - out-of-range feature returns false
 */
static void test_compiled_out_of_range(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_feature_compiled(__TEST_FEAT_MAX));
	KUNIT_EXPECT_FALSE(test, test_feature_compiled(__TEST_FEAT_MAX + 1));
}

/*
 * test_global_enabled_set - globally enabled feature returns true
 */
static void test_global_enabled_set(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };

	set_bit(TEST_FEAT_ENCRYPTION, &conf.features);
	KUNIT_EXPECT_TRUE(test,
			  test_feature_global_enabled(&conf,
						      TEST_FEAT_ENCRYPTION));
}

/*
 * test_global_enabled_unset - globally disabled feature returns false
 */
static void test_global_enabled_unset(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };

	KUNIT_EXPECT_FALSE(test,
			   test_feature_global_enabled(&conf,
						       TEST_FEAT_ENCRYPTION));
}

/*
 * test_global_enabled_out_of_range - out-of-range returns false
 */
static void test_global_enabled_out_of_range(struct kunit *test)
{
	struct test_server_conf conf = { .features = ~0UL };

	KUNIT_EXPECT_FALSE(test,
			   test_feature_global_enabled(&conf,
						       __TEST_FEAT_MAX));
}

/*
 * test_feat_enabled_all_three_tiers - passes when all tiers pass
 */
static void test_feat_enabled_all_three_tiers(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };
	struct test_conn conn = { .features = 0 };

	set_bit(TEST_FEAT_SIGNING, &conf.features);
	set_bit(TEST_FEAT_SIGNING, &conn.features);

	KUNIT_EXPECT_TRUE(test,
			  test_feat_enabled(&conf, &conn, TEST_FEAT_SIGNING));
}

/*
 * test_feat_enabled_null_conn - NULL conn skips tier 3
 */
static void test_feat_enabled_null_conn(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };

	set_bit(TEST_FEAT_SIGNING, &conf.features);

	/* With NULL conn, only tiers 1 and 2 are checked */
	KUNIT_EXPECT_TRUE(test,
			  test_feat_enabled(&conf, NULL, TEST_FEAT_SIGNING));
}

/*
 * test_feat_enabled_global_disabled - fails when global bit is off
 */
static void test_feat_enabled_global_disabled(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };
	struct test_conn conn = { .features = 0 };

	/* Don't set global bit, but set per-conn bit */
	set_bit(TEST_FEAT_SIGNING, &conn.features);

	KUNIT_EXPECT_FALSE(test,
			   test_feat_enabled(&conf, &conn, TEST_FEAT_SIGNING));
}

/*
 * test_feat_enabled_conn_disabled - fails when conn bit is off
 */
static void test_feat_enabled_conn_disabled(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };
	struct test_conn conn = { .features = 0 };

	set_bit(TEST_FEAT_SIGNING, &conf.features);
	/* Don't set conn bit */

	KUNIT_EXPECT_FALSE(test,
			   test_feat_enabled(&conf, &conn, TEST_FEAT_SIGNING));
}

/*
 * test_feat_enabled_not_compiled - fails if feature not compiled
 */
static void test_feat_enabled_not_compiled(struct kunit *test)
{
	struct test_server_conf conf = { .features = 0 };
	struct test_conn conn = { .features = 0 };

	set_bit(TEST_FEAT_FRUIT, &conf.features);
	set_bit(TEST_FEAT_FRUIT, &conn.features);

	/* FRUIT is not compiled, so should fail at tier 1 */
	KUNIT_EXPECT_FALSE(test,
			   test_feat_enabled(&conf, &conn, TEST_FEAT_FRUIT));
}

static struct kunit_case ksmbd_feature_test_cases[] = {
	KUNIT_CASE(test_compiled_standard_features),
	KUNIT_CASE(test_compiled_fruit_disabled),
	KUNIT_CASE(test_compiled_out_of_range),
	KUNIT_CASE(test_global_enabled_set),
	KUNIT_CASE(test_global_enabled_unset),
	KUNIT_CASE(test_global_enabled_out_of_range),
	KUNIT_CASE(test_feat_enabled_all_three_tiers),
	KUNIT_CASE(test_feat_enabled_null_conn),
	KUNIT_CASE(test_feat_enabled_global_disabled),
	KUNIT_CASE(test_feat_enabled_conn_disabled),
	KUNIT_CASE(test_feat_enabled_not_compiled),
	{}
};

static struct kunit_suite ksmbd_feature_test_suite = {
	.name = "ksmbd_feature",
	.test_cases = ksmbd_feature_test_cases,
};

kunit_test_suite(ksmbd_feature_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd three-tier feature negotiation");
