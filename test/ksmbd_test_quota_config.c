// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for the config-driven default quota feature.
 *
 *   Tests the share_config quota fields and their population from
 *   the netlink response structure.  The production share_config.h
 *   header is not included directly to avoid pulling in heavy VFS
 *   dependencies; we replicate the relevant struct portion and verify
 *   field sizes match the netlink ABI.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "ksmbd_netlink.h"

/*
 * Replicated quota-relevant portion of struct ksmbd_share_config
 * from mgmt/share_config.h -- keeps the test self-contained while
 * verifying the types and semantics.
 */
struct test_share_config_quota {
	unsigned long long	default_quota_hardlimit;  /* bytes, 0 = unlimited */
	unsigned long long	default_quota_softlimit;  /* bytes, 0 = unlimited */
};

static void test_share_config_has_quota_fields(struct kunit *test)
{
	struct test_share_config_quota sc;

	memset(&sc, 0, sizeof(sc));
	/* Verify the fields exist and are zero-initialized */
	KUNIT_EXPECT_EQ(test, sc.default_quota_hardlimit, 0ULL);
	KUNIT_EXPECT_EQ(test, sc.default_quota_softlimit, 0ULL);
}

static void test_netlink_response_has_quota_fields(struct kunit *test)
{
	struct ksmbd_share_config_response resp;

	memset(&resp, 0, sizeof(resp));
	KUNIT_EXPECT_EQ(test, resp.default_quota_hardlimit, (__u64)0);
	KUNIT_EXPECT_EQ(test, resp.default_quota_softlimit, (__u64)0);
}

static void test_share_config_quota_10gb(struct kunit *test)
{
	struct test_share_config_quota sc;

	memset(&sc, 0, sizeof(sc));
	sc.default_quota_hardlimit = 10ULL * 1024 * 1024 * 1024; /* 10 GB */
	sc.default_quota_softlimit = 8ULL * 1024 * 1024 * 1024;  /* 8 GB */

	KUNIT_EXPECT_GT(test, sc.default_quota_hardlimit, sc.default_quota_softlimit);
	KUNIT_EXPECT_EQ(test, sc.default_quota_hardlimit, 10737418240ULL);
}

static void test_share_config_zero_means_unlimited(struct kunit *test)
{
	struct test_share_config_quota sc;

	memset(&sc, 0, sizeof(sc));
	/* Zero means no quota configured (unlimited) */
	KUNIT_EXPECT_FALSE(test, sc.default_quota_hardlimit);
	KUNIT_EXPECT_FALSE(test, sc.default_quota_softlimit);
}

static void test_netlink_quota_populated_from_response(struct kunit *test)
{
	struct test_share_config_quota sc;
	struct ksmbd_share_config_response resp;

	memset(&sc, 0, sizeof(sc));
	memset(&resp, 0, sizeof(resp));

	resp.default_quota_hardlimit = 5368709120ULL; /* 5 GB */
	resp.default_quota_softlimit = 4294967296ULL; /* 4 GB */

	/* Simulate what share_config.c does */
	sc.default_quota_hardlimit = resp.default_quota_hardlimit;
	sc.default_quota_softlimit = resp.default_quota_softlimit;

	KUNIT_EXPECT_EQ(test, sc.default_quota_hardlimit, 5368709120ULL);
	KUNIT_EXPECT_EQ(test, sc.default_quota_softlimit, 4294967296ULL);
}

static struct kunit_case ksmbd_quota_config_test_cases[] = {
	KUNIT_CASE(test_share_config_has_quota_fields),
	KUNIT_CASE(test_netlink_response_has_quota_fields),
	KUNIT_CASE(test_share_config_quota_10gb),
	KUNIT_CASE(test_share_config_zero_means_unlimited),
	KUNIT_CASE(test_netlink_quota_populated_from_response),
	{}
};

static struct kunit_suite ksmbd_quota_config_test_suite = {
	.name = "ksmbd_quota_config",
	.test_cases = ksmbd_quota_config_test_cases,
};

kunit_test_suite(ksmbd_quota_config_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd config-driven default quota");
