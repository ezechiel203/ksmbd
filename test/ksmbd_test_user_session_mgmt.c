// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for user session management helpers (user_session.c)
 *
 *   Since __rpc_method() is static in user_session.c, we replicate its
 *   logic here to verify the RPC method dispatch table correctness.
 *   The RPC name -> method mapping is security-relevant because it
 *   controls which IPC operations are dispatched to mountd.
 */

#include <kunit/test.h>
#include <linux/string.h>

#include "ksmbd_netlink.h"

/*
 * Replicate __rpc_method() from user_session.c.
 * This must stay in sync with the production code.
 */
static int test_rpc_method(char *rpc_name)
{
	if (!strcmp(rpc_name, "\\srvsvc") || !strcmp(rpc_name, "srvsvc"))
		return KSMBD_RPC_SRVSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\wkssvc") || !strcmp(rpc_name, "wkssvc"))
		return KSMBD_RPC_WKSSVC_METHOD_INVOKE;

	if (!strcmp(rpc_name, "LANMAN") || !strcmp(rpc_name, "lanman"))
		return KSMBD_RPC_RAP_METHOD;

	if (!strcmp(rpc_name, "\\samr") || !strcmp(rpc_name, "samr"))
		return KSMBD_RPC_SAMR_METHOD_INVOKE;

	if (!strcmp(rpc_name, "\\lsarpc") || !strcmp(rpc_name, "lsarpc"))
		return KSMBD_RPC_LSARPC_METHOD_INVOKE;

	return 0;
}

/* ===== RPC method dispatch tests ===== */

/*
 * test_rpc_method_srvsvc - \\srvsvc returns SRVSVC method
 */
static void test_rpc_method_srvsvc(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\srvsvc"),
			KSMBD_RPC_SRVSVC_METHOD_INVOKE);
}

/*
 * test_rpc_method_srvsvc_no_backslash - srvsvc without backslash
 */
static void test_rpc_method_srvsvc_no_backslash(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("srvsvc"),
			KSMBD_RPC_SRVSVC_METHOD_INVOKE);
}

/*
 * test_rpc_method_wkssvc - \\wkssvc returns WKSSVC method
 */
static void test_rpc_method_wkssvc(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\wkssvc"),
			KSMBD_RPC_WKSSVC_METHOD_INVOKE);
}

/*
 * test_rpc_method_wkssvc_no_backslash - wkssvc without backslash
 */
static void test_rpc_method_wkssvc_no_backslash(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("wkssvc"),
			KSMBD_RPC_WKSSVC_METHOD_INVOKE);
}

/*
 * test_rpc_method_lanman - LANMAN returns RAP method
 */
static void test_rpc_method_lanman(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("LANMAN"),
			KSMBD_RPC_RAP_METHOD);
}

/*
 * test_rpc_method_lanman_lowercase - lanman (lowercase) returns RAP method
 */
static void test_rpc_method_lanman_lowercase(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("lanman"),
			KSMBD_RPC_RAP_METHOD);
}

/*
 * test_rpc_method_samr - \\samr returns SAMR method
 */
static void test_rpc_method_samr(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\samr"),
			KSMBD_RPC_SAMR_METHOD_INVOKE);
}

/*
 * test_rpc_method_samr_no_backslash - samr without backslash
 */
static void test_rpc_method_samr_no_backslash(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("samr"),
			KSMBD_RPC_SAMR_METHOD_INVOKE);
}

/*
 * test_rpc_method_lsarpc - \\lsarpc returns LSARPC method
 */
static void test_rpc_method_lsarpc(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\lsarpc"),
			KSMBD_RPC_LSARPC_METHOD_INVOKE);
}

/*
 * test_rpc_method_lsarpc_no_backslash - lsarpc without backslash
 */
static void test_rpc_method_lsarpc_no_backslash(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("lsarpc"),
			KSMBD_RPC_LSARPC_METHOD_INVOKE);
}

/*
 * test_rpc_method_unsupported - unknown name returns 0
 */
static void test_rpc_method_unsupported(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("unknown"), 0);
	KUNIT_EXPECT_EQ(test, test_rpc_method(""), 0);
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\netlogon"), 0);
}

/*
 * test_rpc_method_case_sensitive - methods are case-sensitive
 * "\\SRVSVC" (uppercase) should NOT match since the code uses strcmp
 */
static void test_rpc_method_case_sensitive(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\SRVSVC"), 0);
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\WKSSVC"), 0);
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\SAMR"), 0);
	KUNIT_EXPECT_EQ(test, test_rpc_method("\\LSARPC"), 0);
}

/*
 * test_rpc_method_constants_are_nonzero - all valid methods are non-zero
 */
static void test_rpc_method_constants_are_nonzero(struct kunit *test)
{
	KUNIT_EXPECT_NE(test, KSMBD_RPC_SRVSVC_METHOD_INVOKE, 0);
	KUNIT_EXPECT_NE(test, KSMBD_RPC_WKSSVC_METHOD_INVOKE, 0);
	KUNIT_EXPECT_NE(test, KSMBD_RPC_RAP_METHOD, 0);
	KUNIT_EXPECT_NE(test, KSMBD_RPC_SAMR_METHOD_INVOKE, 0);
	KUNIT_EXPECT_NE(test, KSMBD_RPC_LSARPC_METHOD_INVOKE, 0);
}

/*
 * test_rpc_method_all_unique - all method constants are distinct
 */
static void test_rpc_method_all_unique(struct kunit *test)
{
	int methods[] = {
		KSMBD_RPC_SRVSVC_METHOD_INVOKE,
		KSMBD_RPC_WKSSVC_METHOD_INVOKE,
		KSMBD_RPC_RAP_METHOD,
		KSMBD_RPC_SAMR_METHOD_INVOKE,
		KSMBD_RPC_LSARPC_METHOD_INVOKE,
	};
	int i, j;

	for (i = 0; i < ARRAY_SIZE(methods); i++) {
		for (j = i + 1; j < ARRAY_SIZE(methods); j++)
			KUNIT_EXPECT_NE(test, methods[i], methods[j]);
	}
}

static struct kunit_case ksmbd_user_session_mgmt_test_cases[] = {
	KUNIT_CASE(test_rpc_method_srvsvc),
	KUNIT_CASE(test_rpc_method_srvsvc_no_backslash),
	KUNIT_CASE(test_rpc_method_wkssvc),
	KUNIT_CASE(test_rpc_method_wkssvc_no_backslash),
	KUNIT_CASE(test_rpc_method_lanman),
	KUNIT_CASE(test_rpc_method_lanman_lowercase),
	KUNIT_CASE(test_rpc_method_samr),
	KUNIT_CASE(test_rpc_method_samr_no_backslash),
	KUNIT_CASE(test_rpc_method_lsarpc),
	KUNIT_CASE(test_rpc_method_lsarpc_no_backslash),
	KUNIT_CASE(test_rpc_method_unsupported),
	KUNIT_CASE(test_rpc_method_case_sensitive),
	KUNIT_CASE(test_rpc_method_constants_are_nonzero),
	KUNIT_CASE(test_rpc_method_all_unique),
	{}
};

static struct kunit_suite ksmbd_user_session_mgmt_test_suite = {
	.name = "ksmbd_user_session_mgmt",
	.test_cases = ksmbd_user_session_mgmt_test_cases,
};

kunit_test_suite(ksmbd_user_session_mgmt_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd user session management helpers");
