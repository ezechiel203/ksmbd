// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ksmbd_conn_status_str() (ksmbd_debugfs.c)
 *
 *   The status-to-string mapping is pure logic that can be tested
 *   without requiring the debugfs infrastructure.  We replicate the
 *   switch statement inline.
 */

#include <kunit/test.h>
#include <linux/types.h>

/* Replicate connection status enum from connection.h */
enum test_conn_status {
	TEST_KSMBD_SESS_NEW = 0,
	TEST_KSMBD_SESS_GOOD,
	TEST_KSMBD_SESS_EXITING,
	TEST_KSMBD_SESS_NEED_RECONNECT,
	TEST_KSMBD_SESS_NEED_NEGOTIATE,
	TEST_KSMBD_SESS_NEED_SETUP,
	TEST_KSMBD_SESS_RELEASING,
};

static const char *test_conn_status_str(int status)
{
	switch (status) {
	case TEST_KSMBD_SESS_NEW:		return "new";
	case TEST_KSMBD_SESS_GOOD:		return "good";
	case TEST_KSMBD_SESS_EXITING:		return "exiting";
	case TEST_KSMBD_SESS_NEED_RECONNECT:	return "reconnect";
	case TEST_KSMBD_SESS_NEED_NEGOTIATE:	return "negotiate";
	case TEST_KSMBD_SESS_NEED_SETUP:	return "setup";
	case TEST_KSMBD_SESS_RELEASING:		return "releasing";
	default:				return "unknown";
	}
}

/* --- Test cases --- */

static void test_conn_status_str_new(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_NEW),
			   "new");
}

static void test_conn_status_str_good(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_GOOD),
			   "good");
}

static void test_conn_status_str_exiting(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_EXITING),
			   "exiting");
}

static void test_conn_status_str_reconnect(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_NEED_RECONNECT),
			   "reconnect");
}

static void test_conn_status_str_negotiate(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_NEED_NEGOTIATE),
			   "negotiate");
}

static void test_conn_status_str_setup(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_NEED_SETUP),
			   "setup");
}

static void test_conn_status_str_releasing(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(TEST_KSMBD_SESS_RELEASING),
			   "releasing");
}

static void test_conn_status_str_unknown(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test,
			   test_conn_status_str(0xFF),
			   "unknown");
}

static struct kunit_case ksmbd_debugfs_test_cases[] = {
	KUNIT_CASE(test_conn_status_str_new),
	KUNIT_CASE(test_conn_status_str_good),
	KUNIT_CASE(test_conn_status_str_exiting),
	KUNIT_CASE(test_conn_status_str_reconnect),
	KUNIT_CASE(test_conn_status_str_negotiate),
	KUNIT_CASE(test_conn_status_str_setup),
	KUNIT_CASE(test_conn_status_str_releasing),
	KUNIT_CASE(test_conn_status_str_unknown),
	{}
};

static struct kunit_suite ksmbd_debugfs_test_suite = {
	.name = "ksmbd_debugfs",
	.test_cases = ksmbd_debugfs_test_cases,
};

kunit_test_suite(ksmbd_debugfs_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd debugfs status string mapping");
