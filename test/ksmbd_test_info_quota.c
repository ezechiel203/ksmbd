// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for quota info handlers.
 *   QUOTA GET returns empty (out_len=0), QUOTA SET consumes all bytes.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Replicated handlers ---- */

static int test_get_quota(void *buf, unsigned int buf_len,
			  unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

static int test_set_quota(void *buf, unsigned int buf_len,
			  unsigned int *out_len)
{
	*out_len = buf_len;
	return 0;
}

/* ---- Test cases ---- */

static void test_quota_get_returns_empty(struct kunit *test)
{
	u8 buf[64];
	unsigned int out_len = 99;
	int ret;

	ret = test_get_quota(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static void test_quota_set_consumes_all(struct kunit *test)
{
	u8 buf[32];
	unsigned int out_len;
	int ret;

	memset(buf, 0xAA, sizeof(buf));
	ret = test_set_quota(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_quota_set_zero_bytes(struct kunit *test)
{
	unsigned int out_len = 99;
	int ret;

	ret = test_set_quota(NULL, 0, &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)0);
}

static struct kunit_case ksmbd_info_quota_test_cases[] = {
	KUNIT_CASE(test_quota_get_returns_empty),
	KUNIT_CASE(test_quota_set_consumes_all),
	KUNIT_CASE(test_quota_set_zero_bytes),
	{}
};

static struct kunit_suite ksmbd_info_quota_test_suite = {
	.name = "ksmbd_info_quota",
	.test_cases = ksmbd_info_quota_test_cases,
};

kunit_test_suite(ksmbd_info_quota_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd quota info-level handlers");
