// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for file info SET handlers:
 *   PIPE_INFO SET, PIPE_REMOTE SET, MAILSLOT SET, noop consumers
 *   (MOVE_CLUSTER, TRACKING, SHORT_NAME, SFIO_RESERVE, SFIO_VOLUME).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ---- Replicated structures ---- */

struct test_pipe_info {
	__le32 ReadMode;
	__le32 CompletionMode;
} __packed;

struct test_pipe_remote_info {
	__le64 CollectDataTime;
	__le32 MaximumCollectionCount;
	__le32 CollectDataTimeout;
} __packed;

struct test_mailslot_set_info {
	__le64 ReadTimeout;
} __packed;

/* ---- Replicated handlers ---- */

static int test_set_pipe_info(void *buf, unsigned int buf_len,
			      unsigned int *out_len)
{
	if (buf_len < sizeof(struct test_pipe_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct test_pipe_info);
	return 0;
}

static int test_set_pipe_remote(void *buf, unsigned int buf_len,
				unsigned int *out_len)
{
	if (buf_len < sizeof(struct test_pipe_remote_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct test_pipe_remote_info);
	return 0;
}

static int test_set_mailslot(void *buf, unsigned int buf_len,
			     unsigned int *out_len)
{
	if (buf_len < sizeof(struct test_mailslot_set_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct test_mailslot_set_info);
	return 0;
}

static int test_set_noop_consume(void *buf, unsigned int buf_len,
				 unsigned int *out_len)
{
	*out_len = buf_len;
	return 0;
}

/* ---- Test cases: PIPE_INFO SET ---- */

static void test_pipe_info_set_normal(struct kunit *test)
{
	struct test_pipe_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_pipe_info(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_pipe_info_set_buffer_too_small(struct kunit *test)
{
	struct test_pipe_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_pipe_info(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

/* ---- Test cases: PIPE_REMOTE SET ---- */

static void test_pipe_remote_set_normal(struct kunit *test)
{
	struct test_pipe_remote_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_pipe_remote(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_pipe_remote_set_buffer_too_small(struct kunit *test)
{
	struct test_pipe_remote_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_pipe_remote(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

/* ---- Test cases: MAILSLOT SET ---- */

static void test_mailslot_set_normal(struct kunit *test)
{
	struct test_mailslot_set_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_mailslot(&buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_mailslot_set_buffer_too_small(struct kunit *test)
{
	struct test_mailslot_set_info buf = {};
	unsigned int out_len;
	int ret;

	ret = test_set_mailslot(&buf, sizeof(buf) - 1, &out_len);
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
}

/* ---- Test cases: NOOP consumers ---- */

static void test_move_cluster_set_consumes_all(struct kunit *test)
{
	u8 buf[32];
	unsigned int out_len;
	int ret;

	memset(buf, 0xAA, sizeof(buf));
	ret = test_set_noop_consume(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_tracking_set_consumes_all(struct kunit *test)
{
	u8 buf[16];
	unsigned int out_len;
	int ret;

	ret = test_set_noop_consume(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_short_name_set_consumes_all(struct kunit *test)
{
	u8 buf[24];
	unsigned int out_len;
	int ret;

	ret = test_set_noop_consume(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_sfio_reserve_set_consumes_all(struct kunit *test)
{
	u8 buf[8];
	unsigned int out_len;
	int ret;

	ret = test_set_noop_consume(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static void test_sfio_volume_set_consumes_all(struct kunit *test)
{
	u8 buf[4];
	unsigned int out_len;
	int ret;

	ret = test_set_noop_consume(buf, sizeof(buf), &out_len);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, out_len, (unsigned int)sizeof(buf));
}

static struct kunit_case ksmbd_info_file_set_test_cases[] = {
	KUNIT_CASE(test_pipe_info_set_normal),
	KUNIT_CASE(test_pipe_info_set_buffer_too_small),
	KUNIT_CASE(test_pipe_remote_set_normal),
	KUNIT_CASE(test_pipe_remote_set_buffer_too_small),
	KUNIT_CASE(test_mailslot_set_normal),
	KUNIT_CASE(test_mailslot_set_buffer_too_small),
	KUNIT_CASE(test_move_cluster_set_consumes_all),
	KUNIT_CASE(test_tracking_set_consumes_all),
	KUNIT_CASE(test_short_name_set_consumes_all),
	KUNIT_CASE(test_sfio_reserve_set_consumes_all),
	KUNIT_CASE(test_sfio_volume_set_consumes_all),
	{}
};

static struct kunit_suite ksmbd_info_file_set_test_suite = {
	.name = "ksmbd_info_file_set",
	.test_cases = ksmbd_info_file_set_test_cases,
};

kunit_test_suite(ksmbd_info_file_set_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd file info SET handlers");
