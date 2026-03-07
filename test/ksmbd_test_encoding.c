// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for ksmbd encoding functions (unicode.c)
 *
 *   Calls production smb_strtoUTF16(), smbConvertToUTF16(), and
 *   smb_strndup_from_utf16() directly via exported symbols.
 */

#include <kunit/test.h>
#include <linux/nls.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include "unicode.h"

/* Per-test state: NLS codepage handle */
struct encoding_test_ctx {
	struct nls_table *utf8;
};

static int encoding_test_init(struct kunit *test)
{
	struct encoding_test_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->utf8 = load_nls("utf8");
	if (!ctx->utf8)
		ctx->utf8 = load_nls_default();

	KUNIT_ASSERT_NOT_NULL(test, ctx->utf8);

	test->priv = ctx;
	return 0;
}

static void encoding_test_exit(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;

	if (ctx->utf8)
		unload_nls(ctx->utf8);
	kfree(ctx);
}

/* -- smb_strtoUTF16 tests -- */

static void test_strtoUTF16_ascii(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[16];
	int count;

	memset(buf, 0xFF, sizeof(buf));

	count = smb_strtoUTF16(buf, "ABC", 3, ctx->utf8);
	KUNIT_EXPECT_EQ(test, count, 3);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), (int)'A');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[1]), (int)'B');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[2]), (int)'C');
	/* null terminator */
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[3]), 0);
}

static void test_strtoUTF16_empty(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[4];
	int count;

	memset(buf, 0xFF, sizeof(buf));

	count = smb_strtoUTF16(buf, "", 0, ctx->utf8);
	KUNIT_EXPECT_EQ(test, count, 0);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), 0);
}

static void test_strtoUTF16_path(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[32];
	const char *path = "share\\dir\\file";
	int count;

	count = smb_strtoUTF16(buf, path, strlen(path), ctx->utf8);
	KUNIT_EXPECT_EQ(test, count, (int)strlen(path));
	/* Verify backslash is preserved */
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[5]), (int)'\\');
}

static void test_strtoUTF16_single_char(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[4];
	int count;

	count = smb_strtoUTF16(buf, "X", 1, ctx->utf8);
	KUNIT_EXPECT_EQ(test, count, 1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), (int)'X');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[1]), 0);
}

/* -- smbConvertToUTF16 tests (with mapchars=0, delegates to smb_strtoUTF16) -- */

static void test_convertToUTF16_no_mapchars(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[16];
	int count;

	count = smbConvertToUTF16(buf, "test", 4, ctx->utf8, 0);
	KUNIT_EXPECT_EQ(test, count, 4);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), (int)'t');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[1]), (int)'e');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[2]), (int)'s');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[3]), (int)'t');
}

static void test_convertToUTF16_mapchars_colon(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[16];
	int count;

	/* With mapchars=1, colon maps to UNI_COLON (0xF003) */
	count = smbConvertToUTF16(buf, "a:", 2, ctx->utf8, 1);
	KUNIT_EXPECT_EQ(test, count, 2);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), (int)'a');
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[1]), 0xF003); /* UNI_COLON */
}

static void test_convertToUTF16_mapchars_asterisk(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[16];
	int count;

	count = smbConvertToUTF16(buf, "*", 1, ctx->utf8, 1);
	KUNIT_EXPECT_EQ(test, count, 1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), 0xF002); /* UNI_ASTERISK */
}

static void test_convertToUTF16_mapchars_question(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[16];
	int count;

	count = smbConvertToUTF16(buf, "?", 1, ctx->utf8, 1);
	KUNIT_EXPECT_EQ(test, count, 1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), 0xF004); /* UNI_QUESTION */
}

static void test_convertToUTF16_mapchars_pipe(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 buf[16];
	int count;

	count = smbConvertToUTF16(buf, "|", 1, ctx->utf8, 1);
	KUNIT_EXPECT_EQ(test, count, 1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(buf[0]), 0xF007); /* UNI_PIPE */
}

/* -- smb_strndup_from_utf16 tests -- */

static void test_strndup_ascii(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	/* "Hi" in UTF-16LE */
	__le16 src[] = { cpu_to_le16('H'), cpu_to_le16('i'), cpu_to_le16(0) };
	char *dst;

	dst = smb_strndup_from_utf16((const char *)src, 4, true, ctx->utf8);
	KUNIT_ASSERT_FALSE(test, IS_ERR(dst));
	KUNIT_EXPECT_STREQ(test, dst, "Hi");
	kfree(dst);
}

static void test_strndup_non_unicode(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	const char src[] = "hello";
	char *dst;

	dst = smb_strndup_from_utf16(src, 5, false, ctx->utf8);
	KUNIT_ASSERT_FALSE(test, IS_ERR(dst));
	KUNIT_EXPECT_STREQ(test, dst, "hello");
	kfree(dst);
}

static void test_strndup_empty_unicode(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 src[] = { cpu_to_le16(0) };
	char *dst;

	dst = smb_strndup_from_utf16((const char *)src, 2, true, ctx->utf8);
	KUNIT_ASSERT_FALSE(test, IS_ERR(dst));
	KUNIT_EXPECT_STREQ(test, dst, "");
	kfree(dst);
}

static void test_strndup_single_char(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	__le16 src[] = { cpu_to_le16('Z'), cpu_to_le16(0) };
	char *dst;

	dst = smb_strndup_from_utf16((const char *)src, 2, true, ctx->utf8);
	KUNIT_ASSERT_FALSE(test, IS_ERR(dst));
	KUNIT_EXPECT_STREQ(test, dst, "Z");
	kfree(dst);
}

/* -- Roundtrip test: UTF-8 -> UTF-16 -> UTF-8 -- */

static void test_roundtrip_ascii(struct kunit *test)
{
	struct encoding_test_ctx *ctx = test->priv;
	const char *original = "TestFile.txt";
	__le16 utf16_buf[32];
	char *result;
	int u16_count;

	u16_count = smb_strtoUTF16(utf16_buf, original, strlen(original),
				    ctx->utf8);
	KUNIT_ASSERT_GT(test, u16_count, 0);

	result = smb_strndup_from_utf16((const char *)utf16_buf,
					u16_count * 2, true, ctx->utf8);
	KUNIT_ASSERT_FALSE(test, IS_ERR(result));
	KUNIT_EXPECT_STREQ(test, result, original);
	kfree(result);
}

static struct kunit_case ksmbd_encoding_cases[] = {
	KUNIT_CASE(test_strtoUTF16_ascii),
	KUNIT_CASE(test_strtoUTF16_empty),
	KUNIT_CASE(test_strtoUTF16_path),
	KUNIT_CASE(test_strtoUTF16_single_char),
	KUNIT_CASE(test_convertToUTF16_no_mapchars),
	KUNIT_CASE(test_convertToUTF16_mapchars_colon),
	KUNIT_CASE(test_convertToUTF16_mapchars_asterisk),
	KUNIT_CASE(test_convertToUTF16_mapchars_question),
	KUNIT_CASE(test_convertToUTF16_mapchars_pipe),
	KUNIT_CASE(test_strndup_ascii),
	KUNIT_CASE(test_strndup_non_unicode),
	KUNIT_CASE(test_strndup_empty_unicode),
	KUNIT_CASE(test_strndup_single_char),
	KUNIT_CASE(test_roundtrip_ascii),
	{}
};

static struct kunit_suite ksmbd_encoding_suite = {
	.name = "ksmbd_encoding",
	.init = encoding_test_init,
	.exit = encoding_test_exit,
	.test_cases = ksmbd_encoding_cases,
};

kunit_test_suite(ksmbd_encoding_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd Unicode encoding functions (calls production code)");
