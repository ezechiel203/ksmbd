// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for ksmbd Unicode helper functions (unicode.c)
 *
 *   Since KUnit tests cannot link against the ksmbd module directly,
 *   we replicate the pure-logic portions (is_char_allowed, byte
 *   counting, UTF-16LE encoding basics) inline.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

/* ── Replicated logic from unicode.c ─── */

/**
 * test_is_char_allowed() - Replicate is_char_allowed() from unicode.c
 *
 * Return: 1 if char is allowed in filenames, 0 otherwise.
 * Disallows control chars (0x00-0x1F) and ?, ", <, >, |
 * when high bit is not set.
 */
static inline int test_is_char_allowed(char *ch)
{
	if (!(*ch & 0x80) &&
	    (*ch <= 0x1f ||
	     *ch == '?' || *ch == '"' || *ch == '<' ||
	     *ch == '>' || *ch == '|'))
		return 0;

	return 1;
}

/**
 * test_smb1_utf16_name_length() - Replicate smb1_utf16_name_length()
 *
 * Counts bytes in a UTF-16LE string up to (and including) the null
 * terminator, not exceeding maxbytes.
 */
static int test_smb1_utf16_name_length(const __le16 *from, int maxbytes)
{
	int i, len = 0;
	int maxwords = maxbytes / 2;
	__u16 ftmp;

	for (i = 0; i < maxwords; i++) {
		ftmp = le16_to_cpu(from[i]);
		len += 2;
		if (ftmp == 0)
			break;
	}

	return len;
}

/**
 * test_smb_utf16_bytes_simple() - Simplified byte counter for ASCII
 *
 * For pure ASCII content in UTF-16LE, each non-null code unit maps to
 * exactly 1 byte in the destination charset.  This simplified version
 * avoids the nls_table dependency of the real smb_utf16_bytes().
 */
static int test_smb_utf16_bytes_simple(const __le16 *from, int maxbytes)
{
	int i;
	int outlen = 0;
	int maxwords = maxbytes / 2;
	__u16 ftmp;

	for (i = 0; i < maxwords; i++) {
		ftmp = le16_to_cpu(from[i]);
		if (ftmp == 0)
			break;
		outlen++;
	}

	return outlen;
}

/* ── is_char_allowed() tests ─── */

static void test_is_char_allowed_alpha(struct kunit *test)
{
	char c;

	c = 'A';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = 'z';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = 'M';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
}

static void test_is_char_allowed_digit(struct kunit *test)
{
	char c;

	c = '0';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '9';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
}

static void test_is_char_allowed_space_and_dot(struct kunit *test)
{
	char c;

	c = ' ';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '.';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '-';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '_';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
}

static void test_is_char_allowed_control_chars(struct kunit *test)
{
	char c;

	/* NUL */
	c = '\0';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
	/* SOH */
	c = '\x01';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
	/* BEL */
	c = '\x07';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
	/* US (0x1F) - last control char */
	c = '\x1f';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
}

static void test_is_char_allowed_wildcards(struct kunit *test)
{
	char c;

	c = '?';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
}

static void test_is_char_allowed_special_banned(struct kunit *test)
{
	char c;

	c = '"';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
	c = '<';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
	c = '>';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
	c = '|';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 0);
}

static void test_is_char_allowed_high_bit_set(struct kunit *test)
{
	char c;

	/* Characters with high bit set are always allowed (non-ASCII) */
	c = (char)0x80;
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = (char)0xFF;
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = (char)0xC0;
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
}

static void test_is_char_allowed_printable_special(struct kunit *test)
{
	char c;

	/* These printable special chars should be allowed */
	c = '!';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '#';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '$';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '&';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
	c = '~';
	KUNIT_EXPECT_EQ(test, test_is_char_allowed(&c), 1);
}

/* ── smb1_utf16_name_length() tests ─── */

static void test_utf16_name_length_ascii(struct kunit *test)
{
	/* "ABC" in UTF-16LE: 0x41 0x42 0x43 0x00 */
	__le16 str[] = {
		cpu_to_le16('A'), cpu_to_le16('B'),
		cpu_to_le16('C'), cpu_to_le16(0)
	};
	int len;

	/* 4 code units * 2 bytes = 8 bytes max */
	len = test_smb1_utf16_name_length(str, 8);
	/* Should count all 4 words (A, B, C, NUL) = 8 bytes */
	KUNIT_EXPECT_EQ(test, len, 8);
}

static void test_utf16_name_length_empty(struct kunit *test)
{
	/* Just a null terminator */
	__le16 str[] = { cpu_to_le16(0) };
	int len;

	len = test_smb1_utf16_name_length(str, 2);
	/* Just the null = 2 bytes */
	KUNIT_EXPECT_EQ(test, len, 2);
}

static void test_utf16_name_length_maxbytes_boundary(struct kunit *test)
{
	/* "HELLO" in UTF-16LE without NUL */
	__le16 str[] = {
		cpu_to_le16('H'), cpu_to_le16('E'),
		cpu_to_le16('L'), cpu_to_le16('L'),
		cpu_to_le16('O'),
	};
	int len;

	/*
	 * maxbytes = 6 means maxwords = 3, so only first 3 chars
	 * are scanned (H, E, L) = 6 bytes
	 */
	len = test_smb1_utf16_name_length(str, 6);
	KUNIT_EXPECT_EQ(test, len, 6);
}

static void test_utf16_name_length_single_char(struct kunit *test)
{
	__le16 str[] = { cpu_to_le16('X'), cpu_to_le16(0) };
	int len;

	len = test_smb1_utf16_name_length(str, 4);
	KUNIT_EXPECT_EQ(test, len, 4);
}

/* ── smb_utf16_bytes (simplified) tests ─── */

static void test_utf16_bytes_ascii(struct kunit *test)
{
	/* "test" in UTF-16LE */
	__le16 str[] = {
		cpu_to_le16('t'), cpu_to_le16('e'),
		cpu_to_le16('s'), cpu_to_le16('t'),
		cpu_to_le16(0)
	};
	int bytes;

	/* maxbytes = 10 (5 code units * 2) */
	bytes = test_smb_utf16_bytes_simple(str, 10);
	/* 4 ASCII chars = 4 bytes in destination */
	KUNIT_EXPECT_EQ(test, bytes, 4);
}

static void test_utf16_bytes_empty(struct kunit *test)
{
	__le16 str[] = { cpu_to_le16(0) };
	int bytes;

	bytes = test_smb_utf16_bytes_simple(str, 2);
	KUNIT_EXPECT_EQ(test, bytes, 0);
}

static void test_utf16_bytes_bmp_chars(struct kunit *test)
{
	/*
	 * BMP characters (e.g., U+00E9 = e-acute).
	 * For pure ASCII counting, each non-null unit counts as 1.
	 * This tests the counting mechanism rather than codepage conversion.
	 */
	__le16 str[] = {
		cpu_to_le16(0x00E9), /* e-acute */
		cpu_to_le16(0x00F1), /* n-tilde */
		cpu_to_le16(0)
	};
	int bytes;

	bytes = test_smb_utf16_bytes_simple(str, 6);
	/* 2 BMP chars counted as 2 units */
	KUNIT_EXPECT_EQ(test, bytes, 2);
}

/* ── UTF-16LE encoding basics ─── */

static void test_utf16le_encoding_ascii(struct kunit *test)
{
	/*
	 * Verify that cpu_to_le16 of an ASCII char produces
	 * the expected UTF-16LE encoding.
	 */
	__le16 encoded = cpu_to_le16('A');
	u8 *bytes = (u8 *)&encoded;

	/* 'A' = 0x41 -> LE: 0x41, 0x00 */
	KUNIT_EXPECT_EQ(test, bytes[0], 0x41);
	KUNIT_EXPECT_EQ(test, bytes[1], 0x00);
}

static void test_utf16le_encoding_backslash(struct kunit *test)
{
	__le16 encoded = cpu_to_le16('\\');
	u8 *bytes = (u8 *)&encoded;

	/* '\\' = 0x5C -> LE: 0x5C, 0x00 */
	KUNIT_EXPECT_EQ(test, bytes[0], 0x5C);
	KUNIT_EXPECT_EQ(test, bytes[1], 0x00);
}

static void test_utf16le_null_terminator(struct kunit *test)
{
	__le16 null_term = cpu_to_le16(0);
	u8 *bytes = (u8 *)&null_term;

	KUNIT_EXPECT_EQ(test, bytes[0], 0x00);
	KUNIT_EXPECT_EQ(test, bytes[1], 0x00);
}

static void test_utf16le_null_position_in_string(struct kunit *test)
{
	/*
	 * Verify null terminator is at the expected position
	 * for a 3-char string.
	 */
	__le16 str[4];

	str[0] = cpu_to_le16('H');
	str[1] = cpu_to_le16('i');
	str[2] = cpu_to_le16('!');
	str[3] = cpu_to_le16(0);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(str[3]), 0);
	/* Total size = 4 code units * 2 = 8 bytes */
	KUNIT_EXPECT_EQ(test, (int)sizeof(str), 8);
}

static struct kunit_case ksmbd_unicode_test_cases[] = {
	KUNIT_CASE(test_is_char_allowed_alpha),
	KUNIT_CASE(test_is_char_allowed_digit),
	KUNIT_CASE(test_is_char_allowed_space_and_dot),
	KUNIT_CASE(test_is_char_allowed_control_chars),
	KUNIT_CASE(test_is_char_allowed_wildcards),
	KUNIT_CASE(test_is_char_allowed_special_banned),
	KUNIT_CASE(test_is_char_allowed_high_bit_set),
	KUNIT_CASE(test_is_char_allowed_printable_special),
	KUNIT_CASE(test_utf16_name_length_ascii),
	KUNIT_CASE(test_utf16_name_length_empty),
	KUNIT_CASE(test_utf16_name_length_maxbytes_boundary),
	KUNIT_CASE(test_utf16_name_length_single_char),
	KUNIT_CASE(test_utf16_bytes_ascii),
	KUNIT_CASE(test_utf16_bytes_empty),
	KUNIT_CASE(test_utf16_bytes_bmp_chars),
	KUNIT_CASE(test_utf16le_encoding_ascii),
	KUNIT_CASE(test_utf16le_encoding_backslash),
	KUNIT_CASE(test_utf16le_null_terminator),
	KUNIT_CASE(test_utf16le_null_position_in_string),
	{}
};

static struct kunit_suite ksmbd_unicode_test_suite = {
	.name = "ksmbd_unicode",
	.test_cases = ksmbd_unicode_test_cases,
};

kunit_test_suite(ksmbd_unicode_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd Unicode helper functions");
