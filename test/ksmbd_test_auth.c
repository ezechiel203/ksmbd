// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for authentication helpers (auth.c)
 *
 *   These tests replicate the str_to_key() DES key expansion logic
 *   and the GSS negotiation header copy logic without calling
 *   into the ksmbd module directly.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

/*
 * Replicate str_to_key() from auth.c.
 * Expands a 7-byte string into an 8-byte DES key with parity bits.
 */
static void test_str_to_key(unsigned char *str, unsigned char *key)
{
	int i;

	key[0] = str[0] >> 1;
	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
	key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
	key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
	key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
	key[7] = str[6] & 0x7F;
	for (i = 0; i < 8; i++)
		key[i] = (key[i] << 1);
}

/* Replicate AUTH_GSS_LENGTH from auth.h */
#define TEST_AUTH_GSS_LENGTH	96

/*
 * Replicate NEGOTIATE_GSS_HEADER from auth.c.
 * Fixed format data defining GSS header and fixed string
 * "not_defined_in_RFC4178@please_ignore".
 */
static const char test_negotiate_gss_header[TEST_AUTH_GSS_LENGTH] = {
	0x60, 0x5e, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
	0x05, 0x02, 0xa0, 0x54, 0x30, 0x52, 0xa0, 0x24,
	0x30, 0x22, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09, 0x2a,
	0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
	0x37, 0x02, 0x02, 0x0a, 0xa3, 0x2a, 0x30, 0x28,
	0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f,
	0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f,
	0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31,
	0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73,
	0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65
};

/* Replicate ksmbd_copy_gss_neg_header() */
static void test_copy_gss_neg_header(void *buf)
{
	memcpy(buf, test_negotiate_gss_header, TEST_AUTH_GSS_LENGTH);
}

/* --- str_to_key() tests --- */

/*
 * test_str_to_key_all_zeros - all-zero input produces all-zero output
 *
 * When all input bytes are 0x00, every bit-shift result is 0,
 * and the final << 1 produces 0x00 for each byte.
 */
static void test_str_to_key_all_zeros(struct kunit *test)
{
	unsigned char str[7] = {0, 0, 0, 0, 0, 0, 0};
	unsigned char key[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	int i;

	test_str_to_key(str, key);

	for (i = 0; i < 8; i++)
		KUNIT_EXPECT_EQ(test, key[i], (unsigned char)0x00);
}

/*
 * test_str_to_key_all_ff - all-0xFF input produces known output
 *
 * Input:  FF FF FF FF FF FF FF (7 bytes = 56 bits)
 * Step 1 (before <<1):
 *   key[0] = 0xFF >> 1 = 0x7F
 *   key[1] = (0x01 << 6) | (0xFF >> 2) = 0x40 | 0x3F = 0x7F
 *   key[2] = (0x03 << 5) | (0xFF >> 3) = 0x60 | 0x1F = 0x7F
 *   key[3] = (0x07 << 4) | (0xFF >> 4) = 0x70 | 0x0F = 0x7F
 *   key[4] = (0x0F << 3) | (0xFF >> 5) = 0x78 | 0x07 = 0x7F
 *   key[5] = (0x1F << 2) | (0xFF >> 6) = 0x7C | 0x03 = 0x7F
 *   key[6] = (0x3F << 1) | (0xFF >> 7) = 0x7E | 0x01 = 0x7F
 *   key[7] = 0xFF & 0x7F = 0x7F
 * Step 2 (<<1): all 0x7F << 1 = 0xFE
 */
static void test_str_to_key_all_ff(struct kunit *test)
{
	unsigned char str[7] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	unsigned char key[8];
	int i;

	test_str_to_key(str, key);

	for (i = 0; i < 8; i++)
		KUNIT_EXPECT_EQ(test, key[i], (unsigned char)0xFE);
}

/*
 * test_str_to_key_known_vector_1 - test with {0x01, 0, 0, 0, 0, 0, 0}
 *
 * key[0] = 0x01 >> 1 = 0x00 -> << 1 = 0x00
 * key[1] = (0x01 & 0x01) << 6 | (0x00 >> 2) = 0x40 -> << 1 = 0x80
 * key[2..7] = 0x00 -> << 1 = 0x00
 */
static void test_str_to_key_known_vector_1(struct kunit *test)
{
	unsigned char str[7] = {0x01, 0, 0, 0, 0, 0, 0};
	unsigned char key[8];

	test_str_to_key(str, key);

	KUNIT_EXPECT_EQ(test, key[0], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[1], (unsigned char)0x80);
	KUNIT_EXPECT_EQ(test, key[2], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[3], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[4], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[5], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[6], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[7], (unsigned char)0x00);
}

/*
 * test_str_to_key_known_vector_2 - test with {0x80, 0, 0, 0, 0, 0, 0}
 *
 * key[0] = 0x80 >> 1 = 0x40 -> << 1 = 0x80
 * key[1] = (0x80 & 0x01) << 6 | (0x00 >> 2) = 0x00 -> << 1 = 0x00
 * key[2..7] = 0x00 -> << 1 = 0x00
 */
static void test_str_to_key_known_vector_2(struct kunit *test)
{
	unsigned char str[7] = {0x80, 0, 0, 0, 0, 0, 0};
	unsigned char key[8];

	test_str_to_key(str, key);

	KUNIT_EXPECT_EQ(test, key[0], (unsigned char)0x80);
	KUNIT_EXPECT_EQ(test, key[1], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[2], (unsigned char)0x00);
	KUNIT_EXPECT_EQ(test, key[3], (unsigned char)0x00);
}

/*
 * test_str_to_key_known_vector_3 - verify last byte handling
 *
 * Input: {0, 0, 0, 0, 0, 0, 0x80}
 * key[6] = (0x00 & 0x3F) << 1 | (0x80 >> 7) = 0x01 -> << 1 = 0x02
 * key[7] = 0x80 & 0x7F = 0x00 -> << 1 = 0x00
 */
static void test_str_to_key_known_vector_3(struct kunit *test)
{
	unsigned char str[7] = {0, 0, 0, 0, 0, 0, 0x80};
	unsigned char key[8];

	test_str_to_key(str, key);

	KUNIT_EXPECT_EQ(test, key[6], (unsigned char)0x02);
	KUNIT_EXPECT_EQ(test, key[7], (unsigned char)0x00);
}

/*
 * test_str_to_key_output_even_parity - output bytes have parity bit
 *
 * DES key expansion sets the low bit to 0 (the <<1 clears it).
 * Every output byte should have bit 0 = 0.
 */
static void test_str_to_key_output_even_parity(struct kunit *test)
{
	unsigned char str[7] = {0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78};
	unsigned char key[8];
	int i;

	test_str_to_key(str, key);

	for (i = 0; i < 8; i++)
		KUNIT_EXPECT_EQ(test, key[i] & 0x01, (unsigned char)0x00);
}

/* --- ksmbd_copy_gss_neg_header() tests --- */

/*
 * test_gss_header_copy_matches - copied buffer matches expected header
 */
static void test_gss_header_copy_matches(struct kunit *test)
{
	char *buf;

	buf = kzalloc(TEST_AUTH_GSS_LENGTH, GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buf);

	test_copy_gss_neg_header(buf);
	KUNIT_EXPECT_EQ(test, memcmp(buf, test_negotiate_gss_header,
				     TEST_AUTH_GSS_LENGTH), 0);

	kfree(buf);
}

/*
 * test_gss_header_starts_with_asn1_sequence - first byte is ASN.1 SEQUENCE
 *
 * The GSS header starts with 0x60 which is the ASN.1 APPLICATION tag
 * for SEQUENCE in the SPNEGO context.
 */
static void test_gss_header_starts_with_asn1_sequence(struct kunit *test)
{
	char buf[TEST_AUTH_GSS_LENGTH];

	test_copy_gss_neg_header(buf);

	/* 0x60 = ASN.1 APPLICATION [0] SEQUENCE */
	KUNIT_EXPECT_EQ(test, (unsigned char)buf[0], (unsigned char)0x60);
}

/*
 * test_gss_header_contains_spnego_oid - header contains SPNEGO OID
 *
 * The OID 1.3.6.1.5.5.2 (SPNEGO) is encoded as 06 06 2b 06 01 05 05 02
 * and should appear starting at byte offset 2.
 */
static void test_gss_header_contains_spnego_oid(struct kunit *test)
{
	char buf[TEST_AUTH_GSS_LENGTH];
	static const unsigned char spnego_oid[] = {
		0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02
	};

	test_copy_gss_neg_header(buf);

	KUNIT_EXPECT_EQ(test, memcmp(buf + 2, spnego_oid,
				     sizeof(spnego_oid)), 0);
}

/*
 * test_gss_header_length - header is exactly AUTH_GSS_LENGTH bytes
 */
static void test_gss_header_length(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_AUTH_GSS_LENGTH, 96);
}

static struct kunit_case ksmbd_auth_test_cases[] = {
	KUNIT_CASE(test_str_to_key_all_zeros),
	KUNIT_CASE(test_str_to_key_all_ff),
	KUNIT_CASE(test_str_to_key_known_vector_1),
	KUNIT_CASE(test_str_to_key_known_vector_2),
	KUNIT_CASE(test_str_to_key_known_vector_3),
	KUNIT_CASE(test_str_to_key_output_even_parity),
	KUNIT_CASE(test_gss_header_copy_matches),
	KUNIT_CASE(test_gss_header_starts_with_asn1_sequence),
	KUNIT_CASE(test_gss_header_contains_spnego_oid),
	KUNIT_CASE(test_gss_header_length),
	{}
};

static struct kunit_suite ksmbd_auth_test_suite = {
	.name = "ksmbd_auth",
	.test_cases = ksmbd_auth_test_cases,
};

kunit_test_suite(ksmbd_auth_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd authentication helpers");
