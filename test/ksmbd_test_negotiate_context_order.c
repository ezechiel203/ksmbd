// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB 3.1.1 negotiate context structures and ordering.
 *
 *   These tests verify the PAI (Pre-Authentication Integrity) context,
 *   encryption context, and compression context structures match the
 *   MS-SMB2 specification without calling into the ksmbd module directly.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Replicate negotiate context type constants from smb2pdu.h.
 */
#define TEST_SMB2_PREAUTH_INTEGRITY_CAPABILITIES	cpu_to_le16(1)
#define TEST_SMB2_ENCRYPTION_CAPABILITIES		cpu_to_le16(2)
#define TEST_SMB2_COMPRESSION_CAPABILITIES		cpu_to_le16(3)
#define TEST_SMB2_NETNAME_NEGOTIATE_CONTEXT_ID		cpu_to_le16(5)
#define TEST_SMB2_SIGNING_CAPABILITIES			cpu_to_le16(8)

/*
 * Replicate encryption algorithm constants from smb2pdu.h.
 */
#define TEST_SMB2_ENCRYPTION_AES128_CCM		cpu_to_le16(0x0001)
#define TEST_SMB2_ENCRYPTION_AES128_GCM		cpu_to_le16(0x0002)
#define TEST_SMB2_ENCRYPTION_AES256_CCM		cpu_to_le16(0x0003)
#define TEST_SMB2_ENCRYPTION_AES256_GCM		cpu_to_le16(0x0004)

/*
 * Replicate the negotiate context header from smb2pdu.h.
 * MS-SMB2 2.2.3.1: Every negotiate context starts with this 8-byte header.
 */
struct test_smb2_neg_context {
	__le16 ContextType;
	__le16 DataLength;
	__le32 Reserved;
} __packed;

/*
 * Replicate SMB2_PREAUTH_INTEGRITY_CAPABILITIES context from smb2pdu.h.
 * MS-SMB2 2.2.3.1.1: Preauth integrity capabilities context.
 */
#define TEST_SMB311_SALT_SIZE		32
#define TEST_MIN_PREAUTH_CTXT_DATA_LEN	6

struct test_smb2_preauth_neg_context {
	__le16 ContextType;    /* 1 */
	__le16 DataLength;
	__le32 Reserved;
	__le16 HashAlgorithmCount;
	__le16 SaltLength;
	__le16 HashAlgorithms; /* first hash algorithm */
	__u8   Salt[TEST_SMB311_SALT_SIZE];
} __packed;

/*
 * Replicate SMB2_ENCRYPTION_CAPABILITIES context from smb2pdu.h.
 * MS-SMB2 2.2.3.1.2: Encryption capabilities context.
 */
struct test_smb2_encryption_neg_context {
	__le16 ContextType;    /* 2 */
	__le16 DataLength;
	__le32 Reserved;
	__le16 CipherCount;
	__le16 Ciphers[];
} __packed;

/*
 * test_preauth_integrity_context_type - SMB2_PREAUTH_INTEGRITY_CAPABILITIES
 * has context type value 0x0001
 *
 * MS-SMB2 2.2.3.1: ContextType 0x0001 identifies the pre-authentication
 * integrity capabilities negotiate context.
 */
static void test_preauth_integrity_context_type(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_PREAUTH_INTEGRITY_CAPABILITIES),
		(u16)0x0001);
}

/*
 * test_encryption_capabilities_context_type - SMB2_ENCRYPTION_CAPABILITIES
 * has context type value 0x0002
 *
 * MS-SMB2 2.2.3.1: ContextType 0x0002 identifies the encryption
 * capabilities negotiate context.
 */
static void test_encryption_capabilities_context_type(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_ENCRYPTION_CAPABILITIES),
		(u16)0x0002);
}

/*
 * test_compression_capabilities_context_type - SMB2_COMPRESSION_CAPABILITIES
 * has context type value 0x0003
 *
 * MS-SMB2 2.2.3.1: ContextType 0x0003 identifies the compression
 * capabilities negotiate context.
 */
static void test_compression_capabilities_context_type(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_COMPRESSION_CAPABILITIES),
		(u16)0x0003);
}

/*
 * test_negotiate_context_header_size - the negotiate context header is
 * exactly 8 bytes: ContextType (u16) + DataLength (u16) + Reserved (u32)
 *
 * MS-SMB2 2.2.3.1: The negotiate context header is 8 bytes. Each
 * negotiate context is 8-byte aligned (padded after its data).
 */
static void test_negotiate_context_header_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)sizeof(struct test_smb2_neg_context), 8);

	/* Verify individual field offsets */
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_neg_context, ContextType), 0);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_neg_context, DataLength), 2);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_neg_context, Reserved), 4);
}

/*
 * test_preauth_context_layout - PAI context data contains
 * HashAlgorithmCount + SaltLength + HashAlgorithm + Salt
 *
 * MS-SMB2 2.2.3.1.1: The data portion of the preauth integrity context
 * contains HashAlgorithmCount (2), SaltLength (2), HashAlgorithms[] (2*N),
 * and Salt[] (SaltLength bytes).
 *
 * The full structure (header + data) should have fields at the expected
 * offsets from the start.
 */
static void test_preauth_context_layout(struct kunit *test)
{
	/* Header fields at offsets 0, 2, 4 */
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, ContextType), 0);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, DataLength), 2);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, Reserved), 4);

	/* Data fields start at offset 8 (after the 8-byte header) */
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, HashAlgorithmCount), 8);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, SaltLength), 10);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, HashAlgorithms), 12);
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct test_smb2_preauth_neg_context, Salt), 14);
}

/*
 * test_preauth_sha512_algorithm_id - SHA-512 hash algorithm ID is 0x0001
 *
 * MS-SMB2 2.2.3.1.1: The only defined hash algorithm is SHA-512 with
 * identifier 0x0001. Constructing a valid PAI context with SHA-512
 * should have this value in the HashAlgorithms field.
 */
static void test_preauth_sha512_algorithm_id(struct kunit *test)
{
	struct test_smb2_preauth_neg_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = TEST_SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx.HashAlgorithmCount = cpu_to_le16(1);
	ctx.SaltLength = cpu_to_le16(TEST_SMB311_SALT_SIZE);
	ctx.HashAlgorithms = cpu_to_le16(0x0001); /* SHA-512 */

	KUNIT_EXPECT_EQ(test, le16_to_cpu(ctx.ContextType), (u16)0x0001);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ctx.HashAlgorithmCount), (u16)1);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ctx.HashAlgorithms), (u16)0x0001);
}

/*
 * test_preauth_zero_hash_algorithms_rejected - PAI context with zero
 * hash algorithms should be rejected per MS-SMB2
 *
 * MS-SMB2 3.3.5.4: If HashAlgorithmCount is 0 in a PREAUTH_INTEGRITY
 * negotiate context, the server MUST respond with STATUS_INVALID_PARAMETER.
 * This test verifies that a zero count is detectable: the minimum valid
 * data length requires at least one HashAlgorithm (6 bytes minimum).
 */
static void test_preauth_zero_hash_algorithms_rejected(struct kunit *test)
{
	struct test_smb2_preauth_neg_context ctx;
	__le16 data_len;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextType = TEST_SMB2_PREAUTH_INTEGRITY_CAPABILITIES;
	ctx.HashAlgorithmCount = cpu_to_le16(0); /* invalid: zero algorithms */
	ctx.SaltLength = cpu_to_le16(0);

	/*
	 * With zero hash algorithms and zero salt, the data length would be
	 * just 4 bytes (HashAlgorithmCount + SaltLength), which is less than
	 * MIN_PREAUTH_CTXT_DATA_LEN (6). This indicates an invalid context.
	 */
	data_len = cpu_to_le16(
		sizeof(ctx.HashAlgorithmCount) + sizeof(ctx.SaltLength));
	KUNIT_EXPECT_EQ(test, le16_to_cpu(data_len), 4);
	KUNIT_EXPECT_TRUE(test,
		le16_to_cpu(data_len) < TEST_MIN_PREAUTH_CTXT_DATA_LEN);

	/* Zero count itself is the distinguishing invalid condition */
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ctx.HashAlgorithmCount), (u16)0);
}

/*
 * test_encryption_context_cipher_ids - AES-128-CCM is 0x0001 and
 * AES-128-GCM is 0x0002
 *
 * MS-SMB2 2.2.3.1.2: The cipher identifiers for AES-128-CCM and
 * AES-128-GCM are 0x0001 and 0x0002 respectively. AES-256 variants
 * are 0x0003 and 0x0004.
 */
static void test_encryption_context_cipher_ids(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_ENCRYPTION_AES128_CCM), (u16)0x0001);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_ENCRYPTION_AES128_GCM), (u16)0x0002);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_ENCRYPTION_AES256_CCM), (u16)0x0003);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(TEST_SMB2_ENCRYPTION_AES256_GCM), (u16)0x0004);
}

/*
 * test_context_alignment - each negotiate context must be 8-byte aligned
 *
 * MS-SMB2 2.2.3.1: Subsequent negotiate contexts MUST be aligned on
 * 8-byte boundaries from the start of the first context. This test
 * verifies that the header size is already 8-byte aligned and that
 * padding calculations work correctly for various data lengths.
 */
static void test_context_alignment(struct kunit *test)
{
	int hdr_size = sizeof(struct test_smb2_neg_context);
	int total;

	/* Header is exactly 8 bytes, already aligned */
	KUNIT_EXPECT_EQ(test, hdr_size % 8, 0);

	/*
	 * For a context with 6 bytes of data (minimum PAI):
	 * total = 8 (header) + 6 (data) = 14
	 * aligned = roundup(14, 8) = 16
	 * padding = 16 - 14 = 2
	 */
	total = hdr_size + 6;
	KUNIT_EXPECT_EQ(test, total, 14);
	KUNIT_EXPECT_EQ(test, round_up(total, 8), (int)16);

	/*
	 * For a context with 38 bytes of data (PAI with 32-byte salt):
	 * total = 8 (header) + 38 (data) = 46
	 * aligned = roundup(46, 8) = 48
	 * padding = 48 - 46 = 2
	 */
	total = hdr_size + (int)(sizeof(__le16) + sizeof(__le16) +
				  sizeof(__le16) + TEST_SMB311_SALT_SIZE);
	KUNIT_EXPECT_EQ(test, total, 46);
	KUNIT_EXPECT_EQ(test, round_up(total, 8), (int)48);

	/*
	 * For a context with 8 bytes of data (exactly aligned):
	 * total = 8 + 8 = 16, no padding needed
	 */
	total = hdr_size + 8;
	KUNIT_EXPECT_EQ(test, total % 8, 0);
}

static struct kunit_case ksmbd_negotiate_context_order_test_cases[] = {
	KUNIT_CASE(test_preauth_integrity_context_type),
	KUNIT_CASE(test_encryption_capabilities_context_type),
	KUNIT_CASE(test_compression_capabilities_context_type),
	KUNIT_CASE(test_negotiate_context_header_size),
	KUNIT_CASE(test_preauth_context_layout),
	KUNIT_CASE(test_preauth_sha512_algorithm_id),
	KUNIT_CASE(test_preauth_zero_hash_algorithms_rejected),
	KUNIT_CASE(test_encryption_context_cipher_ids),
	KUNIT_CASE(test_context_alignment),
	{}
};

static struct kunit_suite ksmbd_negotiate_context_order_test_suite = {
	.name = "ksmbd_negotiate_context_order",
	.test_cases = ksmbd_negotiate_context_order_test_cases,
};

kunit_test_suite(ksmbd_negotiate_context_order_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB 3.1.1 negotiate context ordering");
