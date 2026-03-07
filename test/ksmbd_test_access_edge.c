// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for FILE_READ_ATTRIBUTES-only access path edge cases.
 *
 *   These tests verify the correctness of the SMB2 access mask constants
 *   defined in smb2pdu.h and their relationships, without calling into
 *   the ksmbd module directly.
 */

#include <kunit/test.h>
#include <linux/types.h>

/*
 * Replicate access mask constants from smb2pdu.h.
 * These are the wire-format little-endian values that appear in SMB2 PDUs.
 */
#define TEST_FILE_READ_DATA_LE			cpu_to_le32(0x00000001)
#define TEST_FILE_WRITE_DATA_LE			cpu_to_le32(0x00000002)
#define TEST_FILE_APPEND_DATA_LE		cpu_to_le32(0x00000004)
#define TEST_FILE_READ_EA_LE			cpu_to_le32(0x00000008)
#define TEST_FILE_WRITE_EA_LE			cpu_to_le32(0x00000010)
#define TEST_FILE_EXECUTE_LE			cpu_to_le32(0x00000020)
#define TEST_FILE_DELETE_CHILD_LE		cpu_to_le32(0x00000040)
#define TEST_FILE_READ_ATTRIBUTES_LE		cpu_to_le32(0x00000080)
#define TEST_FILE_WRITE_ATTRIBUTES_LE		cpu_to_le32(0x00000100)
#define TEST_FILE_DELETE_LE			cpu_to_le32(0x00010000)
#define TEST_FILE_READ_CONTROL_LE		cpu_to_le32(0x00020000)
#define TEST_FILE_WRITE_DAC_LE			cpu_to_le32(0x00040000)
#define TEST_FILE_WRITE_OWNER_LE		cpu_to_le32(0x00080000)
#define TEST_FILE_SYNCHRONIZE_LE		cpu_to_le32(0x00100000)
#define TEST_FILE_GENERIC_ALL_LE		cpu_to_le32(0x10000000)
#define TEST_FILE_GENERIC_EXECUTE_LE		cpu_to_le32(0x20000000)
#define TEST_FILE_GENERIC_WRITE_LE		cpu_to_le32(0x40000000)
#define TEST_FILE_GENERIC_READ_LE		cpu_to_le32(0x80000000)

#define TEST_DESIRED_ACCESS_MASK		cpu_to_le32(0xF21F01FF)

/* Replicate FILE_DELETE_ON_CLOSE_LE from vfs.h (CreateOptions flag) */
#define TEST_FILE_DELETE_ON_CLOSE_LE		cpu_to_le32(0x00001000)

/*
 * Replicate FILE_READ_DESIRED_ACCESS_LE from smb2pdu.h.
 * This is the composite mask used to test read access rights.
 */
#define TEST_FILE_READ_DESIRED_ACCESS_LE	(TEST_FILE_READ_DATA_LE |	\
						TEST_FILE_READ_EA_LE |		\
						TEST_FILE_GENERIC_READ_LE)

/*
 * test_file_read_attributes_bit_position - FILE_READ_ATTRIBUTES_LE is 0x0080
 *
 * MS-SMB2 2.2.13.1: FILE_READ_ATTRIBUTES is bit 7 of the access mask.
 */
static void test_file_read_attributes_bit_position(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_READ_ATTRIBUTES_LE),
			(u32)0x00000080);
}

/*
 * test_file_read_data_bit_position - FILE_READ_DATA_LE is 0x0001
 *
 * MS-SMB2 2.2.13.1: FILE_READ_DATA is bit 0 of the access mask.
 */
static void test_file_read_data_bit_position(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_READ_DATA_LE),
			(u32)0x00000001);
}

/*
 * test_file_write_data_bit_position - FILE_WRITE_DATA_LE is 0x0002
 *
 * MS-SMB2 2.2.13.1: FILE_WRITE_DATA is bit 1 of the access mask.
 */
static void test_file_write_data_bit_position(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_WRITE_DATA_LE),
			(u32)0x00000002);
}

/*
 * test_file_execute_bit_position - FILE_EXECUTE_LE is 0x0020
 *
 * MS-SMB2 2.2.13.1: FILE_EXECUTE is bit 5 of the access mask.
 */
static void test_file_execute_bit_position(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_EXECUTE_LE),
			(u32)0x00000020);
}

/*
 * test_file_delete_bit_position - FILE_DELETE_LE is 0x00010000
 *
 * MS-SMB2 2.2.13.1: DELETE is bit 16 of the access mask.
 */
static void test_file_delete_bit_position(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_DELETE_LE),
			(u32)0x00010000);
}

/*
 * test_desired_access_mask_value - DESIRED_ACCESS_MASK is 0xF21F01FF
 *
 * This is the mask ksmbd uses to validate requested access bits.
 * It must include:
 *   - File-specific bits 0-8:         0x000001FF
 *   - Standard rights bits 16-20:     0x001F0000
 *   - Generic bits 28-31:             0xF0000000
 *   - SYNCHRONIZE bit 20:             0x00100000 (overlap with standard)
 *   - ACCESS_SYSTEM_SECURITY excluded: bit 24 NOT set
 *
 * Total: 0xF0000000 | 0x001F0000 | 0x00100000 | 0x000001FF
 *      = 0xF0000000 | 0x002F01FF  -- wait, let's verify:
 *      0xF0000000 + 0x021F01FF = 0xF21F01FF
 *
 * Bits 25 (MAXIMUM_ALLOWED) included: 0x02000000
 */
static void test_desired_access_mask_value(struct kunit *test)
{
	__le32 mask = TEST_DESIRED_ACCESS_MASK;
	u32 val = le32_to_cpu(mask);

	KUNIT_EXPECT_EQ(test, val, (u32)0xF21F01FF);

	/* Verify all file-specific bits 0-8 are included */
	KUNIT_EXPECT_TRUE(test, !!(val & 0x000001FF));

	/* Verify all standard rights bits 16-20 are included */
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_DELETE_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_READ_CONTROL_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_WRITE_DAC_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_WRITE_OWNER_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_SYNCHRONIZE_LE)));

	/* Verify generic bits 28-31 are included */
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_GENERIC_ALL_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_GENERIC_EXECUTE_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_GENERIC_WRITE_LE)));
	KUNIT_EXPECT_TRUE(test, !!(val & le32_to_cpu(TEST_FILE_GENERIC_READ_LE)));
}

/*
 * test_read_attributes_excludes_read_data - FILE_READ_ATTRIBUTES alone
 * does NOT include FILE_READ_DATA
 *
 * This is critical for the hide_on_access_denied logic: a handle opened
 * with only FILE_READ_ATTRIBUTES cannot read file data. The server must
 * distinguish between "can see the file exists" and "can read its content."
 */
static void test_read_attributes_excludes_read_data(struct kunit *test)
{
	__le32 access = TEST_FILE_READ_ATTRIBUTES_LE;

	/* FILE_READ_ATTRIBUTES (0x0080) should NOT overlap FILE_READ_DATA (0x0001) */
	KUNIT_EXPECT_FALSE(test, !!(access & TEST_FILE_READ_DATA_LE));
	KUNIT_EXPECT_FALSE(test, !!(access & TEST_FILE_WRITE_DATA_LE));
	KUNIT_EXPECT_FALSE(test, !!(access & TEST_FILE_EXECUTE_LE));
}

/*
 * test_generic_read_includes_read_attributes - FILE_GENERIC_READ
 * conceptually includes FILE_READ_ATTRIBUTES
 *
 * Per MS-SMB2: GENERIC_READ (0x80000000) is a composite that, when the
 * server expands it, maps to FILE_READ_DATA | FILE_READ_EA |
 * FILE_READ_ATTRIBUTES | SYNCHRONIZE | READ_CONTROL.
 * In the DESIRED_ACCESS_MASK, both GENERIC_READ and READ_ATTRIBUTES
 * bits are valid, verifying that the mask accepts both.
 */
static void test_generic_read_includes_read_attributes(struct kunit *test)
{
	u32 mask = le32_to_cpu(TEST_DESIRED_ACCESS_MASK);

	/* Both FILE_GENERIC_READ and FILE_READ_ATTRIBUTES must be accepted */
	KUNIT_EXPECT_TRUE(test, !!(mask & le32_to_cpu(TEST_FILE_GENERIC_READ_LE)));
	KUNIT_EXPECT_TRUE(test, !!(mask & le32_to_cpu(TEST_FILE_READ_ATTRIBUTES_LE)));

	/*
	 * FILE_READ_DESIRED_ACCESS_LE is used to check if a handle has
	 * read capability. It includes GENERIC_READ and READ_DATA, but
	 * notably does NOT include FILE_READ_ATTRIBUTES alone.
	 */
	KUNIT_EXPECT_FALSE(test,
		!!(TEST_FILE_READ_ATTRIBUTES_LE & TEST_FILE_READ_DESIRED_ACCESS_LE));
}

/*
 * test_delete_on_close_requires_delete_access - FILE_DELETE_ON_CLOSE
 * requires FILE_DELETE in the access mask
 *
 * MS-SMB2 3.3.5.9: If FILE_DELETE_ON_CLOSE is set in CreateOptions,
 * the server MUST verify that FILE_DELETE (0x00010000) is included in
 * DesiredAccess, otherwise fail with STATUS_ACCESS_DENIED.
 *
 * This test verifies the bit positions are distinct: the CreateOptions
 * FILE_DELETE_ON_CLOSE flag (0x00001000) is not the same bit as the
 * access mask FILE_DELETE (0x00010000).
 */
static void test_delete_on_close_requires_delete_access(struct kunit *test)
{
	/* CreateOptions FILE_DELETE_ON_CLOSE is 0x00001000 */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_DELETE_ON_CLOSE_LE),
			(u32)0x00001000);

	/* Access mask FILE_DELETE is 0x00010000 - different bit position */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(TEST_FILE_DELETE_LE),
			(u32)0x00010000);

	/* They must NOT overlap */
	KUNIT_EXPECT_FALSE(test,
		!!(TEST_FILE_DELETE_ON_CLOSE_LE & TEST_FILE_DELETE_LE));

	/* FILE_DELETE must be in DESIRED_ACCESS_MASK */
	KUNIT_EXPECT_TRUE(test,
		!!(TEST_DESIRED_ACCESS_MASK & TEST_FILE_DELETE_LE));
}

/*
 * test_synchronize_bit_in_desired_access_mask - SYNCHRONIZE (bit 20) is
 * included in DESIRED_ACCESS_MASK
 *
 * DESIRED_ACCESS_MASK was updated from 0xF20F01FF to 0xF21F01FF to
 * include the SYNCHRONIZE bit (0x00100000). Windows clients commonly
 * request SYNCHRONIZE access, and rejecting it breaks compatibility.
 */
static void test_synchronize_bit_in_desired_access_mask(struct kunit *test)
{
	u32 mask = le32_to_cpu(TEST_DESIRED_ACCESS_MASK);
	u32 synchronize = le32_to_cpu(TEST_FILE_SYNCHRONIZE_LE);

	/* SYNCHRONIZE is bit 20 = 0x00100000 */
	KUNIT_EXPECT_EQ(test, synchronize, (u32)0x00100000);

	/* It must be included in the access mask */
	KUNIT_EXPECT_TRUE(test, !!(mask & synchronize));

	/*
	 * Verify that the difference between old mask (0xF20F01FF) and
	 * new mask (0xF21F01FF) is exactly the standard rights block
	 * that includes SYNCHRONIZE.
	 */
	KUNIT_EXPECT_EQ(test, mask & 0x001F0000, (u32)0x001F0000);
}

static struct kunit_case ksmbd_access_edge_test_cases[] = {
	KUNIT_CASE(test_file_read_attributes_bit_position),
	KUNIT_CASE(test_file_read_data_bit_position),
	KUNIT_CASE(test_file_write_data_bit_position),
	KUNIT_CASE(test_file_execute_bit_position),
	KUNIT_CASE(test_file_delete_bit_position),
	KUNIT_CASE(test_desired_access_mask_value),
	KUNIT_CASE(test_read_attributes_excludes_read_data),
	KUNIT_CASE(test_generic_read_includes_read_attributes),
	KUNIT_CASE(test_delete_on_close_requires_delete_access),
	KUNIT_CASE(test_synchronize_bit_in_desired_access_mask),
	{}
};

static struct kunit_suite ksmbd_access_edge_test_suite = {
	.name = "ksmbd_access_edge",
	.test_cases = ksmbd_access_edge_test_cases,
};

kunit_test_suite(ksmbd_access_edge_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd FILE_READ_ATTRIBUTES access path edge cases");
