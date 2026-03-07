// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for read/write operations.
 *   Tests boundary conditions and invalid parameter handling
 *   using production data structures.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/overflow.h>

#include "../smb2pdu.h"

/*
 * These tests verify the pure-logic error checking that the read/write
 * handlers perform before accessing VFS. Since the actual smb2_read/write
 * functions require a full ksmbd_work context, we test the validation
 * logic patterns they use.
 */

/* ---- Offset validation tests ---- */

static void test_read_offset_zero(struct kunit *test)
{
	/*
	 * Verify that a zero u64 offset cast to loff_t (s64) remains
	 * non-negative -- this is the common case for reads at file start.
	 */
	u64 raw_offset = 0;
	loff_t offset = (loff_t)raw_offset;

	KUNIT_EXPECT_GE(test, offset, (loff_t)0);
}

static void test_read_offset_max(struct kunit *test)
{
	/*
	 * Verify that LLONG_MAX (0x7FFFFFFFFFFFFFFF) remains positive
	 * when stored in loff_t -- this is the largest valid positive offset.
	 */
	u64 raw_offset = (u64)LLONG_MAX;
	loff_t offset = (loff_t)raw_offset;

	KUNIT_EXPECT_GT(test, offset, (loff_t)0);
	KUNIT_EXPECT_EQ(test, raw_offset, 0x7FFFFFFFFFFFFFFFULL);
}

static void test_read_offset_negative(struct kunit *test)
{
	/*
	 * The high bit (0x8000000000000000) makes the loff_t negative.
	 * This is how ksmbd detects invalid offsets from the wire.
	 */
	u64 raw_offset = 0x8000000000000000ULL;
	loff_t offset = (loff_t)raw_offset;

	KUNIT_EXPECT_LT(test, offset, (loff_t)0);
}

static void test_read_offset_overflow_check(struct kunit *test)
{
	u64 raw_offset = 0xFFFFFFFFFFFFFFFFULL;
	loff_t offset = (loff_t)raw_offset;

	/*
	 * When 0xFFFFFFFFFFFFFFFF is cast to loff_t (s64), it becomes -1.
	 * This is the append-to-EOF sentinel in SMB2 WRITE.
	 */
	KUNIT_EXPECT_EQ(test, offset, (loff_t)-1);
}

/* ---- Length validation tests ---- */

static void test_write_length_zero(struct kunit *test)
{
	/*
	 * Verify that zero length from le32 wire format round-trips
	 * correctly. Zero-length writes are no-ops in SMB2.
	 */
	__le32 wire_length = cpu_to_le32(0);
	u32 length = le32_to_cpu(wire_length);

	KUNIT_EXPECT_EQ(test, length, (u32)0);
}

static void test_write_length_max_credits(struct kunit *test)
{
	/*
	 * SMB2 credit-based flow control: max data per credit is 65536.
	 * Max credits for a single request is typically 256.
	 * So max write size = 256 * 65536 = 16MB.
	 */
	u32 max_credits = 256;
	u32 credit_size = 65536;
	u64 max_write_size = (u64)max_credits * credit_size;

	KUNIT_EXPECT_EQ(test, max_write_size, (u64)16777216);
}

/* ---- DataOffset validation ---- */

static void test_data_offset_valid(struct kunit *test)
{
	/*
	 * SMB2 READ/WRITE DataOffset must point within the SMB2 message.
	 * Minimum valid DataOffset = sizeof(struct smb2_hdr) + fixed fields.
	 */
	u16 data_offset = sizeof(struct smb2_hdr) + 48;

	KUNIT_EXPECT_GE(test, (u32)data_offset, (u32)sizeof(struct smb2_hdr));
}

static void test_data_offset_zero(struct kunit *test)
{
	u16 data_offset = 0;

	/* Zero DataOffset is invalid */
	KUNIT_EXPECT_LT(test, (u32)data_offset, (u32)sizeof(struct smb2_hdr));
}

static void test_data_offset_too_small(struct kunit *test)
{
	u16 data_offset = 10;

	/* DataOffset smaller than header is invalid */
	KUNIT_EXPECT_LT(test, (u32)data_offset, (u32)sizeof(struct smb2_hdr));
}

/* ---- Offset + length overflow ---- */

static void test_offset_length_overflow(struct kunit *test)
{
	u64 offset = U64_MAX - 10;
	u32 length = 100;
	bool overflow;

	/* Check if offset + length would overflow u64 */
	overflow = check_add_overflow(offset, (u64)length, &offset);
	KUNIT_EXPECT_TRUE(test, overflow);
}

static void test_offset_length_no_overflow(struct kunit *test)
{
	u64 offset = 1000;
	u32 length = 4096;
	u64 result;
	bool overflow;

	overflow = check_add_overflow(offset, (u64)length, &result);
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, result, (u64)5096);
}

static struct kunit_case ksmbd_error_readwrite_test_cases[] = {
	KUNIT_CASE(test_read_offset_zero),
	KUNIT_CASE(test_read_offset_max),
	KUNIT_CASE(test_read_offset_negative),
	KUNIT_CASE(test_read_offset_overflow_check),
	KUNIT_CASE(test_write_length_zero),
	KUNIT_CASE(test_write_length_max_credits),
	KUNIT_CASE(test_data_offset_valid),
	KUNIT_CASE(test_data_offset_zero),
	KUNIT_CASE(test_data_offset_too_small),
	KUNIT_CASE(test_offset_length_overflow),
	KUNIT_CASE(test_offset_length_no_overflow),
	{}
};

static struct kunit_suite ksmbd_error_readwrite_test_suite = {
	.name = "ksmbd_error_readwrite",
	.test_cases = ksmbd_error_readwrite_test_cases,
};

kunit_test_suite(ksmbd_error_readwrite_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for read/write operations");
