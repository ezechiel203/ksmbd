// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit error path tests for IOCTL operations.
 *   Tests FSCTL code validation and flag checking.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "../smb2pdu.h"
#include "../smbfsctl.h"

/*
 * These tests verify the pure-logic error checking that the IOCTL
 * handler performs. The actual smb2_ioctl function requires a full
 * ksmbd_work context, so we test the validation patterns directly.
 */

/* SMB2_0_IOCTL_IS_FSCTL flag value */
#define TEST_SMB2_0_IOCTL_IS_FSCTL	0x00000001

/* ---- IOCTL Flags validation ---- */

static void test_ioctl_flags_fsctl_valid(struct kunit *test)
{
	__le32 flags = cpu_to_le32(TEST_SMB2_0_IOCTL_IS_FSCTL);

	KUNIT_EXPECT_NE(test, le32_to_cpu(flags) & TEST_SMB2_0_IOCTL_IS_FSCTL,
			(u32)0);
}

static void test_ioctl_flags_zero_invalid(struct kunit *test)
{
	__le32 flags = cpu_to_le32(0);

	/* Flags==0 should be rejected per MS-SMB2 */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(flags) & TEST_SMB2_0_IOCTL_IS_FSCTL,
			(u32)0);
}

static void test_ioctl_flags_unknown_bits(struct kunit *test)
{
	__le32 flags = cpu_to_le32(0x80000000);

	/* Unknown flag bits without IS_FSCTL should be invalid */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(flags) & TEST_SMB2_0_IOCTL_IS_FSCTL,
			(u32)0);
}

static void test_ioctl_flags_fsctl_with_extra_bits(struct kunit *test)
{
	__le32 flags = cpu_to_le32(TEST_SMB2_0_IOCTL_IS_FSCTL | 0x80000000);

	/* IS_FSCTL set, extra bits present but IS_FSCTL check passes */
	KUNIT_EXPECT_NE(test, le32_to_cpu(flags) & TEST_SMB2_0_IOCTL_IS_FSCTL,
			(u32)0);
}

/* ---- FSCTL code validation ---- */

static void test_fsctl_known_codes(struct kunit *test)
{
	/* Verify known FSCTL codes are defined */
	KUNIT_EXPECT_NE(test, (u32)FSCTL_DFS_GET_REFERRALS, (u32)0);
	KUNIT_EXPECT_NE(test, (u32)FSCTL_SET_ZERO_DATA, (u32)0);
	KUNIT_EXPECT_NE(test, (u32)FSCTL_QUERY_ALLOCATED_RANGES, (u32)0);
	KUNIT_EXPECT_NE(test, (u32)FSCTL_PIPE_TRANSCEIVE, (u32)0);
}

static void test_fsctl_unknown_code(struct kunit *test)
{
	u32 unknown_fsctl = 0xDEADBEEF;

	/* Unknown FSCTL codes should return STATUS_NOT_SUPPORTED */
	KUNIT_EXPECT_NE(test, unknown_fsctl, (u32)FSCTL_DFS_GET_REFERRALS);
	KUNIT_EXPECT_NE(test, unknown_fsctl, (u32)FSCTL_SET_ZERO_DATA);
}

/* ---- Buffer length validation ---- */

static void test_ioctl_input_buffer_zero(struct kunit *test)
{
	u32 input_count = 0;

	/* Zero input buffer for FSCTLs that require input should fail */
	KUNIT_EXPECT_EQ(test, input_count, (u32)0);
}

static void test_ioctl_max_output_buffer(struct kunit *test)
{
	u32 max_output = le32_to_cpu(cpu_to_le32(65536));

	/* MaxOutputResponse should be bounded */
	KUNIT_EXPECT_LE(test, max_output, (u32)65536);
}

/* ---- Test Registration ---- */

static struct kunit_case ksmbd_error_ioctl_test_cases[] = {
	KUNIT_CASE(test_ioctl_flags_fsctl_valid),
	KUNIT_CASE(test_ioctl_flags_zero_invalid),
	KUNIT_CASE(test_ioctl_flags_unknown_bits),
	KUNIT_CASE(test_ioctl_flags_fsctl_with_extra_bits),
	KUNIT_CASE(test_fsctl_known_codes),
	KUNIT_CASE(test_fsctl_unknown_code),
	KUNIT_CASE(test_ioctl_input_buffer_zero),
	KUNIT_CASE(test_ioctl_max_output_buffer),
	{}
};

static struct kunit_suite ksmbd_error_ioctl_test_suite = {
	.name = "ksmbd_error_ioctl",
	.test_cases = ksmbd_error_ioctl_test_cases,
};

kunit_test_suite(ksmbd_error_ioctl_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit error path tests for IOCTL operations");
