// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for SMB1 NT_TRANSACT quota wire format structures
 *
 *   Tests the wire format structures used by NT_TRANSACT_GET_USER_QUOTA
 *   (subcommand 0x07) and NT_TRANSACT_SET_USER_QUOTA (subcommand 0x08)
 *   as defined in smb1pdu.c: smb1_query_quota_info,
 *   smb1_file_get_quota_info, and smb1_file_quota_info.
 *
 *   These structures must match the MS-SMB / MS-FSCC wire format exactly.
 */

#include <kunit/test.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>

#include "smb_common.h"
#include "smb1pdu.h"
#include "smbacl.h"

/*
 * Wire format structures — must match the production definitions in
 * smb1pdu.c exactly.  We redefine them here because they are local
 * to smb1pdu.c and not exported via a header.
 */
struct smb1_query_quota_info {
	__u8	ReturnSingle;
	__u8	RestartScan;
	__le16	Reserved;
	__le32	SidListLength;
	__le32	StartSidLength;
	__le32	StartSidOffset;
} __packed;

struct smb1_file_get_quota_info {
	__le32	NextEntryOffset;
	__le32	SidLength;
	__u8	Sid[];
} __packed;

struct smb1_file_quota_info {
	__le32	NextEntryOffset;
	__le32	SidLength;
	__le64	ChangeTime;
	__le64	QuotaUsed;
	__le64	QuotaThreshold;
	__le64	QuotaLimit;
	__u8	Sid[];
} __packed;

/* --- Test: struct sizes match MS-SMB / MS-FSCC wire format --- */

static void test_smb1_query_quota_info_size(struct kunit *test)
{
	/*
	 * smb1_query_quota_info: ReturnSingle(1) + RestartScan(1) +
	 * Reserved(2) + SidListLength(4) + StartSidLength(4) +
	 * StartSidOffset(4) = 16 bytes.
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct smb1_query_quota_info), 16);
}

static void test_smb1_file_quota_info_size(struct kunit *test)
{
	/*
	 * smb1_file_quota_info fixed part: NextEntryOffset(4) +
	 * SidLength(4) + ChangeTime(8) + QuotaUsed(8) +
	 * QuotaThreshold(8) + QuotaLimit(8) = 40 bytes.
	 * The Sid[] flexible array member is not included in sizeof.
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct smb1_file_quota_info), 40);
}

static void test_smb1_file_get_quota_info_size(struct kunit *test)
{
	/*
	 * smb1_file_get_quota_info fixed part: NextEntryOffset(4) +
	 * SidLength(4) = 8 bytes.
	 * The Sid[] flexible array member is not included in sizeof.
	 */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct smb1_file_get_quota_info), 8);
}

/* --- Test: SID list traversal via NextEntryOffset chain --- */

static void test_smb1_quota_sid_list_parsing(struct kunit *test)
{
	/*
	 * Build a buffer with two smb1_file_get_quota_info entries
	 * chained via NextEntryOffset.  Verify traversal.
	 *
	 * Entry 0: NextEntryOffset = 16 (8 fixed + 8 SID bytes)
	 *          SidLength = 8
	 * Entry 1: NextEntryOffset = 0  (last entry)
	 *          SidLength = 12
	 */
	char buf[64];
	struct smb1_file_get_quota_info *entry0, *entry1;
	u32 offset;

	memset(buf, 0, sizeof(buf));

	entry0 = (struct smb1_file_get_quota_info *)buf;
	entry0->NextEntryOffset = cpu_to_le32(16);
	entry0->SidLength = cpu_to_le32(8);

	entry1 = (struct smb1_file_get_quota_info *)(buf + 16);
	entry1->NextEntryOffset = cpu_to_le32(0);
	entry1->SidLength = cpu_to_le32(12);

	/* Traverse the chain */
	offset = 0;
	entry0 = (struct smb1_file_get_quota_info *)(buf + offset);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(entry0->SidLength), 8u);

	offset += le32_to_cpu(entry0->NextEntryOffset);
	KUNIT_EXPECT_EQ(test, offset, 16u);

	entry1 = (struct smb1_file_get_quota_info *)(buf + offset);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(entry1->SidLength), 12u);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(entry1->NextEntryOffset), 0u);
}

/* --- Test: NextEntryOffset=0 terminates the list --- */

static void test_smb1_quota_sid_list_zero_offset_terminates(struct kunit *test)
{
	/*
	 * A single-entry SID list has NextEntryOffset=0, meaning
	 * there are no more entries.  The traversal loop should stop.
	 */
	struct smb1_file_get_quota_info entry;
	int count = 0;
	u32 next;

	memset(&entry, 0, sizeof(entry));
	entry.NextEntryOffset = cpu_to_le32(0);
	entry.SidLength = cpu_to_le32(4);

	/* Simulate traversal: process entry, then check NextEntryOffset */
	next = le32_to_cpu(entry.NextEntryOffset);
	count++;

	KUNIT_EXPECT_EQ(test, next, 0u);
	KUNIT_EXPECT_EQ(test, count, 1);
}

/* --- Test: le64 encoding of QuotaThreshold and QuotaLimit --- */

static void test_smb1_quota_info_endianness(struct kunit *test)
{
	struct smb1_file_quota_info *qi;
	char buf[sizeof(struct smb1_file_quota_info) + 16];

	memset(buf, 0, sizeof(buf));
	qi = (struct smb1_file_quota_info *)buf;

	qi->QuotaThreshold = cpu_to_le64(0x0000000100000000ULL); /* 4 GiB */
	qi->QuotaLimit = cpu_to_le64(0x0000001000000000ULL);     /* 64 GiB */
	qi->QuotaUsed = cpu_to_le64(0x0000000040000000ULL);      /* 1 GiB */
	qi->ChangeTime = cpu_to_le64(132456789012345678ULL);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(qi->QuotaThreshold),
			0x0000000100000000ULL);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(qi->QuotaLimit),
			0x0000001000000000ULL);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(qi->QuotaUsed),
			0x0000000040000000ULL);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(qi->ChangeTime),
			132456789012345678ULL);
}

/* --- Test: ReturnSingle=1 means only first entry returned --- */

static void test_smb1_query_quota_return_single(struct kunit *test)
{
	struct smb1_query_quota_info qqi;

	memset(&qqi, 0, sizeof(qqi));
	qqi.ReturnSingle = 1;

	/*
	 * When ReturnSingle=1, the server should return at most one
	 * FILE_QUOTA_INFORMATION entry.  Verify the field encoding.
	 */
	KUNIT_EXPECT_EQ(test, qqi.ReturnSingle, (u8)1);

	/* Verify the complementary case */
	qqi.ReturnSingle = 0;
	KUNIT_EXPECT_EQ(test, qqi.ReturnSingle, (u8)0);
}

/* --- Test: RestartScan=1 means start from beginning --- */

static void test_smb1_query_quota_restart_scan(struct kunit *test)
{
	struct smb1_query_quota_info qqi;

	memset(&qqi, 0, sizeof(qqi));
	qqi.RestartScan = 1;

	/*
	 * When RestartScan=1, the server restarts enumeration from
	 * the first user.  When 0, it continues from where it left off.
	 */
	KUNIT_EXPECT_EQ(test, qqi.RestartScan, (u8)1);

	/* Verify both flags can be set independently */
	qqi.ReturnSingle = 1;
	KUNIT_EXPECT_EQ(test, qqi.ReturnSingle, (u8)1);
	KUNIT_EXPECT_EQ(test, qqi.RestartScan, (u8)1);
}

/* --- Test: NT_TRANSACT function code values --- */

static void test_smb1_nt_transact_function_codes(struct kunit *test)
{
	/*
	 * MS-SMB 2.2.7.2: NT_TRANSACT subcommand codes.
	 * NT_TRANSACT_GET_USER_QUOTA = 0x0007
	 * NT_TRANSACT_SET_USER_QUOTA = 0x0008
	 */
	KUNIT_EXPECT_EQ(test, (int)NT_TRANSACT_GET_USER_QUOTA, 7);
	KUNIT_EXPECT_EQ(test, (int)NT_TRANSACT_SET_USER_QUOTA, 8);
}

static struct kunit_case ksmbd_smb1_quota_test_cases[] = {
	KUNIT_CASE(test_smb1_query_quota_info_size),
	KUNIT_CASE(test_smb1_file_quota_info_size),
	KUNIT_CASE(test_smb1_file_get_quota_info_size),
	KUNIT_CASE(test_smb1_quota_sid_list_parsing),
	KUNIT_CASE(test_smb1_quota_sid_list_zero_offset_terminates),
	KUNIT_CASE(test_smb1_quota_info_endianness),
	KUNIT_CASE(test_smb1_query_quota_return_single),
	KUNIT_CASE(test_smb1_query_quota_restart_scan),
	KUNIT_CASE(test_smb1_nt_transact_function_codes),
	{}
};

static struct kunit_suite ksmbd_smb1_quota_test_suite = {
	.name = "ksmbd_smb1_quota",
	.test_cases = ksmbd_smb1_quota_test_cases,
};

kunit_test_suite(ksmbd_smb1_quota_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB1 quota wire format structures");
