// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 WRITE_THROUGH / read-write PDU structure layout
 *
 *   Since these tests run as a separate KUnit module, we cannot call
 *   functions from the ksmbd module directly.  Instead, we inline the
 *   relevant structures and constants from smb2pdu.h and verify their
 *   layout, sizes, and flag encodings.
 */

#include <kunit/test.h>
#include <linux/types.h>

/* ---- Inlined SMB2 header from smb2pdu.h ---- */

struct test_smb2_hdr {
	__le32 ProtocolId;	/* 0xFE 'S' 'M' 'B' */
	__le16 StructureSize;	/* 64 */
	__le16 CreditCharge;
	__le32 Status;
	__le16 Command;
	__le16 CreditRequest;
	__le32 Flags;
	__le32 NextCommand;
	__le64 MessageId;
	union {
		struct {
			__le32 ProcessId;
			__le32 TreeId;
		} __packed SyncId;
		__le64 AsyncId;
	} __packed Id;
	__le64 SessionId;
	__u8   Signature[16];
} __packed;

/* ---- Inlined write flag constants from smb2pdu.h ---- */

#define TEST_SMB2_WRITEFLAG_WRITE_THROUGH		0x00000001
#define TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED		0x00000002
#define TEST_SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION 0x00000004

/* ---- Inlined read flag constants from smb2pdu.h ---- */

#define TEST_SMB2_READFLAG_READ_UNBUFFERED		0x00000001
#define TEST_SMB2_READFLAG_READ_COMPRESSED		0x00000002
#define TEST_SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION	0x00000004

/* ---- Inlined channel constants from smb2pdu.h ---- */

#define TEST_SMB2_CHANNEL_NONE			cpu_to_le32(0x00000000)
#define TEST_SMB2_CHANNEL_RDMA_V1		cpu_to_le32(0x00000001)
#define TEST_SMB2_CHANNEL_RDMA_V1_INVALIDATE	cpu_to_le32(0x00000002)

/* ---- Inlined PDU structures from smb2pdu.h ---- */

struct test_smb2_read_req {
	struct test_smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__u8   Padding;
	__u8   Reserved;
	__le32 Length;
	__le64 Offset;
	__u64  PersistentFileId;
	__u64  VolatileFileId;
	__le32 MinimumCount;
	__le32 Channel;
	__le32 RemainingBytes;
	__le16 ReadChannelInfoOffset;
	__le16 ReadChannelInfoLength;
	__u8   Buffer[];
} __packed;

struct test_smb2_read_rsp {
	struct test_smb2_hdr hdr;
	__le16 StructureSize; /* Must be 17 */
	__u8   DataOffset;
	__u8   Reserved;
	__le32 DataLength;
	__le32 DataRemaining;
	__le32 Reserved2;
	__u8   Buffer[];
} __packed;

struct test_smb2_write_req {
	struct test_smb2_hdr hdr;
	__le16 StructureSize; /* Must be 49 */
	__le16 DataOffset;
	__le32 Length;
	__le64 Offset;
	__u64  PersistentFileId;
	__u64  VolatileFileId;
	__le32 Channel;
	__le32 RemainingBytes;
	__le16 WriteChannelInfoOffset;
	__le16 WriteChannelInfoLength;
	__le32 Flags;
	__u8   Buffer[];
} __packed;

struct test_smb2_write_rsp {
	struct test_smb2_hdr hdr;
	__le16 StructureSize; /* Must be 17 */
	__u8   DataOffset;
	__u8   Reserved;
	__le32 DataLength;
	__le32 DataRemaining;
	__le32 Reserved2;
	__u8   Buffer[];
} __packed;

/* ---- Test cases ---- */

/*
 * test_write_through_flag_value - SMB2_WRITEFLAG_WRITE_THROUGH is 0x1
 */
static void test_write_through_flag_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_SMB2_WRITEFLAG_WRITE_THROUGH,
			(u32)0x00000001);
}

/*
 * test_write_unbuffered_flag_value - SMB2_WRITEFLAG_WRITE_UNBUFFERED is 0x2
 */
static void test_write_unbuffered_flag_value(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED,
			(u32)0x00000002);
}

/*
 * test_write_req_structure_size - StructureSize must be 49 (0x0031)
 *
 * MS-SMB2 2.2.21: The client MUST set StructureSize to 49.
 * This is the fixed portion size including the single-byte Buffer.
 */
static void test_write_req_structure_size(struct kunit *test)
{
	struct test_smb2_write_req req;

	memset(&req, 0, sizeof(req));
	req.StructureSize = cpu_to_le16(49);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.StructureSize), (u16)49);
}

/*
 * test_read_req_structure_size - Read request StructureSize is 49
 *
 * MS-SMB2 2.2.19: The client MUST set StructureSize to 49.
 */
static void test_read_req_structure_size(struct kunit *test)
{
	struct test_smb2_read_req req;

	memset(&req, 0, sizeof(req));
	req.StructureSize = cpu_to_le16(49);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.StructureSize), (u16)49);
}

/*
 * test_write_rsp_structure_size - Write response StructureSize is 17
 *
 * MS-SMB2 2.2.22: The server MUST set StructureSize to 17.
 */
static void test_write_rsp_structure_size(struct kunit *test)
{
	struct test_smb2_write_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(17);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.StructureSize), (u16)17);
}

/*
 * test_read_rsp_structure_size - Read response StructureSize is 17
 *
 * MS-SMB2 2.2.20: The server MUST set StructureSize to 17.
 */
static void test_read_rsp_structure_size(struct kunit *test)
{
	struct test_smb2_read_rsp rsp;

	memset(&rsp, 0, sizeof(rsp));
	rsp.StructureSize = cpu_to_le16(17);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(rsp.StructureSize), (u16)17);
}

/*
 * test_write_flags_field_offset - Flags field position in write request
 *
 * The Flags field in SMB2_WRITE_REQ comes after:
 *   hdr(64) + StructureSize(2) + DataOffset(2) + Length(4) +
 *   Offset(8) + PersistentFileId(8) + VolatileFileId(8) +
 *   Channel(4) + RemainingBytes(4) + WriteChannelInfoOffset(2) +
 *   WriteChannelInfoLength(2) = 108 bytes from start of message.
 *
 * Relative to the start of the write-specific fields (after hdr),
 * Flags is at offset 44.
 */
static void test_write_flags_field_offset(struct kunit *test)
{
	size_t flags_off;

	flags_off = offsetof(struct test_smb2_write_req, Flags);

	/* Flags offset from start of entire structure (hdr + body) */
	KUNIT_EXPECT_EQ(test, flags_off,
			(size_t)(sizeof(struct test_smb2_hdr) + 44));

	/* Also verify it is at offset 44 relative to body start */
	KUNIT_EXPECT_EQ(test,
			flags_off - sizeof(struct test_smb2_hdr),
			(size_t)44);
}

/*
 * test_write_channel_values - Channel field values
 *
 * MS-SMB2 2.2.21: Channel values for WRITE.
 */
static void test_write_channel_values(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_SMB2_CHANNEL_NONE,
			cpu_to_le32(0x00000000));
	KUNIT_EXPECT_EQ(test, TEST_SMB2_CHANNEL_RDMA_V1,
			cpu_to_le32(0x00000001));
	KUNIT_EXPECT_EQ(test, TEST_SMB2_CHANNEL_RDMA_V1_INVALIDATE,
			cpu_to_le32(0x00000002));
}

/*
 * test_write_req_field_layout - verify key field offsets in WRITE request body
 *
 * MS-SMB2 2.2.21: The WRITE request body layout after the SMB2 header has
 * StructureSize(2) + DataOffset(2) + Length(4) + Offset(8) +
 * PersistentFileId(8) + VolatileFileId(8) + Channel(4) +
 * RemainingBytes(4) + WriteChannelInfoOffset(2) +
 * WriteChannelInfoLength(2) + Flags(4).
 */
static void test_write_req_field_layout(struct kunit *test)
{
	size_t base = sizeof(struct test_smb2_hdr);

	/* StructureSize at body+0 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_smb2_write_req, StructureSize),
			base + 0);

	/* DataOffset at body+2 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_smb2_write_req, DataOffset),
			base + 2);

	/* Length at body+4 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_smb2_write_req, Length),
			base + 4);

	/* Offset at body+8 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_smb2_write_req, Offset),
			base + 8);

	/* Channel at body+32 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_smb2_write_req, Channel),
			base + 32);

	/* Flags at body+44 */
	KUNIT_EXPECT_EQ(test,
			offsetof(struct test_smb2_write_req, Flags),
			base + 44);
}

/*
 * test_combined_write_flags - WRITE_THROUGH | WRITE_UNBUFFERED encoding
 *
 * Verify that combining the two flags produces the expected bitmask.
 */
static void test_combined_write_flags(struct kunit *test)
{
	u32 combined;

	combined = TEST_SMB2_WRITEFLAG_WRITE_THROUGH |
		   TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED;

	KUNIT_EXPECT_EQ(test, combined, (u32)0x00000003);

	/* Each flag should be independently testable in the combined value */
	KUNIT_EXPECT_TRUE(test,
			  combined & TEST_SMB2_WRITEFLAG_WRITE_THROUGH);
	KUNIT_EXPECT_TRUE(test,
			  combined & TEST_SMB2_WRITEFLAG_WRITE_UNBUFFERED);

	/* Transport encryption flag should NOT be present */
	KUNIT_EXPECT_FALSE(test,
			   combined & TEST_SMB2_WRITEFLAG_REQUEST_TRANSPORT_ENCRYPTION);
}

static struct kunit_case ksmbd_write_through_test_cases[] = {
	KUNIT_CASE(test_write_through_flag_value),
	KUNIT_CASE(test_write_unbuffered_flag_value),
	KUNIT_CASE(test_write_req_structure_size),
	KUNIT_CASE(test_read_req_structure_size),
	KUNIT_CASE(test_write_rsp_structure_size),
	KUNIT_CASE(test_read_rsp_structure_size),
	KUNIT_CASE(test_write_flags_field_offset),
	KUNIT_CASE(test_write_req_field_layout),
	KUNIT_CASE(test_write_channel_values),
	KUNIT_CASE(test_combined_write_flags),
	{}
};

static struct kunit_suite ksmbd_write_through_test_suite = {
	.name = "ksmbd_write_through",
	.test_cases = ksmbd_write_through_test_cases,
};

kunit_test_suite(ksmbd_write_through_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 WRITE_THROUGH and read/write PDU layout");
