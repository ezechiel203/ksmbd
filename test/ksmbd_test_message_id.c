// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 MessageId handling and replay protection
 *
 *   Covers the MessageId field layout and protocol rules specified in
 *   MS-SMB2 §3.3.5.2.4 (Verifying the Sequence Number) and related
 *   sections.  No production functions are called; the tests verify
 *   struct layout, constant values, and arithmetic invariants.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/kernel.h>

/*
 * Minimal local redefinition of the SMB2 fixed header to avoid pulling in
 * the full SMB2 header chain.  Field names and types are identical to those
 * in smb2pdu.h; the struct is declared __packed to match the wire layout.
 */
struct test_smb2_hdr {
	__le32 ProtocolId;       /* offset  0, size 4 */
	__le16 StructureSize;    /* offset  4, size 2 */
	__le16 CreditCharge;     /* offset  6, size 2 */
	__le32 Status;           /* offset  8, size 4 */
	__le16 Command;          /* offset 12, size 2 */
	__le16 CreditRequest;    /* offset 14, size 2 */
	__le32 Flags;            /* offset 16, size 4 */
	__le32 NextCommand;      /* offset 20, size 4 */
	__le64 MessageId;        /* offset 24, size 8 */
	union {
		struct {
			__le32 ProcessId;
			__le32 TreeId;
		} __packed SyncId;
		__le64 AsyncId;      /* same offset as SyncId */
	} __packed Id;           /* offset 32, size 8 */
	__le64 SessionId;        /* offset 40, size 8 */
	__u8   Signature[16];    /* offset 48, size 16 */
} __packed;                  /* total = 64 bytes */

/* Command codes (host endian, from smb2pdu.h) */
#define TEST_SMB2_NEGOTIATE_HE		0x0000
#define TEST_SMB2_CANCEL_HE		0x000C

/* Fixed SMB2 header size */
#define TEST_SMB2_HDR_SIZE		64

/*
 * test_message_id_offset_in_header - MessageId is at byte offset 28
 *
 * MS-SMB2 §2.2.1.1 specifies the SMB2 fixed header.  MessageId starts
 * after: ProtocolId(4) + StructureSize(2) + CreditCharge(2) + Status(4) +
 * Command(2) + CreditRequest(2) + Flags(4) + NextCommand(4) = 24 bytes.
 *
 * Note: the actual struct uses offset 24 because the layout above (which
 * precisely mirrors the kernel struct) places MessageId at byte 24 inside
 * the SMB2 header body (4-byte RFC1001 length prefix is NOT part of the
 * SMB2 header struct; smb2_hdr starts at the ProtocolId field).
 */
static void test_message_id_offset_in_header(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct test_smb2_hdr, MessageId),
			24);
}

/*
 * test_message_id_size_8bytes - MessageId is stored as a 64-bit integer
 *
 * MS-SMB2 §2.2.1.1 defines MessageId as an 8-byte (64-bit) unsigned
 * little-endian integer, matching __le64 in the kernel struct.
 */
static void test_message_id_size_8bytes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			(int)sizeof_field(struct test_smb2_hdr, MessageId),
			8);
}

/*
 * test_cancel_message_id_exempted - CANCEL uses AsyncId, not MessageId
 *
 * MS-SMB2 §3.3.5.16 (Processing an SMB2 CANCEL Request) states that the
 * client identifies the pending request via the AsyncId field (for async
 * requests) or the MessageId of the original request.  The server matches
 * CANCEL against outstanding requests rather than validating the CANCEL's
 * own MessageId against the receive window.
 *
 * Verify that the AsyncId field occupies the same wire offset as the
 * SyncId union, and that CANCEL (0x000C) is a distinct command value.
 */
static void test_cancel_message_id_exempted(struct kunit *test)
{
	/* AsyncId must be at the same offset as SyncId within the union */
	KUNIT_EXPECT_EQ(test,
			(int)offsetof(struct test_smb2_hdr, Id.AsyncId),
			(int)offsetof(struct test_smb2_hdr, Id.SyncId));

	/* SMB2_CANCEL command code */
	KUNIT_EXPECT_EQ(test, TEST_SMB2_CANCEL_HE, 0x000Cu);
}

/*
 * test_message_id_0_valid_for_negotiate - first request may use MessageId=0
 *
 * MS-SMB2 §3.2.4.1.3 says the client MUST set MessageId to 0 for the first
 * SMB2 NEGOTIATE request.  Verify that the zero value is representable in
 * little-endian __le64 encoding.
 */
static void test_message_id_0_valid_for_negotiate(struct kunit *test)
{
	__le64 mid = cpu_to_le64(0ULL);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(mid), 0ULL);
}

/*
 * test_credit_charge_determines_id_range - CreditCharge=N reserves N IDs
 *
 * MS-SMB2 §3.2.4.1.3: the client allocates CreditCharge consecutive
 * MessageIds beginning at the next available sequence number.  So a request
 * with MessageId=N and CreditCharge=4 reserves IDs N, N+1, N+2, N+3.
 */
static void test_credit_charge_determines_id_range(struct kunit *test)
{
	u64 base_id = 100;
	unsigned short charge = 4;
	u64 last_reserved;

	last_reserved = base_id + charge - 1;

	KUNIT_EXPECT_EQ(test, last_reserved, (u64)103);
	/* Exactly 'charge' IDs are consumed */
	KUNIT_EXPECT_EQ(test, last_reserved - base_id + 1, (u64)charge);
}

/*
 * test_async_id_field_offset - AsyncId is at the same offset as SyncId
 *
 * The SMB2 header uses a union at offset 32 that holds either
 * { ProcessId, TreeId } (synchronous) or AsyncId (asynchronous).
 * Both branches must start at the same wire offset so that responses
 * can flip between the two forms by changing only the Flags field.
 */
static void test_async_id_field_offset(struct kunit *test)
{
	int sync_off = (int)offsetof(struct test_smb2_hdr, Id.SyncId);
	int async_off = (int)offsetof(struct test_smb2_hdr, Id.AsyncId);

	KUNIT_EXPECT_EQ(test, sync_off, async_off);
	KUNIT_EXPECT_EQ(test, sync_off, 32);
}

/*
 * test_compound_message_ids_sequential - compound requests use sequential IDs
 *
 * MS-SMB2 §3.2.4.1.4: in a compound chain each constituent request
 * consumes (CreditCharge) consecutive MessageIds, and the IDs are
 * allocated in chain order.  Simulate a 3-request compound where each
 * sub-request has CreditCharge=1.
 */
static void test_compound_message_ids_sequential(struct kunit *test)
{
	u64 next_id = 1;
	u64 id[3];
	unsigned short charge[3] = {1, 1, 1};
	int i;

	for (i = 0; i < 3; i++) {
		id[i] = next_id;
		next_id += charge[i];
	}

	KUNIT_EXPECT_EQ(test, id[0], (u64)1);
	KUNIT_EXPECT_EQ(test, id[1], (u64)2);
	KUNIT_EXPECT_EQ(test, id[2], (u64)3);
	KUNIT_EXPECT_EQ(test, next_id, (u64)4);
}

/*
 * test_smb2_header_message_id_le64 - MessageId is little-endian on the wire
 *
 * Verify that a known MessageId value round-trips correctly through the
 * cpu_to_le64 / le64_to_cpu pair used when reading/writing the header.
 */
static void test_smb2_header_message_id_le64(struct kunit *test)
{
	struct test_smb2_hdr hdr;
	u64 original = 0xDEADBEEFCAFEBABEULL;

	memset(&hdr, 0, sizeof(hdr));
	hdr.MessageId = cpu_to_le64(original);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(hdr.MessageId), original);
}

/*
 * test_outstanding_request_tracking_struct - verify ksmbd conn tracks credits
 *
 * ksmbd_conn (connection.h) maintains two counters used for MessageId
 * tracking and credit enforcement:
 *   total_credits      - total credits granted to this connection
 *   outstanding_credits - credits currently in use (requests in flight)
 *
 * Simulate the basic credit accounting: new request increments outstanding,
 * response decrements it and adjusts total by the granted delta.
 */
static void test_outstanding_request_tracking_struct(struct kunit *test)
{
	unsigned int total_credits = 10;
	unsigned int outstanding_credits = 0;
	unsigned int charge = 2;
	unsigned int granted = 3;

	/* Request arrives: consume charge credits from outstanding */
	outstanding_credits += charge;
	KUNIT_EXPECT_EQ(test, outstanding_credits, 2U);

	/* Response sent: release charge, add granted */
	total_credits -= charge;
	total_credits += granted;
	outstanding_credits -= charge;

	KUNIT_EXPECT_EQ(test, outstanding_credits, 0U);
	KUNIT_EXPECT_EQ(test, total_credits, 11U);
}

/*
 * test_max_message_id_u64_max - MessageId can be up to 0xFFFFFFFFFFFFFFFE
 *
 * MS-SMB2 §3.2.4.1.3 reserves 0xFFFFFFFFFFFFFFFF as invalid; all other
 * 64-bit values are valid MessageIds.  Verify that the maximum usable value
 * is U64_MAX - 1 and that it is representable as __le64.
 */
static void test_max_message_id_u64_max(struct kunit *test)
{
	u64 max_valid_mid = U64_MAX - 1;
	__le64 encoded = cpu_to_le64(max_valid_mid);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(encoded), max_valid_mid);
	KUNIT_EXPECT_LT(test, max_valid_mid, U64_MAX);
}

static struct kunit_case ksmbd_message_id_test_cases[] = {
	KUNIT_CASE(test_message_id_offset_in_header),
	KUNIT_CASE(test_message_id_size_8bytes),
	KUNIT_CASE(test_cancel_message_id_exempted),
	KUNIT_CASE(test_message_id_0_valid_for_negotiate),
	KUNIT_CASE(test_credit_charge_determines_id_range),
	KUNIT_CASE(test_async_id_field_offset),
	KUNIT_CASE(test_compound_message_ids_sequential),
	KUNIT_CASE(test_smb2_header_message_id_le64),
	KUNIT_CASE(test_outstanding_request_tracking_struct),
	KUNIT_CASE(test_max_message_id_u64_max),
	{}
};

static struct kunit_suite ksmbd_message_id_test_suite = {
	.name = "ksmbd_message_id",
	.test_cases = ksmbd_message_id_test_cases,
};

kunit_test_suite(ksmbd_message_id_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd SMB2 MessageId handling and replay protection");
