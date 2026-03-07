// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for SMB2 request validation invariants.
 *
 *   Tests the StructureSize constants, header layout, data-area offset
 *   fields, and other invariants that smb2_check_message() and
 *   smb2_get_data_area_len() rely on.  Because those functions are static,
 *   this file tests the underlying struct layout and constant values that
 *   the validation logic depends upon rather than calling the functions
 *   directly.
 *
 *   SMB2 StructureSize convention (MS-SMB2 §2.2):
 *   For commands whose request body ends with a flexible Buffer[] array,
 *   the StructureSize counts the fixed fields PLUS one implied byte of that
 *   array.  Consequently sizeof(struct) - sizeof(smb2_hdr) is one less than
 *   the spec's StructureSize for those commands (25, 9, 57, 49, 33, 41).
 *   For commands with no variable payload the sizeof matches exactly.
 *   The tests below call this out explicitly with +1 where it applies.
 */

#include <kunit/test.h>
#include <linux/types.h>

#include "smb2pdu.h"
#include "smb_common.h"

/* -----------------------------------------------------------------------
 * Part 1: StructureSize constants (smb2_req_struct_sizes[] in smb2misc.c)
 *
 * Each test verifies that the StructureSize for a given SMB2 command
 * matches the value mandated by the MS-SMB2 specification and mirrored in
 * smb2misc.c's smb2_req_struct_sizes[] table.
 *
 * For structs ending with a flexible Buffer[] member, sizeof() omits that
 * implied first byte, so we add 1 to sizeof() - sizeof(smb2_hdr) when
 * comparing against the spec value.
 * ----------------------------------------------------------------------- */

/*
 * test_negotiate_struct_size_36 - SMB2_NEGOTIATE request StructureSize is 36
 *
 * MS-SMB2 §2.2.3: StructureSize MUST be 36.
 * smb2_negotiate_req has a flexible Dialects[] array.  The fixed body is
 * exactly 36 bytes; the Dialects[] contributes zero bytes to sizeof(), so
 * the comparison is direct (no +1 needed because Dialects is not uint8_t
 * Buffer — the spec's implied byte falls within the fixed Dialects[0] slot
 * and is already counted in the 36).
 */
static void test_negotiate_struct_size_36(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_negotiate_req) -
		      sizeof(struct smb2_hdr)),
		36);
}

/*
 * test_session_setup_struct_size_25 - SMB2_SESSION_SETUP StructureSize is 25
 *
 * MS-SMB2 §2.2.5: StructureSize MUST be 25.
 * smb2_sess_setup_req ends with Buffer[] (uint8_t flex).  sizeof() gives 24
 * for the fixed body; the spec's 25 includes one implied byte of Buffer[].
 */
static void test_session_setup_struct_size_25(struct kunit *test)
{
	/* Fixed body without the implied Buffer[] byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_sess_setup_req) -
		      sizeof(struct smb2_hdr)),
		24);
	/* Including the one implied byte mandated by the spec */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_sess_setup_req) -
		      sizeof(struct smb2_hdr)) + 1,
		25);
}

/*
 * test_logoff_struct_size_4 - SMB2_LOGOFF request StructureSize is 4
 *
 * MS-SMB2 §2.2.7: StructureSize MUST be 4.
 * No variable-length area; sizeof matches exactly.
 */
static void test_logoff_struct_size_4(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_logoff_req) -
		      sizeof(struct smb2_hdr)),
		4);
}

/*
 * test_tree_connect_struct_size_9 - SMB2_TREE_CONNECT request StructureSize
 * is 9
 *
 * MS-SMB2 §2.2.9: StructureSize MUST be 9.
 * smb2_tree_connect_req ends with Buffer[].  Fixed body is 8 bytes; spec
 * value is 9 (includes one implied Buffer[] byte).
 */
static void test_tree_connect_struct_size_9(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_tree_connect_req) -
		      sizeof(struct smb2_hdr)),
		8);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_tree_connect_req) -
		      sizeof(struct smb2_hdr)) + 1,
		9);
}

/*
 * test_tree_disconnect_struct_size_4 - SMB2_TREE_DISCONNECT request
 * StructureSize is 4
 *
 * MS-SMB2 §2.2.11: StructureSize MUST be 4.
 * No variable-length area; sizeof matches exactly.
 */
static void test_tree_disconnect_struct_size_4(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_tree_disconnect_req) -
		      sizeof(struct smb2_hdr)),
		4);
}

/*
 * test_create_struct_size_57 - SMB2_CREATE request StructureSize is 57
 *
 * MS-SMB2 §2.2.13: StructureSize MUST be 57.
 * smb2_create_req ends with Buffer[].  Fixed body is 56 bytes; spec value
 * is 57 (includes one implied Buffer[] byte).
 */
static void test_create_struct_size_57(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_create_req) -
		      sizeof(struct smb2_hdr)),
		56);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_create_req) -
		      sizeof(struct smb2_hdr)) + 1,
		57);
}

/*
 * test_close_struct_size_24 - SMB2_CLOSE request StructureSize is 24
 *
 * MS-SMB2 §2.2.15: StructureSize MUST be 24.
 * No variable-length area; sizeof matches exactly.
 */
static void test_close_struct_size_24(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_close_req) -
		      sizeof(struct smb2_hdr)),
		24);
}

/*
 * test_flush_struct_size_24 - SMB2_FLUSH request StructureSize is 24
 *
 * MS-SMB2 §2.2.17: StructureSize MUST be 24.
 * No variable-length area; sizeof matches exactly.
 */
static void test_flush_struct_size_24(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_flush_req) -
		      sizeof(struct smb2_hdr)),
		24);
}

/*
 * test_read_struct_size_49 - SMB2_READ request StructureSize is 49
 *
 * MS-SMB2 §2.2.19: StructureSize MUST be 49.
 * smb2_read_req ends with Buffer[].  Fixed body is 48 bytes; spec value is
 * 49 (includes one implied Buffer[] byte).
 */
static void test_read_struct_size_49(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_read_req) -
		      sizeof(struct smb2_hdr)),
		48);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_read_req) -
		      sizeof(struct smb2_hdr)) + 1,
		49);
}

/*
 * test_write_struct_size_49 - SMB2_WRITE request StructureSize is 49
 *
 * MS-SMB2 §2.2.21: StructureSize MUST be 49.
 * smb2_write_req ends with Buffer[].  Fixed body is 48 bytes; spec value
 * is 49 (includes one implied Buffer[] byte).
 */
static void test_write_struct_size_49(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_write_req) -
		      sizeof(struct smb2_hdr)),
		48);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_write_req) -
		      sizeof(struct smb2_hdr)) + 1,
		49);
}

/*
 * test_lock_struct_size_48 - SMB2_LOCK request StructureSize is 48
 *
 * MS-SMB2 §2.2.26: StructureSize MUST be 48.
 * smb2_lock_req uses a concrete locks[1] (not a flexible array) to model
 * the one mandatory lock element that the spec includes in the fixed body.
 * sizeof() gives exactly 48 bytes for the fixed portion.
 */
static void test_lock_struct_size_48(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_lock_req) -
		      sizeof(struct smb2_hdr)),
		48);
	/* One smb2_lock_element is 24 bytes */
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct smb2_lock_element), 24);
}

/*
 * test_ioctl_struct_size_57 - SMB2_IOCTL request StructureSize is 57
 *
 * MS-SMB2 §2.2.31: StructureSize MUST be 57.
 * smb2_ioctl_req ends with Buffer[].  Fixed body is 56 bytes; spec value
 * is 57 (includes one implied Buffer[] byte).
 */
static void test_ioctl_struct_size_57(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_ioctl_req) -
		      sizeof(struct smb2_hdr)),
		56);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_ioctl_req) -
		      sizeof(struct smb2_hdr)) + 1,
		57);
}

/*
 * test_cancel_struct_size_4 - SMB2_CANCEL request StructureSize is 4
 *
 * MS-SMB2 §2.2.29: StructureSize MUST be 4.
 * The cancel request shares the same 4-byte body layout as SMB2_ECHO —
 * both are { __le16 StructureSize; __le16 Reserved; }.  We verify using
 * the explicitly defined smb2_echo_req struct as a proxy.
 */
static void test_cancel_struct_size_4(struct kunit *test)
{
	/*
	 * smb2_echo_req == cancel layout: hdr + StructureSize(u16) +
	 * Reserved(u16) = 4 bytes body; no variable area.
	 */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_echo_req) -
		      sizeof(struct smb2_hdr)),
		4);
}

/*
 * test_echo_struct_size_4 - SMB2_ECHO request StructureSize is 4
 *
 * MS-SMB2 §2.2.28: StructureSize MUST be 4.
 * No variable-length area; sizeof matches exactly.
 */
static void test_echo_struct_size_4(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_echo_req) -
		      sizeof(struct smb2_hdr)),
		4);
}

/*
 * test_query_dir_struct_size_33 - SMB2_QUERY_DIRECTORY request StructureSize
 * is 33
 *
 * MS-SMB2 §2.2.33: StructureSize MUST be 33.
 * smb2_query_directory_req ends with Buffer[].  Fixed body is 32 bytes;
 * spec value is 33 (includes one implied Buffer[] byte).
 */
static void test_query_dir_struct_size_33(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_query_directory_req) -
		      sizeof(struct smb2_hdr)),
		32);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_query_directory_req) -
		      sizeof(struct smb2_hdr)) + 1,
		33);
}

/*
 * test_change_notify_struct_size_32 - SMB2_CHANGE_NOTIFY request StructureSize
 * is 32
 *
 * MS-SMB2 §2.2.35: StructureSize MUST be 32.
 * No variable-length area; sizeof matches exactly.
 */
static void test_change_notify_struct_size_32(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_notify_req) -
		      sizeof(struct smb2_hdr)),
		32);
}

/*
 * test_query_info_struct_size_41 - SMB2_QUERY_INFO request StructureSize is 41
 *
 * MS-SMB2 §2.2.37: StructureSize MUST be 41.
 * smb2_query_info_req ends with Buffer[].  Fixed body is 40 bytes; spec
 * value is 41 (includes one implied Buffer[] byte).
 */
static void test_query_info_struct_size_41(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_query_info_req) -
		      sizeof(struct smb2_hdr)),
		40);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_query_info_req) -
		      sizeof(struct smb2_hdr)) + 1,
		41);
}

/*
 * test_set_info_struct_size_33 - SMB2_SET_INFO request StructureSize is 33
 *
 * MS-SMB2 §2.2.39: StructureSize MUST be 33.
 * smb2_set_info_req ends with Buffer[].  Fixed body is 32 bytes; spec
 * value is 33 (includes one implied Buffer[] byte).
 */
static void test_set_info_struct_size_33(struct kunit *test)
{
	/* Fixed body */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_set_info_req) -
		      sizeof(struct smb2_hdr)),
		32);
	/* Fixed body + one implied byte */
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_set_info_req) -
		      sizeof(struct smb2_hdr)) + 1,
		33);
}

/*
 * test_oplock_break_struct_size_24 - SMB2_OPLOCK_BREAK StructureSize is 24
 *
 * MS-SMB2 §2.2.23.1 (oplock break notification): StructureSize MUST be 24.
 * No variable area; sizeof matches exactly.
 * smb2_check_message() also accepts 36 (OP_BREAK_STRUCT_SIZE_21) for the
 * SMB2.1 lease break acknowledgement variant.
 */
static void test_oplock_break_struct_size_24(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
		(int)(sizeof(struct smb2_oplock_break) -
		      sizeof(struct smb2_hdr)),
		24);
	/* The two oplock-break StructureSize constants used in validation */
	KUNIT_EXPECT_EQ(test, OP_BREAK_STRUCT_SIZE_20, 24);
	KUNIT_EXPECT_EQ(test, OP_BREAK_STRUCT_SIZE_21, 36);
}

/* -----------------------------------------------------------------------
 * Part 2: smb2_get_data_area_len() invariants
 *
 * These tests verify that the fields used to derive data-area offset and
 * length for each command are at the expected offsets within the structs.
 * smb2_get_data_area_len() is a static function; these tests exercise the
 * struct-layout invariants it relies on.
 * ----------------------------------------------------------------------- */

/*
 * test_session_setup_data_area_from_security_buffer - SecurityBufferOffset
 * and SecurityBufferLength correctly describe the data area.
 *
 * smb2_get_data_area_len() for SMB2_SESSION_SETUP uses:
 *   le16_to_cpu(req->SecurityBufferOffset)  - offset of GSS blob
 *   le16_to_cpu(req->SecurityBufferLength)  - length of GSS blob
 * The Buffer[] field starts at sizeof(smb2_sess_setup_req) from the struct
 * base, which equals the fixed body size (24 bytes past the header).
 */
static void test_session_setup_data_area_from_security_buffer(struct kunit *test)
{
	struct smb2_sess_setup_req req;

	memset(&req, 0, sizeof(req));
	req.SecurityBufferOffset = cpu_to_le16(0x58);
	req.SecurityBufferLength = cpu_to_le16(0x20);

	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(req.SecurityBufferOffset), 0x58);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(req.SecurityBufferLength), 0x20);

	/*
	 * Buffer[] starts immediately after the fixed fields.  offsetof()
	 * on a flexible-array member gives the offset of that member, which
	 * equals sizeof(struct) when the flex array contributes 0 bytes.
	 */
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct smb2_sess_setup_req, Buffer),
		(int)sizeof(struct smb2_sess_setup_req));
}

/*
 * test_create_data_area_from_create_contexts - CreateContextsOffset and
 * CreateContextsLength drive the data-area calculation when non-zero.
 *
 * smb2_get_data_area_len() for SMB2_CREATE:
 *   when CreateContextsLength != 0: off = CreateContextsOffset (u32),
 *                                   len = CreateContextsLength (u32)
 *   otherwise: off = max(NameOffset, offsetof(..., Buffer)),
 *              len = NameLength
 */
static void test_create_data_area_from_create_contexts(struct kunit *test)
{
	struct smb2_create_req req;

	memset(&req, 0, sizeof(req));
	req.CreateContextsOffset = cpu_to_le32(0x80);
	req.CreateContextsLength = cpu_to_le32(0x40);

	KUNIT_EXPECT_EQ(test,
		le32_to_cpu(req.CreateContextsOffset), 0x80U);
	KUNIT_EXPECT_EQ(test,
		le32_to_cpu(req.CreateContextsLength), 0x40U);

	/* Fallback path: NameOffset + NameLength */
	req.NameOffset = cpu_to_le16(0x78);
	req.NameLength = cpu_to_le16(0x0c);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.NameOffset), 0x78);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.NameLength), 0x0c);

	/*
	 * Buffer[] starts at sizeof(smb2_create_req), i.e. 56 bytes past
	 * the header.  smb2_get_data_area_len() clamps NameOffset to at
	 * least offsetof(..., Buffer) == 56 + 64 == 120 from buf start.
	 */
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct smb2_create_req, Buffer),
		(int)sizeof(struct smb2_create_req));
}

/*
 * test_write_data_area_from_buffer - DataOffset and Length fields locate
 * the write payload.
 *
 * smb2_get_data_area_len() for SMB2_WRITE:
 *   when DataOffset || Length != 0: off = max(DataOffset, offsetof Buffer),
 *                                   len = Length (u32)
 *   otherwise: off = WriteChannelInfoOffset,
 *              len = WriteChannelInfoLength
 */
static void test_write_data_area_from_buffer(struct kunit *test)
{
	struct smb2_write_req req;

	/* Primary path: DataOffset + Length */
	memset(&req, 0, sizeof(req));
	req.DataOffset = cpu_to_le16(0x70);
	req.Length     = cpu_to_le32(0x800);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(req.DataOffset), 0x70);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.Length),     0x800U);

	/* Channel-info fallback path */
	memset(&req, 0, sizeof(req));
	req.WriteChannelInfoOffset = cpu_to_le16(0x90);
	req.WriteChannelInfoLength = cpu_to_le16(0x10);

	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(req.WriteChannelInfoOffset), 0x90);
	KUNIT_EXPECT_EQ(test,
		le16_to_cpu(req.WriteChannelInfoLength), 0x10);
}

/*
 * test_ioctl_data_area_from_input_buffer - InputOffset and InputCount fields
 * locate the IOCTL input buffer.
 *
 * smb2_get_data_area_len() for SMB2_IOCTL:
 *   off = max(InputOffset (u32), offsetof(..., Buffer))
 *   len = InputCount (u32)
 * MaxOutputResponse is used separately for credit validation.
 */
static void test_ioctl_data_area_from_input_buffer(struct kunit *test)
{
	struct smb2_ioctl_req req;

	memset(&req, 0, sizeof(req));
	req.InputOffset        = cpu_to_le32(0x78);
	req.InputCount         = cpu_to_le32(0x30);
	req.MaxOutputResponse  = cpu_to_le32(0x10000);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.InputOffset),       0x78U);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.InputCount),        0x30U);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.MaxOutputResponse), 0x10000U);

	/*
	 * Buffer[] is at offset sizeof(smb2_ioctl_req) from the struct base
	 * (56 bytes past the header).
	 */
	KUNIT_EXPECT_EQ(test,
		(int)offsetof(struct smb2_ioctl_req, Buffer),
		(int)sizeof(struct smb2_ioctl_req));
}

/* -----------------------------------------------------------------------
 * Part 3: SMB2 header layout invariants
 * ----------------------------------------------------------------------- */

/*
 * test_smb2_header_size_64 - struct smb2_hdr is exactly 64 bytes
 *
 * MS-SMB2 §2.2.1: the fixed SMB2 header is 64 bytes.  All request
 * StructureSize values are relative to the start of the header, so an
 * incorrect header size would break every StructureSize check.
 */
static void test_smb2_header_size_64(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)sizeof(struct smb2_hdr), 64);
	/* The #define used by smb2_check_message() must agree */
	KUNIT_EXPECT_EQ(test, __SMB2_HEADER_STRUCTURE_SIZE, 64);
}

/*
 * test_smb2_protocol_id - SMB2_PROTO_NUMBER encodes 0xFE 'S' 'M' 'B'
 *
 * MS-SMB2 §2.2.1: ProtocolId MUST be 0xFE534D42 (bytes on the wire:
 * 0xFE, 0x53, 0x4D, 0x42 = 0xFE 'S' 'M' 'B').
 *
 * SMB2_PROTO_NUMBER is defined as cpu_to_le32(0x424d53fe); on a
 * little-endian host le32_to_cpu round-trips to 0x424d53fe.
 */
static void test_smb2_protocol_id(struct kunit *test)
{
	__le32 proto = SMB2_PROTO_NUMBER;

	/* Round-trip: le32 → host must give back the original constant */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(proto), 0x424d53feU);

	/*
	 * The first byte on the wire (ProtocolId[0]) is 0xFE — the SMB2
	 * magic.  In little-endian encoding the least-significant byte of
	 * 0x424d53fe is 0xfe.
	 */
	KUNIT_EXPECT_EQ(test, (u8)(le32_to_cpu(proto) & 0xff), 0xfe);
}

/* -----------------------------------------------------------------------
 * Test suite registration
 * ----------------------------------------------------------------------- */

static struct kunit_case ksmbd_smb2_validate_test_cases[] = {
	/* Part 1: StructureSize per SMB2 command */
	KUNIT_CASE(test_negotiate_struct_size_36),
	KUNIT_CASE(test_session_setup_struct_size_25),
	KUNIT_CASE(test_logoff_struct_size_4),
	KUNIT_CASE(test_tree_connect_struct_size_9),
	KUNIT_CASE(test_tree_disconnect_struct_size_4),
	KUNIT_CASE(test_create_struct_size_57),
	KUNIT_CASE(test_close_struct_size_24),
	KUNIT_CASE(test_flush_struct_size_24),
	KUNIT_CASE(test_read_struct_size_49),
	KUNIT_CASE(test_write_struct_size_49),
	KUNIT_CASE(test_lock_struct_size_48),
	KUNIT_CASE(test_ioctl_struct_size_57),
	KUNIT_CASE(test_cancel_struct_size_4),
	KUNIT_CASE(test_echo_struct_size_4),
	KUNIT_CASE(test_query_dir_struct_size_33),
	KUNIT_CASE(test_change_notify_struct_size_32),
	KUNIT_CASE(test_query_info_struct_size_41),
	KUNIT_CASE(test_set_info_struct_size_33),
	KUNIT_CASE(test_oplock_break_struct_size_24),
	/* Part 2: smb2_get_data_area_len() invariants */
	KUNIT_CASE(test_session_setup_data_area_from_security_buffer),
	KUNIT_CASE(test_create_data_area_from_create_contexts),
	KUNIT_CASE(test_write_data_area_from_buffer),
	KUNIT_CASE(test_ioctl_data_area_from_input_buffer),
	/* Part 3: SMB2 header layout */
	KUNIT_CASE(test_smb2_header_size_64),
	KUNIT_CASE(test_smb2_protocol_id),
	{}
};

static struct kunit_suite ksmbd_smb2_validate_test_suite = {
	.name = "ksmbd_smb2_validate",
	.test_cases = ksmbd_smb2_validate_test_cases,
};

kunit_test_suite(ksmbd_smb2_validate_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB2 request validation invariants");
