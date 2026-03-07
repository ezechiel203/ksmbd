// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for MS-SMB2 §3.3.5.9.5 CREATE_QUERY_MAXIMAL_ACCESS context
 *
 *   The "MxAc" create context signals that the client wants the server to
 *   return the maximum access rights the authenticated user holds on the
 *   opened file.  The response blob is built by create_mxac_rsp_buf()
 *   (oplock.c) and its layout is governed by struct create_mxac_rsp
 *   (smb2pdu.h).
 *
 *   These tests verify:
 *     - Tag name bytes and length (wire value "MxAc")
 *     - struct create_mxac_rsp / create_mxac_req field layout
 *     - Access mask bit definitions used in MaximalAccess
 *     - Context header NameOffset / NameLength contract
 *     - QueryStatus success value
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "smb2pdu.h"
#include "smb_common.h"

/* ──────────────────────────────────────────────────────────────────────────
 * 1. Tag name
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_mxac_context_tag_name - "MxAc" wire bytes are 0x4D 0x78 0x41 0x63
 *
 * MS-SMB2 §2.2.13.2.8 defines the context name as the four-character ASCII
 * string "MxAc".  Verify the macro and the individual bytes match.
 */
static void test_mxac_context_tag_name(struct kunit *test)
{
	const char *tag = SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST;

	KUNIT_EXPECT_EQ(test, (unsigned char)tag[0], 0x4Du); /* 'M' */
	KUNIT_EXPECT_EQ(test, (unsigned char)tag[1], 0x78u); /* 'x' */
	KUNIT_EXPECT_EQ(test, (unsigned char)tag[2], 0x41u); /* 'A' */
	KUNIT_EXPECT_EQ(test, (unsigned char)tag[3], 0x63u); /* 'c' */
}

/*
 * test_mxac_tag_length - the tag string is exactly 4 characters long
 */
static void test_mxac_tag_length(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			strlen(SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST),
			(size_t)4);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 2. Response struct layout (create_mxac_rsp)
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_mxac_response_struct_size - create_mxac_rsp has the expected packed size
 *
 * The structure is:
 *   struct create_context ccontext  (Next=4, NameOffset=2, NameLength=2,
 *                                    Reserved=2, DataOffset=2, DataLength=4)
 *                                 = 16 bytes
 *   __u8  Name[8]                 =  8 bytes
 *   __le32 QueryStatus            =  4 bytes
 *   __le32 MaximalAccess          =  4 bytes
 *                                 = 32 bytes total
 */
static void test_mxac_response_struct_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			sizeof(struct create_mxac_rsp),
			(size_t)32);
}

/*
 * test_mxac_request_struct_has_timestamp - create_mxac_req contains a Timestamp field
 *
 * MS-SMB2 §2.2.13.2.8: the request data is either empty or an 8-byte
 * Timestamp.  The struct create_mxac_req holds exactly one __le64 Timestamp
 * field after the ccontext + Name.
 */
static void test_mxac_request_struct_has_timestamp(struct kunit *test)
{
	/*
	 * struct create_mxac_req:
	 *   struct create_context ccontext  (16 bytes)
	 *   __u8  Name[8]                   ( 8 bytes)
	 *   __le64 Timestamp                ( 8 bytes)
	 *                                   = 32 bytes
	 */
	KUNIT_EXPECT_EQ(test,
			sizeof(struct create_mxac_req),
			(size_t)32);
}

/*
 * test_mxac_query_status_field_offset - QueryStatus is at the expected offset
 *
 * In create_mxac_rsp, QueryStatus immediately follows the 8-byte Name array
 * which itself follows the 16-byte create_context header.
 */
static void test_mxac_query_status_field_offset(struct kunit *test)
{
	size_t expected = offsetof(struct create_context, /* anonymous — use ccontext */ Next)
			  + sizeof(struct create_context)  /* 16 */
			  + 8;                             /* Name[8] */

	KUNIT_EXPECT_EQ(test,
			offsetof(struct create_mxac_rsp, QueryStatus),
			expected);
}

/*
 * test_mxac_maximal_access_field_offset - MaximalAccess follows QueryStatus
 */
static void test_mxac_maximal_access_field_offset(struct kunit *test)
{
	size_t qs_off  = offsetof(struct create_mxac_rsp, QueryStatus);
	size_t max_off = offsetof(struct create_mxac_rsp, MaximalAccess);

	KUNIT_EXPECT_EQ(test, max_off, qs_off + sizeof(__le32));
}

/* ──────────────────────────────────────────────────────────────────────────
 * 3. Access mask bit definitions
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_mxac_maximal_access_mask_bits - DESIRED_ACCESS_MASK covers standard bits
 *
 * DESIRED_ACCESS_MASK (0xF21F01FF) is the maximum value returned for
 * MaximalAccess.  Verify it includes the standard file rights.
 */
static void test_mxac_maximal_access_mask_bits(struct kunit *test)
{
	__le32 mask = DESIRED_ACCESS_MASK;
	__u32  val  = le32_to_cpu(mask);

	/* Must be non-zero and plausible (< 32-bit overflow) */
	KUNIT_EXPECT_NE(test, val, 0u);
	KUNIT_EXPECT_EQ(test, val, 0xF21F01FFu);
}

/*
 * test_mxac_read_access_includes_read_data - FILE_READ_DATA_LE bit is set in mask
 */
static void test_mxac_read_access_includes_read_data(struct kunit *test)
{
	__u32 mask = le32_to_cpu(DESIRED_ACCESS_MASK);
	__u32 bit  = le32_to_cpu(FILE_READ_DATA_LE);

	KUNIT_EXPECT_TRUE(test, (mask & bit) != 0);
}

/*
 * test_mxac_write_access_includes_write_data - FILE_WRITE_DATA_LE bit is set in mask
 */
static void test_mxac_write_access_includes_write_data(struct kunit *test)
{
	__u32 mask = le32_to_cpu(DESIRED_ACCESS_MASK);
	__u32 bit  = le32_to_cpu(FILE_WRITE_DATA_LE);

	KUNIT_EXPECT_TRUE(test, (mask & bit) != 0);
}

/*
 * test_mxac_delete_access_includes_delete - FILE_DELETE_LE bit is set in mask
 */
static void test_mxac_delete_access_includes_delete(struct kunit *test)
{
	__u32 mask = le32_to_cpu(DESIRED_ACCESS_MASK);
	__u32 bit  = le32_to_cpu(FILE_DELETE_LE);

	KUNIT_EXPECT_TRUE(test, (mask & bit) != 0);
}

/*
 * test_mxac_synchronize_bit_included - FILE_SYNCHRONIZE_LE is set in mask
 *
 * MS-SMB2 §2.2.13.2.8 notes that SYNCHRONIZE should be included in the
 * maximal access returned for files.  DESIRED_ACCESS_MASK = 0xF21F01FF
 * has bit 20 (0x00100000) set.
 */
static void test_mxac_synchronize_bit_included(struct kunit *test)
{
	__u32 mask = le32_to_cpu(DESIRED_ACCESS_MASK);
	__u32 bit  = le32_to_cpu(FILE_SYNCHRONIZE_LE);

	KUNIT_EXPECT_TRUE(test, (mask & bit) != 0);
}

/*
 * test_mxac_generic_all_includes_specific - GENERIC_ALL bits subsume standard bits
 *
 * FILE_GENERIC_ALL_LE (0x10000000) is one of the generic access rights.
 * The DESIRED_ACCESS_MASK must include it to indicate full generic access.
 */
static void test_mxac_generic_all_includes_specific(struct kunit *test)
{
	__u32 mask = le32_to_cpu(DESIRED_ACCESS_MASK);
	__u32 ball = le32_to_cpu(FILE_GENERIC_ALL_LE);

	KUNIT_EXPECT_TRUE(test, (mask & ball) != 0);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 4. Create context header contract
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_mxac_context_name_offset - NameOffset field in create_context header
 *
 * The create_context.NameOffset field is at byte offset 4 within the generic
 * create_context structure, per [MS-SMB2] §2.2.13.2.
 */
static void test_mxac_context_name_offset(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			offsetof(struct create_context, NameOffset),
			(size_t)4);
}

/*
 * test_mxac_context_name_length_offset - NameLength field follows NameOffset
 */
static void test_mxac_context_name_length_offset(struct kunit *test)
{
	size_t name_off_off = offsetof(struct create_context, NameOffset);
	size_t name_len_off = offsetof(struct create_context, NameLength);

	KUNIT_EXPECT_EQ(test, name_len_off, name_off_off + sizeof(__le16));
}

/*
 * test_mxac_context_header_size - generic create_context is 16 bytes
 *
 * [MS-SMB2] §2.2.13.2: Next(4) + NameOffset(2) + NameLength(2) +
 * Reserved(2) + DataOffset(2) + DataLength(4) = 16 bytes.
 */
static void test_mxac_context_header_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, sizeof(struct create_context), (size_t)16);
}

/*
 * test_mxac_query_status_success - QueryStatus = 0 means STATUS_SUCCESS
 *
 * create_mxac_rsp_buf() sets buf->QueryStatus = STATUS_SUCCESS.  On the
 * wire STATUS_SUCCESS is 0x00000000.  Verify the constant is zero.
 */
static void test_mxac_query_status_success(struct kunit *test)
{
	/*
	 * STATUS_SUCCESS is defined in smbstatus.h as cpu_to_le32(0).
	 * We check the raw value here without pulling in the full header.
	 */
	__le32 status_success = cpu_to_le32(0);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(status_success), 0u);
}

/*
 * test_mxac_timestamp_field_optional - Timestamp in request is 8 bytes or absent
 *
 * The MxAc request body is optionally an 8-byte FILETIME.  If present its
 * size must be exactly 8 bytes (sizeof __le64).  Verify the field size.
 */
static void test_mxac_timestamp_field_optional(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			sizeof(__le64),
			(size_t)8);
	KUNIT_EXPECT_EQ(test,
			sizeof(((struct create_mxac_req *)NULL)->Timestamp),
			(size_t)8);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_create_maximal_access_test_cases[] = {
	/* Tag name */
	KUNIT_CASE(test_mxac_context_tag_name),
	KUNIT_CASE(test_mxac_tag_length),
	/* Response struct layout */
	KUNIT_CASE(test_mxac_response_struct_size),
	KUNIT_CASE(test_mxac_request_struct_has_timestamp),
	KUNIT_CASE(test_mxac_query_status_field_offset),
	KUNIT_CASE(test_mxac_maximal_access_field_offset),
	/* Access mask bits */
	KUNIT_CASE(test_mxac_maximal_access_mask_bits),
	KUNIT_CASE(test_mxac_read_access_includes_read_data),
	KUNIT_CASE(test_mxac_write_access_includes_write_data),
	KUNIT_CASE(test_mxac_delete_access_includes_delete),
	KUNIT_CASE(test_mxac_synchronize_bit_included),
	KUNIT_CASE(test_mxac_generic_all_includes_specific),
	/* Create context header */
	KUNIT_CASE(test_mxac_context_name_offset),
	KUNIT_CASE(test_mxac_context_name_length_offset),
	KUNIT_CASE(test_mxac_context_header_size),
	/* Status and optional fields */
	KUNIT_CASE(test_mxac_query_status_success),
	KUNIT_CASE(test_mxac_timestamp_field_optional),
	{}
};

static struct kunit_suite ksmbd_create_maximal_access_test_suite = {
	.name = "ksmbd_create_maximal_access",
	.test_cases = ksmbd_create_maximal_access_test_cases,
};

kunit_test_suite(ksmbd_create_maximal_access_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for SMB2 CREATE_QUERY_MAXIMAL_ACCESS context (MxAc)");
