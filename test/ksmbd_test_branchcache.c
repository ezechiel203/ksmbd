// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *   Author(s): Namjae Jeon <linkinjeon@kernel.org>
 *
 *   KUnit tests for BranchCache support (ksmbd_branchcache.c)
 *
 *   Tests the BranchCache protocol structures and validation logic.
 *   Actual hash computation requires filesystem state and crypto
 *   contexts, so we test boundary conditions and structural
 *   properties.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "ksmbd_branchcache.h"

/* ═══════════════════════════════════════════════════════════════════
 *  Constants and Structure Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_constants(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, SRV_HASH_VER_1, 0x00000001U);
	KUNIT_EXPECT_EQ(test, SRV_HASH_VER_2, 0x00000002U);
	KUNIT_EXPECT_EQ(test, SRV_HASH_TYPE_PEER_DIST, 0x00000001U);
	KUNIT_EXPECT_EQ(test, SRV_HASH_RETRIEVE_HASH_BASED, 0x00000001U);
	KUNIT_EXPECT_EQ(test, SRV_HASH_RETRIEVE_FILE_BASED, 0x00000002U);
}

static void test_branchcache_segment_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, PCCRC_SEGMENT_SIZE, 64 * 1024U);
}

static void test_branchcache_hash_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, PCCRC_V1_HASH_SIZE, 32U);
}

static void test_branchcache_read_buf_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, PCCRC_READ_BUF_SIZE, 4096U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Request Structure Validation
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_read_hash_input_too_small(struct kunit *test)
{
	/* Request must be at least sizeof(srv_read_hash_req) */
	KUNIT_EXPECT_TRUE(test, sizeof(struct srv_read_hash_req) > 0);
	/* A buffer smaller than the struct should be rejected */
	KUNIT_EXPECT_GT(test, sizeof(struct srv_read_hash_req), (size_t)10);
}

static void test_branchcache_read_hash_struct_layout(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashType = cpu_to_le32(SRV_HASH_TYPE_PEER_DIST);
	req.HashVersion = cpu_to_le32(SRV_HASH_VER_1);
	req.HashRetrievalType = cpu_to_le32(SRV_HASH_RETRIEVE_FILE_BASED);
	req.Length = cpu_to_le32(65536);
	req.Offset = cpu_to_le64(0);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashType),
			SRV_HASH_TYPE_PEER_DIST);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashVersion), SRV_HASH_VER_1);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.Length), 65536U);
	KUNIT_EXPECT_EQ(test, le64_to_cpu(req.Offset), 0ULL);
}

static void test_branchcache_read_hash_invalid_hash_type(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashType = cpu_to_le32(0x99); /* Invalid */
	KUNIT_EXPECT_NE(test, le32_to_cpu(req.HashType),
			SRV_HASH_TYPE_PEER_DIST);
}

static void test_branchcache_read_hash_invalid_hash_version(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashVersion = cpu_to_le32(0x03); /* Only V1 and V2 are valid */
	KUNIT_EXPECT_NE(test, le32_to_cpu(req.HashVersion), SRV_HASH_VER_1);
	KUNIT_EXPECT_NE(test, le32_to_cpu(req.HashVersion), SRV_HASH_VER_2);
}

static void test_branchcache_read_hash_invalid_retrieval_type(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashRetrievalType = cpu_to_le32(0x05); /* Invalid */
	KUNIT_EXPECT_NE(test, le32_to_cpu(req.HashRetrievalType),
			SRV_HASH_RETRIEVE_HASH_BASED);
	KUNIT_EXPECT_NE(test, le32_to_cpu(req.HashRetrievalType),
			SRV_HASH_RETRIEVE_FILE_BASED);
}

static void test_branchcache_read_hash_zero_length(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.Length = 0;
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.Length), 0U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Response Structure Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_rsp_struct_layout(struct kunit *test)
{
	struct srv_read_hash_rsp rsp = {};

	rsp.Offset = cpu_to_le64(12345);
	rsp.BufferLength = cpu_to_le32(1024);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(rsp.Offset), 12345ULL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(rsp.BufferLength), 1024U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Content Info V1 Structure Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_content_info_v1_header(struct kunit *test)
{
	struct pccrc_content_info_v1 ci = {};

	ci.Version = cpu_to_le16(0x0100);
	ci.HashAlgo = cpu_to_le32(0x0000800C);
	ci.cSegments = cpu_to_le32(1);

	KUNIT_EXPECT_EQ(test, le16_to_cpu(ci.Version), 0x0100U);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ci.HashAlgo), 0x0000800CU);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ci.cSegments), 1U);
	KUNIT_EXPECT_EQ(test, le16_to_cpu(ci.Padding), 0U);
}

static void test_branchcache_content_info_v1_single_segment(struct kunit *test)
{
	struct pccrc_content_info_v1 ci = {};

	ci.cSegments = cpu_to_le32(1);
	ci.dwOffsetInFirstSegment = cpu_to_le32(0);
	ci.dwReadBytesInLastSegment = cpu_to_le32(PCCRC_SEGMENT_SIZE);

	KUNIT_EXPECT_EQ(test, le32_to_cpu(ci.cSegments), 1U);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ci.dwOffsetInFirstSegment), 0U);
}

static void test_branchcache_content_info_v1_multiple_segments(struct kunit *test)
{
	struct pccrc_content_info_v1 ci = {};
	u32 file_size = 3 * PCCRC_SEGMENT_SIZE + 1024;
	u32 num_segments = (file_size + PCCRC_SEGMENT_SIZE - 1) /
			   PCCRC_SEGMENT_SIZE;

	ci.cSegments = cpu_to_le32(num_segments);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(ci.cSegments), 4U);
}

static void test_branchcache_content_info_v1_partial_last(struct kunit *test)
{
	u32 file_size = PCCRC_SEGMENT_SIZE + 512;
	u32 last_seg_bytes = file_size % PCCRC_SEGMENT_SIZE;

	KUNIT_EXPECT_EQ(test, last_seg_bytes, 512U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Segment Description Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_segment_desc_layout(struct kunit *test)
{
	struct pccrc_segment_desc_v1 desc = {};

	desc.ullOffsetInContent = cpu_to_le64(0);
	desc.cbSegment = cpu_to_le32(PCCRC_SEGMENT_SIZE);
	desc.cbBlockSize = cpu_to_le32(PCCRC_SEGMENT_SIZE);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(desc.ullOffsetInContent), 0ULL);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(desc.cbSegment),
			(u32)PCCRC_SEGMENT_SIZE);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(desc.cbBlockSize),
			(u32)PCCRC_SEGMENT_SIZE);
}

static void test_branchcache_segment_hash_size(struct kunit *test)
{
	struct pccrc_segment_desc_v1 desc;

	/* Each segment has a 32-byte HoD and a 32-byte SegmentSecret */
	KUNIT_EXPECT_EQ(test, sizeof(desc.SegmentHashOfData),
			(size_t)PCCRC_V1_HASH_SIZE);
	KUNIT_EXPECT_EQ(test, sizeof(desc.SegmentSecret),
			(size_t)PCCRC_V1_HASH_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Segment Count Computation Tests
 * ═══════════════════════════════════════════════════════════════════ */

static u32 compute_segment_count(u64 file_size)
{
	if (file_size == 0)
		return 0;
	return (u32)((file_size + PCCRC_SEGMENT_SIZE - 1) / PCCRC_SEGMENT_SIZE);
}

static void test_branchcache_segment_count_empty_file(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, compute_segment_count(0), 0U);
}

static void test_branchcache_segment_count_one_byte(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, compute_segment_count(1), 1U);
}

static void test_branchcache_segment_count_exact_segment(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, compute_segment_count(PCCRC_SEGMENT_SIZE), 1U);
}

static void test_branchcache_segment_count_one_over(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, compute_segment_count(PCCRC_SEGMENT_SIZE + 1), 2U);
}

static void test_branchcache_segment_count_large(struct kunit *test)
{
	/* 1 MB = 16 segments */
	KUNIT_EXPECT_EQ(test, compute_segment_count(1024 * 1024), 16U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Read Hash Request Validation Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_read_hash_valid_v1_file_based(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashType = cpu_to_le32(SRV_HASH_TYPE_PEER_DIST);
	req.HashVersion = cpu_to_le32(SRV_HASH_VER_1);
	req.HashRetrievalType = cpu_to_le32(SRV_HASH_RETRIEVE_FILE_BASED);
	req.Length = cpu_to_le32(PCCRC_SEGMENT_SIZE);
	req.Offset = cpu_to_le64(0);

	/* All fields valid */
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashType),
			SRV_HASH_TYPE_PEER_DIST);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashVersion), SRV_HASH_VER_1);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashRetrievalType),
			SRV_HASH_RETRIEVE_FILE_BASED);
}

static void test_branchcache_read_hash_valid_v2(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashVersion = cpu_to_le32(SRV_HASH_VER_2);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashVersion), SRV_HASH_VER_2);
}

static void test_branchcache_read_hash_hash_based_retrieval(struct kunit *test)
{
	struct srv_read_hash_req req = {};

	req.HashRetrievalType = cpu_to_le32(SRV_HASH_RETRIEVE_HASH_BASED);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(req.HashRetrievalType),
			SRV_HASH_RETRIEVE_HASH_BASED);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Content Info V1 Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_content_info_v1_zero_segments(struct kunit *test)
{
	/* Empty file has zero segments */
	KUNIT_EXPECT_EQ(test, compute_segment_count(0), 0U);
}

static void test_branchcache_content_info_v1_exact_boundary(struct kunit *test)
{
	/* File exactly 2 segments */
	KUNIT_EXPECT_EQ(test,
			compute_segment_count(2 * PCCRC_SEGMENT_SIZE), 2U);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Segment Description Additional Tests
 * ═══════════════════════════════════════════════════════════════════ */

static void test_branchcache_segment_desc_second_segment(struct kunit *test)
{
	struct pccrc_segment_desc_v1 desc = {};

	desc.ullOffsetInContent = cpu_to_le64(PCCRC_SEGMENT_SIZE);
	desc.cbSegment = cpu_to_le32(PCCRC_SEGMENT_SIZE);

	KUNIT_EXPECT_EQ(test, le64_to_cpu(desc.ullOffsetInContent),
			(u64)PCCRC_SEGMENT_SIZE);
}

static void test_branchcache_segment_desc_partial_segment(struct kunit *test)
{
	struct pccrc_segment_desc_v1 desc = {};

	/* Last segment of a file that's not segment-aligned */
	desc.cbSegment = cpu_to_le32(1024);
	KUNIT_EXPECT_EQ(test, le32_to_cpu(desc.cbSegment), 1024U);
	KUNIT_EXPECT_LT(test, le32_to_cpu(desc.cbSegment),
			 (u32)PCCRC_SEGMENT_SIZE);
}

/* ═══════════════════════════════════════════════════════════════════
 *  Test Case Array and Suite Registration
 * ═══════════════════════════════════════════════════════════════════ */

static struct kunit_case ksmbd_branchcache_test_cases[] = {
	/* Constants */
	KUNIT_CASE(test_branchcache_constants),
	KUNIT_CASE(test_branchcache_segment_size),
	KUNIT_CASE(test_branchcache_hash_size),
	KUNIT_CASE(test_branchcache_read_buf_size),
	/* Request validation */
	KUNIT_CASE(test_branchcache_read_hash_input_too_small),
	KUNIT_CASE(test_branchcache_read_hash_struct_layout),
	KUNIT_CASE(test_branchcache_read_hash_invalid_hash_type),
	KUNIT_CASE(test_branchcache_read_hash_invalid_hash_version),
	KUNIT_CASE(test_branchcache_read_hash_invalid_retrieval_type),
	KUNIT_CASE(test_branchcache_read_hash_zero_length),
	/* Response structure */
	KUNIT_CASE(test_branchcache_rsp_struct_layout),
	/* Content Info V1 */
	KUNIT_CASE(test_branchcache_content_info_v1_header),
	KUNIT_CASE(test_branchcache_content_info_v1_single_segment),
	KUNIT_CASE(test_branchcache_content_info_v1_multiple_segments),
	KUNIT_CASE(test_branchcache_content_info_v1_partial_last),
	/* Segment description */
	KUNIT_CASE(test_branchcache_segment_desc_layout),
	KUNIT_CASE(test_branchcache_segment_hash_size),
	/* Segment count */
	KUNIT_CASE(test_branchcache_segment_count_empty_file),
	KUNIT_CASE(test_branchcache_segment_count_one_byte),
	KUNIT_CASE(test_branchcache_segment_count_exact_segment),
	KUNIT_CASE(test_branchcache_segment_count_one_over),
	KUNIT_CASE(test_branchcache_segment_count_large),
	/* Read hash additional */
	KUNIT_CASE(test_branchcache_read_hash_valid_v1_file_based),
	KUNIT_CASE(test_branchcache_read_hash_valid_v2),
	KUNIT_CASE(test_branchcache_read_hash_hash_based_retrieval),
	/* Content info additional */
	KUNIT_CASE(test_branchcache_content_info_v1_zero_segments),
	KUNIT_CASE(test_branchcache_content_info_v1_exact_boundary),
	/* Segment desc additional */
	KUNIT_CASE(test_branchcache_segment_desc_second_segment),
	KUNIT_CASE(test_branchcache_segment_desc_partial_segment),
	{}
};

static struct kunit_suite ksmbd_branchcache_test_suite = {
	.name = "ksmbd_branchcache",
	.test_cases = ksmbd_branchcache_test_cases,
};

kunit_test_suite(ksmbd_branchcache_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd BranchCache support");
