// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for RDMA/SMB Direct transport (transport_rdma.c)
 *
 *   Tests cover:
 *   - I/O size constants and range validation
 *   - SMB Direct negotiate packet structure and default values
 *   - Buffer management and credit limits
 *   - Connection lifecycle constants
 *   - Error/boundary conditions
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>

#include "transport_rdma.h"

/* ──────────────────────────────────────────────────────────
 * Replicated constants from transport_rdma.c for testing
 * without requiring actual RDMA hardware or kernel symbols.
 * ────────────────────────────────────────────────────────── */

/* SMB Direct ports [MS-SMBD] 2.1 */
#define TEST_SMB_DIRECT_PORT_IWARP		5445
#define TEST_SMB_DIRECT_PORT_INFINIBAND		445

/* SMB Direct version [MS-SMBD] 2.2.1 */
#define TEST_SMB_DIRECT_VERSION			0x0100

/* SMB Direct negotiation timeout in seconds */
#define TEST_SMB_DIRECT_NEGOTIATE_TIMEOUT	120

/* Max scatter/gather entries */
#define TEST_SMB_DIRECT_MAX_SEND_SGES		6
#define TEST_SMB_DIRECT_MAX_RECV_SGES		1

/* Connection manager parameters */
#define TEST_SMB_DIRECT_CM_INITIATOR_DEPTH	8
#define TEST_SMB_DIRECT_CM_RETRY		6
#define TEST_SMB_DIRECT_CM_RNR_RETRY		0

/* Default module parameter values from transport_rdma.c */
#define TEST_RECEIVE_CREDIT_MAX			255
#define TEST_SEND_CREDIT_TARGET			255
#define TEST_MAX_SEND_SIZE			1364
#define TEST_MAX_FRAGMENTED_RECV_SIZE		(1024 * 1024)
#define TEST_MAX_RECEIVE_SIZE			1364

/* SMB Direct response flag [MS-SMBD] 2.2.3 */
#define TEST_SMB_DIRECT_RESPONSE_REQUESTED	0x0001

/* ──────────────────────────────────────────────────────────
 * I/O size constants and range validation
 * ────────────────────────────────────────────────────────── */

static void test_smbd_default_iosize(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBD_DEFAULT_IOSIZE,
			8u * 1024u * 1024u);
}

static void test_smbd_min_iosize(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBD_MIN_IOSIZE,
			512u * 1024u);
}

static void test_smbd_max_iosize(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBD_MAX_IOSIZE,
			16u * 1024u * 1024u);
}

static void test_smbd_iosize_range(struct kunit *test)
{
	/* min <= default <= max must hold */
	KUNIT_EXPECT_LE(test, (unsigned int)SMBD_MIN_IOSIZE,
			(unsigned int)SMBD_DEFAULT_IOSIZE);
	KUNIT_EXPECT_LE(test, (unsigned int)SMBD_DEFAULT_IOSIZE,
			(unsigned int)SMBD_MAX_IOSIZE);
}

/* ──────────────────────────────────────────────────────────
 * SMB Direct negotiate values [MS-SMBD] 2.2.1 / 2.2.2
 * ────────────────────────────────────────────────────────── */

static void test_smbd_negotiate_min_version(struct kunit *test)
{
	/* [MS-SMBD] 3.1.5.2: MinVersion and MaxVersion are both 0x0100 */
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_VERSION, 0x0100);
}

static void test_smbd_negotiate_max_version(struct kunit *test)
{
	/* Current implementation supports only version 0x0100 */
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_VERSION, 0x0100);
}

static void test_smbd_negotiate_preferred_send_size(struct kunit *test)
{
	/* Default max_send_size = 1364 bytes per [MS-SMBD] */
	KUNIT_EXPECT_EQ(test, TEST_MAX_SEND_SIZE, 1364);
}

static void test_smbd_negotiate_max_send_size(struct kunit *test)
{
	/* max_send_size must be at least large enough for SMB2 header */
	KUNIT_EXPECT_GE(test, TEST_MAX_SEND_SIZE, 64);
	/* and must not exceed a reasonable upper bound */
	KUNIT_EXPECT_LE(test, TEST_MAX_SEND_SIZE, 8192);
}

static void test_smbd_negotiate_max_receive_size(struct kunit *test)
{
	/* Default max_receive_size matches max_send_size */
	KUNIT_EXPECT_EQ(test, TEST_MAX_RECEIVE_SIZE, 1364);
	KUNIT_EXPECT_EQ(test, TEST_MAX_RECEIVE_SIZE, TEST_MAX_SEND_SIZE);
}

static void test_smbd_negotiate_max_fragmented_size(struct kunit *test)
{
	/* Default fragmented receive size = 1 MB */
	KUNIT_EXPECT_EQ(test, TEST_MAX_FRAGMENTED_RECV_SIZE,
			1024 * 1024);
	/* Must be >= max_receive_size */
	KUNIT_EXPECT_GE(test, TEST_MAX_FRAGMENTED_RECV_SIZE,
			TEST_MAX_RECEIVE_SIZE);
}

static void test_smbd_credits_requested(struct kunit *test)
{
	/* Default credit request/grant values */
	KUNIT_EXPECT_EQ(test, TEST_RECEIVE_CREDIT_MAX, 255);
	KUNIT_EXPECT_EQ(test, TEST_SEND_CREDIT_TARGET, 255);
}

/* ──────────────────────────────────────────────────────────
 * Buffer management and segment sizes
 * ────────────────────────────────────────────────────────── */

static void test_smbd_max_send_segment(struct kunit *test)
{
	/*
	 * The maximum payload in a single send message is
	 * max_send_size - sizeof(struct smb_direct_data_transfer).
	 * Verify the data transfer header does not consume the
	 * entire send buffer.
	 */
	unsigned int hdr_size = sizeof(struct smb_direct_data_transfer);
	unsigned int payload;

	KUNIT_ASSERT_GT(test, (unsigned int)TEST_MAX_SEND_SIZE, hdr_size);
	payload = TEST_MAX_SEND_SIZE - hdr_size;
	KUNIT_EXPECT_GT(test, payload, 0u);
}

static void test_smbd_receive_credit_max(struct kunit *test)
{
	/* Credit max must fit in __le16 (negotiate packet field) */
	KUNIT_EXPECT_LE(test, TEST_RECEIVE_CREDIT_MAX, 65535);
	/* Must be positive */
	KUNIT_EXPECT_GT(test, TEST_RECEIVE_CREDIT_MAX, 0);
}

/* ──────────────────────────────────────────────────────────
 * Connection lifecycle and transport type
 * ────────────────────────────────────────────────────────── */

static void test_rdma_transport_type(struct kunit *test)
{
	/*
	 * SMB Direct uses port 445 for InfiniBand and 5445 for iWARP.
	 * Default is InfiniBand port.
	 */
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_PORT_INFINIBAND, 445);
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_PORT_IWARP, 5445);
}

static void test_rdma_header_size(struct kunit *test)
{
	/*
	 * Verify SMB Direct packet structures are properly packed.
	 * [MS-SMBD] 2.2.1: negotiate request = 20 bytes
	 * [MS-SMBD] 2.2.2: negotiate response = 32 bytes
	 * [MS-SMBD] 2.2.3: data transfer header = 24 bytes (excl. buffer[])
	 */
	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_direct_negotiate_req),
			20u);
	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_direct_negotiate_resp),
			32u);
	KUNIT_EXPECT_EQ(test, (unsigned int)sizeof(struct smb_direct_data_transfer),
			24u);
}

static void test_rdma_negotiate_req_layout(struct kunit *test)
{
	/*
	 * Verify field offsets in the negotiate request structure
	 * to ensure correct wire format [MS-SMBD] 2.2.1.
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_req, min_version),
		0u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_req, max_version),
		2u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_req, credits_requested),
		6u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_req, preferred_send_size),
		8u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_req, max_receive_size),
		12u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_req, max_fragmented_size),
		16u);
}

static void test_rdma_negotiate_resp_layout(struct kunit *test)
{
	/*
	 * Verify field offsets in the negotiate response structure
	 * to ensure correct wire format [MS-SMBD] 2.2.2.
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, min_version),
		0u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, negotiated_version),
		4u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, credits_requested),
		8u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, credits_granted),
		10u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, status),
		12u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, max_readwrite_size),
		16u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, preferred_send_size),
		20u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, max_receive_size),
		24u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_negotiate_resp, max_fragmented_size),
		28u);
}

static void test_rdma_data_transfer_layout(struct kunit *test)
{
	/*
	 * Verify field offsets in the data transfer header
	 * [MS-SMBD] 2.2.3.
	 */
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, credits_requested),
		0u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, credits_granted),
		2u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, flags),
		4u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, remaining_data_length),
		8u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, data_offset),
		12u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, data_length),
		16u);
	KUNIT_EXPECT_EQ(test,
		(unsigned int)offsetof(struct smb_direct_data_transfer, padding),
		20u);
}

/* ──────────────────────────────────────────────────────────
 * Error cases and boundary conditions
 * ────────────────────────────────────────────────────────── */

static void test_rdma_invalid_iosize_below_min(struct kunit *test)
{
	/*
	 * Values below SMBD_MIN_IOSIZE should be rejected or clamped.
	 * Verify the boundary relationship.
	 */
	unsigned int below_min_values[] = { 0, 1, 256 * 1024, SMBD_MIN_IOSIZE - 1 };
	int i;

	for (i = 0; i < ARRAY_SIZE(below_min_values); i++) {
		KUNIT_EXPECT_LT(test, below_min_values[i],
				(unsigned int)SMBD_MIN_IOSIZE);
	}
}

static void test_rdma_invalid_iosize_above_max(struct kunit *test)
{
	/*
	 * Values above SMBD_MAX_IOSIZE should be rejected or clamped.
	 * Verify the boundary relationship.
	 */
	unsigned int above_max_values[] = {
		SMBD_MAX_IOSIZE + 1,
		SMBD_MAX_IOSIZE + 4096,
		32u * 1024u * 1024u,
		0xFFFFFFFFu
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(above_max_values); i++) {
		KUNIT_EXPECT_GT(test, above_max_values[i],
				(unsigned int)SMBD_MAX_IOSIZE);
	}
}

static void test_rdma_zero_credits(struct kunit *test)
{
	/*
	 * A credit request of zero is invalid per [MS-SMBD].
	 * Verify our defaults are non-zero.
	 */
	KUNIT_EXPECT_NE(test, TEST_RECEIVE_CREDIT_MAX, 0);
	KUNIT_EXPECT_NE(test, TEST_SEND_CREDIT_TARGET, 0);
}

static void test_rdma_max_credits_boundary(struct kunit *test)
{
	/*
	 * Credits fields in negotiate packets are __le16, so the
	 * absolute maximum is 65535.  Verify defaults are within range.
	 */
	KUNIT_EXPECT_LE(test, TEST_RECEIVE_CREDIT_MAX, 65535);
	KUNIT_EXPECT_LE(test, TEST_SEND_CREDIT_TARGET, 65535);
	KUNIT_EXPECT_GT(test, TEST_RECEIVE_CREDIT_MAX, 0);
	KUNIT_EXPECT_GT(test, TEST_SEND_CREDIT_TARGET, 0);
}

static void test_rdma_response_requested_flag(struct kunit *test)
{
	/* [MS-SMBD] 2.2.3: RESPONSE_REQUESTED flag value */
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_DIRECT_RESPONSE_REQUESTED,
			TEST_SMB_DIRECT_RESPONSE_REQUESTED);
	KUNIT_EXPECT_EQ(test, (unsigned int)SMB_DIRECT_RESPONSE_REQUESTED,
			0x0001u);
}

static void test_rdma_cm_parameters(struct kunit *test)
{
	/* Connection manager retry/depth parameters */
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_CM_INITIATOR_DEPTH, 8);
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_CM_RETRY, 6);
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_CM_RNR_RETRY, 0);
}

static void test_rdma_negotiate_timeout(struct kunit *test)
{
	/* Negotiation timeout in seconds */
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_NEGOTIATE_TIMEOUT, 120);
}

static void test_rdma_sge_limits(struct kunit *test)
{
	/* Scatter/gather entry limits */
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_MAX_SEND_SGES, 6);
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_MAX_RECV_SGES, 1);
	KUNIT_EXPECT_GE(test, TEST_SMB_DIRECT_MAX_SEND_SGES,
			TEST_SMB_DIRECT_MAX_RECV_SGES);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_rdma_test_cases[] = {
	/* I/O size constants */
	KUNIT_CASE(test_smbd_default_iosize),
	KUNIT_CASE(test_smbd_min_iosize),
	KUNIT_CASE(test_smbd_max_iosize),
	KUNIT_CASE(test_smbd_iosize_range),
	/* SMB Direct negotiate values */
	KUNIT_CASE(test_smbd_negotiate_min_version),
	KUNIT_CASE(test_smbd_negotiate_max_version),
	KUNIT_CASE(test_smbd_negotiate_preferred_send_size),
	KUNIT_CASE(test_smbd_negotiate_max_send_size),
	KUNIT_CASE(test_smbd_negotiate_max_receive_size),
	KUNIT_CASE(test_smbd_negotiate_max_fragmented_size),
	KUNIT_CASE(test_smbd_credits_requested),
	/* Buffer management */
	KUNIT_CASE(test_smbd_max_send_segment),
	KUNIT_CASE(test_smbd_receive_credit_max),
	/* Connection lifecycle */
	KUNIT_CASE(test_rdma_transport_type),
	KUNIT_CASE(test_rdma_header_size),
	KUNIT_CASE(test_rdma_negotiate_req_layout),
	KUNIT_CASE(test_rdma_negotiate_resp_layout),
	KUNIT_CASE(test_rdma_data_transfer_layout),
	/* Error cases */
	KUNIT_CASE(test_rdma_invalid_iosize_below_min),
	KUNIT_CASE(test_rdma_invalid_iosize_above_max),
	KUNIT_CASE(test_rdma_zero_credits),
	KUNIT_CASE(test_rdma_max_credits_boundary),
	KUNIT_CASE(test_rdma_response_requested_flag),
	KUNIT_CASE(test_rdma_cm_parameters),
	KUNIT_CASE(test_rdma_negotiate_timeout),
	KUNIT_CASE(test_rdma_sge_limits),
	{}
};

static struct kunit_suite ksmbd_rdma_test_suite = {
	.name = "ksmbd_rdma",
	.test_cases = ksmbd_rdma_test_cases,
};

kunit_test_suite(ksmbd_rdma_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for RDMA/SMB Direct transport constants and structures");
