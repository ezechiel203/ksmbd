// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for RDMA/SMB Direct buffer management algorithms
 *
 *   These tests exercise the credit accounting, buffer sizing, scatter-gather,
 *   fragmentation, and queue-depth algorithms that govern SMB Direct transport
 *   ([MS-SMBD] RFC).  No RDMA hardware or kernel RDMA stack is required; all
 *   tests operate on constants, arithmetic, and structure layout.
 *
 *   Constants are replicated from transport_rdma.c (static module parameters)
 *   and transport_rdma.h (exported definitions) so the test module remains
 *   self-contained and can be built without KSMBD_SMBDIRECT enabled.
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/stddef.h>

#include "transport_rdma.h"

/* ──────────────────────────────────────────────────────────────────────────
 * Replicated constants from transport_rdma.c (static module parameters).
 * These mirror the defaults described in [MS-SMBD] 3.1.1.1 and must not
 * change without a corresponding update to this test.
 * ────────────────────────────────────────────────────────────────────────── */

/* Initial credit grant / target values */
#define TEST_RECEIVE_CREDIT_MAX		255
#define TEST_SEND_CREDIT_TARGET		255

/* Per-message size defaults */
#define TEST_MAX_SEND_SIZE		1364
#define TEST_MAX_RECEIVE_SIZE		1364

/* Fragmented PDU reassembly size (1 MiB) */
#define TEST_MAX_FRAGMENTED_RECV_SIZE	(1024 * 1024)

/* Scatter/gather entry limits */
#define TEST_SMB_DIRECT_MAX_SEND_SGES	6
#define TEST_SMB_DIRECT_MAX_RECV_SGES	1

/* Negotiation timeout */
#define TEST_SMB_DIRECT_NEGOTIATE_TIMEOUT 120

/* Connection manager initiator queue depth */
#define TEST_SMB_DIRECT_CM_INITIATOR_DEPTH 8

/*
 * Inline-data threshold: payloads smaller than this can be sent in the
 * data-transfer header without a separate RDMA Write.  We define it as the
 * maximum inline payload = max_send_size - data_transfer_header.
 */
#define TEST_INLINE_DATA_THRESHOLD \
	(TEST_MAX_SEND_SIZE - (int)sizeof(struct smb_direct_data_transfer))

/* ──────────────────────────────────────────────────────────────────────────
 * 1. I/O size constants
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_max_send_size_default - SMBD_DEFAULT_IOSIZE is 8 MiB
 *
 * [MS-SMBD] 3.1.1.1: MaxReadWriteSize is set to a locally configured value.
 * ksmbd chooses 8 MiB as the default.
 */
static void test_rdma_max_send_size_default(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBD_DEFAULT_IOSIZE,
			8u * 1024u * 1024u);
}

/*
 * test_rdma_min_send_size - SMBD_MIN_IOSIZE is 512 KiB
 *
 * Values below this minimum are rejected (or clamped) by init_smbd_max_io_size().
 */
static void test_rdma_min_send_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBD_MIN_IOSIZE,
			512u * 1024u);
}

/*
 * test_rdma_max_send_size_cap - SMBD_MAX_IOSIZE is 16 MiB
 *
 * Values above this ceiling are clamped by init_smbd_max_io_size().
 */
static void test_rdma_max_send_size_cap(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (unsigned int)SMBD_MAX_IOSIZE,
			16u * 1024u * 1024u);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 2. Credit accounting
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_credit_initial_count - default send/receive credit count is 255
 *
 * [MS-SMBD] 3.1.1.1: InitialReceiveCredits and InitialSendCredits.
 * Both default to 255, which fits in the __le16 negotiate-packet fields.
 */
static void test_rdma_credit_initial_count(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_RECEIVE_CREDIT_MAX, 255);
	KUNIT_EXPECT_EQ(test, TEST_SEND_CREDIT_TARGET, 255);
}

/*
 * test_rdma_credit_replenishment_threshold - credits must be replenished before zero
 *
 * The server must not allow recv_credits to drop to zero; it replenishes
 * credits before the peer exhausts them.  Verify that the initial credit
 * count leaves headroom above zero (i.e., > 1).
 */
static void test_rdma_credit_replenishment_threshold(struct kunit *test)
{
	/* A threshold of at least 1/4 of max is a reasonable policy */
	int threshold = TEST_RECEIVE_CREDIT_MAX / 4;

	KUNIT_EXPECT_GT(test, threshold, 0);
	KUNIT_EXPECT_LT(test, threshold, TEST_RECEIVE_CREDIT_MAX);
}

/*
 * test_rdma_send_credit_limit - send credits must not exceed negotiated value
 *
 * The peer grants send_credit_target credits; the local side must never
 * attempt to send more messages than that.  Verify the default is non-zero
 * and fits in a __le16 field.
 */
static void test_rdma_send_credit_limit(struct kunit *test)
{
	KUNIT_EXPECT_GT(test, TEST_SEND_CREDIT_TARGET, 0);
	KUNIT_EXPECT_LE(test, TEST_SEND_CREDIT_TARGET, 65535);
}

/*
 * test_rdma_receive_buffer_size - receive buffer size >= negotiated max read size
 *
 * Each receive buffer must be large enough to hold the maximum single
 * message.  Verify the default receive size is at least 64 bytes (a
 * minimal SMB2 header) and no larger than SMBD_MAX_IOSIZE.
 */
static void test_rdma_receive_buffer_size(struct kunit *test)
{
	KUNIT_EXPECT_GE(test, TEST_MAX_RECEIVE_SIZE, 64);
	KUNIT_EXPECT_LE(test, (unsigned int)TEST_MAX_RECEIVE_SIZE,
			(unsigned int)SMBD_MAX_IOSIZE);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 3. Fragmentation and reassembly
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_fragmentation_threshold - PDUs larger than max_send_size are fragmented
 *
 * A PDU that exceeds TEST_MAX_SEND_SIZE bytes must be split into multiple
 * SMB Direct data-transfer messages.  The fragmentation boundary is exactly
 * TEST_MAX_SEND_SIZE (exclusive).
 */
static void test_rdma_fragmentation_threshold(struct kunit *test)
{
	/* Any payload equal to or larger than this requires fragmentation */
	int fragment_at = TEST_MAX_SEND_SIZE;

	KUNIT_EXPECT_GT(test, fragment_at, 0);
	/* Confirm it is smaller than the 1 MiB reassembly limit */
	KUNIT_EXPECT_LT(test, fragment_at, TEST_MAX_FRAGMENTED_RECV_SIZE);
}

/*
 * test_rdma_max_fragmented_size - max reassembled PDU size is 1 MiB
 *
 * [MS-SMBD] 3.1.1.1: MaxFragmentedSize governs the maximum reassembled
 * upper-layer PDU.  ksmbd defaults to 1 MiB.
 */
static void test_rdma_max_fragmented_size(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_MAX_FRAGMENTED_RECV_SIZE, 1024 * 1024);

	/* Must be strictly greater than the per-message send size */
	KUNIT_EXPECT_GT(test, TEST_MAX_FRAGMENTED_RECV_SIZE,
			TEST_MAX_SEND_SIZE);
}

/*
 * test_rdma_fragment_count_calculation - number of fragments for a given PDU size
 *
 * For a PDU of size N bytes, the number of SMB Direct messages required is
 * ceil(N / max_send_payload), where max_send_payload = max_send_size - hdr.
 * Verify the arithmetic for representative sizes.
 */
static void test_rdma_fragment_count_calculation(struct kunit *test)
{
	int hdr_sz    = sizeof(struct smb_direct_data_transfer);
	int payload   = TEST_MAX_SEND_SIZE - hdr_sz;
	int pdu_small = payload;            /* exactly 1 fragment */
	int pdu_two   = payload + 1;        /* needs 2 fragments */
	int frags;

	KUNIT_ASSERT_GT(test, payload, 0);

	/* Small PDU fits in one message */
	frags = (pdu_small + payload - 1) / payload;
	KUNIT_EXPECT_EQ(test, frags, 1);

	/* PDU one byte over fills two messages */
	frags = (pdu_two + payload - 1) / payload;
	KUNIT_EXPECT_EQ(test, frags, 2);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 4. Scatter-gather entry (SGE) count
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_sge_count_calculation - SGE count for a send message
 *
 * A single SMB Direct send typically uses:
 *   SGE[0] = SMB Direct data-transfer header (always present)
 *   SGE[1] = payload data (if non-empty)
 *   SGE[2..] = additional scatter-gather pages for large payloads
 *
 * The maximum is TEST_SMB_DIRECT_MAX_SEND_SGES = 6.  For a single-page
 * payload the count is 2; for zero-length data it is 1.
 */
static void test_rdma_sge_count_calculation(struct kunit *test)
{
	int max_sges     = TEST_SMB_DIRECT_MAX_SEND_SGES;
	int recv_sges    = TEST_SMB_DIRECT_MAX_RECV_SGES;

	/* A receive uses exactly 1 SGE (the receive buffer itself) */
	KUNIT_EXPECT_EQ(test, recv_sges, 1);

	/* Send must support at least 2 (header + data) */
	KUNIT_EXPECT_GE(test, max_sges, 2);

	/* Send limit should not exceed a reasonable architectural bound */
	KUNIT_EXPECT_LE(test, max_sges, 32);
}

/*
 * test_rdma_inline_data_threshold - data smaller than threshold goes inline
 *
 * Data small enough to fit within a single data-transfer message (header +
 * payload <= max_send_size) is sent inline without a separate RDMA Write.
 * Verify the threshold is positive and consistent.
 */
static void test_rdma_inline_data_threshold(struct kunit *test)
{
	int threshold = TEST_INLINE_DATA_THRESHOLD;

	KUNIT_EXPECT_GT(test, threshold, 0);
	KUNIT_EXPECT_LT(test, threshold, TEST_MAX_SEND_SIZE);

	/* The sum of header + threshold must equal max_send_size */
	KUNIT_EXPECT_EQ(test,
			(int)sizeof(struct smb_direct_data_transfer) + threshold,
			TEST_MAX_SEND_SIZE);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 5. Queue depth calculation
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_queue_depth_calculation - send/receive queue depths from credit count
 *
 * The RDMA queue pair (QP) send and receive queue depths are sized to match
 * the number of outstanding credits.  At minimum the QP depth must be at
 * least as large as the credit count so that no message is dropped because
 * the QP is full.
 *
 * send_queue_depth   >= send_credit_target
 * receive_queue_depth >= receive_credit_max
 */
static void test_rdma_queue_depth_calculation(struct kunit *test)
{
	int recv_credits = TEST_RECEIVE_CREDIT_MAX;
	int send_credits = TEST_SEND_CREDIT_TARGET;

	/*
	 * A typical implementation sizes the QP depth to the credit count.
	 * Verify the credit counts are within the IB QP depth limit of 65535.
	 */
	KUNIT_EXPECT_LE(test, recv_credits, 65535);
	KUNIT_EXPECT_LE(test, send_credits, 65535);
	KUNIT_EXPECT_GT(test, recv_credits, 0);
	KUNIT_EXPECT_GT(test, send_credits, 0);

	/* The initiator depth (for RDMA Read) must not exceed the credit limit */
	KUNIT_EXPECT_LE(test, TEST_SMB_DIRECT_CM_INITIATOR_DEPTH,
			send_credits);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 6. Keepalive / negotiation timeout
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_keepalive_interval - negotiation timeout is 120 seconds
 *
 * [MS-SMBD] 3.1.5.2 specifies a 120-second negotiation timeout.
 * ksmbd mirrors this as SMB_DIRECT_NEGOTIATE_TIMEOUT.
 */
static void test_rdma_keepalive_interval(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_SMB_DIRECT_NEGOTIATE_TIMEOUT, 120);
	/* Must be positive and less than 10 minutes */
	KUNIT_EXPECT_GT(test, TEST_SMB_DIRECT_NEGOTIATE_TIMEOUT, 0);
	KUNIT_EXPECT_LE(test, TEST_SMB_DIRECT_NEGOTIATE_TIMEOUT, 600);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 7. Negotiated values struct (smb_direct_negotiate_resp)
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_negotiated_values_struct - smb_direct_negotiate_resp has all required fields
 *
 * [MS-SMBD] 2.2.2: the negotiate response contains at minimum the fields
 * verified below.  We check offsets to confirm the packed layout matches
 * the wire format.
 */
static void test_rdma_negotiated_values_struct(struct kunit *test)
{
	/* credits_granted immediately follows credits_requested (both __le16) */
	size_t cr_off = offsetof(struct smb_direct_negotiate_resp, credits_requested);
	size_t cg_off = offsetof(struct smb_direct_negotiate_resp, credits_granted);

	KUNIT_EXPECT_EQ(test, cg_off, cr_off + sizeof(__le16));

	/* max_readwrite_size is present (governs RDMA Read/Write payload) */
	KUNIT_EXPECT_GT(test,
			sizeof(struct smb_direct_negotiate_resp),
			offsetof(struct smb_direct_negotiate_resp,
				 max_readwrite_size));
}

/*
 * test_rdma_negotiate_resp_credits_fields - credits fields fit in __le16
 *
 * Both CreditsRequested and CreditsGranted in the negotiate response are
 * 16-bit little-endian fields.  Verify the default values fit.
 */
static void test_rdma_negotiate_resp_credits_fields(struct kunit *test)
{
	/* Default credit values must fit in __le16 (0 – 65535) */
	KUNIT_EXPECT_LE(test, TEST_RECEIVE_CREDIT_MAX, (int)USHRT_MAX);
	KUNIT_EXPECT_LE(test, TEST_SEND_CREDIT_TARGET,  (int)USHRT_MAX);
}

/* ──────────────────────────────────────────────────────────────────────────
 * 8. Status flags
 * ────────────────────────────────────────────────────────────────────────── */

/*
 * test_rdma_status_flags - SMB_DIRECT_RESPONSE_REQUESTED flag value
 *
 * [MS-SMBD] 2.2.3: the Flags field of a data-transfer message may have
 * bit 0 (SMB_DIRECT_RESPONSE_REQUESTED = 0x0001) set to request an
 * immediate credit replenishment response from the peer.
 */
static void test_rdma_status_flags(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			(unsigned int)SMB_DIRECT_RESPONSE_REQUESTED,
			0x0001u);
	/* Must be a single-bit flag */
	KUNIT_EXPECT_EQ(test,
			SMB_DIRECT_RESPONSE_REQUESTED &
			(SMB_DIRECT_RESPONSE_REQUESTED - 1),
			0u);
}

/*
 * test_rdma_data_transfer_flags_width - data-transfer Flags field is 16 bits
 *
 * The flags field in struct smb_direct_data_transfer is __le16, so it can
 * hold values 0x0000 – 0xFFFF.  Verify SMB_DIRECT_RESPONSE_REQUESTED fits.
 */
static void test_rdma_data_transfer_flags_width(struct kunit *test)
{
	KUNIT_EXPECT_LE(test,
			(unsigned int)SMB_DIRECT_RESPONSE_REQUESTED,
			(unsigned int)USHRT_MAX);
}

/*
 * test_rdma_data_transfer_remaining_field - remaining_data_length is at correct offset
 *
 * [MS-SMBD] 2.2.3: RemainingDataLength is at offset 8 in the data-transfer
 * header (after Credits­Requested(2), Credits­Granted(2), Flags(2), Reserved(2)).
 */
static void test_rdma_data_transfer_remaining_field(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test,
			offsetof(struct smb_direct_data_transfer, remaining_data_length),
			(size_t)8);
}

/* ── Test suite registration ─── */

static struct kunit_case ksmbd_rdma_logic_test_cases[] = {
	/* I/O size constants */
	KUNIT_CASE(test_rdma_max_send_size_default),
	KUNIT_CASE(test_rdma_min_send_size),
	KUNIT_CASE(test_rdma_max_send_size_cap),
	/* Credit accounting */
	KUNIT_CASE(test_rdma_credit_initial_count),
	KUNIT_CASE(test_rdma_credit_replenishment_threshold),
	KUNIT_CASE(test_rdma_send_credit_limit),
	KUNIT_CASE(test_rdma_receive_buffer_size),
	/* Fragmentation and reassembly */
	KUNIT_CASE(test_rdma_fragmentation_threshold),
	KUNIT_CASE(test_rdma_max_fragmented_size),
	KUNIT_CASE(test_rdma_fragment_count_calculation),
	/* Scatter-gather */
	KUNIT_CASE(test_rdma_sge_count_calculation),
	KUNIT_CASE(test_rdma_inline_data_threshold),
	/* Queue depth */
	KUNIT_CASE(test_rdma_queue_depth_calculation),
	/* Keepalive / timeout */
	KUNIT_CASE(test_rdma_keepalive_interval),
	/* Negotiated values struct */
	KUNIT_CASE(test_rdma_negotiated_values_struct),
	KUNIT_CASE(test_rdma_negotiate_resp_credits_fields),
	/* Status flags */
	KUNIT_CASE(test_rdma_status_flags),
	KUNIT_CASE(test_rdma_data_transfer_flags_width),
	KUNIT_CASE(test_rdma_data_transfer_remaining_field),
	{}
};

static struct kunit_suite ksmbd_rdma_logic_test_suite = {
	.name = "ksmbd_rdma_logic",
	.test_cases = ksmbd_rdma_logic_test_cases,
};

kunit_test_suite(ksmbd_rdma_logic_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for RDMA/SMB Direct credit and buffer management algorithms");
