// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB Direct (RDMA) negotiate request parsing
 *
 *   This module exercises the SMB Direct negotiate request message
 *   parsing as defined in [MS-SMBD] Section 2.2.1. The negotiate
 *   request is the first message received on an RDMA connection and
 *   is parsed before any authentication. Malformed negotiate requests
 *   can lead to denial-of-service through excessively small buffer
 *   sizes, integer overflows in size calculations, or connection state
 *   corruption.
 *
 *   Targets:
 *     - smb_direct_check_recvmsg() version and credit validation
 *     - smb_direct_prepare() buffer size negotiation:
 *       - preferred_send_size / max_receive_size clamping
 *       - max_fragmented_size minimum enforcement
 *       - min_version / max_version range validation
 *       - credits_requested validation
 *     - Data transfer header parsing:
 *       - data_offset + data_length bounds check
 *       - remaining_data_length overflow
 *       - credits_requested / credits_granted in transfer context
 *     - Response generation with negotiated parameters
 *
 *   Corpus seed hints:
 *     - Negotiate req: min_version=0x0100, max_version=0x0100,
 *       credits_requested=10, preferred_send_size=8192,
 *       max_receive_size=8192, max_fragmented_size=1048576
 *     - Data transfer: credits_requested=10, credits_granted=0,
 *       flags=SMB_DIRECT_RESPONSE_REQUESTED, data_offset=24,
 *       data_length=N, remaining_data_length=0
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB Direct negotiation request [MS-SMBD] 2.2.1 */
struct smb_direct_neg_req_fuzz {
	__le16 min_version;
	__le16 max_version;
	__le16 reserved;
	__le16 credits_requested;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

/* SMB Direct negotiation response [MS-SMBD] 2.2.2 */
struct smb_direct_neg_resp_fuzz {
	__le16 min_version;
	__le16 max_version;
	__le16 negotiated_version;
	__le16 reserved;
	__le16 credits_requested;
	__le16 credits_granted;
	__le32 status;
	__le32 max_readwrite_size;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

/* SMB Direct data transfer [MS-SMBD] 2.2.3 */
struct smb_direct_data_xfer_fuzz {
	__le16 credits_requested;
	__le16 credits_granted;
	__le16 flags;
	__le16 reserved;
	__le32 remaining_data_length;
	__le32 data_offset;
	__le32 data_length;
	__le32 padding;
	__u8   buffer[];
} __packed;

#define SMB_DIRECT_RESPONSE_REQUESTED	0x0001
#define SMB_DIRECT_VERSION_LE		0x0100

/* Server-side defaults matching transport_rdma.c */
#define SMBD_DEFAULT_MAX_SEND_SIZE	8192
#define SMBD_DEFAULT_MAX_RECV_SIZE	8192
#define SMBD_DEFAULT_MAX_FRAG_SIZE	(1024 * 1024)
#define SMBD_MIN_BUFFER_SIZE		8192
#define SMBD_MIN_FRAG_SIZE		(128 * 1024)
#define SMBD_DEFAULT_CREDITS		255
#define SMBD_MAX_IOSIZE			(16 * 1024 * 1024)
#define SMBD_MIN_IOSIZE			(512 * 1024)

/*
 * fuzz_rdma_negotiate_validate - Validate RDMA negotiate request fields
 * @data:	raw request bytes
 * @len:	length of received data (from wc->byte_len in RDMA)
 *
 * Mirrors smb_direct_check_recvmsg() for the NEGOTIATE_REQ message type.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_rdma_negotiate_validate(const u8 *data, size_t len)
{
	const struct smb_direct_neg_req_fuzz *req;
	u16 min_ver, max_ver, credits;
	u32 preferred_send, max_recv, max_frag;

	/* Check minimum message size */
	if (len < sizeof(struct smb_direct_neg_req_fuzz)) {
		pr_debug("fuzz_rdma: negotiate too short (%zu < %zu)\n",
			 len, sizeof(struct smb_direct_neg_req_fuzz));
		return -EINVAL;
	}

	req = (const struct smb_direct_neg_req_fuzz *)data;

	min_ver = le16_to_cpu(req->min_version);
	max_ver = le16_to_cpu(req->max_version);
	credits = le16_to_cpu(req->credits_requested);
	preferred_send = le32_to_cpu(req->preferred_send_size);
	max_recv = le32_to_cpu(req->max_receive_size);
	max_frag = le32_to_cpu(req->max_fragmented_size);

	pr_debug("fuzz_rdma: min_ver=0x%04x max_ver=0x%04x credits=%u "
		 "send=%u recv=%u frag=%u\n",
		 min_ver, max_ver, credits, preferred_send, max_recv, max_frag);

	/* Version range must include 0x0100 */
	if (min_ver > SMB_DIRECT_VERSION_LE) {
		pr_debug("fuzz_rdma: min_version 0x%04x > supported 0x0100\n",
			 min_ver);
		return -EOPNOTSUPP;
	}

	if (max_ver < SMB_DIRECT_VERSION_LE) {
		pr_debug("fuzz_rdma: max_version 0x%04x < supported 0x0100\n",
			 max_ver);
		return -EOPNOTSUPP;
	}

	/* min_version must not exceed max_version */
	if (min_ver > max_ver) {
		pr_debug("fuzz_rdma: min_version 0x%04x > max_version 0x%04x\n",
			 min_ver, max_ver);
		return -EINVAL;
	}

	/* Credits must be positive */
	if (credits == 0) {
		pr_debug("fuzz_rdma: zero credits_requested\n");
		return -ECONNABORTED;
	}

	/* Buffer sizes must be reasonable */
	if (max_recv <= 128) {
		pr_debug("fuzz_rdma: max_receive_size %u <= 128\n", max_recv);
		return -ECONNABORTED;
	}

	if (max_frag <= SMBD_MIN_FRAG_SIZE) {
		pr_debug("fuzz_rdma: max_fragmented_size %u <= %u\n",
			 max_frag, SMBD_MIN_FRAG_SIZE);
		return -ECONNABORTED;
	}

	return 0;
}

/*
 * fuzz_rdma_negotiate_params - Simulate server-side parameter negotiation
 * @data:	raw request bytes
 * @len:	length of received data
 *
 * Mirrors the parameter clamping logic in smb_direct_prepare().
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_rdma_negotiate_params(const u8 *data, size_t len)
{
	const struct smb_direct_neg_req_fuzz *req;
	u32 server_max_recv, server_max_send;
	u32 negotiated_recv, negotiated_send, negotiated_frag;
	int ret;

	ret = fuzz_rdma_negotiate_validate(data, len);
	if (ret < 0)
		return ret;

	req = (const struct smb_direct_neg_req_fuzz *)data;

	server_max_recv = SMBD_DEFAULT_MAX_RECV_SIZE;
	server_max_send = SMBD_DEFAULT_MAX_SEND_SIZE;

	/*
	 * Negotiate buffer sizes:
	 * server_recv = min(server_max_recv, client_preferred_send)
	 * server_send = min(server_max_send, client_max_recv)
	 */
	negotiated_recv = min_t(u32, server_max_recv,
				le32_to_cpu(req->preferred_send_size));
	negotiated_send = min_t(u32, server_max_send,
				le32_to_cpu(req->max_receive_size));

	/* Enforce minimum buffer sizes (DoS protection) */
	if (negotiated_recv < SMBD_MIN_BUFFER_SIZE) {
		pr_debug("fuzz_rdma: negotiated recv %u < min %u\n",
			 negotiated_recv, SMBD_MIN_BUFFER_SIZE);
		return -ECONNABORTED;
	}

	if (negotiated_send < SMBD_MIN_BUFFER_SIZE) {
		pr_debug("fuzz_rdma: negotiated send %u < min %u\n",
			 negotiated_send, SMBD_MIN_BUFFER_SIZE);
		return -ECONNABORTED;
	}

	/* Negotiate fragmented size */
	negotiated_frag = le32_to_cpu(req->max_fragmented_size);
	if (negotiated_frag == 0)
		negotiated_frag = SMBD_DEFAULT_MAX_FRAG_SIZE;
	else if (negotiated_frag < SMBD_MIN_FRAG_SIZE)
		negotiated_frag = SMBD_MIN_FRAG_SIZE;

	pr_debug("fuzz_rdma: negotiated recv=%u send=%u frag=%u\n",
		 negotiated_recv, negotiated_send, negotiated_frag);

	/* Verify max_readwrite_size calculation would not overflow */
	{
		u64 recv_credit_max = SMBD_DEFAULT_CREDITS;
		u64 max_rw = recv_credit_max * negotiated_recv;

		if (max_rw > SMBD_MAX_IOSIZE)
			max_rw = SMBD_MAX_IOSIZE;
		if (max_rw < SMBD_MIN_IOSIZE)
			max_rw = SMBD_MIN_IOSIZE;

		pr_debug("fuzz_rdma: max_readwrite_size=%llu\n", max_rw);
	}

	return 0;
}

/*
 * fuzz_rdma_data_transfer - Fuzz SMB Direct data transfer header parsing
 * @data:	raw received data
 * @len:	length of received data (wc->byte_len equivalent)
 *
 * Mirrors the DATA_TRANSFER case in recv_done() and the subsequent
 * bounds checking on data_offset, data_length, and remaining_data_length.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_rdma_data_transfer(const u8 *data, size_t len)
{
	const struct smb_direct_data_xfer_fuzz *xfer;
	u32 remaining, data_offset, data_length;
	u16 credits_req, credits_grant, flags;

	/* Minimum: must contain the fixed header (before buffer[]) */
	if (len < offsetof(struct smb_direct_data_xfer_fuzz, buffer)) {
		pr_debug("fuzz_rdma: data transfer too short (%zu)\n", len);
		return -EINVAL;
	}

	xfer = (const struct smb_direct_data_xfer_fuzz *)data;

	credits_req = le16_to_cpu(xfer->credits_requested);
	credits_grant = le16_to_cpu(xfer->credits_granted);
	flags = le16_to_cpu(xfer->flags);
	remaining = le32_to_cpu(xfer->remaining_data_length);
	data_offset = le32_to_cpu(xfer->data_offset);
	data_length = le32_to_cpu(xfer->data_length);

	pr_debug("fuzz_rdma: xfer credits_req=%u credits_grant=%u flags=0x%04x "
		 "remaining=%u offset=%u length=%u\n",
		 credits_req, credits_grant, flags,
		 remaining, data_offset, data_length);

	/* Validate data_offset does not exceed message length */
	if (data_offset > len) {
		pr_debug("fuzz_rdma: data_offset %u > message len %zu\n",
			 data_offset, len);
		return -EINVAL;
	}

	/* Validate data_offset + data_length does not overflow or exceed len */
	if ((u64)data_offset + data_length > len) {
		pr_debug("fuzz_rdma: data_offset+length %u+%u > message len %zu\n",
			 data_offset, data_length, len);
		return -EINVAL;
	}

	/* Validate remaining + data does not exceed max fragmented size */
	if ((u64)remaining + data_length > SMBD_DEFAULT_MAX_FRAG_SIZE) {
		pr_debug("fuzz_rdma: remaining+data %u+%u > max frag %u\n",
			 remaining, data_length, SMBD_DEFAULT_MAX_FRAG_SIZE);
		return -EINVAL;
	}

	/* Validate remaining_data_length is reasonable */
	if (remaining > SMBD_DEFAULT_MAX_FRAG_SIZE) {
		pr_debug("fuzz_rdma: remaining_data_length %u > max frag\n",
			 remaining);
		return -EINVAL;
	}

	/* data_length alone should not exceed max_frag */
	if (data_length > SMBD_DEFAULT_MAX_FRAG_SIZE) {
		pr_debug("fuzz_rdma: data_length %u > max frag\n", data_length);
		return -EINVAL;
	}

	/* SMB_DIRECT_RESPONSE_REQUESTED flag validation */
	if (flags & SMB_DIRECT_RESPONSE_REQUESTED) {
		pr_debug("fuzz_rdma: response requested\n");
	}

	/* Unknown flags */
	if (flags & ~SMB_DIRECT_RESPONSE_REQUESTED) {
		pr_debug("fuzz_rdma: unknown flags 0x%04x\n",
			 flags & ~SMB_DIRECT_RESPONSE_REQUESTED);
	}

	return 0;
}

static int __init rdma_negotiate_fuzz_init(void)
{
	u8 *test_buf;
	struct smb_direct_neg_req_fuzz *req;
	struct smb_direct_data_xfer_fuzz *xfer;
	int ret;

	pr_info("rdma_negotiate_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid negotiate request */
	req = (struct smb_direct_neg_req_fuzz *)test_buf;
	req->min_version = cpu_to_le16(0x0100);
	req->max_version = cpu_to_le16(0x0100);
	req->credits_requested = cpu_to_le16(10);
	req->preferred_send_size = cpu_to_le32(8192);
	req->max_receive_size = cpu_to_le32(8192);
	req->max_fragmented_size = cpu_to_le32(1048576);

	ret = fuzz_rdma_negotiate_params(test_buf,
					 sizeof(struct smb_direct_neg_req_fuzz));
	pr_info("rdma_negotiate_fuzz: valid negotiate returned %d\n", ret);

	/* Self-test 2: truncated request */
	ret = fuzz_rdma_negotiate_validate(test_buf, 4);
	pr_info("rdma_negotiate_fuzz: truncated test returned %d\n", ret);

	/* Self-test 3: version mismatch (too high) */
	memset(test_buf, 0, 512);
	req = (struct smb_direct_neg_req_fuzz *)test_buf;
	req->min_version = cpu_to_le16(0x0200);
	req->max_version = cpu_to_le16(0x0300);
	req->credits_requested = cpu_to_le16(10);
	req->preferred_send_size = cpu_to_le32(8192);
	req->max_receive_size = cpu_to_le32(8192);
	req->max_fragmented_size = cpu_to_le32(1048576);

	ret = fuzz_rdma_negotiate_validate(test_buf,
					   sizeof(struct smb_direct_neg_req_fuzz));
	pr_info("rdma_negotiate_fuzz: version too high returned %d\n", ret);

	/* Self-test 4: zero credits */
	memset(test_buf, 0, 512);
	req = (struct smb_direct_neg_req_fuzz *)test_buf;
	req->min_version = cpu_to_le16(0x0100);
	req->max_version = cpu_to_le16(0x0100);
	req->credits_requested = cpu_to_le16(0);
	req->preferred_send_size = cpu_to_le32(8192);
	req->max_receive_size = cpu_to_le32(8192);
	req->max_fragmented_size = cpu_to_le32(1048576);

	ret = fuzz_rdma_negotiate_validate(test_buf,
					   sizeof(struct smb_direct_neg_req_fuzz));
	pr_info("rdma_negotiate_fuzz: zero credits returned %d\n", ret);

	/* Self-test 5: pathologically small buffer sizes (DoS vector) */
	memset(test_buf, 0, 512);
	req = (struct smb_direct_neg_req_fuzz *)test_buf;
	req->min_version = cpu_to_le16(0x0100);
	req->max_version = cpu_to_le16(0x0100);
	req->credits_requested = cpu_to_le16(1);
	req->preferred_send_size = cpu_to_le32(1);
	req->max_receive_size = cpu_to_le32(1);
	req->max_fragmented_size = cpu_to_le32(1);

	ret = fuzz_rdma_negotiate_params(test_buf,
					 sizeof(struct smb_direct_neg_req_fuzz));
	pr_info("rdma_negotiate_fuzz: tiny buffers returned %d\n", ret);

	/* Self-test 6: maximum buffer sizes (overflow potential) */
	memset(test_buf, 0, 512);
	req = (struct smb_direct_neg_req_fuzz *)test_buf;
	req->min_version = cpu_to_le16(0x0100);
	req->max_version = cpu_to_le16(0x0100);
	req->credits_requested = cpu_to_le16(0xFFFF);
	req->preferred_send_size = cpu_to_le32(0xFFFFFFFF);
	req->max_receive_size = cpu_to_le32(0xFFFFFFFF);
	req->max_fragmented_size = cpu_to_le32(0xFFFFFFFF);

	ret = fuzz_rdma_negotiate_params(test_buf,
					 sizeof(struct smb_direct_neg_req_fuzz));
	pr_info("rdma_negotiate_fuzz: max values returned %d\n", ret);

	/* Self-test 7: valid data transfer header */
	memset(test_buf, 0, 512);
	xfer = (struct smb_direct_data_xfer_fuzz *)test_buf;
	xfer->credits_requested = cpu_to_le16(10);
	xfer->credits_granted = cpu_to_le16(5);
	xfer->flags = cpu_to_le16(SMB_DIRECT_RESPONSE_REQUESTED);
	xfer->data_offset = cpu_to_le32(
		offsetof(struct smb_direct_data_xfer_fuzz, buffer));
	xfer->data_length = cpu_to_le32(64);
	xfer->remaining_data_length = 0;
	memset(xfer->buffer, 0xAA, 64);

	ret = fuzz_rdma_data_transfer(test_buf,
		offsetof(struct smb_direct_data_xfer_fuzz, buffer) + 64);
	pr_info("rdma_negotiate_fuzz: valid data transfer returned %d\n", ret);

	/* Self-test 8: data transfer with overflow data_offset */
	memset(test_buf, 0, 512);
	xfer = (struct smb_direct_data_xfer_fuzz *)test_buf;
	xfer->credits_requested = cpu_to_le16(1);
	xfer->data_offset = cpu_to_le32(0xFFFFFFF0);
	xfer->data_length = cpu_to_le32(100);

	ret = fuzz_rdma_data_transfer(test_buf,
		offsetof(struct smb_direct_data_xfer_fuzz, buffer));
	pr_info("rdma_negotiate_fuzz: oob data_offset returned %d\n", ret);

	/* Self-test 9: data transfer with huge remaining */
	memset(test_buf, 0, 512);
	xfer = (struct smb_direct_data_xfer_fuzz *)test_buf;
	xfer->credits_requested = cpu_to_le16(1);
	xfer->data_offset = cpu_to_le32(
		offsetof(struct smb_direct_data_xfer_fuzz, buffer));
	xfer->data_length = cpu_to_le32(10);
	xfer->remaining_data_length = cpu_to_le32(0xFFFFFFFF);

	ret = fuzz_rdma_data_transfer(test_buf,
		offsetof(struct smb_direct_data_xfer_fuzz, buffer) + 10);
	pr_info("rdma_negotiate_fuzz: huge remaining returned %d\n", ret);

	/* Self-test 10: garbage data */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_rdma_negotiate_validate(test_buf, 512);
	pr_info("rdma_negotiate_fuzz: garbage negotiate returned %d\n", ret);
	ret = fuzz_rdma_data_transfer(test_buf, 512);
	pr_info("rdma_negotiate_fuzz: garbage transfer returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit rdma_negotiate_fuzz_exit(void)
{
	pr_info("rdma_negotiate_fuzz: module unloaded\n");
}

module_init(rdma_negotiate_fuzz_init);
module_exit(rdma_negotiate_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB Direct (RDMA) negotiate request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
