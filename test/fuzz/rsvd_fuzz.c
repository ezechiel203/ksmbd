// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for RSVD (Remote Shared Virtual Disk) tunnel operations
 *
 *   This module exercises the SVHDX tunnel header validation and SCSI
 *   operation passthrough parsing used in ksmbd's RSVD implementation.
 *
 *   Targets:
 *     - svhdx_tunnel_operation_header: OperationCode prefix validation,
 *       RequestId, Status
 *     - Per-opcode dispatch: GET_INITIAL_INFO, SCSI_OPERATION,
 *       CHECK_CONNECTION_STATUS, SRB_STATUS, GET_DISK_INFO, etc.
 *     - SCSI CDB passthrough: CDB length, DataTransferLength,
 *       SenseDataLength
 *
 *   Corpus seed hints:
 *     - Tunnel header: OperationCode=0x02001001 (GET_INITIAL_INFO),
 *       Status=0, RequestId=1
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SVHDX tunnel operation header (MS-RSVD 2.2.4.12) */
struct svhdx_tunnel_op_hdr {
	__le32 OperationCode;
	__le32 Status;
	__le64 RequestId;
} __packed;

#define SVHDX_HDR_SIZE		sizeof(struct svhdx_tunnel_op_hdr)

/* Operation codes (MS-RSVD 2.2.4.12) */
#define RSVD_TUNNEL_GET_INITIAL_INFO		0x02001001
#define RSVD_TUNNEL_SCSI			0x02001002
#define RSVD_TUNNEL_CHECK_CONNECTION_STATUS	0x02001003
#define RSVD_TUNNEL_SRB_STATUS			0x02001004
#define RSVD_TUNNEL_GET_DISK_INFO		0x02001005
#define RSVD_TUNNEL_VALIDATE_DISK		0x02001006
#define RSVD_TUNNEL_META_OPERATION_START	0x02002101
#define RSVD_TUNNEL_VHDSET_QUERY		0x02002005
#define RSVD_TUNNEL_DELETE_SNAPSHOT		0x02002501

/* SCSI operation (simplified) */
struct svhdx_tunnel_scsi_req {
	__le16 Length;
	__u8   Reserved1;
	__u8   CdbLength;
	__u8   SenseInfoExLength;
	__u8   DataIn;
	__u8   Reserved2;
	__u8   SrbFlags;
	__le32 DataTransferLength;
	__u8   CDB[16];
	/* Followed by SenseData and DataBuffer */
} __packed;

#define SCSI_REQ_SIZE		sizeof(struct svhdx_tunnel_scsi_req)
#define MAX_CDB_LENGTH		16
#define MAX_SENSE_LENGTH	252
#define MAX_TRANSFER_LENGTH	(1 * 1024 * 1024)

/*
 * fuzz_rsvd_tunnel_header - Fuzz SVHDX tunnel header validation
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_rsvd_tunnel_header(const u8 *data, size_t len)
{
	const struct svhdx_tunnel_op_hdr *hdr;
	u32 opcode;

	if (len < SVHDX_HDR_SIZE) {
		pr_debug("fuzz_rsvd: input too small (%zu)\n", len);
		return -EINVAL;
	}

	hdr = (const struct svhdx_tunnel_op_hdr *)data;
	opcode = le32_to_cpu(hdr->OperationCode);

	/* OperationCode must have 0x02 prefix byte */
	if ((opcode >> 24) != 0x02) {
		pr_debug("fuzz_rsvd: bad opcode prefix 0x%08x\n", opcode);
		return -EINVAL;
	}

	/* Dispatch to known opcodes */
	switch (opcode) {
	case RSVD_TUNNEL_GET_INITIAL_INFO:
		pr_debug("fuzz_rsvd: GET_INITIAL_INFO\n");
		break;
	case RSVD_TUNNEL_SCSI:
		pr_debug("fuzz_rsvd: SCSI\n");
		break;
	case RSVD_TUNNEL_CHECK_CONNECTION_STATUS:
		pr_debug("fuzz_rsvd: CHECK_CONNECTION_STATUS\n");
		break;
	case RSVD_TUNNEL_SRB_STATUS:
		pr_debug("fuzz_rsvd: SRB_STATUS\n");
		break;
	case RSVD_TUNNEL_GET_DISK_INFO:
		pr_debug("fuzz_rsvd: GET_DISK_INFO\n");
		break;
	case RSVD_TUNNEL_VALIDATE_DISK:
		pr_debug("fuzz_rsvd: VALIDATE_DISK\n");
		break;
	case RSVD_TUNNEL_META_OPERATION_START:
		pr_debug("fuzz_rsvd: META_OPERATION_START\n");
		break;
	case RSVD_TUNNEL_VHDSET_QUERY:
		pr_debug("fuzz_rsvd: VHDSET_QUERY\n");
		break;
	case RSVD_TUNNEL_DELETE_SNAPSHOT:
		pr_debug("fuzz_rsvd: DELETE_SNAPSHOT\n");
		break;
	default:
		pr_debug("fuzz_rsvd: unknown opcode 0x%08x\n", opcode);
		return -EINVAL;
	}

	pr_debug("fuzz_rsvd: status=%u request_id=%llu\n",
		 le32_to_cpu(hdr->Status),
		 le64_to_cpu(hdr->RequestId));

	return 0;
}

/*
 * fuzz_rsvd_scsi_operation - Fuzz SCSI operation input parsing
 * @data:	raw input after tunnel header
 * @len:	length of input
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_rsvd_scsi_operation(const u8 *data, size_t len)
{
	const struct svhdx_tunnel_scsi_req *req;
	u8 cdb_len;
	u8 sense_len;
	u32 xfer_len;

	if (len < SCSI_REQ_SIZE) {
		pr_debug("fuzz_rsvd_scsi: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct svhdx_tunnel_scsi_req *)data;
	cdb_len = req->CdbLength;
	sense_len = req->SenseInfoExLength;
	xfer_len = le32_to_cpu(req->DataTransferLength);

	/* CDB length validation */
	if (cdb_len > MAX_CDB_LENGTH) {
		pr_debug("fuzz_rsvd_scsi: CDB length %u > max %u\n",
			 cdb_len, MAX_CDB_LENGTH);
		return -EINVAL;
	}

	if (cdb_len == 0) {
		pr_debug("fuzz_rsvd_scsi: zero CDB length\n");
		return -EINVAL;
	}

	/* Sense data length */
	if (sense_len > MAX_SENSE_LENGTH) {
		pr_debug("fuzz_rsvd_scsi: sense length %u > max %u\n",
			 sense_len, MAX_SENSE_LENGTH);
		return -EINVAL;
	}

	/* Data transfer length */
	if (xfer_len > MAX_TRANSFER_LENGTH) {
		pr_debug("fuzz_rsvd_scsi: xfer length %u > max %u\n",
			 xfer_len, MAX_TRANSFER_LENGTH);
		return -EINVAL;
	}

	/* DataIn direction validation */
	if (req->DataIn > 2) {
		pr_debug("fuzz_rsvd_scsi: invalid DataIn %u\n", req->DataIn);
		return -EINVAL;
	}

	/* Check that data fits in buffer */
	if (SCSI_REQ_SIZE + xfer_len > len) {
		pr_debug("fuzz_rsvd_scsi: xfer data exceeds buffer\n");
		/* Not fatal for fuzzing */
	}

	pr_debug("fuzz_rsvd_scsi: cdb_len=%u sense=%u xfer=%u dir=%u\n",
		 cdb_len, sense_len, xfer_len, req->DataIn);

	return 0;
}

static int __init rsvd_fuzz_init(void)
{
	u8 *test_buf;
	struct svhdx_tunnel_op_hdr *hdr;
	int ret;

	pr_info("rsvd_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid GET_INITIAL_INFO */
	hdr = (struct svhdx_tunnel_op_hdr *)test_buf;
	hdr->OperationCode = cpu_to_le32(RSVD_TUNNEL_GET_INITIAL_INFO);
	hdr->Status = 0;
	hdr->RequestId = cpu_to_le64(1);
	ret = fuzz_rsvd_tunnel_header(test_buf, SVHDX_HDR_SIZE);
	pr_info("rsvd_fuzz: valid header returned %d\n", ret);

	/* Self-test 2: bad opcode prefix */
	hdr->OperationCode = cpu_to_le32(0x03001001);
	ret = fuzz_rsvd_tunnel_header(test_buf, SVHDX_HDR_SIZE);
	pr_info("rsvd_fuzz: bad prefix returned %d\n", ret);

	/* Self-test 3: SCSI operation */
	{
		struct svhdx_tunnel_scsi_req *scsi;

		memset(test_buf, 0, 256);
		scsi = (struct svhdx_tunnel_scsi_req *)test_buf;
		scsi->CdbLength = 6;
		scsi->SenseInfoExLength = 18;
		scsi->DataIn = 1;
		scsi->DataTransferLength = cpu_to_le32(512);
		scsi->CDB[0] = 0x28; /* READ(10) */

		ret = fuzz_rsvd_scsi_operation(test_buf, SCSI_REQ_SIZE + 512);
		pr_info("rsvd_fuzz: scsi valid returned %d\n", ret);
	}

	/* Self-test 4: oversized CDB */
	{
		struct svhdx_tunnel_scsi_req *scsi;

		memset(test_buf, 0, 256);
		scsi = (struct svhdx_tunnel_scsi_req *)test_buf;
		scsi->CdbLength = 32;
		ret = fuzz_rsvd_scsi_operation(test_buf, SCSI_REQ_SIZE);
		pr_info("rsvd_fuzz: oversized CDB returned %d\n", ret);
	}

	/* Self-test 5: truncated */
	ret = fuzz_rsvd_tunnel_header(test_buf, 4);
	pr_info("rsvd_fuzz: truncated returned %d\n", ret);

	/* Self-test 6: garbage */
	memset(test_buf, 0xFF, 256);
	ret = fuzz_rsvd_tunnel_header(test_buf, 256);
	pr_info("rsvd_fuzz: garbage returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit rsvd_fuzz_exit(void)
{
	pr_info("rsvd_fuzz: module unloaded\n");
}

module_init(rsvd_fuzz_init);
module_exit(rsvd_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for RSVD/SVHDX tunnel operations");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
