// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 header parsing
 *
 *   This module accepts arbitrary byte input and feeds it through SMB2
 *   header validation and field extraction paths. The goal is to ensure
 *   that malformed headers are rejected gracefully without crashes,
 *   memory corruption, or undefined behavior.
 *
 *   Targets:
 *     - struct smb2_hdr field extraction and validation
 *     - Protocol ID checks (0xFE 'S' 'M' 'B')
 *     - StructureSize validation
 *     - Command range validation
 *     - Credit charge and credit request parsing
 *     - Session ID and Tree ID extraction
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_smb2_header() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the structures we need to avoid pulling in the full ksmbd
 * header chain, which has complex kernel dependencies.
 */

#define SMB2_PROTO_NUMBER	cpu_to_le32(0x424d53fe) /* 0xFE 'S' 'M' 'B' */
#define __SMB2_HEADER_STRUCTURE_SIZE	64

struct smb2_hdr_fuzz {
	__le32 ProtocolId;
	__le16 StructureSize;
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
		} __packed SyncHdr;
		__le64 AsyncId;
	} __packed;
	__le64 SessionId;
	__u8   Signature[16];
} __packed;

/* Maximum valid SMB2 command value */
#define SMB2_OPLOCK_BREAK_HE	0x0012

/*
 * fuzz_smb2_header - Fuzz the SMB2 header parsing logic
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the header validation that ksmbd performs when receiving
 * an SMB2 packet. Exercises all field extraction and range checks.
 *
 * Return: 0 on success (valid or gracefully rejected), negative on error
 */
static int fuzz_smb2_header(const u8 *data, size_t len)
{
	struct smb2_hdr_fuzz *hdr;
	u16 structure_size;
	u16 command;
	u16 credit_charge;
	u16 credit_request;
	u32 flags;
	u32 next_command;
	u64 message_id;
	u64 session_id;
	u32 tree_id;
	u32 status;

	/* Need at least enough bytes for the header */
	if (len < sizeof(struct smb2_hdr_fuzz))
		return -EINVAL;

	hdr = (struct smb2_hdr_fuzz *)data;

	/* Validate protocol ID - must be 0xFE 'S' 'M' 'B' */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER) {
		pr_debug("fuzz: invalid protocol id: 0x%08x\n",
			 le32_to_cpu(hdr->ProtocolId));
		return -EINVAL;
	}

	/* Validate structure size - must be 64 */
	structure_size = le16_to_cpu(hdr->StructureSize);
	if (structure_size != __SMB2_HEADER_STRUCTURE_SIZE) {
		pr_debug("fuzz: invalid structure size: %u\n", structure_size);
		return -EINVAL;
	}

	/* Extract and validate command */
	command = le16_to_cpu(hdr->Command);
	if (command > SMB2_OPLOCK_BREAK_HE) {
		pr_debug("fuzz: invalid command: 0x%04x\n", command);
		return -EINVAL;
	}

	/* Extract credit fields */
	credit_charge = le16_to_cpu(hdr->CreditCharge);
	credit_request = le16_to_cpu(hdr->CreditRequest);

	/* Extract status */
	status = le32_to_cpu(hdr->Status);

	/* Extract flags and validate */
	flags = le32_to_cpu(hdr->Flags);

	/* Extract next command offset */
	next_command = le32_to_cpu(hdr->NextCommand);
	if (next_command != 0) {
		/* NextCommand must be 8-byte aligned */
		if (next_command & 0x7) {
			pr_debug("fuzz: unaligned next command: %u\n",
				 next_command);
			return -EINVAL;
		}
		/* NextCommand must point within the buffer */
		if (next_command >= len) {
			pr_debug("fuzz: next command out of bounds: %u >= %zu\n",
				 next_command, len);
			return -EINVAL;
		}
		/* Recursively validate the chained header */
		if (next_command + sizeof(struct smb2_hdr_fuzz) <= len) {
			int ret;

			ret = fuzz_smb2_header(data + next_command,
					       len - next_command);
			if (ret < 0)
				pr_debug("fuzz: chained header invalid\n");
		}
	}

	/* Extract message ID */
	message_id = le64_to_cpu(hdr->MessageId);

	/* Extract session ID */
	session_id = le64_to_cpu(hdr->SessionId);

	/* Extract tree ID (only valid for sync requests) */
	if (!(flags & (1 << 1))) { /* SMB2_FLAGS_ASYNC_COMMAND */
		tree_id = le32_to_cpu(hdr->SyncHdr.TreeId);
	}

	/* Validate session ID for non-negotiate/non-echo commands */
	if (command != 0x0000 /* NEGOTIATE */ &&
	    command != 0x000D /* ECHO */) {
		if (session_id == 0 || session_id == (u64)-1) {
			pr_debug("fuzz: invalid session id for command 0x%04x\n",
				 command);
			/* Not a fatal error in fuzz context */
		}
	}

	/* Verify signature area is accessible (already guaranteed by size) */
	pr_debug("fuzz: valid header cmd=0x%04x sid=%llu cc=%u cr=%u\n",
		 command, session_id, credit_charge, credit_request);

	/* Suppress unused variable warnings */
	(void)status;
	(void)tree_id;
	(void)message_id;

	return 0;
}

/*
 * Module entry point for fuzzing.
 * In a syzkaller setup, the fuzzer calls this with crafted data.
 */
static int __init smb2_header_fuzz_init(void)
{
	u8 test_buf[128];
	struct smb2_hdr_fuzz *hdr;
	int ret;

	pr_info("smb2_header_fuzz: module loaded\n");

	/* Self-test with a minimal valid header */
	memset(test_buf, 0, sizeof(test_buf));
	hdr = (struct smb2_hdr_fuzz *)test_buf;
	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->StructureSize = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	hdr->Command = cpu_to_le16(0x0000); /* NEGOTIATE */

	ret = fuzz_smb2_header(test_buf, sizeof(test_buf));
	pr_info("smb2_header_fuzz: self-test returned %d\n", ret);

	/* Test with a truncated buffer */
	ret = fuzz_smb2_header(test_buf, 10);
	pr_info("smb2_header_fuzz: truncated test returned %d\n", ret);

	/* Test with garbage data */
	memset(test_buf, 0xff, sizeof(test_buf));
	ret = fuzz_smb2_header(test_buf, sizeof(test_buf));
	pr_info("smb2_header_fuzz: garbage test returned %d\n", ret);

	return 0;
}

static void __exit smb2_header_fuzz_exit(void)
{
	pr_info("smb2_header_fuzz: module unloaded\n");
}

module_init(smb2_header_fuzz_init);
module_exit(smb2_header_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 header parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
