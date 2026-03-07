// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 CANCEL request parsing
 *
 *   This module exercises the SMB2 CANCEL request header validation
 *   including StructureSize, Flags (SMB2_FLAGS_ASYNC_COMMAND),
 *   MessageId matching, and AsyncId extraction.
 *
 *   The CANCEL command is unique among SMB2 commands:
 *     - StructureSize is only 4 (smallest of all SMB2 commands)
 *     - No response is sent (send_no_response = 1)
 *     - Not signed (excluded from signing requirement)
 *     - Not added to the request queue (prevents deadlock)
 *     - Can match by AsyncId (async path) or MessageId (sync path)
 *     - MessageId=0 fallback matches by SessionId
 *
 *   Targets:
 *     - StructureSize validation (must be 4)
 *     - SMB2_FLAGS_ASYNC_COMMAND flag dispatch
 *     - AsyncId extraction for async cancel
 *     - MessageId matching for sync cancel
 *     - MessageId=0 SessionId fallback path
 *     - Compound chain cancel (next_smb2_rcv_hdr_off != 0)
 *
 *   Corpus seed hints:
 *     - CANCEL req: StructureSize=4, Flags=0 (sync), MessageId=N
 *     - CANCEL req: StructureSize=4, Flags=SMB2_FLAGS_ASYNC_COMMAND,
 *       AsyncId=N
 *     - CANCEL req in compound: NextCommand offset, related flag
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 header for cancel request context */
struct smb2_hdr_cancel_fuzz {
	__le32 ProtocolId;	/* 0xFE 'S' 'M' 'B' */
	__le16 StructureSize;	/* Must be 64 */
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
	} __packed Id;
	__le64 SessionId;
	__u8   Signature[16];
} __packed;

/* SMB2 CANCEL request body */
struct smb2_cancel_req_fuzz {
	__le16 StructureSize;	/* Must be 4 */
	__le16 Reserved;
} __packed;

#define SMB2_PROTO_NUMBER_FUZZ		cpu_to_le32(0x424d53fe)
#define SMB2_HDR_STRUCTURE_SIZE		64
#define CANCEL_STRUCTURE_SIZE		4
#define SMB2_CANCEL_COMMAND		cpu_to_le16(0x000C)

/* Flags */
#define SMB2_FLAGS_SERVER_TO_REDIR	cpu_to_le32(0x00000001)
#define SMB2_FLAGS_ASYNC_COMMAND	cpu_to_le32(0x00000002)
#define SMB2_FLAGS_RELATED_OPS		cpu_to_le32(0x00000004)
#define SMB2_FLAGS_SIGNED		cpu_to_le32(0x00000008)

/*
 * fuzz_cancel_request - Fuzz SMB2 CANCEL request header + body
 * @data:	raw input (SMB2 header + CANCEL body)
 * @len:	length of input
 *
 * Validates the SMB2 header fields relevant to CANCEL and the
 * minimal 4-byte CANCEL body.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_cancel_request(const u8 *data, size_t len)
{
	const struct smb2_hdr_cancel_fuzz *hdr;
	const struct smb2_cancel_req_fuzz *req;
	u16 hdr_structure_size;
	u16 cancel_structure_size;
	u32 flags;
	u64 message_id;
	u64 session_id;
	size_t total_min;

	total_min = sizeof(struct smb2_hdr_cancel_fuzz) +
		    sizeof(struct smb2_cancel_req_fuzz);

	if (len < total_min) {
		pr_debug("fuzz_cancel: input too small (%zu < %zu)\n",
			 len, total_min);
		return -EINVAL;
	}

	hdr = (const struct smb2_hdr_cancel_fuzz *)data;

	/* Validate protocol ID */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER_FUZZ) {
		pr_debug("fuzz_cancel: bad protocol id 0x%08x\n",
			 le32_to_cpu(hdr->ProtocolId));
		return -EINVAL;
	}

	/* Validate header structure size */
	hdr_structure_size = le16_to_cpu(hdr->StructureSize);
	if (hdr_structure_size != SMB2_HDR_STRUCTURE_SIZE) {
		pr_debug("fuzz_cancel: bad hdr structure size %u\n",
			 hdr_structure_size);
		return -EINVAL;
	}

	/* Validate command is CANCEL */
	if (hdr->Command != SMB2_CANCEL_COMMAND) {
		pr_debug("fuzz_cancel: command 0x%04x != CANCEL\n",
			 le16_to_cpu(hdr->Command));
		return -EINVAL;
	}

	flags = le32_to_cpu(hdr->Flags);
	message_id = le64_to_cpu(hdr->MessageId);
	session_id = le64_to_cpu(hdr->SessionId);

	/* CANCEL must not have SERVER_TO_REDIR flag (it is a request) */
	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR) {
		pr_debug("fuzz_cancel: server-to-redir flag on request\n");
		return -EINVAL;
	}

	/*
	 * CANCEL should never be signed per MS-SMB2 section 3.2.4.24:
	 * "The client MUST NOT sign the SMB2 CANCEL request."
	 * However, we accept it gracefully; the server just skips
	 * signature verification for CANCEL.
	 */
	if (hdr->Flags & SMB2_FLAGS_SIGNED) {
		pr_debug("fuzz_cancel: signed flag set (unusual but accepted)\n");
	}

	/* Parse cancel body */
	req = (const struct smb2_cancel_req_fuzz *)
	      (data + sizeof(struct smb2_hdr_cancel_fuzz));
	cancel_structure_size = le16_to_cpu(req->StructureSize);

	if (cancel_structure_size != CANCEL_STRUCTURE_SIZE) {
		pr_debug("fuzz_cancel: bad cancel structure size %u\n",
			 cancel_structure_size);
		return -EINVAL;
	}

	/* Dispatch based on async vs sync */
	if (hdr->Flags & SMB2_FLAGS_ASYNC_COMMAND) {
		u64 async_id = le64_to_cpu(hdr->Id.AsyncId);

		pr_debug("fuzz_cancel: async cancel async_id=%llu sid=%llu\n",
			 async_id, session_id);

		/* AsyncId of 0 is suspicious */
		if (async_id == 0)
			pr_debug("fuzz_cancel: zero AsyncId in async cancel\n");
	} else {
		u32 tree_id = le32_to_cpu(hdr->Id.SyncHdr.TreeId);

		pr_debug("fuzz_cancel: sync cancel mid=%llu sid=%llu tid=%u\n",
			 message_id, session_id, tree_id);

		/*
		 * MessageId=0 is valid for CANCEL: the client may send
		 * a cancel before receiving the interim response that
		 * assigns an AsyncId. In this case, the server matches
		 * by SessionId instead.
		 */
		if (message_id == 0) {
			pr_debug("fuzz_cancel: mid=0, will match by SessionId\n");
			if (session_id == 0)
				pr_debug("fuzz_cancel: mid=0 and sid=0 is unresolvable\n");
		}
	}

	/* CANCEL must not be compounded per MS-SMB2 3.2.4.24 */
	if (hdr->NextCommand != 0) {
		pr_debug("fuzz_cancel: NextCommand=%u (should be 0)\n",
			 le32_to_cpu(hdr->NextCommand));
	}

	/* CreditCharge should be 0 for CANCEL */
	if (hdr->CreditCharge != 0)
		pr_debug("fuzz_cancel: non-zero CreditCharge %u\n",
			 le16_to_cpu(hdr->CreditCharge));

	return 0;
}

/*
 * fuzz_cancel_body_only - Fuzz just the 4-byte CANCEL body
 * @data:	raw input (just the body, no header)
 * @len:	length of input
 *
 * Tests the minimal body parsing in isolation.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_cancel_body_only(const u8 *data, size_t len)
{
	const struct smb2_cancel_req_fuzz *req;
	u16 structure_size;

	if (len < sizeof(struct smb2_cancel_req_fuzz)) {
		pr_debug("fuzz_cancel_body: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_cancel_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);

	if (structure_size != CANCEL_STRUCTURE_SIZE) {
		pr_debug("fuzz_cancel_body: bad structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Reserved should be zero */
	if (req->Reserved != 0)
		pr_debug("fuzz_cancel_body: non-zero Reserved 0x%04x\n",
			 le16_to_cpu(req->Reserved));

	return 0;
}

/*
 * fuzz_cancel_compound - Fuzz CANCEL as part of a compound chain
 * @data:	raw compound chain (multiple SMB2 header+body pairs)
 * @len:	total chain length
 *
 * Walks a compound chain looking for CANCEL commands.
 * Per MS-SMB2 3.2.4.24, CANCEL should not be compounded,
 * but a fuzzer may send it. Validates graceful handling.
 *
 * Return: number of CANCEL commands found, negative on error
 */
static int fuzz_cancel_compound(const u8 *data, size_t len)
{
	const struct smb2_hdr_cancel_fuzz *hdr;
	u32 offset = 0;
	u32 next_command;
	int cancel_count = 0;
	int chain_count = 0;

	while (offset + sizeof(struct smb2_hdr_cancel_fuzz) <= len) {
		hdr = (const struct smb2_hdr_cancel_fuzz *)(data + offset);

		/* Validate protocol ID */
		if (hdr->ProtocolId != SMB2_PROTO_NUMBER_FUZZ)
			break;

		chain_count++;
		if (chain_count > 64) {
			pr_debug("fuzz_cancel_compound: chain too long\n");
			break;
		}

		/* Check if this is a CANCEL */
		if (hdr->Command == SMB2_CANCEL_COMMAND) {
			cancel_count++;
			pr_debug("fuzz_cancel_compound: CANCEL at offset %u\n",
				 offset);
		}

		next_command = le32_to_cpu(hdr->NextCommand);
		if (next_command == 0)
			break;

		/* Must be 8-byte aligned */
		if (next_command & 0x7) {
			pr_debug("fuzz_cancel_compound: unaligned NextCommand %u\n",
				 next_command);
			break;
		}

		/* Must move forward */
		if (next_command < sizeof(struct smb2_hdr_cancel_fuzz)) {
			pr_debug("fuzz_cancel_compound: NextCommand %u too small\n",
				 next_command);
			break;
		}

		if (offset + next_command > len) {
			pr_debug("fuzz_cancel_compound: NextCommand overflow\n");
			break;
		}

		offset += next_command;
	}

	pr_debug("fuzz_cancel_compound: %d chain entries, %d CANCELs\n",
		 chain_count, cancel_count);
	return cancel_count;
}

static void build_cancel_hdr(struct smb2_hdr_cancel_fuzz *hdr, u32 flags,
			     u64 message_id, u64 session_id, u64 async_id)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->ProtocolId = SMB2_PROTO_NUMBER_FUZZ;
	hdr->StructureSize = cpu_to_le16(SMB2_HDR_STRUCTURE_SIZE);
	hdr->Command = SMB2_CANCEL_COMMAND;
	hdr->Flags = cpu_to_le32(flags);
	hdr->MessageId = cpu_to_le64(message_id);
	hdr->SessionId = cpu_to_le64(session_id);
	if (flags & le32_to_cpu(SMB2_FLAGS_ASYNC_COMMAND))
		hdr->Id.AsyncId = cpu_to_le64(async_id);
}

static int __init cancel_request_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_hdr_cancel_fuzz *hdr;
	struct smb2_cancel_req_fuzz *body;
	int ret;

	pr_info("cancel_request_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid sync CANCEL */
	hdr = (struct smb2_hdr_cancel_fuzz *)test_buf;
	build_cancel_hdr(hdr, 0, 42, 0x1234, 0);
	body = (struct smb2_cancel_req_fuzz *)
	       (test_buf + sizeof(struct smb2_hdr_cancel_fuzz));
	body->StructureSize = cpu_to_le16(CANCEL_STRUCTURE_SIZE);
	body->Reserved = 0;

	ret = fuzz_cancel_request(test_buf,
		sizeof(struct smb2_hdr_cancel_fuzz) +
		sizeof(struct smb2_cancel_req_fuzz));
	pr_info("cancel_request_fuzz: sync cancel returned %d\n", ret);

	/* Self-test 2: valid async CANCEL */
	build_cancel_hdr(hdr, 0x02 /* ASYNC */, 0, 0x5678, 0xABCD);
	body->StructureSize = cpu_to_le16(CANCEL_STRUCTURE_SIZE);
	body->Reserved = 0;

	ret = fuzz_cancel_request(test_buf,
		sizeof(struct smb2_hdr_cancel_fuzz) +
		sizeof(struct smb2_cancel_req_fuzz));
	pr_info("cancel_request_fuzz: async cancel returned %d\n", ret);

	/* Self-test 3: MessageId=0 sync cancel (SessionId fallback) */
	build_cancel_hdr(hdr, 0, 0, 0x9999, 0);
	body->StructureSize = cpu_to_le16(CANCEL_STRUCTURE_SIZE);

	ret = fuzz_cancel_request(test_buf,
		sizeof(struct smb2_hdr_cancel_fuzz) +
		sizeof(struct smb2_cancel_req_fuzz));
	pr_info("cancel_request_fuzz: mid=0 cancel returned %d\n", ret);

	/* Self-test 4: wrong structure size in body */
	build_cancel_hdr(hdr, 0, 1, 0x1234, 0);
	body->StructureSize = cpu_to_le16(48); /* wrong */

	ret = fuzz_cancel_request(test_buf,
		sizeof(struct smb2_hdr_cancel_fuzz) +
		sizeof(struct smb2_cancel_req_fuzz));
	pr_info("cancel_request_fuzz: wrong body size returned %d\n", ret);

	/* Self-test 5: body-only parsing */
	{
		u8 body_buf[4];
		struct smb2_cancel_req_fuzz *b =
			(struct smb2_cancel_req_fuzz *)body_buf;

		b->StructureSize = cpu_to_le16(CANCEL_STRUCTURE_SIZE);
		b->Reserved = 0;
		ret = fuzz_cancel_body_only(body_buf, sizeof(body_buf));
		pr_info("cancel_request_fuzz: body-only returned %d\n", ret);
	}

	/* Self-test 6: signed CANCEL (unusual but accepted) */
	build_cancel_hdr(hdr, 0x08 /* SIGNED */, 10, 0x1234, 0);
	body->StructureSize = cpu_to_le16(CANCEL_STRUCTURE_SIZE);

	ret = fuzz_cancel_request(test_buf,
		sizeof(struct smb2_hdr_cancel_fuzz) +
		sizeof(struct smb2_cancel_req_fuzz));
	pr_info("cancel_request_fuzz: signed cancel returned %d\n", ret);

	/* Self-test 7: truncated */
	ret = fuzz_cancel_request(test_buf, 4);
	pr_info("cancel_request_fuzz: truncated returned %d\n", ret);

	/* Self-test 8: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_cancel_request(test_buf, 512);
	pr_info("cancel_request_fuzz: garbage returned %d\n", ret);

	/* Self-test 9: compound chain with CANCEL */
	memset(test_buf, 0, 512);
	{
		struct smb2_hdr_cancel_fuzz *h1, *h2;
		u32 pkt_size;

		/* First header: a non-cancel command (NEGOTIATE=0x0000)
		 * with NextCommand pointing to second header */
		pkt_size = (sizeof(struct smb2_hdr_cancel_fuzz) + 7) & ~7U;
		h1 = (struct smb2_hdr_cancel_fuzz *)test_buf;
		memset(h1, 0, sizeof(*h1));
		h1->ProtocolId = SMB2_PROTO_NUMBER_FUZZ;
		h1->StructureSize = cpu_to_le16(SMB2_HDR_STRUCTURE_SIZE);
		h1->Command = cpu_to_le16(0x0000); /* NEGOTIATE */
		h1->NextCommand = cpu_to_le32(pkt_size);

		/* Second header: CANCEL */
		h2 = (struct smb2_hdr_cancel_fuzz *)(test_buf + pkt_size);
		build_cancel_hdr(h2, 0, 42, 0x1234, 0);

		ret = fuzz_cancel_compound(test_buf,
			pkt_size + sizeof(struct smb2_hdr_cancel_fuzz));
		pr_info("cancel_request_fuzz: compound returned %d\n", ret);
	}

	kfree(test_buf);
	return 0;
}

static void __exit cancel_request_fuzz_exit(void)
{
	pr_info("cancel_request_fuzz: module unloaded\n");
}

module_init(cancel_request_fuzz_init);
module_exit(cancel_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 CANCEL request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
