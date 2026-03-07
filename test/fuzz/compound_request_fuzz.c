// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 compound request chaining
 *
 *   This module exercises the compound request chain validation logic
 *   used in ksmbd. Compound requests allow multiple SMB2 operations
 *   in a single packet. Malformed chains can confuse FID state,
 *   cause circular references, or bypass authentication.
 *
 *   Targets:
 *     - NextCommand offset validation (8-byte alignment, bounds)
 *     - Related vs unrelated compound flags
 *     - SessionId/TreeId inheritance in related compounds
 *     - Circular chain detection (NextCommand pointing backwards)
 *     - Compound FID propagation from CREATE
 *     - Error propagation: compound_err_status cascading
 *
 *   Corpus seed hints:
 *     - Two chained SMB2 headers: first with NextCommand=128,
 *       second with NextCommand=0
 *     - Related compound: FLAGS_RELATED_OPERATIONS set on second request
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 header (from smb2_header_fuzz.c) */
#define SMB2_PROTO_NUMBER		cpu_to_le32(0x424d53fe)
#define __SMB2_HEADER_STRUCTURE_SIZE	64
#define SMB2_FLAGS_RELATED_OPERATIONS	cpu_to_le32(0x00000002)
#define SMB2_FLAGS_ASYNC_COMMAND	cpu_to_le32(0x00000002)

#define SMB2_NEGOTIATE_HE		0x0000
#define SMB2_SESSION_SETUP_HE		0x0001
#define SMB2_TREE_CONNECT_HE		0x0003
#define SMB2_CREATE_HE			0x0005
#define SMB2_CLOSE_HE			0x0006
#define SMB2_READ_HE			0x0008
#define SMB2_WRITE_HE			0x0009
#define SMB2_OPLOCK_BREAK_HE		0x0012

struct smb2_hdr_compound {
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

#define MAX_COMPOUND_DEPTH	256

/*
 * fuzz_compound_chain - Fuzz compound request chain validation
 * @data:	raw input containing chained SMB2 requests
 * @len:	length of input
 *
 * Walks the compound chain via NextCommand offsets, validating alignment,
 * bounds, and detecting circular references.
 *
 * Return: number of requests in chain, negative on error
 */
static int fuzz_compound_chain(const u8 *data, size_t len)
{
	const struct smb2_hdr_compound *hdr;
	u32 offset = 0;
	int count = 0;
	u64 prev_session_id = 0;
	u32 prev_tree_id = 0;
	bool prev_was_create = false;
	u32 visited[MAX_COMPOUND_DEPTH]; /* track offsets for circular detect */

	if (len < __SMB2_HEADER_STRUCTURE_SIZE) {
		pr_debug("fuzz_compound: input too small\n");
		return -EINVAL;
	}

	/* Cap input */
	if (len > 256 * 1024)
		len = 256 * 1024;

	while (offset + __SMB2_HEADER_STRUCTURE_SIZE <= len &&
	       count < MAX_COMPOUND_DEPTH) {
		u16 structure_size;
		u16 command;
		u32 flags;
		u32 next_command;
		u64 session_id;
		u32 tree_id;
		bool is_related;
		int i;

		hdr = (const struct smb2_hdr_compound *)(data + offset);

		/* Validate protocol ID */
		if (hdr->ProtocolId != SMB2_PROTO_NUMBER) {
			pr_debug("fuzz_compound: bad protocol id at offset %u\n",
				 offset);
			return -EINVAL;
		}

		structure_size = le16_to_cpu(hdr->StructureSize);
		if (structure_size != __SMB2_HEADER_STRUCTURE_SIZE) {
			pr_debug("fuzz_compound: bad structure size %u at offset %u\n",
				 structure_size, offset);
			return -EINVAL;
		}

		command = le16_to_cpu(hdr->Command);
		flags = le32_to_cpu(hdr->Flags);
		next_command = le32_to_cpu(hdr->NextCommand);
		session_id = le64_to_cpu(hdr->SessionId);
		tree_id = le32_to_cpu(hdr->SyncHdr.TreeId);
		is_related = !!(flags & 0x00000002); /* RELATED_OPERATIONS */

		/* Check for circular reference */
		for (i = 0; i < count; i++) {
			if (visited[i] == offset) {
				pr_debug("fuzz_compound: circular chain at offset %u\n",
					 offset);
				return -EINVAL;
			}
		}
		visited[count] = offset;

		/* Related flag on first request is invalid */
		if (count == 0 && is_related) {
			pr_debug("fuzz_compound: RELATED flag on first request\n");
			/* Not necessarily fatal; just note it */
		}

		/* Related compound: SessionId/TreeId inherited from previous */
		if (is_related && count > 0) {
			if (session_id == 0xFFFFFFFFFFFFFFFFULL)
				session_id = prev_session_id;
			if (tree_id == 0xFFFFFFFF)
				tree_id = prev_tree_id;
			pr_debug("fuzz_compound: related[%d] inherited sid=%llu tid=%u\n",
				 count, session_id, tree_id);
		}

		/* Track if this is a CREATE (for FID propagation) */
		if (command == SMB2_CREATE_HE)
			prev_was_create = true;
		else if (prev_was_create && is_related)
			pr_debug("fuzz_compound: FID propagation from CREATE to cmd 0x%04x\n",
				 command);

		prev_session_id = session_id;
		prev_tree_id = tree_id;

		pr_debug("fuzz_compound: [%d] cmd=0x%04x flags=0x%08x next=%u\n",
			 count, command, flags, next_command);

		count++;

		/* Advance to next request */
		if (next_command == 0)
			break;

		/* NextCommand must be 8-byte aligned */
		if (next_command & 0x7) {
			pr_debug("fuzz_compound: unaligned NextCommand %u\n",
				 next_command);
			return -EINVAL;
		}

		/* NextCommand must advance forward */
		if (next_command <= __SMB2_HEADER_STRUCTURE_SIZE) {
			pr_debug("fuzz_compound: NextCommand %u too small\n",
				 next_command);
			return -EINVAL;
		}

		/* NextCommand must stay within buffer */
		if (offset + next_command >= len) {
			pr_debug("fuzz_compound: NextCommand at %u+%u exceeds buffer %zu\n",
				 offset, next_command, len);
			return -EINVAL;
		}

		offset += next_command;
	}

	pr_debug("fuzz_compound: chain contains %d requests\n", count);
	return count;
}

/*
 * fuzz_compound_fid_propagation - Fuzz FID propagation in compound CREATE+op
 * @data:	raw input with compound requests
 * @len:	length of input
 *
 * Simulates the FID capture from a CREATE response being propagated to
 * a subsequent READ/WRITE/CLOSE in a related compound.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_compound_fid_propagation(const u8 *data, size_t len)
{
	const struct smb2_hdr_compound *hdr;
	u64 compound_fid_persistent = 0;
	u64 compound_fid_volatile = 0;
	bool fid_set = false;
	u32 offset = 0;
	int count = 0;

	if (len < 2 * __SMB2_HEADER_STRUCTURE_SIZE)
		return -EINVAL;

	while (offset + __SMB2_HEADER_STRUCTURE_SIZE <= len && count < 16) {
		u16 command;
		u32 next_command;
		u32 flags;

		hdr = (const struct smb2_hdr_compound *)(data + offset);

		if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
			return -EINVAL;

		command = le16_to_cpu(hdr->Command);
		next_command = le32_to_cpu(hdr->NextCommand);
		flags = le32_to_cpu(hdr->Flags);

		if (command == SMB2_CREATE_HE) {
			/* Simulate FID capture from CREATE */
			compound_fid_persistent = 0xDEADBEEFULL;
			compound_fid_volatile = 0xCAFEBABEULL;
			fid_set = true;
			pr_debug("fuzz_compound_fid: CREATE -> FID captured\n");
		} else if (fid_set && (flags & 0x00000002)) {
			/* Related request uses compound FID */
			pr_debug("fuzz_compound_fid: cmd 0x%04x uses compound FID p=%llx v=%llx\n",
				 command, compound_fid_persistent,
				 compound_fid_volatile);
		}

		count++;
		if (next_command == 0 || (next_command & 0x7) ||
		    offset + next_command >= len)
			break;

		offset += next_command;
	}

	return 0;
}

static int __init compound_request_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_hdr_compound *hdr1, *hdr2;
	int ret;

	pr_info("compound_request_fuzz: module loaded\n");

	test_buf = kzalloc(1024, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: two-request chain (CREATE + CLOSE) */
	hdr1 = (struct smb2_hdr_compound *)test_buf;
	hdr1->ProtocolId = SMB2_PROTO_NUMBER;
	hdr1->StructureSize = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	hdr1->Command = cpu_to_le16(SMB2_CREATE_HE);
	hdr1->NextCommand = cpu_to_le32(128); /* next at offset 128 */
	hdr1->SessionId = cpu_to_le64(0x1234);
	hdr1->SyncHdr.TreeId = cpu_to_le32(1);

	hdr2 = (struct smb2_hdr_compound *)(test_buf + 128);
	hdr2->ProtocolId = SMB2_PROTO_NUMBER;
	hdr2->StructureSize = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	hdr2->Command = cpu_to_le16(SMB2_CLOSE_HE);
	hdr2->Flags = cpu_to_le32(0x00000002); /* RELATED */
	hdr2->NextCommand = 0;
	hdr2->SessionId = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);

	ret = fuzz_compound_chain(test_buf, 192);
	pr_info("compound_request_fuzz: two-chain test returned %d\n", ret);

	/* Self-test 2: circular chain */
	hdr1->NextCommand = cpu_to_le32(0); /* points to self at offset 0 */
	/* Actually NextCommand=0 means "last request", so set to 64 pointing back */
	hdr1->NextCommand = cpu_to_le32(64); /* minimum: exactly header size */
	/* This should be caught because NextCommand must advance meaningfully */
	ret = fuzz_compound_chain(test_buf, 192);
	pr_info("compound_request_fuzz: small NextCommand test returned %d\n", ret);

	/* Self-test 3: unaligned NextCommand */
	hdr1->NextCommand = cpu_to_le32(65);
	ret = fuzz_compound_chain(test_buf, 192);
	pr_info("compound_request_fuzz: unaligned test returned %d\n", ret);

	/* Self-test 4: FID propagation */
	hdr1->NextCommand = cpu_to_le32(128);
	ret = fuzz_compound_fid_propagation(test_buf, 192);
	pr_info("compound_request_fuzz: FID propagation test returned %d\n", ret);

	/* Self-test 5: single request (no chain) */
	hdr1->NextCommand = 0;
	ret = fuzz_compound_chain(test_buf, 64);
	pr_info("compound_request_fuzz: single request test returned %d\n", ret);

	/* Self-test 6: truncated input */
	ret = fuzz_compound_chain(test_buf, 10);
	pr_info("compound_request_fuzz: truncated test returned %d\n", ret);

	/* Self-test 7: garbage */
	memset(test_buf, 0xFF, 1024);
	ret = fuzz_compound_chain(test_buf, 1024);
	pr_info("compound_request_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit compound_request_fuzz_exit(void)
{
	pr_info("compound_request_fuzz: module unloaded\n");
}

module_init(compound_request_fuzz_init);
module_exit(compound_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 compound request chaining");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
