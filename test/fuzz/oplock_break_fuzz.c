// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 oplock break acknowledgment parsing
 *
 *   This module exercises the oplock break acknowledgment and lease
 *   break acknowledgment request parsing used in ksmbd.
 *
 *   Targets:
 *     - Oplock break ack: StructureSize (24), OplockLevel validation,
 *       FileId extraction
 *     - Lease break ack: StructureSize (36), LeaseKey, LeaseState,
 *       LeaseFlags validation
 *     - Lease create context (RqLs): LeaseKey, LeaseState, version
 *
 *   Corpus seed hints:
 *     - Oplock break ack: StructureSize=24, OplockLevel=0x01 (Level II),
 *       FileId
 *     - Lease break ack: StructureSize=36, LeaseState=0x07,
 *       16-byte LeaseKey
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 oplock break ack request */
struct smb2_oplock_break_ack_fuzz {
	__le16 StructureSize;	/* Must be 24 */
	__u8   OplockLevel;
	__u8   Reserved;
	__le32 Reserved2;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
} __packed;

/* SMB2 lease break ack request */
struct smb2_lease_break_ack_fuzz {
	__le16 StructureSize;	/* Must be 36 */
	__le16 Reserved;
	__le32 Flags;
	__u8   LeaseKey[16];
	__le32 LeaseState;
	__le64 LeaseDuration;
} __packed;

/* Lease create context data (RqLs) */
struct lease_create_ctx_fuzz {
	__u8   LeaseKey[16];
	__le32 LeaseState;
	__le32 LeaseFlags;
	__le64 LeaseDuration;
	/* v2: + ParentLeaseKey[16] + Epoch + Reserved */
} __packed;

#define OPLOCK_BREAK_STRUCTURE_SIZE	24
#define LEASE_BREAK_STRUCTURE_SIZE	36

/* Oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE		0x00
#define SMB2_OPLOCK_LEVEL_II		0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE	0x08
#define SMB2_OPLOCK_LEVEL_BATCH		0x09
#define SMB2_OPLOCK_LEVEL_LEASE		0xFF

/* Lease states */
#define SMB2_LEASE_READ_CACHING_LE	cpu_to_le32(0x01)
#define SMB2_LEASE_HANDLE_CACHING_LE	cpu_to_le32(0x02)
#define SMB2_LEASE_WRITE_CACHING_LE	cpu_to_le32(0x04)
#define SMB2_LEASE_VALID_MASK		0x07

/* Lease flags */
#define SMB2_LEASE_FLAG_BREAK_IN_PROGRESS	cpu_to_le32(0x02)

/*
 * fuzz_oplock_break_ack - Fuzz oplock break ack request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_oplock_break_ack(const u8 *data, size_t len)
{
	const struct smb2_oplock_break_ack_fuzz *req;
	u16 structure_size;
	u8 oplock_level;

	if (len < sizeof(struct smb2_oplock_break_ack_fuzz)) {
		pr_debug("fuzz_oplock: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_oplock_break_ack_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	oplock_level = req->OplockLevel;

	/* Validate structure size */
	if (structure_size != OPLOCK_BREAK_STRUCTURE_SIZE) {
		pr_debug("fuzz_oplock: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate oplock level */
	switch (oplock_level) {
	case SMB2_OPLOCK_LEVEL_NONE:
	case SMB2_OPLOCK_LEVEL_II:
		/* Valid ack levels */
		break;
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
	case SMB2_OPLOCK_LEVEL_BATCH:
		/* Upgrading to exclusive/batch in ack is unusual but valid */
		pr_debug("fuzz_oplock: unusual ack level 0x%02x\n",
			 oplock_level);
		break;
	case SMB2_OPLOCK_LEVEL_LEASE:
		pr_debug("fuzz_oplock: lease level in oplock ack\n");
		break;
	default:
		pr_debug("fuzz_oplock: unknown level 0x%02x\n", oplock_level);
		return -EINVAL;
	}

	pr_debug("fuzz_oplock: level=0x%02x fid_p=%llx fid_v=%llx\n",
		 oplock_level,
		 le64_to_cpu(req->FileId_Persistent),
		 le64_to_cpu(req->FileId_Volatile));

	return 0;
}

/*
 * fuzz_lease_break_ack - Fuzz lease break ack request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_lease_break_ack(const u8 *data, size_t len)
{
	const struct smb2_lease_break_ack_fuzz *req;
	u16 structure_size;
	u32 lease_state;
	u32 flags;

	if (len < sizeof(struct smb2_lease_break_ack_fuzz)) {
		pr_debug("fuzz_lease: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_lease_break_ack_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	lease_state = le32_to_cpu(req->LeaseState);
	flags = le32_to_cpu(req->Flags);

	/* Validate structure size */
	if (structure_size != LEASE_BREAK_STRUCTURE_SIZE) {
		pr_debug("fuzz_lease: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate lease state */
	if (lease_state & ~SMB2_LEASE_VALID_MASK) {
		pr_debug("fuzz_lease: reserved LeaseState bits 0x%08x\n",
			 lease_state);
	}

	/* Check LeaseKey not all zeros */
	{
		int i;
		bool all_zero = true;

		for (i = 0; i < 16; i++) {
			if (req->LeaseKey[i] != 0) {
				all_zero = false;
				break;
			}
		}
		if (all_zero)
			pr_debug("fuzz_lease: all-zero LeaseKey\n");
	}

	pr_debug("fuzz_lease: state=0x%08x flags=0x%08x\n",
		 lease_state, flags);

	return 0;
}

/*
 * fuzz_lease_create_context - Fuzz lease create context (RqLs)
 * @data:	raw context data
 * @len:	length of data
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_lease_create_context(const u8 *data, size_t len)
{
	const struct lease_create_ctx_fuzz *ctx;
	u32 lease_state;
	u32 lease_flags;

	if (len < sizeof(struct lease_create_ctx_fuzz)) {
		pr_debug("fuzz_lease_ctx: data too small (%zu)\n", len);
		return -EINVAL;
	}

	ctx = (const struct lease_create_ctx_fuzz *)data;
	lease_state = le32_to_cpu(ctx->LeaseState);
	lease_flags = le32_to_cpu(ctx->LeaseFlags);

	/* Validate lease state */
	if (lease_state & ~SMB2_LEASE_VALID_MASK) {
		pr_debug("fuzz_lease_ctx: reserved state bits 0x%08x\n",
			 lease_state);
	}

	/* Determine version: v2 has ParentLeaseKey */
	if (len >= sizeof(struct lease_create_ctx_fuzz) + 16 + 4) {
		pr_debug("fuzz_lease_ctx: lease v2 (has ParentLeaseKey)\n");
	} else {
		pr_debug("fuzz_lease_ctx: lease v1\n");
	}

	pr_debug("fuzz_lease_ctx: state=0x%08x flags=0x%08x\n",
		 lease_state, lease_flags);

	return 0;
}

static int __init oplock_break_fuzz_init(void)
{
	u8 test_buf[64];
	int ret;

	pr_info("oplock_break_fuzz: module loaded\n");

	/* Self-test 1: valid oplock break ack */
	{
		struct smb2_oplock_break_ack_fuzz *req =
			(struct smb2_oplock_break_ack_fuzz *)test_buf;

		memset(test_buf, 0, sizeof(test_buf));
		req->StructureSize = cpu_to_le16(OPLOCK_BREAK_STRUCTURE_SIZE);
		req->OplockLevel = SMB2_OPLOCK_LEVEL_II;
		req->FileId_Persistent = cpu_to_le64(0x1234);
		req->FileId_Volatile = cpu_to_le64(0x5678);

		ret = fuzz_oplock_break_ack(test_buf,
					    sizeof(struct smb2_oplock_break_ack_fuzz));
		pr_info("oplock_break_fuzz: valid oplock returned %d\n", ret);
	}

	/* Self-test 2: invalid oplock level */
	{
		struct smb2_oplock_break_ack_fuzz *req =
			(struct smb2_oplock_break_ack_fuzz *)test_buf;

		req->OplockLevel = 0x42;
		ret = fuzz_oplock_break_ack(test_buf,
					    sizeof(struct smb2_oplock_break_ack_fuzz));
		pr_info("oplock_break_fuzz: bad level returned %d\n", ret);
	}

	/* Self-test 3: valid lease break ack */
	{
		struct smb2_lease_break_ack_fuzz *req =
			(struct smb2_lease_break_ack_fuzz *)test_buf;

		memset(test_buf, 0, sizeof(test_buf));
		req->StructureSize = cpu_to_le16(LEASE_BREAK_STRUCTURE_SIZE);
		req->LeaseState = cpu_to_le32(0x01); /* READ */
		memset(req->LeaseKey, 0xAA, 16);

		ret = fuzz_lease_break_ack(test_buf,
					   sizeof(struct smb2_lease_break_ack_fuzz));
		pr_info("oplock_break_fuzz: valid lease returned %d\n", ret);
	}

	/* Self-test 4: all bits set in LeaseState */
	{
		struct smb2_lease_break_ack_fuzz *req =
			(struct smb2_lease_break_ack_fuzz *)test_buf;

		req->LeaseState = cpu_to_le32(0xFFFFFFFF);
		ret = fuzz_lease_break_ack(test_buf,
					   sizeof(struct smb2_lease_break_ack_fuzz));
		pr_info("oplock_break_fuzz: all-bits lease returned %d\n", ret);
	}

	/* Self-test 5: lease create context */
	{
		struct lease_create_ctx_fuzz *ctx =
			(struct lease_create_ctx_fuzz *)test_buf;

		memset(test_buf, 0, sizeof(test_buf));
		memset(ctx->LeaseKey, 0xBB, 16);
		ctx->LeaseState = cpu_to_le32(0x07); /* R|H|W */

		ret = fuzz_lease_create_context(test_buf,
						sizeof(struct lease_create_ctx_fuzz));
		pr_info("oplock_break_fuzz: lease ctx returned %d\n", ret);
	}

	/* Self-test 6: truncated */
	ret = fuzz_oplock_break_ack(test_buf, 4);
	pr_info("oplock_break_fuzz: truncated returned %d\n", ret);

	/* Self-test 7: garbage */
	memset(test_buf, 0xFF, sizeof(test_buf));
	ret = fuzz_oplock_break_ack(test_buf, sizeof(test_buf));
	pr_info("oplock_break_fuzz: garbage oplock returned %d\n", ret);
	ret = fuzz_lease_break_ack(test_buf, sizeof(test_buf));
	pr_info("oplock_break_fuzz: garbage lease returned %d\n", ret);

	return 0;
}

static void __exit oplock_break_fuzz_exit(void)
{
	pr_info("oplock_break_fuzz: module unloaded\n");
}

module_init(oplock_break_fuzz_init);
module_exit(oplock_break_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 oplock/lease break ack parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
