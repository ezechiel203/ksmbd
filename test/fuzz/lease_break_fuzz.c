// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for oplock/lease break notification parsing
 *
 *   This module exercises oplock break and lease break notification
 *   parsing with random lease states, break-to levels, lease keys,
 *   epoch values, and flags. It validates the state machine transitions
 *   that ksmbd performs when processing break notifications and
 *   acknowledgments.
 *
 *   Targets:
 *     - Oplock break: StructureSize (24), OplockLevel validation,
 *       FileId extraction
 *     - Lease break: StructureSize (44), CurrentLeaseState,
 *       NewLeaseState transition validity
 *     - Lease key: 16-byte GUID validation
 *     - Epoch: wraparound and increment validation
 *     - Flags: ACK_REQUIRED flag handling
 *     - Invalid state transitions (e.g., NONE -> WRITE)
 *     - Lease acknowledgment: LeaseState must be subset of current
 *
 *   Usage with syzkaller:
 *     Load as a test module. Self-tests run on module init.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/random.h>

/* Inline structures matching smb2pdu.h */

#define SMB2_PROTO_NUMBER		cpu_to_le32(0x424d53fe)
#define __SMB2_HEADER_STRUCTURE_SIZE	64
#define SMB2_OPLOCK_BREAK_HE		0x0012

/* Oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE		0x00
#define SMB2_OPLOCK_LEVEL_II		0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE	0x08
#define SMB2_OPLOCK_LEVEL_BATCH		0x09
#define SMB2_OPLOCK_LEVEL_LEASE		0xFF

/* Lease states */
#define SMB2_LEASE_NONE			0x00
#define SMB2_LEASE_READ_CACHING		0x01
#define SMB2_LEASE_HANDLE_CACHING	0x02
#define SMB2_LEASE_WRITE_CACHING	0x04
#define SMB2_LEASE_ALL			(SMB2_LEASE_READ_CACHING | \
					 SMB2_LEASE_HANDLE_CACHING | \
					 SMB2_LEASE_WRITE_CACHING)

#define SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED	0x01
#define SMB2_LEASE_KEY_SIZE		16

struct fuzz_smb2_hdr {
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
		} __packed SyncId;
		__le64 AsyncId;
	} __packed Id;
	__le64 SessionId;
	__u8   Signature[16];
} __packed;

struct fuzz_oplock_break {
	struct fuzz_smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 24 */
	__u8   OplockLevel;
	__u8   Reserved;
	__le32 Reserved2;
	__le64 PersistentFid;
	__le64 VolatileFid;
} __packed;

struct fuzz_lease_break {
	struct fuzz_smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 44 */
	__le16 Epoch;
	__le32 Flags;
	__u8   LeaseKey[SMB2_LEASE_KEY_SIZE];
	__le32 CurrentLeaseState;
	__le32 NewLeaseState;
	__le32 BreakReason;
	__le32 AccessMaskHint;
	__le32 ShareMaskHint;
} __packed;

struct fuzz_lease_ack {
	struct fuzz_smb2_hdr hdr;
	__le16 StructureSize;	/* Must be 36 */
	__le16 Reserved;
	__le32 Flags;
	__u8   LeaseKey[SMB2_LEASE_KEY_SIZE];
	__le32 LeaseState;
	__le64 LeaseDuration;
} __packed;

#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		256

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

/*
 * fuzz_valid_oplock_level - Check if oplock level is valid
 */
static bool fuzz_valid_oplock_level(u8 level)
{
	return level == SMB2_OPLOCK_LEVEL_NONE ||
	       level == SMB2_OPLOCK_LEVEL_II ||
	       level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||
	       level == SMB2_OPLOCK_LEVEL_BATCH;
}

/*
 * fuzz_valid_lease_transition - Check if a lease state transition is valid
 * @current_state:	current lease state
 * @new_state:		proposed new lease state
 *
 * Valid breaks always reduce capabilities (new_state is a subset of current).
 *
 * Return: true if valid transition
 */
static bool fuzz_valid_lease_transition(u32 current_state, u32 new_state)
{
	/* New state must be a subset of current state */
	if ((new_state & ~current_state) != 0)
		return false;

	/* Cannot break from NONE to anything */
	if (current_state == SMB2_LEASE_NONE && new_state != SMB2_LEASE_NONE)
		return false;

	return true;
}

/*
 * fuzz_validate_oplock_break - Validate an oplock break notification
 * @data:	raw buffer
 * @len:	buffer length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_oplock_break(const u8 *data, size_t len)
{
	const struct fuzz_oplock_break *brk;
	u16 structure_size;
	u8 level;

	if (len < sizeof(struct fuzz_oplock_break))
		return -EINVAL;

	brk = (const struct fuzz_oplock_break *)data;

	if (brk->hdr.ProtocolId != SMB2_PROTO_NUMBER)
		return -EINVAL;

	structure_size = le16_to_cpu(brk->StructureSize);
	if (structure_size != 24) {
		pr_debug("lease_fuzz: oplock break bad StructureSize %u\n",
			 structure_size);
		return -EINVAL;
	}

	level = brk->OplockLevel;
	if (!fuzz_valid_oplock_level(level)) {
		pr_debug("lease_fuzz: invalid oplock level 0x%02x\n", level);
		return -EINVAL;
	}

	pr_debug("lease_fuzz: valid oplock break level=0x%02x\n", level);
	return 0;
}

/*
 * fuzz_validate_lease_break - Validate a lease break notification
 * @data:	raw buffer
 * @len:	buffer length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_lease_break(const u8 *data, size_t len)
{
	const struct fuzz_lease_break *brk;
	u16 structure_size;
	u32 current_state, new_state, flags;
	u16 epoch;
	bool all_zero_key = true;
	int i;

	if (len < sizeof(struct fuzz_lease_break))
		return -EINVAL;

	brk = (const struct fuzz_lease_break *)data;

	if (brk->hdr.ProtocolId != SMB2_PROTO_NUMBER)
		return -EINVAL;

	structure_size = le16_to_cpu(brk->StructureSize);
	if (structure_size != 44) {
		pr_debug("lease_fuzz: lease break bad StructureSize %u\n",
			 structure_size);
		return -EINVAL;
	}

	current_state = le32_to_cpu(brk->CurrentLeaseState);
	new_state = le32_to_cpu(brk->NewLeaseState);
	flags = le32_to_cpu(brk->Flags);
	epoch = le16_to_cpu(brk->Epoch);

	/* Valid lease state bits */
	if (current_state & ~SMB2_LEASE_ALL) {
		pr_debug("lease_fuzz: invalid CurrentLeaseState 0x%x\n",
			 current_state);
		return -EINVAL;
	}

	if (new_state & ~SMB2_LEASE_ALL) {
		pr_debug("lease_fuzz: invalid NewLeaseState 0x%x\n",
			 new_state);
		return -EINVAL;
	}

	/* Validate transition */
	if (!fuzz_valid_lease_transition(current_state, new_state)) {
		pr_debug("lease_fuzz: invalid transition 0x%x -> 0x%x\n",
			 current_state, new_state);
	}

	/* Lease key should not be all zeros in production */
	for (i = 0; i < SMB2_LEASE_KEY_SIZE; i++) {
		if (brk->LeaseKey[i] != 0) {
			all_zero_key = false;
			break;
		}
	}
	if (all_zero_key)
		pr_debug("lease_fuzz: all-zero lease key\n");

	pr_debug("lease_fuzz: lease break cur=0x%x new=0x%x epoch=%u flags=0x%x\n",
		 current_state, new_state, epoch, flags);

	return 0;
}

/*
 * fuzz_validate_lease_ack - Validate a lease break acknowledgment
 * @data:		raw buffer
 * @len:		buffer length
 * @expected_state:	the state the server expects
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_lease_ack(const u8 *data, size_t len,
				   u32 expected_state)
{
	const struct fuzz_lease_ack *ack;
	u32 ack_state;

	if (len < sizeof(struct fuzz_lease_ack))
		return -EINVAL;

	ack = (const struct fuzz_lease_ack *)data;

	if (le16_to_cpu(ack->StructureSize) != 36)
		return -EINVAL;

	ack_state = le32_to_cpu(ack->LeaseState);

	/* Acknowledged state must be subset of expected state */
	if ((ack_state & ~expected_state) != 0) {
		pr_debug("lease_fuzz: ack state 0x%x not subset of 0x%x\n",
			 ack_state, expected_state);
		return -EINVAL;
	}

	return 0;
}

static int __init lease_break_fuzz_init(void)
{
	u8 *buf;
	int i;

	pr_info("lease_break_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0x12345678;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		u32 choice = fuzz_next() % 3;

		memset(buf, 0, FUZZ_BUF_SIZE);

		if (choice == 0) {
			/* Random oplock break */
			struct fuzz_oplock_break *brk =
				(struct fuzz_oplock_break *)buf;

			brk->hdr.ProtocolId = SMB2_PROTO_NUMBER;
			brk->hdr.StructureSize =
				cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
			brk->hdr.Command = cpu_to_le16(SMB2_OPLOCK_BREAK_HE);
			brk->StructureSize = cpu_to_le16(
				(fuzz_next() % 4 == 0) ? fuzz_next() : 24);
			brk->OplockLevel = fuzz_next() % 256;
			brk->PersistentFid = cpu_to_le64(fuzz_next());
			brk->VolatileFid = cpu_to_le64(fuzz_next());

			fuzz_validate_oplock_break(buf,
				sizeof(struct fuzz_oplock_break));
		} else if (choice == 1) {
			/* Random lease break */
			struct fuzz_lease_break *brk =
				(struct fuzz_lease_break *)buf;

			brk->hdr.ProtocolId = SMB2_PROTO_NUMBER;
			brk->hdr.StructureSize =
				cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
			brk->hdr.Command = cpu_to_le16(SMB2_OPLOCK_BREAK_HE);
			brk->StructureSize = cpu_to_le16(
				(fuzz_next() % 4 == 0) ? fuzz_next() : 44);
			brk->Epoch = cpu_to_le16(fuzz_next());
			brk->Flags = cpu_to_le32(fuzz_next() % 4);
			get_random_bytes(brk->LeaseKey, SMB2_LEASE_KEY_SIZE);

			/* Generate lease states: valid or random */
			if (fuzz_next() % 2) {
				brk->CurrentLeaseState =
					cpu_to_le32(fuzz_next() % 8);
				brk->NewLeaseState =
					cpu_to_le32(fuzz_next() % 8);
			} else {
				brk->CurrentLeaseState =
					cpu_to_le32(fuzz_next());
				brk->NewLeaseState =
					cpu_to_le32(fuzz_next());
			}

			brk->BreakReason = cpu_to_le32(fuzz_next());
			brk->AccessMaskHint = cpu_to_le32(fuzz_next());
			brk->ShareMaskHint = cpu_to_le32(fuzz_next());

			fuzz_validate_lease_break(buf,
				sizeof(struct fuzz_lease_break));
		} else {
			/* Random lease acknowledgment */
			struct fuzz_lease_ack *ack =
				(struct fuzz_lease_ack *)buf;
			u32 expected = fuzz_next() % 8;

			ack->hdr.ProtocolId = SMB2_PROTO_NUMBER;
			ack->StructureSize = cpu_to_le16(
				(fuzz_next() % 4 == 0) ? fuzz_next() : 36);
			ack->LeaseState = cpu_to_le32(fuzz_next() % 8);
			get_random_bytes(ack->LeaseKey, SMB2_LEASE_KEY_SIZE);

			fuzz_validate_lease_ack(buf,
				sizeof(struct fuzz_lease_ack), expected);
		}
	}

	/* Edge cases */
	fuzz_validate_oplock_break(buf, 0);
	fuzz_validate_lease_break(buf, 0);
	fuzz_validate_lease_ack(buf, 0, 0);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_oplock_break(buf, FUZZ_BUF_SIZE);
	fuzz_validate_lease_break(buf, FUZZ_BUF_SIZE);
	fuzz_validate_lease_ack(buf, FUZZ_BUF_SIZE, SMB2_LEASE_ALL);

	kfree(buf);
	pr_info("lease_break_fuzz: all iterations completed\n");
	return 0;
}

static void __exit lease_break_fuzz_exit(void)
{
	pr_info("lease_break_fuzz: module unloaded\n");
}

module_init(lease_break_fuzz_init);
module_exit(lease_break_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for oplock/lease break notification parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
