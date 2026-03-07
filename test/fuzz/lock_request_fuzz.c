// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2_LOCK request parsing
 *
 *   This module exercises the SMB2 LOCK request parsing logic used in
 *   ksmbd. Lock requests carry arrays of lock elements specifying byte
 *   ranges and flags. Malformed requests can cause integer overflows,
 *   out-of-bounds reads, or conflicting lock states.
 *
 *   Targets:
 *     - Lock count validation
 *     - Lock element array bounds checking
 *     - Flag combination validation (shared + exclusive conflict)
 *     - Overlapping byte range detection
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_lock_request() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the lock structures to avoid full header dependencies.
 */

struct smb2_lock_element {
	__le64 Offset;
	__le64 Length;
	__le32 Flags;
	__le32 Reserved;
} __packed;

/* Lock request header (after SMB2 header) */
struct smb2_lock_req_hdr {
	__le16 StructureSize;	/* Must be 48 */
	__le16 LockCount;
	__le32 LockSequenceNumber;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
	/* Followed by LockCount * smb2_lock_element */
} __packed;

/* Lock flags */
#define SMB2_LOCKFLAG_SHARED_LOCK	0x00000001
#define SMB2_LOCKFLAG_EXCLUSIVE_LOCK	0x00000002
#define SMB2_LOCKFLAG_UNLOCK		0x00000004
#define SMB2_LOCKFLAG_FAIL_IMMEDIATELY	0x00000010

#define SMB2_LOCK_STRUCTURE_SIZE	48
#define MAX_LOCK_COUNT			1024

/*
 * fuzz_validate_lock_flags - Validate lock flag combinations
 * @flags:	lock flags from a lock element
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_lock_flags(u32 flags)
{
	u32 lock_type = flags & (SMB2_LOCKFLAG_SHARED_LOCK |
				 SMB2_LOCKFLAG_EXCLUSIVE_LOCK |
				 SMB2_LOCKFLAG_UNLOCK);

	/* Must have exactly one lock type */
	if (lock_type == 0) {
		pr_debug("fuzz_lock: no lock type specified in flags 0x%08x\n",
			 flags);
		return -EINVAL;
	}

	/* Shared and exclusive are mutually exclusive */
	if ((flags & SMB2_LOCKFLAG_SHARED_LOCK) &&
	    (flags & SMB2_LOCKFLAG_EXCLUSIVE_LOCK)) {
		pr_debug("fuzz_lock: shared+exclusive conflict in flags 0x%08x\n",
			 flags);
		return -EINVAL;
	}

	/* Unlock cannot combine with shared or exclusive */
	if ((flags & SMB2_LOCKFLAG_UNLOCK) &&
	    (flags & (SMB2_LOCKFLAG_SHARED_LOCK |
		      SMB2_LOCKFLAG_EXCLUSIVE_LOCK))) {
		pr_debug("fuzz_lock: unlock+lock conflict in flags 0x%08x\n",
			 flags);
		return -EINVAL;
	}

	return 0;
}

/*
 * fuzz_check_lock_overlap - Check if two lock ranges overlap
 * @off1:	offset of first range
 * @len1:	length of first range
 * @off2:	offset of second range
 * @len2:	length of second range
 *
 * Return: 1 if overlapping, 0 if not
 */
static int fuzz_check_lock_overlap(u64 off1, u64 len1, u64 off2, u64 len2)
{
	u64 end1, end2;

	/* Zero-length ranges don't overlap */
	if (len1 == 0 || len2 == 0)
		return 0;

	/* Check for overflow */
	if (off1 + len1 < off1 || off2 + len2 < off2)
		return 0;

	end1 = off1 + len1;
	end2 = off2 + len2;

	if (off1 < end2 && off2 < end1)
		return 1;

	return 0;
}

/*
 * fuzz_lock_request - Fuzz SMB2_LOCK request parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the lock request validation that ksmbd performs when
 * processing SMB2_LOCK commands.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_lock_request(const u8 *data, size_t len)
{
	const struct smb2_lock_req_hdr *req;
	const struct smb2_lock_element *locks;
	u16 lock_count;
	u16 structure_size;
	size_t required_size;
	u32 i, j;
	int overlap_count = 0;
	int flag_errors = 0;

	if (len < sizeof(struct smb2_lock_req_hdr)) {
		pr_debug("fuzz_lock: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_lock_req_hdr *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	lock_count = le16_to_cpu(req->LockCount);

	/* Validate structure size */
	if (structure_size != SMB2_LOCK_STRUCTURE_SIZE) {
		pr_debug("fuzz_lock: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate lock count */
	if (lock_count == 0) {
		pr_debug("fuzz_lock: zero lock count\n");
		return -EINVAL;
	}

	if (lock_count > MAX_LOCK_COUNT) {
		pr_debug("fuzz_lock: lock count %u exceeds max %u\n",
			 lock_count, MAX_LOCK_COUNT);
		return -EINVAL;
	}

	/* Check that all lock elements fit in the buffer */
	required_size = sizeof(struct smb2_lock_req_hdr) +
			(size_t)lock_count * sizeof(struct smb2_lock_element);
	if (required_size > len) {
		pr_debug("fuzz_lock: %u lock elements need %zu bytes, have %zu\n",
			 lock_count, required_size, len);
		return -EINVAL;
	}

	locks = (const struct smb2_lock_element *)(data +
		sizeof(struct smb2_lock_req_hdr));

	/* Validate each lock element */
	for (i = 0; i < lock_count; i++) {
		u64 offset = le64_to_cpu(locks[i].Offset);
		u64 length = le64_to_cpu(locks[i].Length);
		u32 flags = le32_to_cpu(locks[i].Flags);

		if (fuzz_validate_lock_flags(flags) < 0)
			flag_errors++;

		/* Check for offset + length overflow */
		if (length > 0 && offset + length < offset) {
			pr_debug("fuzz_lock: lock %u offset+length overflow\n", i);
			flag_errors++;
		}

		pr_debug("fuzz_lock: lock[%u] off=%llu len=%llu flags=0x%08x\n",
			 i, offset, length, flags);
	}

	/* Check for overlapping ranges between lock elements */
	for (i = 0; i < lock_count && i < 64; i++) {
		for (j = i + 1; j < lock_count && j < 64; j++) {
			if (fuzz_check_lock_overlap(
				le64_to_cpu(locks[i].Offset),
				le64_to_cpu(locks[i].Length),
				le64_to_cpu(locks[j].Offset),
				le64_to_cpu(locks[j].Length))) {
				overlap_count++;
			}
		}
	}

	pr_debug("fuzz_lock: parsed %u locks, %d flag errors, %d overlaps\n",
		 lock_count, flag_errors, overlap_count);

	return 0;
}

static int __init lock_request_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_lock_req_hdr *req;
	struct smb2_lock_element *locks;
	int ret;

	pr_info("lock_request_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: single valid lock */
	req = (struct smb2_lock_req_hdr *)test_buf;
	req->StructureSize = cpu_to_le16(SMB2_LOCK_STRUCTURE_SIZE);
	req->LockCount = cpu_to_le16(1);
	locks = (struct smb2_lock_element *)(test_buf +
		sizeof(struct smb2_lock_req_hdr));
	locks[0].Offset = cpu_to_le64(0);
	locks[0].Length = cpu_to_le64(4096);
	locks[0].Flags = cpu_to_le32(SMB2_LOCKFLAG_EXCLUSIVE_LOCK);
	locks[0].Reserved = 0;

	ret = fuzz_lock_request(test_buf,
		sizeof(struct smb2_lock_req_hdr) +
		sizeof(struct smb2_lock_element));
	pr_info("lock_request_fuzz: single lock test returned %d\n", ret);

	/* Self-test 2: zero lock count */
	memset(test_buf, 0, 512);
	req = (struct smb2_lock_req_hdr *)test_buf;
	req->StructureSize = cpu_to_le16(SMB2_LOCK_STRUCTURE_SIZE);
	req->LockCount = cpu_to_le16(0);
	ret = fuzz_lock_request(test_buf, sizeof(struct smb2_lock_req_hdr));
	pr_info("lock_request_fuzz: zero locks test returned %d\n", ret);

	/* Self-test 3: overlapping ranges */
	memset(test_buf, 0, 512);
	req = (struct smb2_lock_req_hdr *)test_buf;
	req->StructureSize = cpu_to_le16(SMB2_LOCK_STRUCTURE_SIZE);
	req->LockCount = cpu_to_le16(2);
	locks = (struct smb2_lock_element *)(test_buf +
		sizeof(struct smb2_lock_req_hdr));
	locks[0].Offset = cpu_to_le64(0);
	locks[0].Length = cpu_to_le64(100);
	locks[0].Flags = cpu_to_le32(SMB2_LOCKFLAG_EXCLUSIVE_LOCK);
	locks[1].Offset = cpu_to_le64(50);
	locks[1].Length = cpu_to_le64(100);
	locks[1].Flags = cpu_to_le32(SMB2_LOCKFLAG_EXCLUSIVE_LOCK);

	ret = fuzz_lock_request(test_buf,
		sizeof(struct smb2_lock_req_hdr) +
		2 * sizeof(struct smb2_lock_element));
	pr_info("lock_request_fuzz: overlapping ranges test returned %d\n", ret);

	/* Self-test 4: max lock count (truncated buffer) */
	memset(test_buf, 0, 512);
	req = (struct smb2_lock_req_hdr *)test_buf;
	req->StructureSize = cpu_to_le16(SMB2_LOCK_STRUCTURE_SIZE);
	req->LockCount = cpu_to_le16(0xFFFF);
	ret = fuzz_lock_request(test_buf, sizeof(struct smb2_lock_req_hdr));
	pr_info("lock_request_fuzz: max lock count test returned %d\n", ret);

	/* Self-test 5: conflicting flags */
	memset(test_buf, 0, 512);
	req = (struct smb2_lock_req_hdr *)test_buf;
	req->StructureSize = cpu_to_le16(SMB2_LOCK_STRUCTURE_SIZE);
	req->LockCount = cpu_to_le16(1);
	locks = (struct smb2_lock_element *)(test_buf +
		sizeof(struct smb2_lock_req_hdr));
	locks[0].Offset = cpu_to_le64(0);
	locks[0].Length = cpu_to_le64(4096);
	locks[0].Flags = cpu_to_le32(SMB2_LOCKFLAG_SHARED_LOCK |
				     SMB2_LOCKFLAG_EXCLUSIVE_LOCK);

	ret = fuzz_lock_request(test_buf,
		sizeof(struct smb2_lock_req_hdr) +
		sizeof(struct smb2_lock_element));
	pr_info("lock_request_fuzz: conflicting flags test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit lock_request_fuzz_exit(void)
{
	pr_info("lock_request_fuzz: module unloaded\n");
}

module_init(lock_request_fuzz_init);
module_exit(lock_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2_LOCK request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
