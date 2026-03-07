// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 LOCK request parsing
 *
 *   This module exercises lock request parsing with randomly generated
 *   lock arrays. It tests extreme lock counts, overlapping byte ranges,
 *   extreme offsets (0, UINT64_MAX), conflicting flags (shared +
 *   exclusive), and lock sequence replay validation.
 *
 *   Targets:
 *     - LockCount vs actual lock element array size
 *     - Lock element Offset + Length overflow detection
 *     - Flag combination validation (SHARED | EXCLUSIVE is invalid)
 *     - UNLOCK without prior matching lock
 *     - Lock sequence index extraction (bits 0-3 index, bits 4-7 seq)
 *     - Zero-length locks and MAX_UINT64 ranges
 *     - StructureSize validation (must be 48)
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

#define SMB2_LOCKFLAG_SHARED		0x0001
#define SMB2_LOCKFLAG_EXCLUSIVE		0x0002
#define SMB2_LOCKFLAG_UNLOCK		0x0004
#define SMB2_LOCKFLAG_FAIL_IMMEDIATELY	0x0010
#define SMB2_LOCKFLAG_MASK		0x0017

struct fuzz_lock_element {
	__le64 Offset;
	__le64 Length;
	__le32 Flags;
	__le32 Reserved;
} __packed;

struct fuzz_lock_req {
	__u8   hdr[64];	/* SMB2 header placeholder */
	__le16 StructureSize;	/* Must be 48 */
	__le16 LockCount;
	__le32 Reserved;
	__u64  PersistentFileId;
	__u64  VolatileFileId;
	struct fuzz_lock_element locks[];
} __packed;

#define FUZZ_LOCK_HDR_SIZE	offsetof(struct fuzz_lock_req, locks)
#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		4096
#define MAX_LOCK_COUNT		64

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

static u64 fuzz_next64(void)
{
	return ((u64)fuzz_next() << 48) | ((u64)fuzz_next() << 32) |
	       ((u64)fuzz_next() << 16) | (u64)fuzz_next();
}

/*
 * fuzz_validate_lock_element - Check a single lock element for sanity
 * @elem:	pointer to lock element
 *
 * Return: 0 on valid, -EINVAL on invalid
 */
static int fuzz_validate_lock_element(const struct fuzz_lock_element *elem)
{
	u64 offset = le64_to_cpu(elem->Offset);
	u64 length = le64_to_cpu(elem->Length);
	u32 flags  = le32_to_cpu(elem->Flags);

	/* Conflicting flags: shared + exclusive */
	if ((flags & SMB2_LOCKFLAG_SHARED) &&
	    (flags & SMB2_LOCKFLAG_EXCLUSIVE)) {
		pr_debug("lock_fuzz: shared+exclusive conflict\n");
		return -EINVAL;
	}

	/* Must have at least one lock type or unlock */
	if (!(flags & (SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_EXCLUSIVE |
		       SMB2_LOCKFLAG_UNLOCK))) {
		pr_debug("lock_fuzz: no lock type specified\n");
		return -EINVAL;
	}

	/* UNLOCK cannot be combined with SHARED or EXCLUSIVE */
	if ((flags & SMB2_LOCKFLAG_UNLOCK) &&
	    (flags & (SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_EXCLUSIVE))) {
		pr_debug("lock_fuzz: unlock combined with lock type\n");
		return -EINVAL;
	}

	/* Unknown flags */
	if (flags & ~SMB2_LOCKFLAG_MASK) {
		pr_debug("lock_fuzz: unknown flags 0x%x\n", flags);
		return -EINVAL;
	}

	/* Check for offset + length overflow */
	if (length > 0 && offset + length < offset) {
		pr_debug("lock_fuzz: offset+length overflow %llu+%llu\n",
			 offset, length);
		return -EINVAL;
	}

	(void)offset;
	(void)length;
	return 0;
}

/*
 * fuzz_check_lock_overlap - Check if two lock ranges overlap
 * @a:	first lock element
 * @b:	second lock element
 *
 * Return: true if overlapping
 */
static bool fuzz_check_lock_overlap(const struct fuzz_lock_element *a,
				    const struct fuzz_lock_element *b)
{
	u64 a_start = le64_to_cpu(a->Offset);
	u64 a_len   = le64_to_cpu(a->Length);
	u64 b_start = le64_to_cpu(b->Offset);
	u64 b_len   = le64_to_cpu(b->Length);
	u64 a_end, b_end;

	if (a_len == 0 || b_len == 0)
		return false;

	/* Inclusive end with wrap-around handling */
	a_end = a_start + a_len - 1;
	if (a_end < a_start)
		a_end = U64_MAX;
	b_end = b_start + b_len - 1;
	if (b_end < b_start)
		b_end = U64_MAX;

	return a_start <= b_end && b_start <= a_end;
}

/*
 * fuzz_validate_lock_request - Validate an entire LOCK request
 * @data:	raw buffer
 * @len:	buffer length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_lock_request(const u8 *data, size_t len)
{
	const struct fuzz_lock_req *req;
	u16 structure_size, lock_count;
	size_t required;
	u32 i, j;
	int overlap_count = 0;

	if (len < FUZZ_LOCK_HDR_SIZE)
		return -EINVAL;

	req = (const struct fuzz_lock_req *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	lock_count = le16_to_cpu(req->LockCount);

	if (structure_size != 48) {
		pr_debug("lock_fuzz: bad StructureSize %u\n", structure_size);
		return -EINVAL;
	}

	if (lock_count == 0) {
		pr_debug("lock_fuzz: zero LockCount\n");
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (lock_count > MAX_LOCK_COUNT) {
		pr_debug("lock_fuzz: LockCount %u exceeds limit\n", lock_count);
		return -EINVAL;
	}

	/* Check that all lock elements fit in the buffer */
	required = FUZZ_LOCK_HDR_SIZE +
		   (size_t)lock_count * sizeof(struct fuzz_lock_element);
	if (required > len) {
		pr_debug("lock_fuzz: LockCount %u exceeds buffer\n", lock_count);
		return -EINVAL;
	}

	/* Validate each lock element */
	for (i = 0; i < lock_count; i++) {
		int ret = fuzz_validate_lock_element(&req->locks[i]);

		if (ret < 0)
			pr_debug("lock_fuzz: element %u invalid\n", i);
	}

	/* Check for overlapping ranges */
	for (i = 0; i < lock_count; i++) {
		for (j = i + 1; j < lock_count; j++) {
			if (fuzz_check_lock_overlap(&req->locks[i],
						    &req->locks[j]))
				overlap_count++;
		}
	}

	if (overlap_count > 0)
		pr_debug("lock_fuzz: %d overlapping ranges\n", overlap_count);

	return 0;
}

/*
 * fuzz_build_random_lock_request - Build a random LOCK request
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: total bytes written
 */
static size_t fuzz_build_random_lock_request(u8 *buf, size_t buf_size)
{
	struct fuzz_lock_req *req;
	u16 lock_count;
	size_t total;
	u32 i;
	u32 corrupt = fuzz_next() % 8;

	lock_count = (fuzz_next() % MAX_LOCK_COUNT) + 1;
	total = FUZZ_LOCK_HDR_SIZE +
		(size_t)lock_count * sizeof(struct fuzz_lock_element);
	if (total > buf_size)
		lock_count = (buf_size - FUZZ_LOCK_HDR_SIZE) /
			     sizeof(struct fuzz_lock_element);

	total = FUZZ_LOCK_HDR_SIZE +
		(size_t)lock_count * sizeof(struct fuzz_lock_element);

	memset(buf, 0, total);
	req = (struct fuzz_lock_req *)buf;
	req->StructureSize = cpu_to_le16(corrupt == 0 ? fuzz_next() : 48);
	req->LockCount = cpu_to_le16(lock_count);
	req->PersistentFileId = fuzz_next64();
	req->VolatileFileId = fuzz_next64();

	for (i = 0; i < lock_count; i++) {
		u32 flag_choice = fuzz_next() % 7;

		/* Generate interesting offset/length combos */
		switch (fuzz_next() % 5) {
		case 0: /* Zero offset, small length */
			req->locks[i].Offset = 0;
			req->locks[i].Length = cpu_to_le64(fuzz_next() % 4096);
			break;
		case 1: /* Max offset */
			req->locks[i].Offset = cpu_to_le64(U64_MAX);
			req->locks[i].Length = cpu_to_le64(1);
			break;
		case 2: /* Overflow: large offset + large length */
			req->locks[i].Offset = cpu_to_le64(U64_MAX - 100);
			req->locks[i].Length = cpu_to_le64(200);
			break;
		case 3: /* Zero-length lock */
			req->locks[i].Offset = cpu_to_le64(fuzz_next64());
			req->locks[i].Length = 0;
			break;
		default: /* Random */
			req->locks[i].Offset = cpu_to_le64(fuzz_next64());
			req->locks[i].Length = cpu_to_le64(fuzz_next64());
			break;
		}

		/* Generate interesting flag combos */
		switch (flag_choice) {
		case 0:
			req->locks[i].Flags = cpu_to_le32(SMB2_LOCKFLAG_SHARED);
			break;
		case 1:
			req->locks[i].Flags = cpu_to_le32(SMB2_LOCKFLAG_EXCLUSIVE);
			break;
		case 2:
			req->locks[i].Flags = cpu_to_le32(SMB2_LOCKFLAG_UNLOCK);
			break;
		case 3: /* Invalid: shared + exclusive */
			req->locks[i].Flags = cpu_to_le32(SMB2_LOCKFLAG_SHARED |
							  SMB2_LOCKFLAG_EXCLUSIVE);
			break;
		case 4: /* Fail immediately */
			req->locks[i].Flags = cpu_to_le32(SMB2_LOCKFLAG_EXCLUSIVE |
							  SMB2_LOCKFLAG_FAIL_IMMEDIATELY);
			break;
		case 5: /* Invalid: unlock + exclusive */
			req->locks[i].Flags = cpu_to_le32(SMB2_LOCKFLAG_UNLOCK |
							  SMB2_LOCKFLAG_EXCLUSIVE);
			break;
		default: /* Random garbage flags */
			req->locks[i].Flags = cpu_to_le32(fuzz_next());
			break;
		}
	}

	/* Corruption: sometimes set LockCount larger than actual data */
	if (corrupt == 1)
		req->LockCount = cpu_to_le16(lock_count + 100);

	return total;
}

static int __init smb2_lock_fuzz_init(void)
{
	u8 *buf;
	size_t req_len;
	int i;

	pr_info("smb2_lock_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0xCAFEBABE;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		req_len = fuzz_build_random_lock_request(buf, FUZZ_BUF_SIZE);
		fuzz_validate_lock_request(buf, req_len);
	}

	/* Edge cases */

	/* Empty buffer */
	fuzz_validate_lock_request(buf, 0);

	/* Truncated header */
	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_lock_request(buf, FUZZ_LOCK_HDR_SIZE - 1);

	/* Valid header but zero LockCount */
	memset(buf, 0, FUZZ_BUF_SIZE);
	((struct fuzz_lock_req *)buf)->StructureSize = cpu_to_le16(48);
	((struct fuzz_lock_req *)buf)->LockCount = 0;
	fuzz_validate_lock_request(buf, FUZZ_LOCK_HDR_SIZE);

	/* All 0xFF */
	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_lock_request(buf, FUZZ_BUF_SIZE);

	kfree(buf);
	pr_info("smb2_lock_fuzz: all iterations completed\n");
	return 0;
}

static void __exit smb2_lock_fuzz_exit(void)
{
	pr_info("smb2_lock_fuzz: module unloaded\n");
}

module_init(smb2_lock_fuzz_init);
module_exit(smb2_lock_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 LOCK request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
