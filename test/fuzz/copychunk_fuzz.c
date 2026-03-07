// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for FSCTL_COPYCHUNK request validation
 *
 *   This module exercises the copychunk IOCTL input buffer parsing.
 *   FSCTL_COPYCHUNK (0x001440F2) and FSCTL_COPYCHUNK_WRITE carry a
 *   source key followed by an array of chunk descriptors. Malformed
 *   requests can cause integer overflows, out-of-bounds reads, or
 *   excessive resource consumption.
 *
 *   Targets:
 *     - copychunk_ioctl_req: SourceKey, ChunkCount, Reserved
 *     - srv_copychunk array: SourceOffset, TargetOffset, Length
 *     - ChunkCount vs buffer length validation
 *     - Overlapping source/target ranges
 *
 *   Corpus seed hints:
 *     - 24-byte SourceKey + le32(ChunkCount=1) + le32(0) +
 *       srv_copychunk(0, 0, 4096)
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* Copy chunk structures (MS-SMB2 2.2.31.1) */
struct srv_copychunk {
	__le64 SourceOffset;
	__le64 TargetOffset;
	__le32 Length;
	__le32 Reserved;
} __packed;

struct copychunk_ioctl_req {
	__u8   SourceKey[24];
	__le32 ChunkCount;
	__le32 Reserved;
	/* Followed by ChunkCount * srv_copychunk */
} __packed;

#define COPYCHUNK_HDR_SIZE	sizeof(struct copychunk_ioctl_req)
#define COPYCHUNK_ELEM_SIZE	sizeof(struct srv_copychunk)
#define MAX_CHUNK_COUNT		256  /* ksmbd limit */

/*
 * fuzz_copychunk_request - Fuzz FSCTL_COPYCHUNK input buffer
 * @data:	raw FSCTL input buffer
 * @len:	length of buffer
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_copychunk_request(const u8 *data, size_t len)
{
	const struct copychunk_ioctl_req *req;
	const struct srv_copychunk *chunks;
	u32 chunk_count;
	size_t required;
	u32 i;
	int overlap_count = 0;

	if (len < COPYCHUNK_HDR_SIZE) {
		pr_debug("fuzz_copychunk: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct copychunk_ioctl_req *)data;
	chunk_count = le32_to_cpu(req->ChunkCount);

	/* Validate chunk count */
	if (chunk_count == 0) {
		pr_debug("fuzz_copychunk: zero ChunkCount\n");
		return -EINVAL;
	}

	if (chunk_count > MAX_CHUNK_COUNT) {
		pr_debug("fuzz_copychunk: ChunkCount %u exceeds max %u\n",
			 chunk_count, MAX_CHUNK_COUNT);
		return -EINVAL;
	}

	/* Check buffer has room for all chunks */
	required = COPYCHUNK_HDR_SIZE +
		   (size_t)chunk_count * COPYCHUNK_ELEM_SIZE;
	if (required > len) {
		pr_debug("fuzz_copychunk: need %zu bytes, have %zu\n",
			 required, len);
		return -EINVAL;
	}

	chunks = (const struct srv_copychunk *)(data + COPYCHUNK_HDR_SIZE);

	/* Validate each chunk */
	for (i = 0; i < chunk_count; i++) {
		u64 src_off = le64_to_cpu(chunks[i].SourceOffset);
		u64 tgt_off = le64_to_cpu(chunks[i].TargetOffset);
		u32 length = le32_to_cpu(chunks[i].Length);

		/* Zero-length copy not useful */
		if (length == 0) {
			pr_debug("fuzz_copychunk: chunk %u has zero length\n", i);
		}

		/* Check for offset + length overflow */
		if (length > 0 && src_off + length < src_off) {
			pr_debug("fuzz_copychunk: chunk %u source overflow\n", i);
			return -EINVAL;
		}
		if (length > 0 && tgt_off + length < tgt_off) {
			pr_debug("fuzz_copychunk: chunk %u target overflow\n", i);
			return -EINVAL;
		}

		pr_debug("fuzz_copychunk: [%u] src=%llu tgt=%llu len=%u\n",
			 i, src_off, tgt_off, length);
	}

	/* Check for overlapping source/target ranges between chunks */
	for (i = 0; i < chunk_count && i < 64; i++) {
		u32 j;

		for (j = i + 1; j < chunk_count && j < 64; j++) {
			u64 s1 = le64_to_cpu(chunks[i].TargetOffset);
			u32 l1 = le32_to_cpu(chunks[i].Length);
			u64 s2 = le64_to_cpu(chunks[j].TargetOffset);
			u32 l2 = le32_to_cpu(chunks[j].Length);

			if (l1 > 0 && l2 > 0 &&
			    s1 < s2 + l2 && s2 < s1 + l1) {
				overlap_count++;
			}
		}
	}

	if (overlap_count > 0)
		pr_debug("fuzz_copychunk: %d overlapping target ranges\n",
			 overlap_count);

	return 0;
}

static int __init copychunk_fuzz_init(void)
{
	u8 *test_buf;
	struct copychunk_ioctl_req *req;
	struct srv_copychunk *chunks;
	int ret;

	pr_info("copychunk_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: single chunk */
	req = (struct copychunk_ioctl_req *)test_buf;
	memset(req->SourceKey, 0xAA, 24);
	req->ChunkCount = cpu_to_le32(1);
	chunks = (struct srv_copychunk *)(test_buf + COPYCHUNK_HDR_SIZE);
	chunks[0].SourceOffset = cpu_to_le64(0);
	chunks[0].TargetOffset = cpu_to_le64(0);
	chunks[0].Length = cpu_to_le32(4096);

	ret = fuzz_copychunk_request(test_buf, COPYCHUNK_HDR_SIZE + COPYCHUNK_ELEM_SIZE);
	pr_info("copychunk_fuzz: single chunk returned %d\n", ret);

	/* Self-test 2: zero ChunkCount */
	req->ChunkCount = 0;
	ret = fuzz_copychunk_request(test_buf, COPYCHUNK_HDR_SIZE);
	pr_info("copychunk_fuzz: zero count returned %d\n", ret);

	/* Self-test 3: huge ChunkCount (truncated buffer) */
	req->ChunkCount = cpu_to_le32(0xFFFFFFFF);
	ret = fuzz_copychunk_request(test_buf, COPYCHUNK_HDR_SIZE + 32);
	pr_info("copychunk_fuzz: huge count returned %d\n", ret);

	/* Self-test 4: overlapping target ranges */
	memset(test_buf, 0, 512);
	req = (struct copychunk_ioctl_req *)test_buf;
	req->ChunkCount = cpu_to_le32(2);
	chunks = (struct srv_copychunk *)(test_buf + COPYCHUNK_HDR_SIZE);
	chunks[0].SourceOffset = cpu_to_le64(0);
	chunks[0].TargetOffset = cpu_to_le64(0);
	chunks[0].Length = cpu_to_le32(100);
	chunks[1].SourceOffset = cpu_to_le64(200);
	chunks[1].TargetOffset = cpu_to_le64(50);
	chunks[1].Length = cpu_to_le32(100);

	ret = fuzz_copychunk_request(test_buf, COPYCHUNK_HDR_SIZE + 2 * COPYCHUNK_ELEM_SIZE);
	pr_info("copychunk_fuzz: overlap returned %d\n", ret);

	/* Self-test 5: source offset + length overflow */
	memset(test_buf, 0, 512);
	req = (struct copychunk_ioctl_req *)test_buf;
	req->ChunkCount = cpu_to_le32(1);
	chunks = (struct srv_copychunk *)(test_buf + COPYCHUNK_HDR_SIZE);
	chunks[0].SourceOffset = cpu_to_le64(0xFFFFFFFFFFFFFF00ULL);
	chunks[0].TargetOffset = cpu_to_le64(0);
	chunks[0].Length = cpu_to_le32(0x200);

	ret = fuzz_copychunk_request(test_buf, COPYCHUNK_HDR_SIZE + COPYCHUNK_ELEM_SIZE);
	pr_info("copychunk_fuzz: overflow returned %d\n", ret);

	/* Self-test 6: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_copychunk_request(test_buf, 512);
	pr_info("copychunk_fuzz: garbage returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit copychunk_fuzz_exit(void)
{
	pr_info("copychunk_fuzz: module unloaded\n");
}

module_init(copychunk_fuzz_init);
module_exit(copychunk_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for FSCTL_COPYCHUNK request validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
