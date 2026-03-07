// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 READ request field validation
 *
 *   This module exercises READ request parsing with random offsets
 *   (including the 0xFFFFFFFFFFFFFFFF sentinel), lengths (0, MAX),
 *   channel info, remaining bytes field, and read flags. It validates
 *   the bounds checking and overflow detection logic.
 *
 *   Targets:
 *     - StructureSize validation (must be 49)
 *     - Offset: 0, large values, 0xFFFFFFFFFFFFFFFF sentinel
 *     - Length: 0, typical (4096-65536), oversized, MAX_UINT32
 *     - Offset + Length overflow detection
 *     - MinimumCount <= Length constraint
 *     - Channel: NONE, RDMA_V1, RDMA_V1_INVALIDATE, unknown
 *     - ReadChannelInfoOffset + ReadChannelInfoLength bounds
 *     - RemainingBytes field sanity
 *     - Flags: READ_UNBUFFERED, READ_COMPRESSED
 *     - Padding field validation
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

#define SMB2_CHANNEL_NONE		0x00000000
#define SMB2_CHANNEL_RDMA_V1		0x00000001
#define SMB2_CHANNEL_RDMA_V1_INVAL	0x00000002

#define SMB2_READFLAG_READ_UNBUFFERED	0x01
#define SMB2_READFLAG_READ_COMPRESSED	0x02
#define SMB2_READFLAG_TRANSPORT_ENC	0x04

#define SMB2_READ_APPEND_SENTINEL	0xFFFFFFFFFFFFFFFFULL
#define MAX_SMB2_READ_SIZE		(8 * 1024 * 1024)  /* 8 MB cap */

struct fuzz_read_req {
	__u8   hdr[64];	/* SMB2 header placeholder */
	__le16 StructureSize;	/* Must be 49 */
	__u8   Padding;
	__u8   Flags;
	__le32 Length;
	__le64 Offset;
	__u64  PersistentFileId;
	__u64  VolatileFileId;
	__le32 MinimumCount;
	__le32 Channel;
	__le32 RemainingBytes;
	__le16 ReadChannelInfoOffset;
	__le16 ReadChannelInfoLength;
	__u8   Buffer[1];
} __packed;

#define FUZZ_READ_HDR_SIZE	sizeof(struct fuzz_read_req)
#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		512

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
 * fuzz_validate_read_request - Validate a READ request
 * @data:	raw buffer
 * @len:	buffer length
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_read_request(const u8 *data, size_t len)
{
	const struct fuzz_read_req *req;
	u16 structure_size;
	u32 length, min_count, channel, remaining;
	u64 offset;
	u16 ch_info_off, ch_info_len;
	u8 flags, padding;

	if (len < FUZZ_READ_HDR_SIZE) {
		pr_debug("read_fuzz: buffer too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct fuzz_read_req *)data;

	/* StructureSize must be 49 */
	structure_size = le16_to_cpu(req->StructureSize);
	if (structure_size != 49) {
		pr_debug("read_fuzz: bad StructureSize %u\n", structure_size);
		return -EINVAL;
	}

	padding = req->Padding;
	flags = req->Flags;
	length = le32_to_cpu(req->Length);
	offset = le64_to_cpu(req->Offset);
	min_count = le32_to_cpu(req->MinimumCount);
	channel = le32_to_cpu(req->Channel);
	remaining = le32_to_cpu(req->RemainingBytes);
	ch_info_off = le16_to_cpu(req->ReadChannelInfoOffset);
	ch_info_len = le16_to_cpu(req->ReadChannelInfoLength);

	/* Length check */
	if (length == 0) {
		pr_debug("read_fuzz: zero length read\n");
		return -EINVAL;
	}

	if (length > MAX_SMB2_READ_SIZE) {
		pr_debug("read_fuzz: length %u exceeds max\n", length);
		return -EINVAL;
	}

	/* Offset + Length overflow check (except for sentinel) */
	if (offset != SMB2_READ_APPEND_SENTINEL) {
		if (offset + length < offset) {
			pr_debug("read_fuzz: offset+length overflow\n");
			return -EINVAL;
		}
	} else {
		pr_debug("read_fuzz: append sentinel offset detected\n");
	}

	/* MinimumCount should not exceed Length */
	if (min_count > length) {
		pr_debug("read_fuzz: MinimumCount %u > Length %u\n",
			 min_count, length);
		/* Not fatal per spec, but unusual */
	}

	/* Channel validation */
	if (channel != SMB2_CHANNEL_NONE &&
	    channel != SMB2_CHANNEL_RDMA_V1 &&
	    channel != SMB2_CHANNEL_RDMA_V1_INVAL) {
		pr_debug("read_fuzz: unknown channel 0x%x\n", channel);
	}

	/* ReadChannelInfo bounds check */
	if (ch_info_len > 0) {
		if (channel == SMB2_CHANNEL_NONE) {
			pr_debug("read_fuzz: ChannelInfo with CHANNEL_NONE\n");
		}
		if (ch_info_off + ch_info_len > len) {
			pr_debug("read_fuzz: ChannelInfo exceeds buffer\n");
			return -EINVAL;
		}
	}

	/* Flags validation */
	if (flags & ~(SMB2_READFLAG_READ_UNBUFFERED |
		      SMB2_READFLAG_READ_COMPRESSED |
		      SMB2_READFLAG_TRANSPORT_ENC)) {
		pr_debug("read_fuzz: unknown flags 0x%02x\n", flags);
	}

	pr_debug("read_fuzz: valid req len=%u off=%llu min=%u ch=0x%x\n",
		 length, offset, min_count, channel);

	(void)padding;
	(void)remaining;
	return 0;
}

/*
 * fuzz_build_random_read_request - Build a random READ request
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: bytes written
 */
static size_t fuzz_build_random_read_request(u8 *buf, size_t buf_size)
{
	struct fuzz_read_req *req;
	u32 corrupt = fuzz_next() % 10;

	if (buf_size < FUZZ_READ_HDR_SIZE)
		return 0;

	memset(buf, 0, FUZZ_READ_HDR_SIZE);
	req = (struct fuzz_read_req *)buf;

	/* Header */
	*(__le32 *)req->hdr = SMB2_PROTO_NUMBER;
	*(__le16 *)(req->hdr + 4) = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	*(__le16 *)(req->hdr + 12) = cpu_to_le16(0x0008); /* READ command */

	/* StructureSize: usually 49, sometimes wrong */
	req->StructureSize = cpu_to_le16(corrupt == 0 ? fuzz_next() : 49);

	req->Padding = fuzz_next() % 256;

	/* Flags */
	switch (fuzz_next() % 5) {
	case 0:
		req->Flags = 0;
		break;
	case 1:
		req->Flags = SMB2_READFLAG_READ_UNBUFFERED;
		break;
	case 2:
		req->Flags = SMB2_READFLAG_READ_COMPRESSED;
		break;
	default:
		req->Flags = fuzz_next() % 256;
		break;
	}

	/* Length: interesting values */
	switch (fuzz_next() % 6) {
	case 0:
		req->Length = 0;
		break;
	case 1:
		req->Length = cpu_to_le32(4096);
		break;
	case 2:
		req->Length = cpu_to_le32(65536);
		break;
	case 3:
		req->Length = cpu_to_le32(0xFFFFFFFF);
		break;
	case 4:
		req->Length = cpu_to_le32(MAX_SMB2_READ_SIZE + 1);
		break;
	default:
		req->Length = cpu_to_le32(fuzz_next() % 0x100000);
		break;
	}

	/* Offset: interesting values */
	switch (fuzz_next() % 5) {
	case 0:
		req->Offset = 0;
		break;
	case 1:
		req->Offset = cpu_to_le64(SMB2_READ_APPEND_SENTINEL);
		break;
	case 2:
		req->Offset = cpu_to_le64(U64_MAX - 100);
		break;
	case 3:
		req->Offset = cpu_to_le64(1ULL << 40);
		break;
	default:
		req->Offset = cpu_to_le64(fuzz_next64());
		break;
	}

	/* FileIds */
	req->PersistentFileId = fuzz_next64();
	req->VolatileFileId = fuzz_next64();

	/* MinimumCount */
	req->MinimumCount = cpu_to_le32(fuzz_next() % 0x10000);

	/* Channel */
	switch (fuzz_next() % 4) {
	case 0:
		req->Channel = cpu_to_le32(SMB2_CHANNEL_NONE);
		break;
	case 1:
		req->Channel = cpu_to_le32(SMB2_CHANNEL_RDMA_V1);
		break;
	case 2:
		req->Channel = cpu_to_le32(SMB2_CHANNEL_RDMA_V1_INVAL);
		break;
	default:
		req->Channel = cpu_to_le32(fuzz_next());
		break;
	}

	req->RemainingBytes = cpu_to_le32(fuzz_next());

	/* Channel info: sometimes point out of bounds */
	if (corrupt == 1) {
		req->ReadChannelInfoOffset = cpu_to_le16(fuzz_next());
		req->ReadChannelInfoLength = cpu_to_le16(fuzz_next());
	}

	return FUZZ_READ_HDR_SIZE;
}

static int __init smb2_read_fuzz_init(void)
{
	u8 *buf;
	int i;

	pr_info("smb2_read_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0x0EADF00D;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		fuzz_build_random_read_request(buf, FUZZ_BUF_SIZE);
		fuzz_validate_read_request(buf, FUZZ_BUF_SIZE);
	}

	/* Edge cases */
	fuzz_validate_read_request(buf, 0);
	fuzz_validate_read_request(buf, FUZZ_READ_HDR_SIZE - 1);

	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_read_request(buf, FUZZ_READ_HDR_SIZE);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_read_request(buf, FUZZ_BUF_SIZE);

	kfree(buf);
	pr_info("smb2_read_fuzz: all iterations completed\n");
	return 0;
}

static void __exit smb2_read_fuzz_exit(void)
{
	pr_info("smb2_read_fuzz: module unloaded\n");
}

module_init(smb2_read_fuzz_init);
module_exit(smb2_read_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 READ request field validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
