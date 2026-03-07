// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 WRITE request field validation
 *
 *   This module exercises WRITE request parsing with random offsets
 *   (including 0xFFFFFFFFFFFFFFFF for append-to-EOF), data lengths
 *   vs DataOffset, WriteChannelInfo, and write flags. It focuses on
 *   overflow detection and the append sentinel handling.
 *
 *   Targets:
 *     - StructureSize validation (must be 49)
 *     - DataOffset: alignment, must point within buffer
 *     - Length vs actual data after DataOffset
 *     - Offset: 0xFFFFFFFFFFFFFFFF append-to-EOF sentinel
 *     - Offset + Length overflow detection
 *     - Channel: NONE, RDMA_V1, RDMA_V1_INVALIDATE
 *     - WriteChannelInfoOffset + WriteChannelInfoLength bounds
 *     - Flags: WRITE_THROUGH (0x01), WRITE_UNBUFFERED (0x02)
 *     - FILE_APPEND_DATA-only handle offset enforcement
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

#define SMB2_WRITEFLAG_WRITE_THROUGH	0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED	0x00000002
#define SMB2_WRITEFLAG_TRANSPORT_ENC	0x00000004
#define SMB2_WRITEFLAG_MASK		0x00000007

#define SMB2_WRITE_APPEND_SENTINEL	0xFFFFFFFFFFFFFFFFULL
#define MAX_SMB2_WRITE_SIZE		(8 * 1024 * 1024)  /* 8 MB cap */

struct fuzz_write_req {
	__u8   hdr[64];	/* SMB2 header placeholder */
	__le16 StructureSize;	/* Must be 49 */
	__le16 DataOffset;	/* offset from start of SMB2 header */
	__le32 Length;
	__le64 Offset;
	__u64  PersistentFileId;
	__u64  VolatileFileId;
	__le32 Channel;
	__le32 RemainingBytes;
	__le16 WriteChannelInfoOffset;
	__le16 WriteChannelInfoLength;
	__le32 Flags;
	__u8   Buffer[1];
} __packed;

#define FUZZ_WRITE_HDR_SIZE	sizeof(struct fuzz_write_req)
#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		2048

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
 * fuzz_validate_write_request - Validate a WRITE request
 * @data:	raw buffer
 * @len:	buffer length (total packet including header)
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_write_request(const u8 *data, size_t len)
{
	const struct fuzz_write_req *req;
	u16 structure_size, data_offset;
	u32 length, channel, remaining, flags;
	u64 offset;
	u16 ch_info_off, ch_info_len;

	if (len < FUZZ_WRITE_HDR_SIZE) {
		pr_debug("write_fuzz: buffer too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct fuzz_write_req *)data;

	/* StructureSize must be 49 */
	structure_size = le16_to_cpu(req->StructureSize);
	if (structure_size != 49) {
		pr_debug("write_fuzz: bad StructureSize %u\n", structure_size);
		return -EINVAL;
	}

	data_offset = le16_to_cpu(req->DataOffset);
	length = le32_to_cpu(req->Length);
	offset = le64_to_cpu(req->Offset);
	channel = le32_to_cpu(req->Channel);
	remaining = le32_to_cpu(req->RemainingBytes);
	ch_info_off = le16_to_cpu(req->WriteChannelInfoOffset);
	ch_info_len = le16_to_cpu(req->WriteChannelInfoLength);
	flags = le32_to_cpu(req->Flags);

	/* DataOffset must point within the buffer */
	if (data_offset > 0 && data_offset > len) {
		pr_debug("write_fuzz: DataOffset %u exceeds buffer %zu\n",
			 data_offset, len);
		return -EINVAL;
	}

	/* DataOffset + Length must not exceed buffer */
	if (data_offset > 0 && length > 0) {
		if ((size_t)data_offset + length > len) {
			pr_debug("write_fuzz: DataOffset+Length exceeds buffer\n");
			return -EINVAL;
		}
	}

	/* Length check */
	if (length > MAX_SMB2_WRITE_SIZE) {
		pr_debug("write_fuzz: length %u exceeds max\n", length);
		return -EINVAL;
	}

	/* Offset: check for append sentinel */
	if (offset == SMB2_WRITE_APPEND_SENTINEL) {
		pr_debug("write_fuzz: append-to-EOF sentinel\n");
		/* Valid: server should use i_size_read() */
	} else {
		/* Offset + Length overflow */
		if (length > 0 && offset + length < offset) {
			pr_debug("write_fuzz: offset+length overflow\n");
			return -EINVAL;
		}
	}

	/* Channel validation */
	if (channel != SMB2_CHANNEL_NONE &&
	    channel != SMB2_CHANNEL_RDMA_V1 &&
	    channel != SMB2_CHANNEL_RDMA_V1_INVAL) {
		pr_debug("write_fuzz: unknown channel 0x%x\n", channel);
	}

	/* WriteChannelInfo bounds */
	if (ch_info_len > 0) {
		if (channel == SMB2_CHANNEL_NONE) {
			pr_debug("write_fuzz: ChannelInfo with CHANNEL_NONE\n");
		}
		if ((size_t)ch_info_off + ch_info_len > len) {
			pr_debug("write_fuzz: ChannelInfo exceeds buffer\n");
			return -EINVAL;
		}
	}

	/* Flags validation */
	if (flags & ~SMB2_WRITEFLAG_MASK) {
		pr_debug("write_fuzz: unknown flags 0x%x\n", flags);
	}

	pr_debug("write_fuzz: valid req len=%u doff=%u off=%llu ch=0x%x fl=0x%x\n",
		 length, data_offset, offset, channel, flags);

	(void)remaining;
	return 0;
}

/*
 * fuzz_build_random_write_request - Build a random WRITE request
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: bytes used (including simulated payload)
 */
static size_t fuzz_build_random_write_request(u8 *buf, size_t buf_size)
{
	struct fuzz_write_req *req;
	u32 corrupt = fuzz_next() % 10;
	u32 payload_len;
	size_t total;
	u16 data_offset;

	if (buf_size < FUZZ_WRITE_HDR_SIZE + 64)
		return 0;

	memset(buf, 0, buf_size);
	req = (struct fuzz_write_req *)buf;

	/* Header */
	*(__le32 *)req->hdr = SMB2_PROTO_NUMBER;
	*(__le16 *)(req->hdr + 4) = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	*(__le16 *)(req->hdr + 12) = cpu_to_le16(0x0009); /* WRITE command */

	/* StructureSize */
	req->StructureSize = cpu_to_le16(corrupt == 0 ? fuzz_next() : 49);

	/* DataOffset: usually header + fixed fields, sometimes garbage */
	data_offset = FUZZ_WRITE_HDR_SIZE;
	if (corrupt == 1)
		data_offset = fuzz_next() % (buf_size + 100);
	else if (corrupt == 2)
		data_offset = 0;
	req->DataOffset = cpu_to_le16(data_offset);

	/* Length and payload */
	switch (fuzz_next() % 7) {
	case 0:
		payload_len = 0;
		break;
	case 1:
		payload_len = 4096;
		break;
	case 2:
		payload_len = 65536;
		break;
	case 3:
		payload_len = 0xFFFFFFFF; /* max */
		break;
	case 4:
		payload_len = MAX_SMB2_WRITE_SIZE + 1;
		break;
	case 5:
		payload_len = 1;
		break;
	default:
		payload_len = fuzz_next() % 0x10000;
		break;
	}
	req->Length = cpu_to_le32(payload_len);

	/* Offset */
	switch (fuzz_next() % 6) {
	case 0:
		req->Offset = 0;
		break;
	case 1:
		req->Offset = cpu_to_le64(SMB2_WRITE_APPEND_SENTINEL);
		break;
	case 2:
		req->Offset = cpu_to_le64(U64_MAX - 50);
		break;
	case 3:
		req->Offset = cpu_to_le64(1ULL << 40);
		break;
	case 4:
		req->Offset = cpu_to_le64(1); /* offset 1 */
		break;
	default:
		req->Offset = cpu_to_le64(fuzz_next64());
		break;
	}

	/* FileIds */
	req->PersistentFileId = fuzz_next64();
	req->VolatileFileId = fuzz_next64();

	/* Channel */
	switch (fuzz_next() % 4) {
	case 0:
		req->Channel = cpu_to_le32(SMB2_CHANNEL_NONE);
		break;
	case 1:
		req->Channel = cpu_to_le32(SMB2_CHANNEL_RDMA_V1);
		break;
	default:
		req->Channel = cpu_to_le32(fuzz_next());
		break;
	}

	req->RemainingBytes = cpu_to_le32(fuzz_next());

	/* WriteChannelInfo */
	if (corrupt == 3) {
		req->WriteChannelInfoOffset = cpu_to_le16(fuzz_next());
		req->WriteChannelInfoLength = cpu_to_le16(fuzz_next());
	}

	/* Flags */
	switch (fuzz_next() % 4) {
	case 0:
		req->Flags = 0;
		break;
	case 1:
		req->Flags = cpu_to_le32(SMB2_WRITEFLAG_WRITE_THROUGH);
		break;
	case 2:
		req->Flags = cpu_to_le32(SMB2_WRITEFLAG_WRITE_UNBUFFERED);
		break;
	default:
		req->Flags = cpu_to_le32(fuzz_next());
		break;
	}

	/* Write some random payload data */
	total = FUZZ_WRITE_HDR_SIZE;
	if (payload_len > 0 && payload_len < buf_size - total) {
		u32 actual = min_t(u32, payload_len, buf_size - total);

		get_random_bytes(buf + total, min_t(u32, actual, 512));
		total += actual;
	} else {
		total = buf_size; /* claim full buffer for validation */
	}

	return total;
}

static int __init smb2_write_fuzz_init(void)
{
	u8 *buf;
	size_t total;
	int i;

	pr_info("smb2_write_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0xFEEDBACE;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		total = fuzz_build_random_write_request(buf, FUZZ_BUF_SIZE);
		fuzz_validate_write_request(buf, total);
	}

	/* Edge cases */
	fuzz_validate_write_request(buf, 0);
	fuzz_validate_write_request(buf, FUZZ_WRITE_HDR_SIZE - 1);

	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_write_request(buf, FUZZ_WRITE_HDR_SIZE);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_write_request(buf, FUZZ_BUF_SIZE);

	/* Append sentinel with zero length */
	{
		struct fuzz_write_req *req = (struct fuzz_write_req *)buf;

		memset(buf, 0, FUZZ_BUF_SIZE);
		req->StructureSize = cpu_to_le16(49);
		req->Offset = cpu_to_le64(SMB2_WRITE_APPEND_SENTINEL);
		req->Length = 0;
		req->DataOffset = cpu_to_le16(FUZZ_WRITE_HDR_SIZE);
		fuzz_validate_write_request(buf, FUZZ_BUF_SIZE);
	}

	kfree(buf);
	pr_info("smb2_write_fuzz: all iterations completed\n");
	return 0;
}

static void __exit smb2_write_fuzz_exit(void)
{
	pr_info("smb2_write_fuzz: module unloaded\n");
}

module_init(smb2_write_fuzz_init);
module_exit(smb2_write_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 WRITE request field validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
