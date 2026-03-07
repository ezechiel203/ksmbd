// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 WRITE request validation
 *
 *   This module exercises the WRITE request header parsing including
 *   DataOffset, Length, Offset validation, and the special sentinel
 *   value 0xFFFFFFFFFFFFFFFF for append-to-EOF.
 *
 *   Targets:
 *     - StructureSize validation (must be 49)
 *     - DataOffset: must point within buffer, alignment
 *     - Length: must match DataOffset + buffer size
 *     - Offset: 0xFFFFFFFFFFFFFFFF sentinel (append-to-EOF)
 *     - Offset + Length overflow check
 *     - WriteChannelInfo for RDMA
 *     - Flags: WRITE_UNBUFFERED, REQUEST_TRANSPORT_ENCRYPTION
 *
 *   Corpus seed hints:
 *     - WRITE req: StructureSize=49, DataOffset=112, Length=4096,
 *       Offset=0, Flags=0
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 WRITE request structure */
struct smb2_write_req_fuzz {
	__le16 StructureSize;	/* Must be 49 */
	__le16 DataOffset;
	__le32 Length;
	__le64 Offset;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
	__le32 Channel;
	__le32 RemainingBytes;
	__le16 WriteChannelInfoOffset;
	__le16 WriteChannelInfoLength;
	__le32 Flags;
	/* Followed by data at DataOffset */
} __packed;

#define WRITE_STRUCTURE_SIZE	49
#define WRITE_HDR_SIZE		sizeof(struct smb2_write_req_fuzz)
#define WRITE_APPEND_SENTINEL	0xFFFFFFFFFFFFFFFFULL
#define MAX_WRITE_LENGTH	(8 * 1024 * 1024)

/* Write flags */
#define SMB2_WRITEFLAG_WRITE_THROUGH		0x00000001
#define SMB2_WRITEFLAG_WRITE_UNBUFFERED		0x00000002

/*
 * fuzz_write_request - Fuzz SMB2 WRITE request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_write_request(const u8 *data, size_t len)
{
	const struct smb2_write_req_fuzz *req;
	u16 structure_size;
	u16 data_offset;
	u32 length;
	u64 offset;
	u32 flags;
	u16 channel_info_offset, channel_info_length;

	if (len < WRITE_HDR_SIZE) {
		pr_debug("fuzz_write: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_write_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	data_offset = le16_to_cpu(req->DataOffset);
	length = le32_to_cpu(req->Length);
	offset = le64_to_cpu(req->Offset);
	flags = le32_to_cpu(req->Flags);
	channel_info_offset = le16_to_cpu(req->WriteChannelInfoOffset);
	channel_info_length = le16_to_cpu(req->WriteChannelInfoLength);

	/* Validate structure size */
	if (structure_size != WRITE_STRUCTURE_SIZE) {
		pr_debug("fuzz_write: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Length sanity */
	if (length > MAX_WRITE_LENGTH) {
		pr_debug("fuzz_write: length %u > max %u\n",
			 length, MAX_WRITE_LENGTH);
		return -EINVAL;
	}

	if (length == 0) {
		pr_debug("fuzz_write: zero length write\n");
		return -EINVAL;
	}

	/* DataOffset must be within buffer */
	if (data_offset > 0 && (u32)data_offset + length > len) {
		pr_debug("fuzz_write: data overflow off=%u len=%u buf=%zu\n",
			 data_offset, length, len);
		return -EINVAL;
	}

	/* Check append-to-EOF sentinel */
	if (offset == WRITE_APPEND_SENTINEL) {
		pr_debug("fuzz_write: append-to-EOF sentinel detected\n");
	} else {
		/* Check offset + length overflow */
		if (offset + length < offset) {
			pr_debug("fuzz_write: offset+length overflow\n");
			return -EINVAL;
		}
	}

	/* WriteChannelInfo validation */
	if (channel_info_length > 0) {
		if ((u32)channel_info_offset + channel_info_length > len) {
			pr_debug("fuzz_write: channel info overflow\n");
			return -EINVAL;
		}
	}

	pr_debug("fuzz_write: off=%llu len=%u data_off=%u flags=0x%08x\n",
		 offset, length, data_offset, flags);

	return 0;
}

static int __init write_request_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_write_req_fuzz *req;
	int ret;

	pr_info("write_request_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid write */
	req = (struct smb2_write_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(WRITE_STRUCTURE_SIZE);
	req->DataOffset = cpu_to_le16(WRITE_HDR_SIZE);
	req->Length = cpu_to_le32(64);
	req->Offset = cpu_to_le64(0);

	ret = fuzz_write_request(test_buf, WRITE_HDR_SIZE + 64);
	pr_info("write_request_fuzz: valid returned %d\n", ret);

	/* Self-test 2: append-to-EOF */
	req->Offset = cpu_to_le64(WRITE_APPEND_SENTINEL);
	ret = fuzz_write_request(test_buf, WRITE_HDR_SIZE + 64);
	pr_info("write_request_fuzz: append-EOF returned %d\n", ret);

	/* Self-test 3: offset + length overflow */
	req->Offset = cpu_to_le64(0xFFFFFFFFFFFFFF00ULL);
	req->Length = cpu_to_le32(0x200);
	ret = fuzz_write_request(test_buf, WRITE_HDR_SIZE + 0x200);
	pr_info("write_request_fuzz: overflow returned %d\n", ret);

	/* Self-test 4: zero length */
	req->Offset = 0;
	req->Length = 0;
	ret = fuzz_write_request(test_buf, WRITE_HDR_SIZE);
	pr_info("write_request_fuzz: zero length returned %d\n", ret);

	/* Self-test 5: truncated */
	ret = fuzz_write_request(test_buf, 8);
	pr_info("write_request_fuzz: truncated returned %d\n", ret);

	/* Self-test 6: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_write_request(test_buf, 512);
	pr_info("write_request_fuzz: garbage returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit write_request_fuzz_exit(void)
{
	pr_info("write_request_fuzz: module unloaded\n");
}

module_init(write_request_fuzz_init);
module_exit(write_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 WRITE request validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
