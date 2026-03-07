// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 READ request validation
 *
 *   This module exercises the READ request header parsing including
 *   DataOffset, Length, Offset validation, ReadChannelInfo for RDMA,
 *   and read flags.
 *
 *   Targets:
 *     - StructureSize validation (must be 49)
 *     - Offset + Length overflow check
 *     - Length cap against max read size
 *     - MinimumCount validation
 *     - ReadChannelInfo offset/length for RDMA
 *     - Flags: READ_UNBUFFERED, READ_COMPRESSED
 *
 *   Corpus seed hints:
 *     - READ req: StructureSize=49, Length=4096, Offset=0, Flags=0
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 READ request structure */
struct smb2_read_req_fuzz {
	__le16 StructureSize;	/* Must be 49 */
	__u8   Padding;
	__u8   Flags;
	__le32 Length;
	__le64 Offset;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
	__le32 MinimumCount;
	__le32 Channel;
	__le32 RemainingBytes;
	__le16 ReadChannelInfoOffset;
	__le16 ReadChannelInfoLength;
	__u8   Buffer[1];
} __packed;

#define READ_STRUCTURE_SIZE	49
#define READ_HDR_SIZE		offsetof(struct smb2_read_req_fuzz, Buffer)
#define MAX_READ_LENGTH		(8 * 1024 * 1024)

/* Read flags */
#define SMB2_READFLAG_READ_UNBUFFERED		0x01
#define SMB2_READFLAG_READ_COMPRESSED		0x02
#define SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION	0x04

/*
 * fuzz_read_request - Fuzz SMB2 READ request
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_read_request(const u8 *data, size_t len)
{
	const struct smb2_read_req_fuzz *req;
	u16 structure_size;
	u8 flags;
	u32 length;
	u64 offset;
	u32 minimum_count;
	u16 channel_info_offset, channel_info_length;

	if (len < READ_HDR_SIZE) {
		pr_debug("fuzz_read: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_read_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	flags = req->Flags;
	length = le32_to_cpu(req->Length);
	offset = le64_to_cpu(req->Offset);
	minimum_count = le32_to_cpu(req->MinimumCount);
	channel_info_offset = le16_to_cpu(req->ReadChannelInfoOffset);
	channel_info_length = le16_to_cpu(req->ReadChannelInfoLength);

	/* Validate structure size */
	if (structure_size != READ_STRUCTURE_SIZE) {
		pr_debug("fuzz_read: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Length validation */
	if (length == 0) {
		pr_debug("fuzz_read: zero length read\n");
		return -EINVAL;
	}

	if (length > MAX_READ_LENGTH) {
		pr_debug("fuzz_read: length %u > max %u\n",
			 length, MAX_READ_LENGTH);
		return -EINVAL;
	}

	/* MinimumCount should not exceed Length */
	if (minimum_count > length) {
		pr_debug("fuzz_read: MinimumCount %u > Length %u\n",
			 minimum_count, length);
		return -EINVAL;
	}

	/* Offset + Length overflow check */
	if (offset + length < offset) {
		pr_debug("fuzz_read: offset+length overflow\n");
		return -EINVAL;
	}

	/* ReadChannelInfo validation */
	if (channel_info_length > 0) {
		if ((u32)channel_info_offset + channel_info_length > len) {
			pr_debug("fuzz_read: channel info overflow\n");
			return -EINVAL;
		}
	}

	/* Flag validation */
	if (flags & ~(SMB2_READFLAG_READ_UNBUFFERED |
		      SMB2_READFLAG_READ_COMPRESSED |
		      SMB2_READFLAG_REQUEST_TRANSPORT_ENCRYPTION)) {
		pr_debug("fuzz_read: reserved flags set 0x%02x\n", flags);
	}

	pr_debug("fuzz_read: off=%llu len=%u min=%u flags=0x%02x\n",
		 offset, length, minimum_count, flags);

	return 0;
}

static int __init read_request_fuzz_init(void)
{
	u8 test_buf[128];
	struct smb2_read_req_fuzz *req;
	int ret;

	pr_info("read_request_fuzz: module loaded\n");

	/* Self-test 1: valid read */
	memset(test_buf, 0, sizeof(test_buf));
	req = (struct smb2_read_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(READ_STRUCTURE_SIZE);
	req->Length = cpu_to_le32(4096);
	req->Offset = cpu_to_le64(0);
	req->MinimumCount = cpu_to_le32(0);

	ret = fuzz_read_request(test_buf, READ_HDR_SIZE);
	pr_info("read_request_fuzz: valid returned %d\n", ret);

	/* Self-test 2: zero length */
	req->Length = 0;
	ret = fuzz_read_request(test_buf, READ_HDR_SIZE);
	pr_info("read_request_fuzz: zero length returned %d\n", ret);

	/* Self-test 3: offset + length overflow */
	req->Length = cpu_to_le32(0x200);
	req->Offset = cpu_to_le64(0xFFFFFFFFFFFFFF00ULL);
	ret = fuzz_read_request(test_buf, READ_HDR_SIZE);
	pr_info("read_request_fuzz: overflow returned %d\n", ret);

	/* Self-test 4: MinimumCount > Length */
	req->Offset = 0;
	req->Length = cpu_to_le32(100);
	req->MinimumCount = cpu_to_le32(200);
	ret = fuzz_read_request(test_buf, READ_HDR_SIZE);
	pr_info("read_request_fuzz: min>len returned %d\n", ret);

	/* Self-test 5: truncated */
	ret = fuzz_read_request(test_buf, 8);
	pr_info("read_request_fuzz: truncated returned %d\n", ret);

	/* Self-test 6: garbage */
	memset(test_buf, 0xFF, sizeof(test_buf));
	ret = fuzz_read_request(test_buf, sizeof(test_buf));
	pr_info("read_request_fuzz: garbage returned %d\n", ret);

	return 0;
}

static void __exit read_request_fuzz_exit(void)
{
	pr_info("read_request_fuzz: module unloaded\n");
}

module_init(read_request_fuzz_init);
module_exit(read_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 READ request validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
