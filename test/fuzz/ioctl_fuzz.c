// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 IOCTL request parsing
 *
 *   This module exercises the IOCTL request header and per-FSCTL
 *   input buffer parsing. The IOCTL command carries many different
 *   sub-protocols (COPYCHUNK, VALIDATE_NEGOTIATE, SET_REPARSE_POINT,
 *   PIPE operations, etc.) each with its own input format.
 *
 *   Targets:
 *     - IOCTL request: StructureSize, Flags, CtlCode, InputOffset,
 *       InputCount, MaxOutputResponse
 *     - FSCTL dispatch: validate CtlCode range
 *     - FSCTL_VALIDATE_NEGOTIATE_INFO: dialects array
 *     - FSCTL_SET_COMPRESSION: USHORT compression format
 *     - FSCTL_PIPE_WAIT: NameLength + Name
 *
 *   Corpus seed hints:
 *     - IOCTL req: StructureSize=57, Flags=1 (FSCTL),
 *       CtlCode=0x00140190 (VALIDATE_NEGOTIATE)
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB2 IOCTL request structure */
struct smb2_ioctl_req_fuzz {
	__le16 StructureSize;	/* Must be 57 */
	__le16 Reserved;
	__le32 CtlCode;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
	__le32 InputOffset;
	__le32 InputCount;
	__le32 MaxInputResponse;
	__le32 OutputOffset;
	__le32 OutputCount;
	__le32 MaxOutputResponse;
	__le32 Flags;
	__le32 Reserved2;
} __packed;

#define IOCTL_STRUCTURE_SIZE	57
#define IOCTL_HDR_SIZE		sizeof(struct smb2_ioctl_req_fuzz)
#define SMB2_0_IOCTL_IS_FSCTL	0x00000001

/* Well-known FSCTL codes */
#define FSCTL_DFS_GET_REFERRALS		0x00060041
#define FSCTL_PIPE_TRANSCEIVE		0x0009001C
#define FSCTL_PIPE_WAIT			0x00110018
#define FSCTL_PIPE_PEEK			0x0011400C
#define FSCTL_SET_REPARSE_POINT		0x000900A4
#define FSCTL_QUERY_ALLOCATED_RANGES	0x000940CF
#define FSCTL_SET_ZERO_DATA		0x000980C8
#define FSCTL_SET_SPARSE		0x000900C4
#define FSCTL_SET_COMPRESSION		0x0009C040
#define FSCTL_VALIDATE_NEGOTIATE_INFO	0x00140204
#define FSCTL_COPYCHUNK			0x001440F2
#define FSCTL_COPYCHUNK_WRITE		0x001480F2
#define FSCTL_SVHDX_SYNC_TUNNEL		0x00090304
#define FSCTL_DUPLICATE_EXTENTS		0x00098344

/* FSCTL_VALIDATE_NEGOTIATE_INFO input */
struct validate_negotiate_info_req_fuzz {
	__le32 Capabilities;
	__u8   Guid[16];
	__le16 SecurityMode;
	__le16 DialectCount;
	/* Followed by DialectCount * __le16 */
} __packed;

/* FSCTL_PIPE_WAIT input */
struct fsctl_pipe_wait_req_fuzz {
	__le64 Timeout;
	__le32 NameLength;
	__u8   TimeoutSpecified;
	__u8   Padding;
	/* Followed by Name[NameLength] */
} __packed;

/*
 * fuzz_ioctl_request - Fuzz SMB2 IOCTL request header
 * @data:	raw request body
 * @len:	length of body
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ioctl_request(const u8 *data, size_t len)
{
	const struct smb2_ioctl_req_fuzz *req;
	u16 structure_size;
	u32 ctl_code;
	u32 input_offset, input_count;
	u32 max_output;
	u32 flags;

	if (len < IOCTL_HDR_SIZE) {
		pr_debug("fuzz_ioctl: input too small (%zu)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_ioctl_req_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	ctl_code = le32_to_cpu(req->CtlCode);
	input_offset = le32_to_cpu(req->InputOffset);
	input_count = le32_to_cpu(req->InputCount);
	max_output = le32_to_cpu(req->MaxOutputResponse);
	flags = le32_to_cpu(req->Flags);

	/* Validate structure size */
	if (structure_size != IOCTL_STRUCTURE_SIZE) {
		pr_debug("fuzz_ioctl: invalid structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate flags - must be FSCTL */
	if (!(flags & SMB2_0_IOCTL_IS_FSCTL)) {
		pr_debug("fuzz_ioctl: FSCTL flag not set (flags=0x%08x)\n",
			 flags);
		return -EINVAL;
	}

	/* Validate input buffer bounds */
	if (input_count > 0) {
		if ((u64)input_offset + input_count > len) {
			pr_debug("fuzz_ioctl: input buffer overflow off=%u cnt=%u buf=%zu\n",
				 input_offset, input_count, len);
			return -EINVAL;
		}
	}

	/* MaxOutputResponse sanity */
	if (max_output > 16 * 1024 * 1024) {
		pr_debug("fuzz_ioctl: MaxOutputResponse %u too large\n",
			 max_output);
		return -EINVAL;
	}

	pr_debug("fuzz_ioctl: ctl=0x%08x in_off=%u in_cnt=%u max_out=%u\n",
		 ctl_code, input_offset, input_count, max_output);

	/* Dispatch to per-FSCTL validation */
	if (input_count > 0 && input_offset < len) {
		const u8 *input_buf = data + input_offset;
		size_t input_len = min_t(size_t, input_count, len - input_offset);

		switch (ctl_code) {
		case FSCTL_VALIDATE_NEGOTIATE_INFO:
		{
			const struct validate_negotiate_info_req_fuzz *vni;
			u16 dialect_count;

			if (input_len < sizeof(*vni)) {
				pr_debug("fuzz_ioctl: VNI input too small\n");
				break;
			}
			vni = (const struct validate_negotiate_info_req_fuzz *)input_buf;
			dialect_count = le16_to_cpu(vni->DialectCount);

			if (sizeof(*vni) + (size_t)dialect_count * 2 > input_len) {
				pr_debug("fuzz_ioctl: VNI %u dialects exceed buffer\n",
					 dialect_count);
				break;
			}
			pr_debug("fuzz_ioctl: VNI sec_mode=0x%04x dialects=%u\n",
				 le16_to_cpu(vni->SecurityMode), dialect_count);
			break;
		}
		case FSCTL_SET_COMPRESSION:
		{
			if (input_len < 2) {
				pr_debug("fuzz_ioctl: SET_COMPRESSION too small\n");
				break;
			}
			pr_debug("fuzz_ioctl: SET_COMPRESSION format=%u\n",
				 le16_to_cpu(*(__le16 *)input_buf));
			break;
		}
		case FSCTL_PIPE_WAIT:
		{
			const struct fsctl_pipe_wait_req_fuzz *pw;
			u32 name_len;

			if (input_len < sizeof(*pw)) {
				pr_debug("fuzz_ioctl: PIPE_WAIT too small\n");
				break;
			}
			pw = (const struct fsctl_pipe_wait_req_fuzz *)input_buf;
			name_len = le32_to_cpu(pw->NameLength);
			if (sizeof(*pw) + name_len > input_len) {
				pr_debug("fuzz_ioctl: PIPE_WAIT name overflow\n");
				break;
			}
			pr_debug("fuzz_ioctl: PIPE_WAIT timeout=%llu name_len=%u\n",
				 le64_to_cpu(pw->Timeout), name_len);
			break;
		}
		default:
			pr_debug("fuzz_ioctl: unhandled FSCTL 0x%08x\n", ctl_code);
			break;
		}
	}

	return 0;
}

static int __init ioctl_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_ioctl_req_fuzz *req;
	int ret;

	pr_info("ioctl_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid VALIDATE_NEGOTIATE_INFO */
	req = (struct smb2_ioctl_req_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(IOCTL_STRUCTURE_SIZE);
	req->CtlCode = cpu_to_le32(FSCTL_VALIDATE_NEGOTIATE_INFO);
	req->InputOffset = cpu_to_le32(IOCTL_HDR_SIZE);
	req->InputCount = cpu_to_le32(26); /* header + 1 dialect */
	req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
	req->MaxOutputResponse = cpu_to_le32(24);
	{
		struct validate_negotiate_info_req_fuzz *vni =
			(struct validate_negotiate_info_req_fuzz *)(test_buf + IOCTL_HDR_SIZE);

		vni->SecurityMode = cpu_to_le16(1);
		vni->DialectCount = cpu_to_le16(1);
		*(__le16 *)(test_buf + IOCTL_HDR_SIZE + sizeof(*vni)) = cpu_to_le16(0x0311);
	}
	ret = fuzz_ioctl_request(test_buf, IOCTL_HDR_SIZE + 26);
	pr_info("ioctl_fuzz: VNI returned %d\n", ret);

	/* Self-test 2: no FSCTL flag */
	req->Flags = 0;
	ret = fuzz_ioctl_request(test_buf, IOCTL_HDR_SIZE + 26);
	pr_info("ioctl_fuzz: no FSCTL flag returned %d\n", ret);

	/* Self-test 3: input buffer overflow */
	req->Flags = cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL);
	req->InputCount = cpu_to_le32(0xFFFF);
	ret = fuzz_ioctl_request(test_buf, IOCTL_HDR_SIZE + 26);
	pr_info("ioctl_fuzz: input overflow returned %d\n", ret);

	/* Self-test 4: truncated */
	ret = fuzz_ioctl_request(test_buf, 8);
	pr_info("ioctl_fuzz: truncated returned %d\n", ret);

	/* Self-test 5: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_ioctl_request(test_buf, 512);
	pr_info("ioctl_fuzz: garbage returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit ioctl_fuzz_exit(void)
{
	pr_info("ioctl_fuzz: module unloaded\n");
}

module_init(ioctl_fuzz_init);
module_exit(ioctl_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 IOCTL request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
