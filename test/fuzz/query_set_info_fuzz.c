// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 query/set info request parsing
 *
 *   This module exercises the query and set info request validation
 *   logic used in ksmbd. These requests carry info type, info class,
 *   and variable-length input/output buffers. Malformed requests can
 *   lead to out-of-bounds reads, invalid info class dispatching, or
 *   buffer length mismatches.
 *
 *   Targets:
 *     - InfoType (FILE/FS/SECURITY/QUOTA) range validation
 *     - InfoClass bounds checking per InfoType
 *     - InputBufferLength vs actual buffer validation
 *     - OutputBufferLength sanity checks
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_query_info() and fuzz_set_info()
 *     entry points accept raw byte buffers.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * SMB2 info type constants
 */
#define SMB2_O_INFO_FILE	0x01
#define SMB2_O_INFO_FILESYSTEM	0x02
#define SMB2_O_INFO_SECURITY	0x03
#define SMB2_O_INFO_QUOTA	0x04

/*
 * Maximum valid FileInformationClass values (MS-FSCC)
 */
#define FILE_INFO_CLASS_MAX		81  /* FileIdAllExtdBothDirectoryInformation */
#define FS_INFO_CLASS_MAX		11  /* FileFsSectorSizeInformation */

/*
 * Inline query info request structure
 */
struct smb2_query_info_req_hdr {
	__le16 StructureSize;	/* Must be 41 */
	__u8   InfoType;
	__u8   FileInfoClass;
	__le32 OutputBufferLength;
	__le16 InputBufferOffset;
	__le16 Reserved;
	__le32 InputBufferLength;
	__le32 AdditionalInformation;
	__le32 Flags;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
} __packed;

/*
 * Inline set info request structure
 */
struct smb2_set_info_req_hdr {
	__le16 StructureSize;	/* Must be 33 */
	__u8   InfoType;
	__u8   FileInfoClass;
	__le32 BufferLength;
	__le16 BufferOffset;
	__le16 Reserved;
	__le32 AdditionalInformation;
	__le64 FileId_Persistent;
	__le64 FileId_Volatile;
} __packed;

#define QUERY_INFO_STRUCTURE_SIZE	41
#define SET_INFO_STRUCTURE_SIZE		33
#define MAX_OUTPUT_BUFFER_LENGTH	(64 * 1024)

/*
 * fuzz_validate_info_class - Validate InfoType and InfoClass combination
 * @info_type:	the info type
 * @info_class:	the info class
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_info_class(u8 info_type, u8 info_class)
{
	switch (info_type) {
	case SMB2_O_INFO_FILE:
		if (info_class == 0 || info_class > FILE_INFO_CLASS_MAX) {
			pr_debug("fuzz_qsi: invalid FILE info class %u\n",
				 info_class);
			return -EINVAL;
		}
		break;
	case SMB2_O_INFO_FILESYSTEM:
		if (info_class == 0 || info_class > FS_INFO_CLASS_MAX) {
			pr_debug("fuzz_qsi: invalid FS info class %u\n",
				 info_class);
			return -EINVAL;
		}
		break;
	case SMB2_O_INFO_SECURITY:
		/* Security info uses AdditionalInformation, class is 0 */
		pr_debug("fuzz_qsi: SECURITY info class=%u\n", info_class);
		break;
	case SMB2_O_INFO_QUOTA:
		/* Quota info has its own validation */
		pr_debug("fuzz_qsi: QUOTA info class=%u\n", info_class);
		break;
	default:
		pr_debug("fuzz_qsi: invalid InfoType %u\n", info_type);
		return -EINVAL;
	}

	return 0;
}

/*
 * fuzz_query_info - Fuzz SMB2 QUERY_INFO request parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_query_info(const u8 *data, size_t len)
{
	const struct smb2_query_info_req_hdr *req;
	u16 structure_size;
	u8 info_type;
	u8 info_class;
	u32 output_buf_len;
	u16 input_buf_offset;
	u32 input_buf_len;
	int ret;

	if (len < sizeof(struct smb2_query_info_req_hdr)) {
		pr_debug("fuzz_qsi: query input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_query_info_req_hdr *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	info_type = req->InfoType;
	info_class = req->FileInfoClass;
	output_buf_len = le32_to_cpu(req->OutputBufferLength);
	input_buf_offset = le16_to_cpu(req->InputBufferOffset);
	input_buf_len = le32_to_cpu(req->InputBufferLength);

	/* Validate structure size */
	if (structure_size != QUERY_INFO_STRUCTURE_SIZE) {
		pr_debug("fuzz_qsi: invalid query structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate info type and class */
	ret = fuzz_validate_info_class(info_type, info_class);
	if (ret < 0)
		return ret;

	/* Validate output buffer length sanity */
	if (output_buf_len > MAX_OUTPUT_BUFFER_LENGTH) {
		pr_debug("fuzz_qsi: output buffer length %u exceeds max\n",
			 output_buf_len);
		return -EINVAL;
	}

	/* Validate input buffer if present */
	if (input_buf_len > 0) {
		if (input_buf_offset == 0) {
			pr_debug("fuzz_qsi: input_buf_len %u but offset is 0\n",
				 input_buf_len);
			return -EINVAL;
		}

		/* Check that input buffer fits within the packet */
		if ((u32)input_buf_offset + input_buf_len > len) {
			pr_debug("fuzz_qsi: input buffer at %u+%u exceeds packet %zu\n",
				 input_buf_offset, input_buf_len, len);
			return -EINVAL;
		}
	}

	pr_debug("fuzz_qsi: query type=%u class=%u outlen=%u inlen=%u\n",
		 info_type, info_class, output_buf_len, input_buf_len);

	return 0;
}

/*
 * fuzz_set_info - Fuzz SMB2 SET_INFO request parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_set_info(const u8 *data, size_t len)
{
	const struct smb2_set_info_req_hdr *req;
	u16 structure_size;
	u8 info_type;
	u8 info_class;
	u32 buf_len;
	u16 buf_offset;
	int ret;

	if (len < sizeof(struct smb2_set_info_req_hdr)) {
		pr_debug("fuzz_qsi: set input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	req = (const struct smb2_set_info_req_hdr *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	info_type = req->InfoType;
	info_class = req->FileInfoClass;
	buf_len = le32_to_cpu(req->BufferLength);
	buf_offset = le16_to_cpu(req->BufferOffset);

	/* Validate structure size */
	if (structure_size != SET_INFO_STRUCTURE_SIZE) {
		pr_debug("fuzz_qsi: invalid set structure size %u\n",
			 structure_size);
		return -EINVAL;
	}

	/* Validate info type and class */
	ret = fuzz_validate_info_class(info_type, info_class);
	if (ret < 0)
		return ret;

	/* Validate buffer length */
	if (buf_len == 0) {
		pr_debug("fuzz_qsi: set info with zero buffer length\n");
		return -EINVAL;
	}

	/* Validate buffer offset and length against packet */
	if (buf_offset == 0) {
		pr_debug("fuzz_qsi: set info buffer offset is 0\n");
		return -EINVAL;
	}

	if ((u32)buf_offset + buf_len > len) {
		pr_debug("fuzz_qsi: set buffer at %u+%u exceeds packet %zu\n",
			 buf_offset, buf_len, len);
		return -EINVAL;
	}

	pr_debug("fuzz_qsi: set type=%u class=%u buflen=%u bufoff=%u\n",
		 info_type, info_class, buf_len, buf_offset);

	return 0;
}

static int __init query_set_info_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_query_info_req_hdr *qreq;
	struct smb2_set_info_req_hdr *sreq;
	int ret;

	pr_info("query_set_info_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid FILE_BASIC_INFO query */
	qreq = (struct smb2_query_info_req_hdr *)test_buf;
	qreq->StructureSize = cpu_to_le16(QUERY_INFO_STRUCTURE_SIZE);
	qreq->InfoType = SMB2_O_INFO_FILE;
	qreq->FileInfoClass = 4; /* FileBasicInformation */
	qreq->OutputBufferLength = cpu_to_le32(40);
	qreq->InputBufferOffset = 0;
	qreq->InputBufferLength = 0;

	ret = fuzz_query_info(test_buf, sizeof(struct smb2_query_info_req_hdr));
	pr_info("query_set_info_fuzz: valid query test returned %d\n", ret);

	/* Self-test 2: truncated buffer */
	ret = fuzz_query_info(test_buf, 4);
	pr_info("query_set_info_fuzz: truncated query test returned %d\n", ret);

	/* Self-test 3: invalid info class */
	memset(test_buf, 0, 256);
	qreq = (struct smb2_query_info_req_hdr *)test_buf;
	qreq->StructureSize = cpu_to_le16(QUERY_INFO_STRUCTURE_SIZE);
	qreq->InfoType = SMB2_O_INFO_FILE;
	qreq->FileInfoClass = 200; /* invalid */
	qreq->OutputBufferLength = cpu_to_le32(40);

	ret = fuzz_query_info(test_buf, sizeof(struct smb2_query_info_req_hdr));
	pr_info("query_set_info_fuzz: invalid class test returned %d\n", ret);

	/* Self-test 4: invalid InfoType */
	memset(test_buf, 0, 256);
	qreq = (struct smb2_query_info_req_hdr *)test_buf;
	qreq->StructureSize = cpu_to_le16(QUERY_INFO_STRUCTURE_SIZE);
	qreq->InfoType = 0xFF;
	qreq->FileInfoClass = 1;
	qreq->OutputBufferLength = cpu_to_le32(40);

	ret = fuzz_query_info(test_buf, sizeof(struct smb2_query_info_req_hdr));
	pr_info("query_set_info_fuzz: invalid type test returned %d\n", ret);

	/* Self-test 5: valid set info */
	memset(test_buf, 0, 256);
	sreq = (struct smb2_set_info_req_hdr *)test_buf;
	sreq->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	sreq->InfoType = SMB2_O_INFO_FILE;
	sreq->FileInfoClass = 4; /* FileBasicInformation */
	sreq->BufferLength = cpu_to_le32(40);
	sreq->BufferOffset = cpu_to_le16(sizeof(struct smb2_set_info_req_hdr));

	ret = fuzz_set_info(test_buf,
		sizeof(struct smb2_set_info_req_hdr) + 40);
	pr_info("query_set_info_fuzz: valid set test returned %d\n", ret);

	/* Self-test 6: set info with buffer overflow */
	memset(test_buf, 0, 256);
	sreq = (struct smb2_set_info_req_hdr *)test_buf;
	sreq->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	sreq->InfoType = SMB2_O_INFO_FILE;
	sreq->FileInfoClass = 4;
	sreq->BufferLength = cpu_to_le32(0xFFFF);
	sreq->BufferOffset = cpu_to_le16(sizeof(struct smb2_set_info_req_hdr));

	ret = fuzz_set_info(test_buf, sizeof(struct smb2_set_info_req_hdr) + 16);
	pr_info("query_set_info_fuzz: buffer overflow test returned %d\n", ret);

	/* Self-test 7: garbage data */
	memset(test_buf, 0xff, 256);
	ret = fuzz_query_info(test_buf, 256);
	pr_info("query_set_info_fuzz: garbage query test returned %d\n", ret);
	ret = fuzz_set_info(test_buf, 256);
	pr_info("query_set_info_fuzz: garbage set test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit query_set_info_fuzz_exit(void)
{
	pr_info("query_set_info_fuzz: module unloaded\n");
}

module_init(query_set_info_fuzz_init);
module_exit(query_set_info_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 query/set info request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
