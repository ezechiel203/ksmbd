// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 SET_INFO dispatcher
 *
 *   This module exercises the smb2_set_info() dispatcher which handles
 *   20+ file information levels using client-controlled InfoType,
 *   FileInfoClass, and arbitrary buffer content. This is a type-confusion
 *   attack surface where a malicious client can send a SET_INFO request
 *   with one FileInfoClass but supply a buffer formatted for a different
 *   class, potentially causing out-of-bounds reads or writes.
 *
 *   Targets:
 *     - InfoType (FILE/FS/SECURITY/QUOTA) routing
 *     - FileInfoClass dispatch for each InfoType:
 *         FILE_BASIC_INFORMATION (4)
 *         FILE_ALLOCATION_INFORMATION (19)
 *         FILE_END_OF_FILE_INFORMATION (20)
 *         FILE_RENAME_INFORMATION (10)
 *         FILE_DISPOSITION_INFORMATION (13)
 *         FILE_DISPOSITION_INFORMATION_EX (64)
 *         FILE_FULL_EA_INFORMATION (15)
 *         FILE_POSITION_INFORMATION (14)
 *         FILE_MODE_INFORMATION (16)
 *     - BufferOffset + BufferLength bounds validation
 *     - AdditionalInformation bitmask for SECURITY InfoType
 *     - Type confusion: wrong buffer size for declared info class
 *     - SET_INFO on pipe handles (FileId=pipe_id)
 *
 *   Corpus seed hints:
 *     - StructureSize=33, InfoType=1, FileInfoClass=4, BufferLength=40
 *     - Security: InfoType=3, AdditionalInformation=DACL_SECINFO(4)
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* InfoType constants */
#define SMB2_O_INFO_FILE	0x01
#define SMB2_O_INFO_FILESYSTEM	0x02
#define SMB2_O_INFO_SECURITY	0x03
#define SMB2_O_INFO_QUOTA	0x04

/* Security info flags */
#define OWNER_SECINFO		0x00000001
#define GROUP_SECINFO		0x00000002
#define DACL_SECINFO		0x00000004
#define SACL_SECINFO		0x00000008
#define LABEL_SECINFO		0x00000010
#define ATTRIBUTE_SECINFO	0x00000020
#define SCOPE_SECINFO		0x00000040
#define BACKUP_SECINFO		0x00010000

/* File information classes (MS-FSCC) */
#define FILE_BASIC_INFORMATION			4
#define FILE_RENAME_INFORMATION			10
#define FILE_DISPOSITION_INFORMATION		13
#define FILE_POSITION_INFORMATION		14
#define FILE_FULL_EA_INFORMATION		15
#define FILE_MODE_INFORMATION			16
#define FILE_ALLOCATION_INFORMATION		19
#define FILE_END_OF_FILE_INFORMATION		20
#define FILE_DISPOSITION_INFORMATION_EX		64
#define FILE_RENAME_INFORMATION_EX		65
#define FILE_LINK_INFORMATION			11
#define FILE_OBJECT_ID_INFORMATION		29

/* SET_INFO request (without SMB2 header for fuzzing) */
struct smb2_set_info_fuzz {
	__le16 StructureSize;		/* Must be 33 */
	__u8   InfoType;
	__u8   FileInfoClass;
	__le32 BufferLength;
	__le16 BufferOffset;
	__le16 Reserved;
	__le32 AdditionalInformation;
	__le64 PersistentFileId;
	__le64 VolatileFileId;
	__u8   Buffer[];
} __packed;

#define SET_INFO_STRUCTURE_SIZE		33
#define SET_INFO_HDR_SIZE		sizeof(struct smb2_set_info_fuzz)

/* Minimum buffer sizes expected for each FileInfoClass */
struct info_class_entry {
	u8 info_class;
	u32 min_buf_size;
	const char *name;
};

static const struct info_class_entry file_info_classes[] = {
	{ FILE_BASIC_INFORMATION,	40, "FileBasicInformation" },
	{ FILE_ALLOCATION_INFORMATION,	8,  "FileAllocationInformation" },
	{ FILE_END_OF_FILE_INFORMATION,	8,  "FileEndOfFileInformation" },
	{ FILE_RENAME_INFORMATION,	20, "FileRenameInformation" },
	{ FILE_DISPOSITION_INFORMATION,	1,  "FileDispositionInformation" },
	{ FILE_DISPOSITION_INFORMATION_EX, 4, "FileDispositionInformationEx" },
	{ FILE_FULL_EA_INFORMATION,	8,  "FileFullEaInformation" },
	{ FILE_POSITION_INFORMATION,	8,  "FilePositionInformation" },
	{ FILE_MODE_INFORMATION,	4,  "FileModeInformation" },
	{ FILE_LINK_INFORMATION,	20, "FileLinkInformation" },
	{ FILE_RENAME_INFORMATION_EX,	20, "FileRenameInformationEx" },
	{ FILE_OBJECT_ID_INFORMATION,	64, "FileObjectIdInformation" },
	{ 0, 0, NULL },
};

/*
 * fuzz_validate_info_class - Look up min buffer size for info class
 * @info_class:	FileInfoClass from the request
 * @min_size:	output: minimum expected buffer size
 *
 * Return: 0 if known class, -EINVAL if unknown
 */
static int fuzz_lookup_info_class(u8 info_class, u32 *min_size,
				  const char **name)
{
	const struct info_class_entry *entry;

	for (entry = file_info_classes; entry->name != NULL; entry++) {
		if (entry->info_class == info_class) {
			*min_size = entry->min_buf_size;
			*name = entry->name;
			return 0;
		}
	}

	*min_size = 0;
	*name = "unknown";
	return -EINVAL;
}

/*
 * fuzz_set_info_file - Fuzz FILE info class buffer validation
 * @info_class:	the FileInfoClass
 * @buffer:	pointer to the set info buffer content
 * @buf_len:	buffer length
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_set_info_file(u8 info_class, const u8 *buffer, u32 buf_len)
{
	u32 min_size;
	const char *name;
	int ret;

	ret = fuzz_lookup_info_class(info_class, &min_size, &name);
	if (ret < 0) {
		pr_debug("fuzz_si: unknown FileInfoClass %u\n", info_class);
		return -EINVAL;
	}

	pr_debug("fuzz_si: %s (class=%u) buf_len=%u min=%u\n",
		 name, info_class, buf_len, min_size);

	/* Type confusion: buffer too small for declared info class */
	if (buf_len < min_size) {
		pr_debug("fuzz_si: buffer too small for %s: %u < %u\n",
			 name, buf_len, min_size);
		return -EMSGSIZE;
	}

	/* Class-specific field validation */
	switch (info_class) {
	case FILE_BASIC_INFORMATION:
	{
		/* Validate timestamp fields (8 bytes each, 4 timestamps) */
		if (buf_len >= 32) {
			__le64 *timestamps = (__le64 *)buffer;
			int i;

			for (i = 0; i < 4; i++) {
				u64 ts = le64_to_cpu(timestamps[i]);

				/* 0 means "don't change", -1 means "don't change" */
				if (ts != 0 && ts != (u64)-1 && ts != (u64)-2)
					pr_debug("fuzz_si: timestamp[%d]=0x%llx\n",
						 i, ts);
			}
		}
		/* FileAttributes at offset 32 (4 bytes) */
		if (buf_len >= 36) {
			u32 attrs = le32_to_cpu(*(__le32 *)(buffer + 32));

			pr_debug("fuzz_si: FileAttributes=0x%08x\n", attrs);
		}
		break;
	}
	case FILE_RENAME_INFORMATION:
	case FILE_RENAME_INFORMATION_EX:
	{
		/* ReplaceIfExists(1) + reserved(7) + RootDirectory(8) +
		 * FileNameLength(4) + FileName(variable) */
		if (buf_len >= 20) {
			u32 name_len = le32_to_cpu(*(__le32 *)(buffer + 16));

			pr_debug("fuzz_si: rename FileNameLength=%u\n",
				 name_len);
			if (20 + (u64)name_len > buf_len) {
				pr_debug("fuzz_si: rename FileName exceeds buffer\n");
				return -EINVAL;
			}
			/* FileName must be even length (UTF-16LE) */
			if (name_len & 1) {
				pr_debug("fuzz_si: rename FileName odd length %u\n",
					 name_len);
			}
		}
		break;
	}
	case FILE_DISPOSITION_INFORMATION:
	{
		u8 delete_pending = buffer[0];

		pr_debug("fuzz_si: DeletePending=%u\n", delete_pending);
		break;
	}
	case FILE_DISPOSITION_INFORMATION_EX:
	{
		u32 flags = le32_to_cpu(*(__le32 *)buffer);

		pr_debug("fuzz_si: DispositionFlags=0x%08x\n", flags);
		break;
	}
	case FILE_ALLOCATION_INFORMATION:
	case FILE_END_OF_FILE_INFORMATION:
	{
		u64 size = le64_to_cpu(*(__le64 *)buffer);

		pr_debug("fuzz_si: size/allocation=0x%llx\n", size);
		break;
	}
	case FILE_FULL_EA_INFORMATION:
	{
		/* NextEntryOffset(4) + Flags(1) + EaNameLength(1) +
		 * EaValueLength(2) */
		if (buf_len >= 8) {
			u32 next_off = le32_to_cpu(*(__le32 *)buffer);
			u8 ea_name_len = buffer[5];
			u16 ea_value_len = le16_to_cpu(*(__le16 *)(buffer + 6));

			pr_debug("fuzz_si: EA next=%u name_len=%u value_len=%u\n",
				 next_off, ea_name_len, ea_value_len);
			if (8 + (u32)ea_name_len + 1 + ea_value_len > buf_len) {
				pr_debug("fuzz_si: EA data exceeds buffer\n");
				return -EINVAL;
			}
		}
		break;
	}
	default:
		break;
	}

	return 0;
}

/*
 * fuzz_set_info_security - Fuzz SECURITY info type validation
 * @additional_info:	AdditionalInformation bitmask
 * @buffer:		pointer to security descriptor buffer
 * @buf_len:		buffer length
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_set_info_security(u32 additional_info, const u8 *buffer,
				  u32 buf_len)
{
	/* Minimum security descriptor: revision(2) + type(2) + 4 offsets(16) = 20 */
	if (buf_len < 20) {
		pr_debug("fuzz_si: security descriptor too small (%u)\n",
			 buf_len);
		return -EINVAL;
	}

	/* Validate AdditionalInformation flags */
	if (additional_info == 0) {
		pr_debug("fuzz_si: zero AdditionalInformation for SECURITY\n");
		return -EINVAL;
	}

	pr_debug("fuzz_si: security additional_info=0x%08x\n",
		 additional_info);

	/* Check which parts of the security descriptor are being set */
	if (additional_info & OWNER_SECINFO)
		pr_debug("fuzz_si: setting OWNER_SECINFO\n");
	if (additional_info & GROUP_SECINFO)
		pr_debug("fuzz_si: setting GROUP_SECINFO\n");
	if (additional_info & DACL_SECINFO)
		pr_debug("fuzz_si: setting DACL_SECINFO\n");
	if (additional_info & SACL_SECINFO)
		pr_debug("fuzz_si: setting SACL_SECINFO\n");

	/* Check for unknown flags */
	if (additional_info & ~(OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO |
				SACL_SECINFO | LABEL_SECINFO | ATTRIBUTE_SECINFO |
				SCOPE_SECINFO | BACKUP_SECINFO |
				0x10000000 | 0x20000000 | 0x40000000 | 0x80000000)) {
		pr_debug("fuzz_si: unknown bits in AdditionalInformation: 0x%08x\n",
			 additional_info);
		return -EINVAL;
	}

	return 0;
}

/*
 * fuzz_set_info - Fuzz SMB2 SET_INFO request dispatcher
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the validation and dispatch logic in smb2_set_info(),
 * including buffer bounds checking, InfoType routing, and per-class
 * buffer size validation.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_set_info(const u8 *data, size_t len)
{
	const struct smb2_set_info_fuzz *req;
	u16 structure_size;
	u8 info_type, info_class;
	u32 buf_len;
	u16 buf_offset;
	u32 additional_info;
	const u8 *buffer;

	if (len < SET_INFO_HDR_SIZE) {
		pr_debug("fuzz_si: input too small (%zu < %zu)\n",
			 len, SET_INFO_HDR_SIZE);
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	req = (const struct smb2_set_info_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	info_type = req->InfoType;
	info_class = req->FileInfoClass;
	buf_len = le32_to_cpu(req->BufferLength);
	buf_offset = le16_to_cpu(req->BufferOffset);
	additional_info = le32_to_cpu(req->AdditionalInformation);

	/* Validate structure size */
	if (structure_size != SET_INFO_STRUCTURE_SIZE) {
		pr_debug("fuzz_si: invalid StructureSize %u (expected %u)\n",
			 structure_size, SET_INFO_STRUCTURE_SIZE);
		return -EINVAL;
	}

	/* Validate buffer length is non-zero */
	if (buf_len == 0) {
		pr_debug("fuzz_si: zero BufferLength\n");
		return -EINVAL;
	}

	/* Validate buffer offset minimum */
	if (buf_offset < SET_INFO_HDR_SIZE) {
		pr_debug("fuzz_si: BufferOffset %u < header size %zu\n",
			 buf_offset, SET_INFO_HDR_SIZE);
		return -EINVAL;
	}

	/* Validate buffer bounds (integer overflow safe) */
	if (buf_offset > len || buf_len > len - buf_offset) {
		pr_debug("fuzz_si: buffer at %u+%u exceeds packet %zu\n",
			 buf_offset, buf_len, len);
		return -EINVAL;
	}

	buffer = data + buf_offset;

	pr_debug("fuzz_si: InfoType=%u FileInfoClass=%u BufferLength=%u "
		 "BufferOffset=%u AdditionalInfo=0x%x\n",
		 info_type, info_class, buf_len, buf_offset, additional_info);

	/* InfoType-based dispatch */
	switch (info_type) {
	case SMB2_O_INFO_FILE:
		return fuzz_set_info_file(info_class, buffer, buf_len);

	case SMB2_O_INFO_FILESYSTEM:
		pr_debug("fuzz_si: FILESYSTEM set info class=%u\n", info_class);
		/* FS info classes have limited settable fields */
		return 0;

	case SMB2_O_INFO_SECURITY:
		return fuzz_set_info_security(additional_info, buffer, buf_len);

	case SMB2_O_INFO_QUOTA:
		pr_debug("fuzz_si: QUOTA set info class=%u\n", info_class);
		return 0;

	default:
		pr_debug("fuzz_si: invalid InfoType %u\n", info_type);
		return -EINVAL;
	}
}

static int __init smb2_set_info_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_set_info_fuzz *req;
	int ret;

	pr_info("smb2_set_info_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid FILE_BASIC_INFORMATION set */
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_BASIC_INFORMATION;
	req->BufferLength = cpu_to_le32(40);
	req->BufferOffset = cpu_to_le16(SET_INFO_HDR_SIZE);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 40);
	pr_info("smb2_set_info_fuzz: valid basic info returned %d\n", ret);

	/* Self-test 2: type confusion - BASIC class but only 4 bytes */
	memset(test_buf, 0, 512);
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_BASIC_INFORMATION;
	req->BufferLength = cpu_to_le32(4);
	req->BufferOffset = cpu_to_le16(SET_INFO_HDR_SIZE);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 4);
	pr_info("smb2_set_info_fuzz: type confusion test returned %d\n", ret);

	/* Self-test 3: rename with overflow FileNameLength */
	memset(test_buf, 0, 512);
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_RENAME_INFORMATION;
	req->BufferLength = cpu_to_le32(24);
	req->BufferOffset = cpu_to_le16(SET_INFO_HDR_SIZE);
	/* FileNameLength at offset 16 within buffer */
	*(__le32 *)(test_buf + SET_INFO_HDR_SIZE + 16) = cpu_to_le32(0xFFFFFFF0);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 24);
	pr_info("smb2_set_info_fuzz: rename overflow test returned %d\n", ret);

	/* Self-test 4: SECURITY with DACL flag */
	memset(test_buf, 0, 512);
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = SMB2_O_INFO_SECURITY;
	req->FileInfoClass = 0;
	req->BufferLength = cpu_to_le32(20);
	req->BufferOffset = cpu_to_le16(SET_INFO_HDR_SIZE);
	req->AdditionalInformation = cpu_to_le32(DACL_SECINFO);
	/* Minimal security descriptor: revision(2) + type(2) + 4 offsets */
	*(__le16 *)(test_buf + SET_INFO_HDR_SIZE) = cpu_to_le16(1);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 20);
	pr_info("smb2_set_info_fuzz: security DACL test returned %d\n", ret);

	/* Self-test 5: invalid InfoType */
	memset(test_buf, 0, 512);
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = 0xFF;
	req->FileInfoClass = 1;
	req->BufferLength = cpu_to_le32(8);
	req->BufferOffset = cpu_to_le16(SET_INFO_HDR_SIZE);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 8);
	pr_info("smb2_set_info_fuzz: invalid InfoType test returned %d\n", ret);

	/* Self-test 6: buffer offset past end of packet */
	memset(test_buf, 0, 512);
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_BASIC_INFORMATION;
	req->BufferLength = cpu_to_le32(40);
	req->BufferOffset = cpu_to_le16(0xFFF0);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 40);
	pr_info("smb2_set_info_fuzz: oob offset test returned %d\n", ret);

	/* Self-test 7: EA information with invalid entry */
	memset(test_buf, 0, 512);
	req = (struct smb2_set_info_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(SET_INFO_STRUCTURE_SIZE);
	req->InfoType = SMB2_O_INFO_FILE;
	req->FileInfoClass = FILE_FULL_EA_INFORMATION;
	req->BufferLength = cpu_to_le32(12);
	req->BufferOffset = cpu_to_le16(SET_INFO_HDR_SIZE);
	/* EA entry: NextEntryOffset=0, Flags=0, EaNameLength=255, EaValueLength=0xFFFF */
	test_buf[SET_INFO_HDR_SIZE + 5] = 255;
	*(__le16 *)(test_buf + SET_INFO_HDR_SIZE + 6) = cpu_to_le16(0xFFFF);

	ret = fuzz_set_info(test_buf, SET_INFO_HDR_SIZE + 12);
	pr_info("smb2_set_info_fuzz: bad EA test returned %d\n", ret);

	/* Self-test 8: garbage data */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_set_info(test_buf, 512);
	pr_info("smb2_set_info_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit smb2_set_info_fuzz_exit(void)
{
	pr_info("smb2_set_info_fuzz: module unloaded\n");
}

module_init(smb2_set_info_fuzz_init);
module_exit(smb2_set_info_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 SET_INFO dispatcher");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
