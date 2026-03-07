// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 QUERY_DIRECTORY request parsing
 *
 *   This module exercises the smb2_query_dir() request parsing path
 *   including FileInformationClass dispatch, SearchPattern wildcard
 *   expression validation, OutputBufferLength sanity checks, and the
 *   FileNameOffset/FileNameLength bounds validation.
 *
 *   The QUERY_DIRECTORY command is a significant attack surface because:
 *   - The SearchPattern is an arbitrary UTF-16LE string from the client
 *     that gets converted and used in readdir + wildcard matching
 *   - FileInformationClass selects between 14+ different output formats,
 *     each with different structure sizes and field layouts
 *   - The Flags field controls enumeration restart, index specification,
 *     and single-entry mode
 *   - FileNameOffset/FileNameLength can point anywhere in the packet
 *
 *   Targets:
 *     - verify_info_level() dispatch for all FileInformationClass values
 *     - FileNameOffset + FileNameLength bounds checking
 *     - UTF-16LE SearchPattern: odd length, embedded NULs, wildcards
 *     - OutputBufferLength: zero, very small, very large
 *     - Flags: RESTART_SCANS, RETURN_SINGLE_ENTRY, INDEX_SPECIFIED, REOPEN
 *     - FileIndex with INDEX_SPECIFIED flag
 *     - StructureSize validation (must be 33)
 *
 *   Corpus seed hints:
 *     - StructureSize=33, FileInformationClass=37 (BOTH_DIRECTORY),
 *       Flags=0, OutputBufferLength=65536, FileName="*"
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* Query directory request structure (without SMB2 header) */
struct smb2_query_dir_fuzz {
	__le16 StructureSize;		/* Must be 33 */
	__u8   FileInformationClass;
	__u8   Flags;
	__le32 FileIndex;
	__le64 PersistentFileId;
	__le64 VolatileFileId;
	__le16 FileNameOffset;
	__le16 FileNameLength;
	__le32 OutputBufferLength;
	__u8   Buffer[];
} __packed;

#define QUERY_DIR_STRUCTURE_SIZE	33
#define QUERY_DIR_HDR_SIZE		sizeof(struct smb2_query_dir_fuzz)

/* FileInformationClass values valid for QUERY_DIRECTORY (MS-SMB2 2.2.33) */
#define FILE_DIRECTORY_INFORMATION		1
#define FILE_FULL_DIRECTORY_INFORMATION		2
#define FILE_BOTH_DIRECTORY_INFORMATION		3   /* also ID=37 */
#define FILE_NAMES_INFORMATION			12
#define FILEID_FULL_DIRECTORY_INFORMATION	38
#define FILEID_BOTH_DIRECTORY_INFORMATION	37

/* Extended directory info classes from ksmbd */
#define FILEID_GLOBAL_TX_DIRECTORY_INFORMATION		50
#define FILEID_EXTD_DIRECTORY_INFORMATION		60
#define FILEID_EXTD_BOTH_DIRECTORY_INFORMATION		63
#define FILEID_64_EXTD_DIRECTORY_INFORMATION		0x3C
#define FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION	0x3F
#define FILEID_ALL_EXTD_DIRECTORY_INFORMATION		0x44
#define FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION	0x45
#define SMB_FIND_FILE_POSIX_INFO			0x64

/* Flags */
#define SMB2_RESTART_SCANS		0x01
#define SMB2_RETURN_SINGLE_ENTRY	0x02
#define SMB2_INDEX_SPECIFIED		0x04
#define SMB2_REOPEN			0x10

/* Minimum output sizes per info level */
struct dir_info_level {
	u8 info_class;
	u32 min_entry_size;
	const char *name;
};

static const struct dir_info_level dir_info_levels[] = {
	{ FILE_DIRECTORY_INFORMATION,		64, "FileDirectoryInformation" },
	{ FILE_FULL_DIRECTORY_INFORMATION,	68, "FileFullDirectoryInformation" },
	{ FILE_BOTH_DIRECTORY_INFORMATION,	94, "FileBothDirectoryInformation" },
	{ FILE_NAMES_INFORMATION,		12, "FileNamesInformation" },
	{ FILEID_FULL_DIRECTORY_INFORMATION,	80, "FileIdFullDirectoryInformation" },
	{ FILEID_BOTH_DIRECTORY_INFORMATION,	104, "FileIdBothDirectoryInformation" },
	{ FILEID_GLOBAL_TX_DIRECTORY_INFORMATION, 80, "FileIdGlobalTxDirectoryInformation" },
	{ FILEID_EXTD_DIRECTORY_INFORMATION,	80, "FileIdExtdDirectoryInformation" },
	{ FILEID_EXTD_BOTH_DIRECTORY_INFORMATION, 104, "FileIdExtdBothDirectoryInformation" },
	{ SMB_FIND_FILE_POSIX_INFO,		80, "SMBFindFilePosixInfo" },
	{ 0, 0, NULL },
};

/*
 * fuzz_verify_info_level - Validate FileInformationClass for QUERY_DIRECTORY
 * @info_class:	the FileInformationClass value
 * @min_entry:	output: minimum entry size for this level
 *
 * Return: 0 if valid, -EINVAL if unknown
 */
static int fuzz_verify_info_level(u8 info_class, u32 *min_entry,
				  const char **name)
{
	const struct dir_info_level *entry;

	for (entry = dir_info_levels; entry->name != NULL; entry++) {
		if (entry->info_class == info_class) {
			*min_entry = entry->min_entry_size;
			*name = entry->name;
			return 0;
		}
	}

	*min_entry = 0;
	*name = "unknown";
	return -EINVAL;
}

/*
 * fuzz_validate_search_pattern - Validate UTF-16LE search pattern
 * @data:	pointer to the raw FileName bytes
 * @len:	length in bytes of the FileName
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_validate_search_pattern(const u8 *data, u16 len)
{
	u16 i;
	bool has_wildcard = false;
	bool has_null = false;
	int char_count;

	if (len == 0) {
		pr_debug("fuzz_qd: empty search pattern\n");
		return 0;
	}

	/* UTF-16LE: length must be even */
	if (len & 1) {
		pr_debug("fuzz_qd: odd-length search pattern (%u bytes)\n",
			 len);
		return -EINVAL;
	}

	char_count = len / 2;
	pr_debug("fuzz_qd: search pattern %u bytes (%d UTF-16 chars)\n",
		 len, char_count);

	/* Scan for wildcards and embedded NULs */
	for (i = 0; i + 1 < len; i += 2) {
		u16 wchar = data[i] | (data[i + 1] << 8);

		if (wchar == 0) {
			has_null = true;
			pr_debug("fuzz_qd: embedded NUL at char %u\n", i / 2);
		}

		/* Standard wildcards: * ? */
		if (wchar == '*' || wchar == '?')
			has_wildcard = true;

		/* DOS wildcards: " > < (MS-FSCC 2.1.4.4) */
		if (wchar == '"' || wchar == '>' || wchar == '<')
			has_wildcard = true;

		/* Path separator checks */
		if (wchar == '\\' || wchar == '/') {
			pr_debug("fuzz_qd: path separator at char %u\n",
				 i / 2);
		}
	}

	if (has_wildcard)
		pr_debug("fuzz_qd: pattern contains wildcards\n");
	if (has_null)
		pr_debug("fuzz_qd: pattern contains embedded NULs\n");

	return 0;
}

/*
 * fuzz_query_dir - Fuzz SMB2 QUERY_DIRECTORY request parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the request parsing and validation that smb2_query_dir()
 * performs before dispatching to readdir + output formatting.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_query_dir(const u8 *data, size_t len)
{
	const struct smb2_query_dir_fuzz *req;
	u16 structure_size;
	u8 info_class, flags;
	u32 file_index, output_buf_len;
	u16 fn_offset, fn_length;
	u32 min_entry;
	const char *level_name;
	int ret;

	if (len < QUERY_DIR_HDR_SIZE) {
		pr_debug("fuzz_qd: input too small (%zu < %zu)\n",
			 len, QUERY_DIR_HDR_SIZE);
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	req = (const struct smb2_query_dir_fuzz *)data;
	structure_size = le16_to_cpu(req->StructureSize);
	info_class = req->FileInformationClass;
	flags = req->Flags;
	file_index = le32_to_cpu(req->FileIndex);
	fn_offset = le16_to_cpu(req->FileNameOffset);
	fn_length = le16_to_cpu(req->FileNameLength);
	output_buf_len = le32_to_cpu(req->OutputBufferLength);

	/* Validate structure size */
	if (structure_size != QUERY_DIR_STRUCTURE_SIZE) {
		pr_debug("fuzz_qd: invalid StructureSize %u (expected %u)\n",
			 structure_size, QUERY_DIR_STRUCTURE_SIZE);
		return -EINVAL;
	}

	/* Validate FileInformationClass */
	ret = fuzz_verify_info_level(info_class, &min_entry, &level_name);
	if (ret < 0) {
		pr_debug("fuzz_qd: unsupported FileInformationClass %u\n",
			 info_class);
		return -EINVAL;
	}

	pr_debug("fuzz_qd: %s (class=%u) flags=0x%02x index=%u outlen=%u\n",
		 level_name, info_class, flags, file_index, output_buf_len);

	/* Validate Flags */
	if (flags & ~(SMB2_RESTART_SCANS | SMB2_RETURN_SINGLE_ENTRY |
		      SMB2_INDEX_SPECIFIED | SMB2_REOPEN)) {
		pr_debug("fuzz_qd: unknown flags bits: 0x%02x\n",
			 flags & ~0x17);
	}

	/* INDEX_SPECIFIED without a FileIndex is suspicious */
	if ((flags & SMB2_INDEX_SPECIFIED) && file_index == 0) {
		pr_debug("fuzz_qd: INDEX_SPECIFIED with FileIndex=0\n");
	}

	/* REOPEN and RESTART_SCANS together */
	if ((flags & SMB2_REOPEN) && (flags & SMB2_RESTART_SCANS)) {
		pr_debug("fuzz_qd: both REOPEN and RESTART_SCANS set\n");
	}

	/* Validate OutputBufferLength */
	if (output_buf_len == 0) {
		pr_debug("fuzz_qd: zero OutputBufferLength\n");
		return -EINVAL;
	}

	if (output_buf_len < min_entry) {
		pr_debug("fuzz_qd: OutputBufferLength %u < min_entry %u for %s\n",
			 output_buf_len, min_entry, level_name);
		/* Not necessarily fatal; server can return STATUS_BUFFER_OVERFLOW */
	}

	/* Validate FileNameOffset + FileNameLength bounds */
	if (fn_length > 0) {
		if (fn_offset == 0) {
			pr_debug("fuzz_qd: FileNameLength %u but offset is 0\n",
				 fn_length);
			return -EINVAL;
		}

		if ((u64)fn_offset + fn_length > len) {
			pr_debug("fuzz_qd: FileName at %u+%u exceeds packet %zu\n",
				 fn_offset, fn_length, len);
			return -EINVAL;
		}

		/* Validate the search pattern content */
		ret = fuzz_validate_search_pattern(data + fn_offset, fn_length);
		if (ret < 0)
			return ret;
	} else {
		pr_debug("fuzz_qd: empty FileName (enumerate all)\n");
	}

	return 0;
}

static int __init smb2_query_dir_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_query_dir_fuzz *req;
	int ret;

	pr_info("smb2_query_dir_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid QUERY_DIRECTORY with "*" pattern */
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILEID_BOTH_DIRECTORY_INFORMATION;
	req->Flags = 0;
	req->FileIndex = 0;
	req->OutputBufferLength = cpu_to_le32(65536);
	req->FileNameOffset = cpu_to_le16(QUERY_DIR_HDR_SIZE);
	req->FileNameLength = cpu_to_le16(2); /* "*" in UTF-16LE */
	test_buf[QUERY_DIR_HDR_SIZE] = '*';
	test_buf[QUERY_DIR_HDR_SIZE + 1] = 0;

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE + 2);
	pr_info("smb2_query_dir_fuzz: valid wildcard test returned %d\n", ret);

	/* Self-test 2: empty filename (enumerate all) */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILE_BOTH_DIRECTORY_INFORMATION;
	req->OutputBufferLength = cpu_to_le32(4096);
	req->FileNameOffset = 0;
	req->FileNameLength = 0;

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE);
	pr_info("smb2_query_dir_fuzz: empty filename test returned %d\n", ret);

	/* Self-test 3: invalid FileInformationClass */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = 255;
	req->OutputBufferLength = cpu_to_le32(4096);

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE);
	pr_info("smb2_query_dir_fuzz: invalid class test returned %d\n", ret);

	/* Self-test 4: FileName with odd length (invalid UTF-16LE) */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILE_NAMES_INFORMATION;
	req->OutputBufferLength = cpu_to_le32(4096);
	req->FileNameOffset = cpu_to_le16(QUERY_DIR_HDR_SIZE);
	req->FileNameLength = cpu_to_le16(3); /* odd length */
	test_buf[QUERY_DIR_HDR_SIZE] = '*';
	test_buf[QUERY_DIR_HDR_SIZE + 1] = 0;
	test_buf[QUERY_DIR_HDR_SIZE + 2] = '?';

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE + 3);
	pr_info("smb2_query_dir_fuzz: odd filename test returned %d\n", ret);

	/* Self-test 5: FileName offset past end of packet */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILE_DIRECTORY_INFORMATION;
	req->OutputBufferLength = cpu_to_le32(4096);
	req->FileNameOffset = cpu_to_le16(0xFFF0);
	req->FileNameLength = cpu_to_le16(100);

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE);
	pr_info("smb2_query_dir_fuzz: oob offset test returned %d\n", ret);

	/* Self-test 6: REOPEN + RESTART_SCANS flags */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILE_FULL_DIRECTORY_INFORMATION;
	req->Flags = SMB2_REOPEN | SMB2_RESTART_SCANS | SMB2_INDEX_SPECIFIED;
	req->FileIndex = cpu_to_le32(0xDEADBEEF);
	req->OutputBufferLength = cpu_to_le32(4096);
	req->FileNameOffset = cpu_to_le16(QUERY_DIR_HDR_SIZE);
	req->FileNameLength = cpu_to_le16(2);
	test_buf[QUERY_DIR_HDR_SIZE] = '*';
	test_buf[QUERY_DIR_HDR_SIZE + 1] = 0;

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE + 2);
	pr_info("smb2_query_dir_fuzz: flags combo test returned %d\n", ret);

	/* Self-test 7: search pattern with DOS wildcards and embedded NULs */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILEID_FULL_DIRECTORY_INFORMATION;
	req->OutputBufferLength = cpu_to_le32(4096);
	req->FileNameOffset = cpu_to_le16(QUERY_DIR_HDR_SIZE);
	req->FileNameLength = cpu_to_le16(14);
	/* "*.t\0x\0t" in UTF-16LE with embedded NUL and DOS wildcard */
	{
		u8 *fn = test_buf + QUERY_DIR_HDR_SIZE;
		fn[0] = '*';  fn[1] = 0;	/* '*' */
		fn[2] = '.';  fn[3] = 0;	/* '.' */
		fn[4] = 't';  fn[5] = 0;	/* 't' */
		fn[6] = 0;    fn[7] = 0;	/* NUL */
		fn[8] = 'x';  fn[9] = 0;	/* 'x' */
		fn[10] = '"'; fn[11] = 0;	/* '"' (DOS wildcard) */
		fn[12] = '>'; fn[13] = 0;	/* '>' (DOS wildcard) */
	}

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE + 14);
	pr_info("smb2_query_dir_fuzz: dos wildcard test returned %d\n", ret);

	/* Self-test 8: zero OutputBufferLength */
	memset(test_buf, 0, 512);
	req = (struct smb2_query_dir_fuzz *)test_buf;
	req->StructureSize = cpu_to_le16(QUERY_DIR_STRUCTURE_SIZE);
	req->FileInformationClass = FILE_NAMES_INFORMATION;
	req->OutputBufferLength = 0;

	ret = fuzz_query_dir(test_buf, QUERY_DIR_HDR_SIZE);
	pr_info("smb2_query_dir_fuzz: zero outlen test returned %d\n", ret);

	/* Self-test 9: garbage data */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_query_dir(test_buf, 512);
	pr_info("smb2_query_dir_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit smb2_query_dir_fuzz_exit(void)
{
	pr_info("smb2_query_dir_fuzz: module unloaded\n");
}

module_init(smb2_query_dir_fuzz_init);
module_exit(smb2_query_dir_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2 QUERY_DIRECTORY request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
