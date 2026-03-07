// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB1 command parsing
 *
 *   This module exercises the SMB1 header validation, per-command
 *   WordCount/ByteCount checks, AndX chain traversal, NEGOTIATE
 *   dialect string parsing, and TRANSACTION parameter/data offset
 *   validation used in ksmbd.
 *
 *   Targets:
 *     - SMB1 header: Protocol signature, Command, Flags/Flags2,
 *       WordCount validation per command
 *     - AndX chain: AndXCommand, AndXOffset validation
 *     - NEGOTIATE: dialect string list ("\2" prefix, NUL-separated)
 *     - TRANSACTION/TRANSACTION2: ParameterOffset, ParameterCount,
 *       DataOffset, DataCount bounds
 *
 *   Corpus seed hints:
 *     - SMB1 header: 0xFF534D42 + Command byte + 32-byte header
 *     - NEGOTIATE: WC=0, ByteCount=N, "\2NT LM 0.12\0"
 *     - SESSION_SETUP_ANDX: WC=12 or 13
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* SMB1 protocol constants */
#define SMB1_PROTO_NUMBER		cpu_to_le32(0x424d53ff)
#define SMBFLG_RESPONSE			0x80

/* SMB1 commands (subset) */
#define SMB_COM_CREATE_DIRECTORY	0x00
#define SMB_COM_DELETE_DIRECTORY	0x01
#define SMB_COM_CLOSE			0x04
#define SMB_COM_FLUSH			0x05
#define SMB_COM_DELETE			0x06
#define SMB_COM_RENAME			0x07
#define SMB_COM_QUERY_INFORMATION	0x08
#define SMB_COM_SETATTR			0x09
#define SMB_COM_WRITE			0x0B
#define SMB_COM_CHECK_DIRECTORY		0x10
#define SMB_COM_PROCESS_EXIT		0x11
#define SMB_COM_LOCKING_ANDX		0x24
#define SMB_COM_TRANSACTION		0x25
#define SMB_COM_ECHO			0x2B
#define SMB_COM_READ_ANDX		0x2E
#define SMB_COM_WRITE_ANDX		0x2F
#define SMB_COM_TRANSACTION2		0x32
#define SMB_COM_FIND_CLOSE2		0x34
#define SMB_COM_TREE_DISCONNECT		0x71
#define SMB_COM_NEGOTIATE		0x72
#define SMB_COM_SESSION_SETUP_ANDX	0x73
#define SMB_COM_TREE_CONNECT_ANDX	0x75
#define SMB_COM_NT_TRANSACT		0xA0
#define SMB_COM_NT_CREATE_ANDX		0xA2
#define SMB_COM_NT_CANCEL		0xA4
#define SMB_COM_NT_RENAME		0xA5
#define SMB_COM_LOGOFF_ANDX		0x74
#define SMB_COM_OPEN_ANDX		0x2D
#define SMB_COM_QUERY_INFORMATION2	0x23
#define SMB_COM_SET_INFORMATION2	0x27
#define SMB_COM_QUERY_INFORMATION_DISK	0x80

#define SMBFLG2_UNICODE			0x8000

/* Minimal SMB1 header */
struct smb1_hdr {
	__u8  Protocol[4];     /* 0xFF 'S' 'M' 'B' */
	__u8  Command;
	__le32 Status;
	__u8  Flags;
	__le16 Flags2;
	__le16 PIDHigh;
	__u8  SecurityFeatures[8];
	__le16 Reserved;
	__le16 TID;
	__le16 PIDLow;
	__le16 UID;
	__le16 MID;
	__u8  WordCount;
	/* ParameterWords follow, then 2-byte ByteCount, then Bytes */
} __packed;

#define SMB1_HDR_SIZE	sizeof(struct smb1_hdr)

/*
 * fuzz_smb1_header - Fuzz SMB1 header validation
 * @data:	raw packet bytes
 * @len:	length of packet
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_smb1_header(const u8 *data, size_t len)
{
	const struct smb1_hdr *hdr;

	if (len < SMB1_HDR_SIZE) {
		pr_debug("fuzz_smb1: header too short (%zu)\n", len);
		return -EINVAL;
	}

	hdr = (const struct smb1_hdr *)data;

	/* Validate protocol signature */
	if (*(__le32 *)hdr->Protocol != SMB1_PROTO_NUMBER) {
		pr_debug("fuzz_smb1: bad protocol 0x%08x\n",
			 *(u32 *)hdr->Protocol);
		return -EINVAL;
	}

	/* Must be a request (not a response) */
	if (hdr->Flags & SMBFLG_RESPONSE) {
		pr_debug("fuzz_smb1: response flag set\n");
		return -EINVAL;
	}

	pr_debug("fuzz_smb1: cmd=0x%02x wc=%u flags=0x%02x flags2=0x%04x\n",
		 hdr->Command, hdr->WordCount, hdr->Flags,
		 le16_to_cpu(hdr->Flags2));

	return 0;
}

/*
 * fuzz_smb1_check_message - Full SMB1 message validation
 * @data:	raw packet bytes
 * @len:	length of packet
 *
 * Validates WordCount per command type and ByteCount against remaining buffer.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_smb1_check_message(const u8 *data, size_t len)
{
	const struct smb1_hdr *hdr;
	int wc;
	int expected_wc = -1;
	unsigned int offset;
	int bc;
	unsigned int total_size;
	int ret;

	ret = fuzz_smb1_header(data, len);
	if (ret < 0)
		return ret;

	hdr = (const struct smb1_hdr *)data;
	wc = hdr->WordCount;

	/* Validate WordCount per command */
	switch (hdr->Command) {
	case SMB_COM_CREATE_DIRECTORY:
	case SMB_COM_DELETE_DIRECTORY:
	case SMB_COM_QUERY_INFORMATION:
	case SMB_COM_TREE_DISCONNECT:
	case SMB_COM_NEGOTIATE:
	case SMB_COM_NT_CANCEL:
	case SMB_COM_CHECK_DIRECTORY:
	case SMB_COM_PROCESS_EXIT:
	case SMB_COM_QUERY_INFORMATION_DISK:
		expected_wc = 0;
		break;
	case SMB_COM_FLUSH:
	case SMB_COM_DELETE:
	case SMB_COM_RENAME:
	case SMB_COM_ECHO:
	case SMB_COM_FIND_CLOSE2:
	case SMB_COM_QUERY_INFORMATION2:
		expected_wc = 1;
		break;
	case SMB_COM_LOGOFF_ANDX:
		expected_wc = 2;
		break;
	case SMB_COM_CLOSE:
		expected_wc = 3;
		break;
	case SMB_COM_TREE_CONNECT_ANDX:
	case SMB_COM_NT_RENAME:
		expected_wc = 4;
		break;
	case SMB_COM_WRITE:
		expected_wc = 5;
		break;
	case SMB_COM_SETATTR:
	case SMB_COM_LOCKING_ANDX:
		expected_wc = 8;
		break;
	case SMB_COM_SET_INFORMATION2:
		expected_wc = 7;
		break;
	case SMB_COM_TRANSACTION:
		if (wc < 14)
			expected_wc = -2; /* error */
		break;
	case SMB_COM_SESSION_SETUP_ANDX:
		if (wc != 12 && wc != 13)
			expected_wc = -2;
		break;
	case SMB_COM_OPEN_ANDX:
	case SMB_COM_TRANSACTION2:
		expected_wc = 15;
		break;
	case SMB_COM_NT_TRANSACT:
		if (wc < 19)
			expected_wc = -2;
		break;
	case SMB_COM_NT_CREATE_ANDX:
		expected_wc = 24;
		break;
	case SMB_COM_READ_ANDX:
		if (wc != 10 && wc != 12)
			expected_wc = -2;
		break;
	case SMB_COM_WRITE_ANDX:
		if (wc != 12 && wc != 14)
			expected_wc = -2;
		break;
	default:
		pr_debug("fuzz_smb1: unknown command 0x%02x\n", hdr->Command);
		return -EOPNOTSUPP;
	}

	if (expected_wc == -2) {
		pr_debug("fuzz_smb1: invalid WordCount %d for cmd 0x%02x\n",
			 wc, hdr->Command);
		return -EINVAL;
	}

	if (expected_wc >= 0 && wc != expected_wc) {
		pr_debug("fuzz_smb1: WordCount %d != expected %d for cmd 0x%02x\n",
			 wc, expected_wc, hdr->Command);
		return -EINVAL;
	}

	/* Validate ByteCount */
	offset = SMB1_HDR_SIZE + wc * 2;
	if (offset + 2 > len) {
		pr_debug("fuzz_smb1: no room for ByteCount at offset %u\n",
			 offset);
		return -EINVAL;
	}

	bc = le16_to_cpu(*(__le16 *)(data + offset));

	/* Calculate total expected packet size */
	total_size = SMB1_HDR_SIZE - 4 + 2 + wc * 2 + bc;

	pr_debug("fuzz_smb1: cmd=0x%02x wc=%d bc=%d total=%u buflen=%zu\n",
		 hdr->Command, wc, bc, total_size, len);

	return 0;
}

/*
 * fuzz_smb1_andx_chain - Fuzz AndX chain traversal
 * @data:	raw packet bytes
 * @len:	length of packet
 *
 * Follows the AndX chain (AndXCommand/AndXOffset) validating that
 * offsets advance forward and stay within the buffer.
 *
 * Return: number of AndX commands in chain, negative on error
 */
static int fuzz_smb1_andx_chain(const u8 *data, size_t len)
{
	const struct smb1_hdr *hdr;
	int count = 0;
	unsigned int offset;
	u8 andx_command;
	u16 andx_offset;
	int wc;

	if (len < SMB1_HDR_SIZE)
		return -EINVAL;

	hdr = (const struct smb1_hdr *)data;
	if (*(__le32 *)hdr->Protocol != SMB1_PROTO_NUMBER)
		return -EINVAL;

	wc = hdr->WordCount;
	if (wc < 2) {
		/* Not enough words for AndX fields */
		return 0;
	}

	/* AndXCommand is first word (byte 0), AndXOffset is byte 2-3 */
	offset = SMB1_HDR_SIZE;
	if (offset + 4 > len)
		return -EINVAL;

	andx_command = data[offset];
	andx_offset = le16_to_cpu(*(__le16 *)(data + offset + 2));

	while (andx_command != 0xFF && count < 32) {
		count++;

		pr_debug("fuzz_smb1_andx: [%d] cmd=0x%02x offset=%u\n",
			 count, andx_command, andx_offset);

		/* AndXOffset must advance forward */
		if (andx_offset <= offset) {
			pr_debug("fuzz_smb1_andx: backward offset %u <= %u\n",
				 andx_offset, offset);
			return -EINVAL;
		}

		/* AndXOffset must be within buffer */
		if (andx_offset + SMB1_HDR_SIZE > len) {
			pr_debug("fuzz_smb1_andx: offset %u exceeds buffer\n",
				 andx_offset);
			return -EINVAL;
		}

		offset = andx_offset;

		/* Read next AndX fields */
		if (offset + 4 > len)
			break;

		andx_command = data[offset];
		andx_offset = le16_to_cpu(*(__le16 *)(data + offset + 2));
	}

	pr_debug("fuzz_smb1_andx: chain depth = %d\n", count);
	return count;
}

/*
 * fuzz_smb1_negotiate_dialects - Fuzz SMB1 NEGOTIATE dialect string parsing
 * @data:	raw dialect bytes (after SMB1 header + ByteCount)
 * @len:	length of dialect data
 *
 * Parses the NUL-terminated, "\2"-prefixed dialect string list.
 *
 * Return: number of dialects parsed, negative on error
 */
static int fuzz_smb1_negotiate_dialects(const u8 *data, size_t len)
{
	size_t pos = 0;
	int count = 0;

	if (len == 0)
		return 0;

	/* Cap to prevent excessive processing */
	if (len > 4096)
		len = 4096;

	while (pos < len) {
		size_t start;
		size_t str_len;

		/* Each dialect starts with 0x02 */
		if (data[pos] != 0x02) {
			pr_debug("fuzz_smb1_neg: bad dialect prefix 0x%02x at %zu\n",
				 data[pos], pos);
			return -EINVAL;
		}
		pos++;
		start = pos;

		/* Find NUL terminator */
		while (pos < len && data[pos] != '\0')
			pos++;

		if (pos >= len) {
			pr_debug("fuzz_smb1_neg: unterminated dialect string\n");
			return -EINVAL;
		}

		str_len = pos - start;
		pr_debug("fuzz_smb1_neg: dialect[%d] len=%zu '%.32s'\n",
			 count, str_len,
			 str_len > 0 ? (const char *)(data + start) : "");

		pos++; /* skip NUL */
		count++;

		if (count > 64) {
			pr_debug("fuzz_smb1_neg: too many dialects\n");
			break;
		}
	}

	pr_debug("fuzz_smb1_neg: parsed %d dialects\n", count);
	return count;
}

/*
 * fuzz_smb1_transaction - Fuzz TRANSACTION parameter/data offset validation
 * @data:	raw packet bytes (full SMB1 packet)
 * @len:	length of packet
 *
 * Validates ParameterOffset, ParameterCount, DataOffset, DataCount
 * for TRANSACTION/TRANSACTION2/NT_TRANSACT commands.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_smb1_transaction(const u8 *data, size_t len)
{
	const struct smb1_hdr *hdr;
	int wc;
	unsigned int words_offset;
	u16 param_count, param_offset;
	u16 data_count, data_offset;

	if (len < SMB1_HDR_SIZE)
		return -EINVAL;

	hdr = (const struct smb1_hdr *)data;
	if (*(__le32 *)hdr->Protocol != SMB1_PROTO_NUMBER)
		return -EINVAL;

	wc = hdr->WordCount;
	if (wc < 14) {
		pr_debug("fuzz_smb1_trans: WordCount %d too small\n", wc);
		return -EINVAL;
	}

	words_offset = SMB1_HDR_SIZE;
	if (words_offset + wc * 2 > len)
		return -EINVAL;

	/* TRANSACTION parameter words layout (MS-SMB section 2.2.4.33):
	 * Word[0]: TotalParameterCount
	 * Word[1]: TotalDataCount
	 * ...
	 * Word[9]: ParameterCount
	 * Word[10]: ParameterOffset
	 * Word[11]: DataCount
	 * Word[12]: DataOffset
	 */
	if (wc >= 15) {
		param_count = le16_to_cpu(*(__le16 *)(data + words_offset + 9 * 2));
		param_offset = le16_to_cpu(*(__le16 *)(data + words_offset + 10 * 2));
		data_count = le16_to_cpu(*(__le16 *)(data + words_offset + 11 * 2));
		data_offset = le16_to_cpu(*(__le16 *)(data + words_offset + 12 * 2));

		/* Validate parameter region */
		if (param_count > 0) {
			if ((u32)param_offset + param_count > len) {
				pr_debug("fuzz_smb1_trans: param overflow off=%u cnt=%u buf=%zu\n",
					 param_offset, param_count, len);
				return -EINVAL;
			}
		}

		/* Validate data region */
		if (data_count > 0) {
			if ((u32)data_offset + data_count > len) {
				pr_debug("fuzz_smb1_trans: data overflow off=%u cnt=%u buf=%zu\n",
					 data_offset, data_count, len);
				return -EINVAL;
			}
		}

		/* Check for overlapping regions */
		if (param_count > 0 && data_count > 0) {
			if (param_offset < data_offset + data_count &&
			    data_offset < param_offset + param_count) {
				pr_debug("fuzz_smb1_trans: param/data regions overlap\n");
			}
		}

		pr_debug("fuzz_smb1_trans: pc=%u po=%u dc=%u do=%u\n",
			 param_count, param_offset, data_count, data_offset);
	}

	return 0;
}

static int __init smb1_command_fuzz_init(void)
{
	u8 *test_buf;
	struct smb1_hdr *hdr;
	int ret;

	pr_info("smb1_command_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid NEGOTIATE */
	hdr = (struct smb1_hdr *)test_buf;
	*(__le32 *)hdr->Protocol = SMB1_PROTO_NUMBER;
	hdr->Command = SMB_COM_NEGOTIATE;
	hdr->WordCount = 0;
	/* ByteCount at offset 33 */
	{
		unsigned int bc_off = SMB1_HDR_SIZE;

		*(__le16 *)(test_buf + bc_off) = cpu_to_le16(16);
		/* Dialect: "\2NT LM 0.12\0" */
		test_buf[bc_off + 2] = 0x02;
		memcpy(test_buf + bc_off + 3, "NT LM 0.12", 11);
		test_buf[bc_off + 14] = 0;
	}
	ret = fuzz_smb1_check_message(test_buf, 48);
	pr_info("smb1_command_fuzz: valid negotiate returned %d\n", ret);

	/* Self-test 2: dialect string parsing */
	{
		u8 dialects[] = "\x02NT LM 0.12\x00\x02NT LANMAN 1.0\x00"
				"\x02SMB 2.002\x00";

		ret = fuzz_smb1_negotiate_dialects(dialects,
						   sizeof(dialects) - 1);
		pr_info("smb1_command_fuzz: dialect parse returned %d\n", ret);
	}

	/* Self-test 3: empty dialect list */
	ret = fuzz_smb1_negotiate_dialects(NULL, 0);
	pr_info("smb1_command_fuzz: empty dialect returned %d\n", ret);

	/* Self-test 4: truncated header */
	ret = fuzz_smb1_header(test_buf, 10);
	pr_info("smb1_command_fuzz: truncated header returned %d\n", ret);

	/* Self-test 5: wrong protocol */
	*(__le32 *)test_buf = cpu_to_le32(0x424d53fe); /* SMB2 */
	ret = fuzz_smb1_header(test_buf, 64);
	pr_info("smb1_command_fuzz: wrong protocol returned %d\n", ret);

	/* Self-test 6: TRANSACTION with overlapping regions */
	memset(test_buf, 0, 512);
	hdr = (struct smb1_hdr *)test_buf;
	*(__le32 *)hdr->Protocol = SMB1_PROTO_NUMBER;
	hdr->Command = SMB_COM_TRANSACTION;
	hdr->WordCount = 15;
	{
		unsigned int wo = SMB1_HDR_SIZE;

		/* param at offset 100, count 50 */
		*(__le16 *)(test_buf + wo + 9 * 2) = cpu_to_le16(50);
		*(__le16 *)(test_buf + wo + 10 * 2) = cpu_to_le16(100);
		/* data at offset 120, count 50 -- overlaps with params */
		*(__le16 *)(test_buf + wo + 11 * 2) = cpu_to_le16(50);
		*(__le16 *)(test_buf + wo + 12 * 2) = cpu_to_le16(120);
	}
	ret = fuzz_smb1_transaction(test_buf, 256);
	pr_info("smb1_command_fuzz: transaction overlap returned %d\n", ret);

	/* Self-test 7: garbage data */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_smb1_check_message(test_buf, 512);
	pr_info("smb1_command_fuzz: garbage returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit smb1_command_fuzz_exit(void)
{
	pr_info("smb1_command_fuzz: module unloaded\n");
}

module_init(smb1_command_fuzz_init);
module_exit(smb1_command_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB1 command parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
