// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for extended attribute (EA) buffer parsing
 *
 *   This module exercises the EA chain parsing logic used in ksmbd
 *   when processing SET_INFO with FILE_FULL_EA_INFORMATION and
 *   CREATE contexts with embedded EA buffers.
 *
 *   Targets:
 *     - smb2_ea_info chain walk: NextEntryOffset, EaNameLength,
 *       EaValueLength validation
 *     - EA in CREATE context: create_ea_buf_req wrapper
 *     - EA query: smb2_ea_info_req traversal
 *
 *   Corpus seed hints:
 *     - Single EA: NextEntryOffset=0, EaNameLength=4, EaValueLength=8,
 *       Flags=0, "test\0" + 8 bytes value
 *     - Chained: NextEntryOffset=24 (aligned), then another EA
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* Extended attribute information entry (MS-FSCC 2.4.15) */
struct smb2_ea_info_fuzz {
	__le32 NextEntryOffset;
	__u8   Flags;
	__u8   EaNameLength;
	__le16 EaValueLength;
	/* EaName[EaNameLength+1] followed by EaValue[EaValueLength] */
} __packed;

#define EA_INFO_HDR_SIZE	sizeof(struct smb2_ea_info_fuzz)
#define MAX_EA_ENTRIES		1024
#define MAX_EA_NAME_LEN		255
#define MAX_EA_VALUE_LEN	65535

/*
 * fuzz_ea_set - Fuzz EA buffer parsing for SET_INFO
 * @data:	raw EA buffer
 * @len:	length of buffer
 *
 * Walks the chained EA entries validating NextEntryOffset, EaNameLength,
 * and EaValueLength against the buffer bounds.
 *
 * Return: number of EA entries, negative on error
 */
static int fuzz_ea_set(const u8 *data, size_t len)
{
	size_t offset = 0;
	int count = 0;

	if (len < EA_INFO_HDR_SIZE)
		return -EINVAL;

	if (len > 65536)
		len = 65536;

	while (offset + EA_INFO_HDR_SIZE <= len && count < MAX_EA_ENTRIES) {
		const struct smb2_ea_info_fuzz *ea;
		u32 next_off;
		u8 name_len;
		u16 value_len;
		size_t entry_size;

		ea = (const struct smb2_ea_info_fuzz *)(data + offset);
		next_off = le32_to_cpu(ea->NextEntryOffset);
		name_len = ea->EaNameLength;
		value_len = le16_to_cpu(ea->EaValueLength);

		/* Minimum entry size: header + name + NUL + value */
		entry_size = EA_INFO_HDR_SIZE + name_len + 1 + value_len;

		if (offset + entry_size > len) {
			pr_debug("fuzz_ea: entry %d overflows buffer "
				 "(off=%zu name=%u val=%u buf=%zu)\n",
				 count, offset, name_len, value_len, len);
			return -EINVAL;
		}

		/* Verify NUL terminator after name */
		if (data[offset + EA_INFO_HDR_SIZE + name_len] != '\0') {
			pr_debug("fuzz_ea: entry %d name not NUL-terminated\n",
				 count);
			/* Not always fatal, but noted */
		}

		pr_debug("fuzz_ea: [%d] name_len=%u val_len=%u next=%u flags=0x%02x\n",
			 count, name_len, value_len, next_off, ea->Flags);

		count++;

		if (next_off == 0)
			break;

		/* NextEntryOffset should be >= entry_size */
		if (next_off < entry_size) {
			pr_debug("fuzz_ea: NextEntryOffset %u < entry_size %zu\n",
				 next_off, entry_size);
			return -EINVAL;
		}

		/* NextEntryOffset should not go backward */
		if (offset + next_off <= offset) {
			pr_debug("fuzz_ea: NextEntryOffset overflow\n");
			return -EINVAL;
		}

		if (offset + next_off > len) {
			pr_debug("fuzz_ea: NextEntryOffset %u past end of buffer\n",
				 next_off);
			return -EINVAL;
		}

		offset += next_off;
	}

	pr_debug("fuzz_ea: parsed %d EA entries\n", count);
	return count;
}

/*
 * fuzz_ea_query - Fuzz EA query request buffer parsing
 * @data:	raw EA query info request buffer
 * @len:	length of buffer
 *
 * Walks the chained EA query entries (NextEntryOffset + EaNameLength + name).
 *
 * Return: number of entries, negative on error
 */
static int fuzz_ea_query(const u8 *data, size_t len)
{
	size_t offset = 0;
	int count = 0;

	/* EA query entry: 4-byte NextEntryOffset + 1-byte EaNameLength + name */
	while (offset + 5 <= len && count < MAX_EA_ENTRIES) {
		u32 next_off;
		u8 name_len;

		next_off = le32_to_cpu(*(__le32 *)(data + offset));
		name_len = data[offset + 4];

		if (offset + 5 + name_len > len) {
			pr_debug("fuzz_ea_q: entry %d name exceeds buffer\n",
				 count);
			return -EINVAL;
		}

		pr_debug("fuzz_ea_q: [%d] name_len=%u next=%u\n",
			 count, name_len, next_off);

		count++;

		if (next_off == 0)
			break;

		if (offset + next_off > len || offset + next_off <= offset)
			return -EINVAL;

		offset += next_off;
	}

	return count;
}

static int __init ea_parse_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_ea_info_fuzz *ea;
	int ret;

	pr_info("ea_parse_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: single EA entry */
	ea = (struct smb2_ea_info_fuzz *)test_buf;
	ea->NextEntryOffset = 0;
	ea->Flags = 0;
	ea->EaNameLength = 4;
	ea->EaValueLength = cpu_to_le16(6);
	memcpy(test_buf + EA_INFO_HDR_SIZE, "test", 4);
	test_buf[EA_INFO_HDR_SIZE + 4] = '\0';
	memcpy(test_buf + EA_INFO_HDR_SIZE + 5, "value1", 6);

	ret = fuzz_ea_set(test_buf, EA_INFO_HDR_SIZE + 11);
	pr_info("ea_parse_fuzz: single EA returned %d\n", ret);

	/* Self-test 2: two chained EAs */
	{
		u32 first_entry_size = EA_INFO_HDR_SIZE + 5 + 6;
		u32 next_aligned = (first_entry_size + 3) & ~3u;

		memset(test_buf, 0, 512);
		ea = (struct smb2_ea_info_fuzz *)test_buf;
		ea->NextEntryOffset = cpu_to_le32(next_aligned);
		ea->EaNameLength = 4;
		ea->EaValueLength = cpu_to_le16(6);
		memcpy(test_buf + EA_INFO_HDR_SIZE, "name", 4);
		test_buf[EA_INFO_HDR_SIZE + 4] = '\0';
		memcpy(test_buf + EA_INFO_HDR_SIZE + 5, "val123", 6);

		ea = (struct smb2_ea_info_fuzz *)(test_buf + next_aligned);
		ea->NextEntryOffset = 0;
		ea->EaNameLength = 3;
		ea->EaValueLength = cpu_to_le16(4);
		memcpy(test_buf + next_aligned + EA_INFO_HDR_SIZE, "foo", 3);
		test_buf[next_aligned + EA_INFO_HDR_SIZE + 3] = '\0';
		memcpy(test_buf + next_aligned + EA_INFO_HDR_SIZE + 4, "bar!", 4);

		ret = fuzz_ea_set(test_buf, next_aligned + EA_INFO_HDR_SIZE + 8);
		pr_info("ea_parse_fuzz: chained EA returned %d\n", ret);
	}

	/* Self-test 3: truncated */
	ret = fuzz_ea_set(test_buf, 4);
	pr_info("ea_parse_fuzz: truncated returned %d\n", ret);

	/* Self-test 4: EA query */
	memset(test_buf, 0, 512);
	*(__le32 *)test_buf = 0; /* NextEntryOffset = 0 */
	test_buf[4] = 5; /* EaNameLength */
	memcpy(test_buf + 5, "hello", 5);
	ret = fuzz_ea_query(test_buf, 10);
	pr_info("ea_parse_fuzz: query returned %d\n", ret);

	/* Self-test 5: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_ea_set(test_buf, 512);
	pr_info("ea_parse_fuzz: garbage set returned %d\n", ret);
	ret = fuzz_ea_query(test_buf, 512);
	pr_info("ea_parse_fuzz: garbage query returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit ea_parse_fuzz_exit(void)
{
	pr_info("ea_parse_fuzz: module unloaded\n");
}

module_init(ea_parse_fuzz_init);
module_exit(ea_parse_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for extended attribute (EA) buffer parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
