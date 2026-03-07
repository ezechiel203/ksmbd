// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for QUERY_QUOTA_INFO structure parsing
 *
 *   This module exercises the quota query SID list parsing logic used
 *   in ksmbd. Quota requests carry SID lists with chained entries.
 *   Malformed SID lists can lead to out-of-bounds reads, infinite
 *   loops, or incorrect quota lookups.
 *
 *   Targets:
 *     - SID list traversal (NextEntryOffset chain)
 *     - SID length bounds checking
 *     - StartSidOffset/Length validation
 *     - ReturnSingle and RestartScan flag handling
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_quota_request() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the structures to avoid full header dependencies.
 */

struct smb2_query_quota_info {
	__u8   ReturnSingle;
	__u8   RestartScan;
	__le16 Reserved;
	__le32 SidListLength;
	__le32 StartSidLength;
	__le32 StartSidOffset;
} __packed;

/* SID list entry in quota query */
struct smb2_sid_list_entry {
	__le32 NextEntryOffset;
	__le32 SidLength;
	/* Followed by SID data */
} __packed;

/* Minimal SID structure for validation */
struct smb_sid_basic {
	__u8 revision;
	__u8 num_subauth;
	__u8 authority[6];
	/* Followed by num_subauth * __le32 sub_auth */
} __packed;

#define SID_MAX_SUB_AUTHORITIES	15
#define MAX_SID_LIST_ENTRIES	1024

/*
 * fuzz_validate_sid_in_list - Validate a SID embedded in a list entry
 * @data:	pointer to the SID data
 * @max_len:	maximum bytes available for the SID
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_sid_in_list(const u8 *data, size_t max_len)
{
	const struct smb_sid_basic *sid;
	size_t expected_size;

	if (max_len < sizeof(struct smb_sid_basic)) {
		pr_debug("fuzz_quota: SID too small (%zu bytes)\n", max_len);
		return -EINVAL;
	}

	sid = (const struct smb_sid_basic *)data;

	if (sid->revision != 1) {
		pr_debug("fuzz_quota: SID revision %u != 1\n", sid->revision);
		return -EINVAL;
	}

	if (sid->num_subauth > SID_MAX_SUB_AUTHORITIES) {
		pr_debug("fuzz_quota: SID num_subauth %u exceeds max\n",
			 sid->num_subauth);
		return -EINVAL;
	}

	expected_size = sizeof(struct smb_sid_basic) +
			sid->num_subauth * sizeof(__le32);
	if (expected_size > max_len) {
		pr_debug("fuzz_quota: SID needs %zu bytes, have %zu\n",
			 expected_size, max_len);
		return -EINVAL;
	}

	pr_debug("fuzz_quota: valid SID rev=%u num_subauth=%u\n",
		 sid->revision, sid->num_subauth);
	return 0;
}

/*
 * fuzz_walk_sid_list - Walk the SID list chain
 * @data:	pointer to the start of the SID list
 * @len:	total SID list length
 *
 * Return: number of entries traversed, or negative on error
 */
static int fuzz_walk_sid_list(const u8 *data, size_t len)
{
	const struct smb2_sid_list_entry *entry;
	u32 offset = 0;
	u32 next_entry_offset;
	u32 sid_length;
	int count = 0;

	if (len < sizeof(struct smb2_sid_list_entry)) {
		pr_debug("fuzz_quota: SID list too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	while (offset + sizeof(struct smb2_sid_list_entry) <= len) {
		entry = (const struct smb2_sid_list_entry *)(data + offset);
		next_entry_offset = le32_to_cpu(entry->NextEntryOffset);
		sid_length = le32_to_cpu(entry->SidLength);

		/* Validate SID data fits within this entry */
		if (offset + sizeof(struct smb2_sid_list_entry) + sid_length > len) {
			pr_debug("fuzz_quota: SID entry %d data at %u+%u exceeds buffer %zu\n",
				 count, offset,
				 (u32)sizeof(struct smb2_sid_list_entry) + sid_length,
				 len);
			return -EINVAL;
		}

		/* Validate the SID itself if present */
		if (sid_length > 0) {
			int ret = fuzz_validate_sid_in_list(
				data + offset + sizeof(struct smb2_sid_list_entry),
				sid_length);
			if (ret < 0)
				pr_debug("fuzz_quota: SID entry %d has invalid SID\n",
					 count);
		}

		count++;

		/* Safety limit */
		if (count > MAX_SID_LIST_ENTRIES) {
			pr_debug("fuzz_quota: too many SID entries, stopping\n");
			break;
		}

		/* Advance to next entry */
		if (next_entry_offset == 0)
			break;

		/* NextEntryOffset must move forward */
		if (next_entry_offset < sizeof(struct smb2_sid_list_entry)) {
			pr_debug("fuzz_quota: NextEntryOffset %u too small\n",
				 next_entry_offset);
			return -EINVAL;
		}

		if (offset + next_entry_offset > len) {
			pr_debug("fuzz_quota: NextEntryOffset %u exceeds buffer at offset %u\n",
				 next_entry_offset, offset);
			return -EINVAL;
		}

		offset += next_entry_offset;
	}

	pr_debug("fuzz_quota: walked %d SID list entries\n", count);
	return count;
}

/*
 * fuzz_quota_request - Fuzz QUERY_QUOTA_INFO request parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the quota query request validation that ksmbd performs.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_quota_request(const u8 *data, size_t len)
{
	const struct smb2_query_quota_info *info;
	u32 sid_list_length;
	u32 start_sid_length;
	u32 start_sid_offset;
	size_t remaining;

	if (len < sizeof(struct smb2_query_quota_info)) {
		pr_debug("fuzz_quota: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (len > 65536)
		len = 65536;

	info = (const struct smb2_query_quota_info *)data;
	sid_list_length = le32_to_cpu(info->SidListLength);
	start_sid_length = le32_to_cpu(info->StartSidLength);
	start_sid_offset = le32_to_cpu(info->StartSidOffset);

	pr_debug("fuzz_quota: ReturnSingle=%u RestartScan=%u SidListLen=%u StartSidLen=%u StartSidOff=%u\n",
		 info->ReturnSingle, info->RestartScan,
		 sid_list_length, start_sid_length, start_sid_offset);

	remaining = len - sizeof(struct smb2_query_quota_info);

	/* Validate SID list if present */
	if (sid_list_length > 0) {
		if (sid_list_length > remaining) {
			pr_debug("fuzz_quota: SidListLength %u exceeds remaining %zu\n",
				 sid_list_length, remaining);
			return -EINVAL;
		}

		return fuzz_walk_sid_list(
			data + sizeof(struct smb2_query_quota_info),
			sid_list_length);
	}

	/* Validate StartSid if present */
	if (start_sid_length > 0) {
		if (start_sid_offset < sizeof(struct smb2_query_quota_info)) {
			pr_debug("fuzz_quota: StartSidOffset %u overlaps header\n",
				 start_sid_offset);
			return -EINVAL;
		}

		if (start_sid_offset + start_sid_length > len) {
			pr_debug("fuzz_quota: StartSid at %u+%u exceeds buffer %zu\n",
				 start_sid_offset, start_sid_length, len);
			return -EINVAL;
		}

		return fuzz_validate_sid_in_list(
			data + start_sid_offset, start_sid_length);
	}

	return 0;
}

static int __init quota_request_fuzz_init(void)
{
	u8 *test_buf;
	struct smb2_query_quota_info *info;
	struct smb2_sid_list_entry *entry;
	struct smb_sid_basic *sid;
	size_t off;
	int ret;

	pr_info("quota_request_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: empty SID list */
	info = (struct smb2_query_quota_info *)test_buf;
	info->ReturnSingle = 0;
	info->RestartScan = 1;
	info->SidListLength = 0;
	info->StartSidLength = 0;
	info->StartSidOffset = 0;

	ret = fuzz_quota_request(test_buf, sizeof(struct smb2_query_quota_info));
	pr_info("quota_request_fuzz: empty SID list test returned %d\n", ret);

	/* Self-test 2: single SID in list */
	memset(test_buf, 0, 512);
	info = (struct smb2_query_quota_info *)test_buf;
	info->ReturnSingle = 1;
	info->RestartScan = 0;
	off = sizeof(struct smb2_query_quota_info);

	entry = (struct smb2_sid_list_entry *)(test_buf + off);
	entry->NextEntryOffset = 0;
	entry->SidLength = cpu_to_le32(sizeof(struct smb_sid_basic) +
				       sizeof(__le32));
	sid = (struct smb_sid_basic *)(test_buf + off +
		sizeof(struct smb2_sid_list_entry));
	sid->revision = 1;
	sid->num_subauth = 1;
	memset(sid->authority, 0, 6);
	sid->authority[5] = 5;

	info->SidListLength = cpu_to_le32(
		sizeof(struct smb2_sid_list_entry) +
		sizeof(struct smb_sid_basic) + sizeof(__le32));

	ret = fuzz_quota_request(test_buf, off +
		sizeof(struct smb2_sid_list_entry) +
		sizeof(struct smb_sid_basic) + sizeof(__le32));
	pr_info("quota_request_fuzz: single SID test returned %d\n", ret);

	/* Self-test 3: chained SIDs */
	memset(test_buf, 0, 512);
	info = (struct smb2_query_quota_info *)test_buf;
	off = sizeof(struct smb2_query_quota_info);

	/* First entry */
	entry = (struct smb2_sid_list_entry *)(test_buf + off);
	entry->NextEntryOffset = cpu_to_le32(
		sizeof(struct smb2_sid_list_entry) +
		sizeof(struct smb_sid_basic) + sizeof(__le32));
	entry->SidLength = cpu_to_le32(sizeof(struct smb_sid_basic) +
				       sizeof(__le32));
	sid = (struct smb_sid_basic *)(test_buf + off +
		sizeof(struct smb2_sid_list_entry));
	sid->revision = 1;
	sid->num_subauth = 1;

	/* Second entry */
	off += sizeof(struct smb2_sid_list_entry) +
	       sizeof(struct smb_sid_basic) + sizeof(__le32);
	entry = (struct smb2_sid_list_entry *)(test_buf + off);
	entry->NextEntryOffset = 0;
	entry->SidLength = cpu_to_le32(sizeof(struct smb_sid_basic) +
				       sizeof(__le32));
	sid = (struct smb_sid_basic *)(test_buf + off +
		sizeof(struct smb2_sid_list_entry));
	sid->revision = 1;
	sid->num_subauth = 1;

	off += sizeof(struct smb2_sid_list_entry) +
	       sizeof(struct smb_sid_basic) + sizeof(__le32);

	info->SidListLength = cpu_to_le32(
		off - sizeof(struct smb2_query_quota_info));

	ret = fuzz_quota_request(test_buf, off);
	pr_info("quota_request_fuzz: chained SIDs test returned %d\n", ret);

	/* Self-test 4: truncated chain */
	memset(test_buf, 0, 512);
	info = (struct smb2_query_quota_info *)test_buf;
	info->SidListLength = cpu_to_le32(100);
	ret = fuzz_quota_request(test_buf,
		sizeof(struct smb2_query_quota_info) + 4); /* too short */
	pr_info("quota_request_fuzz: truncated chain test returned %d\n", ret);

	/* Self-test 5: garbage data */
	memset(test_buf, 0xff, 512);
	ret = fuzz_quota_request(test_buf, 512);
	pr_info("quota_request_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit quota_request_fuzz_exit(void)
{
	pr_info("quota_request_fuzz: module unloaded\n");
}

module_init(quota_request_fuzz_init);
module_exit(quota_request_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for quota query SID list traversal");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
