// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for DFS_GET_REFERRAL request parsing
 *
 *   This module exercises the DFS referral request validation logic used
 *   in ksmbd. DFS referral requests carry a referral level and a variable-
 *   length filename. Malformed requests can lead to out-of-bounds reads
 *   if null-termination or length checks are missing.
 *
 *   Targets:
 *     - MaxReferralLevel range validation
 *     - RequestFileName null-termination checking
 *     - Total request length validation
 *     - Unicode filename handling
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_dfs_referral() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the DFS referral request structure to avoid full header
 * dependencies.
 */

struct req_get_dfs_referral {
	__le16 MaxReferralLevel;
	__u8   RequestFileName[];
} __packed;

/* Maximum supported DFS referral level */
#define DFS_MAX_REFERRAL_LEVEL	4

/* Maximum filename length we'll process (safety cap) */
#define DFS_MAX_FILENAME_LEN	4096

/*
 * fuzz_validate_unicode_filename - Check unicode filename for validity
 * @data:	pointer to the filename bytes
 * @max_len:	maximum bytes available for the filename
 *
 * Scans for a null-terminator (16-bit null for Unicode).
 *
 * Return: length in bytes (including null terminator) if valid, negative on error
 */
static int fuzz_validate_unicode_filename(const u8 *data, size_t max_len)
{
	size_t i;

	/* Unicode null terminator is two zero bytes on a 2-byte boundary */
	if (max_len < 2)
		return -EINVAL;

	for (i = 0; i + 1 < max_len; i += 2) {
		if (data[i] == 0 && data[i + 1] == 0) {
			pr_debug("fuzz_dfs: found null terminator at offset %zu\n",
				 i);
			return (int)(i + 2);
		}
	}

	pr_debug("fuzz_dfs: no null terminator found in %zu bytes\n", max_len);
	return -EINVAL;
}

/*
 * fuzz_dfs_referral - Fuzz DFS_GET_REFERRAL request parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the DFS referral request validation that ksmbd performs
 * when processing FSCTL_DFS_GET_REFERRALS.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_dfs_referral(const u8 *data, size_t len)
{
	const struct req_get_dfs_referral *req;
	u16 max_referral_level;
	size_t filename_max_len;
	int filename_len;

	if (len < sizeof(struct req_get_dfs_referral)) {
		pr_debug("fuzz_dfs: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	/* Cap to prevent excessive processing */
	if (len > DFS_MAX_FILENAME_LEN + sizeof(struct req_get_dfs_referral))
		len = DFS_MAX_FILENAME_LEN + sizeof(struct req_get_dfs_referral);

	req = (const struct req_get_dfs_referral *)data;
	max_referral_level = le16_to_cpu(req->MaxReferralLevel);

	/* Validate MaxReferralLevel */
	if (max_referral_level == 0) {
		pr_debug("fuzz_dfs: MaxReferralLevel is 0\n");
		return -EINVAL;
	}

	if (max_referral_level > DFS_MAX_REFERRAL_LEVEL) {
		pr_debug("fuzz_dfs: MaxReferralLevel %u exceeds max %u\n",
			 max_referral_level, DFS_MAX_REFERRAL_LEVEL);
		return -EINVAL;
	}

	/* Calculate available filename bytes */
	filename_max_len = len - sizeof(struct req_get_dfs_referral);

	if (filename_max_len == 0) {
		pr_debug("fuzz_dfs: empty RequestFileName\n");
		return -EINVAL;
	}

	/* Validate filename is null-terminated (Unicode) */
	filename_len = fuzz_validate_unicode_filename(req->RequestFileName,
						      filename_max_len);
	if (filename_len < 0) {
		pr_debug("fuzz_dfs: filename not null-terminated\n");
		return -EINVAL;
	}

	/* Validate filename starts with a backslash (Unicode LE: 0x5C 0x00) */
	if (filename_len >= 2) {
		if (req->RequestFileName[0] != 0x5C ||
		    req->RequestFileName[1] != 0x00) {
			pr_debug("fuzz_dfs: filename does not start with backslash\n");
			/* Not fatal, just noted */
		}
	}

	pr_debug("fuzz_dfs: referral level=%u filename_len=%d\n",
		 max_referral_level, filename_len);

	return 0;
}

static int __init dfs_referral_fuzz_init(void)
{
	u8 *test_buf;
	struct req_get_dfs_referral *req;
	int ret;

	pr_info("dfs_referral_fuzz: module loaded\n");

	test_buf = kzalloc(256, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid referral request with backslash filename */
	req = (struct req_get_dfs_referral *)test_buf;
	req->MaxReferralLevel = cpu_to_le16(3);
	/* Unicode "\\server\share" followed by null terminator */
	req->RequestFileName[0] = 0x5C; /* backslash LE */
	req->RequestFileName[1] = 0x00;
	req->RequestFileName[2] = 0x73; /* 's' LE */
	req->RequestFileName[3] = 0x00;
	req->RequestFileName[4] = 0x00; /* null terminator */
	req->RequestFileName[5] = 0x00;

	ret = fuzz_dfs_referral(test_buf,
		sizeof(struct req_get_dfs_referral) + 6);
	pr_info("dfs_referral_fuzz: valid referral test returned %d\n", ret);

	/* Self-test 2: empty filename */
	memset(test_buf, 0, 256);
	req = (struct req_get_dfs_referral *)test_buf;
	req->MaxReferralLevel = cpu_to_le16(3);
	ret = fuzz_dfs_referral(test_buf, sizeof(struct req_get_dfs_referral));
	pr_info("dfs_referral_fuzz: empty filename test returned %d\n", ret);

	/* Self-test 3: oversized filename (no null terminator) */
	memset(test_buf, 0x41, 256); /* fill with 'A' */
	req = (struct req_get_dfs_referral *)test_buf;
	req->MaxReferralLevel = cpu_to_le16(2);
	ret = fuzz_dfs_referral(test_buf, 256);
	pr_info("dfs_referral_fuzz: oversized filename test returned %d\n", ret);

	/* Self-test 4: MaxReferralLevel too high */
	memset(test_buf, 0, 256);
	req = (struct req_get_dfs_referral *)test_buf;
	req->MaxReferralLevel = cpu_to_le16(100);
	req->RequestFileName[0] = 0x00;
	req->RequestFileName[1] = 0x00;
	ret = fuzz_dfs_referral(test_buf,
		sizeof(struct req_get_dfs_referral) + 2);
	pr_info("dfs_referral_fuzz: high referral level test returned %d\n", ret);

	/* Self-test 5: MaxReferralLevel zero */
	memset(test_buf, 0, 256);
	req = (struct req_get_dfs_referral *)test_buf;
	req->MaxReferralLevel = 0;
	req->RequestFileName[0] = 0x00;
	req->RequestFileName[1] = 0x00;
	ret = fuzz_dfs_referral(test_buf,
		sizeof(struct req_get_dfs_referral) + 2);
	pr_info("dfs_referral_fuzz: zero referral level test returned %d\n", ret);

	/* Self-test 6: garbage data */
	memset(test_buf, 0xff, 256);
	ret = fuzz_dfs_referral(test_buf, 256);
	pr_info("dfs_referral_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit dfs_referral_fuzz_exit(void)
{
	pr_info("dfs_referral_fuzz: module unloaded\n");
}

module_init(dfs_referral_fuzz_init);
module_exit(dfs_referral_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for DFS referral request parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
