// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB3 transform header parsing
 *
 *   This module exercises the SMB3 encryption transform header validation
 *   logic. Transform headers precede encrypted SMB3 messages and carry
 *   session identification, message size, and cryptographic nonce data.
 *   Malformed transform headers can bypass encryption, cause buffer
 *   overflows on decryption, or lead to session confusion.
 *
 *   Targets:
 *     - ProtocolId validation (must be 0x424d53FD)
 *     - OriginalMessageSize sanity checking
 *     - SessionId non-zero validation
 *     - Flags field validation
 *     - Nonce and Signature field accessibility
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_transform_header() entry point
 *     accepts a raw byte buffer and length.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Inline the transform header structure to avoid full header
 * dependencies.
 */

struct smb2_transform_hdr {
	__le32 ProtocolId;	/* 0x424d53FD */
	__u8   Signature[16];
	__u8   Nonce[16];
	__le32 OriginalMessageSize;
	__le16 Reserved1;
	__le16 Flags;
	__le64 SessionId;
} __packed;

#define SMB3_TRANSFORM_PROTO_NUM	cpu_to_le32(0x424d53FD)
#define SMB3_TRANSFORM_HDR_SIZE		sizeof(struct smb2_transform_hdr)

/*
 * Maximum original message size. SMB3 messages are limited in practice
 * by the negotiated MaxTransactSize, but we use a generous safety cap.
 */
#define SMB3_MAX_MSG_SIZE		(16 * 1024 * 1024)

/* Transform header flags */
#define SMB2_TRANSFORM_FLAG_ENCRYPTED	0x0001

/*
 * fuzz_transform_header - Fuzz SMB3 transform header parsing
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Simulates the transform header validation that ksmbd performs
 * when receiving an encrypted SMB3 message.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_transform_header(const u8 *data, size_t len)
{
	const struct smb2_transform_hdr *hdr;
	u32 original_msg_size;
	u16 flags;
	u64 session_id;

	if (len < SMB3_TRANSFORM_HDR_SIZE) {
		pr_debug("fuzz_xform: input too small (%zu bytes)\n", len);
		return -EINVAL;
	}

	hdr = (const struct smb2_transform_hdr *)data;

	/* Validate ProtocolId - must be 0xFD 'S' 'M' 'B' */
	if (hdr->ProtocolId != SMB3_TRANSFORM_PROTO_NUM) {
		pr_debug("fuzz_xform: invalid protocol id: 0x%08x\n",
			 le32_to_cpu(hdr->ProtocolId));
		return -EINVAL;
	}

	/* Extract and validate OriginalMessageSize */
	original_msg_size = le32_to_cpu(hdr->OriginalMessageSize);
	if (original_msg_size == 0) {
		pr_debug("fuzz_xform: zero OriginalMessageSize\n");
		return -EINVAL;
	}

	if (original_msg_size > SMB3_MAX_MSG_SIZE) {
		pr_debug("fuzz_xform: OriginalMessageSize %u exceeds max %u\n",
			 original_msg_size, SMB3_MAX_MSG_SIZE);
		return -EINVAL;
	}

	/* Check that OriginalMessageSize fits within the remaining data */
	if (SMB3_TRANSFORM_HDR_SIZE + original_msg_size > len) {
		pr_debug("fuzz_xform: OriginalMessageSize %u exceeds available data %zu\n",
			 original_msg_size,
			 len - SMB3_TRANSFORM_HDR_SIZE);
		/* Not fatal - the encrypted data might be streamed */
	}

	/* Validate Flags */
	flags = le16_to_cpu(hdr->Flags);
	if (!(flags & SMB2_TRANSFORM_FLAG_ENCRYPTED)) {
		pr_debug("fuzz_xform: encrypted flag not set (flags=0x%04x)\n",
			 flags);
		/* Note: per spec, Flags should be 0x0001 for encrypted */
	}

	/* Validate SessionId - must be non-zero */
	session_id = le64_to_cpu(hdr->SessionId);
	if (session_id == 0) {
		pr_debug("fuzz_xform: zero SessionId\n");
		return -EINVAL;
	}

	/* Verify Signature and Nonce areas are accessible (guaranteed by size check) */
	pr_debug("fuzz_xform: valid transform hdr msg_size=%u flags=0x%04x sid=%llu\n",
		 original_msg_size, flags, session_id);

	/* Validate the signature is not all zeros (weak check) */
	{
		int i;
		int all_zero = 1;

		for (i = 0; i < 16; i++) {
			if (hdr->Signature[i] != 0) {
				all_zero = 0;
				break;
			}
		}
		if (all_zero)
			pr_debug("fuzz_xform: warning - all-zero signature\n");
	}

	/* Validate the nonce is not all zeros */
	{
		int i;
		int all_zero = 1;

		for (i = 0; i < 16; i++) {
			if (hdr->Nonce[i] != 0) {
				all_zero = 0;
				break;
			}
		}
		if (all_zero)
			pr_debug("fuzz_xform: warning - all-zero nonce\n");
	}

	return 0;
}

static int __init transform_header_fuzz_init(void)
{
	u8 test_buf[128];
	struct smb2_transform_hdr *hdr;
	int ret, i;

	pr_info("transform_header_fuzz: module loaded\n");

	/* Self-test 1: valid transform header */
	memset(test_buf, 0, sizeof(test_buf));
	hdr = (struct smb2_transform_hdr *)test_buf;
	hdr->ProtocolId = SMB3_TRANSFORM_PROTO_NUM;
	/* Set non-zero signature */
	for (i = 0; i < 16; i++)
		hdr->Signature[i] = (u8)(i + 1);
	/* Set non-zero nonce */
	for (i = 0; i < 16; i++)
		hdr->Nonce[i] = (u8)(i + 0x10);
	hdr->OriginalMessageSize = cpu_to_le32(64);
	hdr->Flags = cpu_to_le16(SMB2_TRANSFORM_FLAG_ENCRYPTED);
	hdr->SessionId = cpu_to_le64(0x1234567890ABCDEFULL);

	ret = fuzz_transform_header(test_buf, sizeof(test_buf));
	pr_info("transform_header_fuzz: valid header test returned %d\n", ret);

	/* Self-test 2: wrong protocol ID */
	memset(test_buf, 0, sizeof(test_buf));
	hdr = (struct smb2_transform_hdr *)test_buf;
	hdr->ProtocolId = cpu_to_le32(0x424d53FE); /* SMB2, not transform */
	hdr->OriginalMessageSize = cpu_to_le32(64);
	hdr->Flags = cpu_to_le16(SMB2_TRANSFORM_FLAG_ENCRYPTED);
	hdr->SessionId = cpu_to_le64(1);

	ret = fuzz_transform_header(test_buf, sizeof(test_buf));
	pr_info("transform_header_fuzz: wrong protocol test returned %d\n", ret);

	/* Self-test 3: zero message size */
	memset(test_buf, 0, sizeof(test_buf));
	hdr = (struct smb2_transform_hdr *)test_buf;
	hdr->ProtocolId = SMB3_TRANSFORM_PROTO_NUM;
	hdr->OriginalMessageSize = 0;
	hdr->Flags = cpu_to_le16(SMB2_TRANSFORM_FLAG_ENCRYPTED);
	hdr->SessionId = cpu_to_le64(1);

	ret = fuzz_transform_header(test_buf, sizeof(test_buf));
	pr_info("transform_header_fuzz: zero msg size test returned %d\n", ret);

	/* Self-test 4: max message size (exceeding limit) */
	memset(test_buf, 0, sizeof(test_buf));
	hdr = (struct smb2_transform_hdr *)test_buf;
	hdr->ProtocolId = SMB3_TRANSFORM_PROTO_NUM;
	hdr->OriginalMessageSize = cpu_to_le32(0xFFFFFFFF);
	hdr->Flags = cpu_to_le16(SMB2_TRANSFORM_FLAG_ENCRYPTED);
	hdr->SessionId = cpu_to_le64(1);

	ret = fuzz_transform_header(test_buf, sizeof(test_buf));
	pr_info("transform_header_fuzz: max msg size test returned %d\n", ret);

	/* Self-test 5: zero session ID */
	memset(test_buf, 0, sizeof(test_buf));
	hdr = (struct smb2_transform_hdr *)test_buf;
	hdr->ProtocolId = SMB3_TRANSFORM_PROTO_NUM;
	hdr->OriginalMessageSize = cpu_to_le32(64);
	hdr->Flags = cpu_to_le16(SMB2_TRANSFORM_FLAG_ENCRYPTED);
	hdr->SessionId = 0;

	ret = fuzz_transform_header(test_buf, sizeof(test_buf));
	pr_info("transform_header_fuzz: zero session test returned %d\n", ret);

	/* Self-test 6: truncated input */
	ret = fuzz_transform_header(test_buf, 10);
	pr_info("transform_header_fuzz: truncated test returned %d\n", ret);

	/* Self-test 7: garbage data */
	memset(test_buf, 0xff, sizeof(test_buf));
	ret = fuzz_transform_header(test_buf, sizeof(test_buf));
	pr_info("transform_header_fuzz: garbage test returned %d\n", ret);

	return 0;
}

static void __exit transform_header_fuzz_exit(void)
{
	pr_info("transform_header_fuzz: module unloaded\n");
}

module_init(transform_header_fuzz_init);
module_exit(transform_header_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB3 encryption transform header");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
