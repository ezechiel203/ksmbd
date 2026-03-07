// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB3 transform header parsing
 *
 *   This module exercises SMB3 encryption transform header parsing
 *   with malformed OriginalMessageSize, SessionId, nonce, flags,
 *   and protocol ID fields. Transform headers precede encrypted
 *   SMB3 messages and must be validated before decryption.
 *
 *   A compromised transform header can cause buffer overflows during
 *   decryption, session confusion, or bypass of encryption enforcement.
 *
 *   Targets:
 *     - ProtocolId validation (must be 0xFD 'S' 'M' 'B')
 *     - OriginalMessageSize: zero, enormous, exceeding buffer
 *     - SessionId: zero, valid, MAX_UINT64
 *     - Flags: valid encryption algorithms vs garbage
 *     - Nonce field: all zeros, all ones, random
 *     - Signature field accessibility
 *     - Chained transform + SMB2 header relationship
 *
 *   Usage with syzkaller:
 *     Load as a test module. Self-tests run on module init.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/random.h>

/* Inline structures matching smb2pdu.h */

#define SMB2_TRANSFORM_PROTO_NUM	cpu_to_le32(0x424d53fd)
#define SMB2_PROTO_NUMBER		cpu_to_le32(0x424d53fe)
#define SMB2_ENCRYPTION_AES128_CCM	cpu_to_le16(0x0001)
#define SMB2_ENCRYPTION_AES128_GCM	cpu_to_le16(0x0002)
#define SMB2_ENCRYPTION_AES256_CCM	cpu_to_le16(0x0003)
#define SMB2_ENCRYPTION_AES256_GCM	cpu_to_le16(0x0004)

struct fuzz_transform_hdr {
	__le32 ProtocolId;	/* 0xFD 'S' 'M' 'B' */
	__u8   Signature[16];
	__u8   Nonce[16];
	__le32 OriginalMessageSize;
	__le16 Reserved1;
	__le16 Flags;		/* EncryptionAlgorithm for SMB 3.0/3.0.2 */
	__le64 SessionId;
} __packed;

#define FUZZ_TRANSFORM_HDR_SIZE	sizeof(struct fuzz_transform_hdr)
#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		4096
#define MAX_ORIG_MSG_SIZE	(16 * 1024 * 1024)  /* 16 MB cap */

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

/*
 * fuzz_validate_transform_hdr - Validate a transform header
 * @data:	raw buffer
 * @len:	buffer length
 *
 * Simulates the validation ksmbd performs when encountering an
 * encrypted message. Checks protocol ID, message size bounds,
 * session ID validity, and encryption algorithm flags.
 *
 * Return: 0 on valid, negative on invalid
 */
static int fuzz_validate_transform_hdr(const u8 *data, size_t len)
{
	const struct fuzz_transform_hdr *hdr;
	u32 orig_msg_size;
	u64 session_id;
	u16 flags;
	bool valid_algo;

	if (len < FUZZ_TRANSFORM_HDR_SIZE) {
		pr_debug("enc_fuzz: buffer too small (%zu)\n", len);
		return -EINVAL;
	}

	hdr = (const struct fuzz_transform_hdr *)data;

	/* Protocol ID must be 0xFD534D42 */
	if (hdr->ProtocolId != SMB2_TRANSFORM_PROTO_NUM) {
		pr_debug("enc_fuzz: bad protocol id 0x%08x\n",
			 le32_to_cpu(hdr->ProtocolId));
		return -EINVAL;
	}

	/* OriginalMessageSize sanity */
	orig_msg_size = le32_to_cpu(hdr->OriginalMessageSize);
	if (orig_msg_size == 0) {
		pr_debug("enc_fuzz: zero OriginalMessageSize\n");
		return -EINVAL;
	}

	if (orig_msg_size > MAX_ORIG_MSG_SIZE) {
		pr_debug("enc_fuzz: OriginalMessageSize %u exceeds limit\n",
			 orig_msg_size);
		return -EINVAL;
	}

	/* Check if the original message would fit after the header */
	if (FUZZ_TRANSFORM_HDR_SIZE + orig_msg_size > len) {
		pr_debug("enc_fuzz: OriginalMessageSize %u exceeds buffer\n",
			 orig_msg_size);
		/* Not necessarily fatal: we may have only the header */
	}

	/* SessionId must not be zero */
	session_id = le64_to_cpu(hdr->SessionId);
	if (session_id == 0) {
		pr_debug("enc_fuzz: zero SessionId\n");
		return -EINVAL;
	}

	/* Flags field carries the encryption algorithm for SMB 3.0/3.0.2 */
	flags = le16_to_cpu(hdr->Flags);
	valid_algo = (hdr->Flags == SMB2_ENCRYPTION_AES128_CCM ||
		      hdr->Flags == SMB2_ENCRYPTION_AES128_GCM ||
		      hdr->Flags == SMB2_ENCRYPTION_AES256_CCM ||
		      hdr->Flags == SMB2_ENCRYPTION_AES256_GCM ||
		      flags == 0x0001); /* SMB 3.1.1 uses Flags=0x0001 */

	if (!valid_algo) {
		pr_debug("enc_fuzz: unknown encryption algo/flags 0x%04x\n",
			 flags);
		/* Not fatal, just informational */
	}

	/* If payload is present, check for embedded SMB2 header */
	if (FUZZ_TRANSFORM_HDR_SIZE + 4 <= len) {
		__le32 inner_proto = *(__le32 *)(data + FUZZ_TRANSFORM_HDR_SIZE);

		if (inner_proto == SMB2_PROTO_NUMBER)
			pr_debug("enc_fuzz: inner SMB2 header detected\n");
		else
			pr_debug("enc_fuzz: inner proto 0x%08x (encrypted)\n",
				 le32_to_cpu(inner_proto));
	}

	pr_debug("enc_fuzz: valid transform hdr size=%u sid=%llu flags=0x%04x\n",
		 orig_msg_size, session_id, flags);

	return 0;
}

/*
 * fuzz_build_random_transform - Build a random transform header + payload
 * @buf:	output buffer
 * @buf_size:	buffer size
 *
 * Return: total bytes written
 */
static size_t fuzz_build_random_transform(u8 *buf, size_t buf_size)
{
	struct fuzz_transform_hdr *hdr;
	u32 corrupt = fuzz_next() % 10;
	u32 msg_size;
	size_t total;

	if (buf_size < FUZZ_TRANSFORM_HDR_SIZE)
		return 0;

	memset(buf, 0, FUZZ_TRANSFORM_HDR_SIZE);
	hdr = (struct fuzz_transform_hdr *)buf;

	/* Protocol ID: usually valid, sometimes corrupted */
	if (corrupt == 0)
		hdr->ProtocolId = cpu_to_le32(fuzz_next());
	else
		hdr->ProtocolId = SMB2_TRANSFORM_PROTO_NUM;

	/* Signature: random bytes */
	get_random_bytes(hdr->Signature, 16);

	/* Nonce: various patterns */
	switch (fuzz_next() % 4) {
	case 0: /* All zeros */
		memset(hdr->Nonce, 0, 16);
		break;
	case 1: /* All ones */
		memset(hdr->Nonce, 0xff, 16);
		break;
	default: /* Random */
		get_random_bytes(hdr->Nonce, 16);
		break;
	}

	/* OriginalMessageSize: various interesting values */
	switch (fuzz_next() % 6) {
	case 0:
		msg_size = 0;
		break;
	case 1:
		msg_size = 64; /* minimal SMB2 header */
		break;
	case 2:
		msg_size = 0xFFFFFFFF;
		break;
	case 3:
		msg_size = buf_size * 2; /* exceeds buffer */
		break;
	case 4:
		msg_size = 1; /* tiny */
		break;
	default:
		msg_size = fuzz_next() % 8192;
		break;
	}
	hdr->OriginalMessageSize = cpu_to_le32(msg_size);

	/* Flags/EncryptionAlgorithm */
	switch (fuzz_next() % 5) {
	case 0:
		hdr->Flags = SMB2_ENCRYPTION_AES128_CCM;
		break;
	case 1:
		hdr->Flags = SMB2_ENCRYPTION_AES128_GCM;
		break;
	case 2:
		hdr->Flags = SMB2_ENCRYPTION_AES256_GCM;
		break;
	case 3:
		hdr->Flags = cpu_to_le16(0x0001);
		break;
	default:
		hdr->Flags = cpu_to_le16(fuzz_next());
		break;
	}

	/* SessionId */
	switch (fuzz_next() % 4) {
	case 0:
		hdr->SessionId = 0;
		break;
	case 1:
		hdr->SessionId = cpu_to_le64(U64_MAX);
		break;
	default:
		hdr->SessionId = cpu_to_le64(((u64)fuzz_next() << 16) |
					     fuzz_next());
		break;
	}

	/* Fill payload with random data if msg_size fits */
	total = FUZZ_TRANSFORM_HDR_SIZE;
	if (msg_size > 0 && msg_size < buf_size - FUZZ_TRANSFORM_HDR_SIZE) {
		get_random_bytes(buf + FUZZ_TRANSFORM_HDR_SIZE,
				 min_t(u32, msg_size, 512));
		total += min_t(u32, msg_size, buf_size - FUZZ_TRANSFORM_HDR_SIZE);
	}

	return total;
}

static int __init encryption_fuzz_init(void)
{
	u8 *buf;
	size_t total;
	int i;

	pr_info("encryption_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0xFEEDFACE;

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		memset(buf, 0, FUZZ_BUF_SIZE);
		total = fuzz_build_random_transform(buf, FUZZ_BUF_SIZE);
		fuzz_validate_transform_hdr(buf, total);
	}

	/* Edge cases */
	fuzz_validate_transform_hdr(buf, 0);
	fuzz_validate_transform_hdr(buf, 1);
	fuzz_validate_transform_hdr(buf, FUZZ_TRANSFORM_HDR_SIZE - 1);

	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_validate_transform_hdr(buf, FUZZ_BUF_SIZE);

	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_validate_transform_hdr(buf, FUZZ_BUF_SIZE);

	kfree(buf);
	pr_info("encryption_fuzz: all iterations completed\n");
	return 0;
}

static void __exit encryption_fuzz_exit(void)
{
	pr_info("encryption_fuzz: module unloaded\n");
}

module_init(encryption_fuzz_init);
module_exit(encryption_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB3 transform header parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
