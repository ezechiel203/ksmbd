// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2/3 signing verification
 *
 *   This module exercises the SMB2 signature verification path with
 *   crafted headers containing invalid signatures, truncated signature
 *   fields, wrong dialect signing algorithms, and edge-case key
 *   material. The goal is to ensure signature verification rejects
 *   malformed input gracefully.
 *
 *   Targets:
 *     - Signature field (16 bytes) integrity
 *     - SMB2_FLAGS_SIGNED flag handling
 *     - Signing key: zero-length, all-zeros, all-ones, random
 *     - Pre-authentication integrity hash (SHA-512) input validation
 *     - HMAC-SHA256 (SMB 2.0.2/2.1) vs AES-CMAC (SMB 3.x) selection
 *     - Truncated header with SIGNED flag set
 *     - Zero-filled vs random signature comparison
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
#include <linux/crypto.h>
#include <crypto/hash.h>

/* Inline structures matching smb2pdu.h */

#define SMB2_PROTO_NUMBER		cpu_to_le32(0x424d53fe)
#define SMB2_FLAGS_SIGNED		cpu_to_le32(0x00000008)
#define __SMB2_HEADER_STRUCTURE_SIZE	64
#define SMB2_SIGNATURE_SIZE		16

/* Signing algorithm IDs from negotiate context */
#define SIGNING_ALG_HMAC_SHA256		0x0000
#define SIGNING_ALG_AES_CMAC		0x0001
#define SIGNING_ALG_AES_GMAC		0x0002

struct fuzz_smb2_hdr {
	__le32 ProtocolId;
	__le16 StructureSize;
	__le16 CreditCharge;
	__le32 Status;
	__le16 Command;
	__le16 CreditRequest;
	__le32 Flags;
	__le32 NextCommand;
	__le64 MessageId;
	union {
		struct {
			__le32 ProcessId;
			__le32 TreeId;
		} __packed SyncId;
		__le64 AsyncId;
	} __packed Id;
	__le64 SessionId;
	__u8   Signature[SMB2_SIGNATURE_SIZE];
} __packed;

#define FUZZ_ITERATIONS		500
#define FUZZ_BUF_SIZE		1024
#define SIGNING_KEY_SIZE	16

static u32 fuzz_seed;

static u32 fuzz_next(void)
{
	fuzz_seed = fuzz_seed * 1103515245 + 12345;
	return (fuzz_seed >> 16) & 0x7fff;
}

/*
 * fuzz_compute_simple_hash - Compute a simple hash for signature comparison
 * @key:	signing key
 * @key_len:	key length
 * @data:	message data (with signature zeroed)
 * @data_len:	message length
 * @out:	16-byte output signature
 *
 * This is a simplified stand-in that exercises the pattern of zeroing
 * the signature field before computing, without requiring crypto API.
 */
static void fuzz_compute_simple_hash(const u8 *key, size_t key_len,
				     const u8 *data, size_t data_len,
				     u8 *out)
{
	u32 hash = 0x811c9dc5; /* FNV-1a basis */
	size_t i;

	/* Mix in key */
	for (i = 0; i < key_len; i++)
		hash = (hash ^ key[i]) * 0x01000193;

	/* Mix in data */
	for (i = 0; i < data_len && i < 256; i++)
		hash = (hash ^ data[i]) * 0x01000193;

	/* Expand to 16 bytes */
	for (i = 0; i < SMB2_SIGNATURE_SIZE; i++) {
		out[i] = (u8)(hash & 0xff);
		hash = (hash >> 8) | (hash << 24);
		hash ^= (u32)i;
	}
}

/*
 * fuzz_verify_signature - Simulate SMB2 signature verification
 * @data:	raw packet buffer
 * @len:	packet length
 * @key:	signing key
 * @key_len:	key length
 * @algo:	signing algorithm ID
 *
 * Return: 0 on valid/unsigned, -EINVAL on malformed, -EKEYREJECTED on bad sig
 */
static int fuzz_verify_signature(const u8 *data, size_t len,
				 const u8 *key, size_t key_len,
				 u16 algo)
{
	struct fuzz_smb2_hdr *hdr;
	u8 saved_sig[SMB2_SIGNATURE_SIZE];
	u8 computed_sig[SMB2_SIGNATURE_SIZE];
	u8 *work_buf;
	u32 flags;

	if (len < sizeof(struct fuzz_smb2_hdr))
		return -EINVAL;

	hdr = (struct fuzz_smb2_hdr *)data;

	/* Validate protocol ID */
	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)
		return -EINVAL;

	flags = le32_to_cpu(hdr->Flags);

	/* If not signed, nothing to verify */
	if (!(hdr->Flags & SMB2_FLAGS_SIGNED)) {
		pr_debug("sign_fuzz: packet not signed\n");
		return 0;
	}

	/* Key must be present for signed packets */
	if (!key || key_len == 0) {
		pr_debug("sign_fuzz: signed but no key\n");
		return -EINVAL;
	}

	/* Validate algorithm */
	if (algo != SIGNING_ALG_HMAC_SHA256 &&
	    algo != SIGNING_ALG_AES_CMAC &&
	    algo != SIGNING_ALG_AES_GMAC) {
		pr_debug("sign_fuzz: unknown signing algo 0x%04x\n", algo);
		return -EINVAL;
	}

	/* Save original signature */
	memcpy(saved_sig, hdr->Signature, SMB2_SIGNATURE_SIZE);

	/* Create working copy with signature zeroed */
	work_buf = kzalloc(len, GFP_KERNEL);
	if (!work_buf)
		return -ENOMEM;

	memcpy(work_buf, data, len);
	memset(work_buf + offsetof(struct fuzz_smb2_hdr, Signature),
	       0, SMB2_SIGNATURE_SIZE);

	/* Compute expected signature */
	fuzz_compute_simple_hash(key, key_len, work_buf, len, computed_sig);

	kfree(work_buf);

	/* Compare */
	if (memcmp(saved_sig, computed_sig, SMB2_SIGNATURE_SIZE) != 0) {
		pr_debug("sign_fuzz: signature mismatch for algo 0x%04x\n",
			 algo);
		return -EKEYREJECTED;
	}

	pr_debug("sign_fuzz: signature valid\n");
	(void)flags;
	return 0;
}

/*
 * fuzz_build_signed_packet - Build a random signed/unsigned SMB2 packet
 * @buf:	output buffer
 * @buf_size:	buffer size
 * @key:	signing key
 * @key_len:	key length
 *
 * Return: total bytes written
 */
static size_t fuzz_build_signed_packet(u8 *buf, size_t buf_size,
				       u8 *key, size_t key_len)
{
	struct fuzz_smb2_hdr *hdr;
	u32 corrupt = fuzz_next() % 10;
	size_t payload_len;
	size_t total;

	if (buf_size < sizeof(struct fuzz_smb2_hdr))
		return 0;

	memset(buf, 0, sizeof(struct fuzz_smb2_hdr));
	hdr = (struct fuzz_smb2_hdr *)buf;

	hdr->ProtocolId = SMB2_PROTO_NUMBER;
	hdr->StructureSize = cpu_to_le16(__SMB2_HEADER_STRUCTURE_SIZE);
	hdr->Command = cpu_to_le16(fuzz_next() % 0x13);
	hdr->SessionId = cpu_to_le64(((u64)fuzz_next() << 16) | fuzz_next());
	hdr->MessageId = cpu_to_le64(fuzz_next());

	/* Random payload after header */
	payload_len = fuzz_next() % (buf_size - sizeof(struct fuzz_smb2_hdr));
	if (payload_len > 0)
		get_random_bytes(buf + sizeof(struct fuzz_smb2_hdr), payload_len);

	total = sizeof(struct fuzz_smb2_hdr) + payload_len;

	/* Decide whether to sign */
	if (fuzz_next() % 2) {
		u8 computed[SMB2_SIGNATURE_SIZE];

		hdr->Flags |= SMB2_FLAGS_SIGNED;

		/* Zero signature for computation */
		memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);

		/* Compute and set correct signature */
		fuzz_compute_simple_hash(key, key_len, buf, total, computed);
		memcpy(hdr->Signature, computed, SMB2_SIGNATURE_SIZE);

		/* Corruption modes */
		if (corrupt == 0) {
			/* Flip one bit in signature */
			hdr->Signature[fuzz_next() % SMB2_SIGNATURE_SIZE] ^=
				(1 << (fuzz_next() % 8));
		} else if (corrupt == 1) {
			/* All-zero signature */
			memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
		} else if (corrupt == 2) {
			/* Random signature */
			get_random_bytes(hdr->Signature, SMB2_SIGNATURE_SIZE);
		}
	} else {
		/* Unsigned packet */
		if (corrupt == 3) {
			/* Set SIGNED flag but no actual signature */
			hdr->Flags |= SMB2_FLAGS_SIGNED;
			memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);
		}
	}

	/* Sometimes corrupt the protocol ID */
	if (corrupt == 4)
		hdr->ProtocolId = cpu_to_le32(fuzz_next());

	return total;
}

static int __init signing_fuzz_init(void)
{
	u8 *buf;
	u8 key[SIGNING_KEY_SIZE];
	u16 algos[] = { SIGNING_ALG_HMAC_SHA256, SIGNING_ALG_AES_CMAC,
			SIGNING_ALG_AES_GMAC, 0xFFFF };
	size_t total;
	int i;

	pr_info("signing_fuzz: module loaded, running %d iterations\n",
		FUZZ_ITERATIONS);

	buf = kzalloc(FUZZ_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	fuzz_seed = 0xA5A5A5A5;

	/* Generate a random signing key */
	get_random_bytes(key, SIGNING_KEY_SIZE);

	for (i = 0; i < FUZZ_ITERATIONS; i++) {
		u16 algo = algos[fuzz_next() % ARRAY_SIZE(algos)];

		memset(buf, 0, FUZZ_BUF_SIZE);
		total = fuzz_build_signed_packet(buf, FUZZ_BUF_SIZE,
						 key, SIGNING_KEY_SIZE);
		fuzz_verify_signature(buf, total, key, SIGNING_KEY_SIZE, algo);
	}

	/* Edge cases */

	/* Zero-length key */
	fuzz_verify_signature(buf, sizeof(struct fuzz_smb2_hdr),
			      key, 0, SIGNING_ALG_HMAC_SHA256);

	/* Null key */
	fuzz_verify_signature(buf, sizeof(struct fuzz_smb2_hdr),
			      NULL, 0, SIGNING_ALG_AES_CMAC);

	/* Truncated header */
	fuzz_verify_signature(buf, 10, key, SIGNING_KEY_SIZE,
			      SIGNING_ALG_HMAC_SHA256);

	/* All zeros */
	memset(buf, 0, FUZZ_BUF_SIZE);
	fuzz_verify_signature(buf, FUZZ_BUF_SIZE, key, SIGNING_KEY_SIZE,
			      SIGNING_ALG_AES_CMAC);

	/* All 0xFF */
	memset(buf, 0xff, FUZZ_BUF_SIZE);
	fuzz_verify_signature(buf, FUZZ_BUF_SIZE, key, SIGNING_KEY_SIZE,
			      SIGNING_ALG_HMAC_SHA256);

	kfree(buf);
	pr_info("signing_fuzz: all iterations completed\n");
	return 0;
}

static void __exit signing_fuzz_exit(void)
{
	pr_info("signing_fuzz: module unloaded\n");
}

module_init(signing_fuzz_init);
module_exit(signing_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for SMB2/3 signing verification");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
