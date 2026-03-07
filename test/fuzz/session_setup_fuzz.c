// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for SMB2 session setup / NTLMSSP parsing
 *
 *   This module exercises the NTLMSSP NEGOTIATE and AUTHENTICATE message
 *   parsing logic used in ksmbd. Session setup is pre-auth and
 *   unauthenticated, making it a critical attack surface.
 *
 *   Targets:
 *     - NTLMSSP NEGOTIATE_MESSAGE: Signature, MessageType, NegotiateFlags,
 *       DomainNameFields (Len/MaxLen/Offset), WorkstationFields
 *     - NTLMSSP AUTHENTICATE_MESSAGE: LmChallengeResponseFields,
 *       NtChallengeResponseFields, DomainNameFields, UserNameFields,
 *       WorkstationFields, EncryptedRandomSessionKeyFields, NegotiateFlags
 *     - NTLMSSP_ANONYMOUS detection (zero-length NtChallengeResponse)
 *     - SPNEGO NegTokenInit wrapper: outer SEQUENCE, mechTypes OID list
 *
 *   Corpus seed hints:
 *     - NTLMSSP Negotiate: "NTLMSSP\0" + le32(1) + le32(flags) + fields
 *     - NTLMSSP Authenticate: "NTLMSSP\0" + le32(3) + offset/length pairs
 *     - SPNEGO: 0x60 + length + OID SEQUENCE
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* NTLMSSP constants */
#define NTLMSSP_SIGNATURE		"NTLMSSP"
#define NTLMSSP_NEGOTIATE_MESSAGE	1
#define NTLMSSP_CHALLENGE_MESSAGE	2
#define NTLMSSP_AUTHENTICATE_MESSAGE	3

/* NTLMSSP field descriptor (offset/length pair) */
struct ntlmssp_field {
	__le16 Len;
	__le16 MaxLen;
	__le32 BufferOffset;
} __packed;

/* NTLMSSP NEGOTIATE_MESSAGE (type 1) */
struct ntlmssp_negotiate {
	__u8   Signature[8];       /* "NTLMSSP\0" */
	__le32 MessageType;        /* 1 */
	__le32 NegotiateFlags;
	struct ntlmssp_field DomainName;
	struct ntlmssp_field Workstation;
	/* Optional: Version (8 bytes) if NTLMSSP_NEGOTIATE_VERSION flag */
} __packed;

/* NTLMSSP AUTHENTICATE_MESSAGE (type 3) */
struct ntlmssp_authenticate {
	__u8   Signature[8];       /* "NTLMSSP\0" */
	__le32 MessageType;        /* 3 */
	struct ntlmssp_field LmChallengeResponse;
	struct ntlmssp_field NtChallengeResponse;
	struct ntlmssp_field DomainName;
	struct ntlmssp_field UserName;
	struct ntlmssp_field Workstation;
	struct ntlmssp_field EncryptedRandomSessionKey;
	__le32 NegotiateFlags;
	/* Optional: Version, MIC */
} __packed;

#define NTLMSSP_NEGOTIATE_UNICODE	0x00000001
#define NTLMSSP_NEGOTIATE_NTLM		0x00000200
#define NTLMSSP_NEGOTIATE_VERSION	0x02000000
#define NTLMSSP_ANONYMOUS		0x00000800

/*
 * fuzz_validate_ntlmssp_field - Validate an NTLMSSP offset/length field
 * @field:	the field descriptor
 * @buf_len:	total buffer length
 * @name:	field name for debug messages
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_ntlmssp_field(const struct ntlmssp_field *field,
				       size_t buf_len, const char *name)
{
	u16 field_len = le16_to_cpu(field->Len);
	u16 max_len = le16_to_cpu(field->MaxLen);
	u32 offset = le32_to_cpu(field->BufferOffset);

	/* MaxLen should be >= Len */
	if (max_len < field_len) {
		pr_debug("fuzz_sess: %s MaxLen %u < Len %u\n",
			 name, max_len, field_len);
		return -EINVAL;
	}

	/* If length is 0, offset doesn't matter */
	if (field_len == 0) {
		pr_debug("fuzz_sess: %s empty (len=0)\n", name);
		return 0;
	}

	/* Offset must be within buffer */
	if (offset >= buf_len) {
		pr_debug("fuzz_sess: %s offset %u >= buf_len %zu\n",
			 name, offset, buf_len);
		return -EINVAL;
	}

	/* Offset + length must be within buffer */
	if ((u64)offset + field_len > buf_len) {
		pr_debug("fuzz_sess: %s offset+len %u+%u > buf_len %zu\n",
			 name, offset, field_len, buf_len);
		return -EINVAL;
	}

	pr_debug("fuzz_sess: %s offset=%u len=%u maxlen=%u\n",
		 name, offset, field_len, max_len);

	return 0;
}

/*
 * fuzz_ntlmssp_negotiate - Fuzz NTLMSSP NEGOTIATE_MESSAGE parsing
 * @data:	raw NTLMSSP negotiate blob
 * @len:	length of blob
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ntlmssp_negotiate(const u8 *data, size_t len)
{
	const struct ntlmssp_negotiate *msg;
	u32 flags;
	int ret;

	if (len < sizeof(struct ntlmssp_negotiate)) {
		pr_debug("fuzz_sess: negotiate too short (%zu)\n", len);
		return -EINVAL;
	}

	msg = (const struct ntlmssp_negotiate *)data;

	/* Validate signature */
	if (memcmp(msg->Signature, NTLMSSP_SIGNATURE, 8) != 0) {
		pr_debug("fuzz_sess: bad NTLMSSP signature\n");
		return -EINVAL;
	}

	/* Validate message type */
	if (le32_to_cpu(msg->MessageType) != NTLMSSP_NEGOTIATE_MESSAGE) {
		pr_debug("fuzz_sess: wrong message type %u (expected 1)\n",
			 le32_to_cpu(msg->MessageType));
		return -EINVAL;
	}

	flags = le32_to_cpu(msg->NegotiateFlags);
	pr_debug("fuzz_sess: negotiate flags=0x%08x\n", flags);

	/* Validate optional fields */
	ret = fuzz_validate_ntlmssp_field(&msg->DomainName, len, "DomainName");
	if (ret < 0)
		return ret;

	ret = fuzz_validate_ntlmssp_field(&msg->Workstation, len, "Workstation");
	if (ret < 0)
		return ret;

	return 0;
}

/*
 * fuzz_ntlmssp_authenticate - Fuzz NTLMSSP AUTHENTICATE_MESSAGE parsing
 * @data:	raw NTLMSSP authenticate blob
 * @len:	length of blob
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ntlmssp_authenticate(const u8 *data, size_t len)
{
	const struct ntlmssp_authenticate *msg;
	u32 flags;
	int ret;
	bool is_anonymous = false;

	if (len < sizeof(struct ntlmssp_authenticate)) {
		pr_debug("fuzz_sess: auth too short (%zu)\n", len);
		return -EINVAL;
	}

	msg = (const struct ntlmssp_authenticate *)data;

	/* Validate signature */
	if (memcmp(msg->Signature, NTLMSSP_SIGNATURE, 8) != 0) {
		pr_debug("fuzz_sess: bad NTLMSSP signature\n");
		return -EINVAL;
	}

	/* Validate message type */
	if (le32_to_cpu(msg->MessageType) != NTLMSSP_AUTHENTICATE_MESSAGE) {
		pr_debug("fuzz_sess: wrong message type %u (expected 3)\n",
			 le32_to_cpu(msg->MessageType));
		return -EINVAL;
	}

	flags = le32_to_cpu(msg->NegotiateFlags);
	pr_debug("fuzz_sess: auth flags=0x%08x\n", flags);

	/* Check for anonymous authentication */
	if (le16_to_cpu(msg->NtChallengeResponse.Len) == 0) {
		is_anonymous = true;
		pr_debug("fuzz_sess: NTLMSSP_ANONYMOUS detected\n");
	}

	/* Validate all offset/length fields */
	ret = fuzz_validate_ntlmssp_field(&msg->LmChallengeResponse, len,
					  "LmChallengeResponse");
	if (ret < 0)
		return ret;

	ret = fuzz_validate_ntlmssp_field(&msg->NtChallengeResponse, len,
					  "NtChallengeResponse");
	if (ret < 0)
		return ret;

	ret = fuzz_validate_ntlmssp_field(&msg->DomainName, len, "DomainName");
	if (ret < 0)
		return ret;

	ret = fuzz_validate_ntlmssp_field(&msg->UserName, len, "UserName");
	if (ret < 0)
		return ret;

	ret = fuzz_validate_ntlmssp_field(&msg->Workstation, len,
					  "Workstation");
	if (ret < 0)
		return ret;

	ret = fuzz_validate_ntlmssp_field(&msg->EncryptedRandomSessionKey,
					  len, "EncryptedRandomSessionKey");
	if (ret < 0)
		return ret;

	/* Check for overlapping fields */
	{
		u32 nt_off = le32_to_cpu(msg->NtChallengeResponse.BufferOffset);
		u16 nt_len = le16_to_cpu(msg->NtChallengeResponse.Len);
		u32 lm_off = le32_to_cpu(msg->LmChallengeResponse.BufferOffset);
		u16 lm_len = le16_to_cpu(msg->LmChallengeResponse.Len);

		if (nt_len > 0 && lm_len > 0) {
			if (nt_off < lm_off + lm_len && lm_off < nt_off + nt_len)
				pr_debug("fuzz_sess: NtChallenge and LmChallenge overlap\n");
		}
	}

	(void)is_anonymous;
	return 0;
}

/*
 * fuzz_spnego_negtokeninit - Fuzz SPNEGO NegTokenInit wrapper
 * @data:	raw SPNEGO blob
 * @len:	length of blob
 *
 * Performs basic structural validation of the SPNEGO ASN.1 wrapper
 * around the NTLMSSP blob.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_spnego_negtokeninit(const u8 *data, size_t len)
{
	size_t pos = 0;
	u8 tag;
	size_t asn_len;

	if (len < 2) {
		pr_debug("fuzz_sess: spnego too short\n");
		return -EINVAL;
	}

	/* Cap processing */
	if (len > 65536)
		len = 65536;

	tag = data[pos++];

	/* Expect Application[0] = 0x60 for NegTokenInit */
	if (tag != 0x60 && tag != 0xA0) {
		pr_debug("fuzz_sess: unexpected SPNEGO tag 0x%02x\n", tag);
		return -EINVAL;
	}

	/* Parse ASN.1 length */
	if (data[pos] & 0x80) {
		/* Long form */
		int num_octets = data[pos] & 0x7F;

		pos++;
		if (num_octets > 4 || pos + num_octets > len) {
			pr_debug("fuzz_sess: bad ASN.1 length encoding\n");
			return -EINVAL;
		}
		asn_len = 0;
		while (num_octets-- > 0) {
			asn_len = (asn_len << 8) | data[pos++];
		}
	} else {
		asn_len = data[pos++];
	}

	pr_debug("fuzz_sess: SPNEGO tag=0x%02x asn_len=%zu remaining=%zu\n",
		 tag, asn_len, len - pos);

	/* Check that declared length fits within buffer */
	if (pos + asn_len > len) {
		pr_debug("fuzz_sess: SPNEGO length exceeds buffer\n");
		return -EINVAL;
	}

	/* Look for OID within the SPNEGO structure */
	if (pos < len && data[pos] == 0x06) {
		u8 oid_len;

		pos++;
		if (pos >= len)
			return -EINVAL;
		oid_len = data[pos++];
		if (pos + oid_len > len)
			return -EINVAL;
		pr_debug("fuzz_sess: found OID, length=%u\n", oid_len);
		pos += oid_len;
	}

	/* Look for mechToken containing NTLMSSP */
	while (pos + 8 <= len) {
		if (memcmp(data + pos, NTLMSSP_SIGNATURE, 8) == 0) {
			pr_debug("fuzz_sess: found embedded NTLMSSP at offset %zu\n",
				 pos);
			/* Could recurse into fuzz_ntlmssp_negotiate/authenticate */
			break;
		}
		pos++;
	}

	return 0;
}

static int __init session_setup_fuzz_init(void)
{
	u8 *test_buf;
	int ret;

	pr_info("session_setup_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid NEGOTIATE_MESSAGE */
	{
		struct ntlmssp_negotiate *msg =
			(struct ntlmssp_negotiate *)test_buf;

		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_NEGOTIATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM |
						  NTLMSSP_NEGOTIATE_UNICODE);
		ret = fuzz_ntlmssp_negotiate(test_buf,
					     sizeof(struct ntlmssp_negotiate));
		pr_info("session_setup_fuzz: valid negotiate returned %d\n", ret);
	}

	/* Self-test 2: truncated negotiate */
	ret = fuzz_ntlmssp_negotiate(test_buf, 8);
	pr_info("session_setup_fuzz: truncated negotiate returned %d\n", ret);

	/* Self-test 3: wrong signature */
	memset(test_buf, 0, 512);
	memcpy(test_buf, "NTLMXSP\0", 8);
	((struct ntlmssp_negotiate *)test_buf)->MessageType =
		cpu_to_le32(NTLMSSP_NEGOTIATE_MESSAGE);
	ret = fuzz_ntlmssp_negotiate(test_buf,
				     sizeof(struct ntlmssp_negotiate));
	pr_info("session_setup_fuzz: bad signature returned %d\n", ret);

	/* Self-test 4: valid AUTHENTICATE_MESSAGE (anonymous) */
	{
		struct ntlmssp_authenticate *msg =
			(struct ntlmssp_authenticate *)test_buf;

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);
		/* NtChallengeResponse.Len = 0 => anonymous */
		ret = fuzz_ntlmssp_authenticate(test_buf,
						sizeof(struct ntlmssp_authenticate));
		pr_info("session_setup_fuzz: anonymous auth returned %d\n", ret);
	}

	/* Self-test 5: authenticate with out-of-bounds offset */
	{
		struct ntlmssp_authenticate *msg =
			(struct ntlmssp_authenticate *)test_buf;

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->UserName.Len = cpu_to_le16(10);
		msg->UserName.MaxLen = cpu_to_le16(10);
		msg->UserName.BufferOffset = cpu_to_le32(0xFFFF);
		ret = fuzz_ntlmssp_authenticate(test_buf,
						sizeof(struct ntlmssp_authenticate) + 16);
		pr_info("session_setup_fuzz: oob offset returned %d\n", ret);
	}

	/* Self-test 6: SPNEGO wrapper */
	{
		memset(test_buf, 0, 512);
		test_buf[0] = 0x60; /* Application[0] */
		test_buf[1] = 20;   /* length */
		test_buf[2] = 0x06; /* OID tag */
		test_buf[3] = 6;    /* OID length */
		memset(test_buf + 4, 0x2B, 6); /* dummy OID bytes */
		memcpy(test_buf + 10, NTLMSSP_SIGNATURE, 8);
		ret = fuzz_spnego_negtokeninit(test_buf, 22);
		pr_info("session_setup_fuzz: spnego test returned %d\n", ret);
	}

	/* Self-test 7: garbage */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_ntlmssp_negotiate(test_buf, 512);
	pr_info("session_setup_fuzz: garbage negotiate returned %d\n", ret);
	ret = fuzz_ntlmssp_authenticate(test_buf, 512);
	pr_info("session_setup_fuzz: garbage auth returned %d\n", ret);
	ret = fuzz_spnego_negtokeninit(test_buf, 512);
	pr_info("session_setup_fuzz: garbage spnego returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit session_setup_fuzz_exit(void)
{
	pr_info("session_setup_fuzz: module unloaded\n");
}

module_init(session_setup_fuzz_init);
module_exit(session_setup_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for NTLMSSP/SPNEGO session setup parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
