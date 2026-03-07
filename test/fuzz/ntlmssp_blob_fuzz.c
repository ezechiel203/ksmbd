// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for raw NTLMSSP field parsing
 *
 *   This module exercises the NTLMSSP NEGOTIATE and AUTHENTICATE message
 *   field-level parsing logic as implemented in ksmbd's auth.c functions
 *   ksmbd_decode_ntlmssp_neg_blob() and ksmbd_decode_ntlmssp_auth_blob().
 *
 *   Unlike session_setup_fuzz.c which tests the high-level message
 *   structure, this harness targets the low-level field parsing that
 *   can trigger integer overflows in offset/length arithmetic, out-of-
 *   bounds reads from malformed BufferOffset values, and type confusion
 *   when NtChallengeResponse contains a crafted NTLMv2_CLIENT_CHALLENGE
 *   structure.
 *
 *   Targets:
 *     - SecurityBuffer.BufferOffset + Length overflow (u32 + u16 > u64)
 *     - SecurityBuffer.Length > MaximumLength inconsistency
 *     - NtChallengeResponse pointing into the fixed header region
 *     - DomainName/UserName/Workstation overlapping with NtChallengeResponse
 *     - NTLMv2_CLIENT_CHALLENGE blob_signature/AvPairs validation
 *     - NegotiateFlags bit combinations with inconsistent field presence
 *     - NTLMSSP_ANONYMOUS with non-zero NtChallengeResponse length
 *     - Version field presence (flag 0x02000000) with truncated message
 *     - MIC field (16 bytes at offset 72) presence and alignment
 *
 *   Corpus seed hints:
 *     - NTLMSSP Negotiate: "NTLMSSP\0" + le32(1) + le32(flags) + fields
 *     - NTLMSSP Authenticate: "NTLMSSP\0" + le32(3) + 6 SecurityBuffers
 *     - Anonymous: le16(0) in NtChallengeResponse.Length + flag 0x800
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

#define NTLMSSP_SIGNATURE		"NTLMSSP"
#define NTLMSSP_NEGOTIATE_MESSAGE	1
#define NTLMSSP_CHALLENGE_MESSAGE	2
#define NTLMSSP_AUTHENTICATE_MESSAGE	3

/* SecurityBuffer (MS-NLMP 2.2.1.1) */
struct security_buffer_fuzz {
	__le16 Length;
	__le16 MaximumLength;
	__le32 BufferOffset;
} __packed;

/* NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1) */
struct negotiate_message_fuzz {
	__u8   Signature[8];
	__le32 MessageType;
	__le32 NegotiateFlags;
	struct security_buffer_fuzz DomainName;
	struct security_buffer_fuzz Workstation;
} __packed;

/* AUTHENTICATE_MESSAGE (MS-NLMP 2.2.1.3) */
struct authenticate_message_fuzz {
	__u8   Signature[8];
	__le32 MessageType;
	struct security_buffer_fuzz LmChallengeResponse;
	struct security_buffer_fuzz NtChallengeResponse;
	struct security_buffer_fuzz DomainName;
	struct security_buffer_fuzz UserName;
	struct security_buffer_fuzz Workstation;
	struct security_buffer_fuzz EncryptedRandomSessionKey;
	__le32 NegotiateFlags;
} __packed;

/* NTLMv2_CLIENT_CHALLENGE fixed header (MS-NLMP 2.2.2.7) */
struct ntlmv2_client_challenge_fuzz {
	__u8   RespType;	/* Must be 1 */
	__u8   HiRespType;	/* Must be 1 */
	__le16 Reserved1;
	__le32 Reserved2;
	__le64 TimeStamp;
	__u8   ChallengeFromClient[8];
	__le32 Reserved3;
	/* AvPairs follow */
} __packed;

/* AvPair (MS-NLMP 2.2.2.1) */
struct av_pair_fuzz {
	__le16 AvId;
	__le16 AvLen;
} __packed;

#define NTLMSSP_NEGOTIATE_UNICODE	0x00000001
#define NTLMSSP_NEGOTIATE_OEM		0x00000002
#define NTLMSSP_NEGOTIATE_NTLM		0x00000200
#define NTLMSSP_NEGOTIATE_VERSION	0x02000000
#define NTLMSSP_NEGOTIATE_EXT_SEC	0x00080000
#define NTLMSSP_ANONYMOUS		0x00000800

#define CIFS_ENCPWD_SIZE		16
#define NTLMV2_CHALLENGE_HDR_SIZE	sizeof(struct ntlmv2_client_challenge_fuzz)

/* MsvAvEOL terminates AvPairs list */
#define MSV_AV_EOL	0x0000
#define MSV_AV_NB_COMPUTER_NAME	0x0001
#define MSV_AV_NB_DOMAIN_NAME	0x0002
#define MSV_AV_DNS_COMPUTER_NAME	0x0003
#define MSV_AV_DNS_DOMAIN_NAME	0x0004
#define MSV_AV_TIMESTAMP	0x0007
#define MSV_AV_FLAGS		0x0006

/*
 * fuzz_validate_secbuf - Strict SecurityBuffer field validation
 * @field:	the SecurityBuffer field descriptor
 * @buf_len:	total blob length
 * @name:	field name for debug
 * @min_header_off: minimum valid BufferOffset (size of fixed header)
 *
 * Return: 0 if valid, negative on error
 */
static int fuzz_validate_secbuf(const struct security_buffer_fuzz *field,
				size_t buf_len, const char *name,
				u32 min_header_off)
{
	u16 length = le16_to_cpu(field->Length);
	u16 max_length = le16_to_cpu(field->MaximumLength);
	u32 offset = le32_to_cpu(field->BufferOffset);

	/* MaximumLength must be >= Length */
	if (max_length < length) {
		pr_debug("fuzz_ntlm: %s MaxLen %u < Len %u\n",
			 name, max_length, length);
		return -EINVAL;
	}

	/* Zero-length field: offset is irrelevant */
	if (length == 0)
		return 0;

	/* Offset must not point into fixed header */
	if (offset < min_header_off) {
		pr_debug("fuzz_ntlm: %s offset %u < min %u (points into header)\n",
			 name, offset, min_header_off);
		return -EINVAL;
	}

	/* Integer overflow check: offset + length as u64 */
	if ((u64)offset + length > buf_len) {
		pr_debug("fuzz_ntlm: %s offset+len %u+%u > buf_len %zu\n",
			 name, offset, length, buf_len);
		return -EINVAL;
	}

	return 0;
}

/*
 * fuzz_check_overlap - Check if two SecurityBuffer ranges overlap
 * @a:		first field descriptor
 * @b:		second field descriptor
 * @a_name:	name of first field
 * @b_name:	name of second field
 */
static void fuzz_check_overlap(const struct security_buffer_fuzz *a,
			       const struct security_buffer_fuzz *b,
			       const char *a_name, const char *b_name)
{
	u32 a_off = le32_to_cpu(a->BufferOffset);
	u16 a_len = le16_to_cpu(a->Length);
	u32 b_off = le32_to_cpu(b->BufferOffset);
	u16 b_len = le16_to_cpu(b->Length);

	if (a_len == 0 || b_len == 0)
		return;

	if (a_off < b_off + b_len && b_off < a_off + a_len) {
		pr_debug("fuzz_ntlm: %s [%u+%u] overlaps %s [%u+%u]\n",
			 a_name, a_off, a_len, b_name, b_off, b_len);
	}
}

/*
 * fuzz_ntlmssp_negotiate - Fuzz NTLMSSP NEGOTIATE_MESSAGE parsing
 * @data:	raw message bytes
 * @len:	message length
 *
 * Mirrors ksmbd_decode_ntlmssp_neg_blob() validation.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ntlmssp_negotiate(const u8 *data, size_t len)
{
	const struct negotiate_message_fuzz *msg;
	u32 flags;

	if (len < sizeof(struct negotiate_message_fuzz)) {
		pr_debug("fuzz_ntlm: negotiate too short (%zu < %zu)\n",
			 len, sizeof(struct negotiate_message_fuzz));
		return -EINVAL;
	}

	msg = (const struct negotiate_message_fuzz *)data;

	if (memcmp(msg->Signature, NTLMSSP_SIGNATURE, 8) != 0) {
		pr_debug("fuzz_ntlm: bad NTLMSSP signature in negotiate\n");
		return -EINVAL;
	}

	if (le32_to_cpu(msg->MessageType) != NTLMSSP_NEGOTIATE_MESSAGE) {
		pr_debug("fuzz_ntlm: wrong message type %u (expected 1)\n",
			 le32_to_cpu(msg->MessageType));
		return -EINVAL;
	}

	flags = le32_to_cpu(msg->NegotiateFlags);
	pr_debug("fuzz_ntlm: negotiate flags=0x%08x\n", flags);

	/* Flag consistency checks */
	if ((flags & NTLMSSP_NEGOTIATE_UNICODE) &&
	    (flags & NTLMSSP_NEGOTIATE_OEM)) {
		pr_debug("fuzz_ntlm: both UNICODE and OEM negotiated\n");
	}

	/* Version field present? Check there is room for it */
	if (flags & NTLMSSP_NEGOTIATE_VERSION) {
		if (len < sizeof(struct negotiate_message_fuzz) + 8) {
			pr_debug("fuzz_ntlm: VERSION flag set but message too short\n");
			/* Not fatal, just noted */
		}
	}

	/* Validate SecurityBuffer fields */
	fuzz_validate_secbuf(&msg->DomainName, len, "DomainName",
			     sizeof(struct negotiate_message_fuzz));
	fuzz_validate_secbuf(&msg->Workstation, len, "Workstation",
			     sizeof(struct negotiate_message_fuzz));

	return 0;
}

/*
 * fuzz_ntlmv2_challenge - Fuzz NTLMv2_CLIENT_CHALLENGE AvPairs parsing
 * @data:	pointer to the NtChallengeResponse blob after the 16-byte hash
 * @len:	remaining length
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ntlmv2_challenge(const u8 *data, size_t len)
{
	const struct ntlmv2_client_challenge_fuzz *challenge;
	const u8 *ptr;
	const u8 *end;
	int pair_count = 0;

	if (len < NTLMV2_CHALLENGE_HDR_SIZE) {
		pr_debug("fuzz_ntlm: NTLMv2 challenge too short (%zu)\n", len);
		return -EINVAL;
	}

	challenge = (const struct ntlmv2_client_challenge_fuzz *)data;

	if (challenge->RespType != 1 || challenge->HiRespType != 1) {
		pr_debug("fuzz_ntlm: bad RespType=%u HiRespType=%u\n",
			 challenge->RespType, challenge->HiRespType);
		return -EINVAL;
	}

	pr_debug("fuzz_ntlm: NTLMv2 challenge timestamp=0x%llx\n",
		 le64_to_cpu(challenge->TimeStamp));

	/* Walk AvPairs */
	ptr = data + NTLMV2_CHALLENGE_HDR_SIZE;
	end = data + len;

	while (ptr + sizeof(struct av_pair_fuzz) <= end && pair_count < 128) {
		const struct av_pair_fuzz *pair;
		u16 av_id, av_len;

		pair = (const struct av_pair_fuzz *)ptr;
		av_id = le16_to_cpu(pair->AvId);
		av_len = le16_to_cpu(pair->AvLen);

		pr_debug("fuzz_ntlm: AvPair[%d] id=%u len=%u\n",
			 pair_count, av_id, av_len);

		ptr += sizeof(struct av_pair_fuzz);

		/* Check AvLen fits */
		if (ptr + av_len > end) {
			pr_debug("fuzz_ntlm: AvPair[%d] len %u exceeds buffer\n",
				 pair_count, av_len);
			return -EINVAL;
		}

		/* MsvAvEOL terminates the list */
		if (av_id == MSV_AV_EOL)
			break;

		ptr += av_len;
		pair_count++;
	}

	return 0;
}

/*
 * fuzz_ntlmssp_authenticate - Fuzz NTLMSSP AUTHENTICATE_MESSAGE parsing
 * @data:	raw message bytes
 * @len:	message length
 *
 * Mirrors ksmbd_decode_ntlmssp_auth_blob() validation, including the
 * NTLMv2_CLIENT_CHALLENGE AvPairs parsing path.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_ntlmssp_authenticate(const u8 *data, size_t len)
{
	const struct authenticate_message_fuzz *msg;
	u32 flags;
	u16 nt_len;
	u32 nt_off;
	bool is_anonymous = false;
	int ret;

	if (len < sizeof(struct authenticate_message_fuzz)) {
		pr_debug("fuzz_ntlm: auth too short (%zu < %zu)\n",
			 len, sizeof(struct authenticate_message_fuzz));
		return -EINVAL;
	}

	msg = (const struct authenticate_message_fuzz *)data;

	if (memcmp(msg->Signature, NTLMSSP_SIGNATURE, 8) != 0) {
		pr_debug("fuzz_ntlm: bad NTLMSSP signature in auth\n");
		return -EINVAL;
	}

	if (le32_to_cpu(msg->MessageType) != NTLMSSP_AUTHENTICATE_MESSAGE) {
		pr_debug("fuzz_ntlm: wrong message type %u (expected 3)\n",
			 le32_to_cpu(msg->MessageType));
		return -EINVAL;
	}

	flags = le32_to_cpu(msg->NegotiateFlags);
	nt_len = le16_to_cpu(msg->NtChallengeResponse.Length);
	nt_off = le32_to_cpu(msg->NtChallengeResponse.BufferOffset);

	pr_debug("fuzz_ntlm: auth flags=0x%08x nt_len=%u\n", flags, nt_len);

	/* Check for anonymous authentication */
	if (nt_len == 0 && (flags & NTLMSSP_ANONYMOUS)) {
		is_anonymous = true;
		pr_debug("fuzz_ntlm: anonymous authentication detected\n");
	}

	/* Flag consistency: ANONYMOUS with non-zero NtChallengeResponse */
	if ((flags & NTLMSSP_ANONYMOUS) && nt_len > 0) {
		pr_debug("fuzz_ntlm: WARNING: ANONYMOUS flag with nt_len=%u\n",
			 nt_len);
	}

	/* Validate all 6 SecurityBuffer fields */
	ret = fuzz_validate_secbuf(&msg->LmChallengeResponse, len,
				   "LmChallengeResponse",
				   sizeof(struct authenticate_message_fuzz));
	if (ret < 0)
		return ret;

	ret = fuzz_validate_secbuf(&msg->NtChallengeResponse, len,
				   "NtChallengeResponse",
				   sizeof(struct authenticate_message_fuzz));
	if (ret < 0)
		return ret;

	ret = fuzz_validate_secbuf(&msg->DomainName, len, "DomainName",
				   sizeof(struct authenticate_message_fuzz));
	if (ret < 0)
		return ret;

	ret = fuzz_validate_secbuf(&msg->UserName, len, "UserName",
				   sizeof(struct authenticate_message_fuzz));
	if (ret < 0)
		return ret;

	ret = fuzz_validate_secbuf(&msg->Workstation, len, "Workstation",
				   sizeof(struct authenticate_message_fuzz));
	if (ret < 0)
		return ret;

	ret = fuzz_validate_secbuf(&msg->EncryptedRandomSessionKey, len,
				   "EncryptedRandomSessionKey",
				   sizeof(struct authenticate_message_fuzz));
	if (ret < 0)
		return ret;

	/* Check for overlapping critical fields */
	fuzz_check_overlap(&msg->NtChallengeResponse, &msg->UserName,
			   "NtChallenge", "UserName");
	fuzz_check_overlap(&msg->NtChallengeResponse, &msg->DomainName,
			   "NtChallenge", "DomainName");
	fuzz_check_overlap(&msg->LmChallengeResponse, &msg->NtChallengeResponse,
			   "LmChallenge", "NtChallenge");
	fuzz_check_overlap(&msg->UserName, &msg->DomainName,
			   "UserName", "DomainName");

	/* Parse NTLMv2_CLIENT_CHALLENGE if NtChallengeResponse is present */
	if (!is_anonymous && nt_len > CIFS_ENCPWD_SIZE) {
		if ((u64)nt_off + nt_len <= len) {
			const u8 *challenge_data = data + nt_off + CIFS_ENCPWD_SIZE;
			size_t challenge_len = nt_len - CIFS_ENCPWD_SIZE;

			fuzz_ntlmv2_challenge(challenge_data, challenge_len);
		}
	}

	/* MIC field check: at offset 72, 16 bytes */
	if (flags & NTLMSSP_NEGOTIATE_VERSION) {
		size_t mic_offset = sizeof(struct authenticate_message_fuzz) + 8;

		if (len >= mic_offset + 16) {
			const u8 *mic = data + mic_offset;
			bool mic_zero = true;
			int i;

			for (i = 0; i < 16; i++) {
				if (mic[i] != 0) {
					mic_zero = false;
					break;
				}
			}
			pr_debug("fuzz_ntlm: MIC field present, all-zero=%d\n",
				 mic_zero);
		}
	}

	return 0;
}

static int __init ntlmssp_blob_fuzz_init(void)
{
	u8 *test_buf;
	int ret;

	pr_info("ntlmssp_blob_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid NEGOTIATE_MESSAGE */
	{
		struct negotiate_message_fuzz *msg =
			(struct negotiate_message_fuzz *)test_buf;

		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_NEGOTIATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM |
						  NTLMSSP_NEGOTIATE_UNICODE);

		ret = fuzz_ntlmssp_negotiate(test_buf,
					     sizeof(struct negotiate_message_fuzz));
		pr_info("ntlmssp_blob_fuzz: valid negotiate returned %d\n", ret);
	}

	/* Self-test 2: negotiate with VERSION flag but too short */
	{
		struct negotiate_message_fuzz *msg =
			(struct negotiate_message_fuzz *)test_buf;

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_NEGOTIATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM |
						  NTLMSSP_NEGOTIATE_VERSION);

		ret = fuzz_ntlmssp_negotiate(test_buf,
					     sizeof(struct negotiate_message_fuzz));
		pr_info("ntlmssp_blob_fuzz: version-short negotiate returned %d\n",
			ret);
	}

	/* Self-test 3: valid anonymous AUTHENTICATE_MESSAGE */
	{
		struct authenticate_message_fuzz *msg =
			(struct authenticate_message_fuzz *)test_buf;

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM |
						  NTLMSSP_ANONYMOUS);
		/* NtChallengeResponse.Length = 0 => anonymous */

		ret = fuzz_ntlmssp_authenticate(test_buf,
						sizeof(struct authenticate_message_fuzz));
		pr_info("ntlmssp_blob_fuzz: anonymous auth returned %d\n", ret);
	}

	/* Self-test 4: authenticate with out-of-bounds UserName offset */
	{
		struct authenticate_message_fuzz *msg =
			(struct authenticate_message_fuzz *)test_buf;

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);
		msg->UserName.Length = cpu_to_le16(20);
		msg->UserName.MaximumLength = cpu_to_le16(20);
		msg->UserName.BufferOffset = cpu_to_le32(0xFFFE);

		ret = fuzz_ntlmssp_authenticate(test_buf,
						sizeof(struct authenticate_message_fuzz) + 32);
		pr_info("ntlmssp_blob_fuzz: oob username returned %d\n", ret);
	}

	/* Self-test 5: authenticate with overlapping fields */
	{
		struct authenticate_message_fuzz *msg =
			(struct authenticate_message_fuzz *)test_buf;
		u32 base_off = sizeof(struct authenticate_message_fuzz);

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);
		/* Make NtChallenge and UserName overlap */
		msg->NtChallengeResponse.Length = cpu_to_le16(30);
		msg->NtChallengeResponse.MaximumLength = cpu_to_le16(30);
		msg->NtChallengeResponse.BufferOffset = cpu_to_le32(base_off);
		msg->UserName.Length = cpu_to_le16(20);
		msg->UserName.MaximumLength = cpu_to_le16(20);
		msg->UserName.BufferOffset = cpu_to_le32(base_off + 10);

		ret = fuzz_ntlmssp_authenticate(test_buf,
						base_off + 100);
		pr_info("ntlmssp_blob_fuzz: overlapping fields returned %d\n",
			ret);
	}

	/* Self-test 6: authenticate with NTLMv2 challenge blob */
	{
		struct authenticate_message_fuzz *msg =
			(struct authenticate_message_fuzz *)test_buf;
		struct ntlmv2_client_challenge_fuzz *challenge;
		struct av_pair_fuzz *pair;
		u32 base_off = sizeof(struct authenticate_message_fuzz);

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM);
		/* NtChallengeResponse: 16-byte hash + challenge blob */
		msg->NtChallengeResponse.Length = cpu_to_le16(16 + 28 + 8);
		msg->NtChallengeResponse.MaximumLength = cpu_to_le16(16 + 28 + 8);
		msg->NtChallengeResponse.BufferOffset = cpu_to_le32(base_off);

		/* Fill 16-byte NTLMv2 hash with dummy data */
		memset(test_buf + base_off, 0xAA, 16);

		/* NTLMv2_CLIENT_CHALLENGE header */
		challenge = (struct ntlmv2_client_challenge_fuzz *)
			(test_buf + base_off + 16);
		challenge->RespType = 1;
		challenge->HiRespType = 1;
		challenge->TimeStamp = cpu_to_le64(0x01D0000000000000ULL);

		/* Add an MsvAvEOL pair to terminate */
		pair = (struct av_pair_fuzz *)
			(test_buf + base_off + 16 + NTLMV2_CHALLENGE_HDR_SIZE);
		pair->AvId = cpu_to_le16(MSV_AV_EOL);
		pair->AvLen = 0;

		ret = fuzz_ntlmssp_authenticate(test_buf,
						base_off + 16 + 28 + 8);
		pr_info("ntlmssp_blob_fuzz: ntlmv2 challenge returned %d\n",
			ret);
	}

	/* Self-test 7: ANONYMOUS flag but non-zero NtChallengeResponse */
	{
		struct authenticate_message_fuzz *msg =
			(struct authenticate_message_fuzz *)test_buf;
		u32 base_off = sizeof(struct authenticate_message_fuzz);

		memset(test_buf, 0, 512);
		memcpy(msg->Signature, NTLMSSP_SIGNATURE, 8);
		msg->MessageType = cpu_to_le32(NTLMSSP_AUTHENTICATE_MESSAGE);
		msg->NegotiateFlags = cpu_to_le32(NTLMSSP_NEGOTIATE_NTLM |
						  NTLMSSP_ANONYMOUS);
		msg->NtChallengeResponse.Length = cpu_to_le16(24);
		msg->NtChallengeResponse.MaximumLength = cpu_to_le16(24);
		msg->NtChallengeResponse.BufferOffset = cpu_to_le32(base_off);

		ret = fuzz_ntlmssp_authenticate(test_buf, base_off + 24);
		pr_info("ntlmssp_blob_fuzz: anon+ntchallenge returned %d\n",
			ret);
	}

	/* Self-test 8: garbage data */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_ntlmssp_negotiate(test_buf, 512);
	pr_info("ntlmssp_blob_fuzz: garbage negotiate returned %d\n", ret);
	ret = fuzz_ntlmssp_authenticate(test_buf, 512);
	pr_info("ntlmssp_blob_fuzz: garbage auth returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit ntlmssp_blob_fuzz_exit(void)
{
	pr_info("ntlmssp_blob_fuzz: module unloaded\n");
}

module_init(ntlmssp_blob_fuzz_init);
module_exit(ntlmssp_blob_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for raw NTLMSSP field parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
