// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace libFuzzer target for NTLMSSP blob parsing.
 *
 * Exercises the pre-authentication NTLMSSP message parsing that ksmbd
 * performs during SESSION_SETUP (MS-NLMP):
 *   - NTLMSSP signature validation
 *   - NEGOTIATE_MESSAGE (type 1): flag extraction, domain/workstation fields
 *   - AUTHENTICATE_MESSAGE (type 3): all 6 payload fields with offset/length
 *     validation, anonymous detection, NtChallengeResponse extraction
 *   - SPNEGO NegTokenInit ASN.1 wrapper: tag/length parsing, OID extraction,
 *     embedded mechToken location
 *   - Overlapping field detection
 *
 * Build: clang -fsanitize=fuzzer,address,undefined -g -O1 \
 *        -I. fuzz_ntlmssp.c -o fuzz_ntlmssp
 */

#include "ksmbd_compat.h"

/* --- NTLMSSP constants and structures (match ntlmssp.h / auth.c) --- */

#define NTLMSSP_SIGNATURE		"NTLMSSP"
#define NTLMSSP_SIGNATURE_SIZE		8
#define NTLMSSP_NEGOTIATE_MESSAGE	1
#define NTLMSSP_CHALLENGE_MESSAGE	2
#define NTLMSSP_AUTHENTICATE_MESSAGE	3

/* Negotiate flags */
#define NTLMSSP_NEGOTIATE_UNICODE	0x00000001
#define NTLMSSP_NEGOTIATE_OEM		0x00000002
#define NTLMSSP_REQUEST_TARGET		0x00000004
#define NTLMSSP_NEGOTIATE_SIGN		0x00000010
#define NTLMSSP_NEGOTIATE_SEAL		0x00000020
#define NTLMSSP_NEGOTIATE_NTLM		0x00000200
#define NTLMSSP_NEGOTIATE_EXTENDED_SEC	0x00080000
#define NTLMSSP_NEGOTIATE_VERSION	0x02000000
#define NTLMSSP_NEGOTIATE_128		0x20000000
#define NTLMSSP_NEGOTIATE_KEY_XCH	0x40000000
#define NTLMSSP_NEGOTIATE_56		0x80000000
#define NTLMSSP_ANONYMOUS		0x00000800

/* NTLMSSP field descriptor */
struct ntlmssp_field {
	__le16 Len;
	__le16 MaxLen;
	__le32 BufferOffset;
} __packed;

/* NEGOTIATE_MESSAGE (type 1) */
struct ntlmssp_negotiate {
	__u8   Signature[8];
	__le32 MessageType;
	__le32 NegotiateFlags;
	struct ntlmssp_field DomainName;
	struct ntlmssp_field Workstation;
} __packed;

/* AUTHENTICATE_MESSAGE (type 3) */
struct ntlmssp_authenticate {
	__u8   Signature[8];
	__le32 MessageType;
	struct ntlmssp_field LmChallengeResponse;
	struct ntlmssp_field NtChallengeResponse;
	struct ntlmssp_field DomainName;
	struct ntlmssp_field UserName;
	struct ntlmssp_field Workstation;
	struct ntlmssp_field EncryptedRandomSessionKey;
	__le32 NegotiateFlags;
} __packed;

/* NTLMv2 client challenge (inside NtChallengeResponse) */
struct ntlmv2_client_challenge {
	__u8   RespType;         /* 1 */
	__u8   HiRespType;       /* 1 */
	__le16 Reserved1;
	__le32 Reserved2;
	__le64 TimeStamp;
	__u8   ChallengeFromClient[8];
	__le32 Reserved3;
	/* followed by AvPairs */
} __packed;

/* --- Validation helpers --- */

static int validate_field(const struct ntlmssp_field *field,
			  size_t buf_len, const u8 *buf_start)
{
	u16 field_len = le16_to_cpu(field->Len);
	u16 max_len = le16_to_cpu(field->MaxLen);
	u32 offset = le32_to_cpu(field->BufferOffset);

	if (max_len < field_len)
		return -EINVAL;

	if (field_len == 0)
		return 0;

	if (offset >= buf_len)
		return -EINVAL;

	if ((u64)offset + field_len > buf_len)
		return -EINVAL;

	/* Touch the field data to trigger ASAN on OOB */
	volatile u8 first = buf_start[offset];
	volatile u8 last = buf_start[offset + field_len - 1];
	(void)first;
	(void)last;

	return 0;
}

static int check_fields_overlap(const struct ntlmssp_field *a,
				const struct ntlmssp_field *b)
{
	u32 a_off = le32_to_cpu(a->BufferOffset);
	u16 a_len = le16_to_cpu(a->Len);
	u32 b_off = le32_to_cpu(b->BufferOffset);
	u16 b_len = le16_to_cpu(b->Len);

	if (a_len == 0 || b_len == 0)
		return 0;

	if (a_off < b_off + b_len && b_off < a_off + a_len)
		return 1; /* overlap detected */

	return 0;
}

/* --- NTLMSSP NEGOTIATE parsing --- */

static void parse_negotiate(const u8 *data, size_t len)
{
	const struct ntlmssp_negotiate *msg;
	u32 flags;

	if (len < sizeof(struct ntlmssp_negotiate))
		return;

	msg = (const struct ntlmssp_negotiate *)data;

	if (memcmp(msg->Signature, NTLMSSP_SIGNATURE, 8) != 0)
		return;

	if (le32_to_cpu(msg->MessageType) != NTLMSSP_NEGOTIATE_MESSAGE)
		return;

	flags = le32_to_cpu(msg->NegotiateFlags);

	/* Validate fields */
	validate_field(&msg->DomainName, len, data);
	validate_field(&msg->Workstation, len, data);

	/* If VERSION flag is set, check we have space for Version (8 bytes) */
	if (flags & NTLMSSP_NEGOTIATE_VERSION) {
		if (len >= sizeof(struct ntlmssp_negotiate) + 8) {
			const u8 *ver = data + sizeof(struct ntlmssp_negotiate);
			volatile u8 major = ver[0];
			volatile u8 minor = ver[1];
			(void)major;
			(void)minor;
		}
	}
}

/* --- NTLMSSP AUTHENTICATE parsing --- */

static void parse_authenticate(const u8 *data, size_t len)
{
	const struct ntlmssp_authenticate *msg;
	u32 flags;
	bool is_anonymous;

	if (len < sizeof(struct ntlmssp_authenticate))
		return;

	msg = (const struct ntlmssp_authenticate *)data;

	if (memcmp(msg->Signature, NTLMSSP_SIGNATURE, 8) != 0)
		return;

	if (le32_to_cpu(msg->MessageType) != NTLMSSP_AUTHENTICATE_MESSAGE)
		return;

	flags = le32_to_cpu(msg->NegotiateFlags);

	/* Check for anonymous authentication */
	is_anonymous = (le16_to_cpu(msg->NtChallengeResponse.Len) == 0);
	(void)is_anonymous;

	/* Validate all 6 payload fields */
	if (validate_field(&msg->LmChallengeResponse, len, data) < 0)
		return;
	if (validate_field(&msg->NtChallengeResponse, len, data) < 0)
		return;
	if (validate_field(&msg->DomainName, len, data) < 0)
		return;
	if (validate_field(&msg->UserName, len, data) < 0)
		return;
	if (validate_field(&msg->Workstation, len, data) < 0)
		return;
	if (validate_field(&msg->EncryptedRandomSessionKey, len, data) < 0)
		return;

	/* Check for overlapping fields */
	check_fields_overlap(&msg->NtChallengeResponse,
			     &msg->LmChallengeResponse);
	check_fields_overlap(&msg->UserName, &msg->DomainName);

	/* Extract NtChallengeResponse if present and long enough */
	{
		u16 nt_len = le16_to_cpu(msg->NtChallengeResponse.Len);
		u32 nt_off = le32_to_cpu(msg->NtChallengeResponse.BufferOffset);

		if (nt_len > 24 && nt_off + nt_len <= len) {
			/*
			 * NTLMv2: first 16 bytes are NtProofStr,
			 * remainder is the client challenge structure.
			 */
			const u8 *nt_data = data + nt_off;
			size_t challenge_off = 16;
			size_t challenge_len = nt_len - 16;

			if (challenge_len >= sizeof(struct ntlmv2_client_challenge)) {
				const struct ntlmv2_client_challenge *cc =
					(const struct ntlmv2_client_challenge *)
					(nt_data + challenge_off);

				volatile u8 resp_type = cc->RespType;
				volatile u64 ts = le64_to_cpu(cc->TimeStamp);
				(void)resp_type;
				(void)ts;

				/*
				 * Walk AvPairs after the fixed fields.
				 * Each AvPair: AvId(2) + AvLen(2) + Value(AvLen).
				 * AvId==0x0000 (MsvAvEOL) terminates.
				 */
				const u8 *av = nt_data + challenge_off +
					sizeof(struct ntlmv2_client_challenge);
				const u8 *av_end = nt_data + nt_len;

				while (av + 4 <= av_end) {
					u16 av_id = le16_to_cpu(*(const __le16 *)av);
					u16 av_len = le16_to_cpu(*(const __le16 *)(av + 2));

					if (av_id == 0)
						break;

					av += 4;
					if (av + av_len > av_end)
						break;
					av += av_len;
				}
			}
		}
	}

	/* Extract UserName string if UNICODE */
	{
		u16 user_len = le16_to_cpu(msg->UserName.Len);
		u32 user_off = le32_to_cpu(msg->UserName.BufferOffset);

		if (user_len > 0 && user_off + user_len <= len) {
			if (flags & NTLMSSP_NEGOTIATE_UNICODE) {
				/* UTF-16LE: length should be even */
				if (user_len & 1) {
					/* Odd-length Unicode - suspicious */
				}
			}
		}
	}
}

/* --- SPNEGO NegTokenInit wrapper parsing --- */

static void parse_spnego_wrapper(const u8 *data, size_t len)
{
	size_t pos = 0;
	u8 tag;
	size_t asn_len;

	if (len < 2)
		return;

	tag = data[pos++];

	/* Expect Application[0] = 0x60 or context[0] = 0xA0 */
	if (tag != 0x60 && tag != 0xA0 && tag != 0xA1)
		return;

	/* Parse ASN.1 length */
	if (data[pos] & 0x80) {
		int num_octets = data[pos] & 0x7F;

		pos++;
		if (num_octets > 4 || pos + (size_t)num_octets > len)
			return;

		asn_len = 0;
		while (num_octets-- > 0)
			asn_len = (asn_len << 8) | data[pos++];
	} else {
		asn_len = data[pos++];
	}

	if (pos + asn_len > len)
		return;

	/* Look for OID tag */
	if (pos < len && data[pos] == 0x06) {
		u8 oid_len;

		pos++;
		if (pos >= len)
			return;
		oid_len = data[pos++];
		if (pos + oid_len > len)
			return;

		/* Read OID bytes */
		for (u8 i = 0; i < oid_len && pos + i < len; i++) {
			volatile u8 b = data[pos + i];
			(void)b;
		}
		pos += oid_len;
	}

	/* Scan for embedded NTLMSSP signature */
	while (pos + NTLMSSP_SIGNATURE_SIZE <= len) {
		if (memcmp(data + pos, NTLMSSP_SIGNATURE,
			   NTLMSSP_SIGNATURE_SIZE) == 0) {
			/* Found NTLMSSP - determine message type and recurse */
			if (pos + 12 <= len) {
				u32 msg_type = le32_to_cpu(
					*(const __le32 *)(data + pos + 8));

				if (msg_type == NTLMSSP_NEGOTIATE_MESSAGE)
					parse_negotiate(data + pos, len - pos);
				else if (msg_type == NTLMSSP_AUTHENTICATE_MESSAGE)
					parse_authenticate(data + pos,
							   len - pos);
			}
			break;
		}
		pos++;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return 0;

	/* Cap to prevent excessive processing */
	if (size > 65536)
		size = 65536;

	/*
	 * Use the first byte to select the parsing mode:
	 * 0: NEGOTIATE_MESSAGE
	 * 1: AUTHENTICATE_MESSAGE
	 * 2: SPNEGO wrapper (auto-detects embedded NTLMSSP)
	 * 3+: Raw - try all parsers
	 */
	u8 mode = data[0] % 4;
	const u8 *payload = data + 1;
	size_t payload_len = size - 1;

	switch (mode) {
	case 0:
		parse_negotiate(payload, payload_len);
		break;
	case 1:
		parse_authenticate(payload, payload_len);
		break;
	case 2:
		parse_spnego_wrapper(payload, payload_len);
		break;
	default:
		parse_negotiate(payload, payload_len);
		parse_authenticate(payload, payload_len);
		parse_spnego_wrapper(payload, payload_len);
		break;
	}

	return 0;
}
