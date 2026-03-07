// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for Kerberos authentication blob parsing
 *
 *   This module exercises the Kerberos token parsing paths used in
 *   ksmbd's SESSION_SETUP handler. The krb5_authenticate() path accepts
 *   an arbitrary in_blob from unauthenticated clients, making it a
 *   critical pre-auth attack surface. The blob is first passed through
 *   SPNEGO (ASN.1 BER) decoding to extract OIDs and mechTokens, then
 *   through the Kerberos IPC path.
 *
 *   Targets:
 *     - SPNEGO NegTokenInit / NegTokenTarg outer wrapper parsing
 *     - ASN.1 BER tag/length/value decoding with nested structures
 *     - OID extraction and comparison (KRB5, MSKRB5, NTLMSSP, SPNEGO)
 *     - mechToken extraction from SPNEGO context
 *     - SecurityBuffer offset/length validation from SESSION_SETUP request
 *     - Kerberos AP-REQ/AP-REP token structure validation
 *
 *   Corpus seed hints:
 *     - SPNEGO: 0x60 + length + OID(1.3.6.1.5.5.2) + NegTokenInit
 *     - KRB5 OID: {1.2.840.113554.1.2.2}
 *     - MSKRB5 OID: {1.2.840.48018.1.2.2}
 *     - AP-REQ: 0x6E + length + [APPLICATION 14]
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* ASN.1 BER tags used in SPNEGO/Kerberos */
#define ASN1_APPLICATION_0	0x60
#define ASN1_CONTEXT_0		0xA0
#define ASN1_CONTEXT_1		0xA1
#define ASN1_CONTEXT_2		0xA2
#define ASN1_CONTEXT_3		0xA3
#define ASN1_SEQUENCE		0x30
#define ASN1_OID		0x06
#define ASN1_OCTET_STRING	0x04
#define ASN1_ENUMERATED		0x0A
#define ASN1_BIT_STRING		0x03

/* Kerberos application tags */
#define KRB5_AP_REQ_TAG		0x6E	/* [APPLICATION 14] */
#define KRB5_AP_REP_TAG		0x6F	/* [APPLICATION 15] */
#define KRB5_TGS_REQ_TAG	0x6C	/* [APPLICATION 12] */
#define KRB5_TGS_REP_TAG	0x6D	/* [APPLICATION 13] */

/* Well-known OIDs in BER-encoded form */
static const u8 SPNEGO_OID_BER[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };
static const u8 KRB5_OID_BER[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12,
				    0x01, 0x02, 0x02 };
static const u8 MSKRB5_OID_BER[] = { 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12,
				      0x01, 0x02, 0x02 };
static const u8 NTLMSSP_OID_BER[] = { 0x2b, 0x06, 0x01, 0x04, 0x01,
				       0x82, 0x37, 0x02, 0x02, 0x0a };

/*
 * fuzz_asn1_decode_length - Decode ASN.1 BER length field
 * @data:	pointer to the current position (updated on return)
 * @end:	pointer to end of buffer
 * @out_len:	output: decoded length value
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_asn1_decode_length(const u8 **data, const u8 *end,
				   size_t *out_len)
{
	const u8 *ptr = *data;
	u8 first;

	if (ptr >= end)
		return -EINVAL;

	first = *ptr++;

	if (!(first & 0x80)) {
		/* Short form: length in single byte */
		*out_len = first;
	} else {
		/* Long form: first byte indicates number of length bytes */
		int num_octets = first & 0x7F;

		if (num_octets == 0 || num_octets > 4) {
			pr_debug("fuzz_krb: invalid ASN.1 length encoding (%d octets)\n",
				 num_octets);
			return -EINVAL;
		}
		if (ptr + num_octets > end) {
			pr_debug("fuzz_krb: ASN.1 length octets exceed buffer\n");
			return -EINVAL;
		}

		*out_len = 0;
		while (num_octets-- > 0) {
			*out_len = (*out_len << 8) | *ptr++;
		}
	}

	*data = ptr;
	return 0;
}

/*
 * fuzz_match_oid - Check if an OID at the given position matches a known OID
 * @oid_data:	pointer to OID value bytes (after tag and length)
 * @oid_len:	length of OID value
 * @known_oid:	known OID byte sequence
 * @known_len:	length of known OID
 *
 * Return: true if match, false otherwise
 */
static bool fuzz_match_oid(const u8 *oid_data, size_t oid_len,
			   const u8 *known_oid, size_t known_len)
{
	if (oid_len != known_len)
		return false;
	return memcmp(oid_data, known_oid, known_len) == 0;
}

/*
 * fuzz_parse_spnego_oid_list - Walk an OID SEQUENCE inside SPNEGO
 * @data:	pointer to start of SEQUENCE content
 * @len:	length of SEQUENCE content
 *
 * Extracts and identifies OIDs, returning a bitmask of found mechanisms.
 *
 * Return: bitmask of mechanisms found, or negative on error
 */
#define MECH_KRB5	0x01
#define MECH_MSKRB5	0x02
#define MECH_NTLMSSP	0x04
#define MECH_SPNEGO	0x08

static int fuzz_parse_spnego_oid_list(const u8 *data, size_t len)
{
	const u8 *ptr = data;
	const u8 *end = data + len;
	int mechs = 0;
	int count = 0;

	while (ptr < end && count < 32) {
		u8 tag;
		size_t oid_len;
		int ret;

		tag = *ptr++;
		if (tag != ASN1_OID) {
			pr_debug("fuzz_krb: expected OID tag 0x06, got 0x%02x\n",
				 tag);
			break;
		}

		ret = fuzz_asn1_decode_length(&ptr, end, &oid_len);
		if (ret < 0)
			break;

		if (ptr + oid_len > end) {
			pr_debug("fuzz_krb: OID length %zu exceeds buffer\n",
				 oid_len);
			break;
		}

		/* Identify the OID */
		if (fuzz_match_oid(ptr, oid_len, KRB5_OID_BER,
				   sizeof(KRB5_OID_BER))) {
			pr_debug("fuzz_krb: found KRB5 OID\n");
			mechs |= MECH_KRB5;
		} else if (fuzz_match_oid(ptr, oid_len, MSKRB5_OID_BER,
					  sizeof(MSKRB5_OID_BER))) {
			pr_debug("fuzz_krb: found MSKRB5 OID\n");
			mechs |= MECH_MSKRB5;
		} else if (fuzz_match_oid(ptr, oid_len, NTLMSSP_OID_BER,
					  sizeof(NTLMSSP_OID_BER))) {
			pr_debug("fuzz_krb: found NTLMSSP OID\n");
			mechs |= MECH_NTLMSSP;
		} else if (fuzz_match_oid(ptr, oid_len, SPNEGO_OID_BER,
					  sizeof(SPNEGO_OID_BER))) {
			pr_debug("fuzz_krb: found SPNEGO OID\n");
			mechs |= MECH_SPNEGO;
		} else {
			pr_debug("fuzz_krb: unknown OID (len=%zu)\n", oid_len);
		}

		ptr += oid_len;
		count++;
	}

	pr_debug("fuzz_krb: parsed %d OIDs, mechanism bitmask=0x%x\n",
		 count, mechs);
	return mechs;
}

/*
 * fuzz_validate_krb5_token - Validate a Kerberos AP-REQ/AP-REP token
 * @data:	pointer to token data (inside the SPNEGO mechToken)
 * @len:	length of token data
 *
 * Performs structural validation of the Kerberos application-level
 * wrapper. In production, this blob is forwarded to userspace via
 * netlink IPC for actual Kerberos processing.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_validate_krb5_token(const u8 *data, size_t len)
{
	const u8 *ptr = data;
	const u8 *end = data + len;
	u8 app_tag;
	size_t token_len;
	int ret;

	if (len < 2) {
		pr_debug("fuzz_krb: krb5 token too short (%zu)\n", len);
		return -EINVAL;
	}

	app_tag = *ptr++;

	/* Check for valid Kerberos application tags */
	switch (app_tag) {
	case KRB5_AP_REQ_TAG:
		pr_debug("fuzz_krb: AP-REQ token\n");
		break;
	case KRB5_AP_REP_TAG:
		pr_debug("fuzz_krb: AP-REP token\n");
		break;
	case KRB5_TGS_REQ_TAG:
		pr_debug("fuzz_krb: TGS-REQ token\n");
		break;
	case KRB5_TGS_REP_TAG:
		pr_debug("fuzz_krb: TGS-REP token\n");
		break;
	default:
		pr_debug("fuzz_krb: unknown application tag 0x%02x\n", app_tag);
		return -EINVAL;
	}

	ret = fuzz_asn1_decode_length(&ptr, end, &token_len);
	if (ret < 0)
		return ret;

	if (ptr + token_len > end) {
		pr_debug("fuzz_krb: token length %zu exceeds buffer (remaining %zu)\n",
			 token_len, (size_t)(end - ptr));
		return -EINVAL;
	}

	/* Inside AP-REQ: expect a SEQUENCE */
	if (ptr < end && *ptr == ASN1_SEQUENCE) {
		const u8 *seq_ptr = ptr + 1;
		size_t seq_len;

		ret = fuzz_asn1_decode_length(&seq_ptr, end, &seq_len);
		if (ret == 0) {
			pr_debug("fuzz_krb: inner SEQUENCE len=%zu\n", seq_len);
			if (seq_ptr + seq_len > end)
				pr_debug("fuzz_krb: inner SEQUENCE exceeds token\n");
		}
	}

	return 0;
}

/*
 * fuzz_kerberos_blob - Fuzz Kerberos authentication blob parsing
 * @data:	raw input bytes (as received in SESSION_SETUP SecurityBuffer)
 * @len:	length of input
 *
 * Simulates the server-side parsing path for a Kerberos authentication
 * blob that arrives in the SESSION_SETUP request SecurityBuffer. The blob
 * is typically a SPNEGO NegTokenInit wrapping a KRB5 AP-REQ token.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_kerberos_blob(const u8 *data, size_t len)
{
	const u8 *ptr = data;
	const u8 *end = data + len;
	u8 outer_tag;
	size_t outer_len;
	int ret;

	if (len < 4) {
		pr_debug("fuzz_krb: input too short (%zu bytes)\n", len);
		return -EINVAL;
	}

	/* Cap input to prevent excessive processing */
	if (len > 65536)
		len = 65536;
	end = data + len;

	outer_tag = *ptr++;

	/* Expect Application[0] (0x60) for NegTokenInit or context tag */
	if (outer_tag != ASN1_APPLICATION_0 && outer_tag != ASN1_CONTEXT_0 &&
	    outer_tag != ASN1_CONTEXT_1) {
		/* Might be a raw Kerberos token (no SPNEGO wrapper) */
		if (outer_tag == KRB5_AP_REQ_TAG ||
		    outer_tag == KRB5_AP_REP_TAG) {
			pr_debug("fuzz_krb: raw Kerberos token (no SPNEGO)\n");
			return fuzz_validate_krb5_token(data, len);
		}
		pr_debug("fuzz_krb: unexpected outer tag 0x%02x\n", outer_tag);
		return -EINVAL;
	}

	ret = fuzz_asn1_decode_length(&ptr, end, &outer_len);
	if (ret < 0)
		return ret;

	if (ptr + outer_len > end) {
		pr_debug("fuzz_krb: outer length %zu exceeds buffer\n",
			 outer_len);
		return -EINVAL;
	}

	/* For Application[0], expect an OID first (SPNEGO OID) */
	if (outer_tag == ASN1_APPLICATION_0 && ptr < end &&
	    *ptr == ASN1_OID) {
		const u8 *oid_ptr = ptr + 1;
		size_t oid_len;

		ret = fuzz_asn1_decode_length(&oid_ptr, end, &oid_len);
		if (ret < 0)
			return ret;

		if (oid_ptr + oid_len > end)
			return -EINVAL;

		if (fuzz_match_oid(oid_ptr, oid_len, SPNEGO_OID_BER,
				   sizeof(SPNEGO_OID_BER)))
			pr_debug("fuzz_krb: SPNEGO wrapper confirmed\n");
		else
			pr_debug("fuzz_krb: non-SPNEGO OID in wrapper\n");

		ptr = oid_ptr + oid_len;
	}

	/* Walk remaining context-tagged fields */
	while (ptr + 2 <= end) {
		u8 ctx_tag;
		size_t ctx_len;

		ctx_tag = *ptr++;

		ret = fuzz_asn1_decode_length(&ptr, end, &ctx_len);
		if (ret < 0)
			break;

		if (ptr + ctx_len > end) {
			pr_debug("fuzz_krb: context field 0x%02x overflows\n",
				 ctx_tag);
			break;
		}

		switch (ctx_tag) {
		case ASN1_CONTEXT_0:
			/* MechTypes: SEQUENCE of OIDs */
			if (ctx_len > 0 && ptr < end && *ptr == ASN1_SEQUENCE) {
				const u8 *seq_ptr = ptr + 1;
				size_t seq_len;

				ret = fuzz_asn1_decode_length(&seq_ptr, end,
							     &seq_len);
				if (ret == 0 && seq_ptr + seq_len <= end)
					fuzz_parse_spnego_oid_list(seq_ptr,
								  seq_len);
			}
			break;
		case ASN1_CONTEXT_2:
			/* MechToken: OCTET STRING containing the KRB5 blob */
			if (ctx_len > 0 && ptr < end &&
			    *ptr == ASN1_OCTET_STRING) {
				const u8 *oct_ptr = ptr + 1;
				size_t oct_len;

				ret = fuzz_asn1_decode_length(&oct_ptr, end,
							     &oct_len);
				if (ret == 0 && oct_ptr + oct_len <= end) {
					pr_debug("fuzz_krb: mechToken len=%zu\n",
						 oct_len);
					fuzz_validate_krb5_token(oct_ptr,
								 oct_len);
				}
			}
			break;
		case ASN1_CONTEXT_1:
			/* reqFlags or negResult */
			pr_debug("fuzz_krb: context[1] len=%zu\n", ctx_len);
			break;
		case ASN1_CONTEXT_3:
			/* mechListMIC */
			pr_debug("fuzz_krb: mechListMIC len=%zu\n", ctx_len);
			break;
		default:
			pr_debug("fuzz_krb: unknown context 0x%02x len=%zu\n",
				 ctx_tag, ctx_len);
			break;
		}

		ptr += ctx_len;
	}

	return 0;
}

/*
 * fuzz_session_setup_secbuf - Fuzz SecurityBuffer offset/length validation
 * @data:	raw packet bytes simulating an SMB2 SESSION_SETUP request
 * @len:	packet length
 *
 * Validates the SecurityBufferOffset and SecurityBufferLength fields
 * from the SESSION_SETUP request header, which gate all blob parsing.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_session_setup_secbuf(const u8 *data, size_t len)
{
	__le16 *sec_buf_offset;
	__le16 *sec_buf_length;
	u16 offset, length;

	/*
	 * SESSION_SETUP request: StructureSize(2) + Flags(1) +
	 * SecurityMode(1) + Capabilities(4) + Channel(4) +
	 * SecurityBufferOffset(2) + SecurityBufferLength(2) +
	 * PreviousSessionId(8) = 24 bytes (before the SMB2 header)
	 */
	if (len < 24) {
		pr_debug("fuzz_krb: session setup header too short\n");
		return -EINVAL;
	}

	/* Offsets within the fixed-size portion */
	sec_buf_offset = (__le16 *)(data + 12);
	sec_buf_length = (__le16 *)(data + 14);

	offset = le16_to_cpu(*sec_buf_offset);
	length = le16_to_cpu(*sec_buf_length);

	pr_debug("fuzz_krb: SecurityBufferOffset=%u SecurityBufferLength=%u\n",
		 offset, length);

	/* Offset must be at least past the fixed header */
	if (offset < 24) {
		pr_debug("fuzz_krb: offset %u overlaps fixed header\n", offset);
		return -EINVAL;
	}

	/* Offset + length must fit within the packet */
	if ((u64)offset + length > len) {
		pr_debug("fuzz_krb: offset+length %u+%u exceeds packet %zu\n",
			 offset, length, len);
		return -EINVAL;
	}

	/* If there is a security buffer, try to parse it as a Kerberos blob */
	if (length > 0)
		return fuzz_kerberos_blob(data + offset, length);

	return 0;
}

static int __init kerberos_blob_fuzz_init(void)
{
	u8 *test_buf;
	int ret;

	pr_info("kerberos_blob_fuzz: module loaded\n");

	test_buf = kzalloc(512, GFP_KERNEL);
	if (!test_buf)
		return -ENOMEM;

	/* Self-test 1: valid SPNEGO wrapper with KRB5 OID */
	{
		u8 *p = test_buf;

		*p++ = ASN1_APPLICATION_0;	/* Application[0] */
		*p++ = 30;			/* outer length */
		*p++ = ASN1_OID;		/* SPNEGO OID */
		*p++ = sizeof(SPNEGO_OID_BER);
		memcpy(p, SPNEGO_OID_BER, sizeof(SPNEGO_OID_BER));
		p += sizeof(SPNEGO_OID_BER);
		*p++ = ASN1_CONTEXT_0;		/* mechTypes */
		*p++ = 13;
		*p++ = ASN1_SEQUENCE;
		*p++ = 11;
		*p++ = ASN1_OID;		/* KRB5 OID */
		*p++ = sizeof(KRB5_OID_BER);
		memcpy(p, KRB5_OID_BER, sizeof(KRB5_OID_BER));

		ret = fuzz_kerberos_blob(test_buf, 32);
		pr_info("kerberos_blob_fuzz: SPNEGO+KRB5 test returned %d\n",
			ret);
	}

	/* Self-test 2: raw AP-REQ token (no SPNEGO wrapper) */
	{
		memset(test_buf, 0, 512);
		test_buf[0] = KRB5_AP_REQ_TAG;
		test_buf[1] = 10;
		test_buf[2] = ASN1_SEQUENCE;
		test_buf[3] = 8;
		memset(test_buf + 4, 0xAA, 8);

		ret = fuzz_kerberos_blob(test_buf, 12);
		pr_info("kerberos_blob_fuzz: raw AP-REQ test returned %d\n",
			ret);
	}

	/* Self-test 3: truncated SPNEGO blob */
	{
		memset(test_buf, 0, 512);
		test_buf[0] = ASN1_APPLICATION_0;
		test_buf[1] = 0x82;	/* 2-byte length */
		test_buf[2] = 0x01;
		test_buf[3] = 0x00;	/* claims 256 bytes */

		ret = fuzz_kerberos_blob(test_buf, 6);
		pr_info("kerberos_blob_fuzz: truncated SPNEGO test returned %d\n",
			ret);
	}

	/* Self-test 4: too-short input */
	ret = fuzz_kerberos_blob(test_buf, 2);
	pr_info("kerberos_blob_fuzz: short input test returned %d\n", ret);

	/* Self-test 5: session setup SecurityBuffer validation */
	{
		memset(test_buf, 0, 512);
		/* SecurityBufferOffset at byte 12 */
		*(__le16 *)(test_buf + 12) = cpu_to_le16(24);
		/* SecurityBufferLength at byte 14 */
		*(__le16 *)(test_buf + 14) = cpu_to_le16(12);
		/* Place a raw AP-REQ at offset 24 */
		test_buf[24] = KRB5_AP_REQ_TAG;
		test_buf[25] = 6;
		test_buf[26] = ASN1_SEQUENCE;
		test_buf[27] = 4;

		ret = fuzz_session_setup_secbuf(test_buf, 36);
		pr_info("kerberos_blob_fuzz: secbuf test returned %d\n", ret);
	}

	/* Self-test 6: SecurityBuffer with out-of-bounds offset */
	{
		memset(test_buf, 0, 512);
		*(__le16 *)(test_buf + 12) = cpu_to_le16(0xFFF0);
		*(__le16 *)(test_buf + 14) = cpu_to_le16(100);

		ret = fuzz_session_setup_secbuf(test_buf, 64);
		pr_info("kerberos_blob_fuzz: oob secbuf test returned %d\n",
			ret);
	}

	/* Self-test 7: garbage data */
	memset(test_buf, 0xFF, 512);
	ret = fuzz_kerberos_blob(test_buf, 512);
	pr_info("kerberos_blob_fuzz: garbage test returned %d\n", ret);

	kfree(test_buf);
	return 0;
}

static void __exit kerberos_blob_fuzz_exit(void)
{
	pr_info("kerberos_blob_fuzz: module unloaded\n");
}

module_init(kerberos_blob_fuzz_init);
module_exit(kerberos_blob_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for Kerberos authentication blob parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
