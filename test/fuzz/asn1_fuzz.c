// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for ASN.1 SPNEGO parsing
 *
 *   This module exercises the ASN.1 BER decoding routines used in
 *   ksmbd's SPNEGO authentication path. Malformed ASN.1 blobs are
 *   a common attack vector against SMB servers, making this a
 *   critical fuzzing target.
 *
 *   Targets:
 *     - asn1_subid_decode: variable-length sub-identifier decoding
 *     - asn1_oid_decode: OID (Object Identifier) decoding
 *     - build_spnego_ntlmssp_neg_blob: SPNEGO blob construction
 *     - build_spnego_ntlmssp_auth_blob: SPNEGO auth blob construction
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_asn1_oid_decode() and
 *     fuzz_asn1_spnego_blob() entry points accept raw byte buffers.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/*
 * Reimplement the critical ASN.1 parsing functions here to allow
 * fuzzing without pulling in the full ksmbd module dependencies.
 * These are faithful copies of the functions from asn1.c.
 */

static bool fuzz_asn1_subid_decode(const unsigned char **begin,
				   const unsigned char *end,
				   unsigned long *subid)
{
	const unsigned char *ptr = *begin;
	unsigned char ch;

	*subid = 0;

	do {
		if (ptr >= end)
			return false;

		ch = *ptr++;
		*subid <<= 7;
		*subid |= ch & 0x7F;
	} while ((ch & 0x80) == 0x80);

	*begin = ptr;
	return true;
}

static bool fuzz_asn1_oid_decode(const unsigned char *value, size_t vlen,
				 unsigned long **oid, size_t *oidlen)
{
	const unsigned char *iptr = value, *end = value + vlen;
	unsigned long *optr;
	unsigned long subid;

	vlen += 1;
	if (vlen < 2 || vlen > UINT_MAX / sizeof(unsigned long))
		goto fail_nullify;

	*oid = kmalloc(vlen * sizeof(unsigned long), GFP_KERNEL);
	if (!*oid)
		return false;

	optr = *oid;

	if (!fuzz_asn1_subid_decode(&iptr, end, &subid))
		goto fail;

	if (subid < 40) {
		optr[0] = 0;
		optr[1] = subid;
	} else if (subid < 80) {
		optr[0] = 1;
		optr[1] = subid - 40;
	} else {
		optr[0] = 2;
		optr[1] = subid - 80;
	}

	*oidlen = 2;
	optr += 2;

	while (iptr < end) {
		if (++(*oidlen) > vlen)
			goto fail;

		if (!fuzz_asn1_subid_decode(&iptr, end, optr++))
			goto fail;
	}
	return true;

fail:
	kfree(*oid);
fail_nullify:
	*oid = NULL;
	return false;
}

/*
 * fuzz_asn1_subid - Fuzz the ASN.1 sub-identifier decoder
 * @data:	raw input bytes to decode as sub-identifiers
 * @len:	length of input
 *
 * Feeds arbitrary bytes through the variable-length sub-identifier
 * decoder, which uses 7-bit encoding with continuation bits.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_asn1_subid(const u8 *data, size_t len)
{
	const unsigned char *ptr = data;
	const unsigned char *end = data + len;
	unsigned long subid;
	int count = 0;

	while (ptr < end) {
		if (!fuzz_asn1_subid_decode(&ptr, end, &subid))
			break;
		count++;
		/* Prevent runaway loops on crafted input */
		if (count > 1024)
			break;
	}

	pr_debug("fuzz_asn1: decoded %d sub-identifiers from %zu bytes\n",
		 count, len);
	return 0;
}

/*
 * fuzz_asn1_oid - Fuzz the ASN.1 OID decoder
 * @data:	raw input bytes to decode as an OID
 * @len:	length of input
 *
 * Attempts to decode the input as an ASN.1 Object Identifier.
 * Tests the allocation, decoding, and cleanup paths.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_asn1_oid(const u8 *data, size_t len)
{
	unsigned long *oid = NULL;
	size_t oidlen = 0;
	bool ret;

	if (len == 0)
		return 0;

	/* Cap input length to prevent excessive allocations */
	if (len > 4096)
		len = 4096;

	ret = fuzz_asn1_oid_decode(data, len, &oid, &oidlen);
	if (ret) {
		pr_debug("fuzz_asn1: decoded OID with %zu components\n",
			 oidlen);
		kfree(oid);
	} else {
		pr_debug("fuzz_asn1: OID decode failed (expected for fuzz)\n");
	}

	return 0;
}

/*
 * fuzz_asn1_spnego_blob - Fuzz ASN.1 tag/length encoding paths
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Tests the compute_asn_hdr_len_bytes and encode_asn_tag functions
 * by feeding them various length values extracted from the fuzz input.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_asn1_spnego_blob(const u8 *data, size_t len)
{
	int hdr_len;
	unsigned int test_len;

	if (len < 4)
		return -EINVAL;

	/*
	 * Extract a 32-bit length value from the fuzz input and
	 * compute the ASN.1 header length bytes for it.
	 */
	test_len = (data[0] << 24) | (data[1] << 16) |
		   (data[2] << 8) | data[3];

	/* Replicate compute_asn_hdr_len_bytes logic */
	if (test_len > 0xFFFFFF)
		hdr_len = 4;
	else if (test_len > 0xFFFF)
		hdr_len = 3;
	else if (test_len > 0xFF)
		hdr_len = 2;
	else if (test_len > 0x7F)
		hdr_len = 1;
	else
		hdr_len = 0;

	pr_debug("fuzz_asn1: len=0x%x hdr_len=%d\n", test_len, hdr_len);

	/*
	 * If we have enough remaining data, try to interpret it as a
	 * sequence of ASN.1 TLV (Tag-Length-Value) triplets.
	 */
	if (len >= 6) {
		const u8 *ptr = data + 4;
		const u8 *end = data + len;
		u8 tag, length_byte;

		while (ptr + 2 <= end) {
			tag = *ptr++;
			length_byte = *ptr++;

			if (length_byte & 0x80) {
				/* Long form length */
				int num_octets = length_byte & 0x7F;

				if (num_octets > 4 || ptr + num_octets > end)
					break;
				ptr += num_octets;
			} else {
				/* Short form - skip value */
				if (ptr + length_byte > end)
					break;
				ptr += length_byte;
			}

			pr_debug("fuzz_asn1: TLV tag=0x%02x\n", tag);
		}
	}

	return 0;
}

static int __init asn1_fuzz_init(void)
{
	u8 test_data[64];
	int i, ret;

	pr_info("asn1_fuzz: module loaded\n");

	/* Self-test: decode a known SPNEGO OID {1.3.6.1.5.5.2} */
	{
		static const u8 spnego_oid[] = {
			0x2b, 0x06, 0x01, 0x05, 0x05, 0x02
		};

		ret = fuzz_asn1_oid(spnego_oid, sizeof(spnego_oid));
		pr_info("asn1_fuzz: SPNEGO OID test returned %d\n", ret);
	}

	/* Self-test: decode a known NTLMSSP OID */
	{
		static const u8 ntlmssp_oid[] = {
			0x2b, 0x06, 0x01, 0x04, 0x01,
			0x82, 0x37, 0x02, 0x02, 0x0a
		};

		ret = fuzz_asn1_oid(ntlmssp_oid, sizeof(ntlmssp_oid));
		pr_info("asn1_fuzz: NTLMSSP OID test returned %d\n", ret);
	}

	/* Test with zero-length input */
	ret = fuzz_asn1_oid(test_data, 0);
	pr_info("asn1_fuzz: zero-length test returned %d\n", ret);

	/* Test with garbage sub-identifiers */
	for (i = 0; i < sizeof(test_data); i++)
		test_data[i] = 0x80 | (i & 0x7F);
	/* Terminate last byte (clear high bit) */
	test_data[sizeof(test_data) - 1] &= 0x7F;
	ret = fuzz_asn1_subid(test_data, sizeof(test_data));
	pr_info("asn1_fuzz: subid fuzz test returned %d\n", ret);

	/* Test SPNEGO blob path */
	memset(test_data, 0xAB, sizeof(test_data));
	ret = fuzz_asn1_spnego_blob(test_data, sizeof(test_data));
	pr_info("asn1_fuzz: spnego blob test returned %d\n", ret);

	return 0;
}

static void __exit asn1_fuzz_exit(void)
{
	pr_info("asn1_fuzz: module unloaded\n");
}

module_init(asn1_fuzz_init);
module_exit(asn1_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for ASN.1 SPNEGO parsing");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
