// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for Unicode/UTF-16 conversion
 *
 *   This module exercises the UTF-16LE to UTF-8 and UTF-8 to UTF-16LE
 *   conversion routines used throughout ksmbd. Every string from the
 *   SMB wire is UTF-16LE and must be converted; malformed encodings
 *   can cause buffer overflows, infinite loops, or incorrect lengths.
 *
 *   Targets:
 *     - UTF-16LE to UTF-8 conversion (smb_strndup_from_utf16 equivalent)
 *     - UTF-8 to UTF-16LE conversion (smb_strtoUTF16 equivalent)
 *     - Surrogate pair handling (0xD800-0xDFFF)
 *     - Null-termination handling
 *     - Odd-length source buffers (incomplete code unit)
 *     - BOM handling (0xFEFF)
 *
 *   Corpus seed hints:
 *     - "\\server\\share" in UTF-16LE: 5c005c00730065007200...
 *     - Lone surrogate: D800 followed by ASCII
 *     - BOM prefix: FFFE followed by normal text
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/nls.h>

/*
 * fuzz_utf16_to_utf8 - Fuzz UTF-16LE to UTF-8 conversion
 * @data:	raw UTF-16LE bytes
 * @len:	length in bytes (may be odd)
 *
 * Simulates the conversion that ksmbd performs on every wire string.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_utf16_to_utf8(const u8 *data, size_t len)
{
	char *utf8_buf;
	size_t utf8_len;
	size_t num_codeunits;
	size_t i;
	size_t out_pos = 0;

	if (len == 0)
		return 0;

	/* Cap to prevent excessive allocation */
	if (len > 8192)
		len = 8192;

	/* Odd-length: last byte is incomplete code unit */
	num_codeunits = len / 2;
	if (num_codeunits == 0) {
		pr_debug("fuzz_unicode: odd single byte, no code units\n");
		return -EINVAL;
	}

	/* UTF-8 worst case: 3 bytes per BMP char, 4 bytes for supplementary */
	utf8_len = num_codeunits * 4 + 1;
	utf8_buf = kzalloc(utf8_len, GFP_KERNEL);
	if (!utf8_buf)
		return -ENOMEM;

	for (i = 0; i < num_codeunits && out_pos < utf8_len - 4; i++) {
		u16 cu = (u16)data[i * 2] | ((u16)data[i * 2 + 1] << 8);

		/* Check for null terminator */
		if (cu == 0) {
			pr_debug("fuzz_unicode: null at codeunit %zu\n", i);
			break;
		}

		/* Check for BOM */
		if (cu == 0xFEFF && i == 0) {
			pr_debug("fuzz_unicode: BOM detected, skipping\n");
			continue;
		}

		/* Check for surrogates */
		if (cu >= 0xD800 && cu <= 0xDBFF) {
			/* High surrogate: need low surrogate next */
			u16 low;

			if (i + 1 >= num_codeunits) {
				pr_debug("fuzz_unicode: lone high surrogate at end\n");
				utf8_buf[out_pos++] = '?';
				continue;
			}
			low = (u16)data[(i + 1) * 2] |
			      ((u16)data[(i + 1) * 2 + 1] << 8);
			if (low >= 0xDC00 && low <= 0xDFFF) {
				/* Valid surrogate pair */
				u32 cp = 0x10000 +
					 ((u32)(cu - 0xD800) << 10) +
					 (u32)(low - 0xDC00);
				/* Encode as 4-byte UTF-8 */
				utf8_buf[out_pos++] = 0xF0 | ((cp >> 18) & 0x07);
				utf8_buf[out_pos++] = 0x80 | ((cp >> 12) & 0x3F);
				utf8_buf[out_pos++] = 0x80 | ((cp >> 6) & 0x3F);
				utf8_buf[out_pos++] = 0x80 | (cp & 0x3F);
				i++; /* skip low surrogate */
			} else {
				pr_debug("fuzz_unicode: orphaned high surrogate\n");
				utf8_buf[out_pos++] = '?';
			}
		} else if (cu >= 0xDC00 && cu <= 0xDFFF) {
			pr_debug("fuzz_unicode: orphaned low surrogate\n");
			utf8_buf[out_pos++] = '?';
		} else if (cu < 0x80) {
			utf8_buf[out_pos++] = (char)cu;
		} else if (cu < 0x800) {
			utf8_buf[out_pos++] = 0xC0 | ((cu >> 6) & 0x1F);
			utf8_buf[out_pos++] = 0x80 | (cu & 0x3F);
		} else {
			utf8_buf[out_pos++] = 0xE0 | ((cu >> 12) & 0x0F);
			utf8_buf[out_pos++] = 0x80 | ((cu >> 6) & 0x3F);
			utf8_buf[out_pos++] = 0x80 | (cu & 0x3F);
		}
	}

	utf8_buf[out_pos] = '\0';
	pr_debug("fuzz_unicode: converted %zu codeunits to %zu UTF-8 bytes\n",
		 i, out_pos);

	kfree(utf8_buf);
	return 0;
}

/*
 * fuzz_utf8_to_utf16 - Fuzz UTF-8 to UTF-16LE conversion
 * @data:	raw UTF-8 bytes
 * @len:	length of input
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_utf8_to_utf16(const u8 *data, size_t len)
{
	u8 *utf16_buf;
	size_t utf16_len;
	size_t i;
	size_t out_pos = 0;

	if (len == 0)
		return 0;

	if (len > 4096)
		len = 4096;

	/* UTF-16 worst case: 2 bytes per character (or 4 for supplementary) */
	utf16_len = len * 2 + 2;
	utf16_buf = kzalloc(utf16_len, GFP_KERNEL);
	if (!utf16_buf)
		return -ENOMEM;

	i = 0;
	while (i < len && out_pos < utf16_len - 4) {
		u8 byte = data[i];
		u32 cp;
		int expect;

		if (byte == 0)
			break;

		if (byte < 0x80) {
			cp = byte;
			expect = 0;
		} else if ((byte & 0xE0) == 0xC0) {
			cp = byte & 0x1F;
			expect = 1;
		} else if ((byte & 0xF0) == 0xE0) {
			cp = byte & 0x0F;
			expect = 2;
		} else if ((byte & 0xF8) == 0xF0) {
			cp = byte & 0x07;
			expect = 3;
		} else {
			/* Invalid start byte */
			pr_debug("fuzz_unicode: invalid UTF-8 start 0x%02x\n", byte);
			i++;
			continue;
		}

		i++;
		while (expect > 0 && i < len) {
			u8 cont = data[i];

			if ((cont & 0xC0) != 0x80) {
				pr_debug("fuzz_unicode: bad continuation byte\n");
				break;
			}
			cp = (cp << 6) | (cont & 0x3F);
			i++;
			expect--;
		}

		if (expect > 0)
			continue; /* Truncated sequence */

		/* Encode as UTF-16LE */
		if (cp < 0x10000) {
			utf16_buf[out_pos++] = cp & 0xFF;
			utf16_buf[out_pos++] = (cp >> 8) & 0xFF;
		} else if (cp < 0x110000) {
			u16 high = 0xD800 + ((cp - 0x10000) >> 10);
			u16 low = 0xDC00 + ((cp - 0x10000) & 0x3FF);

			utf16_buf[out_pos++] = high & 0xFF;
			utf16_buf[out_pos++] = (high >> 8) & 0xFF;
			utf16_buf[out_pos++] = low & 0xFF;
			utf16_buf[out_pos++] = (low >> 8) & 0xFF;
		}
	}

	pr_debug("fuzz_unicode: encoded %zu UTF-8 bytes to %zu UTF-16 bytes\n",
		 len, out_pos);

	kfree(utf16_buf);
	return 0;
}

/*
 * fuzz_utf16_roundtrip - Fuzz UTF-16 -> UTF-8 -> UTF-16 round-trip
 * @data:	raw UTF-16LE bytes
 * @len:	length in bytes
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_utf16_roundtrip(const u8 *data, size_t len)
{
	int ret;

	ret = fuzz_utf16_to_utf8(data, len);
	if (ret < 0)
		return ret;

	/* The round-trip would need the intermediate buffer; for fuzzing
	 * we just exercise both directions with the same input. */
	ret = fuzz_utf8_to_utf16(data, len);
	return ret;
}

static int __init unicode_fuzz_init(void)
{
	int ret;

	pr_info("unicode_fuzz: module loaded\n");

	/* Self-test 1: simple ASCII in UTF-16LE */
	{
		static const u8 ascii_utf16[] = {
			'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0
		};

		ret = fuzz_utf16_to_utf8(ascii_utf16, sizeof(ascii_utf16));
		pr_info("unicode_fuzz: ascii UTF-16 returned %d\n", ret);
	}

	/* Self-test 2: lone high surrogate */
	{
		static const u8 lone_high[] = {
			0x00, 0xD8, 'A', 0
		};

		ret = fuzz_utf16_to_utf8(lone_high, sizeof(lone_high));
		pr_info("unicode_fuzz: lone surrogate returned %d\n", ret);
	}

	/* Self-test 3: valid surrogate pair (U+10000) */
	{
		static const u8 pair[] = {
			0x00, 0xD8, 0x00, 0xDC
		};

		ret = fuzz_utf16_to_utf8(pair, sizeof(pair));
		pr_info("unicode_fuzz: surrogate pair returned %d\n", ret);
	}

	/* Self-test 4: BOM prefix */
	{
		static const u8 bom[] = {
			0xFF, 0xFE, 'A', 0, 'B', 0
		};

		ret = fuzz_utf16_to_utf8(bom, sizeof(bom));
		pr_info("unicode_fuzz: BOM returned %d\n", ret);
	}

	/* Self-test 5: odd-length buffer */
	{
		static const u8 odd[] = { 'A', 0, 'B' };

		ret = fuzz_utf16_to_utf8(odd, sizeof(odd));
		pr_info("unicode_fuzz: odd length returned %d\n", ret);
	}

	/* Self-test 6: empty input */
	ret = fuzz_utf16_to_utf8(NULL, 0);
	pr_info("unicode_fuzz: empty UTF-16 returned %d\n", ret);
	ret = fuzz_utf8_to_utf16(NULL, 0);
	pr_info("unicode_fuzz: empty UTF-8 returned %d\n", ret);

	/* Self-test 7: UTF-8 with multi-byte chars */
	{
		static const u8 utf8[] = {
			0xC3, 0xA9, /* e-acute */
			0xE4, 0xB8, 0xAD, /* CJK character */
			0xF0, 0x9F, 0x98, 0x80 /* emoji U+1F600 */
		};

		ret = fuzz_utf8_to_utf16(utf8, sizeof(utf8));
		pr_info("unicode_fuzz: multibyte UTF-8 returned %d\n", ret);
	}

	/* Self-test 8: overlong UTF-8 */
	{
		static const u8 overlong[] = { 0xC0, 0xAF }; /* overlong '/' */

		ret = fuzz_utf8_to_utf16(overlong, sizeof(overlong));
		pr_info("unicode_fuzz: overlong UTF-8 returned %d\n", ret);
	}

	/* Self-test 9: single byte (incomplete code unit for UTF-16) */
	{
		static const u8 single = 0x41;

		ret = fuzz_utf16_to_utf8(&single, 1);
		pr_info("unicode_fuzz: single byte returned %d\n", ret);
	}

	/* Self-test 10: round-trip */
	{
		static const u8 data[] = { 'T', 0, 'e', 0, 's', 0, 't', 0 };

		ret = fuzz_utf16_roundtrip(data, sizeof(data));
		pr_info("unicode_fuzz: roundtrip returned %d\n", ret);
	}

	return 0;
}

static void __exit unicode_fuzz_exit(void)
{
	pr_info("unicode_fuzz: module unloaded\n");
}

module_init(unicode_fuzz_init);
module_exit(unicode_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for Unicode/UTF-16 conversion");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
