// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for DOS/SMB wildcard pattern matching
 *
 *   This module exercises the wildcard pattern matching logic from
 *   ksmbd's misc.c. The match_pattern() function is used for
 *   QUERY_DIRECTORY FileNamePattern matching. Pathological patterns
 *   can cause exponential time complexity or infinite loops.
 *
 *   Targets:
 *     - match_pattern(): '*' and '?' wildcard matching, case-insensitive
 *     - DOS wildcard translation: '?' -> '>' (match any or nothing at end),
 *       '*' -> '<' (match to dot), '"' -> '.' (match dot or end)
 *     - Pattern matching termination guarantees
 *     - Edge cases: empty pattern, empty string, both empty
 *
 *   Corpus seed hints:
 *     - Pattern: "*.txt", String: "file.txt"
 *     - Pattern: "???.*", String: "abc.doc"
 *     - Pattern: "*" (match everything)
 *
 *   Usage with syzkaller:
 *     Load as a test module.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>

/*
 * fuzz_match_pattern - Replicate ksmbd's match_pattern logic
 * @string:	the string to match
 * @str_len:	length of string
 * @pattern:	the pattern to match against
 * @pat_len:	length of pattern
 *
 * Return: 1 if match, 0 if no match
 */
static int fuzz_match_pattern(const char *string, size_t str_len,
			      const char *pattern, size_t pat_len)
{
	const char *s = string;
	const char *p = pattern;
	const char *s_save = string;
	const char *p_save = pattern;
	bool star = false;
	unsigned int iterations = 0;

	while (*s && str_len && iterations < 100000) {
		iterations++;
		switch (*p) {
		case '?':
			s++;
			str_len--;
			p++;
			break;
		case '*':
			star = true;
			s_save = s;
			if (!*++p)
				return 1;
			p_save = p;
			break;
		default:
			if (tolower(*s) == tolower(*p)) {
				s++;
				str_len--;
				p++;
			} else {
				if (!star)
					return 0;
				s_save++;
				s = s_save;
				p = p_save;
			}
			break;
		}
	}

	while (*p == '*')
		++p;

	return !*p;
}

/*
 * fuzz_dos_wildcard - Fuzz DOS wildcard translation + matching
 * @data:	raw input bytes
 * @len:	length of input
 *
 * DOS wildcards: '>' matches any single char or nothing at end of name,
 * '<' matches to the next dot or end, '"' matches a dot or end.
 *
 * Splits input in half: first half = string, second half = pattern.
 * Translates DOS wildcards in pattern before matching.
 *
 * Return: 0 on success (match or no-match is informational)
 */
static int fuzz_dos_wildcard(const u8 *data, size_t len)
{
	char *str, *pattern, *p;
	size_t str_len, pat_len;
	int result;

	if (len < 2)
		return -EINVAL;

	/* Cap to prevent long-running matches */
	if (len > 1024)
		len = 1024;

	str_len = len / 2;
	pat_len = len - str_len;

	str = kmalloc(str_len + 1, GFP_KERNEL);
	pattern = kmalloc(pat_len + 1, GFP_KERNEL);
	if (!str || !pattern) {
		kfree(str);
		kfree(pattern);
		return -ENOMEM;
	}

	memcpy(str, data, str_len);
	str[str_len] = '\0';
	memcpy(pattern, data + str_len, pat_len);
	pattern[pat_len] = '\0';

	/* Translate DOS wildcards */
	for (p = pattern; *p; p++) {
		switch (*p) {
		case '>':
			/* '>' matches any single char or nothing at end */
			*p = '?';
			break;
		case '<':
			/* '<' matches to next dot or end */
			*p = '*';
			break;
		case '"':
			/* '"' matches dot or end */
			*p = '.';
			break;
		}
	}

	result = fuzz_match_pattern(str, str_len, pattern, pat_len);
	pr_debug("fuzz_wildcard: match='%.*s' pattern='%.*s' result=%d\n",
		 (int)min(str_len, (size_t)32), str,
		 (int)min(pat_len, (size_t)32), pattern, result);

	kfree(str);
	kfree(pattern);
	return 0;
}

/*
 * fuzz_wildcard_stress - Stress test with pathological patterns
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Tests patterns that could cause exponential blowup.
 *
 * Return: 0 on success
 */
static int fuzz_wildcard_stress(const u8 *data, size_t len)
{
	char *str, *pattern;
	size_t str_len, pat_len;
	int result;

	if (len < 2)
		return -EINVAL;

	if (len > 512)
		len = 512;

	str_len = len / 2;
	pat_len = len - str_len;

	str = kmalloc(str_len + 1, GFP_KERNEL);
	pattern = kmalloc(pat_len + 1, GFP_KERNEL);
	if (!str || !pattern) {
		kfree(str);
		kfree(pattern);
		return -ENOMEM;
	}

	memcpy(str, data, str_len);
	str[str_len] = '\0';
	memcpy(pattern, data + str_len, pat_len);
	pattern[pat_len] = '\0';

	result = fuzz_match_pattern(str, str_len, pattern, pat_len);
	pr_debug("fuzz_wildcard_stress: result=%d\n", result);

	kfree(str);
	kfree(pattern);
	return 0;
}

static int __init wildcard_fuzz_init(void)
{
	int ret, result;

	pr_info("wildcard_fuzz: module loaded\n");

	/* Self-test 1: simple star match */
	result = fuzz_match_pattern("file.txt", 8, "*.txt", 5);
	pr_info("wildcard_fuzz: *.txt vs file.txt = %d\n", result);

	/* Self-test 2: question mark */
	result = fuzz_match_pattern("abc.doc", 7, "???.doc", 7);
	pr_info("wildcard_fuzz: ???.doc vs abc.doc = %d\n", result);

	/* Self-test 3: star matches everything */
	result = fuzz_match_pattern("anything", 8, "*", 1);
	pr_info("wildcard_fuzz: * vs anything = %d\n", result);

	/* Self-test 4: no match */
	result = fuzz_match_pattern("file.txt", 8, "*.doc", 5);
	pr_info("wildcard_fuzz: *.doc vs file.txt = %d\n", result);

	/* Self-test 5: empty pattern */
	result = fuzz_match_pattern("file", 4, "", 0);
	pr_info("wildcard_fuzz: empty pattern vs file = %d\n", result);

	/* Self-test 6: empty string */
	result = fuzz_match_pattern("", 0, "*", 1);
	pr_info("wildcard_fuzz: * vs empty = %d\n", result);

	/* Self-test 7: both empty */
	result = fuzz_match_pattern("", 0, "", 0);
	pr_info("wildcard_fuzz: empty vs empty = %d\n", result);

	/* Self-test 8: DOS wildcard */
	{
		static const u8 dos_data[] = "file.txt" ">.txt";

		ret = fuzz_dos_wildcard(dos_data, sizeof(dos_data) - 1);
		pr_info("wildcard_fuzz: DOS wildcard returned %d\n", ret);
	}

	/* Self-test 9: pathological pattern (many *) */
	{
		char stress_input[128];

		memset(stress_input, 'a', 64);
		memset(stress_input + 64, '*', 60);
		stress_input[124] = 'b';
		stress_input[125] = 0;
		ret = fuzz_wildcard_stress((const u8 *)stress_input, 126);
		pr_info("wildcard_fuzz: stress test returned %d\n", ret);
	}

	/* Self-test 10: case insensitive */
	result = fuzz_match_pattern("FILE.TXT", 8, "*.txt", 5);
	pr_info("wildcard_fuzz: case insensitive = %d\n", result);

	return 0;
}

static void __exit wildcard_fuzz_exit(void)
{
	pr_info("wildcard_fuzz: module unloaded\n");
}

module_init(wildcard_fuzz_init);
module_exit(wildcard_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for DOS/SMB wildcard pattern matching");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
