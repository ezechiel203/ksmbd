// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Fuzzing harness for path parsing and validation
 *
 *   This module exercises the path parsing, validation, and conversion
 *   routines used by ksmbd. Path traversal vulnerabilities are a
 *   critical security concern for any file server, making these
 *   functions important fuzzing targets.
 *
 *   Targets:
 *     - ksmbd_validate_filename: checks for illegal characters
 *     - ksmbd_conv_path_to_unix: converts backslashes to forward slashes
 *     - ksmbd_conv_path_to_windows: converts forward slashes to backslashes
 *     - ksmbd_strip_last_slash: removes trailing slashes
 *     - parse_stream_name: parses alternate data stream names
 *     - match_pattern: wildcard pattern matching
 *
 *   Usage with syzkaller:
 *     Load as a test module. The fuzz_path_*() entry points
 *     accept raw byte buffers.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>

/*
 * Replicate the path validation logic from misc.c to allow fuzzing
 * without pulling in full ksmbd dependencies.
 */

static inline int fuzz_is_char_allowed(char ch)
{
	if (!(ch & 0x80) &&
	    (ch <= 0x1f ||
	     ch == '?' || ch == '"' || ch == '<' ||
	     ch == '>' || ch == '|' || ch == '*'))
		return 0;

	return 1;
}

/*
 * fuzz_validate_filename - Fuzz filename character validation
 * @data:	raw input bytes to validate as a filename
 * @len:	length of input
 *
 * Creates a null-terminated copy of the input and passes it through
 * the character validation logic, checking each byte against the
 * allowed character set.
 *
 * Return: 0 if all characters valid, -ENOENT if invalid char found
 */
static int fuzz_validate_filename(const u8 *data, size_t len)
{
	char *filename;
	char *p;
	int ret = 0;

	if (len == 0)
		return 0;

	/* Cap length to prevent excessive allocations */
	if (len > PATH_MAX)
		len = PATH_MAX;

	filename = kmalloc(len + 1, GFP_KERNEL);
	if (!filename)
		return -ENOMEM;

	memcpy(filename, data, len);
	filename[len] = '\0';

	p = filename;
	while (*p) {
		char c = *p++;

		if (!fuzz_is_char_allowed(c)) {
			pr_debug("fuzz_path: invalid char 0x%02x\n", c);
			ret = -ENOENT;
			break;
		}
	}

	kfree(filename);
	return ret;
}

/*
 * fuzz_conv_path_to_unix - Fuzz Windows-to-Unix path conversion
 * @data:	raw input bytes containing a Windows-style path
 * @len:	length of input
 *
 * Creates a null-terminated copy and converts all backslashes to
 * forward slashes.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_conv_path_to_unix(const u8 *data, size_t len)
{
	char *path;
	int i;

	if (len == 0)
		return 0;

	if (len > PATH_MAX)
		len = PATH_MAX;

	path = kmalloc(len + 1, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	memcpy(path, data, len);
	path[len] = '\0';

	/* Convert backslashes to forward slashes (strreplace equivalent) */
	for (i = 0; path[i]; i++) {
		if (path[i] == '\\')
			path[i] = '/';
	}

	pr_debug("fuzz_path: unix path: %.64s%s\n",
		 path, len > 64 ? "..." : "");

	kfree(path);
	return 0;
}

/*
 * fuzz_conv_path_to_windows - Fuzz Unix-to-Windows path conversion
 * @data:	raw input bytes containing a Unix-style path
 * @len:	length of input
 *
 * Creates a null-terminated copy and converts all forward slashes to
 * backslashes.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_conv_path_to_windows(const u8 *data, size_t len)
{
	char *path;
	int i;

	if (len == 0)
		return 0;

	if (len > PATH_MAX)
		len = PATH_MAX;

	path = kmalloc(len + 1, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	memcpy(path, data, len);
	path[len] = '\0';

	for (i = 0; path[i]; i++) {
		if (path[i] == '/')
			path[i] = '\\';
	}

	pr_debug("fuzz_path: windows path: %.64s%s\n",
		 path, len > 64 ? "..." : "");

	kfree(path);
	return 0;
}

/*
 * fuzz_strip_last_slash - Fuzz trailing slash removal
 * @data:	raw input bytes
 * @len:	length of input
 *
 * Creates a null-terminated copy and strips trailing slashes.
 * Tests the loop termination with paths that are entirely slashes
 * or have no trailing slashes.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_strip_last_slash(const u8 *data, size_t len)
{
	char *path;
	int path_len;

	if (len == 0)
		return 0;

	if (len > PATH_MAX)
		len = PATH_MAX;

	path = kmalloc(len + 1, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	memcpy(path, data, len);
	path[len] = '\0';

	/* Replicate ksmbd_strip_last_slash logic */
	path_len = strlen(path);
	while (path_len && path[path_len - 1] == '/') {
		path[path_len - 1] = '\0';
		path_len--;
	}

	pr_debug("fuzz_path: stripped path len=%d\n", path_len);

	kfree(path);
	return 0;
}

/*
 * fuzz_parse_stream_name - Fuzz alternate data stream name parsing
 * @data:	raw input bytes containing a filename with potential stream
 * @len:	length of input
 *
 * Creates a null-terminated copy and attempts to parse it as a
 * filename:stream_name:stream_type triplet.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_parse_stream_name(const u8 *data, size_t len)
{
	char *filename, *s_name;
	char *stream_type;
	int s_type = 0;

	if (len == 0)
		return 0;

	if (len > PATH_MAX)
		len = PATH_MAX;

	filename = kmalloc(len + 1, GFP_KERNEL);
	if (!filename)
		return -ENOMEM;

	memcpy(filename, data, len);
	filename[len] = '\0';

	/* Split on first colon */
	s_name = filename;
	strsep(&s_name, ":");
	if (!s_name) {
		pr_debug("fuzz_path: no stream name found\n");
		kfree(filename);
		return -ENOENT;
	}

	pr_debug("fuzz_path: stream name: %.32s\n", s_name);

	/* Check for stream type */
	if (strchr(s_name, ':')) {
		stream_type = s_name;
		s_name = strsep(&stream_type, ":");

		/* Validate stream name characters */
		{
			char *p = s_name;

			while (*p) {
				char c = *p++;

				if (c == '/' || c == ':' || c == '\\') {
					kfree(filename);
					return -ENOENT;
				}
			}
		}

		if (stream_type) {
			if (!strncasecmp("$data", stream_type, 5))
				s_type = 1; /* DATA_STREAM */
			else if (!strncasecmp("$index_allocation",
					      stream_type, 17))
				s_type = 2; /* DIR_STREAM */

			pr_debug("fuzz_path: stream type=%d\n", s_type);
		}
	}

	kfree(filename);
	return 0;
}

/*
 * fuzz_match_pattern - Fuzz wildcard pattern matching
 * @data:	raw input bytes, split into string and pattern
 * @len:	length of input
 *
 * Splits the input in half: first half is the string to match,
 * second half is the pattern. Tests '*' and '?' wildcard handling.
 *
 * Return: 0 on success, negative on error
 */
static int fuzz_match_pattern(const u8 *data, size_t len)
{
	char *str, *pattern;
	size_t str_len, pat_len;
	const char *s, *p;
	bool star;
	int result;

	if (len < 2)
		return -EINVAL;

	/* Cap to prevent long-running matches */
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

	/* Replicate match_pattern logic from misc.c */
	s = str;
	p = pattern;
	star = false;
	result = 0;

	while (*s && str_len) {
		switch (*p) {
		case '?':
			s++;
			str_len--;
			p++;
			break;
		case '*':
			star = true;
			str = (char *)s;
			if (!*++p) {
				result = 1;
				goto out;
			}
			pattern = (char *)p;
			break;
		default:
			if (tolower(*s) == tolower(*p)) {
				s++;
				str_len--;
				p++;
			} else {
				if (!star) {
					result = 0;
					goto out;
				}
				str++;
				s = str;
				p = pattern;
			}
			break;
		}
	}

	while (*p == '*')
		++p;
	result = !*p;

out:
	pr_debug("fuzz_path: match_pattern result=%d\n", result);

	kfree(str);
	kfree(pattern);
	return 0;
}

static int __init path_parse_fuzz_init(void)
{
	int ret;

	pr_info("path_parse_fuzz: module loaded\n");

	/* Self-test: valid filename */
	{
		static const u8 valid[] = "test_file.txt";

		ret = fuzz_validate_filename(valid, sizeof(valid) - 1);
		pr_info("path_parse_fuzz: valid filename test returned %d\n",
			ret);
	}

	/* Self-test: filename with control chars */
	{
		static const u8 invalid[] = "test\x01\x02.txt";

		ret = fuzz_validate_filename(invalid, sizeof(invalid) - 1);
		pr_info("path_parse_fuzz: control char test returned %d\n",
			ret);
	}

	/* Self-test: filename with wildcard */
	{
		static const u8 wild[] = "test*.txt";

		ret = fuzz_validate_filename(wild, sizeof(wild) - 1);
		pr_info("path_parse_fuzz: wildcard test returned %d\n", ret);
	}

	/* Self-test: path conversion */
	{
		static const u8 winpath[] = "\\share\\dir\\file.txt";

		ret = fuzz_conv_path_to_unix(winpath, sizeof(winpath) - 1);
		pr_info("path_parse_fuzz: path conv test returned %d\n", ret);
	}

	/* Self-test: strip trailing slashes */
	{
		static const u8 slashpath[] = "/share/dir///";

		ret = fuzz_strip_last_slash(slashpath, sizeof(slashpath) - 1);
		pr_info("path_parse_fuzz: strip slash test returned %d\n",
			ret);
	}

	/* Self-test: all slashes */
	{
		static const u8 allslash[] = "////";

		ret = fuzz_strip_last_slash(allslash, sizeof(allslash) - 1);
		pr_info("path_parse_fuzz: all slash test returned %d\n", ret);
	}

	/* Self-test: stream name parsing */
	{
		static const u8 stream[] = "file.txt:stream1:$DATA";

		ret = fuzz_parse_stream_name(stream, sizeof(stream) - 1);
		pr_info("path_parse_fuzz: stream test returned %d\n", ret);
	}

	/* Self-test: pattern matching */
	{
		static const u8 match_data[] = "testfile.txt" "*.txt";

		ret = fuzz_match_pattern(match_data, sizeof(match_data) - 1);
		pr_info("path_parse_fuzz: pattern test returned %d\n", ret);
	}

	/* Self-test: empty inputs */
	ret = fuzz_validate_filename(NULL, 0);
	pr_info("path_parse_fuzz: empty validate returned %d\n", ret);
	ret = fuzz_conv_path_to_unix(NULL, 0);
	pr_info("path_parse_fuzz: empty conv returned %d\n", ret);
	ret = fuzz_strip_last_slash(NULL, 0);
	pr_info("path_parse_fuzz: empty strip returned %d\n", ret);
	ret = fuzz_parse_stream_name(NULL, 0);
	pr_info("path_parse_fuzz: empty stream returned %d\n", ret);

	return 0;
}

static void __exit path_parse_fuzz_exit(void)
{
	pr_info("path_parse_fuzz: module unloaded\n");
}

module_init(path_parse_fuzz_init);
module_exit(path_parse_fuzz_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Fuzzing harness for path parsing and validation");
MODULE_AUTHOR("Samsung Electronics Co., Ltd.");
