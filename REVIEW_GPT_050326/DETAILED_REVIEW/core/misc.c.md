# Line-by-line Review: src/core/misc.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/xattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/unicode.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` * match_pattern() - compare a string with a pattern which might include`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * wildcard '*', '?', and the MS-DOS special wildcards '<', '>', '"'.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * MS-DOS/Windows wildcard semantics (MS-SMB2 §3.3.5.17, MS-FSCC §2.1.4):`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *   '*' — matches any sequence of zero or more characters`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` *   '?' — matches any single character`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` *   '<' (DOS_STAR) — matches any sequence of characters up to but not`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` *                    including the last '.' in the name (the extension`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *                    separator).  If the name has no dot, behaves like '*'.`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *                    Examples: pattern "<.txt" matches "foo.txt" but not`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` *                    "foo.bar.txt"; pattern "<" alone matches any name.`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *   '>' (DOS_QM)   — matches any single character, or end-of-string when`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` *                    the next pattern character is a dot`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` *   '"' (DOS_DOT)  — matches a '.' or end-of-string (allows patterns like`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` *                    "*." to match names without an extension, e.g., "foo")`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * @str:	string to compare with a pattern`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * @len:	string length`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * @pattern:	pattern string which might include wildcards`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * Return:	true if pattern matched with the string, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `int match_pattern(const char *str, size_t len, const char *pattern)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	const char *s = str;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	const char *p = pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	bool star = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	 * For DOS_STAR ('<'): track whether the wildcard is a '<' so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	 * we can prevent it from matching the last '.' and extension.`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	 * last_dot_pos points to the last '.' in the string (or NULL if none).`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	const char *last_dot = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	bool dos_star = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	size_t i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	/* Locate the last '.' in the string for DOS_STAR handling */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	for (i = 0; i < len; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		if (str[i] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `			last_dot = str + i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	while (*s && len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `		switch (*p) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		case '?':`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `			/* Standard: matches any single character */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `			s++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `			len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `			p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		case '*':`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `			/* Standard '*': matches any sequence */`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `			star = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `			dos_star = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `			str = s;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `			if (!*++p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `				return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `			pattern = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		case '<':`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `			 * DOS_STAR '<': like '*' but when backtracking, will`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `			 * not advance past the last '.' in the string.`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `			 * If there is no last dot, behaves exactly like '*'.`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `			star = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `			dos_star = (last_dot != NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `			str = s;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `			if (!*++p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `				return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `			pattern = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		case '>':`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			 * DOS_QM '>': matches any single character, OR`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			 * matches end-of-string when the next pattern char`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `			 * is '.'.`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `			if (!len && p[1] == '.') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `				/* End-of-string before a dot: skip '>' */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `				p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `				s++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `				len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `				p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		case '"':`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			 * DOS_DOT '"': matches '.' or end-of-string.`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			 * Allows patterns like "*." to match names without`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `			 * an extension (e.g., "foo" with no dot).`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `			if (*s == '.') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `				s++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `				len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `				if (!star)`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `					return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `				/* Backtrack, but respect DOS_STAR boundary */`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `				if (dos_star && last_dot && str >= last_dot) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `					return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `				str++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `				len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `				s = str;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `				p = pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `			if (tolower(*s) == tolower(*p)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `				s++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `				len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `				p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `				if (!star)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `					return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `				 * Backtrack: for DOS_STAR ('<'), do not let`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `				 * the match position advance past the last`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `				 * dot in the original string.  This prevents`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `				 * '<' from "eating" the last extension.`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `				if (dos_star && last_dot && str >= last_dot) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `					return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `				str++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `				len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `				s = str;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `				p = pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	/* Skip trailing '*' and '<' wildcards (both match empty string) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	while (*p == '*' || *p == '<')`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		++p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	/* '"' (DOS_DOT) at end-of-pattern matches end-of-string */`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	while (*p == '"')`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		++p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	/* '>' (DOS_QM) at end-of-pattern matches end-of-string */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	while (*p == '>')`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		++p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	return !*p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `EXPORT_SYMBOL_IF_KUNIT(match_pattern);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ` * is_char_allowed() - check for valid character`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` * @ch:		input character to be checked`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` * Return:	1 if char is allowed, otherwise 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `VISIBLE_IF_KUNIT int is_char_allowed(char ch)`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	/* check for control chars, wildcards etc. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	if (!(ch & 0x80) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	    (ch <= 0x1f ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	     ch == '?' || ch == '"' || ch == '<' ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	     ch == '>' || ch == '|' || ch == '*'))`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `EXPORT_SYMBOL_IF_KUNIT(is_char_allowed);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `int ksmbd_validate_filename(char *filename)`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	while (*filename) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		char c = *filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		filename++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		if (!is_char_allowed(c)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `			ksmbd_debug(VFS, "File name validation failed: 0x%x\n", c);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `VISIBLE_IF_KUNIT int ksmbd_validate_stream_name(char *stream_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	while (*stream_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		char c = *stream_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		stream_name++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		if (c == '/' || c == ':' || c == '\\') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [ERROR_PATH|] `			pr_err("Stream name validation failed: %c\n", c);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00219 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00220 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_validate_stream_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `int parse_stream_name(char *filename, char **stream_name, int *s_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	char *stream_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	char *s_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	s_name = filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	filename = strsep(&s_name, ":");`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	if (!s_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		*stream_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00238 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	ksmbd_debug(SMB, "filename : %s, streams : %s\n", filename, s_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	/* Default to DATA_STREAM per MS-SMB2 when no :$TYPE suffix */`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	*s_type = DATA_STREAM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	if (strchr(s_name, ':')) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		stream_type = s_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		s_name = strsep(&stream_type, ":");`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		rc = ksmbd_validate_stream_name(s_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			*stream_name = s_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00253 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		ksmbd_debug(SMB, "stream name : %s, stream type : %s\n", s_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `			    stream_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		if (!strncasecmp("$data", stream_type, 5))`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `			*s_type = DATA_STREAM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		else if (!strncasecmp("$index_allocation", stream_type, 17))`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `			*s_type = DIR_STREAM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	 * An empty stream name with $DATA type (e.g., "file::$DATA")`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	 * refers to the default unnamed data stream, which is the`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	 * file itself. Treat this as a non-stream open by returning`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	 * -ENOENT with a NULL stream_name.`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	if (!rc && (!s_name[0]) && *s_type == DATA_STREAM) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		*stream_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00274 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	*stream_name = s_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `EXPORT_SYMBOL_IF_KUNIT(parse_stream_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ` * convert_to_nt_pathname() - extract and return windows path string`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ` *      whose share directory prefix was removed from file path`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ` * @share: ksmbd_share_config pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ` * @path: path to report`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ` * Return : windows path string or error`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `char *convert_to_nt_pathname(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `			     const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	char *pathname, *ab_pathname, *nt_pathname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	int share_path_len = share->path_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	size_t ab_pathname_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	int prefix;`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [MEM_BOUNDS|] `	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00300 [NONE] `	if (!pathname)`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `		return ERR_PTR(-EACCES);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	ab_pathname = d_path(path, pathname, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	if (IS_ERR(ab_pathname)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `		nt_pathname = ERR_PTR(-EACCES);`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [ERROR_PATH|] `		goto free_pathname;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00307 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	if (strncmp(ab_pathname, share->path, share_path_len)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		nt_pathname = ERR_PTR(-EACCES);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [ERROR_PATH|] `		goto free_pathname;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00312 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	ab_pathname_len = strlen(&ab_pathname[share_path_len]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	prefix = ab_pathname[share_path_len] == '\0' ? 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [MEM_BOUNDS|] `	nt_pathname = kmalloc(prefix + ab_pathname_len + 1, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00317 [NONE] `	if (!nt_pathname) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `		nt_pathname = ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [ERROR_PATH|] `		goto free_pathname;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00320 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	if (prefix)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `		*nt_pathname = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [MEM_BOUNDS|] `	memcpy(nt_pathname + prefix, &ab_pathname[share_path_len],`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00325 [NONE] `	       ab_pathname_len + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	ksmbd_conv_path_to_windows(nt_pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `free_pathname:`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	kfree(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	return nt_pathname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `int get_nlink(struct kstat *st)`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	int nlink;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	nlink = st->nlink;`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	/* Avoid underflow on mount points or pseudo-filesystems */`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	if (S_ISDIR(st->mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		nlink = (nlink > 1) ? nlink - 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	return nlink;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `void ksmbd_conv_path_to_unix(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	strreplace(path, '\\', '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `void ksmbd_strip_last_slash(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	int len = strlen(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	while (len && path[len - 1] == '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		path[len - 1] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `void ksmbd_conv_path_to_windows(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	strreplace(path, '/', '\\');`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `char *ksmbd_casefold_sharename(struct unicode_map *um, const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	char *cf_name, *orig_cf_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	int cf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [MEM_BOUNDS|] `	cf_name = kzalloc(KSMBD_REQ_MAX_SHARE_NAME, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00372 [NONE] `	if (!cf_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	if (IS_ENABLED(CONFIG_UNICODE) && um) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		const struct qstr q_name = {.name = name, .len = strlen(name)};`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `		cf_len = utf8_casefold(um, &q_name, cf_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `				       KSMBD_REQ_MAX_SHARE_NAME);`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		if (cf_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [ERROR_PATH|] `			goto out_ascii;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		return cf_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `out_ascii:`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [MEM_BOUNDS|] `	cf_len = strscpy(cf_name, name, KSMBD_REQ_MAX_SHARE_NAME);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00388 [NONE] `	if (cf_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		kfree(cf_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `		return ERR_PTR(-E2BIG);`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	orig_cf_name = cf_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	for (; *cf_name; ++cf_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `		*cf_name = isascii(*cf_name) ? tolower(*cf_name) : *cf_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	return orig_cf_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` * ksmbd_extract_sharename() - get share name from tree connect request`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` * @treename:	buffer containing tree name and share name`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ` * Return:      share name on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `char *ksmbd_extract_sharename(struct unicode_map *um, const char *treename)`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	const char *name = treename, *pos = strrchr(name, '\\');`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	if (pos)`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		name = (pos + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	/* caller has to free the memory */`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	return ksmbd_casefold_sharename(um, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ` * convert_to_unix_name() - convert windows name to unix format`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ` * @share:	ksmbd_share_config pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ` * @name:	file name that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ` * Return:	converted name on success, otherwise NULL`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `char *convert_to_unix_name(struct ksmbd_share_config *share, const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	int no_slash = 0, name_len, path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	char *new_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	if (name[0] == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		name++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	path_len = share->path_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	name_len = strlen(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [MEM_BOUNDS|] `	new_name = kmalloc(path_len + name_len + 2, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00435 [NONE] `	if (!new_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [MEM_BOUNDS|] `	memcpy(new_name, share->path, path_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00439 [NONE] `	if (new_name[path_len - 1] != '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		new_name[path_len] = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `		no_slash = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [MEM_BOUNDS|] `	memcpy(new_name + path_len + no_slash, name, name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00445 [NONE] `	path_len += name_len + no_slash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	new_name[path_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	return new_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `static char *normalize_path(const char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	size_t path_len, remain_path_len, out_path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	char *out_path, *out_next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	int i, pre_dotdot_cnt = 0, slash_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	bool is_last;`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	path_len = strlen(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	remain_path_len = path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [MEM_BOUNDS|] `	out_path = kzalloc(path_len + 2, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00461 [NONE] `	if (!out_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	out_path_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	out_next = out_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		const char *name = path + path_len - remain_path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `		char *next = strchrnul(name, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `		size_t name_len = next - name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `		is_last = !next[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `		if (name_len == 2 && name[0] == '.' && name[1] == '.') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `			pre_dotdot_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `			/* handle the case that path ends with "/.." */`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `			if (is_last)`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [ERROR_PATH|] `				goto follow_dotdot;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00477 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `			if (pre_dotdot_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `follow_dotdot:`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `				slash_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `				for (i = out_path_len - 1; i >= 0; i--) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `					if (out_path[i] == '/' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `					    ++slash_cnt == pre_dotdot_cnt + 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `						break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `				if (i < 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `				    slash_cnt != pre_dotdot_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `					kfree(out_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `					return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `				out_next = &out_path[i+1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `				*out_next = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `				out_path_len = i + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `			if (name_len != 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `			    !(name_len == 1 && name[0] == '.') &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `			    !(name_len == 2 && name[0] == '.' && name[1] == '.')) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [MEM_BOUNDS|] `				snprintf(out_next, name_len + 2, "%.*s/", (int)name_len, name);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00503 [NONE] `				out_next += name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `				out_path_len += name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `			pre_dotdot_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `		remain_path_len -= name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	} while (!is_last);`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	if (out_path_len > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `		out_path[out_path_len-1] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	return out_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `char *convert_to_unix_name(struct ksmbd_share_config *share, const char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	int no_slash = 0, name_len, path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	char *new_name, *norm_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	if (name[0] == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `		name++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	norm_name = normalize_path(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	if (IS_ERR(norm_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		return norm_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	path_len = share->path_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	name_len = strlen(norm_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [MEM_BOUNDS|] `	new_name = kmalloc(path_len + name_len + 2, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00532 [NONE] `	if (!new_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `		kfree(norm_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [MEM_BOUNDS|] `	memcpy(new_name, share->path, path_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00538 [NONE] `	if (new_name[path_len - 1] != '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `		new_name[path_len] = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `		no_slash = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [MEM_BOUNDS|] `	memcpy(new_name + path_len + no_slash, norm_name, name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00544 [NONE] `	path_len += name_len + no_slash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	new_name[path_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	kfree(norm_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	return new_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `char *ksmbd_convert_dir_info_name(struct ksmbd_dir_info *d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `				  const struct nls_table *local_nls,`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `				  int *conv_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	char *conv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	int  sz = min(4 * d_info->name_len, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	if (!sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [MEM_BOUNDS|] `	conv = kmalloc(sz + 2, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00563 [NONE] `	if (!conv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	/* XXX */`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	*conv_len = smbConvertToUTF16((__le16 *)conv, d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `				      d_info->name_len, local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	*conv_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	/* We allocate buffer twice bigger than needed. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	conv[*conv_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	conv[*conv_len + 1] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	return conv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ` * Convert the NT UTC (based 1601-01-01, in hundred nanosecond units)`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ` * into Unix UTC (based 1970-01-01, in seconds).`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `struct timespec64 ksmbd_NTtimeToUnix(__le64 ntutc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	struct timespec64 ts;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	/* Subtract the NTFS time offset, then convert to 1s intervals. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	s64 t = le64_to_cpu(ntutc) - NTFS_TIME_OFFSET;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `	u64 abs_t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	 * Unfortunately can not use normal 64 bit division on 32 bit arch, but`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	 * the alternative, do_div, does not work with negative numbers so have`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	 * to special case them`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	if (t < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `		abs_t = -t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		ts.tv_nsec = do_div(abs_t, 10000000) * 100;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		ts.tv_nsec = -ts.tv_nsec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `		ts.tv_sec = -abs_t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `		abs_t = t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `		ts.tv_nsec = do_div(abs_t, 10000000) * 100;`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		ts.tv_sec = abs_t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	return ts;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `/* Convert the Unix UTC into NT UTC. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `u64 ksmbd_UnixTimeToNT(struct timespec64 t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	/* Convert to 100ns intervals and then add the NTFS time offset. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	return (u64)t.tv_sec * 10000000 + t.tv_nsec / 100 + NTFS_TIME_OFFSET;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `long long ksmbd_systime(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	struct timespec64	ts;`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	ktime_get_real_ts64(&ts);`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	return ksmbd_UnixTimeToNT(ts);`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
