# Line-by-line Review: src/encoding/unicode.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Some of the source code in this file came from fs/cifs/cifs_unicode.c`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2000,2009`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Modified by Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   Modified by Namjae Jeon (linkinjeon@kernel.org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <asm/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "unicode.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "uniupr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `int smb1_utf16_name_length(const __le16 *from, int maxbytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	int i, len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	int maxwords = maxbytes / 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	__u16 ftmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	for (i = 0; i < maxwords; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `		ftmp = get_unaligned_le16(&from[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `		len += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `		if (ftmp == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * cifs_mapchar() - convert a host-endian char to proper char in codepage`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * @target:	where converted character should be copied`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * @from:	host-endian source string`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * @cp:		codepage to which character should be converted`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * @mapchar:	should character be mapped according to mapchars mount option?`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * This function handles the conversion of a single character. It is the`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * responsibility of the caller to ensure that the target buffer is large`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * enough to hold the result of the conversion (at least NLS_MAX_CHARSET_SIZE).`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * Return:	string length after conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `static int`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `cifs_mapchar(char *target, const __u16 *from, const struct nls_table *cp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	     bool mapchar)`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	int len = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	__u16 src_char;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	src_char = *from;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	if (!mapchar)`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [ERROR_PATH|] `		goto cp_convert;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	 * BB: Cannot handle remapping UNI_SLASH until all the calls to`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	 *     build_path_from_dentry are modified, as they use slash as`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	 *     separator.`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	switch (src_char) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	case UNI_COLON:`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		*target = ':';`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	case UNI_ASTERISK:`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `		*target = '*';`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	case UNI_QUESTION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		*target = '?';`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	case UNI_PIPE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		*target = '|';`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	case UNI_GRTRTHAN:`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `		*target = '>';`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	case UNI_LESSTHAN:`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		*target = '<';`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [ERROR_PATH|] `		goto cp_convert;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00091 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `cp_convert:`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	len = cp->uni2char(src_char, target, NLS_MAX_CHARSET_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	if (len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [ERROR_PATH|] `		goto surrogate_pair;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [ERROR_PATH|] `	goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `surrogate_pair:`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	/* convert SURROGATE_PAIR and IVS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	if (strcmp(cp->charset, "utf8"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [ERROR_PATH|] `		goto unknown;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00107 [NONE] `	len = utf16s_to_utf8s(from, 3, UTF16_LITTLE_ENDIAN, target, 6);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	if (len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [ERROR_PATH|] `		goto unknown;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00110 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `unknown:`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	*target = '?';`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	len = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [ERROR_PATH|] `	goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00116 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * smb_utf16_bytes() - compute converted string length`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * @from:	pointer to input string`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` * @maxbytes:	input string length`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * @codepage:	destination codepage`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` * Walk a utf16le string and return the number of bytes that the string will`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` * be after being converted to the given charset, not including any null`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` * termination required. Don't walk past maxbytes in the source buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` * Return:	string length after conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `static int smb_utf16_bytes(const __le16 *from, int maxbytes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `			   const struct nls_table *codepage)`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	int i, j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	int charlen, outlen = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	int maxwords = maxbytes / 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	char tmp[NLS_MAX_CHARSET_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	__u16 ftmp[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	for (i = 0; i < maxwords; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		ftmp[0] = get_unaligned_le16(&from[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		if (ftmp[0] == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		for (j = 1; j <= 2; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `			if (i + j < maxwords)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `				ftmp[j] = get_unaligned_le16(&from[i + j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `				ftmp[j] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		charlen = cifs_mapchar(tmp, ftmp, codepage, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		if (charlen > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `			outlen += charlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `			outlen++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	return outlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ` * is_char_allowed() - check for valid character`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` * @ch:		input character to be checked`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * Return:	1 if char is allowed, otherwise 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `static inline int is_char_allowed(char *ch)`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	/* check for control chars, wildcards etc. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	if (!(*ch & 0x80) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	    (*ch <= 0x1f ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	     *ch == '?' || *ch == '"' || *ch == '<' ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	     *ch == '>' || *ch == '|'))`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` * smb_from_utf16() - convert utf16le string to local charset`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ` * @to:		destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` * @from:	source buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ` * @tolen:	destination buffer size (in bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` * @fromlen:	source buffer size (in bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` * @codepage:	codepage to which characters should be converted`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ` * @mapchar:	should characters be remapped according to the mapchars option?`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ` * Convert a little-endian utf16le string (as sent by the server) to a string`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ` * in the provided codepage. The tolen and fromlen parameters are to ensure`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ` * that the code doesn't walk off of the end of the buffer (which is always`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ` * a danger if the alignment of the source buffer is off). The destination`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ` * string is always properly null terminated and fits in the destination`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ` * buffer. Returns the length of the destination string in bytes (including`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ` * null terminator).`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ` * Note that some windows versions actually send multiword UTF-16 characters`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` * instead of straight UTF16-2. The linux nls routines however aren't able to`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * deal with those characters properly. In the event that we get some of`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` * those characters, they won't be translated properly.`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` * Return:	string length after conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `static int smb_from_utf16(char *to, const __le16 *from, int tolen, int fromlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `			  const struct nls_table *codepage, bool mapchar)`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	int i, j, charlen, safelen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	int outlen = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	int nullsize = nls_nullsize(codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	int fromwords = fromlen / 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	char tmp[NLS_MAX_CHARSET_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	__u16 ftmp[3];	/* ftmp[3] = 3array x 2bytes = 6bytes UTF-16 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	 * because the chars can be of varying widths, we need to take care`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	 * not to overflow the destination buffer when we get close to the`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	 * end of it. Until we get to this offset, we don't need to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	 * for overflow however.`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	safelen = tolen - (NLS_MAX_CHARSET_SIZE + nullsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	for (i = 0; i < fromwords; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		ftmp[0] = get_unaligned_le16(&from[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		if (ftmp[0] == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		for (j = 1; j <= 2; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `			if (i + j < fromwords)`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `				ftmp[j] = get_unaligned_le16(&from[i + j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `				ftmp[j] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		 * check to see if converting this character might make the`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		 * conversion bleed into the null terminator`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		if (outlen >= safelen) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `			charlen = cifs_mapchar(tmp, ftmp, codepage, mapchar);`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `			if ((outlen + charlen) > (tolen - nullsize))`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		/* put converted char into 'to' buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		charlen = cifs_mapchar(&to[outlen], ftmp, codepage, mapchar);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `		outlen += charlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		 * charlen (=bytes of UTF-8 for 1 character)`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		 * 4bytes UTF-8(surrogate pair) is charlen=4`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		 * (4bytes UTF-16 code)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		 * 7-8bytes UTF-8(IVS) is charlen=3+4 or 4+4`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `		 * (2 UTF-8 pairs divided to 2 UTF-16 pairs)`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `		if (charlen == 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `			i++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		else if (charlen >= 5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `			/* 5-6bytes UTF-8 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `			i += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	/* properly null-terminate string */`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	for (i = 0; i < nullsize; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		to[outlen++] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	return outlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ` * smb_strtoUTF16() - Convert character string to unicode string`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` * @to:		destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ` * @from:	source buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ` * @len:	source string length in bytes (also used as max output`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ` *		code-unit count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] ` * @codepage:	codepage to which characters should be converted`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ` * Callers must ensure @to is large enough to hold the converted`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ` * output. The destination buffer must be at least (len * 2 + 2) bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ` * to accommodate the worst case (all single-byte chars producing one`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ` * 16-bit code unit each, plus a null terminator).`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ` * The @len parameter limits both the number of source bytes consumed`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] ` * and the number of output UTF-16 code units written (excluding the`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ` * null terminator). For BMP characters this is safe; supplementary`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ` * plane characters are clamped to the same limit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ` * Return:	number of UTF-16 code units written (excluding null terminator)`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `int smb_strtoUTF16(__le16 *to, const char *from, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		   const struct nls_table *codepage)`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	int charlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	int max_out = len; /* max output code units (dest limit) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	wchar_t wchar_to; /* needed to quiet sparse */`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	/* special case for utf8 to handle no plane0 chars */`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	if (!strcmp(codepage->charset, "utf8")) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `		 * convert utf8 -> utf16. max_out limits output code`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `		 * units to prevent destination buffer overflow.`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `		i  = utf8s_to_utf16s(from, len, UTF16_LITTLE_ENDIAN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `				     (wchar_t *)to, max_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `		/* if success terminate and exit */`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `		if (i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [ERROR_PATH|] `			goto success;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00306 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		 * if fails fall back to UCS encoding as this`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `		 * function should not return negative values`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		 * currently can fail only if source contains`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		 * invalid encoded characters`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	for (i = 0; len > 0 && *from && i < max_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	     i++, from += charlen, len -= charlen) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `		charlen = codepage->char2uni(from, len, &wchar_to);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `		if (charlen < 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `			/* A question mark */`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `			wchar_to = 0x003f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `			charlen = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		put_unaligned_le16(wchar_to, &to[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `success:`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	put_unaligned_le16(0, &to[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	return i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ` * smb_strndup_from_utf16() - copy a string from wire format to the local`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ` *		codepage`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ` * @src:	source string`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ` * @maxlen:	don't walk past this many bytes in the source string`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ` * @is_unicode:	is this a unicode string?`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ` * @codepage:	destination codepage`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` * Take a string given by the server, convert it to the local codepage and`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` * put it in a new buffer. Returns a pointer to the new string or NULL on`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ` * error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` * Return:	destination string buffer or error ptr`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `char *smb_strndup_from_utf16(const char *src, const int maxlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `			     const bool is_unicode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `			     const struct nls_table *codepage)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	int len, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	char *dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	if (is_unicode) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		len = smb_utf16_bytes((__le16 *)src, maxlen, codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		len += nls_nullsize(codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [MEM_BOUNDS|] `		dst = kmalloc(len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00355 [NONE] `		if (!dst)`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `			return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		ret = smb_from_utf16(dst, (__le16 *)src, len, maxlen, codepage,`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `				     false);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `			kfree(dst);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `			return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		len = strnlen(src, maxlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		len++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [MEM_BOUNDS|] `		dst = kmalloc(len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00367 [NONE] `		if (!dst)`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `			return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [MEM_BOUNDS|] `		strscpy(dst, src, len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00370 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	return dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ` * Convert 16 bit Unicode pathname to wire format from string in current code`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ` * page. Conversion may involve remapping up the six characters that are`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ` * only legal in POSIX-like OS (if they are present in the string). Path`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * names are little endian 16 bit Unicode on the wire`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * smbConvertToUTF16() - convert string from local charset to utf16`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * @target:	destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` * @source:	source buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ` * @srclen:	source buffer size (in bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ` * @cp:		codepage to which characters should be converted`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ` * @mapchar:	should characters be remapped according to the mapchars option?`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ` * Convert 16 bit Unicode pathname to wire format from string in current code`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] ` * page. Conversion may involve remapping up the six characters that are`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ` * only legal in POSIX-like OS (if they are present in the string). Path`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ` * names are little endian 16 bit Unicode on the wire`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ` * NOTE: This function does not perform output bounds checking on @target.`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ` * Callers MUST ensure that @target is allocated with at least`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] ` * (srclen * 2 + 2) bytes to accommodate the worst-case UTF-16 expansion`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] ` * plus a null terminator. Surrogate pairs and IVS sequences may produce`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ` * up to 3 UTF-16 code units per input character.`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` * NOTE: The declaration in unicode.h must also be kept in sync with this`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` * function signature.`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ` * Return:	char length after conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `int smbConvertToUTF16(__le16 *target, const char *source, int srclen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		      const struct nls_table *cp, int mapchars)`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	int i, j, charlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	char src_char;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	__le16 dst_char;`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	wchar_t tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	wchar_t wchar_to[6];	/* UTF-16 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	unicode_t u;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	 * Maximum expected output in __le16 code units.`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	 * Worst case: each source byte could produce up to 2 UTF-16`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	 * code units (surrogate pairs), plus one for null terminator.`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	 * Use srclen * 2 + 2 as the conservative upper bound.`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	const unsigned int max_out_units = (unsigned int)srclen * 2 + 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	if (!mapchars)`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		return smb_strtoUTF16(target, source, srclen, cp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	for (i = 0, j = 0; i < srclen; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		/* Safety check: stop if output index approaches limit */`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `		if (WARN_ON_ONCE((unsigned int)j * sizeof(__le16) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `				 (unsigned int)srclen * 4 + 4))`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		src_char = source[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `		charlen = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		switch (src_char) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `		case 0:`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `			put_unaligned(0, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `			return j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		case ':':`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `			dst_char = cpu_to_le16(UNI_COLON);`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `		case '*':`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `			dst_char = cpu_to_le16(UNI_ASTERISK);`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `		case '?':`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `			dst_char = cpu_to_le16(UNI_QUESTION);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `		case '<':`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `			dst_char = cpu_to_le16(UNI_LESSTHAN);`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `		case '>':`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `			dst_char = cpu_to_le16(UNI_GRTRTHAN);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `		case '|':`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `			dst_char = cpu_to_le16(UNI_PIPE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		 * FIXME: We can not handle remapping backslash (UNI_SLASH)`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `		 * until all the calls to build_path_from_dentry are modified,`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `		 * as they use backslash as separator.`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `			charlen = cp->char2uni(source + i, srclen - i, &tmp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `			dst_char = cpu_to_le16(tmp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `			 * if no match, use question mark, which at least in`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `			 * some cases serves as wild card`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `			if (charlen > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [ERROR_PATH|] `				goto ctoUTF16;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `			/* convert SURROGATE_PAIR */`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `			if (strcmp(cp->charset, "utf8"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [ERROR_PATH|] `				goto unknown;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00475 [NONE] `			if (*(source + i) & 0x80) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `				charlen = utf8_to_utf32(source + i, 6, &u);`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `				if (charlen < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [ERROR_PATH|] `					goto unknown;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00479 [NONE] `			} else`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [ERROR_PATH|] `				goto unknown;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00481 [NONE] `			ret  = utf8s_to_utf16s(source + i, charlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `					UTF16_LITTLE_ENDIAN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `					wchar_to, 6);`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `			if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [ERROR_PATH|] `				goto unknown;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `			i += charlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `			dst_char = cpu_to_le16(*wchar_to);`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `			if (charlen <= 3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `				/* 1-3bytes UTF-8 to 2bytes UTF-16 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `				put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `			} else if (charlen == 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `				 * 4bytes UTF-8(surrogate pair) to 4bytes UTF-16`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `				 * 7-8bytes UTF-8(IVS) divided to 2 UTF-16`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `				 * (charlen=3+4 or 4+4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `				put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `				dst_char = cpu_to_le16(*(wchar_to + 1));`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `				j++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `				if (WARN_ON_ONCE((unsigned int)j >= max_out_units))`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `					return j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `				put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `			} else if (charlen >= 5) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `				/* 5-6bytes UTF-8 to 6bytes UTF-16 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `				put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `				dst_char = cpu_to_le16(*(wchar_to + 1));`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `				j++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `				if (WARN_ON_ONCE((unsigned int)j >= max_out_units))`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `					return j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `				put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `				dst_char = cpu_to_le16(*(wchar_to + 2));`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `				j++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `				if (WARN_ON_ONCE((unsigned int)j >= max_out_units))`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `					return j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `				put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `unknown:`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `			dst_char = cpu_to_le16(0x003f);`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `			charlen = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `ctoUTF16:`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		 * character may take more than one byte in the source string,`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		 * but will take exactly two bytes in the target string`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `		i += charlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `		put_unaligned(dst_char, &target[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	return j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
