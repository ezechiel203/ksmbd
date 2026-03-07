# Line-by-line Review: src/include/encoding/unicode.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * Some of the source code in this file came from fs/cifs/cifs_unicode.c`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` * cifs_unicode:  Unicode kernel case support`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` * Function:`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *     Convert a unicode character to upper or lower case using`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *     compressed tables.`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2000,2009`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` * Notes:`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *     These APIs are based on the C library functions.  The semantics`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *     should match the C functions but with expanded size operands.`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *     The upper/lower functions are based on a table created by mkupr.`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` *     This is a compressed table of upper and lower case conversion.`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#ifndef _CIFS_UNICODE_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define _CIFS_UNICODE_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <asm/byteorder.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include <linux/nls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include <linux/unicode.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define  UNIUPR_NOLOWER		/* Example to not expand lower case tables */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * Windows maps these to the user defined 16 bit Unicode range since they are`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * reserved symbols (along with \ and /), otherwise illegal to store`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * in filenames in NTFS`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define UNI_ASTERISK    ((__u16)('*' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define UNI_QUESTION    ((__u16)('?' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define UNI_COLON       ((__u16)(':' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define UNI_GRTRTHAN    ((__u16)('>' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define UNI_LESSTHAN    ((__u16)('<' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define UNI_PIPE        ((__u16)('|' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define UNI_SLASH       ((__u16)('\\' + 0xF000))`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `/* Just define what we want from uniupr.h.  We don't want to define the tables`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * in each source file.`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#ifndef	UNICASERANGE_DEFINED`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `struct UniCaseRange {`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	wchar_t start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	wchar_t end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	signed char *table;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#endif				/* UNICASERANGE_DEFINED */`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#ifndef UNIUPR_NOUPPER`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/* Defined in uniupr.h, included only from unicode.c */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `extern signed char SmbUniUpperTable[512];`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `extern const struct UniCaseRange SmbUniUpperRange[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#endif				/* UNIUPR_NOUPPER */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#ifndef UNIUPR_NOLOWER`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `extern signed char CifsUniLowerTable[512];`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `extern const struct UniCaseRange CifsUniLowerRange[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#endif				/* UNIUPR_NOLOWER */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#ifdef __KERNEL__`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `int smb1_utf16_name_length(const __le16 *from, int maxbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `int smb_strtoUTF16(__le16 *to, const char *from, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `		   const struct nls_table *codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `char *smb_strndup_from_utf16(const char *src, const int maxlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `			     const bool is_unicode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `			     const struct nls_table *codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `int smbConvertToUTF16(__le16 *target, const char *source, int srclen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		      const struct nls_table *cp, int mapchars);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `char *ksmbd_extract_sharename(struct unicode_map *um, const char *treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * UniStrlen:  Return the length of a string (in 16 bit Unicode chars not bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `static inline size_t UniStrlen(const wchar_t *ucs1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	int i = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	while (*ucs1++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		i++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	return i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * UniStrnlen:  Return the length (in 16 bit Unicode chars not bytes) of a`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` *		string (length limited)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `static inline size_t UniStrnlen(const wchar_t *ucs1, int maxlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	int i = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	while (*ucs1++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		i++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		if (i >= maxlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	return i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * UniStrcat:  Concatenate the second string to the first (bounded)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * Returns:`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` *     Address of the first string`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `static inline wchar_t *UniStrcat(wchar_t *ucs1, size_t dest_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `				 const wchar_t *ucs2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	wchar_t *anchor = ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	size_t len1 = UniStrnlen(ucs1, dest_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	size_t remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	if (len1 >= dest_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		return ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	remaining = dest_size - len1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	ucs1 += len1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	while (remaining > 1 && *ucs2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		*ucs1++ = *ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	*ucs1 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	return anchor;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` * UniStrchr:  Find a character in a string`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * Returns:`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` *     Address of first occurrence of character in string`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` *     or NULL if the character is not in the string`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `static inline wchar_t *UniStrchr(const wchar_t *ucs, wchar_t uc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	while ((*ucs != uc) && *ucs)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		ucs++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	if (*ucs == uc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `		return (wchar_t *)ucs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` * UniStrcmp:  Compare two strings`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` * Returns:`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` *     < 0:  First string is less than second`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` *     = 0:  Strings are equal`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` *     > 0:  First string is greater than second`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `static inline int UniStrcmp(const wchar_t *ucs1, const wchar_t *ucs2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	while ((*ucs1 == *ucs2) && *ucs1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		ucs1++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	return (int)*ucs1 - (int)*ucs2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` * UniStrcpy:  Copy a string (bounded)`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `static inline wchar_t *UniStrcpy(wchar_t *ucs1, size_t dest_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `				 const wchar_t *ucs2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	wchar_t *anchor = ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	if (!dest_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `		return ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	while (dest_size > 1 && *ucs2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		*ucs1++ = *ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		dest_size--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	*ucs1 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	return anchor;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ` * UniStrncat:  Concatenate length limited string`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `static inline wchar_t *UniStrncat(wchar_t *ucs1, const wchar_t *ucs2, size_t n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	wchar_t *anchor = ucs1;	/* save pointer to string 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	while (*ucs1++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	/*NULL*/;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	ucs1--;			/* point to null terminator of s1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	while (n-- && (*ucs1 = *ucs2)) {	/* copy s2 after s1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		ucs1++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	*ucs1 = 0;		/* Null terminate the result */`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	return anchor;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` * UniStrncmp:  Compare length limited string`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `static inline int UniStrncmp(const wchar_t *ucs1, const wchar_t *ucs2, size_t n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	if (!n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `		return 0;	/* Null strings are equal */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	while ((*ucs1 == *ucs2) && *ucs1 && --n) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		ucs1++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `		ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	return (int)*ucs1 - (int)*ucs2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ` * UniStrncmp_le:  Compare length limited string - native to little-endian`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `static inline int`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `UniStrncmp_le(const wchar_t *ucs1, const wchar_t *ucs2, size_t n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	if (!n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		return 0;	/* Null strings are equal */`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	while ((*ucs1 == __le16_to_cpu(*ucs2)) && *ucs1 && --n) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		ucs1++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	return (int)*ucs1 - (int)__le16_to_cpu(*ucs2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ` * UniStrncpy:  Copy length limited string with pad`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `static inline wchar_t *UniStrncpy(wchar_t *ucs1, const wchar_t *ucs2, size_t n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	wchar_t *anchor = ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	while (n-- && *ucs2)	/* Copy the strings */`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		*ucs1++ = *ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	n++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	while (n--)		/* Pad with nulls */`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		*ucs1++ = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	return anchor;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` * UniStrncpy_le:  Copy length limited string with pad to little-endian`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `static inline wchar_t *UniStrncpy_le(wchar_t *ucs1, const wchar_t *ucs2, size_t n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	wchar_t *anchor = ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	while (n-- && *ucs2)	/* Copy the strings */`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		*ucs1++ = __le16_to_cpu(*ucs2++);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	n++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	while (n--)		/* Pad with nulls */`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		*ucs1++ = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	return anchor;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ` * UniStrstr:  Find a string in a string`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` * Returns:`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ` *     Address of first match found`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ` *     NULL if no matching string is found`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `static inline wchar_t *UniStrstr(const wchar_t *ucs1, const wchar_t *ucs2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	const wchar_t *anchor1 = ucs1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	const wchar_t *anchor2 = ucs2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	while (*ucs1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `		if (*ucs1 == *ucs2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `			/* Partial match found */`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `			ucs1++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `			ucs2++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `			if (!*ucs2)	/* Match found */`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `				return (wchar_t *)anchor1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `			ucs1 = ++anchor1;	/* No match */`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `			ucs2 = anchor2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	if (!*ucs2)		/* Both end together */`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `		return (wchar_t *)anchor1;	/* Match found */`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	return NULL;		/* No match */`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `#ifndef UNIUPR_NOUPPER`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ` * UniToupper:  Convert a unicode character to upper case`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `static inline wchar_t UniToupper(register wchar_t uc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	register const struct UniCaseRange *rp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	if (uc >= 0 && (size_t)uc < sizeof(SmbUniUpperTable)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `		/* Latin characters */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `		return uc + SmbUniUpperTable[uc];	/* Use base tables */`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	rp = SmbUniUpperRange;	/* Use range tables */`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	while (rp->start) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		if (uc < rp->start)	/* Before start of range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `			return uc;	/* Uppercase = input */`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		if (uc <= rp->end)	/* In range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `			return uc + rp->table[uc - rp->start];`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		rp++;	/* Try next range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	return uc;		/* Past last range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ` * UniStrupr:  Upper case a unicode string`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `static inline __le16 *UniStrupr(register __le16 *upin)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	register __le16 *up;`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	up = upin;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	while (*up) {		/* For all characters */`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		*up = cpu_to_le16(UniToupper(le16_to_cpu(*up)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		up++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	return upin;		/* Return input pointer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `#endif				/* UNIUPR_NOUPPER */`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `#ifndef UNIUPR_NOLOWER`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` * UniTolower:  Convert a unicode character to lower case`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `static inline wchar_t UniTolower(register wchar_t uc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	register const struct UniCaseRange *rp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	if (uc < sizeof(CifsUniLowerTable)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		/* Latin characters */`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		return uc + CifsUniLowerTable[uc];	/* Use base tables */`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	rp = CifsUniLowerRange;	/* Use range tables */`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	while (rp->start) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		if (uc < rp->start)	/* Before start of range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `			return uc;	/* Uppercase = input */`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		if (uc <= rp->end)	/* In range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `			return uc + rp->table[uc - rp->start];`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		rp++;	/* Try next range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	return uc;		/* Past last range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ` * UniStrlwr:  Lower case a unicode string`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `static inline wchar_t *UniStrlwr(register wchar_t *upin)`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	register wchar_t *up;`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	up = upin;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	while (*up) {		/* For all characters */`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		*up = UniTolower(*up);`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		up++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	return upin;		/* Return input pointer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `#endif /* _CIFS_UNICODE_H */`
  Review: Low-risk line; verify in surrounding control flow.
