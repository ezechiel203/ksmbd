# Line-by-line Review: src/encoding/asn1.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * The ASB.1/BER parsing code is derived from ip_nat_snmp_basic.c which was in`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` * turn derived from the gxsnmp package by Gregory McLean & Jochen Friedrich`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` * Copyright (c) 2000 RP Internet (www.rpi.net.au).`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/mm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/oid_registry.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "glob.h"`
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
- L00025 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "ksmbd_spnego_negtokeninit.asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "ksmbd_spnego_negtokentarg.asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define SPNEGO_OID_LEN 7`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define NTLMSSP_OID_LEN  10`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define KRB5_OID_LEN  7`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define KRB5U2U_OID_LEN  8`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define MSKRB5_OID_LEN  7`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `static unsigned long SPNEGO_OID[7] = { 1, 3, 6, 1, 5, 5, 2 };`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `static unsigned long NTLMSSP_OID[10] = { 1, 3, 6, 1, 4, 1, 311, 2, 2, 10 };`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `static unsigned long KRB5_OID[7] = { 1, 2, 840, 113554, 1, 2, 2 };`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `static unsigned long KRB5U2U_OID[8] = { 1, 2, 840, 113554, 1, 2, 2, 3 };`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `static unsigned long MSKRB5_OID[7] = { 1, 2, 840, 48018, 1, 2, 2 };`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `static char NTLMSSP_OID_STR[NTLMSSP_OID_LEN] = { 0x2b, 0x06, 0x01, 0x04, 0x01,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	0x82, 0x37, 0x02, 0x02, 0x0a };`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `VISIBLE_IF_KUNIT bool`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `asn1_subid_decode(const unsigned char **begin, const unsigned char *end,`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `		  unsigned long *subid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	const unsigned char *ptr = *begin;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	unsigned char ch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	*subid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `		if (ptr >= end)`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `		ch = *ptr++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `		/* Check for overflow before shifting left by 7 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `		if (*subid >> (sizeof(unsigned long) * 8 - 7))`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `		*subid <<= 7;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		*subid |= ch & 0x7F;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	} while ((ch & 0x80) == 0x80);`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	*begin = ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `EXPORT_SYMBOL_IF_KUNIT(asn1_subid_decode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `VISIBLE_IF_KUNIT bool asn1_oid_decode(const unsigned char *value, size_t vlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `			    unsigned long **oid, size_t *oidlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	const unsigned char *iptr = value, *end = value + vlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	unsigned long *optr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	unsigned long subid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	vlen += 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	if (vlen < 2 || vlen > UINT_MAX / sizeof(unsigned long))`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [ERROR_PATH|] `		goto fail_nullify;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [MEM_BOUNDS|] `	*oid = kmalloc(vlen * sizeof(unsigned long), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00085 [NONE] `	if (!*oid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	optr = *oid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	if (!asn1_subid_decode(&iptr, end, &subid))`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [ERROR_PATH|] `		goto fail;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	if (subid < 40) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		optr[0] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		optr[1] = subid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	} else if (subid < 80) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		optr[0] = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		optr[1] = subid - 40;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		optr[0] = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		optr[1] = subid - 80;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	*oidlen = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	optr += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	while (iptr < end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `		if (++(*oidlen) > vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [ERROR_PATH|] `			goto fail;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `		if (!asn1_subid_decode(&iptr, end, optr++))`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [ERROR_PATH|] `			goto fail;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00113 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `fail:`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	kfree(*oid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `fail_nullify:`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	*oid = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `EXPORT_SYMBOL_IF_KUNIT(asn1_oid_decode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `VISIBLE_IF_KUNIT bool oid_eq(unsigned long *oid1, unsigned int oid1len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		   unsigned long *oid2, unsigned int oid2len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	if (oid1len != oid2len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	return memcmp(oid1, oid2, oid1len * sizeof(unsigned long)) == 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `EXPORT_SYMBOL_IF_KUNIT(oid_eq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `int`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `ksmbd_decode_negTokenInit(unsigned char *security_blob, int length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `			  struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	return asn1_ber_decoder(&ksmbd_spnego_negtokeninit_decoder, conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `				security_blob, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `int`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `ksmbd_decode_negTokenTarg(unsigned char *security_blob, int length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `			  struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	return asn1_ber_decoder(&ksmbd_spnego_negtokentarg_decoder, conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `				security_blob, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `VISIBLE_IF_KUNIT int compute_asn_hdr_len_bytes(int len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if (len > 0xFFFFFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		return 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	else if (len > 0xFFFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		return 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	else if (len > 0xFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		return 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	else if (len > 0x7F)`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `EXPORT_SYMBOL_IF_KUNIT(compute_asn_hdr_len_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `static int encode_asn_tag(char *buf, unsigned int *ofs, unsigned int bufsize,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `			  char tag, char seq, int length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	int index = *ofs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	char hdr_len = compute_asn_hdr_len_bytes(length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	int len = length + 2 + hdr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	/* Maximum bytes written: 2 tags + 2 length fields (each up to 1+4) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	int max_write = 2 + (hdr_len ? 1 + hdr_len : 1) * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	if (index + max_write > bufsize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	/* insert tag */`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	buf[index++] = tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	if (!hdr_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `		buf[index++] = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		buf[index++] = 0x80 | hdr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		for (i = hdr_len - 1; i >= 0; i--)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `			buf[index++] = (len >> (i * 8)) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	/* insert seq */`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	len = len - (index - *ofs);`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	buf[index++] = seq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	if (!hdr_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		buf[index++] = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		buf[index++] = 0x80 | hdr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		for (i = hdr_len - 1; i >= 0; i--)`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `			buf[index++] = (len >> (i * 8)) & 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	*ofs += (index - *ofs);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `int build_spnego_ntlmssp_neg_blob(unsigned char **pbuffer, u16 *buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `				  char *ntlm_blob, int ntlm_blob_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	char *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	unsigned int ofs = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	int neg_result_len, oid_len, ntlmssp_len, total_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	/* Validate ntlm_blob_len early to prevent integer overflow in`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	 * subsequent length computations that feed into a u16 buflen.`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	if (ntlm_blob_len < 0 || ntlm_blob_len > U16_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	neg_result_len = 4 + compute_asn_hdr_len_bytes(1) * 2 + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	oid_len = 4 + compute_asn_hdr_len_bytes(NTLMSSP_OID_LEN) * 2 +`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		NTLMSSP_OID_LEN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	ntlmssp_len = 4 + compute_asn_hdr_len_bytes(ntlm_blob_len) * 2 +`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		ntlm_blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	total_len = 4 + compute_asn_hdr_len_bytes(neg_result_len +`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `			oid_len + ntlmssp_len) * 2 +`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `			neg_result_len + oid_len + ntlmssp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	if (total_len > U16_MAX || total_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [MEM_BOUNDS|] `	buf = kmalloc(total_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00231 [NONE] `	if (!buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	/* insert main gss header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	if (encode_asn_tag(buf, &ofs, total_len, 0xa1, 0x30,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `			   neg_result_len + oid_len + ntlmssp_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	/* insert neg result */`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	if (encode_asn_tag(buf, &ofs, total_len, 0xa0, 0x0a, 1))`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00242 [NONE] `	if (ofs >= total_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00244 [NONE] `	buf[ofs++] = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	/* insert oid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	if (encode_asn_tag(buf, &ofs, total_len, 0xa1, 0x06, NTLMSSP_OID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00249 [NONE] `	if (ofs + NTLMSSP_OID_LEN > total_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00251 [MEM_BOUNDS|] `	memcpy(buf + ofs, NTLMSSP_OID_STR, NTLMSSP_OID_LEN);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00252 [NONE] `	ofs += NTLMSSP_OID_LEN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	/* insert response token - ntlmssp blob */`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	if (encode_asn_tag(buf, &ofs, total_len, 0xa2, 0x04, ntlm_blob_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00257 [NONE] `	if (ofs + ntlm_blob_len > total_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00259 [MEM_BOUNDS|] `	memcpy(buf + ofs, ntlm_blob, ntlm_blob_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00260 [NONE] `	ofs += ntlm_blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	*pbuffer = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	*buflen = total_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	kfree(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00269 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `int build_spnego_ntlmssp_auth_blob(unsigned char **pbuffer, u16 *buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `				   int neg_result)`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	char *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	unsigned int ofs = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	int neg_result_len = 4 + compute_asn_hdr_len_bytes(1) * 2 + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	int total_len = 4 + compute_asn_hdr_len_bytes(neg_result_len) * 2 +`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `		neg_result_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [MEM_BOUNDS|] `	buf = kmalloc(total_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00281 [NONE] `	if (!buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	/* insert main gss header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	if (encode_asn_tag(buf, &ofs, total_len, 0xa1, 0x30, neg_result_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	/* insert neg result */`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	if (encode_asn_tag(buf, &ofs, total_len, 0xa0, 0x0a, 1))`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00291 [NONE] `	if (ofs >= total_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00293 [NONE] `	if (neg_result)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		buf[ofs++] = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		buf[ofs++] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	*pbuffer = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	*buflen = total_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `err_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	kfree(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00305 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `int ksmbd_gssapi_this_mech(void *context, size_t hdrlen, unsigned char tag,`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `			   const void *value, size_t vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	unsigned long *oid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	size_t oidlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	if (!asn1_oid_decode(value, vlen, &oid, &oidlen)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		err = -EBADMSG;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00317 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	if (!oid_eq(oid, oidlen, SPNEGO_OID, SPNEGO_OID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		err = -EBADMSG;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	kfree(oid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `		char buf[50];`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		sprint_oid(value, vlen, buf, sizeof(buf));`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `		ksmbd_debug(AUTH, "Unexpected OID: %s\n", buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `int ksmbd_neg_token_init_mech_type(void *context, size_t hdrlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `				   unsigned char tag, const void *value,`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `				   size_t vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	struct ksmbd_conn *conn = context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	unsigned long *oid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	size_t oidlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	int mech_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	char buf[50];`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	if (!asn1_oid_decode(value, vlen, &oid, &oidlen))`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [ERROR_PATH|] `		goto fail;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	if (oid_eq(oid, oidlen, NTLMSSP_OID, NTLMSSP_OID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `		mech_type = KSMBD_AUTH_NTLMSSP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	else if (oid_eq(oid, oidlen, MSKRB5_OID, MSKRB5_OID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		mech_type = KSMBD_AUTH_MSKRB5;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	else if (oid_eq(oid, oidlen, KRB5_OID, KRB5_OID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		mech_type = KSMBD_AUTH_KRB5;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	else if (oid_eq(oid, oidlen, KRB5U2U_OID, KRB5U2U_OID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		mech_type = KSMBD_AUTH_KRB5U2U;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [ERROR_PATH|] `		goto fail;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00355 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	conn->auth_mechs |= mech_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	if (conn->preferred_auth_mech == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		conn->preferred_auth_mech = mech_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	kfree(oid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `fail:`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	kfree(oid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	sprint_oid(value, vlen, buf, sizeof(buf));`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	ksmbd_debug(AUTH, "Unexpected OID: %s\n", buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [ERROR_PATH|] `	return -EBADMSG;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00368 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `static int ksmbd_neg_token_alloc(void *context, size_t hdrlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `				 unsigned char tag, const void *value,`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `				 size_t vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	struct ksmbd_conn *conn = context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	if (!vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	kfree(conn->mechToken);`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	conn->mechToken = kmemdup_nul(value, vlen, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	if (!conn->mechToken)`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	conn->mechTokenLen = (unsigned int)vlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `int ksmbd_neg_token_init_mech_token(void *context, size_t hdrlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `				    unsigned char tag, const void *value,`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `				    size_t vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	return ksmbd_neg_token_alloc(context, hdrlen, tag, value, vlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `int ksmbd_neg_token_targ_resp_token(void *context, size_t hdrlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `				    unsigned char tag, const void *value,`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `				    size_t vlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	return ksmbd_neg_token_alloc(context, hdrlen, tag, value, vlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
