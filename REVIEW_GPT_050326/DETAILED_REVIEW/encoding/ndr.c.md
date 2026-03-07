# Line-by-line Review: src/encoding/ndr.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2021 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Author(s): Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <asm/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `static inline char *ndr_get_field(struct ndr *n)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	return n->data + n->offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `static int try_to_realloc_ndr_blob(struct ndr *n, size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	char *data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	size_t needed, new_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	 * Compute the minimum size needed: offset + sz.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	 * Then add 1024 bytes of headroom to reduce repeated reallocs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	 * Track both to ensure n->length accurately reflects the`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	 * allocated buffer size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [MEM_BOUNDS|] `	if (check_add_overflow((size_t)n->offset, sz, &needed) ||`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00035 [MEM_BOUNDS|] `	    check_add_overflow(needed, (size_t)1024, &new_sz))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00036 [ERROR_PATH|] `		return -EOVERFLOW;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	data = krealloc(n->data, new_sz, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	if (!data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	n->data = data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	n->length = new_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	memset(n->data + n->offset, 0, new_sz - n->offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static int ndr_write_int16(struct ndr *n, __u16 value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	if (n->length <= n->offset + sizeof(value)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		ret = try_to_realloc_ndr_blob(n, sizeof(value));`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	put_unaligned_le16(value, ndr_get_field(n));`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	n->offset += sizeof(value);`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `static int ndr_write_int32(struct ndr *n, __u32 value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	if (n->length <= n->offset + sizeof(value)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `		ret = try_to_realloc_ndr_blob(n, sizeof(value));`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	put_unaligned_le32(value, ndr_get_field(n));`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	n->offset += sizeof(value);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `static int ndr_write_int64(struct ndr *n, __u64 value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	if (n->length <= n->offset + sizeof(value)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `		ret = try_to_realloc_ndr_blob(n, sizeof(value));`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	put_unaligned_le64(value, ndr_get_field(n));`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	n->offset += sizeof(value);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `static int ndr_write_bytes(struct ndr *n, void *value, size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	if (n->length <= n->offset + sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		ret = try_to_realloc_ndr_blob(n, sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [MEM_BOUNDS|] `	memcpy(ndr_get_field(n), value, sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00104 [NONE] `	n->offset += sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `static int ndr_write_string(struct ndr *n, char *value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	int raw_len = strlen(value) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	int sz = ALIGN(raw_len, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	if (n->length <= n->offset + sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		ret = try_to_realloc_ndr_blob(n, sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [MEM_BOUNDS|] `	memcpy(ndr_get_field(n), value, raw_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00122 [NONE] `	if (sz > raw_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `		memset((char *)ndr_get_field(n) + raw_len, 0, sz - raw_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	n->offset += sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	n->offset = ALIGN(n->offset, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `static int ndr_read_string(struct ndr *n, void *value, size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	unsigned int remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	int len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	if (n->offset > n->length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	remaining = n->length - n->offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	if (sz > remaining) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [ERROR_PATH|] `		pr_err_ratelimited("NDR: string length %zu exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00140 [NONE] `				   sz, remaining);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00142 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	len = strnlen(ndr_get_field(n), sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	if (len + 1 > remaining) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [ERROR_PATH|] `		pr_err_ratelimited("NDR: string length %d exceeds remaining %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00147 [NONE] `				   len + 1, remaining);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00149 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	if (value) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [MEM_BOUNDS|] `		memcpy(value, ndr_get_field(n), len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00153 [NONE] `		/* Ensure null termination regardless of source data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		((char *)value)[len] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	len++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	n->offset += len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	n->offset = ALIGN(n->offset, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	if (n->offset > n->length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00161 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `static int ndr_read_bytes(struct ndr *n, void *value, size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	unsigned int remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	if (n->offset > n->length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	remaining = n->length - n->offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	if (sz > remaining) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [ERROR_PATH|] `		pr_err_ratelimited("NDR: read bytes %zu exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00174 [NONE] `				   sz, remaining);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00176 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	if (value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [MEM_BOUNDS|] `		memcpy(value, ndr_get_field(n), sz);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00180 [NONE] `	n->offset += sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `static int ndr_read_int16(struct ndr *n, __u16 *value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	if (n->offset + sizeof(__u16) > n->length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [ERROR_PATH|] `		pr_err_ratelimited("NDR: read int16 at offset %u exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00188 [NONE] `				   n->offset, n->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00190 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	if (value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		*value = get_unaligned_le16(ndr_get_field(n));`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	n->offset += sizeof(__u16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `static int ndr_read_int32(struct ndr *n, __u32 *value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	if (n->offset + sizeof(__u32) > n->length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [ERROR_PATH|] `		pr_err_ratelimited("NDR: read int32 at offset %u exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00202 [NONE] `				   n->offset, n->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00204 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	if (value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `		*value = get_unaligned_le32(ndr_get_field(n));`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	n->offset += sizeof(__u32);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `static int ndr_read_int64(struct ndr *n, __u64 *value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	if (n->offset + sizeof(__u64) > n->length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [ERROR_PATH|] `		pr_err_ratelimited("NDR: read int64 at offset %u exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00216 [NONE] `				   n->offset, n->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00218 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	if (value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		*value = get_unaligned_le64(ndr_get_field(n));`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	n->offset += sizeof(__u64);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `int ndr_encode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	char hex_attr[12] = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	n->offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	n->length = 1024;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [MEM_BOUNDS|] `	n->data = kzalloc(n->length, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00234 [NONE] `	if (!n->data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	if (da->version == 3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [MEM_BOUNDS|] `		snprintf(hex_attr, 10, "0x%x", da->attr);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00239 [NONE] `		ret = ndr_write_string(n, hex_attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		ret = ndr_write_string(n, "");`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	ret = ndr_write_int16(n, da->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	ret = ndr_write_int32(n, da->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	ret = ndr_write_int32(n, da->flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	ret = ndr_write_int32(n, da->attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	if (da->version == 3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `		ret = ndr_write_int32(n, da->ea_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [ERROR_PATH|] `			goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00266 [NONE] `		ret = ndr_write_int64(n, da->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [ERROR_PATH|] `			goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00269 [NONE] `		ret = ndr_write_int64(n, da->alloc_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		 * Version 4 is a simplified format: only itime and`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		 * create_time are stored. change_time is intentionally`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		 * omitted — it is derived from the filesystem's ctime`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		 * rather than persisted in the xattr.`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		ret = ndr_write_int64(n, da->itime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	ret = ndr_write_int64(n, da->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	if (da->version == 3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		ret = ndr_write_int64(n, da->change_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00290 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `err_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	kfree(n->data);`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	n->data = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `int ndr_decode_dos_attr(struct ndr *n, struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	char hex_attr[12];`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	unsigned int version2, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	n->offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	ret = ndr_read_string(n, hex_attr, sizeof(hex_attr));`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	ret = ndr_read_int16(n, &da->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	if (da->version != 3 && da->version != 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		ksmbd_debug(VFS, "v%d version is not supported\n", da->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00316 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	ret = ndr_read_int32(n, &version2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	if (da->version != version2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `		ksmbd_debug(VFS, "ndr version mismatched(version: %d, version2: %d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `		       da->version, version2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00326 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	ret = ndr_read_int32(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	ret = ndr_read_int32(n, &da->attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	if (da->version == 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `		ret = ndr_read_int64(n, &da->itime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		ret = ndr_read_int64(n, &da->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		ret = ndr_read_int32(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		ret = ndr_read_int64(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		ret = ndr_read_int64(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		ret = ndr_read_int64(n, &da->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		ret = ndr_read_int64(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `static int ndr_encode_posix_acl_entry(struct ndr *n, struct xattr_smb_acl *acl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	ret = ndr_write_int32(n, acl->count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	n->offset = ALIGN(n->offset, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	ret = ndr_write_int32(n, acl->count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	ret = ndr_write_int32(n, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	for (i = 0; i < acl->count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		n->offset = ALIGN(n->offset, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		ret = ndr_write_int16(n, acl->entries[i].type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `		ret = ndr_write_int16(n, acl->entries[i].type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `		if (acl->entries[i].type == SMB_ACL_USER) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `			n->offset = ALIGN(n->offset, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `			ret = ndr_write_int64(n, acl->entries[i].uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `		} else if (acl->entries[i].type == SMB_ACL_GROUP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			n->offset = ALIGN(n->offset, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `			ret = ndr_write_int64(n, acl->entries[i].gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		/* push permission */`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		ret = ndr_write_int32(n, acl->entries[i].perm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `int ndr_encode_posix_acl(struct ndr *n,`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `			 struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `			 struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `			 struct inode *inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `			 struct xattr_smb_acl *acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `			 struct xattr_smb_acl *def_acl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	unsigned int ref_id = 0x00020000;`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	vfsuid_t vfsuid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	vfsgid_t vfsgid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	n->offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	n->length = 1024;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [MEM_BOUNDS|] `	n->data = kzalloc(n->length, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00429 [NONE] `	if (!n->data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	if (acl) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `		/* ACL ACCESS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		ret = ndr_write_int32(n, ref_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `		ref_id += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `		ret = ndr_write_int32(n, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	if (def_acl) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		/* DEFAULT ACL ACCESS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `		ret = ndr_write_int32(n, ref_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		ref_id += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `		ret = ndr_write_int32(n, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	vfsuid = i_uid_into_vfsuid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	vfsuid = i_uid_into_vfsuid(user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	ret = ndr_write_int64(n, from_kuid(&init_user_ns, vfsuid_into_kuid(vfsuid)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	ret = ndr_write_int64(n, from_kuid(&init_user_ns, i_uid_into_mnt(user_ns, inode)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	vfsgid = i_gid_into_vfsgid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	vfsgid = i_gid_into_vfsgid(user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	ret = ndr_write_int64(n, from_kgid(&init_user_ns, vfsgid_into_kgid(vfsgid)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	ret = ndr_write_int64(n, from_kgid(&init_user_ns, i_gid_into_mnt(user_ns, inode)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00478 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	ret = ndr_write_int64(n, from_kuid(&init_user_ns, inode->i_uid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	ret = ndr_write_int64(n, from_kgid(&init_user_ns, inode->i_gid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00486 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	ret = ndr_write_int32(n, inode->i_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	if (acl) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `		ret = ndr_encode_posix_acl_entry(n, acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `		if (def_acl && !ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `			ret = ndr_encode_posix_acl_entry(n, def_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00498 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `err_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	kfree(n->data);`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	n->data = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `int ndr_encode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	unsigned int ref_id = 0x00020004;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	n->offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	n->length = 2048;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [MEM_BOUNDS|] `	n->data = kzalloc(n->length, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00515 [NONE] `	if (!n->data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	ret = ndr_write_int16(n, acl->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	ret = ndr_write_int32(n, acl->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	ret = ndr_write_int16(n, 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	ret = ndr_write_int32(n, ref_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	/* push hash type and hash 64bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	ret = ndr_write_int16(n, acl->hash_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00538 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	ret = ndr_write_bytes(n, acl->hash, XATTR_SD_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	ret = ndr_write_bytes(n, acl->desc, acl->desc_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	ret = ndr_write_int64(n, acl->current_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00550 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	ret = ndr_write_bytes(n, acl->posix_acl_hash, XATTR_SD_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	/* push ndr for security descriptor */`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	ret = ndr_write_bytes(n, acl->sd_buf, acl->sd_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [ERROR_PATH|] `		goto err_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00559 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `err_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	kfree(n->data);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	n->data = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `int ndr_decode_v4_ntacl(struct ndr *n, struct xattr_ntacl *acl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	unsigned int version2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	n->offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	ret = ndr_read_int16(n, &acl->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	if (acl->version != 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `		ksmbd_debug(VFS, "v%d version is not supported\n", acl->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00580 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	ret = ndr_read_int32(n, &version2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	if (acl->version != version2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `		ksmbd_debug(VFS, "ndr version mismatched(version: %d, version2: %d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `		       acl->version, version2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00589 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	/* Read Level */`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	ret = ndr_read_int16(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `	/* Read Ref Id */`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	ret = ndr_read_int32(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	ret = ndr_read_int16(n, &acl->hash_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	ret = ndr_read_bytes(n, acl->hash, XATTR_SD_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	ret = ndr_read_bytes(n, acl->desc, 10);`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	if (strncmp(acl->desc, "posix_acl", 9)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [ERROR_PATH|] `		pr_err("Invalid acl description : %.10s\n", acl->desc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00614 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00615 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	/* Read Time */`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	ret = ndr_read_int64(n, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	/* Read Posix ACL hash */`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	ret = ndr_read_bytes(n, acl->posix_acl_hash, XATTR_SD_HASH_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	if (n->offset > n->length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [ERROR_PATH|] `		pr_err_ratelimited("NDR: offset %u exceeds buffer length %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00629 [NONE] `				   n->offset, n->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00631 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	acl->sd_size = n->length - n->offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	if (acl->sd_size == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [ERROR_PATH|] `		pr_err_ratelimited("NDR: no data for security descriptor\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00636 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00637 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [MEM_BOUNDS|] `	acl->sd_buf = kzalloc(acl->sd_size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00640 [NONE] `	if (!acl->sd_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	ret = ndr_read_bytes(n, acl->sd_buf, acl->sd_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
