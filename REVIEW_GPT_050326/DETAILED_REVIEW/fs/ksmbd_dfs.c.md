# Line-by-line Review: src/fs/ksmbd_dfs.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   DFS referral support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS and`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   FSCTL_DFS_GET_REFERRALS_EX and builds a compatible referral`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   response for clients probing DFS capability.`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/minmax.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/err.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "ksmbd_dfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "ksmbd_feature.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "unicode.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define DFS_REFERRAL_V2		2`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define DFS_REFERRAL_V3		3`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define DFS_REFERRAL_V4		4`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#define DFSREF_REFERRAL_SERVER	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define DFSREF_STORAGE_SERVER	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define DFSREF_TARGET_FAILBACK	0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#define DFS_TARGET_SET_BOUNDARY	0x0400`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define DFS_DEFAULT_TTL		300`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * REQ_GET_DFS_REFERRAL request structure ([MS-DFSC] 2.2.2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` * MaxReferralLevel: Maximum referral version the client understands`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` * RequestFileName:  Null-terminated Unicode DFS path`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `struct req_get_dfs_referral {`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	__le16	max_referral_level;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	__u8	request_file_name[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * REQ_GET_DFS_REFERRAL_EX request header ([MS-DFSC] 2.2.2.1).`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * RequestData contains a null-terminated UTF-16 request path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `struct req_get_dfs_referral_ex {`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	__le16	max_referral_level;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__le16	request_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__le32	request_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	__u8	request_data[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * RESP_GET_DFS_REFERRAL response header ([MS-DFSC] 2.2.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `struct resp_get_dfs_referral {`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	__le16	path_consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	__le16	number_of_referrals;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	__le32	referral_header_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * DFS referral entry versions consumed by SMB clients.`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` * Level 3/4 layouts match Linux cifs client parser expectations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `struct dfs_referral_level_2 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	__le16	version_number;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	__le16	size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	__le16	server_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	__le16	referral_entry_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	__le32	proximity;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	__le32	time_to_live;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	__le16	dfs_path_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	__le16	dfs_alt_path_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	__le16	node_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `struct dfs_referral_level_3 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	__le16	version_number;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	__le16	size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	__le16	server_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	__le16	referral_entry_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	__le32	time_to_live;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	__le16	dfs_path_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	__le16	dfs_alt_path_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	__le16	node_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `struct dfs_referral_level_4 {`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	__le16	version_number;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	__le16	size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	__le16	server_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	__le16	referral_entry_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	__le32	time_to_live;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	__le16	dfs_path_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	__le16	dfs_alt_path_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	__le16	node_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	__u8	service_site_guid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `VISIBLE_IF_KUNIT unsigned int dfs_referral_fixed_size(u16 version)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	switch (version) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	case DFS_REFERRAL_V4:`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `		return sizeof(struct dfs_referral_level_4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	case DFS_REFERRAL_V3:`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `		return sizeof(struct dfs_referral_level_3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	case DFS_REFERRAL_V2:`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `		return sizeof(struct dfs_referral_level_2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `EXPORT_SYMBOL_IF_KUNIT(dfs_referral_fixed_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `VISIBLE_IF_KUNIT u16 dfs_select_referral_version(u16 max_level)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	if (max_level >= DFS_REFERRAL_V4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		return DFS_REFERRAL_V4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	if (max_level >= DFS_REFERRAL_V3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		return DFS_REFERRAL_V3;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	if (max_level >= DFS_REFERRAL_V2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		return DFS_REFERRAL_V2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `EXPORT_SYMBOL_IF_KUNIT(dfs_select_referral_version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `VISIBLE_IF_KUNIT int dfs_utf16_name_len(const __u8 *name, unsigned int max_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	if (max_len < sizeof(__le16))`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	for (i = 0; i + 1 < max_len; i += sizeof(__le16)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		if (!name[i] && !name[i + 1])`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `			return i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00159 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `EXPORT_SYMBOL_IF_KUNIT(dfs_utf16_name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `static int dfs_utf16_encode(const struct nls_table *nls,`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `			    const char *name, __u8 **utf16, unsigned int *len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	__le16 *out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	size_t alloc_units;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	alloc_units = strlen(name) * 3 + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	out = kcalloc(alloc_units, sizeof(__le16), KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	if (!out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	conv_len = smbConvertToUTF16(out, name, strlen(name), nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		kfree(out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00178 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	*utf16 = (__u8 *)out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	*len = (conv_len + 1) * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `VISIBLE_IF_KUNIT char *dfs_next_component(const char *path, const char **next)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	const char *start = path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	const char *end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	while (*start == '\\' || *start == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		start++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	if (!*start)`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	end = start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	while (*end && *end != '\\' && *end != '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		end++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	if (next) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		*next = end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		while (**next == '\\' || **next == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `			(*next)++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	return kstrndup(start, end - start, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `EXPORT_SYMBOL_IF_KUNIT(dfs_next_component);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `static char *dfs_build_network_address(const char *request_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	const char *next = request_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	const char *netbios = ksmbd_netbios_name();`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	char *server = NULL, *share = NULL, *target = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	server = dfs_next_component(next, &next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	if (!server)`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [ERROR_PATH|] `		goto fallback;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	share = dfs_next_component(next, &next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	if (!share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [ERROR_PATH|] `		goto fallback;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	target = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\%s", netbios, share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [ERROR_PATH|] `	goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00225 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `fallback:`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	target = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\IPC$", netbios);`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	kfree(server);`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	kfree(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	return target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `static int dfs_build_referral_response(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `				       u16 max_referral_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `				       const __u8 *request_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `				       unsigned int request_name_max_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	struct resp_get_dfs_referral *dfs_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	__u8 *entry_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	__u8 *dfs_path_utf16 = NULL, *target_utf16 = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	unsigned int dfs_path_len = 0, target_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	unsigned int fixed_size, entry_size, total_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	unsigned int path_off, alt_path_off, node_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	int req_name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	u16 version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	char *request_path = NULL, *target = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	version = dfs_select_referral_version(max_referral_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	if (!version) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00256 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00257 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	 * Early check: reject obviously too-small output buffers before`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	 * spending time and memory on UTF-16 encoding allocations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	 * The minimum response is the referral header plus the fixed-size`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	 * referral entry (without variable-length path strings).`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	fixed_size = dfs_referral_fixed_size(version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	if (max_out_len < sizeof(struct resp_get_dfs_referral) + fixed_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00268 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00269 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	req_name_len = dfs_utf16_name_len(request_name, request_name_max_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	if (req_name_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [NONE] `		return req_name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	request_path = smb_strndup_from_utf16((const char *)request_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `					      req_name_len + sizeof(__le16),`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `					      true, work->conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	if (IS_ERR(request_path))`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		return PTR_ERR(request_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	ksmbd_conv_path_to_windows(request_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	target = dfs_build_network_address(request_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	if (!target) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00288 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	ret = dfs_utf16_encode(work->conn->local_nls, request_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `			       &dfs_path_utf16, &dfs_path_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	ret = dfs_utf16_encode(work->conn->local_nls, target,`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `			       &target_utf16, &target_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00299 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	entry_size = fixed_size + dfs_path_len + dfs_path_len + target_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	total_out = sizeof(struct resp_get_dfs_referral) + entry_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	if (max_out_len < total_out) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00304 [NONE] `		ret = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00306 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	dfs_rsp = (struct resp_get_dfs_referral *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	dfs_rsp->path_consumed = cpu_to_le16(min_t(unsigned int, req_name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `						   U16_MAX));`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	dfs_rsp->number_of_referrals = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	dfs_rsp->referral_header_flags =`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `		cpu_to_le32(DFSREF_REFERRAL_SERVER | DFSREF_STORAGE_SERVER |`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `			    (version == DFS_REFERRAL_V4 ? DFSREF_TARGET_FAILBACK : 0));`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	entry_ptr = (__u8 *)dfs_rsp + sizeof(*dfs_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	path_off = fixed_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	alt_path_off = path_off + dfs_path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	node_off = alt_path_off + dfs_path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	if (version == DFS_REFERRAL_V4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		struct dfs_referral_level_4 *ref4 =`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `			(struct dfs_referral_level_4 *)entry_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `		ref4->version_number = cpu_to_le16(DFS_REFERRAL_V4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		ref4->size = cpu_to_le16(min_t(unsigned int, entry_size, U16_MAX));`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `		ref4->server_type = cpu_to_le16(DFS_SERVER_ROOT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		ref4->referral_entry_flags = cpu_to_le16(DFS_TARGET_SET_BOUNDARY);`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		ref4->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		ref4->dfs_path_offset = cpu_to_le16(path_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		ref4->dfs_alt_path_offset = cpu_to_le16(alt_path_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `		ref4->node_offset = cpu_to_le16(node_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		memset(ref4->service_site_guid, 0, sizeof(ref4->service_site_guid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	} else if (version == DFS_REFERRAL_V3) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		struct dfs_referral_level_3 *ref3 =`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			(struct dfs_referral_level_3 *)entry_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		ref3->version_number = cpu_to_le16(DFS_REFERRAL_V3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		ref3->size = cpu_to_le16(min_t(unsigned int, entry_size, U16_MAX));`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `		ref3->server_type = cpu_to_le16(DFS_SERVER_ROOT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		ref3->referral_entry_flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		ref3->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		ref3->dfs_path_offset = cpu_to_le16(path_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		ref3->dfs_alt_path_offset = cpu_to_le16(alt_path_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		ref3->node_offset = cpu_to_le16(node_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		struct dfs_referral_level_2 *ref2 =`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `			(struct dfs_referral_level_2 *)entry_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		ref2->version_number = cpu_to_le16(DFS_REFERRAL_V2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		ref2->size = cpu_to_le16(min_t(unsigned int, entry_size, U16_MAX));`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		ref2->server_type = cpu_to_le16(DFS_SERVER_ROOT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		ref2->referral_entry_flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		ref2->proximity = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		ref2->time_to_live = cpu_to_le32(DFS_DEFAULT_TTL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		ref2->dfs_path_offset = cpu_to_le16(path_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		ref2->dfs_alt_path_offset = cpu_to_le16(alt_path_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		ref2->node_offset = cpu_to_le16(node_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [MEM_BOUNDS|] `	memcpy(entry_ptr + path_off, dfs_path_utf16, dfs_path_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00362 [MEM_BOUNDS|] `	memcpy(entry_ptr + alt_path_off, dfs_path_utf16, dfs_path_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00363 [MEM_BOUNDS|] `	memcpy(entry_ptr + node_off, target_utf16, target_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	*out_len = total_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	kfree(request_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	kfree(target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	kfree(dfs_path_utf16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	kfree(target_utf16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ` * ksmbd_dfs_get_referrals() - Handle FSCTL_DFS_GET_REFERRALS`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ` * @work:           smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ` * @id:             volatile file id (unused for DFS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * @in_buf:         input buffer containing REQ_GET_DFS_REFERRAL`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` * @in_buf_len:     input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` * @max_out_len:    maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * @rsp:            pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` * @out_len:        [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `static int ksmbd_dfs_get_referrals(struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `				   void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `				   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `				   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `				   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	struct req_get_dfs_referral *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	unsigned int request_name_max_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	(void)id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	if (in_buf_len < sizeof(struct req_get_dfs_referral)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [ERROR_PATH|] `		pr_err_ratelimited("DFS referral request too short: %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00398 [NONE] `				   in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00400 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00401 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	req = (struct req_get_dfs_referral *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	request_name_max_len = in_buf_len - sizeof(*req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `		    "DFS GET_REFERRALS: max_level=%u, buf_len=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		    le16_to_cpu(req->max_referral_level), in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	return dfs_build_referral_response(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `				   le16_to_cpu(req->max_referral_level),`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `				   req->request_file_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `				   request_name_max_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `				   max_out_len, rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ` * ksmbd_dfs_get_referrals_ex() - Handle FSCTL_DFS_GET_REFERRALS_EX`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ` * @work:           smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] ` * @id:             volatile file id (unused for DFS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ` * @in_buf:         input buffer containing extended referral request`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ` * @in_buf_len:     input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ` * @max_out_len:    maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ` * @rsp:            pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ` * @out_len:        [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `static int ksmbd_dfs_get_referrals_ex(struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `				      void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `				      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `				      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `				      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `				      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	struct req_get_dfs_referral_ex *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	unsigned int request_data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	(void)id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	ksmbd_debug(SMB, "DFS GET_REFERRALS_EX: buf_len=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		    in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	if (in_buf_len < sizeof(*req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00445 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	req = (struct req_get_dfs_referral_ex *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	request_data_len = le32_to_cpu(req->request_data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	if (request_data_len == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	    request_data_len > in_buf_len - sizeof(*req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00452 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00453 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	return dfs_build_referral_response(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `				   le16_to_cpu(req->max_referral_level),`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `				   req->request_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `				   request_data_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `				   max_out_len, rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `/* FSCTL handler descriptors */`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `static struct ksmbd_fsctl_handler dfs_get_referrals_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	.ctl_code = FSCTL_DFS_GET_REFERRALS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	.handler  = ksmbd_dfs_get_referrals,`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `static struct ksmbd_fsctl_handler dfs_get_referrals_ex_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	.ctl_code = FSCTL_DFS_GET_REFERRALS_EX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	.handler  = ksmbd_dfs_get_referrals_ex,`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] ` * ksmbd_dfs_enabled() - Check if DFS is globally enabled`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] ` * Queries the three-tier feature framework to determine whether`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] ` * DFS referral support is compiled in and enabled server-wide.`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ` * Return: true if DFS is enabled, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `bool ksmbd_dfs_enabled(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	return ksmbd_feat_enabled(NULL, KSMBD_FEAT_DFS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ` * ksmbd_dfs_init() - Initialize DFS referral subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ` * Registers FSCTL handlers for FSCTL_DFS_GET_REFERRALS (0x00060194)`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ` * and FSCTL_DFS_GET_REFERRALS_EX (0x000601B0).`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `int ksmbd_dfs_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	ret = ksmbd_register_fsctl(&dfs_get_referrals_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [ERROR_PATH|] `		pr_err("Failed to register FSCTL_DFS_GET_REFERRALS: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00503 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	ret = ksmbd_register_fsctl(&dfs_get_referrals_ex_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [ERROR_PATH|] `		pr_err("Failed to register FSCTL_DFS_GET_REFERRALS_EX: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00510 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [ERROR_PATH|] `		goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00512 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	ksmbd_debug(SMB, "DFS referral subsystem initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	ksmbd_unregister_fsctl(&dfs_get_referrals_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` * ksmbd_dfs_exit() - Tear down DFS referral subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` * Unregisters both DFS FSCTL handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `void ksmbd_dfs_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	ksmbd_unregister_fsctl(&dfs_get_referrals_ex_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	ksmbd_unregister_fsctl(&dfs_get_referrals_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
