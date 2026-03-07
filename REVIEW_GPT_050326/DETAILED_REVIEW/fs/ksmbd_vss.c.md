# Line-by-line Review: src/fs/ksmbd_vss.c

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
- L00006 [NONE] ` *   VSS/snapshot support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Implements FSCTL_SRV_ENUMERATE_SNAPSHOTS and pluggable snapshot`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   backends (btrfs, ZFS, generic) to enable the Windows "Previous`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   Versions" tab for files served over SMB.`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/time.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/mutex.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `/* Maximum number of snapshots to enumerate */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define KSMBD_VSS_MAX_SNAPSHOTS		256`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * SRV_SNAPSHOT_ARRAY response header (MS-SMB2 2.2.32.2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `struct srv_snapshot_array {`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	__le32 number_of_snapshots;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	__le32 number_of_snapshots_returned;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	__le32 snapshot_array_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/*  Backend registry                                                   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `static DEFINE_MUTEX(vss_backend_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `static LIST_HEAD(vss_backend_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * ksmbd_vss_register_backend() - Register a snapshot backend`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * @be: backend descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * Return: 0 on success, -EEXIST if already registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `int ksmbd_vss_register_backend(struct ksmbd_snapshot_backend *be)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	struct ksmbd_snapshot_backend *cur;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	if (!be || !be->name || !be->enumerate)`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [LOCK|] `	mutex_lock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00076 [NONE] `	list_for_each_entry(cur, &vss_backend_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `		if (!strcmp(cur->name, be->name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [LOCK|] `			mutex_unlock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00079 [ERROR_PATH|] `			pr_err("VSS backend '%s' already registered\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00080 [NONE] `			       be->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [ERROR_PATH|] `			return -EEXIST;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00082 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	list_add_tail(&be->list, &vss_backend_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [LOCK|] `	mutex_unlock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	ksmbd_debug(VFS, "VSS backend '%s' registered\n", be->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * ksmbd_vss_unregister_backend() - Unregister a snapshot backend`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * @be: backend descriptor previously registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `void ksmbd_vss_unregister_backend(struct ksmbd_snapshot_backend *be)`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	if (!be)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [LOCK|] `	mutex_lock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00101 [NONE] `	list_del_init(&be->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [LOCK|] `	mutex_unlock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	ksmbd_debug(VFS, "VSS backend '%s' unregistered\n", be->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * ksmbd_vss_resolve_path() - Resolve a @GMT token to a real path`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * @share_path:	Share root path on the filesystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * @gmt_token:	GMT token string`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * @resolved:	Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * @len:	Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `int ksmbd_vss_resolve_path(const char *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			   const char *gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			   char *resolved, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	struct ksmbd_snapshot_backend *be;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	int ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [LOCK|] `	mutex_lock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00124 [NONE] `	list_for_each_entry(be, &vss_backend_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		if (!be->resolve_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		ret = be->resolve_path(share_path, gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `				       resolved, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `		if (!ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [LOCK|] `	mutex_unlock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `/*  Snapshot directory scanner                                         */`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` * Context for iterate_dir callback when scanning snapshot directories.`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `struct ksmbd_vss_scan_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	struct dir_context ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	struct ksmbd_snapshot_list *list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	unsigned int max_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	int error;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` * ksmbd_vss_is_gmt_token() - Validate a @GMT token string`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` * @name: candidate string`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` * @namlen: length of the string`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` * Checks the format @GMT-YYYY.MM.DD-HH.MM.SS (exactly 24 chars).`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ` * Return: true if valid, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `VISIBLE_IF_KUNIT bool ksmbd_vss_is_gmt_token(const char *name, int namlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	if (namlen != KSMBD_VSS_GMT_TOKEN_LEN - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	/* @GMT-YYYY.MM.DD-HH.MM.SS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	return name[0] == '@' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	       name[1] == 'G' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	       name[2] == 'M' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	       name[3] == 'T' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	       name[4] == '-' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	       name[9] == '.' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	       name[12] == '.' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	       name[15] == '-' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	       name[18] == '.' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	       name[21] == '.';`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_vss_is_gmt_token);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ` * ksmbd_vss_parse_gmt_timestamp() - Parse @GMT token into Unix timestamp`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` * @gmt_token: token string (must pass ksmbd_vss_is_gmt_token())`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` * Return: Unix timestamp, or 0 on parse error`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `VISIBLE_IF_KUNIT u64 ksmbd_vss_parse_gmt_timestamp(const char *gmt_token)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	unsigned int year, month, day, hour, min, sec;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	/* @GMT-YYYY.MM.DD-HH.MM.SS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	ret = sscanf(gmt_token, "@GMT-%4u.%2u.%2u-%2u.%2u.%2u",`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		     &year, &month, &day, &hour, &min, &sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	if (ret != 6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	return (u64)mktime64(year, month, day, hour, min, sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_vss_parse_gmt_timestamp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` * ksmbd_vss_dirname_to_gmt() - Convert snapshot dir name to @GMT token`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` * @dirname:	snapshot directory name (various formats supported)`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * @namlen:	length of @dirname`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * @entry:	output snapshot entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` * Supports the following naming conventions:`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` *   - @GMT-YYYY.MM.DD-HH.MM.SS (pass-through)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` *   - YYYY-MM-DD_HH:MM:SS (common btrfs snapper format)`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` *   - YYYY-MM-DD-HHMMSS (simple)`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ` *   - YYYY-MM-DD (date only, time defaults to 00:00:00)`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ` * Return: 0 on success, -EINVAL if the name cannot be parsed`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `VISIBLE_IF_KUNIT int ksmbd_vss_dirname_to_gmt(const char *dirname, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `				    struct ksmbd_snapshot_entry *entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	unsigned int year, month, day, hour = 0, min = 0, sec = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	/* Already a @GMT token */`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	if (ksmbd_vss_is_gmt_token(dirname, namlen)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [MEM_BOUNDS|] `		memcpy(entry->gmt_token, dirname,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00223 [NONE] `		       KSMBD_VSS_GMT_TOKEN_LEN - 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		entry->gmt_token[KSMBD_VSS_GMT_TOKEN_LEN - 1] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		entry->timestamp =`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `			ksmbd_vss_parse_gmt_timestamp(dirname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	/* Try YYYY-MM-DD_HH:MM:SS (snapper format) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	ret = sscanf(dirname, "%4u-%2u-%2u_%2u:%2u:%2u",`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		     &year, &month, &day, &hour, &min, &sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	if (ret == 6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [ERROR_PATH|] `		goto format;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	/* Try YYYY-MM-DD-HHMMSS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	ret = sscanf(dirname, "%4u-%2u-%2u-%2u%2u%2u",`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		     &year, &month, &day, &hour, &min, &sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	if (ret == 6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [ERROR_PATH|] `		goto format;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	/* Try YYYY-MM-DD (date only) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	hour = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	min = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	sec = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	ret = sscanf(dirname, "%4u-%2u-%2u",`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		     &year, &month, &day);`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	if (ret == 3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [ERROR_PATH|] `		goto format;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `format:`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	/* Basic sanity checks */`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	if (year < 1970 || year > 9999 || month < 1 || month > 12 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	    day < 1 || day > 31 || hour > 23 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	    min > 59 || sec > 59)`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [MEM_BOUNDS|] `	snprintf(entry->gmt_token, KSMBD_VSS_GMT_TOKEN_LEN,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00261 [NONE] `		 "@GMT-%04u.%02u.%02u-%02u.%02u.%02u",`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		 year, month, day, hour, min, sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	entry->timestamp =`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		(u64)mktime64(year, month, day, hour, min, sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_vss_dirname_to_gmt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `/*  Btrfs backend (.snapshots/ directory)                              */`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `static bool ksmbd_vss_btrfs_filldir(struct dir_context *ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `				    const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `static int ksmbd_vss_btrfs_filldir(struct dir_context *ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `				   const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `				   loff_t offset, u64 ino,`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `				   unsigned int d_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	struct ksmbd_vss_scan_ctx *scan_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	struct ksmbd_snapshot_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	scan_ctx = container_of(ctx, struct ksmbd_vss_scan_ctx, ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	/* Skip . and .. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	if (namlen <= 2 && name[0] == '.' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	    (namlen == 1 || name[1] == '.'))`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [ERROR_PATH|] `		goto cont;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	/* Only interested in directories */`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	if (d_type != DT_DIR && d_type != DT_UNKNOWN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [ERROR_PATH|] `		goto cont;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	if (scan_ctx->list->count >= scan_ctx->max_entries)`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [ERROR_PATH|] `		goto stop;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00299 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	entry = &scan_ctx->list->entries[scan_ctx->list->count];`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	if (ksmbd_vss_dirname_to_gmt(name, namlen, entry))`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [ERROR_PATH|] `		goto cont;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	scan_ctx->list->count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `cont:`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `stop:`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [ERROR_PATH|] `	return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00317 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ` * ksmbd_vss_scan_snap_dir() - Scan a snapshot directory for entries`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ` * @snap_dir_path:	Full path to the snapshot directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ` * @list:		Output snapshot list`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `static int ksmbd_vss_scan_snap_dir(const char *snap_dir_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `				   struct ksmbd_snapshot_list *list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	struct path snap_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	struct ksmbd_vss_scan_ctx scan_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `	ret = kern_path(snap_dir_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			LOOKUP_FOLLOW | LOOKUP_DIRECTORY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			&snap_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	filp = dentry_open(&snap_path, O_RDONLY | O_DIRECTORY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `			   current_cred());`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	path_put(&snap_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	if (IS_ERR(filp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		return PTR_ERR(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	list->entries = kvcalloc(KSMBD_VSS_MAX_SNAPSHOTS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `				 sizeof(*list->entries),`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `				 KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	if (!list->entries) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00353 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	list->count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	memset(&scan_ctx, 0, sizeof(scan_ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	scan_ctx.list = list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	scan_ctx.max_entries = KSMBD_VSS_MAX_SNAPSHOTS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	set_ctx_actor(&scan_ctx.ctx, ksmbd_vss_btrfs_filldir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	ret = iterate_dir(filp, &scan_ctx.ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	if (ret < 0 && ret != -ENOSPC) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		kvfree(list->entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `		list->entries = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		list->count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ` * ksmbd_vss_btrfs_enumerate() - Enumerate btrfs snapshots`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ` * @share_path:	Share root path`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ` * @list:	Output snapshot list`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` * Looks for snapshots in share_path/.snapshots/ (snapper convention).`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `static int ksmbd_vss_btrfs_enumerate(const char *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `				     struct ksmbd_snapshot_list *list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	char *snap_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	snap_dir = kasprintf(KSMBD_DEFAULT_GFP, "%s/.snapshots",`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			     share_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	if (!snap_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	ret = ksmbd_vss_scan_snap_dir(snap_dir, list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	kfree(snap_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` * ksmbd_vss_btrfs_resolve() - Resolve @GMT token for btrfs snapshots`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ` * @share_path:	Share root path`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ` * @gmt_token:	@GMT token to resolve`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] ` * @resolved:	Output buffer for resolved path`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] ` * @len:	Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] ` * Return: 0 on success, -ENOENT if no matching snapshot`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `static int ksmbd_vss_btrfs_resolve(const char *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `				   const char *gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `				   char *resolved, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	struct ksmbd_snapshot_list list = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	char *snap_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	snap_dir = kasprintf(KSMBD_DEFAULT_GFP, "%s/.snapshots",`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `			     share_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	if (!snap_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	ret = ksmbd_vss_scan_snap_dir(snap_dir, &list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		kfree(snap_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	for (i = 0; i < list.count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		if (!strncmp(list.entries[i].gmt_token, gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `			     KSMBD_VSS_GMT_TOKEN_LEN - 1)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [MEM_BOUNDS|] `			snprintf(resolved, len,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00434 [NONE] `				 "%s/.snapshots/%s/snapshot",`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `				 share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `				 list.entries[i].gmt_token);`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `			ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	kvfree(list.entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	kfree(snap_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `static struct ksmbd_snapshot_backend ksmbd_vss_btrfs_backend = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	.name		= "btrfs",`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	.enumerate	= ksmbd_vss_btrfs_enumerate,`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	.resolve_path	= ksmbd_vss_btrfs_resolve,`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `/*  ZFS backend (.zfs/snapshot/ directory)                             */`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ` * ksmbd_vss_zfs_enumerate() - Enumerate ZFS snapshots`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ` * @share_path:	Share root path`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ` * @list:	Output snapshot list`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ` * Looks for snapshots in share_path/.zfs/snapshot/.`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `static int ksmbd_vss_zfs_enumerate(const char *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `				   struct ksmbd_snapshot_list *list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	char *snap_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	snap_dir = kasprintf(KSMBD_DEFAULT_GFP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `			     "%s/.zfs/snapshot", share_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	if (!snap_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	ret = ksmbd_vss_scan_snap_dir(snap_dir, list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	kfree(snap_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ` * ksmbd_vss_zfs_resolve() - Resolve @GMT token for ZFS snapshots`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ` * @share_path:	Share root path`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ` * @gmt_token:	@GMT token to resolve`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ` * @resolved:	Output buffer for resolved path`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ` * @len:	Size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ` * Return: 0 on success, -ENOENT if no matching snapshot`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `static int ksmbd_vss_zfs_resolve(const char *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `				 const char *gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `				 char *resolved, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	struct ksmbd_snapshot_list list = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	char *snap_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	snap_dir = kasprintf(KSMBD_DEFAULT_GFP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `			     "%s/.zfs/snapshot", share_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	if (!snap_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	ret = ksmbd_vss_scan_snap_dir(snap_dir, &list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		kfree(snap_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	for (i = 0; i < list.count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `		if (!strncmp(list.entries[i].gmt_token, gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `			     KSMBD_VSS_GMT_TOKEN_LEN - 1)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [MEM_BOUNDS|] `			snprintf(resolved, len,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00516 [NONE] `				 "%s/.zfs/snapshot/%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `				 share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `				 list.entries[i].gmt_token);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `			ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	kvfree(list.entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	kfree(snap_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `static struct ksmbd_snapshot_backend ksmbd_vss_zfs_backend = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	.name		= "zfs",`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	.enumerate	= ksmbd_vss_zfs_enumerate,`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	.resolve_path	= ksmbd_vss_zfs_resolve,`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `/*  Generic backend (configurable snapshot directory)                   */`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ` * The generic backend scans a .snapshots/ directory as a fallback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] ` * It shares the same scan logic as the btrfs backend but can be`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ` * extended to support a configurable snapshot path in the future.`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `static struct ksmbd_snapshot_backend ksmbd_vss_generic_backend = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	.name		= "generic",`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	.enumerate	= ksmbd_vss_btrfs_enumerate,`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	.resolve_path	= ksmbd_vss_btrfs_resolve,`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `/*  FSCTL handler: FSCTL_SRV_ENUMERATE_SNAPSHOTS                       */`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ` * ksmbd_vss_enumerate_snapshots() - FSCTL handler for snapshot enum`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ` * @work:	    SMB work context`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ` * @id:		    Volatile file ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] ` * @in_buf:	    Input buffer (unused for this FSCTL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ` * @in_buf_len:    Input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ` * @max_out_len:   Maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] ` * @rsp:	    Pointer to IOCTL response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ` * @out_len:	    Output: number of bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ` * Builds the SRV_SNAPSHOT_ARRAY response per MS-SMB2 2.2.32.2.`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `static int ksmbd_vss_enumerate_snapshots(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	struct ksmbd_tree_connect *tcon = work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	struct srv_snapshot_array *snap_array;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	struct ksmbd_snapshot_list snap_list = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	struct ksmbd_snapshot_backend *be;`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	unsigned int array_size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	unsigned int i, returned = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	__le16 *utf16_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	int ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	if (!tcon || !tcon->share_conf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [ERROR_PATH|] `		pr_err_ratelimited("VSS: no tree connection\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00588 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00589 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	share = tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	if (!share->path) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [ERROR_PATH|] `		pr_err_ratelimited("VSS: share has no path\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00594 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00595 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	/* Need at least the header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	if (max_out_len < sizeof(struct srv_snapshot_array))`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	 * Try each backend until one succeeds.  We collect the`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	 * backend list under the lock but call the potentially`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	 * blocking enumerate callback outside the lock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [LOCK|] `	mutex_lock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00607 [NONE] `	list_for_each_entry(be, &vss_backend_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		int (*enumerate_fn)(const char *,`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `				    struct ksmbd_snapshot_list *);`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		enumerate_fn = be->enumerate;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [LOCK|] `		mutex_unlock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		ret = enumerate_fn(share->path, &snap_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		if (!ret && snap_list.count > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [ERROR_PATH|] `			goto found;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00617 [NONE] `		/* Reset for next attempt */`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `		if (!ret && snap_list.entries) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `			kvfree(snap_list.entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `			snap_list.entries = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `			snap_list.count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [LOCK|] `		mutex_lock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00626 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [LOCK|] `	mutex_unlock(&vss_backend_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00628 [NONE] `found:`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	 * Per MS-SMB2: if no snapshots exist, return success`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	 * with zero counts rather than an error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	snap_array =`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		(struct srv_snapshot_array *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	if (ret || snap_list.count == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		snap_array->number_of_snapshots =`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `			cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `		snap_array->number_of_snapshots_returned =`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `			cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `		snap_array->snapshot_array_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `			cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `		*out_len = sizeof(struct srv_snapshot_array);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	 * Calculate the array size needed:`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	 * Each @GMT token is 24 chars + NUL in UTF-16LE = 50 bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	 * Plus a final NUL terminator (2 bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	array_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		snap_list.count * (KSMBD_VSS_GMT_TOKEN_LEN * 2) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `		sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	 * If the buffer is too small for the data, return just`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	 * the header with total count and required size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	if (max_out_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	    sizeof(struct srv_snapshot_array) + array_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `		snap_array->number_of_snapshots =`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `			cpu_to_le32(snap_list.count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		snap_array->number_of_snapshots_returned =`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `			cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `		snap_array->snapshot_array_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `			cpu_to_le32(array_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `		*out_len = sizeof(struct srv_snapshot_array);`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `		kvfree(snap_list.entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	/* Write the UTF-16LE snapshot strings */`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	utf16_ptr = (__le16 *)(snap_array + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `	for (i = 0; i < snap_list.count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `		const char *gmt = snap_list.entries[i].gmt_token;`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `		unsigned int j;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `		/* Convert ASCII @GMT token to UTF-16LE */`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `		for (j = 0; j < KSMBD_VSS_GMT_TOKEN_LEN - 1; j++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `			utf16_ptr[j] = cpu_to_le16((u16)gmt[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `		/* NUL terminator */`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `		utf16_ptr[KSMBD_VSS_GMT_TOKEN_LEN - 1] =`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `			cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `		utf16_ptr += KSMBD_VSS_GMT_TOKEN_LEN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `		returned++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	/* Final NUL terminator for the array */`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	*utf16_ptr = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	snap_array->number_of_snapshots =`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		cpu_to_le32(snap_list.count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	snap_array->number_of_snapshots_returned =`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `		cpu_to_le32(returned);`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	snap_array->snapshot_array_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `		cpu_to_le32(array_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `	*out_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `		sizeof(struct srv_snapshot_array) + array_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `	kvfree(snap_list.entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `/*  FSCTL registration                                                 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `static struct ksmbd_fsctl_handler vss_enumerate_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	.ctl_code = FSCTL_SRV_ENUMERATE_SNAPSHOTS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	.handler  = ksmbd_vss_enumerate_snapshots,`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `/*  Init / Exit                                                        */`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ` * ksmbd_vss_init() - Initialize VSS subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] ` * Registers built-in snapshot backends and the FSCTL handler.`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `int ksmbd_vss_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	ret = ksmbd_vss_register_backend(&ksmbd_vss_btrfs_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	ret = ksmbd_vss_register_backend(&ksmbd_vss_zfs_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [ERROR_PATH|] `		goto err_unreg_btrfs;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00741 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	ret = ksmbd_vss_register_backend(&ksmbd_vss_generic_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [ERROR_PATH|] `		goto err_unreg_zfs;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00745 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `	ret = ksmbd_register_fsctl(&vss_enumerate_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [ERROR_PATH|] `		goto err_unreg_generic;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00749 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	ksmbd_debug(SMB, "VSS subsystem initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `err_unreg_generic:`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	ksmbd_vss_unregister_backend(&ksmbd_vss_generic_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `err_unreg_zfs:`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	ksmbd_vss_unregister_backend(&ksmbd_vss_zfs_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `err_unreg_btrfs:`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	ksmbd_vss_unregister_backend(&ksmbd_vss_btrfs_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] ` * ksmbd_vss_exit() - Tear down VSS subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `void ksmbd_vss_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	ksmbd_unregister_fsctl(&vss_enumerate_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	ksmbd_vss_unregister_backend(&ksmbd_vss_generic_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	ksmbd_vss_unregister_backend(&ksmbd_vss_zfs_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	ksmbd_vss_unregister_backend(&ksmbd_vss_btrfs_backend);`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
