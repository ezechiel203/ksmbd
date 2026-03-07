# Line-by-line Review: src/fs/ksmbd_notify.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2024 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   SMB2 CHANGE_NOTIFY implementation using Linux fsnotify.`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   Design: one fsnotify_mark per (group, inode).  Multiple`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   CHANGE_NOTIFY requests on the same directory are tracked`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   via fp->blocked_works.  When fsnotify fires, the handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   walks blocked_works and completes all matching entries.`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   Only the first watch per inode gets a real fsnotify mark;`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *   subsequent watches on the same inode piggyback on it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/fsnotify_backend.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "glob.h"`
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
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `/* Forward declaration (defined later in this file) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `static void ksmbd_notify_send_delete_pending(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * fsnotify group flags differ across kernel versions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#ifdef FSNOTIFY_GROUP_NOFS`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#define KSMBD_FSNOTIFY_GROUP_FLAGS FSNOTIFY_GROUP_NOFS`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define KSMBD_FSNOTIFY_GROUP_FLAGS FSNOTIFY_GROUP_USER`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `/* Global fsnotify group for all ksmbd watches */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `static struct fsnotify_group *ksmbd_notify_group;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `/* Limit total concurrent notify watches server-wide */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define KSMBD_MAX_NOTIFY_WATCHES	4096`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `/* Limit per-connection to prevent memory DoS */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define KSMBD_MAX_NOTIFY_WATCHES_PER_CONN	1024`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [LIFETIME|] `static atomic_t notify_watch_count = ATOMIC_INIT(0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * Mask of all fsnotify events we care about.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define KSMBD_FSNOTIFY_MASK	(FS_CREATE | FS_DELETE | FS_MODIFY |	\`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `				 FS_MOVED_FROM | FS_MOVED_TO |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `				 FS_ATTRIB | FS_ACCESS |		\`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `				 FS_EVENT_ON_CHILD)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * FILE_NOTIFY_INFORMATION on-wire structure (MS-FSCC 2.4.42).`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `struct file_notify_information {`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	__le32 Action;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	__le16 FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `/*  fsnotify event  ->  SMB2 completion-filter mapping                 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `VISIBLE_IF_KUNIT u32 ksmbd_fsnotify_to_smb2_filter(u32 mask)`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	u32 filter = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	 * On Windows, file/directory creation and deletion trigger`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	 * notifications for ALL active completion filters (NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	 * ATTRIBUTES, SIZE, CREATION, LAST_WRITE, etc.).  Map`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	 * FS_CREATE, FS_DELETE, and FS_MOVED to a broad set of SMB2`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	 * filters so the event matches the watch regardless of which`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	 * specific filter the client requested.`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define KSMBD_NOTIFY_ALL_FILTERS 0xFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	if (mask & FS_CREATE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		filter |= KSMBD_NOTIFY_ALL_FILTERS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	if (mask & FS_DELETE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		filter |= KSMBD_NOTIFY_ALL_FILTERS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	if (mask & FS_MODIFY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		filter |= FILE_NOTIFY_CHANGE_LAST_WRITE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			  FILE_NOTIFY_CHANGE_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	if (mask & FS_ATTRIB)`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `		filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES |`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `			  FILE_NOTIFY_CHANGE_SECURITY |`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `			  FILE_NOTIFY_CHANGE_EA;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	if (mask & FS_MOVED_FROM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `		filter |= KSMBD_NOTIFY_ALL_FILTERS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	if (mask & FS_MOVED_TO)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `		filter |= KSMBD_NOTIFY_ALL_FILTERS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	if (mask & FS_ACCESS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		filter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	if (mask & FS_ISDIR) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		if (filter & FILE_NOTIFY_CHANGE_FILE_NAME) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `			filter &= ~FILE_NOTIFY_CHANGE_FILE_NAME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			filter |= FILE_NOTIFY_CHANGE_DIR_NAME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	return filter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_fsnotify_to_smb2_filter);`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `VISIBLE_IF_KUNIT u32 ksmbd_fsnotify_to_action(u32 mask)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	if (mask & FS_CREATE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		return FILE_ACTION_ADDED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	if (mask & FS_DELETE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		return FILE_ACTION_REMOVED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	if (mask & FS_MOVED_FROM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		return FILE_ACTION_RENAMED_OLD_NAME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	if (mask & FS_MOVED_TO)`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		return FILE_ACTION_RENAMED_NEW_NAME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	return FILE_ACTION_MODIFIED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_fsnotify_to_action);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `/*  Build FILE_NOTIFY_INFORMATION buffer and complete async work       */`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `static void ksmbd_notify_build_response(`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		struct ksmbd_notify_watch *watch,`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		u32 action,`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		const struct qstr *file_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	struct ksmbd_work *work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	struct smb2_notify_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	struct file_notify_information *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	int name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	int info_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	int total_rsp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	int uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	u8 *out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [LOCK|] `	spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00158 [NONE] `	work = watch->pending_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	if (!work || watch->completed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00161 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	watch->completed = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [LOCK|] `	spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	 * Reset IOV state.  The main dispatch loop may have called`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	 * encrypt_resp() which allocated work->tr_buf and modified`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	 * the IOV entries.  Clean up so we start fresh.`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	kfree(work->tr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	work->tr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	work->iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	work->iov_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [PROTO_GATE|] `	rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00179 [NONE] `	rsp->hdr.Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	name_bytes = file_name->len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	info_len = sizeof(struct file_notify_information) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `		   name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	if (info_len > (int)watch->output_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOTIFY_ENUM_DIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [PROTO_GATE|] `			__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00192 [PROTO_GATE|] `			SMB2_ERROR_STRUCTURE_SIZE2;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00193 [ERROR_PATH|] `		goto send;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00194 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [PROTO_GATE|] `	out = (u8 *)rsp + __SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00197 [NONE] `	      sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	      sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	      sizeof(rsp->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	info = (struct file_notify_information *)out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	uni_len = smbConvertToUTF16(info->FileName, file_name->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `				    file_name->len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `				    work->conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	if (uni_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		uni_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `		uni_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	info_len = sizeof(struct file_notify_information) + uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	if (info_len > (int)watch->output_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOTIFY_ENUM_DIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [PROTO_GATE|] `			__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00218 [PROTO_GATE|] `			SMB2_ERROR_STRUCTURE_SIZE2;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [ERROR_PATH|] `		goto send;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00220 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	info->NextEntryOffset = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	info->Action = cpu_to_le32(action);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	info->FileNameLength = cpu_to_le32(uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00227 [NONE] `	rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	rsp->OutputBufferOffset = cpu_to_le16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		sizeof(struct smb2_hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		sizeof(rsp->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(info_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [PROTO_GATE|] `		__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00237 [NONE] `		sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		sizeof(rsp->OutputBufferLength) + info_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `send:`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	if (ksmbd_iov_pin_rsp(work, rsp, total_rsp_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	 * Sign the response if the session requires it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	 * Per MS-SMB2 3.3.4.4, the final async response SHOULD`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	 * be signed.  Signing must happen before encryption.`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	    (work->sess->sign ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	     (work->request_buf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [PROTO_GATE|] `	      work->conn->ops->is_sign_req(work, SMB2_CHANGE_NOTIFY_HE))))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00254 [NONE] `		work->conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	if (work->sess && work->sess->enc && work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	    work->conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		int rc = work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [ERROR_PATH|] `			pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00262 [NONE] `				"ksmbd: notify encrypt failed: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `				rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DATA_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	 * The original smb2_notify handler set send_no_response = 1`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	 * to prevent the main dispatch loop from sending a response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	 * Clear it so ksmbd_conn_write actually transmits.`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	if (watch->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [LOCK|] `		spin_lock(&watch->fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00278 [NONE] `		list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [LOCK|] `		spin_unlock(&watch->fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00280 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	/* Remove from async_requests list before freeing */`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [LOCK|] `	spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00284 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [LOCK|] `	spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	 * Only dequeue from the request list if this work was`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	 * a real request (has a request_buf).  Compound-spawned`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	 * async work structs were never queued or counted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (work->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	/* Decrement outstanding async count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [LIFETIME|] `		atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	 * Clear pending_work so the watch can accept a new NOTIFY`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	 * request.  Do NOT NULL out fp or destroy the mark -- the`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	 * watch persists for the lifetime of the file handle so`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	 * that events between this completion and the next NOTIFY`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	 * are buffered (MS-SMB2 3.3.1.6).`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [LOCK|] `	spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00307 [NONE] `	watch->pending_work = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	watch->completed = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [LOCK|] `	spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	/* Drop the extra session reference taken in smb2_notify */`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `		ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ` * ksmbd_notify_complete_piggyback() - complete a piggyback notify work`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ` * @work: the async work item from fp->blocked_works`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ` * @action: FILE_ACTION_* constant`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ` * @file_name: event filename`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ` * Completes a CHANGE_NOTIFY work that does NOT own an fsnotify mark`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ` * (a "piggyback" watch).  These works get completed when the real`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ` * mark's event fires.`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `static void ksmbd_notify_complete_piggyback(`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		u32 action,`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		const struct qstr *file_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	struct smb2_notify_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	struct file_notify_information *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `	int info_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	int total_rsp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	int uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	u8 *out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	u32 output_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	struct smb2_notify_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	output_buf_len = le32_to_cpu(req->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [PROTO_GATE|] `	rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00347 [NONE] `	rsp->hdr.Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	info_len = sizeof(struct file_notify_information) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		   file_name->len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	if (info_len > (int)output_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOTIFY_ENUM_DIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00354 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [PROTO_GATE|] `			__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00359 [PROTO_GATE|] `			SMB2_ERROR_STRUCTURE_SIZE2;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00360 [ERROR_PATH|] `		goto send;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00361 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [PROTO_GATE|] `	out = (u8 *)rsp + __SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00364 [NONE] `	      sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	      sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	      sizeof(rsp->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	info = (struct file_notify_information *)out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	uni_len = smbConvertToUTF16(info->FileName, file_name->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `				    file_name->len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `				    work->conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	if (uni_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `		uni_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `		uni_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	info_len = sizeof(struct file_notify_information) + uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	if (info_len > (int)output_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOTIFY_ENUM_DIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00380 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [PROTO_GATE|] `			__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [PROTO_GATE|] `			SMB2_ERROR_STRUCTURE_SIZE2;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00386 [ERROR_PATH|] `		goto send;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00387 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	info->NextEntryOffset = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	info->Action = cpu_to_le32(action);`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	info->FileNameLength = cpu_to_le32(uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00394 [NONE] `	rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	rsp->OutputBufferOffset = cpu_to_le16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `		sizeof(struct smb2_hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `		sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `		sizeof(rsp->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(info_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [PROTO_GATE|] `		__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00404 [NONE] `		sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `		sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		sizeof(rsp->OutputBufferLength) + info_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `send:`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	if (ksmbd_iov_pin_rsp(work, rsp, total_rsp_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00411 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	/* Sign if required (before encryption) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	    (work->sess->sign ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	     (work->request_buf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [PROTO_GATE|] `	      work->conn->ops->is_sign_req(work, SMB2_CHANGE_NOTIFY_HE))))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00417 [NONE] `		work->conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	if (work->sess && work->sess->enc && work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	    work->conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		int rc = work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DATA_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	/* Clear send_no_response so ksmbd_conn_write transmits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	/* Remove from async_requests list before freeing */`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [LOCK|] `	spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00433 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [LOCK|] `	spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	 * Only dequeue from the request list if this work was`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	 * a real request (has a request_buf).  Compound-spawned`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	 * async work structs were never queued or counted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	if (work->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `	/* Decrement outstanding async count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [LIFETIME|] `		atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	/* Drop the extra session reference taken in smb2_notify */`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `		ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `/*  fsnotify callbacks                                                 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `static int ksmbd_notify_handle_event(`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		struct fsnotify_group *group,`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `		u32 mask,`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		const void *data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		int data_type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `		struct inode *dir,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		const struct qstr *file_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		u32 cookie,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		struct fsnotify_iter_info *iter_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	struct fsnotify_mark *inode_mark = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	struct ksmbd_notify_watch *watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	struct ksmbd_work *work, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	u32 smb2_filter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	u32 action;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	int type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	LIST_HEAD(complete_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	for (type = 0; type < FSNOTIFY_ITER_TYPE_COUNT; type++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `		struct fsnotify_mark *m;`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		m = fsnotify_iter_mark(iter_info, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `		if (m && m->group == group) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `			inode_mark = m;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	if (!inode_mark)`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	watch = container_of(inode_mark,`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `			     struct ksmbd_notify_watch, mark);`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	 * FS_DELETE_SELF: the watched directory itself was deleted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [PROTO_GATE|] `	 * Complete any pending NOTIFY with STATUS_DELETE_PENDING.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00497 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	if (mask & FS_DELETE_SELF) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		struct ksmbd_work *del_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [LOCK|] `		spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00502 [NONE] `		del_work = watch->pending_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `		if (!del_work || watch->completed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [LOCK|] `			spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00505 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		watch->completed = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		watch->pending_work = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `		if (watch->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [LOCK|] `			spin_lock(&watch->fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00513 [NONE] `			list_del_init(&del_work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [LOCK|] `			spin_unlock(&watch->fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00515 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `		ksmbd_notify_send_delete_pending(del_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [LOCK|] `	spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00522 [NONE] `	if (watch->completed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00524 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	fp = watch->fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00529 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	 * Filter out self-events on the watched directory.`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	 * FS_EVENT_ON_CHILD fires for both the child AND the parent`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	 * directory inode.  We only want child events.`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `		struct inode *event_inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `		event_inode = fsnotify_data_inode(data, data_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `		if (event_inode && fp->filp &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `		    event_inode == file_inode(fp->filp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [LOCK|] `			spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00544 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	smb2_filter = ksmbd_fsnotify_to_smb2_filter(mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	if (!file_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00551 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	action = ksmbd_fsnotify_to_action(mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	 * If the event matches the filter and there's a pending`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	 * work, complete it.  Otherwise, buffer the change so it`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	 * can be delivered on the next NOTIFY request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	if (smb2_filter & watch->completion_filter) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `		if (watch->pending_work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [LOCK|] `			spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00564 [NONE] `			ksmbd_notify_build_response(watch, action,`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `						    file_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `			 * No pending NOTIFY -- buffer the event.`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `			 * Limit buffered changes to prevent DoS.`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `			if (watch->buffered_count < 256) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `				struct ksmbd_notify_change *chg, *dup;`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `				bool found = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `				 * H.5: Coalesce duplicate events.`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `				 * Before adding, check if an event with the`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `				 * same filename and action already exists in`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `				 * the buffered list.  If so, drop the`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `				 * duplicate to avoid redundant notifications.`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `				list_for_each_entry(dup,`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `						    &watch->buffered_changes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `						    entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `					if (dup->action == action &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `					    dup->name_len == file_name->len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `					    !memcmp(dup->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `						    file_name->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `						    file_name->len)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `						found = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `						break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `				if (!found) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [MEM_BOUNDS|] `					chg = kzalloc(sizeof(*chg),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00597 [NONE] `						      GFP_ATOMIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `					if (chg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `						chg->name = kstrndup(`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `							file_name->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `							file_name->len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `							GFP_ATOMIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `						if (chg->name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `							chg->name_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `								file_name->len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `							chg->action = action;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `							list_add_tail(`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `								&chg->entry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `								&watch->buffered_changes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `							watch->buffered_count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `						} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `							kfree(chg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [LOCK|] `			spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00618 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00621 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	 * Also complete any piggyback watches on the same fp.`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	 * Re-read watch->fp under the lock since build_response`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	 * may have NULLed it when completing the primary watch.`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [LOCK|] `	spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00629 [NONE] `	fp = watch->fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [LOCK|] `	spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [LOCK|] `	spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00636 [NONE] `	list_for_each_entry_safe(work, tmp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `				 &fp->blocked_works, fp_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `		struct smb2_notify_req *nreq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `		u32 cf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `		hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [PROTO_GATE|] `		if (hdr->Command != SMB2_CHANGE_NOTIFY)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00644 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `		nreq = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `		cf = le32_to_cpu(nreq->CompletionFilter);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `		if (!(smb2_filter & cf))`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `		list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		list_add(&work->fp_entry, &complete_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [LOCK|] `	spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	list_for_each_entry_safe(work, tmp, &complete_list, fp_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [LIFETIME|] `		atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00659 [NONE] `		if (work->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [LIFETIME|] `			atomic_dec(&work->conn->notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00661 [NONE] `		ksmbd_notify_complete_piggyback(work, action, file_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `static void ksmbd_notify_free_mark(struct fsnotify_mark *mark)`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	struct ksmbd_notify_watch *watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	struct ksmbd_notify_change *chg, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	watch = container_of(mark,`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `			     struct ksmbd_notify_watch, mark);`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	/* Free any buffered changes that were never delivered */`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	list_for_each_entry_safe(chg, tmp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `				 &watch->buffered_changes, entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `		list_del(&chg->entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `		kfree(chg->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `		kfree(chg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [LIFETIME|] `	atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00684 [NONE] `	if (watch->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [LIFETIME|] `		atomic_dec(&watch->conn->notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00686 [NONE] `	kfree(watch);`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `static const struct fsnotify_ops ksmbd_notify_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	.handle_event	= ksmbd_notify_handle_event,`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	.free_mark	= ksmbd_notify_free_mark,`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `/*  Public API                                                         */`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `int ksmbd_notify_add_watch(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `			   struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `			   u32 completion_filter,`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `			   bool watch_tree,`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `			   u32 output_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `			   void **cancel_argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `	struct ksmbd_notify_watch *watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	u32 fs_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	if (!fp || !fp->filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	if (!S_ISDIR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [ERROR_PATH|] `		return -ENOTDIR;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	if (!ksmbd_notify_group)`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [ERROR_PATH|] `		return -ENODEV;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	 * Reuse the existing per-handle watch if present.`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	 * This persists across NOTIFY/CANCEL cycles so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	 * events occurring between cancel and the next NOTIFY`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	 * are buffered and can be delivered immediately.`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	watch = fp->notify_watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `	if (watch) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [LOCK|] `		spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00729 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `		/* Update parameters for the new request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		watch->completion_filter = completion_filter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `		watch->watch_tree = watch_tree;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `		watch->output_buf_len = output_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `		watch->completed = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `		 * Check for buffered changes.  If present, we can`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `		 * respond immediately without going async.`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `		 * First, check if the total buffered data exceeds the`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `		 * client's output buffer.  Per MS-SMB2 3.3.4.4, when`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `		 * accumulated changes cannot fit in the buffer, the`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [PROTO_GATE|] `		 * server returns STATUS_NOTIFY_ENUM_DIR.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00744 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		if (!list_empty(&watch->buffered_changes)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `			struct ksmbd_notify_change *chg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `			size_t total_size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `			list_for_each_entry(chg, &watch->buffered_changes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `					    entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `				/* 12-byte header + filename in UTF-16,`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `				 * aligned to 4 bytes per entry */`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `				total_size += ALIGN(`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `					sizeof(struct file_notify_information) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `					chg->name_len * 2, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `			if (total_size > output_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `				/* Overflow: discard all and return ENUM_DIR */`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `				struct ksmbd_notify_change *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `				struct smb2_notify_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `				list_for_each_entry_safe(chg, tmp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `							 &watch->buffered_changes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `							 entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `					list_del(&chg->entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `					kfree(chg->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `					kfree(chg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `				watch->buffered_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [LOCK|] `				spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `				rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_NOTIFY_ENUM_DIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00774 [NONE] `				rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `				rsp->OutputBufferOffset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `				rsp->OutputBufferLength = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `				ksmbd_iov_pin_rsp(work, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [PROTO_GATE|] `					__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00779 [PROTO_GATE|] `					SMB2_ERROR_STRUCTURE_SIZE2);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00780 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `				if (cancel_argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `					cancel_argv[0] = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [ERROR_PATH|] `				return -EIOCBQUEUED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00784 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `		if (!list_empty(&watch->buffered_changes)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `			 * Flush ALL buffered changes into a single`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `			 * chained FILE_NOTIFY_INFORMATION response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `			struct ksmbd_notify_change *chg, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			struct smb2_notify_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `			struct file_notify_information *info, *prev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `			int uni_len, entry_len, total_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `			int total_rsp_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `			u8 *out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `			/* Detach the entire list under the lock */`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `			LIST_HEAD(changes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `			list_splice_init(&watch->buffered_changes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `					 &changes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `			watch->buffered_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [LOCK|] `			spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `			rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00808 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `			out = (u8 *)rsp +`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [PROTO_GATE|] `			      __SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00811 [NONE] `			      sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `			      sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `			      sizeof(rsp->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `			prev = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `			total_data = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `			list_for_each_entry_safe(chg, tmp, &changes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `						 entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `				info = (struct file_notify_information *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `					(out + total_data);`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `				uni_len = smbConvertToUTF16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `					info->FileName, chg->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `					chg->name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `					work->conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `				if (uni_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `					uni_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `				else`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `					uni_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `				entry_len = sizeof(*info) + uni_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `				/* Align to 4 bytes for NextEntryOffset */`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `				entry_len = ALIGN(entry_len, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `				info->Action = cpu_to_le32(chg->action);`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `				info->FileNameLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `					cpu_to_le32(uni_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `				info->NextEntryOffset = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `				/* Chain previous entry to this one */`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `				if (prev)`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `					prev->NextEntryOffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `						cpu_to_le32(`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `						(u8 *)info - (u8 *)prev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `				prev = info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `				total_data += entry_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `				list_del(&chg->entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `				kfree(chg->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `				kfree(chg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `			rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `			rsp->OutputBufferOffset = cpu_to_le16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `				sizeof(struct smb2_hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `				sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `				sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `				sizeof(rsp->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `			rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `				cpu_to_le32(total_data);`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `			total_rsp_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [PROTO_GATE|] `				__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00863 [NONE] `				sizeof(rsp->StructureSize) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `				sizeof(rsp->OutputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `				sizeof(rsp->OutputBufferLength) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `				total_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `			ksmbd_iov_pin_rsp(work, rsp, total_rsp_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `			if (cancel_argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `				cancel_argv[0] = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [ERROR_PATH|] `			return -EIOCBQUEUED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00873 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00875 [NONE] `		/* No buffered changes -- go async as usual */`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `		watch->pending_work = work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `		if (cancel_argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `			cancel_argv[0] = watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [LOCK|] `		spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00882 [NONE] `		list_add(&work->fp_entry, &fp->blocked_works);`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [LOCK|] `		spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	/* No existing watch -- create a new one */`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [LIFETIME|] `	if (atomic_inc_return(&notify_watch_count) >`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00890 [NONE] `	    KSMBD_MAX_NOTIFY_WATCHES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [LIFETIME|] `		atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00892 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00893 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	if (work->conn &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [LIFETIME|] `	    atomic_inc_return(&work->conn->notify_watch_count) >`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00897 [NONE] `	    KSMBD_MAX_NOTIFY_WATCHES_PER_CONN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [LIFETIME|] `		atomic_dec(&work->conn->notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00899 [LIFETIME|] `		atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00900 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00901 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [MEM_BOUNDS|] `	watch = kzalloc(sizeof(*watch), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00904 [NONE] `	if (!watch) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		if (work->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [LIFETIME|] `			atomic_dec(&work->conn->notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00907 [LIFETIME|] `		atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00908 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00909 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `	watch->fp = fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	watch->pending_work = work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	watch->conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	watch->completion_filter = completion_filter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	watch->watch_tree = watch_tree;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	watch->output_buf_len = output_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `	watch->completed = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `	spin_lock_init(&watch->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `	INIT_LIST_HEAD(&watch->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	INIT_LIST_HEAD(&watch->buffered_changes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	watch->buffered_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `	fsnotify_init_mark(&watch->mark, ksmbd_notify_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `	 * Always include FS_CREATE/FS_DELETE/FS_MOVED so we can`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `	 * determine the correct FILE_ACTION (ADDED/REMOVED/RENAMED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `	 * regardless of the completion filter.  On Windows, creation`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	 * and deletion trigger notifications for ALL active filters`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	 * (ATTRIBUTES, SIZE, CREATION, etc.).`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	fs_mask = FS_EVENT_ON_CHILD | FS_DELETE_SELF |`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		  FS_CREATE | FS_DELETE | FS_MOVED_FROM | FS_MOVED_TO;`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	if (watch_tree) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [PROTO_GATE|] `		 * H.6: SMB2_WATCH_TREE — recursive monitoring.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00938 [NONE] `		 * Include all event types for subtree watching.`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `		fs_mask |= FS_MODIFY | FS_ATTRIB;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `	if (completion_filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `		fs_mask |= FS_ATTRIB;`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	if (completion_filter &`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	    (FILE_NOTIFY_CHANGE_SIZE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	     FILE_NOTIFY_CHANGE_LAST_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `		fs_mask |= FS_MODIFY;`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	if (completion_filter & FILE_NOTIFY_CHANGE_LAST_ACCESS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `		fs_mask |= FS_ACCESS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	if (completion_filter & FILE_NOTIFY_CHANGE_CREATION)`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `		fs_mask |= FS_CREATE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `	if (completion_filter & FILE_NOTIFY_CHANGE_SECURITY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `		fs_mask |= FS_ATTRIB;`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	if (completion_filter & FILE_NOTIFY_CHANGE_EA)`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `		fs_mask |= FS_ATTRIB;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `	if (completion_filter &`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	    (FILE_NOTIFY_CHANGE_STREAM_NAME |`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	     FILE_NOTIFY_CHANGE_STREAM_SIZE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `	     FILE_NOTIFY_CHANGE_STREAM_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `		fs_mask |= FS_MODIFY;`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	watch->mark.mask = fs_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	ret = fsnotify_add_inode_mark(&watch->mark, inode, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	if (ret == -EEXIST) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `		 * A mark already exists for this inode from another`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `		 * file handle.  Piggyback on the existing mark.`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `		fsnotify_put_mark(&watch->mark);`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `		if (cancel_argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `			cancel_argv[0] = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [LOCK|] `		spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00976 [NONE] `		list_add(&work->fp_entry, &fp->blocked_works);`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [LOCK|] `		spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	} else if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00982 [NONE] `			"ksmbd: failed to add fsnotify mark: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `			ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `		fsnotify_put_mark(&watch->mark);`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `	/* Attach watch to the file handle for persistence */`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `	fp->notify_watch = watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `	if (cancel_argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `		cancel_argv[0] = watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [LOCK|] `	spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00995 [NONE] `	list_add(&work->fp_entry, &fp->blocked_works);`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [LOCK|] `	spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00997 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `void ksmbd_notify_cancel(void **argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `	struct ksmbd_notify_watch *watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `	struct ksmbd_work *work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	if (!argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	watch = argv[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	if (!watch) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `		 * Piggyback watch (no fsnotify mark of its own).`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `		 * argv[1] = work, argv[2] = fp.`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [PROTO_GATE|] `		 * Remove from fp->blocked_works and send STATUS_CANCELLED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01016 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `		work = argv[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		fp = argv[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `		if (!work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		/* Remove from fp->blocked_works if still linked */`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `		if (fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [LOCK|] `			spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01027 [NONE] `			if (!list_empty(&work->fp_entry))`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `				list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [LOCK|] `			spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01030 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [PROTO_GATE|] `		/* Build STATUS_CANCELLED response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01033 [NONE] `		kfree(work->tr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `		work->tr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `		work->iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `		work->iov_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `		work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `		rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [PROTO_GATE|] `		rsp_hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01043 [NONE] `		rsp_hdr->Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [PROTO_GATE|] `		rsp_hdr->Status = STATUS_CANCELLED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `		/* Sign if required (before encryption) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `		if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `		    (work->sess->sign ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `		     (work->request_buf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [PROTO_GATE|] `		      work->conn->ops->is_sign_req(work, SMB2_CHANGE_NOTIFY_HE))))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01051 [NONE] `			work->conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `		if (work->sess && work->sess->enc && work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `		    work->conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `			int rc = work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `			if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [ERROR_PATH|] `				pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01059 [NONE] `					"ksmbd: piggyback cancel encrypt failed: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `					rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `		ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `		/* Remove from async_requests list before freeing */`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [LOCK|] `		spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01067 [NONE] `		list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [LOCK|] `		spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `		 * Only dequeue from the request list if this work was`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `		 * a real request (has a request_buf).  Compound-spawned`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `		 * async work structs were never queued or counted.`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `		if (work->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `			ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [LIFETIME|] `		atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01079 [NONE] `		if (work->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [LIFETIME|] `			atomic_dec(&work->conn->notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `		/* Decrement outstanding async count */`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `		if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [LIFETIME|] `			atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `		/* Drop the extra session reference taken in smb2_notify */`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `			ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `		ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [LOCK|] `	spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01095 [NONE] `	work = watch->pending_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `	if (!work || watch->completed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01098 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	 * Do NOT set completed = true.  The watch persists for the`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	 * lifetime of the file handle.  Clear pending_work so the`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `	 * event handler knows no request is waiting, and reset`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	 * completed so the watch can accept a new NOTIFY request.`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `	watch->pending_work = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `	watch->completed = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [LOCK|] `	spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [PROTO_GATE|] `	 * Build a proper SMB2 error response with STATUS_CANCELLED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01112 [NONE] `	 * Use smb2_set_err_rsp() to format the error body correctly`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `	 * (StructureSize=9, ErrorContextCount, Reserved, ByteCount)`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `	 * and pin the response with the proper wire size (73 bytes).`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	 * The main dispatch loop may have already called`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	 * encrypt_resp() and set work->tr_buf.  Free it first`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	 * so we start with a clean IOV state.`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `	kfree(work->tr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	work->tr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	work->iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	work->iov_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	 * smb2_set_err_rsp uses send_no_response on pin failure,`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	 * so clear it first.  We will set it properly below.`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [PROTO_GATE|] `	 * Now set the async flags and STATUS_CANCELLED on the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01135 [NONE] `	 * response header.  smb2_set_err_rsp left the status`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	 * as whatever it was before (from init_smb2_rsp_hdr).`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [PROTO_GATE|] `	rsp_hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01140 [NONE] `	rsp_hdr->Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [PROTO_GATE|] `	rsp_hdr->Status = STATUS_CANCELLED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `		    "notify_cancel: flags=0x%x async_id=%llu mid=%llu cmd=0x%x iov_idx=%d iov_cnt=%d rfc1002=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `		    le32_to_cpu(rsp_hdr->Flags),`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `		    le64_to_cpu(rsp_hdr->Id.AsyncId),`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `		    le64_to_cpu(rsp_hdr->MessageId),`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `		    le16_to_cpu(rsp_hdr->Command),`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `		    work->iov_idx, work->iov_cnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `		    get_rfc1002_len(work->iov[0].iov_base));`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `	 * Sign the response if the session requires signing.`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `	 * Per MS-SMB2 3.3.4.4, the final async response SHOULD`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	 * be signed.  Signing must happen before encryption.`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	    (work->sess->sign ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `	     (work->request_buf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [PROTO_GATE|] `	      work->conn->ops->is_sign_req(work, SMB2_CHANGE_NOTIFY_HE))))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01161 [NONE] `		work->conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `	/* Encrypt if the session requires it */`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `	if (work->sess && work->sess->enc && work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `	    work->conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `		int rc = work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [ERROR_PATH|] `			pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01170 [NONE] `				"ksmbd: notify cancel encrypt failed: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `				rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `	if (watch->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [LOCK|] `		spin_lock(&watch->fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01178 [NONE] `		list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [LOCK|] `		spin_unlock(&watch->fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01180 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `	/* Remove from async_requests list before freeing */`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [LOCK|] `	spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01184 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [LOCK|] `	spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `	 * Only dequeue from the request list if this work was`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	 * a real request (has a request_buf).  Compound-spawned`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	 * async work structs were never queued or counted.`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `	if (work->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `	/* Decrement outstanding async count */`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `	if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [LIFETIME|] `		atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `	/* Drop the extra session reference taken in smb2_notify */`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `		ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	 * Do NOT destroy the mark or NULL out fp.  The watch`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	 * persists for the lifetime of the file handle so that`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `	 * events occurring after this cancel (and before the next`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	 * NOTIFY request) are buffered and can be delivered`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `	 * immediately (MS-SMB2 3.3.1.6).`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [PROTO_GATE|] ` * Helper: send STATUS_NOTIFY_CLEANUP for a single async work item`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01216 [NONE] ` * and free it.  Used during file close to terminate any outstanding`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] ` * async CHANGE_NOTIFY requests.`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `static void ksmbd_notify_send_cleanup(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	kfree(work->tr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	work->tr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `	work->iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `	work->iov_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [PROTO_GATE|] `	hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01232 [NONE] `	hdr->Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [PROTO_GATE|] `	hdr->Status = STATUS_NOTIFY_CLEANUP;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	/* Sign if required (before encryption) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `	    (work->sess->sign ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	     (work->request_buf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [PROTO_GATE|] `	      work->conn->ops->is_sign_req(work, SMB2_CHANGE_NOTIFY_HE))))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01240 [NONE] `		work->conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	if (work->sess && work->sess->enc &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	    work->encrypted && work->conn->ops->encrypt_resp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `		work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [LOCK|] `	spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01249 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [LOCK|] `	spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	 * Only dequeue if this work was counted in req_running.`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	 * Compound-spawned async_work has no request_buf and was`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `	 * never enqueued, so dequeuing would underflow req_running.`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	if (work->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `	if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [LIFETIME|] `		atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `		ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `void ksmbd_notify_cleanup_file(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	struct ksmbd_notify_watch *watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	struct ksmbd_work *work, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	LIST_HEAD(cleanup_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	if (!fp || !ksmbd_notify_group)`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	 * Handle the persistent per-handle watch first.`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	 * If there is a pending async work on the watch, complete`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [PROTO_GATE|] `	 * it with STATUS_NOTIFY_CLEANUP.  Then destroy the mark.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01283 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	watch = fp->notify_watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `	if (watch) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `		fp->notify_watch = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [LOCK|] `		spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01289 [NONE] `		work = watch->pending_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `		watch->pending_work = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `		watch->completed = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `		watch->fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `		if (work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `			/* Remove from blocked_works if still linked */`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [LOCK|] `			spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01298 [NONE] `			if (!list_empty(&work->fp_entry))`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `				list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [LOCK|] `			spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01301 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `			ksmbd_notify_send_cleanup(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `		fsnotify_destroy_mark(&watch->mark,`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `				      ksmbd_notify_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `	 * Clean up any piggyback watches (works on fp->blocked_works`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	 * that piggybacked on another handle's fsnotify mark).`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [LOCK|] `	spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01314 [NONE] `	list_for_each_entry_safe(work, tmp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `				 &fp->blocked_works, fp_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `		hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [PROTO_GATE|] `		if (hdr->Command != SMB2_CHANGE_NOTIFY)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01318 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `		list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `		list_add(&work->fp_entry, &cleanup_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [LOCK|] `	spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	list_for_each_entry_safe(work, tmp, &cleanup_list, fp_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `		list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [LIFETIME|] `		atomic_dec(&notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01328 [NONE] `		if (work->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [LIFETIME|] `			atomic_dec(&work->conn->notify_watch_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01330 [NONE] `		ksmbd_notify_send_cleanup(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `/*  Delete-pending notification                                        */`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [PROTO_GATE|] ` * Helper: send STATUS_DELETE_PENDING for a single async NOTIFY work`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01340 [NONE] ` * item and free it.  Very similar to ksmbd_notify_send_cleanup but`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [PROTO_GATE|] ` * uses STATUS_DELETE_PENDING instead of STATUS_NOTIFY_CLEANUP.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01342 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `static void ksmbd_notify_send_delete_pending(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `	work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	kfree(work->tr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `	work->tr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `	work->iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `	work->iov_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `	hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [PROTO_GATE|] `	hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01356 [NONE] `	hdr->Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [PROTO_GATE|] `	hdr->Status = STATUS_DELETE_PENDING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `	/* Sign if required (before encryption) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `	if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	    (work->sess->sign ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	     (work->request_buf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [PROTO_GATE|] `	      work->conn->ops->is_sign_req(work, SMB2_CHANGE_NOTIFY_HE))))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01364 [NONE] `		work->conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `	if (work->sess && work->sess->enc &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	    work->encrypted && work->conn->ops->encrypt_resp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `		work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [LOCK|] `	spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01373 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [LOCK|] `	spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `	 * Only dequeue if this work was counted in req_running.`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	 * Compound-spawned async_work has no request_buf and was`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	 * never enqueued, so dequeuing would underflow req_running.`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	if (work->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [LIFETIME|] `		atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `		ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] ` * ksmbd_notify_complete_delete_pending() - complete pending NOTIFY`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] ` *   watches on an inode that has become delete-pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] ` * @ci: ksmbd_inode whose directory is being deleted`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] ` * Called from __ksmbd_inode_close() when a handle with DELETE_ON_CLOSE`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] ` * is closed and the inode has S_DEL_ON_CLS or S_DEL_PENDING set.`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] ` * Iterates over all file pointers on the inode and completes any`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [PROTO_GATE|] ` * pending CHANGE_NOTIFY requests with STATUS_DELETE_PENDING.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01402 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] ` * This implements the Windows behavior where CHANGE_NOTIFY completes`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [PROTO_GATE|] ` * with STATUS_DELETE_PENDING as soon as the directory becomes`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01405 [NONE] ` * delete-pending (not when it is actually deleted).`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `void ksmbd_notify_complete_delete_pending(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `	struct ksmbd_notify_watch *watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `	struct ksmbd_work *work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `	if (!ksmbd_notify_group)`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `	 * Walk all file pointers on this inode.  For each one that`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `	 * has a notify watch with a pending work, complete it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `	 * We take m_lock for reading.  The caller (__ksmbd_inode_close)`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `	 * has already released m_lock before calling us, and we are`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `	 * safe to re-acquire it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01425 [NONE] `	list_for_each_entry(fp, &ci->m_fp_list, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `		watch = fp->notify_watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `		if (!watch)`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [LOCK|] `		spin_lock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01431 [NONE] `		work = watch->pending_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `		if (!work || watch->completed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [LOCK|] `			spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01434 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `		 * Mark as completed and clear pending_work.`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `		 * The watch persists (for cleanup_file later).`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `		watch->completed = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `		watch->pending_work = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [LOCK|] `		spin_unlock(&watch->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `		/* Remove from blocked_works */`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [LOCK|] `		spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01446 [NONE] `		if (!list_empty(&work->fp_entry))`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `			list_del_init(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [LOCK|] `		spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `		ksmbd_notify_send_delete_pending(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `/*  Module lifecycle                                                   */`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `/* ------------------------------------------------------------------ */`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `bool ksmbd_notify_enabled(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `	return ksmbd_notify_group != NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `int ksmbd_notify_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `	ksmbd_notify_group = fsnotify_alloc_group(&ksmbd_notify_ops,`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `						  KSMBD_FSNOTIFY_GROUP_FLAGS);`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `	if (IS_ERR(ksmbd_notify_group)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `		int err = PTR_ERR(ksmbd_notify_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `		ksmbd_notify_group = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [ERROR_PATH|] `		pr_err("ksmbd: failed to create fsnotify group: %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01473 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `	pr_info("ksmbd: CHANGE_NOTIFY subsystem initialised\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `void ksmbd_notify_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `	if (ksmbd_notify_group) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `		 * Drop the group reference.  fsnotify_put_group will`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `		 * internally call fsnotify_clear_marks_by_group to`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `		 * detach all marks.  Then wait for pending mark`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `		 * destruction to complete before returning to the`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `		 * caller (module unload), preventing use-after-free`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `		 * in fsnotify event delivery paths on kernel 6.18+.`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `		fsnotify_put_group(ksmbd_notify_group);`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `		fsnotify_wait_marks_destroyed();`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `		ksmbd_notify_group = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
