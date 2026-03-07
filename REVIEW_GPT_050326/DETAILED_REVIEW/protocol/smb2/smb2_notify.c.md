# Line-by-line Review: src/protocol/smb2/smb2_notify.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [PROTO_GATE|] ` *   smb2_notify.c - SMB2_CHANGE_NOTIFY handler`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * smb2_notify() - handler for smb2 notify request`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * @work:   smb work containing notify command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * Validates the CHANGE_NOTIFY request, installs an fsnotify watch`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [PROTO_GATE|] ` * on the target directory, and returns STATUS_PENDING.  The actual`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00028 [NONE] ` * response is sent asynchronously when a matching event arrives.`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `int smb2_notify(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	struct smb2_notify_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	struct smb2_notify_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	u32 completion_filter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	u32 output_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	bool watch_tree;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	void **argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	ksmbd_debug(SMB, "Received smb2 notify\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	 * Per MS-SMB2 3.3.5.19, CHANGE_NOTIFY may go async and`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	 * must be the last request in a compound chain.  If it is`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [PROTO_GATE|] `	 * not the last request (NextCommand is set), return`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [PROTO_GATE|] `	 * STATUS_INVALID_PARAMETER for the first request or`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `	 * STATUS_INTERNAL_ERROR for subsequent requests, matching`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [NONE] `	 * Windows behavior.`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [PROTO_GATE|] `	if (req->hdr.NextCommand) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [NONE] `		if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INTERNAL_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00062 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		u64 volatile_id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		u64 persistent_id = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `		if (work->next_smb2_rcv_hdr_off &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `		    !has_file_id(volatile_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `			volatile_id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `			persistent_id = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `		fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [ERROR_PATH|] `		pr_err_ratelimited("ksmbd: notify invalid FID\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00078 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00081 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	/* CHANGE_NOTIFY is only valid on directories */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	if (!S_ISDIR(file_inode(fp->filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00086 [NONE] `			"ksmbd: notify on non-directory\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00091 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	 * Per MS-SMB2 3.3.5.19, the handle must have been opened`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	 * with FILE_LIST_DIRECTORY access.  If not, return`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [PROTO_GATE|] `	 * STATUS_ACCESS_DENIED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	if (!(fp->daccess & FILE_LIST_DIRECTORY_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00100 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00103 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	 * If the CHANGE_NOTIFY subsystem is disabled (e.g.`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	 * fsnotify compat issue on kernel 6.18+):`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	 * - Standalone (non-compound) requests: return`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [PROTO_GATE|] `	 *   STATUS_NOT_SUPPORTED immediately.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00111 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	 * - Compound-chain requests (last in chain): proceed to`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	 *   the async setup path so the compound response includes`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [PROTO_GATE|] `	 *   a proper STATUS_PENDING interim.  No fsnotify watch is`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00115 [NONE] `	 *   installed; the cancel/cleanup path handles teardown.`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	 *   This satisfies the compound.interim1/interim3 tests.`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	if (!ksmbd_notify_enabled() && !work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00120 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00123 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	completion_filter =`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `		le32_to_cpu(req->CompletionFilter);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	output_buf_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		le32_to_cpu(req->OutputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	watch_tree =`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [PROTO_GATE|] `		le16_to_cpu(req->Flags) & SMB2_WATCH_TREE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	/* MS-SMB2 §3.3.5.19: CompletionFilter MUST be non-zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	if (!completion_filter) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00135 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00138 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [PROTO_GATE|] `	/* Set up async work for STATUS_PENDING */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00141 [MEM_BOUNDS|] `	argv = kmalloc(3 * sizeof(void *), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00142 [NONE] `	if (!argv) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00144 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00147 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	 * Initialize argv BEFORE setup_async_work, because once`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	 * setup_async_work registers the cancel callback, a`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [PROTO_GATE|] `	 * concurrent SMB2_CANCEL on another kworker can invoke`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00153 [NONE] `	 * ksmbd_notify_cancel which reads argv[0..2].`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	argv[0] = NULL;	/* watch pointer, set by add_watch */`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	argv[1] = work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	argv[2] = fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	 * Compound CHANGE_NOTIFY handling:`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	 * When NOTIFY is the last request in a compound chain (e.g.`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	 * CREATE + NOTIFY), the preceding responses (CREATE) must be`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	 * sent immediately.  We allocate a separate async work struct`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	 * for the pending NOTIFY, set the NOTIFY response in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [PROTO_GATE|] `	 * compound to STATUS_PENDING, and let the compound response`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00167 [NONE] `	 * flow through the normal send path.  The separate async work`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	 * owns the final NOTIFY response and is managed by the`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	 * cancel/event/cleanup paths.`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	 * For non-compound NOTIFY, the original work struct is used`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	 * directly for the async operation (traditional behavior).`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		struct ksmbd_work *async_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		 * Allocate a separate work struct for the async NOTIFY.`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		 * This work will be used by the cancel/event paths to`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		 * send the final NOTIFY response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `		async_work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `		if (!async_work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `			kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00186 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00189 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		if (allocate_interim_rsp_buf(async_work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `			ksmbd_free_work_struct(async_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `			kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00198 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		/* Copy connection/session state to async work */`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		async_work->conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		async_work->sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		async_work->tcon = work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		async_work->encrypted = work->encrypted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		/* Take a session reference for the async work */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `		if (async_work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `			ksmbd_user_session_get(async_work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `		/* Copy the NOTIFY response header to the async work */`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [MEM_BOUNDS|] `		memcpy(smb2_get_msg(async_work->response_buf), rsp,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00212 [PROTO_GATE|] `		       __SMB2_HEADER_STRUCTURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		/* Update argv to reference the async work, not the compound work */`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		argv[1] = async_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		async_work->pending_async = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `		async_work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		rc = setup_async_work(async_work, ksmbd_notify_cancel, argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `			if (async_work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `				ksmbd_user_session_put(async_work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `			ksmbd_free_work_struct(async_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `			kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00227 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		 * When notify is disabled (no fsnotify), skip watch`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		 * installation.  The async work sits pending until`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		 * cancel/cleanup.  argv[0] stays NULL (no watch).`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		if (!ksmbd_notify_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [ERROR_PATH|] `			goto compound_set_pending;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		rc = ksmbd_notify_add_watch(fp, async_work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `					    completion_filter,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `					    watch_tree,`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `					    output_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `					    argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		if (rc == -EIOCBQUEUED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `			 * Buffered changes available: the response was built`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `			 * synchronously in async_work.  Copy the response back`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `			 * to the compound work's NOTIFY slot.`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `			release_async_work(async_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `			async_work->pending_async = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `			async_work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `			if (async_work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `				ksmbd_user_session_put(async_work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `			/* Copy the synchronous response back */`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [MEM_BOUNDS|] `			memcpy(rsp, smb2_get_msg(async_work->response_buf),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00259 [PROTO_GATE|] `			       __SMB2_HEADER_STRUCTURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `			ksmbd_free_work_struct(async_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `			release_async_work(async_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `			async_work->pending_async = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			async_work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `			if (async_work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `				ksmbd_user_session_put(async_work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `			ksmbd_free_work_struct(async_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `			kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `compound_set_pending:`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `		 * Set the NOTIFY response in the compound to`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [PROTO_GATE|] `		 * STATUS_PENDING with ASYNC_COMMAND flag.  The`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00283 [NONE] `		 * compound response will be sent by the main`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		 * dispatch loop including this pending status.`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [PROTO_GATE|] `		rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00287 [NONE] `		rsp->hdr.Id.AsyncId = cpu_to_le64(async_work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_PENDING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00290 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	 * Non-compound path: use the original work directly.`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	 * Take an extra session reference BEFORE registering the`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	 * async work.  Once setup_async_work returns, the cancel`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	 * path can run concurrently and will use work->sess for`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	 * signing/encryption.  __handle_ksmbd_work will drop its`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	 * own session reference; the async paths (build_response,`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	 * cancel, cleanup_file) drop this extra one.`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `		ksmbd_user_session_get(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	 * Set pending_async BEFORE setup_async_work so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	 * handle_ksmbd_work sees it even if the cancel path`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	 * fires immediately and frees the work.  pending_async`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	 * is read by handle_ksmbd_work after __handle_ksmbd_work`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	 * returns, but the cancel can free the work in between.`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	 * To prevent the use-after-free, we move the dequeue`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	 * logic to the end of __handle_ksmbd_work (see server.c).`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	 * Also set send_no_response early for the same reason --`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	 * the main dispatch loop must not send a response even if`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	 * the cancel path completes before we return.`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	work->pending_async = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	rc = setup_async_work(work, ksmbd_notify_cancel,`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `			      argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `		work->pending_async = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `			ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00333 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	 * Install the fsnotify watch.  On success argv[0]`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	 * is set to the watch pointer for cancel path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	 * or NULL for piggyback watches on existing marks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	rc = ksmbd_notify_add_watch(fp, work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				    completion_filter,`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `				    watch_tree,`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `				    output_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `				    argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	if (rc == -EIOCBQUEUED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		 * Buffered changes were available and the response`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		 * was built synchronously by add_watch.  Undo the`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		 * async setup and return the response normally`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		 * through the main dispatch loop.`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		release_async_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		work->pending_async = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `			ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		release_async_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		work->pending_async = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `			ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00370 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	 * Grant credits in the interim response.  Call set_rsp_credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	 * BEFORE smb2_send_interim_resp so the CreditRequest field is`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	 * set in the response header, and the interim copy inherits it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	if (work->conn->ops->set_rsp_credits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `		work->conn->ops->set_rsp_credits(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [PROTO_GATE|] `	/* Send STATUS_PENDING interim response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00384 [PROTO_GATE|] `	smb2_send_interim_resp(work, STATUS_PENDING);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	 * At this point, ownership is transferred to the async`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	 * subsystem.  The cancel/event/cleanup paths will send the`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	 * final response and free the work.  The main handler must`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	 * not touch the work after returning (see handle_ksmbd_work`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	 * which checks pending_async to skip freeing).`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
