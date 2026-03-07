# Line-by-line Review: src/protocol/smb2/smb2_tree.c

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
- L00007 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/syscalls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/ethtool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/crc32.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/mount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include "ksmbd_dfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `VISIBLE_IF_KUNIT char *ksmbd_extract_dfs_root_sharename(struct unicode_map *um,`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `					      const char *treename)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	const char *p = treename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	const char *share_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	const char *share_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	char *share, *cf_share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	while (*p == '\\' || *p == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	/* server component */`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	while (*p && *p != '\\' && *p != '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	if (!*p)`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	while (*p == '\\' || *p == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	share_start = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	while (*p && *p != '\\' && *p != '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	share_end = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	if (share_end == share_start)`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	share = kstrndup(share_start, share_end - share_start, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	if (!share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	cf_share = ksmbd_casefold_sharename(um, share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	kfree(share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	return cf_share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_extract_dfs_root_sharename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * smb2_tree_connect() - handler for smb2 tree connect command`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `int smb2_tree_connect(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	struct smb2_tree_connect_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	struct smb2_tree_connect_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	char *treename = NULL, *name = NULL, *dfs_name = ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	struct ksmbd_tree_conn_status status = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [PROTO_GATE|] `		.ret = KSMBD_TREE_CONN_STATUS_ERROR,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00118 [NONE] `		.tree_conn = NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	struct ksmbd_share_config *share = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	bool dfs_op;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	int rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	ksmbd_debug(SMB, "Received smb2 tree connect request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `		unsigned int total_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		unsigned int req_off = (char *)req - (char *)work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `		unsigned int path_off = le16_to_cpu(req->PathOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		unsigned int path_len = le16_to_cpu(req->PathLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		const char *path_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `		if (req_off > total_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [ERROR_PATH|] `			goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00138 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		 * MS-SMB2 §2.2.9, §3.3.5.7: when TREE_CONNECT_FLAG_EXTENSION_PRESENT is`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		 * set (SMB 3.1.1+), PathOffset is relative to the start of the`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		 * TREE_CONNECT_Request_Extension (which begins at req->Buffer[0]),`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		 * not to the SMB2 header.  Adjust accordingly.`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		if (conn->dialect >= SMB311_PROT_ID &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [PROTO_GATE|] `		    (req->Reserved & SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00148 [NONE] `			size_t ext_base = offsetof(struct smb2_tree_connect_req, Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `			ksmbd_debug(SMB, "TREE_CONNECT_FLAG_EXTENSION_PRESENT set\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `			if (ext_base + path_off > total_len - req_off ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `			    ext_base + path_off + path_len > total_len - req_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [ERROR_PATH|] `				goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00155 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `			path_ptr = (const char *)req + ext_base + path_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `			if ((u64)path_off + path_len > total_len - req_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [ERROR_PATH|] `				goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00161 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `			path_ptr = (const char *)req + path_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		treename = smb_strndup_from_utf16(path_ptr, path_len, true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `						  conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	if (IS_ERR(treename)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [ERROR_PATH|] `		pr_err_ratelimited("treename is NULL\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00170 [PROTO_GATE|] `		status.ret = KSMBD_TREE_CONN_STATUS_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00171 [ERROR_PATH|] `		goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00172 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [PROTO_GATE|] `	dfs_op = !!(req->hdr.Flags & SMB2_FLAGS_DFS_OPERATIONS);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [NONE] `	if (dfs_op)`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `			    "DFS flag set for tree connect: %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `			    treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	name = ksmbd_extract_sharename(conn->um, treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	if (IS_ERR(name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [PROTO_GATE|] `		status.ret = KSMBD_TREE_CONN_STATUS_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00183 [ERROR_PATH|] `		goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00184 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	 * MS-SMB2 §3.3.5.7: share name MUST be less than 80 characters.`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	 * Reject oversized share names before attempting lookup.`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	if (strlen(name) >= 80) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [ERROR_PATH|] `		pr_warn_ratelimited("tree connect: share name too long (%zu chars)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00192 [NONE] `				    strlen(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BAD_NETWORK_NAME;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [ERROR_PATH|] `		goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00196 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	ksmbd_debug(SMB, "tree connect request for tree %s treename %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		    name, treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	status = ksmbd_tree_conn_connect(work, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [PROTO_GATE|] `	if (status.ret != KSMBD_TREE_CONN_STATUS_OK && dfs_op) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00203 [NONE] `		dfs_name = ksmbd_extract_dfs_root_sharename(conn->um, treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		if (!IS_ERR(dfs_name) && strcmp(name, dfs_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `				    "retry tree connect using DFS root share %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `				    dfs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `			status = ksmbd_tree_conn_connect(work, dfs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [PROTO_GATE|] `			if (status.ret == KSMBD_TREE_CONN_STATUS_OK) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00210 [NONE] `				kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `				name = dfs_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `				dfs_name = ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [PROTO_GATE|] `	if (status.ret == KSMBD_TREE_CONN_STATUS_OK)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00217 [NONE] `		rsp->hdr.Id.SyncId.TreeId = cpu_to_le32(status.tree_conn->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [ERROR_PATH|] `		goto out_err1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	share = status.tree_conn->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		ksmbd_debug(SMB, "IPC share path request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [PROTO_GATE|] `		rsp->ShareType = SMB2_SHARE_TYPE_PIPE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00225 [NONE] `		rsp->MaximalAccess = FILE_READ_DATA_LE | FILE_READ_EA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `			FILE_EXECUTE_LE | FILE_READ_ATTRIBUTES_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `			FILE_DELETE_LE | FILE_READ_CONTROL_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `			FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `			FILE_SYNCHRONIZE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		 * B.8: MaximalAccess should reflect actual maximum access for`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		 * the authenticated user on this share (MS-SMB2 §2.2.10).`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		 * Compute access from the real POSIX permissions on the share`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		 * root directory using inode_permission().  This correctly`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		 * accounts for uid/gid/mode of the underlying filesystem path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		 * FILE_READ_CONTROL_LE and FILE_SYNCHRONIZE_LE are always`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		 * included as they are required for basic file operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [PROTO_GATE|] `		 * B.9: Return SMB2_SHARE_TYPE_PRINT (0x03) for print shares.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [NONE] `		 * KSMBD_SHARE_FLAG_PRINT is not yet defined in ksmbd_netlink.h`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `		 * (the kernel-userspace ABI), so print share detection is not`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		 * currently supported. All non-IPC shares are DISK type.`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		 * When KSMBD_SHARE_FLAG_PRINT is added to ksmbd_netlink.h,`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		 * add: if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PRINT))`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [PROTO_GATE|] `		 *          rsp->ShareType = SMB2_SHARE_TYPE_PRINT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [NONE] `		 * else`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [PROTO_GATE|] `		rsp->ShareType = SMB2_SHARE_TYPE_DISK;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		 * Start with the base access bits that are always present:`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `		 *   FILE_READ_CONTROL_LE - always needed`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		 *   FILE_SYNCHRONIZE_LE  - needed for any open with SYNCHRONIZE`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		 *   FILE_READ_ATTRIBUTES_LE - reading basic file attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `		 *   FILE_READ_EA_LE      - reading extended attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		 * Then probe the share root directory with inode_permission()`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		 * to determine which access classes the current user holds.`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `		rsp->MaximalAccess = FILE_READ_CONTROL_LE | FILE_SYNCHRONIZE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		if (share->vfs_path.dentry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `			struct inode *root_inode =`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `				d_inode(share->vfs_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			struct path *root_path =`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `				(struct path *)&share->vfs_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `			if (root_inode) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `				int perm_r, perm_w, perm_x;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `				perm_r = compat_inode_permission(root_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `								 root_inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `								 MAY_READ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `				perm_w = compat_inode_permission(root_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `								 root_inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `								 MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `				perm_x = compat_inode_permission(root_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `								 root_inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `								 MAY_EXEC);`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `				if (!perm_r) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `					 * MAY_READ on a directory means the`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `					 * client can list contents and read`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `					 * file attributes/EAs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `					rsp->MaximalAccess |=`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `						FILE_READ_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `						FILE_LIST_DIRECTORY_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `						FILE_READ_ATTRIBUTES_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `						FILE_READ_EA_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `				if (!perm_w &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `				    test_tree_conn_flag(status.tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `						KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `					 * MAY_WRITE on directory + share is`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `					 * writable → full write access.`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `					rsp->MaximalAccess |=`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `						FILE_WRITE_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `						FILE_ADD_FILE_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `						FILE_APPEND_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `						FILE_WRITE_EA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `						FILE_DELETE_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `						FILE_WRITE_ATTRIBUTES_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `						FILE_DELETE_CHILD_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `						FILE_WRITE_DAC_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `						FILE_WRITE_OWNER_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `				if (!perm_x) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `					 * MAY_EXEC on a directory means the`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `					 * client can traverse it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `					rsp->MaximalAccess |= FILE_TRAVERSE_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `						FILE_EXECUTE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `					    "MaximalAccess: perm_r=%d perm_w=%d perm_x=%d access=0x%08x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `					    perm_r, perm_w, perm_x,`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `					    le32_to_cpu(rsp->MaximalAccess));`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [ERROR_PATH|] `				goto share_access_fallback;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00331 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `share_access_fallback:`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `			 * vfs_path not available (IPC-like or path lookup`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			 * failed at mount time) -- fall back to share-flag`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			 * based approach.`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `			rsp->MaximalAccess |= FILE_READ_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `				FILE_READ_EA_LE | FILE_EXECUTE_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `				FILE_READ_ATTRIBUTES_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `				FILE_LIST_DIRECTORY_LE | FILE_TRAVERSE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `			if (test_tree_conn_flag(status.tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `						KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `				rsp->MaximalAccess |= FILE_WRITE_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `					FILE_APPEND_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `					FILE_WRITE_EA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `					FILE_DELETE_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `					FILE_WRITE_ATTRIBUTES_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `					FILE_DELETE_CHILD_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `					FILE_WRITE_DAC_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `					FILE_WRITE_OWNER_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	status.tree_conn->maximal_access = le32_to_cpu(rsp->MaximalAccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	if (conn->posix_ext_supported)`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		status.tree_conn->posix_extensions = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	write_lock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	status.tree_conn->t_state = TREE_CONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	write_unlock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	rsp->StructureSize = cpu_to_le16(16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `out_err1:`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	rsp->Capabilities = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE && share &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	    test_share_config_flag(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `				   KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY))`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [PROTO_GATE|] `		rsp->Capabilities |= SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00371 [NONE] `	if (ksmbd_dfs_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [PROTO_GATE|] `		rsp->Capabilities |= SMB2_SHARE_CAP_DFS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00373 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	/* default manual caching */`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [PROTO_GATE|] `	rsp->ShareFlags = cpu_to_le32(SMB2_SHAREFLAG_MANUAL_CACHING);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [NONE] `	if (ksmbd_dfs_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `		rsp->ShareFlags |= cpu_to_le32(SHI1005_FLAGS_DFS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	rc = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_tree_connect_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [PROTO_GATE|] `		if (status.ret == KSMBD_TREE_CONN_STATUS_OK)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00382 [NONE] `			ksmbd_tree_conn_disconnect(sess, status.tree_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [PROTO_GATE|] `		status.ret = KSMBD_TREE_CONN_STATUS_NOMEM;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00384 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	if (!IS_ERR(treename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		kfree(treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	if (!IS_ERR(name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	if (!IS_ERR(dfs_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `		kfree(dfs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	switch (status.ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [PROTO_GATE|] `	case KSMBD_TREE_CONN_STATUS_OK:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00395 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00396 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	case -ESTALE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	case -ENOENT:`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [PROTO_GATE|] `	case KSMBD_TREE_CONN_STATUS_NO_SHARE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00401 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BAD_NETWORK_NAME;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00402 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	case -ENOMEM:`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [PROTO_GATE|] `	case KSMBD_TREE_CONN_STATUS_NOMEM:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00405 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_MEMORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00406 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [PROTO_GATE|] `	case KSMBD_TREE_CONN_STATUS_ERROR:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00408 [PROTO_GATE|] `	case KSMBD_TREE_CONN_STATUS_TOO_MANY_CONNS:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00409 [PROTO_GATE|] `	case KSMBD_TREE_CONN_STATUS_TOO_MANY_SESSIONS:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00410 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00411 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	case -EINVAL:`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00414 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00417 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [PROTO_GATE|] `	if (status.ret != KSMBD_TREE_CONN_STATUS_OK)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00420 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ` * smb2_tree_disconnect() - handler for smb tree connect request`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] ` * @work:	smb work containing request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `int smb2_tree_disconnect(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	struct smb2_tree_disconnect_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	struct smb2_tree_disconnect_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	struct ksmbd_tree_connect *tcon = work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	ksmbd_debug(SMB, "Received smb2 tree disconnect request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	if (!tcon) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `		ksmbd_debug(SMB, "Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00447 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00449 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	ksmbd_close_tree_conn_fds(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	write_lock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	if (tcon->t_state == TREE_DISCONNECTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `		write_unlock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00457 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00459 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	tcon->t_state = TREE_DISCONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	write_unlock(&sess->tree_conns_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	err = ksmbd_tree_conn_disconnect(sess, tcon);`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NETWORK_NAME_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00467 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00468 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	rsp->StructureSize = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	err = ksmbd_iov_pin_rsp(work, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `				sizeof(struct smb2_tree_disconnect_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00475 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00476 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ` * smb2_session_logoff() - handler for session log off request`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ` * @work:	smb work containing request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `int smb2_session_logoff(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	struct smb2_logoff_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	struct smb2_logoff_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	u64 sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	ksmbd_debug(SMB, "Received smb2 session logoff request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	if (!ksmbd_conn_good(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `		 * B.7: MS-SMB2 §3.3.5.6 — requests on a bad/expired connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [PROTO_GATE|] `		 * for LOGOFF should return STATUS_USER_SESSION_DELETED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00511 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00513 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00515 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	sess_id = le64_to_cpu(req->hdr.SessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	ksmbd_all_conn_set_status(sess_id, KSMBD_SESS_NEED_RECONNECT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	 * MS-SMB2 §3.3.4.1.8: on session logoff, notify all other channels`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	 * of the session that the session is closing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	smb2_send_session_closed_notification(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	ksmbd_close_session_fds(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	ksmbd_conn_wait_idle(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	if (ksmbd_tree_conn_session_logoff(sess)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `		ksmbd_debug(SMB, "Invalid tid %d\n", req->hdr.Id.SyncId.TreeId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00532 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00534 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [LOCK|] `	down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00537 [LOCK|] `	down_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00538 [PROTO_GATE|] `	sess->state = SMB2_SESSION_EXPIRED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00539 [LOCK|] `	up_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00540 [LOCK|] `	up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	ksmbd_all_conn_set_status(sess_id, KSMBD_SESS_NEED_SETUP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	rsp->StructureSize = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	err = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_logoff_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00548 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
