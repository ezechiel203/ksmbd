# Line-by-line Review: src/protocol/smb2/smb2_lock.c

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
- L00006 [PROTO_GATE|] ` *   smb2_lock.c - SMB2_LOCK + SMB2_CANCEL handlers`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/syscalls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/ethtool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/crc32.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/mount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * smb2_cancel() - handler for smb2 cancel command`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * @work:	smb work containing cancel command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `int smb2_cancel(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	struct smb2_hdr *chdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	struct ksmbd_work *iter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	struct list_head *command_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	void (*cancel_fn)(void **argv) = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	void **cancel_argv = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `		hdr = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	ksmbd_debug(SMB, "smb2 cancel called on mid %llu, async flags 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		    le64_to_cpu(hdr->MessageId), le32_to_cpu(hdr->Flags));`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [PROTO_GATE|] `	if (hdr->Flags & SMB2_FLAGS_ASYNC_COMMAND) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [NONE] `		command_list = &conn->async_requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [LOCK|] `		spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00088 [NONE] `		list_for_each_entry(iter, command_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `				    async_request_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `			 * Match by async_id FIRST — do not skip entries with`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `			 * request_buf == NULL.  Compound-spawned async work`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `			 * (e.g. CHANGE_NOTIFY created in a compound chain) is`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `			 * allocated via ksmbd_alloc_work_struct() and has no`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `			 * request_buf, but carries a valid async_id and a`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `			 * cancel_fn.  Checking request_buf before async_id`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `			 * caused these entries to be silently skipped, making`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `			 * the client's CANCEL never find the pending operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `			 * and hang indefinitely (smb2.compound interim1).`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `			if (iter->async_id !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			    le64_to_cpu(hdr->Id.AsyncId))`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `			if (iter->request_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `				chdr = smb2_get_msg(iter->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `					    "smb2 with AsyncId %llu cancelled command = 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `					    le64_to_cpu(hdr->Id.AsyncId),`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `					    le16_to_cpu(chdr->Command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `					    "smb2 with AsyncId %llu cancelled (compound async, no request_buf)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `					    le64_to_cpu(hdr->Id.AsyncId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `			iter->state = KSMBD_WORK_CANCELLED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			cancel_fn = iter->cancel_fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			cancel_argv = iter->cancel_argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `			iter->cancel_fn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `			iter->cancel_argv = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [LOCK|] `		spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00124 [NONE] `		if (cancel_fn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `			cancel_fn(cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `		kfree(cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		command_list = &conn->requests;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [LOCK|] `		spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00131 [NONE] `		list_for_each_entry(iter, command_list, request_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `			chdr = smb2_get_msg(iter->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `			if (chdr->MessageId != hdr->MessageId ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `			    iter == work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `				    "smb2 with mid %llu cancelled command = 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `				    le64_to_cpu(hdr->MessageId),`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `				    le16_to_cpu(chdr->Command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `			iter->state = KSMBD_WORK_CANCELLED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `			if (iter->cancel_fn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `				cancel_fn = iter->cancel_fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `				cancel_argv = iter->cancel_argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `				iter->cancel_fn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `				iter->cancel_argv = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		 * If not found in the sync request list, search the`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		 * async list.  A client may send a sync cancel`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [PROTO_GATE|] `		 * (without SMB2_FLAGS_ASYNC_COMMAND) before it`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00156 [PROTO_GATE|] `		 * receives the interim STATUS_PENDING response that`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00157 [NONE] `		 * contains the AsyncId.`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		 * Non-GMAC clients (including Samba and Windows)`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		 * set MessageId=0 in this case, so first try`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		 * matching by MessageId, then fall back to matching`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		 * by SessionId for MessageId=0 cancels.`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		if (!cancel_fn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `			list_for_each_entry(iter,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `					    &conn->async_requests,`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `					    async_request_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `				if (!iter->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `				chdr = smb2_get_msg(iter->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `				if (iter == work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `				if (chdr->MessageId == hdr->MessageId) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `						    "smb2 cancel: found async mid %llu cmd=0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `						    le64_to_cpu(chdr->MessageId),`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `						    le16_to_cpu(chdr->Command));`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `					iter->state = KSMBD_WORK_CANCELLED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `					cancel_fn = iter->cancel_fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `					cancel_argv = iter->cancel_argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `					iter->cancel_fn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `					iter->cancel_argv = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		 * MessageId=0 cancel: client has not yet received`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		 * the interim response, so it cannot use the`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		 * AsyncId.  Match by SessionId instead to find the`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		 * pending async work on this connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		if (!cancel_fn && hdr->MessageId == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `			list_for_each_entry(iter,`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `					    &conn->async_requests,`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `					    async_request_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `				if (!iter->request_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `				chdr = smb2_get_msg(iter->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `				if (iter == work || !iter->cancel_fn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `				if (chdr->SessionId ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `				    hdr->SessionId) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `						    "smb2 cancel: mid=0 matched by SessionId, async cmd=0x%x async_id=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `						    le16_to_cpu(chdr->Command),`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `						    (unsigned long long)iter->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `					iter->state = KSMBD_WORK_CANCELLED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `					cancel_fn = iter->cancel_fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `					cancel_argv = iter->cancel_argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `					iter->cancel_fn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `					iter->cancel_argv = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [LOCK|] `		spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		if (cancel_fn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `			cancel_fn(cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `			kfree(cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [PROTO_GATE|] `	/* For SMB2_CANCEL command itself send no response*/`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00231 [NONE] `	work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `struct file_lock *smb_flock_init(struct file *f)`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	struct file_lock *fl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	fl = locks_alloc_lock();`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	if (!fl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	locks_init_lock(fl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	fl->c.flc_owner = f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	fl->c.flc_pid = current->tgid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	fl->c.flc_file = f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	fl->c.flc_flags = FL_POSIX;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	fl->fl_owner = f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	fl->fl_pid = current->tgid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	fl->fl_file = f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	fl->fl_flags = FL_POSIX;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	fl->fl_ops = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	fl->fl_lmops = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	return fl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` * Wait for a deferred POSIX lock with periodic wakeups so disconnect/cancel`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ` * can abort the wait and prevent stuck worker threads.`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ` * Returns 0 if the lock was granted, -EINTR if the wait was interrupted`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` * (either by a CANCEL request or by a signal), -ETIMEDOUT when exceeding`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ` * the bounded wait budget, or another negative error.`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `#define KSMBD_POSIX_LOCK_WAIT_MAX_JIFFIES	(300 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `static int smb2_wait_for_posix_lock(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `				    struct file_lock *flock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	unsigned long waited_jiffies = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [WAIT_LOOP|] `	for (;;) {`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00279 [NONE] `		rc = ksmbd_vfs_posix_lock_wait_timeout(flock, HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		if (rc > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `		waited_jiffies += HZ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		if (work->state != KSMBD_WORK_ACTIVE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		    !ksmbd_conn_alive(work->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `			if (work->state == KSMBD_WORK_ACTIVE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `				work->state = KSMBD_WORK_CANCELLED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `			ksmbd_vfs_posix_lock_unblock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [ERROR_PATH|] `			return -EINTR;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00290 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		 * -EINTR: interrupted by signal (not just ERESTARTSYS).`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		 * Treat as cancellation so the caller does not silently`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [PROTO_GATE|] `		 * retry and instead sends STATUS_CANCELLED to the client.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00296 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `		if (rc < 0 && rc != -ERESTARTSYS) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `			work->state = KSMBD_WORK_CANCELLED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `			ksmbd_vfs_posix_lock_unblock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [ERROR_PATH|] `			return -EINTR;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00301 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `		if (rc == 0 && waited_jiffies >= KSMBD_POSIX_LOCK_WAIT_MAX_JIFFIES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [ERROR_PATH|] `			pr_warn_ratelimited("SMB2 lock wait timed out after %lu jiffies\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00305 [NONE] `					    waited_jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `			ksmbd_vfs_posix_lock_unblock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [ERROR_PATH|] `			return -ETIMEDOUT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00308 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `VISIBLE_IF_KUNIT int smb2_set_flock_flags(struct file_lock *flock, int flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	int cmd = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	/* Checking for wrong flag combination during lock request*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	switch (flags) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [PROTO_GATE|] `	case SMB2_LOCKFLAG_SHARED:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00319 [NONE] `		ksmbd_debug(SMB, "received shared request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		cmd = F_SETLKW;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		flock->c.flc_type = F_RDLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `		flock->c.flc_flags |= FL_SLEEP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `		flock->fl_type = F_RDLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		flock->fl_flags |= FL_SLEEP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [PROTO_GATE|] `	case SMB2_LOCKFLAG_EXCLUSIVE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00330 [NONE] `		ksmbd_debug(SMB, "received exclusive request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		cmd = F_SETLKW;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		flock->c.flc_type = F_WRLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		flock->c.flc_flags |= FL_SLEEP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `		flock->fl_type = F_WRLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `		flock->fl_flags |= FL_SLEEP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [PROTO_GATE|] `	case SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00341 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `			    "received shared & fail immediately request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		cmd = F_SETLK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		flock->c.flc_type = F_RDLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		flock->fl_type = F_RDLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [PROTO_GATE|] `	case SMB2_LOCKFLAG_EXCLUSIVE | SMB2_LOCKFLAG_FAIL_IMMEDIATELY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `			    "received exclusive & fail immediately request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		cmd = F_SETLK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		flock->c.flc_type = F_WRLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		flock->fl_type = F_WRLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [PROTO_GATE|] `	case SMB2_LOCKFLAG_UNLOCK:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00361 [NONE] `		ksmbd_debug(SMB, "received unlock request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `		flock->c.flc_type = F_UNLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		flock->fl_type = F_UNLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `		cmd = F_SETLK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	return cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_set_flock_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `VISIBLE_IF_KUNIT struct ksmbd_lock *smb2_lock_init(struct file_lock *flock,`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `					 unsigned int cmd, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `					 unsigned long long smb_start,`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `					 unsigned long long smb_end,`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `					 struct list_head *lock_list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	struct ksmbd_lock *lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [MEM_BOUNDS|] `	lock = kzalloc(sizeof(struct ksmbd_lock), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00384 [NONE] `	if (!lock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	lock->cmd = cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	lock->fl = flock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	 * Use the original SMB lock range (before POSIX clamping) for`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	 * ksmbd-internal conflict detection.  SMB2 lock offsets are`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	 * unsigned 64-bit and may exceed the POSIX loff_t (signed 64-bit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	 * range.  The flock fl_start/fl_end are clamped for VFS use, but`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	 * the ksmbd lock list must use the unclamped values so overlapping`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	 * locks at large offsets (e.g. 2^63-1) are properly detected.`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	lock->start = smb_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	lock->end = smb_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	lock->flags = flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	if (lock->start == lock->end)`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `		lock->zero_len = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	INIT_LIST_HEAD(&lock->clist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	INIT_LIST_HEAD(&lock->flist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	INIT_LIST_HEAD(&lock->llist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	list_add_tail(&lock->llist, lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	return lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_lock_init);`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `static void smb2_remove_blocked_lock(void **argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	struct file_lock *flock = (struct file_lock *)argv[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	ksmbd_vfs_posix_lock_unblock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	locks_wake_up(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	wake_up(&flock->fl_wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `static inline bool lock_defer_pending(struct file_lock *fl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	/* check pending lock waiters */`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	return waitqueue_active(&fl->c.flc_wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	return waitqueue_active(&fl->fl_wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ` * check_lock_sequence() - validate lock sequence for resilient/durable handles`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ` * @fp:			ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ` * @lock_seq_val:	lock sequence value from SMB2 LOCK request`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ` * Per MS-SMB2 3.3.5.14:`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ` *   LockSequenceNumber = bits 0-3 (low 4 bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ` *   LockSequenceIndex  = bits 4-31 (upper 28 bits), valid range 1-64`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ` * If the entry is valid and the sequence number matches, this is a replay:`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [PROTO_GATE|] ` * return 1 to signal the caller to return STATUS_OK immediately.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00444 [NONE] ` * If the sequence number differs, invalidate the entry and proceed normally.`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ` * Return:	0 = proceed with lock, 1 = replay (return OK immediately)`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `VISIBLE_IF_KUNIT int check_lock_sequence(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `					 __le32 lock_seq_val)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	u32 val = le32_to_cpu(lock_seq_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	u8 seq_num = val & 0xF;               /* Low 4 bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	u32 seq_idx = (val >> 4) & 0xFFFFFFF;  /* Upper 28 bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	/* Index 0 is reserved - skip validation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	if (seq_idx == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	/* Index out of range - skip validation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	if (seq_idx > 64)`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	/* Only validate for resilient/durable/persistent handles */`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	if (!fp->is_resilient && !fp->is_durable && !fp->is_persistent)`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [LOCK|] `	spin_lock(&fp->lock_seq_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00468 [NONE] `	if (fp->lock_seq[seq_idx] != 0xFF &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	    fp->lock_seq[seq_idx] == seq_num) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		/* Replay detected - return success immediately */`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [LOCK|] `		spin_unlock(&fp->lock_seq_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00472 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	/* Different sequence or entry not valid - invalidate and proceed */`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	fp->lock_seq[seq_idx] = 0xFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [LOCK|] `	spin_unlock(&fp->lock_seq_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00477 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `EXPORT_SYMBOL_IF_KUNIT(check_lock_sequence);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] ` * store_lock_sequence() - record lock sequence after successful lock`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] ` * @fp:			ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ` * @lock_seq_val:	lock sequence value from SMB2 LOCK request`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `VISIBLE_IF_KUNIT void store_lock_sequence(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `					  __le32 lock_seq_val)`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	u32 val = le32_to_cpu(lock_seq_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	u8 seq_num = val & 0xF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	u32 seq_idx = (val >> 4) & 0xFFFFFFF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	if (seq_idx == 0 || seq_idx > 64)`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	if (!fp->is_resilient && !fp->is_durable && !fp->is_persistent)`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [LOCK|] `	spin_lock(&fp->lock_seq_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00499 [NONE] `	fp->lock_seq[seq_idx] = seq_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [LOCK|] `	spin_unlock(&fp->lock_seq_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00501 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `EXPORT_SYMBOL_IF_KUNIT(store_lock_sequence);`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] ` * smb2_lock() - handler for smb2 file lock command`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] ` * @work:	smb work containing lock command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `int smb2_lock(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	struct smb2_lock_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	struct smb2_lock_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	struct smb2_lock_element *lock_ele;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	struct file_lock *flock = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	struct file *filp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	int lock_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	int flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	int cmd = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	int err = -EINVAL, i, rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	u64 lock_start, lock_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	struct ksmbd_lock *smb_lock = NULL, *cmp_lock, *tmp, *tmp2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	int nolock = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	LIST_HEAD(lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	LIST_HEAD(rollback_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	int prior_lock = 0, bkt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	ksmbd_debug(SMB, "Received smb2 lock request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	fp = ksmbd_lookup_fd_slow(work, req->VolatileFileId, req->PersistentFileId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `		ksmbd_debug(SMB, "Invalid file id for lock : %llu\n", req->VolatileFileId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [ERROR_PATH|] `		goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00538 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	/* Validate lock sequence for resilient/durable handles (MS-SMB2 3.3.5.14) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	rc = check_lock_sequence(fp, req->LockSequenceNumber);`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	if (rc > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `		/* Lock replay detected - return success immediately */`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `		rsp->StructureSize = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00546 [NONE] `		rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `		err = ksmbd_iov_pin_rsp(work, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `					sizeof(struct smb2_lock_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [ERROR_PATH|] `			goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00551 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence */`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	if (smb2_check_channel_sequence(work, fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00558 [NONE] `		err = -EAGAIN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [ERROR_PATH|] `		goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00560 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	lock_count = le16_to_cpu(req->LockCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	lock_ele = req->locks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	ksmbd_debug(SMB, "lock count is %d\n", lock_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	if (!lock_count || lock_count > KSMBD_MAX_LOCK_COUNT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [ERROR_PATH|] `		pr_err_ratelimited("Invalid lock count: %d\n", lock_count);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00569 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [ERROR_PATH|] `		goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00571 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	/* Validate that the lock element array fits within the request buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		unsigned int locks_offset = offsetof(struct smb2_lock_req, locks);`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `		unsigned int needed = (unsigned int)lock_count *`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `				      sizeof(struct smb2_lock_element);`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `			req_len -= work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `		if (needed / sizeof(struct smb2_lock_element) != lock_count ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `		    locks_offset + needed > req_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [ERROR_PATH|] `			pr_err_ratelimited("lock elements exceed request buffer\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00586 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [ERROR_PATH|] `			goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00588 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	for (i = 0; i < lock_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `		u64 smb_lock_start, smb_lock_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		flags = le32_to_cpu(lock_ele[i].Flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		flock = smb_flock_init(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		if (!flock) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `			err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00600 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		cmd = smb2_set_flock_flags(flock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		lock_start = le64_to_cpu(lock_ele[i].Offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		lock_length = le64_to_cpu(lock_ele[i].Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		 * MS-SMB2: lock range [offset, offset+length) is valid when`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		 * offset+length <= 2^64.  Wrapping to exactly 0 is allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		 * (e.g. offset=~0, length=1), but wrapping to non-zero is`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		 * invalid (e.g. offset=~0, length=2).`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		if (lock_length > 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		    lock_start + lock_length != 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		    lock_start + lock_length < lock_start) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [ERROR_PATH|] `			pr_err_ratelimited("Invalid lock range requested\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00616 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_LOCK_RANGE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00617 [NONE] `			locks_free_lock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00619 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `		/* Save the original SMB lock range before POSIX clamping */`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		smb_lock_start = lock_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		smb_lock_end = lock_start + lock_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		if (lock_start > OFFSET_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `			flock->fl_start = OFFSET_MAX;`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `			flock->fl_start = lock_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		lock_length = le64_to_cpu(lock_ele[i].Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		if (lock_length > OFFSET_MAX - flock->fl_start)`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `			lock_length = OFFSET_MAX - flock->fl_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		 * POSIX fl_end is inclusive (last byte locked).`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		 * SMB range is [offset, offset+length), so the`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		 * last byte is offset+length-1.`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `		if (lock_length > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `			flock->fl_end = flock->fl_start + lock_length - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `			flock->fl_end = flock->fl_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `		if (flock->fl_end < flock->fl_start) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `				    "the end offset(%llx) is smaller than the start offset(%llx)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `				    flock->fl_end, flock->fl_start);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_LOCK_RANGE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00649 [NONE] `			locks_free_lock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00651 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `		/* Check conflict locks in one request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		list_for_each_entry(cmp_lock, &lock_list, llist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `			if (cmp_lock->start <= smb_lock_start &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `			    cmp_lock->end >= smb_lock_end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `				if (cmp_lock->fl->c.flc_type != F_UNLCK &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `				    flock->c.flc_type != F_UNLCK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `				if (cmp_lock->fl->fl_type != F_UNLCK &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `				    flock->fl_type != F_UNLCK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [ERROR_PATH|] `					pr_err_ratelimited("conflict two locks in one request\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00665 [NONE] `					err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `					locks_free_lock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00668 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `		smb_lock = smb2_lock_init(flock, cmd, flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `					  smb_lock_start, smb_lock_end,`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `					  &lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `		if (!smb_lock) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `			locks_free_lock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00679 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	list_for_each_entry_safe(smb_lock, tmp, &lock_list, llist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `		if (smb_lock->cmd < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00686 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [PROTO_GATE|] `		if (!(smb_lock->flags & SMB2_LOCKFLAG_MASK)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00689 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00691 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [PROTO_GATE|] `		if ((prior_lock & (SMB2_LOCKFLAG_EXCLUSIVE | SMB2_LOCKFLAG_SHARED) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00694 [PROTO_GATE|] `		     smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00695 [PROTO_GATE|] `		    (prior_lock == SMB2_LOCKFLAG_UNLOCK &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00696 [PROTO_GATE|] `		     !(smb_lock->flags & SMB2_LOCKFLAG_UNLOCK))) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00697 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00699 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `		prior_lock = smb_lock->flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [PROTO_GATE|] `		if (!(smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00704 [PROTO_GATE|] `		    !(smb_lock->flags & SMB2_LOCKFLAG_FAIL_IMMEDIATELY)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00705 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `			 * Blocking lock: normally skip the full conflict`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `			 * check and let vfs_lock_file() handle blocking.`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `			 * But first, reject same-handle overlapping locks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `			 * SMB/NT does not support POSIX-style lock upgrades`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `			 * (shared->exclusive), and a same-handle conflict`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `			 * can never be resolved by waiting.`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [PROTO_GATE|] `			if (!(smb_lock->flags & SMB2_LOCKFLAG_SHARED)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00714 [NONE] `				for (bkt = 0; bkt < CONN_HASH_SIZE; bkt++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [LOCK|] `				spin_lock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00716 [NONE] `				hlist_for_each_entry(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `						     &conn_hash[bkt].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `						     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [LOCK|] `					spin_lock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00720 [NONE] `					list_for_each_entry(cmp_lock,`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `							    &conn->lock_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `							    clist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `						if (cmp_lock->fl->c.flc_file !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `						    smb_lock->fl->c.flc_file)`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `						if (cmp_lock->fl->fl_file !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `						    smb_lock->fl->fl_file)`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `							continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `						if (cmp_lock->zero_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `						    smb_lock->zero_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `							continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `						{`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `						u64 c_last = cmp_lock->end ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `							cmp_lock->end - 1 :`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `							~0ULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `						u64 s_last = smb_lock->end ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `							smb_lock->end - 1 :`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `							~0ULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `						if (cmp_lock->start <= s_last &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `						    smb_lock->start <= c_last) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [LOCK|] `							spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00744 [LOCK|] `							spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00745 [ERROR_PATH|] `							pr_err_ratelimited("Same-handle lock conflict (NT byte range)\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00746 [NONE] `							rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [PROTO_GATE|] `								STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00748 [ERROR_PATH|] `							goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00749 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [LOCK|] `					spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00753 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [LOCK|] `				spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00755 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [ERROR_PATH|] `			goto no_check_cl;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00758 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `		nolock = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `		/* check locks in connection list */`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `		for (bkt = 0; bkt < CONN_HASH_SIZE; bkt++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [LOCK|] `		spin_lock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00764 [NONE] `		hlist_for_each_entry(conn, &conn_hash[bkt].head,`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `				     hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [LOCK|] `			spin_lock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00767 [NONE] `			list_for_each_entry_safe(cmp_lock, tmp2, &conn->lock_list, clist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `				if (file_inode(cmp_lock->fl->c.flc_file) !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `				    file_inode(smb_lock->fl->c.flc_file))`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `				if (file_inode(cmp_lock->fl->fl_file) !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `				    file_inode(smb_lock->fl->fl_file))`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `				if (lock_is_unlock(smb_lock->fl)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `				if (smb_lock->fl->fl_type == F_UNLCK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `					if (cmp_lock->fl->c.flc_file == smb_lock->fl->c.flc_file &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `					if (cmp_lock->fl->fl_file == smb_lock->fl->fl_file &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `					    cmp_lock->start == smb_lock->start &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `					    cmp_lock->end == smb_lock->end &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `					    !lock_defer_pending(cmp_lock->fl)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `						nolock = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `						list_del(&cmp_lock->flist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `						list_del(&cmp_lock->clist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [LOCK|] `						spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00794 [LOCK|] `						spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `						locks_free_lock(cmp_lock->fl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `						kfree(cmp_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [ERROR_PATH|] `						goto out_check_cl;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00799 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `				if (cmp_lock->fl->c.flc_file == smb_lock->fl->c.flc_file) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `				if (cmp_lock->fl->fl_file == smb_lock->fl->fl_file) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [PROTO_GATE|] `					if (smb_lock->flags & SMB2_LOCKFLAG_SHARED)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00809 [NONE] `						continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [PROTO_GATE|] `					if (cmp_lock->flags & SMB2_LOCKFLAG_SHARED)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00812 [NONE] `						continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `				/* check zero byte lock range */`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `				if (cmp_lock->zero_len && !smb_lock->zero_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `				    cmp_lock->start > smb_lock->start &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `				    cmp_lock->start < smb_lock->end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [LOCK|] `					spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00820 [LOCK|] `					spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00821 [ERROR_PATH|] `					pr_err_ratelimited("previous lock conflict with zero byte lock range\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00822 [PROTO_GATE|] `					rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00823 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00824 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `				if (smb_lock->zero_len && !cmp_lock->zero_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `				    smb_lock->start > cmp_lock->start &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `				    smb_lock->start < cmp_lock->end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [LOCK|] `					spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00830 [LOCK|] `					spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00831 [ERROR_PATH|] `					pr_err_ratelimited("current lock conflict with zero byte lock range\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00832 [PROTO_GATE|] `					rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00833 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00834 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `				 * Overlap check.  Ranges use exclusive ends,`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `				 * and end==0 means the range wraps past 2^64`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `				 * (e.g., offset=~0, length=1 → end=0).`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `				 * Convert to inclusive last-byte for safe`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `				 * comparison.`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `			    {`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `				u64 cmp_last = cmp_lock->end ? cmp_lock->end - 1 : ~0ULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `				u64 smb_last = smb_lock->end ? smb_lock->end - 1 : ~0ULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `			    if (cmp_lock->start <= smb_last &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `				smb_lock->start <= cmp_last &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `				!cmp_lock->zero_len && !smb_lock->zero_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [LOCK|] `					spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00851 [LOCK|] `					spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00852 [ERROR_PATH|] `					pr_err_ratelimited("Not allow lock operation on exclusive lock range\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00853 [PROTO_GATE|] `					rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00854 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00855 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `			    }`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [LOCK|] `			spin_unlock(&conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00859 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [LOCK|] `		spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00861 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `out_check_cl:`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `		if (lock_is_unlock(smb_lock->fl) && nolock) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `		if (smb_lock->fl->fl_type == F_UNLCK && nolock) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [ERROR_PATH|] `			pr_err_ratelimited("Try to unlock nolocked range\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00869 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_RANGE_NOT_LOCKED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00870 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00871 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `no_check_cl:`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `		flock = smb_lock->fl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		list_del(&smb_lock->llist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `		if (smb_lock->zero_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `			 * MS-SMB2 §2.2.26: zero-length lock ranges are valid`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `			 * and have defined overlap semantics.  POSIX vfs_lock_file()`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `			 * does not support length=0, so skip the VFS call.`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `			 * Track the lock in ksmbd's internal list (done at`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `			 * the skip label when rc==0 and flags != UNLOCK) and`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [PROTO_GATE|] `			 * return STATUS_SUCCESS.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00885 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `			rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `			err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [ERROR_PATH|] `			goto skip;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00889 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `		 * If the SMB lock range starts beyond OFFSET_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		 * the POSIX flock was clamped and cannot represent`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `		 * the actual range.  Skip the VFS lock call to avoid`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `		 * false conflicts between different high-offset ranges`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `		 * that all get mapped to the same clamped value.`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		 * ksmbd tracks the original SMB range in its own lock`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		 * list for correct conflict detection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `		if (smb_lock->start > OFFSET_MAX) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `			rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [ERROR_PATH|] `			goto skip;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00903 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `retry:`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		rc = vfs_lock_file(filp, smb_lock->cmd, flock, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `skip:`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [PROTO_GATE|] `		if (smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00908 [NONE] `			if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `				ksmbd_debug(SMB, "File unlocked\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `			} else if (rc == -ENOENT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_NOT_LOCKED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00912 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00913 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `			locks_free_lock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `			kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `			if (rc == FILE_LOCK_DEFERRED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `				void **argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `					    "would have to wait for getting lock\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `				list_add(&smb_lock->llist, &rollback_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [MEM_BOUNDS|] `				argv = kmalloc(sizeof(void *), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00925 [NONE] `				if (!argv) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `					err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00928 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `				argv[0] = flock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `				rc = setup_async_work(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `						      smb2_remove_blocked_lock,`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `						      argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `				if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `					kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `					err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00938 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [LOCK|] `					spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00940 [NONE] `					list_add(&work->fp_entry, &fp->blocked_works);`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [LOCK|] `					spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [PROTO_GATE|] `					smb2_send_interim_resp(work, STATUS_PENDING);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `					rc = smb2_wait_for_posix_lock(work, flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [LOCK|] `					spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00948 [NONE] `					list_del(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [LOCK|] `					spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `					if (work->state != KSMBD_WORK_ACTIVE || rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `						list_del(&smb_lock->llist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `						locks_free_lock(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `						if (work->state == KSMBD_WORK_CANCELLED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `							/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `							 * MS-SMB2 §3.3.5.14: send a`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `							 * final SMB2 LOCK error response`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [PROTO_GATE|] `						 * with STATUS_CANCELLED.  Do NOT`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00960 [NONE] `						 * use smb2_send_interim_resp()`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `						 * here — that sets the async`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `						 * flag and is for interim-only`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `						 * messages.  Set the status and`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `						 * fall through to smb2_set_err_rsp`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `							 * via out2 so the client receives`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `							 * a proper final response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `							 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `							rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [PROTO_GATE|] `								STATUS_CANCELLED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00970 [NONE] `							kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [ERROR_PATH|] `							goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00972 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `						if (rc == -ETIMEDOUT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [PROTO_GATE|] `							rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00975 [NONE] `							kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [ERROR_PATH|] `							goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00977 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `						rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [PROTO_GATE|] `							STATUS_RANGE_NOT_LOCKED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00981 [NONE] `						kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [ERROR_PATH|] `						goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00983 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `				list_del(&smb_lock->llist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `				release_async_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [ERROR_PATH|] `				goto retry;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00988 [NONE] `			} else if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `				list_add(&smb_lock->llist, &rollback_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [LOCK|] `				spin_lock(&work->conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00991 [NONE] `				list_add_tail(&smb_lock->clist,`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `					      &work->conn->lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `				list_add_tail(&smb_lock->flist,`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `					      &fp->lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [LOCK|] `				spin_unlock(&work->conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00996 [NONE] `				ksmbd_debug(SMB, "successful in taking lock\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00999 [NONE] `				err = rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01001 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [LIFETIME|] `	if (atomic_read(&fp->f_ci->op_count) > 1)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01006 [NONE] `		smb_break_all_oplock(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `	/* Store lock sequence after successful processing */`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	store_lock_sequence(fp, req->LockSequenceNumber);`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	rsp->StructureSize = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `	ksmbd_debug(SMB, "successful in taking lock\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01014 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `	err = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_lock_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `	list_for_each_entry_safe(smb_lock, tmp, &lock_list, llist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		locks_free_lock(smb_lock->fl);`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `		list_del(&smb_lock->llist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	list_for_each_entry_safe(smb_lock, tmp, &rollback_list, llist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `		struct file_lock *rlock = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `		rlock = smb_lock->fl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `		/* Convert to unlock */`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `		rlock->c.flc_type = F_UNLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `		rlock->fl_type = F_UNLCK;`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `		/* Apply the unlock to VFS */`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `		rc = vfs_lock_file(rlock->c.flc_file,`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `				   F_SETLK, rlock, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `		rc = vfs_lock_file(rlock->fl_file,`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `				   F_SETLK, rlock, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [ERROR_PATH|] `			pr_err("rollback unlock fail : %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `		/* Remove from all lists under proper locking */`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [LOCK|] `		spin_lock(&work->conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01052 [NONE] `		list_del(&smb_lock->clist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `		list_del(&smb_lock->flist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [LOCK|] `		spin_unlock(&work->conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01055 [NONE] `		list_del(&smb_lock->llist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `		locks_free_lock(smb_lock->fl);`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `		kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `out2:`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	ksmbd_debug(SMB, "failed in taking lock(flags : %x), err : %d\n", flags, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	if (!rsp->hdr.Status) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `		if (err == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01066 [NONE] `		else if (err == -ENOMEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01068 [NONE] `		else if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01070 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01072 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
