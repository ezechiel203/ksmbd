# Line-by-line Review: src/protocol/smb2/smb2_pdu_common.c

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
- L00006 [NONE] ` *   smb2_pdu_common.c - Shared helpers, signing, encryption, credit management`
  Review: Low-risk line; verify in surrounding control flow.
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
- L00062 [NONE] `void __wbuf(struct ksmbd_work *work, void **req, void **rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		*req = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		*rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `		*req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `		*rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * smb2_check_channel_sequence() - validate ChannelSequence for state-modifying requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * @work: smb work containing the request`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * @fp:   open file handle`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * MS-SMB2 §3.3.5.2.10: For dialects ≥ 2.1, state-modifying requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * (WRITE, LOCK, IOCTL, SET_INFO, FLUSH) carry a ChannelSequence in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * low 16 bits of the request header Status field.  If the sequence is`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * behind the last one seen on this open, the request is stale (e.g. a`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * retransmit after channel failover) and must be rejected.`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` * Return: 0 on success, -EAGAIN if the request should return`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [PROTO_GATE|] ` *         STATUS_FILE_NOT_AVAILABLE to the client.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00086 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `int smb2_check_channel_sequence(struct ksmbd_work *work, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	struct smb2_hdr *hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	__u16 req_seq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	s16 diff;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	/* ChannelSequence only defined for dialect ≥ 2.1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	if (work->conn->dialect <= SMB20_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	 * In request packets, the Status field (32-bit) is overlaid as:`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	 *   bits [15:0]  = ChannelSequence`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	 *   bits [31:16] = Reserved (MBZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	req_seq = (__u16)le32_to_cpu(hdr->Status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [LOCK|] `	spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00105 [NONE] `	diff = (s16)(req_seq - fp->channel_sequence);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	if (diff < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		/* Stale request: ChannelSequence is behind the open's last seen */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [LOCK|] `		spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00109 [ERROR_PATH|] `		pr_warn_ratelimited("ChannelSequence stale: req=%u open=%u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00110 [NONE] `				    req_seq, fp->channel_sequence);`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [ERROR_PATH|] `		return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00112 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	if (diff > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		fp->channel_sequence = req_seq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [LOCK|] `	spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00116 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_check_channel_sequence);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `struct channel *lookup_chann_list(struct ksmbd_session *sess, struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	return xa_load(&sess->ksmbd_chann_list, (long)conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` * smb2_get_ksmbd_tcon() - get tree connection information using a tree id.`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * Return:	0 if there is a tree connection matched or these are`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` *		skipable commands, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `int smb2_get_ksmbd_tcon(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	unsigned int cmd = le16_to_cpu(req_hdr->Command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	unsigned int tree_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [PROTO_GATE|] `	if (cmd == SMB2_TREE_CONNECT_HE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00139 [PROTO_GATE|] `	    cmd ==  SMB2_CANCEL_HE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00140 [PROTO_GATE|] `	    cmd ==  SMB2_LOGOFF_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00141 [NONE] `		ksmbd_debug(SMB, "skip to check tree connect request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	if (xa_empty(&work->sess->tree_conns)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		ksmbd_debug(SMB, "NO tree connected\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00148 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	tree_id = le32_to_cpu(req_hdr->Id.SyncId.TreeId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		bool is_related = !!(req_hdr->Flags &`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [PROTO_GATE|] `				     SMB2_FLAGS_RELATED_OPERATIONS);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		if (is_related) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `			 * Related request: inherit tree connect from`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `			 * previous request.  If no tcon was`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [ERROR_PATH|] `			 * established, return -EINVAL which maps to`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00161 [PROTO_GATE|] `			 * STATUS_INVALID_PARAMETER.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00162 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `			if (!work->tcon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00165 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		 * Unrelated request in a compound: look up the`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		 * tree connect independently by TreeId.`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		 * Release the previous tcon reference first.`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		if (work->tcon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `			ksmbd_tree_connect_put(work->tcon);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		work->tcon = ksmbd_tree_conn_lookup(work->sess, tree_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		if (!work->tcon) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [ERROR_PATH|] `			pr_err_ratelimited("Invalid tid %d in compound\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00178 [NONE] `					   tree_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00180 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	work->tcon = ksmbd_tree_conn_lookup(work->sess, tree_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	if (!work->tcon) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [ERROR_PATH|] `		pr_err_ratelimited("Invalid tid %d\n", tree_id);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00187 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00188 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	 * B.10: Per-session encryption enforcement at tree-connect level.`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	 * MS-SMB2 §3.3.5.2.5 and §3.3.5.5.2: when the client established`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [PROTO_GATE|] `	 * this session with SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA (resulting in`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00194 [NONE] `	 * sess->enc_forced == true and SESSION_FLAG_ENCRYPT_DATA set in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	 * SESSION_SETUP response), ALL subsequent requests on this session`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	 * MUST arrive encrypted.  Unencrypted requests on an`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [PROTO_GATE|] `	 * encryption-required session are rejected with STATUS_ACCESS_DENIED`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00198 [NONE] `	 * and the connection is terminated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [PROTO_GATE|] `	 * This check supplements the global KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00201 [NONE] `	 * enforcement in server.c, covering the case where a client explicitly`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	 * requested per-session encryption but the global flag is not set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	 * Commands NEGOTIATE and SESSION_SETUP are exempt because they are used`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	 * to establish the encrypted channel.`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	 * Note: sess->enc means encryption keys are available; sess->enc_forced`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	 * means encryption was actually negotiated as required (the server set`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [PROTO_GATE|] `	 * SMB2_SESSION_FLAG_ENCRYPT_DATA in the SESSION_SETUP response).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00209 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	if (work->sess->enc_forced && !work->encrypted) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `		struct smb2_hdr *rsp_hdr = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [ERROR_PATH|] `		pr_warn_ratelimited("Unencrypted request (cmd=0x%x) on per-session encrypted session, disconnecting\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00214 [NONE] `				    cmd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [PROTO_GATE|] `		rsp_hdr->Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		ksmbd_conn_set_exiting(work->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00219 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * smb2_set_err_rsp() - set error response code on smb response`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` * @work:	smb work containing response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `void smb2_set_err_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	struct smb2_err_rsp *err_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		err_rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		err_rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [PROTO_GATE|] `	if (err_rsp->hdr.Status != STATUS_STOPPED_ON_SYMLINK) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00238 [NONE] `		int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [PROTO_GATE|] `		err_rsp->StructureSize = SMB2_ERROR_STRUCTURE_SIZE2_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00241 [NONE] `		err_rsp->ErrorContextCount = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		err_rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `		err_rsp->ByteCount = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `		err_rsp->ErrorData[0] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		err = ksmbd_iov_pin_rsp(work, (void *)err_rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [PROTO_GATE|] `					__SMB2_HEADER_STRUCTURE_SIZE +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00247 [PROTO_GATE|] `					SMB2_ERROR_STRUCTURE_SIZE2);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00248 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `			work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` * is_smb2_neg_cmd() - is it smb2 negotiation command`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` * @work:	smb work containing smb header`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ` * Return:      true if smb2 negotiation command, otherwise false`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `bool is_smb2_neg_cmd(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	/* is it SMB2 header ? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [PROTO_GATE|] `	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00265 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	/* make sure it is request not response message */`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [PROTO_GATE|] `	if (hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00269 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [PROTO_GATE|] `	if (hdr->Command != SMB2_NEGOTIATE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00272 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ` * is_smb2_rsp() - is it smb2 response`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ` * @work:	smb work containing smb response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ` * Return:      true if smb2 response, otherwise false`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `bool is_smb2_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	struct smb2_hdr *hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	/* is it SMB2 header ? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [PROTO_GATE|] `	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	/* make sure it is response not request message */`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [PROTO_GATE|] `	if (!(hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00293 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ` * get_smb2_cmd_val() - get smb command code from smb header`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` * Return:      smb2 request command value`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `u16 get_smb2_cmd_val(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	struct smb2_hdr *rcv_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		rcv_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		rcv_hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	return le16_to_cpu(rcv_hdr->Command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] ` * set_smb2_rsp_status() - set error response code on smb2 header`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ` * @work:	smb work containing response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ` * @err:	error response code`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `void set_smb2_rsp_status(struct ksmbd_work *work, __le32 err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	rsp_hdr->Status = err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	work->iov_idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	work->iov_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	work->next_smb2_rcv_hdr_off = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ` * init_smb2_neg_rsp() - initialize smb2 response for negotiate command`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` * smb2 negotiate response is sent in reply of smb1 negotiate command for`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` * dialect auto-negotiation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `int init_smb2_neg_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	struct smb2_negotiate_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [PROTO_GATE|] `	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00350 [PROTO_GATE|] `	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [NONE] `	rsp_hdr->CreditRequest = cpu_to_le16(2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [PROTO_GATE|] `	rsp_hdr->Command = SMB2_NEGOTIATE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00353 [PROTO_GATE|] `	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00354 [PROTO_GATE|] `	rsp_hdr->NextCommand = 0;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00355 [NONE] `	rsp_hdr->MessageId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	rsp_hdr->Id.SyncId.ProcessId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	rsp_hdr->Id.SyncId.TreeId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	rsp_hdr->SessionId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	memset(rsp_hdr->Signature, 0, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [ERROR_PATH|] `	WARN_ON(ksmbd_conn_good(conn));`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	rsp->StructureSize = cpu_to_le16(65);`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	ksmbd_debug(SMB, "conn->dialect 0x%x\n", conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	rsp->DialectRevision = cpu_to_le16(conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	/* Not setting conn guid rsp->ServerGUID, as it`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	 * not used by client for identifying connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	/* Default Max Message Size till SMB2.0, 64K*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	rsp->MaxTransactSize = cpu_to_le32(conn->vals->max_trans_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	rsp->MaxReadSize = cpu_to_le32(conn->vals->max_read_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	rsp->MaxWriteSize = cpu_to_le32(conn->vals->max_write_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	rsp->SystemTime = cpu_to_le64(ksmbd_systime());`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	rsp->ServerStartTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	rsp->SecurityBufferOffset = cpu_to_le16(128);`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	rsp->SecurityBufferLength = cpu_to_le16(AUTH_GSS_LENGTH);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	ksmbd_copy_gss_neg_header((char *)(&rsp->hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		le16_to_cpu(rsp->SecurityBufferOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [PROTO_GATE|] `	rsp->SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [NONE] `	if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [PROTO_GATE|] `		rsp->SecurityMode |= SMB2_NEGOTIATE_SIGNING_REQUIRED_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [NONE] `	err = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_negotiate_rsp) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `				AUTH_GSS_LENGTH);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	conn->use_spnego = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	ksmbd_conn_set_need_negotiate(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ` * smb2_set_rsp_credits() - set number of credits in response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ` * @work:	smb work containing smb response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `int smb2_set_rsp_credits(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	struct smb2_hdr *hdr = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	unsigned short credits_requested, aux_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	unsigned short credit_charge, credits_granted = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	if (work->send_no_response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [PROTO_GATE|] `	hdr->CreditCharge = req_hdr->CreditCharge;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	if (conn->total_credits > conn->vals->max_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `		hdr->CreditRequest = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [ERROR_PATH|] `		pr_err_ratelimited("Total credits overflow: %d\n", conn->total_credits);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00417 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00418 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	credit_charge = max_t(unsigned short,`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [PROTO_GATE|] `			      le16_to_cpu(req_hdr->CreditCharge), 1);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		    "credit_rsp: lock_enter cmd=%u charge=%u req=%u total=%u out=%u granted_total=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		    le16_to_cpu(req_hdr->Command), credit_charge,`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `		    le16_to_cpu(req_hdr->CreditRequest), conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		    conn->outstanding_credits, work->credits_granted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [LOCK|] `	spin_lock(&conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00429 [NONE] `	if (credit_charge > conn->total_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [LOCK|] `		spin_unlock(&conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00431 [NONE] `		ksmbd_debug(SMB, "Insufficient credits granted, given: %u, granted: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `			    credit_charge, conn->total_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00434 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	conn->total_credits -= credit_charge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	if (work->credit_charge_tracked) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		if (credit_charge > conn->outstanding_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [ERROR_PATH|] `			pr_err_ratelimited("Outstanding credits underflow: charge %u, outstanding %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00440 [NONE] `				   credit_charge, conn->outstanding_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `			conn->outstanding_credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `			conn->outstanding_credits -= credit_charge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `			    "credit_rsp: no outstanding debit for cmd=%u charge=%u (uncharged request path)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `			    le16_to_cpu(req_hdr->Command), credit_charge);`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	credits_requested = max_t(unsigned short,`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `				  le16_to_cpu(req_hdr->CreditRequest), 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	/* according to smb2.credits smbtorture, Windows server`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	 * 2016 or later grant up to 8192 credits at once.`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	 * TODO: Need to adjuct CreditRequest value according to`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	 * current cpu load`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [PROTO_GATE|] `	if (hdr->Command == SMB2_NEGOTIATE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00460 [NONE] `		aux_max = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		aux_max = conn->vals->max_credits - conn->total_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	credits_granted = min_t(unsigned short, credits_requested, aux_max);`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	conn->total_credits += credits_granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	work->credits_granted += credits_granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `		    "credit_rsp: lock_exit cmd=%u charge=%u req=%u granted=%u total=%u out=%u granted_total=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `		    le16_to_cpu(req_hdr->Command), credit_charge,`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		    credits_requested, credits_granted, conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `		    conn->outstanding_credits, work->credits_granted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [LOCK|] `	spin_unlock(&conn->credits_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [PROTO_GATE|] `	if (!req_hdr->NextCommand) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00475 [NONE] `		/* Update CreditRequest in last request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `		hdr->CreditRequest = cpu_to_le16(work->credits_granted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `		    "credits: requested[%d] granted[%d] total_granted[%d]\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `		    credits_requested, credits_granted,`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		    conn->total_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ` * init_chained_smb2_rsp() - initialize smb2 chained response`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ` * @work:	smb work containing smb response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `VISIBLE_IF_KUNIT void init_chained_smb2_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	struct smb2_hdr *req = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	struct smb2_hdr *rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	struct smb2_hdr *rcv_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	int next_hdr_offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	int len, new_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	/* Len of this response = updated RFC len - offset of previous cmd`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	 * in the compound rsp`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	/* Storing the current local FID which may be needed by subsequent`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	 * command in the compound request`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [PROTO_GATE|] `	if (req->Command == SMB2_CREATE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00506 [PROTO_GATE|] `		if (rsp->Status == STATUS_SUCCESS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00507 [NONE] `			work->compound_fid = ((struct smb2_create_rsp *)rsp)->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `			work->compound_pfid = ((struct smb2_create_rsp *)rsp)->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `			work->compound_sid = le64_to_cpu(rsp->SessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `			 * CREATE failed: record the error so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `			 * subsequent related operations propagate it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `			work->compound_err_status = rsp->Status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [PROTO_GATE|] `	} else if (rsp->Status == STATUS_SUCCESS &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00518 [NONE] `		   !has_file_id(work->compound_fid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `		 * MS-SMB2 §3.3.5.2.7.2: For related compound requests,`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `		 * if the next request has VolatileFileId = 0xFFFFFFFFFFFFFFFF,`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `		 * the server uses the FID from the previous operation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `		 * Capture the FID from non-CREATE commands that succeeded`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `		 * so subsequent related operations can reference it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `		u64 vol = KSMBD_NO_FID, per = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		switch (req->Command) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [PROTO_GATE|] `		case SMB2_CLOSE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00530 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `			struct smb2_close_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [PROTO_GATE|] `		case SMB2_FLUSH:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00538 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `			struct smb2_flush_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [PROTO_GATE|] `		case SMB2_READ:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00546 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `			struct smb2_read_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [PROTO_GATE|] `		case SMB2_WRITE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00554 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `			struct smb2_write_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [PROTO_GATE|] `		case SMB2_QUERY_INFO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00562 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `			struct smb2_query_info_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [PROTO_GATE|] `		case SMB2_SET_INFO:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00570 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `			struct smb2_set_info_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [PROTO_GATE|] `		case SMB2_LOCK:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00578 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `			struct smb2_lock_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [PROTO_GATE|] `		case SMB2_IOCTL:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00586 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `			struct smb2_ioctl_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [PROTO_GATE|] `		case SMB2_QUERY_DIRECTORY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00594 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `			struct smb2_query_directory_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [PROTO_GATE|] `		case SMB2_CHANGE_NOTIFY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00602 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `			struct smb2_notify_req *r = (void *)req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `			vol = r->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `			per = r->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		if (has_file_id(vol)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `			work->compound_fid = vol;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `			work->compound_pfid = per;`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `			work->compound_sid = le64_to_cpu(rsp->SessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [PROTO_GATE|] `	} else if (req->Flags & SMB2_FLAGS_RELATED_OPERATIONS &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00619 [PROTO_GATE|] `		   rsp->Status != STATUS_SUCCESS &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00620 [NONE] `		   !has_file_id(work->compound_fid) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [PROTO_GATE|] `		   work->compound_err_status == STATUS_SUCCESS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00622 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		 * Non-CREATE related request failed and no compound`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		 * file handle was established.  Propagate this error`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		 * to subsequent related requests (e.g. NOTIFY failing`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		 * with INVALID_PARAMETER should cascade to CLOSE).`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		 * We only do this when compound_fid is invalid (no`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		 * successful CREATE preceded this) and compound_err_status`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		 * is not already set, so that a valid compound handle`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		 * from a successful CREATE is never overridden.`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		work->compound_err_status = rsp->Status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	len = get_rfc1002_len(work->response_buf) - work->next_smb2_rsp_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [PROTO_GATE|] `	next_hdr_offset = le32_to_cpu(req->NextCommand);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	new_len = ALIGN(len, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	work->iov[work->iov_idx].iov_len += (new_len - len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	inc_rfc1001_len(work->response_buf, new_len - len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [PROTO_GATE|] `	rsp->NextCommand = cpu_to_le32(new_len);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	work->next_smb2_rcv_hdr_off += next_hdr_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	work->curr_smb2_rsp_hdr_off = work->next_smb2_rsp_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	work->next_smb2_rsp_hdr_off += new_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `		    "Compound req new_len = %d rcv off = %d rsp off = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `		    new_len, work->next_smb2_rcv_hdr_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `		    work->next_smb2_rsp_hdr_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	rsp_hdr = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	rcv_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [PROTO_GATE|] `	if (!(rcv_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00656 [NONE] `		ksmbd_debug(SMB, "related flag should be set\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		work->compound_fid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `		work->compound_pfid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [PROTO_GATE|] `		work->compound_err_status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00660 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	memset((char *)rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [PROTO_GATE|] `	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00663 [PROTO_GATE|] `	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00664 [NONE] `	rsp_hdr->Command = rcv_hdr->Command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	 * Message is response. We don't grant oplock yet.`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [PROTO_GATE|] `	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00670 [PROTO_GATE|] `				SMB2_FLAGS_RELATED_OPERATIONS);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00671 [PROTO_GATE|] `	rsp_hdr->NextCommand = 0;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00672 [NONE] `	rsp_hdr->MessageId = rcv_hdr->MessageId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	rsp_hdr->Id.SyncId.ProcessId = rcv_hdr->Id.SyncId.ProcessId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	rsp_hdr->Id.SyncId.TreeId = rcv_hdr->Id.SyncId.TreeId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	rsp_hdr->SessionId = rcv_hdr->SessionId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [MEM_BOUNDS|] `	memcpy(rsp_hdr->Signature, rcv_hdr->Signature, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00677 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `EXPORT_SYMBOL_IF_KUNIT(init_chained_smb2_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ` * is_chained_smb2_message() - check for chained command`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ` * Return:      true if chained request, otherwise false`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `bool is_chained_smb2_message(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	unsigned int next_cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [PROTO_GATE|] `	if (hdr->ProtocolId != SMB2_PROTO_NUMBER)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00692 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [PROTO_GATE|] `	next_cmd = le32_to_cpu(hdr->NextCommand);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00696 [NONE] `	if (next_cmd > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `		if ((u64)work->next_smb2_rcv_hdr_off + next_cmd +`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [PROTO_GATE|] `			__SMB2_HEADER_STRUCTURE_SIZE >`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00699 [NONE] `		    get_rfc1002_len(work->request_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [ERROR_PATH|] `			pr_err_ratelimited("next command(%u) offset exceeds smb msg size\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00701 [NONE] `					   next_cmd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `		if ((u64)get_rfc1002_len(work->response_buf) + MAX_CIFS_SMALL_BUFFER_SIZE >`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `		    work->response_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [ERROR_PATH|] `			pr_err_ratelimited("next response offset exceeds response buffer size\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00708 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `		ksmbd_debug(SMB, "got SMB2 chained command\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		init_chained_smb2_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	} else if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `		 * This is the last request in a chained command.`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `		 * Per MS-SMB2 3.3.4.1.3, the last response SHOULD`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `		 * also be padded to 8-byte alignment.  Windows and`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		 * Samba both do this, and smbtorture tests require it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `		int len, pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `		len = get_rfc1002_len(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `		pad = ALIGN(len, 8) - len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `		if (pad) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `			work->iov[work->iov_idx].iov_len += pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `			inc_rfc1001_len(work->response_buf, pad);`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `		work->curr_smb2_rsp_hdr_off = work->next_smb2_rsp_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] ` * init_smb2_rsp_hdr() - initialize smb2 response`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] ` * Return:      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `int init_smb2_rsp_hdr(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	struct smb2_hdr *rsp_hdr = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	struct smb2_hdr *rcv_hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [PROTO_GATE|] `	rsp_hdr->ProtocolId = rcv_hdr->ProtocolId;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00747 [PROTO_GATE|] `	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00748 [NONE] `	rsp_hdr->Command = rcv_hdr->Command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	 * Message is response. We don't grant oplock yet.`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [PROTO_GATE|] `	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00754 [PROTO_GATE|] `	rsp_hdr->NextCommand = 0;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00755 [NONE] `	rsp_hdr->MessageId = rcv_hdr->MessageId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	rsp_hdr->Id.SyncId.ProcessId = rcv_hdr->Id.SyncId.ProcessId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	rsp_hdr->Id.SyncId.TreeId = rcv_hdr->Id.SyncId.TreeId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	rsp_hdr->SessionId = rcv_hdr->SessionId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [MEM_BOUNDS|] `	memcpy(rsp_hdr->Signature, rcv_hdr->Signature, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00760 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] ` * smb2_allocate_rsp_buf() - allocate smb2 response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `int smb2_allocate_rsp_buf(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	size_t small_sz = MAX_CIFS_SMALL_BUFFER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	size_t large_sz = small_sz + work->conn->vals->max_trans_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	size_t sz = small_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	int cmd = le16_to_cpu(hdr->Command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [PROTO_GATE|] `	if (cmd == SMB2_IOCTL_HE || cmd == SMB2_QUERY_DIRECTORY_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00779 [NONE] `		sz = large_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [PROTO_GATE|] `	if (cmd == SMB2_QUERY_INFO_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00782 [NONE] `		struct smb2_query_info_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `		if (get_rfc1002_len(work->request_buf) <`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `		    offsetof(struct smb2_query_info_req, OutputBufferLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `		req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [PROTO_GATE|] `		if ((req->InfoType == SMB2_O_INFO_FILE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00790 [NONE] `		     (req->FileInfoClass == FILE_FULL_EA_INFORMATION ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `		     req->FileInfoClass == FILE_ALL_INFORMATION)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [PROTO_GATE|] `		    req->InfoType == SMB2_O_INFO_SECURITY)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00793 [NONE] `			sz = large_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	/* allocate large response buf for chained commands */`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [PROTO_GATE|] `	if (le32_to_cpu(hdr->NextCommand) > 0)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00798 [NONE] `		sz = large_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [MEM_BOUNDS|] `	work->response_buf = kvzalloc(sz, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00801 [NONE] `	if (!work->response_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	work->response_sz = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] ` * smb2_check_user_session() - check for valid session for a user`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ` * @work:	smb work containing smb request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `int smb2_check_user_session(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	unsigned int cmd = le16_to_cpu(req_hdr->Command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `	unsigned long long sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [PROTO_GATE|] `	 * SMB2_ECHO, SMB2_NEGOTIATE, SMB2_SESSION_SETUP command do not`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00823 [NONE] `	 * require a session id, so no need to validate user session's for`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	 * these commands.`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [PROTO_GATE|] `	if (cmd == SMB2_ECHO_HE || cmd == SMB2_NEGOTIATE_HE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00827 [PROTO_GATE|] `	    cmd == SMB2_SESSION_SETUP_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00828 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `	if (!ksmbd_conn_good(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00832 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	sess_id = le64_to_cpu(req_hdr->SessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `		bool is_related = !!(req_hdr->Flags &`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [PROTO_GATE|] `				     SMB2_FLAGS_RELATED_OPERATIONS);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `		if (is_related) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `			 * Related request: inherit session from`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `			 * previous request in the compound chain.`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `			 * If no session was established (previous`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [ERROR_PATH|] `			 * request failed), return -EINVAL which maps`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00845 [PROTO_GATE|] `			 * to STATUS_INVALID_PARAMETER per MS-SMB2`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00846 [NONE] `			 * 3.3.5.2.3.`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `			if (!work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00850 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `		 * Unrelated request in a compound: look up the`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `		 * session independently by the SessionId in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `		 * request header, just like a first request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		 * Release the previous session reference first to`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `		 * avoid refcount leaks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `			ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `		work->sess = ksmbd_session_lookup_all(conn, sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `			return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `		ksmbd_debug(SMB, "Invalid user session in compound, Uid %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `			    sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00868 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `	/* Check for validity of user session */`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	work->sess = ksmbd_session_lookup_all(conn, sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `	ksmbd_debug(SMB, "Invalid user session, Uid %llu\n", sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [ERROR_PATH|] `	return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00876 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] ` * smb2_get_name() - get filename string from on the wire smb format`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] ` * @src:	source buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] ` * @maxlen:	maxlen of source string`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] ` * @local_nls:	nls_table pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ` * Return:      matching converted filename on success, otherwise error ptr`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `char *`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `smb2_get_name(const char *src, const int maxlen, struct nls_table *local_nls)`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	char *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `	name = smb_strndup_from_utf16(src, maxlen, 1, local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	if (IS_ERR(name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [ERROR_PATH|] `		pr_err("failed to get name %ld\n", PTR_ERR(name));`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00894 [NONE] `		return name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	if (*name == '\0') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	if (*name == '\\') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [ERROR_PATH|] `		pr_err("not allow directory name included leading slash\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00904 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		return ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `	ksmbd_conv_path_to_unix(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `	ksmbd_strip_last_slash(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	return name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `int setup_async_work(struct ksmbd_work *work, void (*fn)(void **), void **arg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	int id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `	unsigned int max_async = READ_ONCE(server_conf.max_async_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	 * Enforce the max async credits limit.  When the number of`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	 * outstanding async operations reaches the limit, reject`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `	 * with -ENOSPC which the caller maps to`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [PROTO_GATE|] `	 * STATUS_INSUFFICIENT_RESOURCES.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00924 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	if (max_async &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [LIFETIME|] `	    atomic_inc_return(&conn->outstanding_async) >= max_async) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00927 [LIFETIME|] `		atomic_dec(&conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00928 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00929 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	id = ksmbd_acquire_async_msg_id(&conn->async_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	if (id < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [ERROR_PATH|] `		pr_err("Failed to alloc async message id\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00934 [NONE] `		if (max_async)`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [LIFETIME|] `			atomic_dec(&conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00936 [NONE] `		return id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	work->asynchronous = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	work->async_id = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `		    "Send interim Response to inform async request id : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `		    work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	work->cancel_fn = fn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	work->cancel_argv = arg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	if (list_empty(&work->async_request_entry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [LOCK|] `		spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00950 [NONE] `		list_add_tail(&work->async_request_entry, &conn->async_requests);`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [LOCK|] `		spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00952 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `void release_async_work(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [LOCK|] `	spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00962 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [LOCK|] `	spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	work->asynchronous = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	work->cancel_fn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	kfree(work->cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	work->cancel_argv = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	if (work->async_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `		ksmbd_release_id(&conn->async_ida, work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `		work->async_id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `		/* Decrement outstanding async count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `		if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [LIFETIME|] `			atomic_dec(&conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00975 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `void smb2_send_interim_resp(struct ksmbd_work *work, __le32 status)`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	struct smb2_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	struct ksmbd_work *in_work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `	if (!in_work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	if (allocate_interim_rsp_buf(in_work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [ERROR_PATH|] `		pr_err("smb_allocate_rsp_buf failed!\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00989 [NONE] `		ksmbd_free_work_struct(in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	in_work->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	in_work->sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `	in_work->encrypted = work->encrypted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [MEM_BOUNDS|] `	memcpy(smb2_get_msg(in_work->response_buf), ksmbd_resp_buf_next(work),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00997 [PROTO_GATE|] `	       __SMB2_HEADER_STRUCTURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `	rsp_hdr = smb2_get_msg(in_work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [PROTO_GATE|] `	rsp_hdr->Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01001 [NONE] `	rsp_hdr->Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	smb2_set_err_rsp(in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `	rsp_hdr->Status = status;`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `	/* Encrypt the interim response if the session requires encryption */`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	if (in_work->sess && in_work->sess->enc && in_work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	    conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `		int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `		rc = conn->ops->encrypt_resp(in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `				    "Failed to encrypt interim response: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `				    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `	ksmbd_conn_write(in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `	ksmbd_free_work_struct(in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `__le32 smb2_get_reparse_tag_special_file(umode_t mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `	if (S_ISDIR(mode) || S_ISREG(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	if (S_ISLNK(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		return IO_REPARSE_TAG_LX_SYMLINK_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	else if (S_ISFIFO(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `		return IO_REPARSE_TAG_LX_FIFO_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `	else if (S_ISSOCK(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `		return IO_REPARSE_TAG_AF_UNIX_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	else if (S_ISCHR(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `		return IO_REPARSE_TAG_LX_CHR_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `	else if (S_ISBLK(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `		return IO_REPARSE_TAG_LX_BLK_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] ` * smb2_get_dos_mode() - get file mode in dos format from unix mode`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ` * @stat:	kstat containing file mode`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ` * @attribute:	attribute flags`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] ` * Return:      converted dos mode`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `int smb2_get_dos_mode(struct kstat *stat, int attribute)`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	int attr = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	if (S_ISDIR(stat->mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `		attr = ATTR_DIRECTORY |`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `			(attribute & (ATTR_HIDDEN | ATTR_SYSTEM));`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `		attr = (attribute & 0x00005137) | ATTR_ARCHIVE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `		attr &= ~(ATTR_DIRECTORY);`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `		if (smb2_get_reparse_tag_special_file(stat->mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `			attr |= ATTR_REPARSE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	return attr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `bool smb2_is_sign_req(struct ksmbd_work *work, unsigned int command)`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	struct smb2_hdr *rcv_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `	 * B.11: MS-SMB2 §3.3.5.16 — "The server MUST NOT require the`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	 * SMB2 CANCEL Request to be signed."  Exclude CANCEL from signing`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `	 * enforcement so that legitimate cancel requests on signing-required`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [PROTO_GATE|] `	 * sessions are not incorrectly rejected with STATUS_ACCESS_DENIED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01075 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [PROTO_GATE|] `	 * B.12: SMB2_OPLOCK_BREAK_HE is excluded unconditionally here so`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01077 [NONE] `	 * that server-to-client oplock break notifications (which have no`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `	 * client signature) are not rejected.  Client acknowledgments that`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [PROTO_GATE|] `	 * arrive with SMB2_FLAGS_SIGNED set will be verified through the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01080 [PROTO_GATE|] `	 * SMB2_FLAGS_SIGNED branch below.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01081 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [PROTO_GATE|] `	if (command == SMB2_NEGOTIATE_HE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01083 [PROTO_GATE|] `	    command == SMB2_CANCEL_HE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01084 [PROTO_GATE|] `	    command == SMB2_OPLOCK_BREAK_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01085 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	 * For compound sub-requests, use the current request header.`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	 * For single requests or the first compound request, use the`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	 * first (and only) header.`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `		rcv_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `		 * MS-SMB2 §3.3.5.2.3: Related compound sub-requests`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `		 * inherit the session/signing context of the first`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `		 * request.  The server MUST NOT verify their signatures.`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [PROTO_GATE|] `		if (rcv_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01101 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `		rcv_hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `	 * SESSION_SETUP: skip signing for initial auth (no key yet),`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [PROTO_GATE|] `	 * but require it when SMB2_FLAGS_SIGNED is set (binding requests).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01109 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [PROTO_GATE|] `	if (command == SMB2_SESSION_SETUP_HE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01111 [PROTO_GATE|] `	    !(rcv_hdr->Flags & SMB2_FLAGS_SIGNED))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01112 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [PROTO_GATE|] `	if ((rcv_hdr->Flags & SMB2_FLAGS_SIGNED) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01115 [NONE] `	    (work->sess && work->sess->sign))`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] ` * smb2_check_sign_req() - handler for req packet sign processing`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] ` * @work:   smb work containing notify command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] ` * Return:	1 on success, 0 otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `int smb2_check_sign_req(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [PROTO_GATE|] `	char signature_req[SMB2_SIGNATURE_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01131 [PROTO_GATE|] `	char signature[SMB2_HMACSHA256_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01132 [NONE] `	struct kvec iov[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	size_t len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	if (!work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `		hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	 * B.11: MS-SMB2 §3.3.5.16 — CANCEL must NOT be verified even on`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	 * signing-required sessions. This is a defence-in-depth guard;`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	 * smb2_is_sign_req() already excludes CANCEL from signing`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	 * enforcement so check_sign_req() should not normally be called`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `	 * for CANCEL, but add the check here as an explicit safety net.`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [PROTO_GATE|] `	if (le16_to_cpu(hdr->Command) == SMB2_CANCEL_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01150 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [PROTO_GATE|] `	if (!hdr->NextCommand && !work->next_smb2_rcv_hdr_off)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01153 [NONE] `		len = get_rfc1002_len(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [PROTO_GATE|] `	else if (hdr->NextCommand)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01155 [PROTO_GATE|] `		len = le32_to_cpu(hdr->NextCommand);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01156 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `		len = get_rfc1002_len(work->request_buf) -`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `			work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(signature_req, hdr->Signature, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01161 [PROTO_GATE|] `	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [PROTO_GATE|] `	iov[0].iov_base = (char *)&hdr->ProtocolId;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01164 [NONE] `	iov[0].iov_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `	if (ksmbd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `				signature))`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [PROTO_GATE|] `	if (crypto_memneq(signature, signature_req, SMB2_SIGNATURE_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01171 [ERROR_PATH|] `		pr_err_ratelimited("bad smb2 signature\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01172 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] ` * smb2_set_sign_rsp() - handler for rsp packet sign processing`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] ` * @work:   smb work containing notify command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `void smb2_set_sign_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [PROTO_GATE|] `	char signature[SMB2_HMACSHA256_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01187 [NONE] `	struct kvec *iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `	int n_vec = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	hdr = ksmbd_resp_buf_curr(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [PROTO_GATE|] `	hdr->Flags |= SMB2_FLAGS_SIGNED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01192 [PROTO_GATE|] `	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [PROTO_GATE|] `	if (hdr->Command == SMB2_READ) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01195 [NONE] `		if (work->iov_idx == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `		/* Need at least 2 iov entries: header + read data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `		if (work->iov_idx < 1 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `		    work->iov_idx + 1 > work->iov_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [ERROR_PATH|] `			pr_err("invalid iov state for READ signing: idx=%d cnt=%d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01201 [NONE] `			       work->iov_idx, work->iov_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `		iov = &work->iov[work->iov_idx - 1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `		n_vec++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `		if (work->iov_idx >= work->iov_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [ERROR_PATH|] `			pr_err("invalid iov index for signing: idx=%d cnt=%d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01209 [NONE] `			       work->iov_idx, work->iov_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `		iov = &work->iov[work->iov_idx];`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	if (!ksmbd_sign_smb2_pdu(work->conn, work->sess->sess_key, iov, n_vec,`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `				 signature))`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(hdr->Signature, signature, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01218 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] ` * smb3_check_sign_req() - handler for req packet sign processing`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] ` * @work:   smb work containing notify command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] ` * Return:	1 on success, 0 otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `int smb3_check_sign_req(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	char *signing_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	struct channel *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [PROTO_GATE|] `	char signature_req[SMB2_SIGNATURE_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01233 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [PROTO_GATE|] `	 * Use SMB2_HMACSHA256_SIZE (32) as the signing buffer size`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01235 [NONE] `	 * to accommodate HMAC-SHA-256 which produces 32 bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	 * AES-CMAC and AES-GMAC produce 16 bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [PROTO_GATE|] `	 * Only the first SMB2_SIGNATURE_SIZE (16) bytes are compared.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01238 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [PROTO_GATE|] `	char signature[SMB2_HMACSHA256_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01240 [NONE] `	struct kvec iov[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `	size_t len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	if (!work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `		hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	 * B.11: CANCEL must not be signature-verified (MS-SMB2 §3.3.5.16).`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `	 * Defence-in-depth: smb2_is_sign_req() already gates this, but`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	 * be explicit in both SMB2 and SMB3 check paths.`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [PROTO_GATE|] `	if (le16_to_cpu(hdr->Command) == SMB2_CANCEL_HE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01256 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [PROTO_GATE|] `	if (!hdr->NextCommand && !work->next_smb2_rcv_hdr_off)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01259 [NONE] `		len = get_rfc1002_len(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [PROTO_GATE|] `	else if (hdr->NextCommand)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01261 [PROTO_GATE|] `		len = le32_to_cpu(hdr->NextCommand);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01262 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `		len = get_rfc1002_len(work->request_buf) -`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `			work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [PROTO_GATE|] `	if (le16_to_cpu(hdr->Command) == SMB2_SESSION_SETUP_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01267 [NONE] `		signing_key = work->sess->smb3signingkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `		chann = lookup_chann_list(work->sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `		if (!chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `		signing_key = chann->smb3signingkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	if (!signing_key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [ERROR_PATH|] `		pr_err("SMB3 signing key is not generated\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01278 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(signature_req, hdr->Signature, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01282 [PROTO_GATE|] `	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01283 [PROTO_GATE|] `	iov[0].iov_base = (char *)&hdr->ProtocolId;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01284 [NONE] `	iov[0].iov_len = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `	if (conn->signing_algorithm == SIGNING_ALG_AES_GMAC) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `		if (ksmbd_sign_smb3_pdu_gmac(conn, signing_key, iov, 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `					      signature))`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	} else if (conn->signing_algorithm == SIGNING_ALG_HMAC_SHA256) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `		if (ksmbd_sign_smb2_pdu(conn, signing_key, iov, 1, signature))`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `		if (ksmbd_sign_smb3_pdu(conn, signing_key, iov, 1, signature))`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [PROTO_GATE|] `	if (crypto_memneq(signature, signature_req, SMB2_SIGNATURE_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01299 [ERROR_PATH|] `		pr_err_ratelimited("bad smb2 signature\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01300 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] ` * smb3_set_sign_rsp() - handler for rsp packet sign processing`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] ` * @work:   smb work containing notify command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `void smb3_set_sign_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `	struct channel *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [PROTO_GATE|] `	char signature[SMB2_HMACSHA256_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01317 [NONE] `	struct kvec *iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	int n_vec = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `	char *signing_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `	hdr = ksmbd_resp_buf_curr(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	if (conn->binding == false &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [PROTO_GATE|] `	    le16_to_cpu(hdr->Command) == SMB2_SESSION_SETUP_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01326 [NONE] `		signing_key = work->sess->smb3signingkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `		chann = lookup_chann_list(work->sess, work->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `		if (!chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `		signing_key = chann->smb3signingkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `	if (!signing_key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [ERROR_PATH|] `		pr_warn_once("SMB3 signing key not available for response\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01337 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [PROTO_GATE|] `	hdr->Flags |= SMB2_FLAGS_SIGNED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01341 [PROTO_GATE|] `	memset(hdr->Signature, 0, SMB2_SIGNATURE_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [PROTO_GATE|] `	if (hdr->Command == SMB2_READ) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01344 [NONE] `		if (work->iov_idx == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `		/* Need at least 2 iov entries: header + read data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `		if (work->iov_idx < 1 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `		    work->iov_idx + 1 > work->iov_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [ERROR_PATH|] `			pr_err("invalid iov state for READ signing: idx=%d cnt=%d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01350 [NONE] `			       work->iov_idx, work->iov_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `		iov = &work->iov[work->iov_idx - 1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `		n_vec++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `		if (work->iov_idx >= work->iov_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [ERROR_PATH|] `			pr_err("invalid iov index for signing: idx=%d cnt=%d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01358 [NONE] `			       work->iov_idx, work->iov_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `		iov = &work->iov[work->iov_idx];`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `	if (conn->signing_algorithm == SIGNING_ALG_AES_GMAC)`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `		rc = ksmbd_sign_smb3_pdu_gmac(conn, signing_key, iov, n_vec,`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `					       signature);`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	else if (conn->signing_algorithm == SIGNING_ALG_HMAC_SHA256)`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `		rc = ksmbd_sign_smb2_pdu(conn, signing_key, iov, n_vec,`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `					 signature);`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `		rc = ksmbd_sign_smb3_pdu(conn, signing_key, iov, n_vec,`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `					 signature);`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [MEM_BOUNDS|PROTO_GATE|] `		memcpy(hdr->Signature, signature, SMB2_SIGNATURE_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01375 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] ` * smb3_preauth_hash_rsp() - handler for computing preauth hash on response`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] ` * @work:   smb work containing response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `void smb3_preauth_hash_rsp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	struct smb2_hdr *req, *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `	if (conn->dialect != SMB311_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [PROTO_GATE|] `	if (le16_to_cpu(req->Command) == SMB2_NEGOTIATE_HE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01394 [NONE] `	    conn->preauth_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `		ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `						 conn->preauth_info->Preauth_HashValue);`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [PROTO_GATE|] `	if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE && sess) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01399 [NONE] `		if (conn->binding) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `			struct preauth_session *preauth_sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [LOCK|] `			down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01403 [NONE] `			preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `			if (!preauth_sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [LOCK|] `				up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01406 [NONE] `				return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `			ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `							 preauth_sess->Preauth_HashValue);`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [LOCK|] `			up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01411 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `			if (!sess->Preauth_HashValue)`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `				return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `			ksmbd_gen_preauth_integrity_hash(conn, work->response_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `							 sess->Preauth_HashValue);`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] ` * ksmbd_gcm_nonce_limit_reached() - check if GCM nonce counter is exhausted`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] ` * @sess:	session to check`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] ` * For deterministic (counter-based) GCM nonces the theoretical limit`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] ` * is 2^64, but we cap at 2^63 - 1 to stay well within safe bounds.`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] ` * Return: true if the nonce space is exhausted`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `VISIBLE_IF_KUNIT bool ksmbd_gcm_nonce_limit_reached(struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `	return atomic64_read(&sess->gcm_nonce_counter) >= S64_MAX;`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_gcm_nonce_limit_reached);`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `VISIBLE_IF_KUNIT int fill_transform_hdr(void *tr_buf, char *old_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `					 __le16 cipher_type,`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `					 struct ksmbd_session *sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `	struct smb2_transform_hdr *tr_hdr = tr_buf + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `	struct smb2_hdr *hdr = smb2_get_msg(old_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `	unsigned int orig_len = get_rfc1002_len(old_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `	memset(tr_buf, 0, sizeof(struct smb2_transform_hdr) + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [PROTO_GATE|] `	tr_hdr->ProtocolId = SMB2_TRANSFORM_PROTO_NUM;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01446 [NONE] `	tr_hdr->OriginalMessageSize = cpu_to_le32(orig_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `	tr_hdr->Flags = cpu_to_le16(0x01);`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [PROTO_GATE|] `	if (cipher_type == SMB2_ENCRYPTION_AES128_GCM ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01449 [PROTO_GATE|] `	    cipher_type == SMB2_ENCRYPTION_AES256_GCM) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01450 [NONE] `		__le64 counter_le;`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `		if (sess && !ksmbd_gcm_nonce_limit_reached(sess)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `			u64 counter;`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `			 * Use deterministic nonce: 4-byte random`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `			 * session prefix + 8-byte monotonic counter.`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `			 * This guarantees uniqueness per session key`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `			 * and avoids the birthday-bound risk of fully`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `			 * random nonces.`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `			counter = atomic64_inc_return(`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `					&sess->gcm_nonce_counter);`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [MEM_BOUNDS|] `			memcpy(&tr_hdr->Nonce,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01465 [NONE] `			       sess->gcm_nonce_prefix, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `			counter_le = cpu_to_le64(counter);`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [MEM_BOUNDS|] `			memcpy(&tr_hdr->Nonce[4],`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01468 [NONE] `			       &counter_le, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `			 * Fallback: no session or counter exhausted;`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `			 * use random nonce.  Counter exhaustion means`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `			 * the key must be rotated — log a warning.`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `			if (sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [ERROR_PATH|] `				pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01477 [NONE] `					"GCM nonce counter exhausted for session %llu, using random nonce\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `					sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `			get_random_bytes(&tr_hdr->Nonce,`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `					 SMB3_AES_GCM_NONCE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `		get_random_bytes(&tr_hdr->Nonce, SMB3_AES_CCM_NONCE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [MEM_BOUNDS|] `	memcpy(&tr_hdr->SessionId, &hdr->SessionId, 8);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01486 [NONE] `	inc_rfc1001_len(tr_buf, sizeof(struct smb2_transform_hdr));`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `	inc_rfc1001_len(tr_buf, orig_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `EXPORT_SYMBOL_IF_KUNIT(fill_transform_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `int smb3_encrypt_resp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `	struct kvec *iov = work->iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	int rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `	void *tr_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [MEM_BOUNDS|] `	tr_buf = kzalloc(sizeof(struct smb2_transform_hdr) + 4, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01499 [NONE] `	if (!tr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `	/* fill transform header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `	fill_transform_hdr(tr_buf, work->response_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `			   work->conn->cipher_type, work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `	iov[0].iov_base = tr_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `	iov[0].iov_len = sizeof(struct smb2_transform_hdr) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `	work->tr_buf = tr_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `	return ksmbd_crypt_message(work, iov, work->iov_idx + 1, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `bool smb3_is_transform_hdr(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `	struct smb2_transform_hdr *trhdr = smb2_get_msg(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [PROTO_GATE|] `	return trhdr->ProtocolId == SMB2_TRANSFORM_PROTO_NUM;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01518 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `int smb3_decrypt_req(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	char *buf = work->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `	unsigned int pdu_length = get_rfc1002_len(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `	struct kvec iov[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `	int buf_data_size = pdu_length - sizeof(struct smb2_transform_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `	struct smb2_transform_hdr *tr_hdr = smb2_get_msg(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `	if (pdu_length < sizeof(struct smb2_transform_hdr) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `	    buf_data_size < sizeof(struct smb2_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [ERROR_PATH|] `		pr_err_ratelimited("Transform message is too small (%u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01533 [NONE] `				   pdu_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01535 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `	if (buf_data_size < le32_to_cpu(tr_hdr->OriginalMessageSize)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [ERROR_PATH|] `		pr_err_ratelimited("Transform message is broken\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01539 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01540 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `	 * Transform Flags validation: MS-SMB2 §2.2.41 states the Flags`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `	 * field in the SMB2 TRANSFORM_HEADER MUST be set to 0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	 * (Encrypted bit).  Any other value is malformed and must be`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `	 * rejected to prevent unexpected behaviour in the decrypt path.`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `	if (tr_hdr->Flags != cpu_to_le16(0x0001)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [ERROR_PATH|] `		pr_err_ratelimited("Transform header has invalid Flags 0x%04x (expected 0x0001)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01550 [NONE] `				   le16_to_cpu(tr_hdr->Flags));`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `	 * Use ksmbd_session_lookup() (not _all) so that expired sessions`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `	 * can still be used for decryption.  After logoff, the session`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [PROTO_GATE|] `	 * state is SMB2_SESSION_EXPIRED but the decryption key is still`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01558 [NONE] `	 * valid.  The session state check happens later in`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	 * smb2_check_user_session(), which will properly return`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [PROTO_GATE|] `	 * STATUS_USER_SESSION_DELETED.  This prevents the client from`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01561 [NONE] `	 * hanging when it sends an encrypted request after logoff.`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `	sess = ksmbd_session_lookup(work->conn, le64_to_cpu(tr_hdr->SessionId));`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] `	if (!sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [ERROR_PATH|] `		pr_err_ratelimited("invalid session id(%llx) in transform header\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01566 [NONE] `				   le64_to_cpu(tr_hdr->SessionId));`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01568 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `	iov[0].iov_base = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `	iov[0].iov_len = sizeof(struct smb2_transform_hdr) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `	iov[1].iov_base = buf + sizeof(struct smb2_transform_hdr) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `	iov[1].iov_len = buf_data_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `	rc = ksmbd_crypt_message(work, iov, 2, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `		ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [MEM_BOUNDS|] `	memmove(buf + 4, iov[1].iov_base, buf_data_size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01581 [NONE] `	*(__be32 *)buf = cpu_to_be32(buf_data_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `	ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `bool smb3_11_final_sess_setup_resp(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `	struct smb2_hdr *rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `	if (conn->dialect < SMB30_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `		rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [PROTO_GATE|] `	if (le16_to_cpu(rsp->Command) == SMB2_SESSION_SETUP_HE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01600 [NONE] `	    sess->user && !user_guest(sess->user) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [PROTO_GATE|] `	    rsp->Status == STATUS_SUCCESS)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01602 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
