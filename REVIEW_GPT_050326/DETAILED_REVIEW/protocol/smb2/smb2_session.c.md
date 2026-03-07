# Line-by-line Review: src/protocol/smb2/smb2_session.c

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
- L00006 [NONE] ` *   smb2_session.c - Session setup + authentication`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/syscalls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/ethtool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/crc32.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/mount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `static int alloc_preauth_hash(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `			      struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	if (sess->Preauth_HashValue)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	if (!conn->preauth_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	sess->Preauth_HashValue = kmemdup(conn->preauth_info->Preauth_HashValue,`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `					  PREAUTH_HASHVALUE_SIZE, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	if (!sess->Preauth_HashValue)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `int generate_preauth_hash(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	u8 *preauth_hash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	if (conn->dialect != SMB311_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	if (conn->binding) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `		struct preauth_session *preauth_sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [LOCK|] `		down_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00093 [NONE] `		preauth_sess = ksmbd_preauth_session_lookup(conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		if (!preauth_sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `			preauth_sess = ksmbd_preauth_session_alloc(conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `			if (!preauth_sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [LOCK|] `				up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00098 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00099 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		preauth_hash = preauth_sess->Preauth_HashValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `		ksmbd_gen_preauth_integrity_hash(conn, work->request_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `						 preauth_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [LOCK|] `		up_write(&conn->session_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00106 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `		if (!sess->Preauth_HashValue)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `			if (alloc_preauth_hash(sess, conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00111 [NONE] `		preauth_hash = sess->Preauth_HashValue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	ksmbd_gen_preauth_integrity_hash(conn, work->request_buf, preauth_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `EXPORT_SYMBOL_IF_KUNIT(generate_preauth_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `int decode_negotiation_token(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `				    struct negotiate_message *negblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `				    size_t sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	if (!conn->use_spnego)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	if (ksmbd_decode_negTokenInit((char *)negblob, sz, conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		if (ksmbd_decode_negTokenTarg((char *)negblob, sz, conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `			kfree(conn->mechToken);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `			conn->mechToken = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `			conn->mechTokenLen = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `			ksmbd_debug(AUTH,`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `				    "SPNEGO decode failed, falling back to raw NTLMSSP\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `			conn->auth_mechs = KSMBD_AUTH_NTLMSSP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `			conn->preferred_auth_mech = KSMBD_AUTH_NTLMSSP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `			conn->use_spnego = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `EXPORT_SYMBOL_IF_KUNIT(decode_negotiation_token);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `int ntlm_negotiate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		   struct negotiate_message *negblob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		   size_t negblob_len, struct smb2_sess_setup_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	struct challenge_message *chgblob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	unsigned char *spnego_blob = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	u16 spnego_blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	char *neg_blob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	int sz, rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	ksmbd_debug(SMB, "negotiate phase\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	rc = ksmbd_decode_ntlmssp_neg_blob(negblob, negblob_len, work->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	sz = le16_to_cpu(rsp->SecurityBufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	chgblob = (struct challenge_message *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	memset(chgblob, 0, sizeof(struct challenge_message));`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	if (!work->conn->use_spnego) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		unsigned int max_blob_sz = work->response_sz -`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `					   ((char *)rsp->Buffer - (char *)work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, max_blob_sz, work->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		if (sz < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		rsp->SecurityBufferLength = cpu_to_le16(sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	sz = sizeof(struct challenge_message);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	sz += (strlen(ksmbd_netbios_name()) * 2 + 1 + 4) * 6;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [MEM_BOUNDS|] `	neg_blob = kzalloc(sz, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00178 [NONE] `	if (!neg_blob)`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	chgblob = (struct challenge_message *)neg_blob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	sz = ksmbd_build_ntlmssp_challenge_blob(chgblob, sz, work->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	if (sz < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00186 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	rc = build_spnego_ntlmssp_neg_blob(&spnego_blob, &spnego_blob_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `					   neg_blob, sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00193 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	if (spnego_blob_len > work->response_sz -`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	    ((char *)rsp->Buffer - (char *)work->response_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		kfree(spnego_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00200 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [MEM_BOUNDS|] `	memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00203 [NONE] `	rsp->SecurityBufferLength = cpu_to_le16(spnego_blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	kfree(spnego_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	kfree(neg_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ntlm_negotiate);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `struct authenticate_message *user_authblob(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `					   struct smb2_sess_setup_req *req)`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	int sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	if (conn->use_spnego && conn->mechToken)`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		return (struct authenticate_message *)conn->mechToken;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	sz = le16_to_cpu(req->SecurityBufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [PROTO_GATE|] `	return (struct authenticate_message *)((char *)&req->hdr.ProtocolId`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00223 [NONE] `					       + sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `EXPORT_SYMBOL_IF_KUNIT(user_authblob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `static struct ksmbd_user *session_user(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `				       struct smb2_sess_setup_req *req)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	struct authenticate_message *authblob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	struct ksmbd_user *user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	char *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	unsigned int name_off, name_len, secbuf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	if (conn->use_spnego && conn->mechToken)`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		secbuf_len = conn->mechTokenLen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		secbuf_len = le16_to_cpu(req->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	if (secbuf_len < sizeof(struct authenticate_message)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		ksmbd_debug(SMB, "blob len %d too small\n", secbuf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	authblob = user_authblob(conn, req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	name_off = le32_to_cpu(authblob->UserName.BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	name_len = le16_to_cpu(authblob->UserName.Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	if (secbuf_len < (u64)name_off + name_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	name = smb_strndup_from_utf16((const char *)authblob + name_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `				      name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `				      true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `				      conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	if (IS_ERR(name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [ERROR_PATH|] `		pr_err("cannot allocate memory\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00256 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	ksmbd_debug(SMB, "session setup request for user %s\n", name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	user = ksmbd_login_user(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	return user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `int ntlm_authenticate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		      struct smb2_sess_setup_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `		      struct smb2_sess_setup_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	struct channel *chann = NULL, *old;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	struct ksmbd_user *user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	u64 prev_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	int sz, rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	ksmbd_debug(SMB, "authenticate phase\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	if (conn->use_spnego) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		unsigned char *spnego_blob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		u16 spnego_blob_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `		rc = build_spnego_ntlmssp_auth_blob(&spnego_blob,`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `						    &spnego_blob_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `						    0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		if (spnego_blob_len > work->response_sz -`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `		    ((char *)rsp->Buffer - (char *)work->response_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `			kfree(spnego_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00292 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [MEM_BOUNDS|] `		memcpy(rsp->Buffer, spnego_blob, spnego_blob_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00295 [NONE] `		rsp->SecurityBufferLength = cpu_to_le16(spnego_blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		kfree(spnego_blob);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	user = session_user(conn, req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	if (!user) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `		ksmbd_debug(SMB, "Unknown user name or an error\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00303 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	/* Check for previous session */`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	prev_id = le64_to_cpu(req->PreviousSessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	if (prev_id && prev_id != sess->id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `		destroy_previous_session(conn, user, prev_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [LOCK|] `	down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00311 [PROTO_GATE|] `	if (sess->state == SMB2_SESSION_VALID) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00312 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		 * Re-authentication (MS-SMB2 3.3.5.2.5): accept the new`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		 * credentials and update the session user.  MS-SMB2 allows`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `		 * re-authentication with different credentials (including`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `		 * anonymous) on a valid session.`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `		if (conn->binding == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `			if (ksmbd_compare_user(sess->user, user)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `				ksmbd_free_user(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `				ksmbd_free_user(sess->user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `				sess->user = user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `			ksmbd_free_user(user);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		sess->user = user;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	if (conn->binding == false && user_guest(sess->user)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		if (server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [ERROR_PATH|] `			pr_err_ratelimited("Guest login rejected: server requires signing\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00337 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00338 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [PROTO_GATE|] `		rsp->SessionFlags = SMB2_SESSION_FLAG_IS_GUEST_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00340 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		struct authenticate_message *authblob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		authblob = user_authblob(conn, req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		if (conn->use_spnego && conn->mechToken)`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `			sz = conn->mechTokenLen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `			sz = le16_to_cpu(req->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		rc = ksmbd_decode_ntlmssp_auth_blob(authblob, sz, conn, sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `			set_user_flag(sess->user, KSMBD_USER_FLAG_BAD_PASSWORD);`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `			ksmbd_debug(SMB, "authentication failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `			 * Preserve -EINVAL for malformed NTLMSSP blobs`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [PROTO_GATE|] `			 * so it maps to STATUS_INVALID_PARAMETER.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00355 [PROTO_GATE|] `			 * Other errors map to STATUS_LOGON_FAILURE.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00356 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `			if (rc == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00359 [ERROR_PATH|] `			return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00360 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `		 * MS-SMB2 §3.3.5.5.3: set SESSION_FLAG_IS_NULL for`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		 * anonymous (null) sessions (NTLMSSP_ANONYMOUS flag set and`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		 * NtChallengeResponse length == 0).`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `		if (authblob &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		    le16_to_cpu(authblob->NtChallengeResponse.Length) == 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		    (le32_to_cpu(authblob->NegotiateFlags) & NTLMSSP_ANONYMOUS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [PROTO_GATE|] `			rsp->SessionFlags |= SMB2_SESSION_FLAG_IS_NULL_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00371 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	 * MS-SMB2 §3.3.5.5.2: Re-authentication.`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [PROTO_GATE|] `	 * When the session state is SMB2_SESSION_VALID and conn->binding is`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00377 [NONE] `	 * false, the client is performing re-authentication on an already`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	 * established session.  The server MUST NOT regenerate the signing`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	 * or encryption keys -- the Samba client (and Windows) do not update`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	 * their keys during re-auth, so regenerating keys server-side would`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	 * cause a signing key mismatch on the response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	 * For channel binding requests, fall through to binding_session so`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	 * the new channel gets its own signing key.`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [LOCK|] `	down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00387 [PROTO_GATE|] `	if (sess->state == SMB2_SESSION_VALID) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00388 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		if (conn->binding)`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [ERROR_PATH|] `			goto binding_session;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00391 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [PROTO_GATE|] `	if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00397 [NONE] `	     (conn->sign || server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [PROTO_GATE|] `	    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00399 [NONE] `		sess->sign = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	if (smb3_encryption_negotiated(conn) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [PROTO_GATE|] `			!(req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00403 [NONE] `		rc = conn->ops->generate_encryptionkey(conn, sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `					"SMB3 encryption key generation failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00408 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `		sess->enc = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `		 * When SMB3 encryption keys are available, signing is`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `		 * superseded by encryption and MUST be disabled so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [PROTO_GATE|] `		 * subsequent requests are not required to carry SMB2_FLAGS_SIGNED`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00414 [NONE] `		 * (they are authenticated by the Transform header instead).`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `		 * This restores the original behaviour where sess->sign was`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `		 * unconditionally cleared whenever sess->enc was set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		sess->sign = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		 * B.6: MS-SMB2 §3.3.5.5.2 — if the client sets`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [PROTO_GATE|] `		 * SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA (0x04) in the SESSION_SETUP`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00423 [NONE] `		 * request Flags field, the server MUST set`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [PROTO_GATE|] `		 * SMB2_SESSION_FLAG_ENCRYPT_DATA in the response and encrypt all`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [NONE] `		 * subsequent traffic on this session, regardless of the global`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `		 * encryption setting.`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `		 * Note: the global "smb2 encryption = yes" flag enables the`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		 * capability (keys are generated above), but does not force`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		 * per-session encryption.  Only client request or per-share`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		 * settings force encryption.`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [PROTO_GATE|] `		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00434 [PROTO_GATE|] `		    (req->Flags & SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00435 [NONE] `			sess->enc_forced = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [PROTO_GATE|] `			rsp->SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00437 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `binding_session:`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	if (conn->dialect >= SMB30_PROT_ID) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `		chann = lookup_chann_list(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		if (!chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [MEM_BOUNDS|] `			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00445 [NONE] `			if (!chann)`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `			chann->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `			atomic64_set(&chann->nonce_counter, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `			 * S3: Insert the channel into the session list before`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `			 * deriving the signing key (generate_signingkey uses`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `			 * lookup_chann_list to find the channel).  If key`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `			 * derivation fails we remove it again, eliminating the`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `			 * window where the channel is visible without a valid key.`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `			old = xa_store(&sess->ksmbd_chann_list, (long)conn, chann,`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `					KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `			if (xa_is_err(old)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `				kfree(chann);`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `				return xa_err(old);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `			if (conn->ops->generate_signingkey) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `				rc = conn->ops->generate_signingkey(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `				if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `					ksmbd_debug(SMB, "SMB3 signing key generation failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `					xa_erase(&sess->ksmbd_chann_list, (long)conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `					kfree(chann);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [ERROR_PATH|] `					return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00472 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [ERROR_PATH|] `			goto ntlm_skip_signingkey;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00476 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	if (conn->ops->generate_signingkey) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `		rc = conn->ops->generate_signingkey(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00484 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `ntlm_skip_signingkey:`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	if (conn->dialect > SMB20_PROT_ID) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		if (!ksmbd_conn_lookup_dialect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [ERROR_PATH|] `			pr_err_ratelimited("fail to verify the dialect\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00491 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00492 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ntlm_authenticate);`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `static int krb5_authenticate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `			     struct smb2_sess_setup_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `			     struct smb2_sess_setup_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	char *in_blob, *out_blob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	struct channel *chann = NULL, *old;`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	u64 prev_sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	int in_len, out_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	int retval;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	if ((u64)le16_to_cpu(req->SecurityBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	    le16_to_cpu(req->SecurityBufferLength) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	    get_rfc1002_len(work->request_buf) + 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00514 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [PROTO_GATE|] `	in_blob = (char *)&req->hdr.ProtocolId +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00516 [NONE] `		le16_to_cpu(req->SecurityBufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	in_len = le16_to_cpu(req->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [PROTO_GATE|] `	out_blob = (char *)&rsp->hdr.ProtocolId +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00519 [NONE] `		le16_to_cpu(rsp->SecurityBufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	out_len = work->response_sz -`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `		(le16_to_cpu(rsp->SecurityBufferOffset) + 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	retval = ksmbd_krb5_authenticate(sess, in_blob, in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `					 out_blob, &out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	if (retval) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `		ksmbd_debug(SMB, "krb5 authentication failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00528 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	/* Check previous session */`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	prev_sess_id = le64_to_cpu(req->PreviousSessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	if (prev_sess_id && prev_sess_id != sess->id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `		destroy_previous_session(conn, sess->user, prev_sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	rsp->SecurityBufferLength = cpu_to_le16(out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	 * B.14 (krb5 path): MS-SMB2 §3.3.5.5.2 — re-authentication key update.`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	 * When the session is already valid and conn->binding is false, the`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	 * client is re-authenticating (e.g. after Kerberos ticket renewal).`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	 * Regenerate signing and encryption keys rather than returning early`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	 * with stale cryptographic material.  For binding requests, fall`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	 * through to binding_session for channel key generation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [LOCK|] `	down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00547 [PROTO_GATE|] `	if (sess->state == SMB2_SESSION_VALID) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00548 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		if (conn->binding)`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [ERROR_PATH|] `			goto binding_session;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00551 [NONE] `		/* Re-auth: fall through to regenerate signing/encryption keys */`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [PROTO_GATE|] `	if ((rsp->SessionFlags != SMB2_SESSION_FLAG_IS_GUEST_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00557 [NONE] `	    (conn->sign || server_conf.signing == KSMBD_CONFIG_OPT_MANDATORY)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [PROTO_GATE|] `	    (req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00559 [NONE] `		sess->sign = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	if (smb3_encryption_negotiated(conn) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [PROTO_GATE|] `	    !(req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00563 [NONE] `		retval = conn->ops->generate_encryptionkey(conn, sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `		if (retval) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `				    "SMB3 encryption key generation failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00568 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		sess->enc = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		/* Encryption supersedes signing; clear sign as in ntlm path */`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `		sess->sign = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [PROTO_GATE|] `		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00574 [PROTO_GATE|] `		    (req->Flags & SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00575 [NONE] `			sess->enc_forced = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [PROTO_GATE|] `			rsp->SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00577 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `binding_session:`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	if (conn->dialect >= SMB30_PROT_ID) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `		chann = lookup_chann_list(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `		if (!chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [MEM_BOUNDS|] `			chann = kmalloc(sizeof(struct channel), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00585 [NONE] `			if (!chann)`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `			chann->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `			atomic64_set(&chann->nonce_counter, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `			/* S3: insert channel before signingkey derivation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `			old = xa_store(&sess->ksmbd_chann_list, (long)conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `					chann, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `			if (xa_is_err(old)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `				kfree(chann);`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `				return xa_err(old);`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `			if (conn->ops->generate_signingkey) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `				retval = conn->ops->generate_signingkey(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `				if (retval) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `					ksmbd_debug(SMB, "SMB3 signing key generation failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `					xa_erase(&sess->ksmbd_chann_list, (long)conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `					kfree(chann);`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [ERROR_PATH|] `					return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00606 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [ERROR_PATH|] `			goto krb5_skip_signingkey;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00610 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	if (conn->ops->generate_signingkey) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		retval = conn->ops->generate_signingkey(sess, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		if (retval) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `			ksmbd_debug(SMB, "SMB3 signing key generation failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00618 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `krb5_skip_signingkey:`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	if (conn->dialect > SMB20_PROT_ID) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		if (!ksmbd_conn_lookup_dialect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [ERROR_PATH|] `			pr_err_ratelimited("fail to verify the dialect\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00625 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00626 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `int smb2_sess_setup(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	struct smb2_sess_setup_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	struct smb2_sess_setup_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	struct negotiate_message *negblob;`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `	unsigned int negblob_len, negblob_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	ksmbd_debug(SMB, "Received smb2 session setup request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	if (!ksmbd_conn_need_setup(conn) && !ksmbd_conn_good(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `		work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	rsp->SessionFlags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	rsp->SecurityBufferOffset = cpu_to_le16(72);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	rsp->SecurityBufferLength = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	ksmbd_conn_lock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	if (!req->hdr.SessionId) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		sess = ksmbd_smb2_session_create();`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `		if (!sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `			rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00661 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `		rsp->hdr.SessionId = cpu_to_le64(sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `		rc = ksmbd_session_register(conn, sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `		conn->binding = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	} else if (conn->dialect >= SMB30_PROT_ID &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `		   (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [PROTO_GATE|] `		   req->Flags & SMB2_SESSION_REQ_FLAG_BINDING) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00671 [NONE] `		u64 sess_id = le64_to_cpu(req->hdr.SessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		sess = ksmbd_session_lookup_slowpath(sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		if (!sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00677 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `		if (conn->dialect != sess->dialect) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00682 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `		 * MS-SMB2 3.3.5.2.7: Session binding requests MUST be`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `		 * signed.  Verify the flag here; actual cryptographic`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `		 * signature verification is performed below after`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `		 * work->sess is set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [PROTO_GATE|] `		if (!(req->hdr.Flags & SMB2_FLAGS_SIGNED)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00691 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00693 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `		if (memcmp(conn->ClientGUID, sess->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [PROTO_GATE|] `			   SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00697 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00699 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [LOCK|] `		down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00702 [PROTO_GATE|] `		if (sess->state == SMB2_SESSION_IN_PROGRESS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00703 [NONE] `			up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00706 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [PROTO_GATE|] `		if (sess->state == SMB2_SESSION_EXPIRED) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00709 [NONE] `			up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `			rc = -EFAULT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00712 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `		if (ksmbd_conn_need_reconnect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `			rc = -EFAULT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `			ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `			sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00720 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `		if (is_ksmbd_session_in_connection(conn, sess_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00725 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `		if (user_guest(sess->user)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `			rc = -EOPNOTSUPP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00730 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `		conn->binding = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	} else if ((conn->dialect < SMB30_PROT_ID ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `		    !(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [PROTO_GATE|] `		   (req->Flags & SMB2_SESSION_REQ_FLAG_BINDING)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00736 [NONE] `		sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00739 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `		sess = ksmbd_session_lookup(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `					    le64_to_cpu(req->hdr.SessionId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `		if (!sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00745 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [LOCK|] `		down_read(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00748 [PROTO_GATE|] `		if (sess->state == SMB2_SESSION_EXPIRED) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00749 [NONE] `			up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `			rc = -EFAULT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00752 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `		up_read(&sess->state_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `		if (ksmbd_conn_need_reconnect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `			rc = -EFAULT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `			ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `			sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00760 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `		conn->binding = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	work->sess = sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	 * MS-SMB2 3.3.5.2.7: Verify the signature on binding requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	 * using the session's signing key. This must happen after`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	 * work->sess is set so that check_sign_req can locate the key.`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	 * Note: __process_request() cannot do this because work->sess`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `	 * is NULL at that point (smb2_check_user_session skips`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	 * SESSION_SETUP).`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	if (conn->binding) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `		if (!conn->ops->check_sign_req ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `		    !conn->ops->check_sign_req(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [ERROR_PATH|] `			pr_err_ratelimited("Session binding signature verification failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00778 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00780 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	negblob_off = le16_to_cpu(req->SecurityBufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `	negblob_len = le16_to_cpu(req->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `	if (negblob_off < offsetof(struct smb2_sess_setup_req, Buffer)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00788 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	if ((u64)negblob_off + negblob_len > get_rfc1002_len(work->request_buf) + 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00792 [NONE] `			"SESSION_SETUP security blob out of bounds: off=%u len=%u msg_len=%u mid=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			negblob_off, negblob_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `			get_rfc1002_len(work->request_buf) + 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `			le64_to_cpu(req->hdr.MessageId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00798 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [PROTO_GATE|] `	negblob = (struct negotiate_message *)((char *)&req->hdr.ProtocolId +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00801 [NONE] `			negblob_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `	if (decode_negotiation_token(conn, negblob, negblob_len) == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `		if (conn->mechToken) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `			negblob = (struct negotiate_message *)conn->mechToken;`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `			negblob_len = conn->mechTokenLen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	if (negblob_len < offsetof(struct negotiate_message, NegotiateFlags)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00813 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	if (server_conf.auth_mechs & conn->auth_mechs) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `		rc = generate_preauth_hash(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `		if (conn->preferred_auth_mech &`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `				(KSMBD_AUTH_KRB5 | KSMBD_AUTH_MSKRB5)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `			rc = krb5_authenticate(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [ERROR_PATH|] `				goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00826 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `			if (!ksmbd_conn_need_reconnect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `				ksmbd_conn_set_good(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [LOCK|] `				down_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00831 [PROTO_GATE|] `				sess->state = SMB2_SESSION_VALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00832 [LOCK|] `				up_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00833 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `			/* S4: Clean up preauth session after Kerberos binding */`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `			if (conn->binding) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `				struct preauth_session *preauth_sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `				preauth_sess =`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `					ksmbd_preauth_session_lookup(conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `				if (preauth_sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `					list_del(&preauth_sess->preauth_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `					kfree(preauth_sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `		} else if (conn->preferred_auth_mech == KSMBD_AUTH_NTLMSSP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `			if (negblob->MessageType == NtLmNegotiate) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `				rc = ntlm_negotiate(work, negblob, negblob_len, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `				if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [ERROR_PATH|] `					goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00850 [NONE] `				rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [PROTO_GATE|] `					STATUS_MORE_PROCESSING_REQUIRED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00852 [NONE] `			} else if (negblob->MessageType == NtLmAuthenticate) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `				rc = ntlm_authenticate(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `				if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [ERROR_PATH|] `					goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00856 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `				if (!ksmbd_conn_need_reconnect(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `					ksmbd_conn_set_good(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [LOCK|] `					down_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00860 [PROTO_GATE|] `					sess->state = SMB2_SESSION_VALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00861 [LOCK|] `					up_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00862 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `				if (conn->binding)`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `					ksmbd_preauth_session_remove(conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `				pr_info_ratelimited("Unknown NTLMSSP message type : 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `						le32_to_cpu(negblob->MessageType));`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `			/* TODO: need one more negotiation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [ERROR_PATH|] `			pr_err_ratelimited("Not support the preferred authentication\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00873 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [ERROR_PATH|] `		pr_err_ratelimited("Not support authentication\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00877 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	if (rc == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00883 [NONE] `	else if (rc == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00885 [NONE] `	else if (rc == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00887 [NONE] `	else if (rc == -EFAULT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NETWORK_SESSION_EXPIRED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00889 [NONE] `	else if (rc == -ENOMEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00891 [NONE] `	else if (rc == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00893 [NONE] `	else if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_LOGON_FAILURE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00895 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	if (conn->use_spnego && conn->mechToken) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		kfree(conn->mechToken);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		conn->mechToken = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `		 * SecurityBufferOffset should be set to zero`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `		 * in session setup error response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		rsp->SecurityBufferOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `		if (sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `			bool try_delay = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `			 * To mitigate dictionary attacks, force the client to`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `			 * reconnect on auth failure. The TCP handshake provides`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `			 * natural rate limiting (~100-300ms per attempt).`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `			if (sess->user && sess->user->flags & KSMBD_USER_FLAG_DELAY_SESSION)`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `				try_delay = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `			WRITE_ONCE(sess->last_active, jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [LOCK|] `			down_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00921 [PROTO_GATE|] `			sess->state = SMB2_SESSION_EXPIRED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00922 [LOCK|] `			up_write(&sess->state_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00923 [NONE] `			ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `			work->sess = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `			if (try_delay) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `				pr_info_ratelimited("Auth failure from %pIS, forcing reconnect\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `						    KSMBD_TCP_PEER_SOCKADDR(conn));`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `				ksmbd_conn_set_need_reconnect(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		unsigned int iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `		if (rsp->SecurityBufferLength)`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `			iov_len = offsetof(struct smb2_sess_setup_rsp, Buffer) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `				le16_to_cpu(rsp->SecurityBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `			iov_len = sizeof(struct smb2_sess_setup_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `		rc = ksmbd_iov_pin_rsp(work, rsp, iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00943 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	ksmbd_conn_unlock(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
