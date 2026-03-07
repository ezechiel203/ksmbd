# Line-by-line Review: src/protocol/smb2/smb2_misc_cmds.c

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
- L00057 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` * smb2_close_pipe() - handler for closing IPC pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` * @work:	smb work containing close request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * Return:	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `static noinline int smb2_close_pipe(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	u64 id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	struct smb2_close_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	struct smb2_close_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	ksmbd_session_rpc_close(work->sess, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	rsp->StructureSize = cpu_to_le16(60);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	rsp->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	rsp->CreationTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	rsp->LastAccessTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	rsp->LastWriteTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	rsp->ChangeTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	rsp->AllocationSize = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	rsp->EndOfFile = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	rsp->Attributes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	return ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `				 sizeof(struct smb2_close_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * smb2_close() - handler for smb2 close file command`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * @work:	smb work containing close request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `int smb2_close(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	u64 volatile_id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	u64 sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	struct smb2_close_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	struct smb2_close_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	ksmbd_debug(SMB, "Received smb2 close request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `				   KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		ksmbd_debug(SMB, "IPC pipe close request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		return smb2_close_pipe(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	sess_id = le64_to_cpu(req->hdr.SessionId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [PROTO_GATE|] `	if (req->hdr.Flags & SMB2_FLAGS_RELATED_OPERATIONS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00120 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		 * Related request: use the compound session ID if set`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		 * (from a prior CREATE), otherwise use the session from`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `		 * the main dispatch loop which already validated it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		if (work->compound_sid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `			sess_id = work->compound_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		else if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `			sess_id = work->sess->id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	work->compound_sid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	if (check_session_id(conn, sess_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		work->compound_sid = sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_USER_SESSION_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [PROTO_GATE|] `		if (req->hdr.Flags & SMB2_FLAGS_RELATED_OPERATIONS)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00137 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00138 [NONE] `		err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00140 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	if (work->next_smb2_rcv_hdr_off &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	    !has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		if (!has_file_id(work->compound_fid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `			/* file already closed, return FILE_CLOSED */`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `			ksmbd_debug(SMB, "file already closed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00148 [NONE] `			err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00150 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `				    "Compound request set FID = %llu:%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `				    work->compound_fid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `				    work->compound_pfid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `			volatile_id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `			/* file closed, stored id is not valid anymore */`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `			work->compound_fid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `			work->compound_pfid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		volatile_id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	ksmbd_debug(SMB, "volatile_id = %llu\n", volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	rsp->StructureSize = cpu_to_le16(60);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [PROTO_GATE|] `	if (req->Flags == SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00170 [NONE] `		struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		fp = ksmbd_lookup_fd_fast(work, volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `		if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `			err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00177 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `				  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00184 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [PROTO_GATE|] `		rsp->Flags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00187 [NONE] `		rsp->AllocationSize = S_ISDIR(stat.mode) ? 0 :`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `			cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		rsp->EndOfFile = cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		rsp->Attributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		rsp->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		rsp->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		rsp->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		rsp->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		rsp->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		rsp->AllocationSize = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		rsp->EndOfFile = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		rsp->Attributes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		rsp->CreationTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `		rsp->LastAccessTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		rsp->LastWriteTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `		rsp->ChangeTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	err = ksmbd_close_fd(work, volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	if (!err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `		err = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `					sizeof(struct smb2_close_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `		if (rsp->hdr.Status == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` * smb2_echo() - handler for smb2 echo(ping) command`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` * @work:	smb work containing echo request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `int smb2_echo(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	struct smb2_echo_rsp *rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	ksmbd_debug(SMB, "Received smb2 echo request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	rsp->StructureSize = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	return ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_echo_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ` * smb20_oplock_break_ack() - handler for smb2.0 oplock break command`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` * @work:	smb work containing oplock break command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ` * Return:	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `static void smb20_oplock_break_ack(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	struct smb2_oplock_break *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	struct smb2_oplock_break *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	struct oplock_info *opinfo = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	__le32 err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	u64 volatile_id, persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	char req_oplevel = 0, rsp_oplevel = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	unsigned int oplock_change_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	volatile_id = le64_to_cpu(req->VolatileFid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	persistent_id = le64_to_cpu(req->PersistentFid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	req_oplevel = req->OplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	ksmbd_debug(OPLOCK, "v_id %llu, p_id %llu request oplock level %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		    volatile_id, persistent_id, req_oplevel);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00274 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	if (!opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [ERROR_PATH|] `		pr_err("unexpected null oplock_info\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00281 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_OPLOCK_PROTOCOL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00282 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [PROTO_GATE|] `	if (opinfo->level == SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00288 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_OPLOCK_PROTOCOL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00290 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (opinfo->op_state == OPLOCK_STATE_NONE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		ksmbd_debug(SMB, "unexpected oplock state 0x%x\n", opinfo->op_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNSUCCESSFUL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00295 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00296 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [PROTO_GATE|] `	if ((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00299 [PROTO_GATE|] `	     opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [PROTO_GATE|] `	    (req_oplevel != SMB2_OPLOCK_LEVEL_II &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00301 [PROTO_GATE|] `	     req_oplevel != SMB2_OPLOCK_LEVEL_NONE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00302 [PROTO_GATE|] `		err = STATUS_INVALID_OPLOCK_PROTOCOL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00303 [NONE] `		oplock_change_type = OPLOCK_WRITE_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [PROTO_GATE|] `	} else if (opinfo->level == SMB2_OPLOCK_LEVEL_II &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00305 [PROTO_GATE|] `		   req_oplevel != SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00306 [PROTO_GATE|] `		err = STATUS_INVALID_OPLOCK_PROTOCOL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00307 [NONE] `		oplock_change_type = OPLOCK_READ_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [PROTO_GATE|] `	} else if (req_oplevel == SMB2_OPLOCK_LEVEL_II ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00309 [PROTO_GATE|] `		   req_oplevel == SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00310 [PROTO_GATE|] `		err = STATUS_INVALID_DEVICE_STATE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00311 [PROTO_GATE|] `		if ((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00312 [PROTO_GATE|] `		     opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00313 [PROTO_GATE|] `		    req_oplevel == SMB2_OPLOCK_LEVEL_II) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00314 [NONE] `			oplock_change_type = OPLOCK_WRITE_TO_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [PROTO_GATE|] `		} else if ((opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00316 [PROTO_GATE|] `			    opinfo->level == SMB2_OPLOCK_LEVEL_BATCH) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00317 [PROTO_GATE|] `			   req_oplevel == SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00318 [NONE] `			oplock_change_type = OPLOCK_WRITE_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [PROTO_GATE|] `		} else if (opinfo->level == SMB2_OPLOCK_LEVEL_II &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00320 [PROTO_GATE|] `			   req_oplevel == SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00321 [NONE] `			oplock_change_type = OPLOCK_READ_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `			oplock_change_type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		oplock_change_type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	switch (oplock_change_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	case OPLOCK_WRITE_TO_READ:`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		ret = opinfo_write_to_read(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [PROTO_GATE|] `		rsp_oplevel = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00333 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	case OPLOCK_WRITE_TO_NONE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		ret = opinfo_write_to_none(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [PROTO_GATE|] `		rsp_oplevel = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00337 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `	case OPLOCK_READ_TO_NONE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		ret = opinfo_read_to_none(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [PROTO_GATE|] `		rsp_oplevel = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00341 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [ERROR_PATH|] `		pr_err_ratelimited("unknown oplock change 0x%x -> 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00344 [NONE] `				   opinfo->level, rsp_oplevel);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		rsp->hdr.Status = err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00351 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	rsp->StructureSize = cpu_to_le16(24);`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	rsp->OplockLevel = rsp_oplevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	rsp->VolatileFid = cpu_to_le64(volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	rsp->PersistentFid = cpu_to_le64(persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_oplock_break));`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	opinfo->op_state = OPLOCK_STATE_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	wake_up_interruptible_all(&opinfo->oplock_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `static int check_lease_state(struct lease *lease, __le32 req_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	if ((lease->new_state ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [PROTO_GATE|] `	     (SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE)) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00375 [PROTO_GATE|] `	    !(req_state & SMB2_LEASE_WRITE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [NONE] `		lease->new_state = req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	 * When breaking RWH -> RW, the client may ack with RW or`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	 * any subset (R or NONE).  Accept if the ack does not`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	 * exceed the offered new_state.`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	if ((lease->new_state ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [PROTO_GATE|] `	     (SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_WRITE_CACHING_LE)) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00387 [PROTO_GATE|] `	    !(req_state & SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00388 [NONE] `		lease->new_state = req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	if (lease->new_state == req_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ` * smb21_lease_break_ack() - handler for smb2.1 lease break command`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` * @work:	smb work containing lease break command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ` * Return:	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `static void smb21_lease_break_ack(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	struct smb2_lease_ack *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	struct smb2_lease_ack *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	__le32 err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	unsigned int lease_change_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	__le32 lease_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	struct lease *lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	ksmbd_debug(OPLOCK, "smb21 lease break, lease state(0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `		    le32_to_cpu(req->LeaseState));`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	opinfo = lookup_lease_in_table(conn, req->LeaseKey);`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	if (!opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `		ksmbd_debug(OPLOCK, "file not opened\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNSUCCESSFUL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	lease = opinfo->o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	if (opinfo->op_state == OPLOCK_STATE_NONE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [ERROR_PATH|] `		pr_err_ratelimited("unexpected lease break state 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00431 [NONE] `				   opinfo->op_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNSUCCESSFUL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00433 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00434 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	if (check_lease_state(lease, req->LeaseState)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_REQUEST_NOT_ACCEPTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00438 [NONE] `		ksmbd_debug(OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `			    "req lease state: 0x%x, expected state: 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `			    req->LeaseState, lease->new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00442 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [LIFETIME|] `	if (!atomic_read(&opinfo->breaking_cnt)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00445 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNSUCCESSFUL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00446 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00447 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	 * Check for bad lease state.  A valid ack must not introduce`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	 * caching types that were not in the new_state offered by the`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	 * break notification.  The special case is RWH -> RW where`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	 * the ack legitimately contains Write caching.`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [PROTO_GATE|] `	if ((lease->state & SMB2_LEASE_WRITE_CACHING_LE) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00456 [PROTO_GATE|] `	    (lease->state & SMB2_LEASE_HANDLE_CACHING_LE) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00457 [PROTO_GATE|] `	    (req->LeaseState & SMB2_LEASE_WRITE_CACHING_LE) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00458 [PROTO_GATE|] `	    !(req->LeaseState & SMB2_LEASE_HANDLE_CACHING_LE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00459 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		 * Valid RWH -> RW transition: client acks with Write`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `		 * caching retained, Handle caching dropped.`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [PROTO_GATE|] `		err = STATUS_INVALID_DEVICE_STATE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00464 [PROTO_GATE|] `		if (req->LeaseState & SMB2_LEASE_READ_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00465 [NONE] `			lease_change_type = OPLOCK_WRITE_HANDLE_TO_WRITE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `			lease_change_type = OPLOCK_WRITE_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	} else if (req->LeaseState &`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [PROTO_GATE|] `	    (~(SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE))) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00470 [PROTO_GATE|] `		err = STATUS_INVALID_OPLOCK_PROTOCOL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00471 [PROTO_GATE|] `		if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00472 [NONE] `			lease_change_type = OPLOCK_WRITE_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `			lease_change_type = OPLOCK_READ_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `		ksmbd_debug(OPLOCK, "handle bad lease state 0x%x -> 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `			    le32_to_cpu(lease->state),`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `			    le32_to_cpu(req->LeaseState));`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [PROTO_GATE|] `	} else if (lease->state == SMB2_LEASE_READ_CACHING_LE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00479 [PROTO_GATE|] `		   req->LeaseState != SMB2_LEASE_NONE_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00480 [PROTO_GATE|] `		err = STATUS_INVALID_OPLOCK_PROTOCOL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00481 [NONE] `		lease_change_type = OPLOCK_READ_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `		ksmbd_debug(OPLOCK, "handle bad lease state 0x%x -> 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `			    le32_to_cpu(lease->state),`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `			    le32_to_cpu(req->LeaseState));`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `		/* valid lease state changes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [PROTO_GATE|] `		err = STATUS_INVALID_DEVICE_STATE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00488 [PROTO_GATE|] `		if (req->LeaseState == SMB2_LEASE_NONE_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [PROTO_GATE|] `			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00490 [NONE] `				lease_change_type = OPLOCK_WRITE_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `				lease_change_type = OPLOCK_READ_TO_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [PROTO_GATE|] `		} else if (req->LeaseState & SMB2_LEASE_READ_CACHING_LE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00494 [PROTO_GATE|] `			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00495 [NONE] `				lease_change_type = OPLOCK_WRITE_TO_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `				lease_change_type = OPLOCK_READ_HANDLE_TO_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `			lease_change_type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	switch (lease_change_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	case OPLOCK_WRITE_HANDLE_TO_WRITE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `		ret = opinfo_write_handle_to_write(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	case OPLOCK_WRITE_TO_READ:`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		ret = opinfo_write_to_read(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	case OPLOCK_READ_HANDLE_TO_READ:`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `		ret = opinfo_read_handle_to_read(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	case OPLOCK_WRITE_TO_NONE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `		ret = opinfo_write_to_none(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	case OPLOCK_READ_TO_NONE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `		ret = opinfo_read_to_none(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `		ksmbd_debug(OPLOCK, "unknown lease change 0x%x -> 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `			    le32_to_cpu(lease->state),`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `			    le32_to_cpu(req->LeaseState));`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		rsp->hdr.Status = err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00529 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	lease_state = lease->state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	rsp->StructureSize = cpu_to_le16(36);`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	rsp->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [MEM_BOUNDS|] `	memcpy(rsp->LeaseKey, req->LeaseKey, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00537 [NONE] `	rsp->LeaseState = lease_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	rsp->LeaseDuration = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_lease_ack));`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	opinfo->op_state = OPLOCK_STATE_NONE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	wake_up_interruptible_all(&opinfo->oplock_q);`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [LIFETIME|] `	atomic_dec(&opinfo->breaking_cnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00548 [NONE] `	wake_up_interruptible_all(&opinfo->oplock_brk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ` * smb2_oplock_break() - dispatcher for smb2.0 and 2.1 oplock/lease break`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ` * @work:	smb work containing oplock/lease break command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `int smb2_oplock_break(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	struct smb2_oplock_break *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	struct smb2_oplock_break *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	ksmbd_debug(SMB, "Received smb2 oplock break acknowledgment request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	switch (le16_to_cpu(req->StructureSize)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	case OP_BREAK_STRUCT_SIZE_20:`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		smb20_oplock_break_ack(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	case OP_BREAK_STRUCT_SIZE_21:`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `		smb21_lease_break_ack(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		ksmbd_debug(OPLOCK, "invalid break cmd %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `			    le16_to_cpu(req->StructureSize));`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00578 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00580 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] ` * smb2_notify_cancel() - cancel callback for async notify`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ` * @argv: cancel arguments (argv[0] = ksmbd_notify_watch *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [PROTO_GATE|] ` * smb2_send_session_closed_notification() - send SMB2_SERVER_TO_CLIENT_NOTIFICATION`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00592 [PROTO_GATE|] ` *   of type SMB2_NOTIFY_SESSION_CLOSED to all channels of the session except`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00593 [NONE] ` *   the channel on which the logoff was received.`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ` * @work: current smb work (identifies current connection and session)`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] ` * MS-SMB2 §3.3.4.1.8 / §3.3.5.6: if the connection is multi-channel capable`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] ` * and other channels exist for this session, send each an unsolicited`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] ` * SMB2 SERVER_TO_CLIENT_NOTIFICATION (command 0x0013) so they can clean up.`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `void smb2_send_session_closed_notification(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	struct ksmbd_conn  *curr_conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	struct channel     *chann;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	unsigned long       chann_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	if (!sess || curr_conn->dialect < SMB311_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	xa_for_each(&sess->ksmbd_chann_list, chann_id, chann) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		struct ksmbd_conn *ch_conn = chann->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		struct ksmbd_work *noti_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		struct smb2_server_to_client_notification *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `		/* Skip the connection that issued the logoff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		if (ch_conn == curr_conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		/* Only send to 3.1.1+ connections (notification capability) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `		if (ch_conn->dialect < SMB311_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		noti_work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		if (!noti_work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [ERROR_PATH|] `			pr_warn_ratelimited("failed to allocate work for session-closed notification\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00627 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		if (allocate_interim_rsp_buf(noti_work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `			ksmbd_free_work_struct(noti_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		noti_work->conn = ch_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		noti_work->sess = sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		hdr = smb2_get_msg(noti_work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `		memset(hdr, 0, sizeof(struct smb2_hdr) + 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [PROTO_GATE|] `		hdr->ProtocolId     = SMB2_PROTO_NUMBER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00641 [PROTO_GATE|] `		hdr->StructureSize  = SMB2_HEADER_STRUCTURE_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00642 [PROTO_GATE|] `		hdr->Command        = SMB2_SERVER_TO_CLIENT_NOTIFICATION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00643 [PROTO_GATE|] `		hdr->Flags          = SMB2_FLAGS_SERVER_TO_REDIR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00644 [NONE] `		hdr->MessageId      = cpu_to_le64(-1);  /* unsolicited */`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `		hdr->SessionId      = cpu_to_le64(sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `		rsp = smb2_get_msg(noti_work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `		rsp->StructureSize    = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `		rsp->Reserved         = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [PROTO_GATE|] `		rsp->NotificationType = SMB2_NOTIFY_SESSION_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		ksmbd_conn_r_count_inc(ch_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		if (ksmbd_iov_pin_rsp(noti_work, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `				      sizeof(struct smb2_server_to_client_notification))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `			ksmbd_conn_r_count_dec(ch_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `			ksmbd_free_work_struct(noti_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `			    "sending NOTIFY_SESSION_CLOSED to chann conn %p for sess %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `			    ch_conn, sess->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `		ksmbd_conn_write(noti_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		ksmbd_conn_r_count_dec(ch_conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `		ksmbd_free_work_struct(noti_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
