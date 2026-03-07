# Line-by-line Review: src/protocol/smb2/smb2_ioctl.c

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
- L00006 [PROTO_GATE|] ` *   smb2_ioctl.c - SMB2_IOCTL handler`
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
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * smb2_ioctl() - handler for smb2 ioctl command`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * @work:	smb work containing ioctl command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `int smb2_ioctl(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	struct smb2_ioctl_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	struct smb2_ioctl_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	unsigned int cnt_code, nbytes = 0, out_buf_len, in_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	u64 id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	char *buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	ksmbd_debug(SMB, "Received smb2 ioctl request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `		req = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `			ksmbd_debug(SMB, "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `				    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `			id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `		rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	if (!has_file_id(id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `		id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [PROTO_GATE|] `	 * MS-SMB2 §2.2.31: Flags MUST be SMB2_0_IOCTL_IS_FSCTL (0x00000001).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00097 [NONE] `	 * No other value is defined; reject anything else.`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [PROTO_GATE|] `	if (req->Flags != cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00100 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00101 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00103 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence when a file handle is given */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	if (has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		struct ksmbd_file *fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `		if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `			ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00112 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		ret = smb2_check_channel_sequence(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00117 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00118 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	cnt_code = le32_to_cpu(req->CntCode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	ret = smb2_calc_max_out_buf_len(work, 48,`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `					le32_to_cpu(req->MaxOutputResponse));`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00126 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00127 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	out_buf_len = (unsigned int)ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	in_buf_len = le32_to_cpu(req->InputCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	/* Validate InputOffset before using it as pointer arithmetic */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	if (in_buf_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		unsigned int input_off = le32_to_cpu(req->InputOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `		if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `			req_len -= work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		if (input_off < sizeof(struct smb2_ioctl_req) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		    input_off > req_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		    in_buf_len > req_len - input_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [ERROR_PATH|] `			pr_err_ratelimited("Invalid IOCTL InputOffset %u or InputCount %u (req_len=%u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00143 [NONE] `					   input_off, in_buf_len, req_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00146 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00147 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	buffer = (char *)req + le32_to_cpu(req->InputOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	/* Try registered FSCTL handlers first */`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	ret = ksmbd_dispatch_fsctl(work, cnt_code, id, buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `				   in_buf_len, out_buf_len, rsp, &nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	if (ret == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [ERROR_PATH|] `		goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00157 [NONE] `	if (ret != -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		 * MS-FSCC §2.3: some FSCTL handlers (e.g. SRV_COPYCHUNK)`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		 * populate the response body even when returning an error`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		 * (to convey server limits).  If the handler set nbytes > 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		 * go through the normal done path so the body is included.`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		if (nbytes > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [ERROR_PATH|] `			goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00166 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00167 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	/* No handler found for this FSCTL code */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	ksmbd_debug(SMB, "unknown ioctl command 0x%x\n", cnt_code);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	ret = -EOPNOTSUPP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [ERROR_PATH|] `	goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `done:`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	rsp->CntCode = cpu_to_le32(cnt_code);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	rsp->InputCount = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	rsp->InputOffset = cpu_to_le32(112);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	rsp->OutputOffset = cpu_to_le32(112);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	rsp->OutputCount = cpu_to_le32(nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	rsp->StructureSize = cpu_to_le16(49);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	rsp->Reserved = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	rsp->Flags = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	rsp->Reserved2 = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_ioctl_rsp) + nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	if (!ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	/* If the handler or pre-check already set a specific status, keep it */`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	if (rsp->hdr.Status == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		if (ret == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00193 [NONE] `		else if (ret == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00195 [NONE] `		else if (ret == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00197 [NONE] `		else if (ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00199 [NONE] `		else if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00201 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * smb20_oplock_break_ack() - handler for smb2.0 oplock break command`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` * @work:	smb work containing oplock break command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ` * Return:	0`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
