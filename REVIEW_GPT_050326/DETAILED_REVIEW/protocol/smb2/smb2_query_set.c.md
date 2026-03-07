# Line-by-line Review: src/protocol/smb2/smb2_query_set.c

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
- L00016 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include "xattr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `int buffer_check_err(int reqOutputBufferLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `			    struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `			    void *rsp_org,`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `			    int min_output_length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	if (reqOutputBufferLength < min_output_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INFO_LENGTH_MISMATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [NONE] `		*(__be32 *)rsp_org = cpu_to_be32(sizeof(struct smb2_hdr));`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00077 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	if (reqOutputBufferLength < le32_to_cpu(rsp->OutputBufferLength)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00081 [NONE] `		*(__be32 *)rsp_org = cpu_to_be32(sizeof(struct smb2_hdr));`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00083 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `EXPORT_SYMBOL_IF_KUNIT(buffer_check_err);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `void get_standard_info_pipe(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `				   void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	struct smb2_file_standard_info *sinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	sinfo->AllocationSize = cpu_to_le64(4096);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	sinfo->EndOfFile = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	sinfo->NumberOfLinks = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	sinfo->DeletePending = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	sinfo->Directory = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_standard_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_standard_info_pipe);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `void get_internal_info_pipe(struct smb2_query_info_rsp *rsp, u64 num,`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `				   void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	struct smb2_file_internal_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	file_info = (struct smb2_file_internal_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	/* any unique number */`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	file_info->IndexNumber = cpu_to_le64(num | (1ULL << 63));`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_internal_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_internal_info_pipe);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `static int smb2_get_info_file_pipe(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `				   struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `				   struct smb2_query_info_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				   struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `				   void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	u64 id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	unsigned int qout_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	 * Windows can sometime send query file info request on`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	 * pipe without opening it, checking error condition here`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	lockdep_assert_not_held(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [LOCK|] `	down_read(&sess->rpc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00140 [NONE] `	if (!ksmbd_session_rpc_method(sess, id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		up_read(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00143 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	up_read(&sess->rpc_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	ksmbd_debug(SMB, "FileInfoClass %u, FileId 0x%llx\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `		    req->FileInfoClass, req->VolatileFileId);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	switch (req->FileInfoClass) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	case FILE_STANDARD_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		get_standard_info_pipe(rsp, rsp_org);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `				      rsp, rsp_org, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	case FILE_INTERNAL_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		get_internal_info_pipe(rsp, id, rsp_org);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `				      rsp, rsp_org, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		rc = ksmbd_dispatch_info(work, NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [PROTO_GATE|] `					 SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00163 [NONE] `					 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `					 KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `					 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `					 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `					 &qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `		if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			rsp->OutputBufferLength = cpu_to_le32(qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `					      rsp, rsp_org, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `			ksmbd_debug(SMB, "smb2_info_file_pipe for %u not supported\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `				    req->FileInfoClass);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` * smb2_get_ea() - handler for smb2 get extended attribute command`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ` * @work:	smb work containing query info command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` * @fp:		ksmbd_file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` * @req:	get extended attribute request`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ` * @rsp:	response buffer pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ` * @rsp_org:	base response buffer pointer in case of chained response`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `static int smb2_get_ea(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		       struct smb2_query_info_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		       struct smb2_query_info_rsp *rsp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	struct smb2_ea_info *eainfo, *prev_eainfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	char *name, *ptr, *xattr_list = NULL, *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	int rc, name_len, value_len, xattr_list_len, idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	ssize_t buf_free_len, alignment_bytes, next_offset, rsp_data_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	struct smb2_ea_info_req *ea_req = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	const struct path *path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	if (!(fp->daccess & FILE_READ_EA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [ERROR_PATH|] `		pr_err("Not permitted to read ext attr : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00208 [NONE] `		       fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00210 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	path = &fp->filp->f_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	/* single EA entry is requested with given user.* name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	if (req->InputBufferLength) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		if (le32_to_cpu(req->InputBufferLength) <=`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		    sizeof(struct smb2_ea_info_req))`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		if ((u64)le16_to_cpu(req->InputBufferOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		    le32_to_cpu(req->InputBufferLength) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		    get_rfc1002_len(work->request_buf) + 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		ea_req = (struct smb2_ea_info_req *)((char *)req +`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `						     le16_to_cpu(req->InputBufferOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		/* need to send all EAs, if no specific EA is requested*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		if (le32_to_cpu(req->Flags) & SL_RETURN_SINGLE_ENTRY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `				    "All EAs are requested but need to send single EA entry in rsp flags 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `				    le32_to_cpu(req->Flags));`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	buf_free_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		smb2_calc_max_out_buf_len(work, 8,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `					  le32_to_cpu(req->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	if (buf_free_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	rc = ksmbd_vfs_listxattr(path->dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00243 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00244 [NONE] `	} else if (!rc) { /* there is no EA in the file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		ksmbd_debug(SMB, "no ea data in the file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [ERROR_PATH|] `		goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00247 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	xattr_list_len = rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	ptr = (char *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	eainfo = (struct smb2_ea_info *)ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	prev_eainfo = eainfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	while (idx < xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `		name = xattr_list + idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		name_len = strlen(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		ksmbd_debug(SMB, "%s, len %d\n", name, name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		idx += name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `		 * CIFS does not support EA other than user.* namespace,`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `		 * still keep the framework generic, to list other attrs`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		 * in future.`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `			     STREAM_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		if (req->InputBufferLength && ea_req &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		    strncmp(&name[XATTR_USER_PREFIX_LEN], ea_req->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `			    ea_req->EaNameLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		if (!strncmp(&name[XATTR_USER_PREFIX_LEN],`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `			     DOS_ATTRIBUTE_PREFIX, DOS_ATTRIBUTE_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `			name_len -= XATTR_USER_PREFIX_LEN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		buf_free_len -= (offsetof(struct smb2_ea_info, name) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `				name_len + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		/* bailout if xattr can't fit in buf_free_len */`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `		if (buf_free_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `		ptr = eainfo->name + name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		value_len = ksmbd_vfs_getxattr(idmap, path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		value_len = ksmbd_vfs_getxattr(user_ns, path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `					       name, &buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `		if (value_len <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00302 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00303 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `		buf_free_len -= value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `		if (buf_free_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `			kfree(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [MEM_BOUNDS|] `		memcpy(ptr, buf, value_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00312 [NONE] `		kfree(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		ptr += value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		eainfo->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `		eainfo->EaNameLength = name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [MEM_BOUNDS|] `			memcpy(eainfo->name, &name[XATTR_USER_PREFIX_LEN],`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00320 [NONE] `			       name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [MEM_BOUNDS|] `			memcpy(eainfo->name, name, name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `		eainfo->name[name_len] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `		eainfo->EaValueLength = cpu_to_le16(value_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		next_offset = offsetof(struct smb2_ea_info, name) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `			name_len + 1 + value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		/* align next xattr entry at 4 byte boundary */`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		alignment_bytes = ((next_offset + 3) & ~3) - next_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		if (alignment_bytes) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `			if (buf_free_len < alignment_bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `			memset(ptr, '\0', alignment_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `			ptr += alignment_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			next_offset += alignment_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			buf_free_len -= alignment_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		eainfo->NextEntryOffset = cpu_to_le32(next_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `		prev_eainfo = eainfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		eainfo = (struct smb2_ea_info *)ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		rsp_data_cnt += next_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		if (req->InputBufferLength) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `			ksmbd_debug(SMB, "single entry requested\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	/* no more ea entries */`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	prev_eainfo->NextEntryOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `done:`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	if (rsp_data_cnt == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_EAS_ON_FILE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00356 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(rsp_data_cnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `void get_file_access_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `				 struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	struct smb2_file_access_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	file_info = (struct smb2_file_access_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	file_info->AccessFlags = fp->daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_access_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_access_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `int get_file_basic_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `			       struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	struct smb2_file_basic_info *basic_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [ERROR_PATH|] `		pr_err("no right to read the attributes : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00386 [NONE] `		       fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00388 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	basic_info = (struct smb2_file_basic_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	basic_info->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	basic_info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	basic_info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	basic_info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	basic_info->Attributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	basic_info->Pad1 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_basic_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_basic_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `int get_file_standard_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `				  struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	struct smb2_file_standard_info *sinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	unsigned int delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	sinfo = (struct smb2_file_standard_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	delete_pending = ksmbd_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	if (ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		sinfo->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		sinfo->EndOfFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		sinfo->AllocationSize = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `		sinfo->EndOfFile = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	sinfo->NumberOfLinks = cpu_to_le32(get_nlink(&stat) - delete_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	sinfo->DeletePending = delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	sinfo->Directory = S_ISDIR(stat.mode) ? 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_standard_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_standard_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `void get_file_alignment_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `				    void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	struct smb2_file_alignment_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	file_info = (struct smb2_file_alignment_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	file_info->AlignmentRequirement = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_alignment_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_alignment_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `static int get_file_all_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `			     struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `			     struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `			     void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	struct smb2_file_all_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	unsigned int delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	char *filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `		ksmbd_debug(SMB, "no right to read the attributes : 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `			    fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00476 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	filename = convert_to_nt_pathname(work->tcon->share_conf, &fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `		return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	ksmbd_debug(SMB, "filename = %s\n", filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	delete_pending = ksmbd_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	file_info = (struct smb2_file_all_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	file_info->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	file_info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	file_info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	file_info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	file_info->Attributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	file_info->Pad1 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	if (ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `		file_info->AllocationSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `			cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		file_info->AllocationSize = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `		file_info->EndOfFile = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	file_info->NumberOfLinks =`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `			cpu_to_le32(get_nlink(&stat) - delete_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	file_info->DeletePending = delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	file_info->Directory = S_ISDIR(stat.mode) ? 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	file_info->Pad2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	file_info->IndexNumber = cpu_to_le64(stat.ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	file_info->EASize = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	file_info->AccessFlags = fp->daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	if (ksmbd_stream_fd(fp) == false)`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `		file_info->CurrentByteOffset = cpu_to_le64(fp->filp->f_pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `		file_info->CurrentByteOffset = cpu_to_le64(fp->stream.pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	file_info->Mode = fp->coption;`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	file_info->AlignmentRequirement = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	conv_len = smbConvertToUTF16((__le16 *)file_info->FileName, filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `				     PATH_MAX, conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	conv_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	/* Clamp to PATH_MAX bytes to prevent response buffer overflow */`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	if (conv_len > PATH_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		conv_len = PATH_MAX;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	file_info->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_all_info) + conv_len - 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `static void get_file_alternate_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `				    struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `				    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `				    void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	struct smb2_file_alt_name_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	struct dentry *dentry = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [LOCK|] `	spin_lock(&dentry->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00548 [NONE] `	file_info = (struct smb2_file_alt_name_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	conv_len = ksmbd_extract_shortname(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `					   dentry->d_name.name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `					   file_info->FileName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [LOCK|] `	spin_unlock(&dentry->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00553 [NONE] `	file_info->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `		cpu_to_le32(struct_size(file_info, FileName, conv_len));`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `static int get_file_stream_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `				struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `				void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	struct smb2_file_stream_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	char *stream_name, *xattr_list = NULL, *stream_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	const struct path *path = &fp->filp->f_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	int nbytes = 0, streamlen, stream_name_len, next, idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	int buf_free_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	file_info = (struct smb2_file_stream_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	 * Use work buffer free space (not client's OutputBufferLength) so we`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	 * compute the full response size.  buffer_check_err() will compare`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	 * the full size against OutputBufferLength and return`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [PROTO_GATE|] `	 * STATUS_BUFFER_OVERFLOW when the client's buffer is too small.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00585 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	buf_free_len = smb2_resp_buf_len(work, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `	if (buf_free_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	/* Zero the response buffer to prevent leaking stale heap data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	memset(rsp->Buffer, 0, buf_free_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	if (xattr_list_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00596 [NONE] `	} else if (!xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		ksmbd_debug(SMB, "empty xattr in the file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00599 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	while (idx < xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		stream_name = xattr_list + idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		streamlen = strlen(stream_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		idx += streamlen + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		ksmbd_debug(SMB, "%s, len %d\n", stream_name, streamlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		if (strncmp(&stream_name[XATTR_USER_PREFIX_LEN],`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `			    STREAM_PREFIX, STREAM_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		stream_name_len = streamlen - (XATTR_USER_PREFIX_LEN +`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `				STREAM_PREFIX_LEN);`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		streamlen = stream_name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `		/* plus : size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		streamlen += 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [MEM_BOUNDS|] `		stream_buf = kmalloc(streamlen + 1, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00619 [NONE] `		if (!stream_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [MEM_BOUNDS|] `		streamlen = snprintf(stream_buf, streamlen + 1,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00623 [NONE] `				     ":%s", &stream_name[XATTR_NAME_STREAM_LEN]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		next = sizeof(struct smb2_file_stream_info) + streamlen * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		if (next > buf_free_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `			kfree(stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		file_info = (struct smb2_file_stream_info *)&rsp->Buffer[nbytes];`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `		streamlen  = smbConvertToUTF16((__le16 *)file_info->StreamName,`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `					       stream_buf, streamlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `					       conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		streamlen *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		kfree(stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		file_info->StreamNameLength = cpu_to_le32(streamlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `		 * G.2: StreamSize must be the actual xattr data size, not the`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `		 * length of the stream name string. Retrieve via getxattr().`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `			char *xattr_val = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `			ssize_t xattr_data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `			u64 stream_data_size, stream_alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `			xattr_data_len = ksmbd_vfs_getxattr(`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `				file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `			xattr_data_len = ksmbd_vfs_getxattr(`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `				file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `				path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `				stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `				&xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `			kfree(xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `			if (xattr_data_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `				xattr_data_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `			stream_data_size = (u64)xattr_data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `			/* Allocation size: round up to 4K */`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `			stream_alloc_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `				(stream_data_size + 4095) & ~(u64)4095;`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `			if (!stream_alloc_size && stream_data_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `				stream_alloc_size = 4096;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `			file_info->StreamSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `				cpu_to_le64(stream_data_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `			file_info->StreamAllocationSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `				cpu_to_le64(stream_alloc_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `		nbytes += next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		buf_free_len -= next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		file_info->NextEntryOffset = cpu_to_le32(next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	 * Time Machine: inject virtual streams on the share root`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	 * when FRUIT_TIME_MACHINE is configured. macOS checks for`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	 * these streams to determine if a volume supports Time Machine.`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	if (conn->is_fruit && S_ISDIR(stat.mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `	    work->tcon && work->tcon->share_conf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `	    test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `				   KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	    path->dentry == work->tcon->share_conf->vfs_path.dentry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `		const char *tm_supported =`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `			":com.apple.timemachine.supported:$DATA";`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `		int tm_len = strlen(tm_supported);`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `		next = sizeof(struct smb2_file_stream_info) + tm_len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `		if (buf_free_len >= next) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `			file_info = (struct smb2_file_stream_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `				&rsp->Buffer[nbytes];`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `			streamlen = smbConvertToUTF16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `				(__le16 *)file_info->StreamName,`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `				tm_supported, tm_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `				conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `			streamlen *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `			file_info->StreamNameLength = cpu_to_le32(streamlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `			/* Stream value is "1" (supported) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `			file_info->StreamSize = cpu_to_le64(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `			file_info->StreamAllocationSize = cpu_to_le64(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `			file_info->NextEntryOffset = cpu_to_le32(next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `			nbytes += next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `			buf_free_len -= next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `		/* Inject MaxSize if configured */`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		if (work->tcon->share_conf->time_machine_max_size > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `			const char *tm_maxsize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `				":com.apple.timemachine.MaxSize:$DATA";`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `			int ms_len = strlen(tm_maxsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `			next = sizeof(struct smb2_file_stream_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `			       ms_len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `			if (buf_free_len >= next) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `				file_info = (struct smb2_file_stream_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `					&rsp->Buffer[nbytes];`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `				streamlen = smbConvertToUTF16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `					(__le16 *)file_info->StreamName,`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `					tm_maxsize, ms_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `					conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `				streamlen *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `				file_info->StreamNameLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `					cpu_to_le32(streamlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `				file_info->StreamSize = cpu_to_le64(8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `				file_info->StreamAllocationSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `					cpu_to_le64(8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `				file_info->NextEntryOffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `					cpu_to_le32(next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `				nbytes += next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `				buf_free_len -= next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	if (!S_ISDIR(stat.mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	    buf_free_len >= sizeof(struct smb2_file_stream_info) + 7 * 2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `		file_info = (struct smb2_file_stream_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `			&rsp->Buffer[nbytes];`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		streamlen = smbConvertToUTF16((__le16 *)file_info->StreamName,`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `					      "::$DATA", 7, conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `		streamlen *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `		file_info->StreamNameLength = cpu_to_le32(streamlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `		file_info->StreamSize = cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `		file_info->StreamAllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `		nbytes += sizeof(struct smb2_file_stream_info) + streamlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	/* last entry offset should be 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	file_info->NextEntryOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `int get_file_internal_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `				  struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	struct smb2_file_internal_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `			AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	file_info = (struct smb2_file_internal_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	file_info->IndexNumber = cpu_to_le64(stat.ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_internal_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_internal_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `static int get_file_network_open_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `				      struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	struct smb2_file_ntwrk_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [ERROR_PATH|] `		pr_err("no right to read the attributes : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00795 [NONE] `		       fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00797 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	file_info = (struct smb2_file_ntwrk_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	file_info->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	file_info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	file_info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	file_info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	file_info->Attributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	if (ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `		file_info->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `		file_info->EndOfFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `		file_info->AllocationSize = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		file_info->EndOfFile = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	file_info->Reserved = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_ntwrk_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] ` * G.5: Compute actual EA size by iterating user.* xattrs (excluding`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ` * stream and DOS-attribute xattrs).  Per MS-FSCC §2.4.13, EaSize is the`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ` * sum of all EA entries encoded as FILE_FULL_EA_INFORMATION records.`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] ` * Each record contributes:`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] ` *   sizeof(FILE_FULL_EA_INFORMATION) + EaNameLength + 1 + EaValueLength`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] ` * aligned to 4 bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `void get_file_ea_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `			     struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	struct smb2_file_ea_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	u32 ea_size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	char *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `	int idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	file_info = (struct smb2_file_ea_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00854 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `					     &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `	if (xattr_list_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	while (idx < xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `		char *name = xattr_list + idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `		int name_len = strlen(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `		char *xattr_val = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `		ssize_t value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `		u32 entry_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `		idx += name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		/* Only user.* namespace, but not streams or DOS attrs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `			     STREAM_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `		if (!strncmp(&name[XATTR_USER_PREFIX_LEN],`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `			     DOS_ATTRIBUTE_PREFIX, DOS_ATTRIBUTE_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `		/* EA name length = name without "user." prefix */`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `		name_len -= XATTR_USER_PREFIX_LEN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `		if (name_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		value_len = ksmbd_vfs_getxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		value_len = ksmbd_vfs_getxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `					       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `					       name, &xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		kfree(xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		if (value_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `			value_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `		 * Each EA entry in FILE_FULL_EA_INFORMATION format:`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `		 *   NextEntryOffset(4) + Flags(1) + EaNameLength(1) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `		 *   EaValueLength(2) + EaName[EaNameLength+1] + EaValue`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		 * = offsetof(smb2_ea_info, name) + name_len + 1 + value_len`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		 * aligned up to 4 bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `		entry_size = offsetof(struct smb2_ea_info, name) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `			     name_len + 1 + (u32)value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `		entry_size = (entry_size + 3) & ~3U;`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		ea_size += entry_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	file_info->EASize = cpu_to_le32(ea_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_ea_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_ea_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `void get_file_position_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `				   struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `	struct smb2_file_pos_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `	file_info = (struct smb2_file_pos_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	if (ksmbd_stream_fd(fp) == false)`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		file_info->CurrentByteOffset = cpu_to_le64(fp->filp->f_pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `		file_info->CurrentByteOffset = cpu_to_le64(fp->stream.pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_pos_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_position_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `void get_file_mode_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `			       struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	struct smb2_file_mode_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	file_info = (struct smb2_file_mode_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	file_info->Mode = fp->coption & FILE_MODE_INFO_MASK;`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_mode_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_mode_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `int get_file_compression_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `				     struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `	struct smb2_file_comp_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	file_info = (struct smb2_file_comp_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	file_info->CompressedFileSize = cpu_to_le64(stat.blocks << 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	if (fp->f_ci->m_fattr & ATTR_COMPRESSED_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `		file_info->CompressionFormat =`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `			cpu_to_le16(COMPRESSION_FORMAT_LZNT1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `		file_info->CompressionFormat =`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `			cpu_to_le16(COMPRESSION_FORMAT_NONE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	file_info->CompressionUnitShift = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `	file_info->ChunkShift = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `	file_info->ClusterShift = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	memset(&file_info->Reserved[0], 0, 3);`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_comp_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_compression_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `int get_file_attribute_tag_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `				       struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `	struct smb2_file_attr_tag_info *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `	char *reparse_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `	__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `	ssize_t reparse_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [ERROR_PATH|] `		pr_err("no right to read the attributes : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00996 [NONE] `		       fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00998 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `	file_info = (struct smb2_file_attr_tag_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	file_info->FileAttributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	file_info->ReparseTag =`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `		smb2_get_reparse_tag_special_file(file_inode(fp->filp)->i_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `	if (file_info->ReparseTag) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `		file_info->FileAttributes |= ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01007 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	reparse_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `	reparse_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `					 fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `					 XATTR_NAME_REPARSE_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `					 &reparse_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `	if (reparse_len >= (ssize_t)sizeof(reparse_tag) && reparse_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [MEM_BOUNDS|] `		memcpy(&reparse_tag, reparse_buf, sizeof(reparse_tag));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01019 [NONE] `		file_info->ReparseTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		file_info->FileAttributes |= ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `	kfree(reparse_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		cpu_to_le32(sizeof(struct smb2_file_attr_tag_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_attribute_tag_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `struct smb2_file_reparse_point_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `	__le64 FileReferenceNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	__le32 Tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `static int get_file_reparse_point_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `				       struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	struct smb2_file_reparse_point_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	char *reparse_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	ssize_t reparse_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `	info = (struct smb2_file_reparse_point_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `	info->FileReferenceNumber = cpu_to_le64(file_inode(fp->filp)->i_ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	info->Tag = smb2_get_reparse_tag_special_file(file_inode(fp->filp)->i_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	if (info->Tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `	reparse_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `	reparse_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `					 fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `					 XATTR_NAME_REPARSE_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `					 &reparse_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	if (reparse_len >= (ssize_t)sizeof(reparse_tag) && reparse_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [MEM_BOUNDS|] `		memcpy(&reparse_tag, reparse_buf, sizeof(reparse_tag));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01063 [NONE] `		info->Tag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `	kfree(reparse_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `struct smb2_file_standard_link_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `	__le32 NumberOfAccessibleLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	__le32 TotalNumberOfLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	__u8 DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	__u8 Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `static int get_file_standard_link_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `				       struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `	struct smb2_file_standard_link_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	unsigned int delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `	delete_pending = ksmbd_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `	info = (struct smb2_file_standard_link_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `	info->TotalNumberOfLinks = cpu_to_le32(get_nlink(&stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `	info->NumberOfAccessibleLinks =`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `		cpu_to_le32(get_nlink(&stat) - delete_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	info->DeletePending = delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	info->Directory = S_ISDIR(stat.mode) ? 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `	info->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] ` * MS-FSCC §2.4.20 FileIdInformation: 24 bytes total`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] ` *   VolumeSerialNumber: 8 bytes (ULONGLONG)`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] ` *   FileId:            16 bytes (128-bit persistent file ID, ULONGLONG[2])`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] ` * We use inode number in the low 64 bits of FileId and zero in the high`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] ` * 64 bits.  VolumeSerialNumber is taken from the superblock device ID.`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `struct smb2_file_id_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	__le64 VolumeSerialNumber; /* 8 bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	__u8   FileId[16];         /* 128-bit FileId */`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `} __packed; /* 24 bytes total */`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `int get_file_id_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `			    struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	struct smb2_file_id_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	struct kstatfs stfs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	__le64 ino_le;`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `	if (le32_to_cpu(rsp->OutputBufferLength) != 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	    le32_to_cpu(rsp->OutputBufferLength) < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	info = (struct smb2_file_id_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `	memset(info, 0, sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	 * G.1: VolumeSerialNumber from statfs.f_fsid per MS-FSCC §2.4.20.`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	 * f_fsid.val[0] is the low 32 bits, f_fsid.val[1] is the high 32 bits.`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	 * Fall back to the encoded device number if statfs fails.`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `	ret = vfs_statfs(&fp->filp->f_path, &stfs);`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `		info->VolumeSerialNumber = cpu_to_le64(`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `			(u64)(unsigned int)stfs.f_fsid.val[0] |`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `			((u64)(unsigned int)stfs.f_fsid.val[1] << 32));`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `		info->VolumeSerialNumber =`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `			cpu_to_le64((u64)new_encode_dev(inode->i_sb->s_dev));`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	/* FileId low 64 bits = inode number, high 64 bits = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	ino_le = cpu_to_le64(inode->i_ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [MEM_BOUNDS|] `	memcpy(&info->FileId[0], &ino_le, sizeof(ino_le));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01160 [NONE] `	/* FileId[8..15] remain zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `EXPORT_SYMBOL_IF_KUNIT(get_file_id_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `void fill_fallback_object_id(struct ksmbd_file *fp, u8 *object_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `	struct inode *inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `	__le64 ino = cpu_to_le64(inode->i_ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	__le32 gen = cpu_to_le32(inode->i_generation);`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	__le32 dev = cpu_to_le32((u32)new_encode_dev(inode->i_sb->s_dev));`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	memset(object_id, 0, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [MEM_BOUNDS|] `	memcpy(object_id, &ino, sizeof(ino));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01177 [MEM_BOUNDS|] `	memcpy(object_id + sizeof(ino), &gen, sizeof(gen));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01178 [MEM_BOUNDS|] `	memcpy(object_id + sizeof(ino) + sizeof(gen), &dev, sizeof(dev));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01179 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `EXPORT_SYMBOL_IF_KUNIT(fill_fallback_object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `static int get_file_object_id_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `				   struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	char *xattr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `	u8 object_id[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	u8 *out;`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	ssize_t xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	if (!(fp->daccess & FILE_READ_ATTRIBUTES_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `				       XATTR_NAME_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `				       &xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `	if (xattr_len == 16) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [MEM_BOUNDS|] `		memcpy(object_id, xattr_buf, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01204 [NONE] `		kfree(xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `		kfree(xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `		if (xattr_len < 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `		    xattr_len != -ENOENT &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `		    xattr_len != -ENODATA &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `		    xattr_len != -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `			return xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `		fill_fallback_object_id(fp, object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	out = (u8 *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `	for (i = 0; i < sizeof(struct file_object_buf_type1_ioctl_rsp); i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `		out[i] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	for (i = 0; i < 16; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `		out[i] = object_id[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `		out[32 + i] = object_id[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	rsp->OutputBufferLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `		cpu_to_le32(sizeof(struct file_object_buf_type1_ioctl_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `static int find_file_posix_info(struct smb2_query_info_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `				struct ksmbd_file *fp, void *rsp_org)`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	struct smb311_posix_qinfo *file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	struct inode *inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	vfsuid_t vfsuid = i_uid_into_vfsuid(user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	vfsgid_t vfsgid = i_gid_into_vfsgid(user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `	int out_buf_len = sizeof(struct smb311_posix_qinfo) + 32;`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	ret = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `			  AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	file_info = (struct smb311_posix_qinfo *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	file_info->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `	file_info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	file_info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `	file_info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	file_info->DosAttributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	file_info->Inode = cpu_to_le64(stat.ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	if (ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `		file_info->EndOfFile = cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `		file_info->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `		file_info->EndOfFile = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `		file_info->AllocationSize = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	file_info->HardLinks = cpu_to_le32(stat.nlink);`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	file_info->ReparseTag =`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `		smb2_get_reparse_tag_special_file(stat.mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	file_info->Mode = cpu_to_le32(stat.mode & 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `	switch (stat.mode & S_IFMT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `	case S_IFDIR:`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `		file_info->Mode |= cpu_to_le32(POSIX_TYPE_DIR << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	case S_IFLNK:`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `		file_info->Mode |= cpu_to_le32(POSIX_TYPE_SYMLINK << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	case S_IFCHR:`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `		file_info->Mode |= cpu_to_le32(POSIX_TYPE_CHARDEV << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	case S_IFBLK:`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `		file_info->Mode |= cpu_to_le32(POSIX_TYPE_BLKDEV << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	case S_IFIFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `		file_info->Mode |= cpu_to_le32(POSIX_TYPE_FIFO << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `	case S_IFSOCK:`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `		file_info->Mode |= cpu_to_le32(POSIX_TYPE_SOCKET << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `	file_info->DeviceId = cpu_to_le32(stat.rdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `	file_info->Zero = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	 * Sids(32) contain owner sid(16) + group sid(16).`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	 * Each UNIX SID(16) = revision(1) + sub_authority_count(1) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `	 *     authority(6) + sub_auth[0](4) + sub_auth[1](4).`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	 * (2 sub-authorities; the second is the UID/GID RID)`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	id_to_sid(from_kuid_munged(&init_user_ns, vfsuid_into_kuid(vfsuid)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `	id_to_sid(from_kuid_munged(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `				   i_uid_into_mnt(user_ns, inode)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `	id_to_sid(from_kuid_munged(&init_user_ns, inode->i_uid),`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `		  SIDUNIX_USER, (struct smb_sid *)&file_info->Sids[0]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	id_to_sid(from_kgid_munged(&init_user_ns, vfsgid_into_kgid(vfsgid)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	id_to_sid(from_kgid_munged(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `				   i_gid_into_mnt(user_ns, inode)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	id_to_sid(from_kgid_munged(&init_user_ns, inode->i_gid),`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `		  SIDUNIX_GROUP, (struct smb_sid *)&file_info->Sids[16]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(out_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `static int smb2_get_info_file(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `			      struct smb2_query_info_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `			      struct smb2_query_info_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `	int fileinfoclass = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `	int min_output_len = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `	unsigned int qout_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	unsigned int max_resp = smb2_calc_max_out_buf_len(work, 8,`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `					le32_to_cpu(req->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `	if (max_resp > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `		memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024));`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `				   KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `		/* smb2 info file called for pipe */`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `		return smb2_get_info_file_pipe(work, work->sess, req, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `					       work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `		if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `			ksmbd_debug(SMB, "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `				    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `			id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `			pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `	if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `		id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `		pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `	fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	fileinfoclass = req->FileInfoClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `	switch (fileinfoclass) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	case FILE_ACCESS_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `		get_file_access_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `		min_output_len = sizeof(struct smb2_file_access_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	case FILE_BASIC_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `		rc = get_file_basic_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `		min_output_len = sizeof(struct smb2_file_basic_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	case FILE_STANDARD_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `		rc = get_file_standard_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `		min_output_len = sizeof(struct smb2_file_standard_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	case FILE_ALIGNMENT_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `		get_file_alignment_info(rsp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `		min_output_len = sizeof(struct smb2_file_alignment_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `	case FILE_ALL_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `		rc = get_file_all_info(work, rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `		min_output_len = FILE_ALL_INFORMATION_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `	case FILE_ALTERNATE_NAME_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `		get_file_alternate_info(work, rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `		min_output_len = FILE_ALTERNATE_NAME_INFORMATION_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `	case FILE_STREAM_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `		rc = get_file_stream_info(work, rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `		min_output_len = FILE_STREAM_INFORMATION_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `	case FILE_INTERNAL_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `		rc = get_file_internal_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `		min_output_len = sizeof(struct smb2_file_internal_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	case FILE_NETWORK_OPEN_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `		rc = get_file_network_open_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `		min_output_len = sizeof(struct smb2_file_ntwrk_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `	case FILE_EA_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `		get_file_ea_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `		min_output_len = sizeof(struct smb2_file_ea_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `	case FILE_FULL_EA_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `		rc = smb2_get_ea(work, fp, req, rsp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `	case FILE_POSITION_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `		get_file_position_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `		min_output_len = sizeof(struct smb2_file_pos_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `	case FILE_MODE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `		get_file_mode_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `		min_output_len = sizeof(struct smb2_file_mode_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `	case FILE_COMPRESSION_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `		rc = get_file_compression_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `		min_output_len = sizeof(struct smb2_file_comp_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `	case FILE_OBJECT_ID_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `		rc = get_file_object_id_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `		min_output_len = sizeof(struct file_object_buf_type1_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `	case FILE_REPARSE_POINT_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `		rc = get_file_reparse_point_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `		min_output_len = sizeof(struct smb2_file_reparse_point_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `	case FILE_ATTRIBUTE_TAG_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `		rc = get_file_attribute_tag_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `		min_output_len = sizeof(struct smb2_file_attr_tag_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	case FILE_STANDARD_LINK_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `		rc = get_file_standard_link_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `		min_output_len = sizeof(struct smb2_file_standard_link_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `	case FILE_ID_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `		rc = get_file_id_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `		min_output_len = sizeof(struct smb2_file_id_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `	 * G.3: FileStatInformation (class 70, MS-FSCC §2.4.47)`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `	 *      Dispatched via the info handler table.`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `	 * G.4: FileStatLxInformation (class 71, MS-FSCC §2.4.48)`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `	 *      Called directly because FILE_CASE_SENSITIVE_INFORMATION is also`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `	 *      class 71 and occupies the dispatch slot for that key.`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `	case 70: /* FILE_STAT_INFORMATION */`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `		unsigned int stat_out = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `		rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [PROTO_GATE|] `					 SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01480 [NONE] `					 fileinfoclass,`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `					 KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `					 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `					 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `					 &stat_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `		if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `			rsp->OutputBufferLength = cpu_to_le32(stat_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `			min_output_len = stat_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `	case 71: /* FILE_STAT_LX_INFORMATION */`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `		unsigned int stat_lx_out = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `		rc = ksmbd_info_get_file_stat_lx(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `						 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `						 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `						 &stat_lx_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `		if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `			rsp->OutputBufferLength = cpu_to_le32(stat_lx_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `			min_output_len = stat_lx_out;`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `	case SMB_FIND_FILE_POSIX_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `		rc = find_file_posix_info(rsp, fp, work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `		min_output_len = sizeof(struct smb311_posix_qinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `		rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [PROTO_GATE|] `					 SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01512 [NONE] `					 fileinfoclass,`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `					 KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `					 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `					 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `					 &qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `			if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `				rsp->OutputBufferLength = cpu_to_le32(qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `				ksmbd_debug(SMB, "fileinfoclass %d unsupported\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `					    fileinfoclass);`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `		rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `				      rsp, work->response_buf, min_output_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `static int smb2_get_info_filesystem(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `				    struct smb2_query_info_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `				    struct smb2_query_info_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `	struct ksmbd_share_config *share = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `	int fsinfoclass = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `	struct kstatfs stfs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `	unsigned int qout_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	int rc = 0, len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `	unsigned int max_resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `	int min_output_len = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `	/* Pre-zero the response buffer to prevent kernel heap data leakage */`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	max_resp = smb2_calc_max_out_buf_len(work, 8,`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `				le32_to_cpu(req->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `	if (max_resp > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `		memset(rsp->Buffer, 0, min_t(unsigned int, max_resp, 1024));`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `	if (!share->path)`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] `	rc = kern_path(share->path, LOOKUP_NO_SYMLINKS, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [ERROR_PATH|] `		pr_err("cannot create vfs path\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01556 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01557 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	rc = vfs_statfs(&path, &stfs);`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [ERROR_PATH|] `		pr_err("cannot do stat of path %s\n", share->path);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01562 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [ERROR_PATH|] `		return -EIO;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01564 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `	fsinfoclass = req->FileInfoClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	switch (fsinfoclass) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] `	case FS_DEVICE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `		struct filesystem_device_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `		info = (struct filesystem_device_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `		info->DeviceType = cpu_to_le32(FILE_DEVICE_DISK);`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `		info->DeviceCharacteristics =`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `			cpu_to_le32(FILE_DEVICE_IS_MOUNTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `		if (!test_tree_conn_flag(work->tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `					 KSMBD_TREE_CONN_FLAG_WRITABLE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `			info->DeviceCharacteristics |=`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `				cpu_to_le32(FILE_READ_ONLY_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `		min_output_len = 8;`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `	case FS_ATTRIBUTE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `		struct filesystem_attribute_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `		size_t sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `		info = (struct filesystem_attribute_info *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `		info->Attributes = cpu_to_le32(FILE_SUPPORTS_OBJECT_IDS |`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] `					       FILE_PERSISTENT_ACLS |`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `					       FILE_UNICODE_ON_DISK |`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `					       FILE_CASE_PRESERVED_NAMES |`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `					       FILE_CASE_SENSITIVE_SEARCH |`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `					       FILE_SUPPORTS_BLOCK_REFCOUNTING);`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] `		info->Attributes |= cpu_to_le32(server_conf.share_fake_fscaps);`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `		if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `		    KSMBD_SHARE_FLAG_STREAMS))`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `			info->Attributes |= cpu_to_le32(FILE_NAMED_STREAMS);`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `		info->MaxPathNameComponentLength = cpu_to_le32(stfs.f_namelen);`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `		len = smbConvertToUTF16((__le16 *)info->FileSystemName,`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `					"NTFS", PATH_MAX, conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `		len = len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `		info->FileSystemNameLen = cpu_to_le32(len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `		sz = sizeof(struct filesystem_attribute_info) + len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `		min_output_len = 16;`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `	case FS_VOLUME_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `		struct filesystem_vol_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `		size_t sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `		unsigned int serial_crc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `		info = (struct filesystem_vol_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `		info->VolumeCreationTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `		serial_crc = crc32_le(serial_crc, share->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `				      strlen(share->name));`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `		serial_crc = crc32_le(serial_crc, share->path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `				      strlen(share->path));`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `		serial_crc = crc32_le(serial_crc, ksmbd_netbios_name(),`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `				      strlen(ksmbd_netbios_name()));`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `		/* Taking dummy value of serial number*/`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `		info->SerialNumber = cpu_to_le32(serial_crc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `		len = smbConvertToUTF16((__le16 *)info->VolumeLabel,`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `					share->name, PATH_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `					conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `		len = len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `		info->VolumeLabelSize = cpu_to_le32(len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `		info->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `		sz = sizeof(struct filesystem_vol_info) + len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `		min_output_len = 24;`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `	case FS_SIZE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `		struct filesystem_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `		 * G.6: Windows expects BytesPerSector=512 and`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `		 * SectorsPerAllocationUnit = f_bsize / 512 (cluster factor).`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `		 * This satisfies:`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `		 *   SectorsPerAllocationUnit * BytesPerSector == f_bsize`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `		 * and allows Windows Explorer to compute correct free space.`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `		unsigned long sectors_per_unit =`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `			max(1UL, (unsigned long)(stfs.f_bsize / 512));`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `		info = (struct filesystem_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `		info->TotalAllocationUnits = cpu_to_le64(stfs.f_blocks);`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `		info->FreeAllocationUnits = cpu_to_le64(stfs.f_bfree);`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `		info->SectorsPerAllocationUnit = cpu_to_le32(sectors_per_unit);`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `		info->BytesPerSector = cpu_to_le32(512);`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(24);`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `		min_output_len = 24;`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `	case FS_FULL_SIZE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `		struct smb2_fs_full_size_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `		unsigned long sectors_per_unit =`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `			max(1UL, (unsigned long)(stfs.f_bsize / 512));`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `		info = (struct smb2_fs_full_size_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `		info->TotalAllocationUnits = cpu_to_le64(stfs.f_blocks);`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `		info->CallerAvailableAllocationUnits =`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `					cpu_to_le64(stfs.f_bavail);`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `		info->ActualAvailableAllocationUnits =`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `					cpu_to_le64(stfs.f_bfree);`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `		info->SectorsPerAllocationUnit = cpu_to_le32(sectors_per_unit);`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `		info->BytesPerSector = cpu_to_le32(512);`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(32);`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `		min_output_len = 32;`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `	case FS_OBJECT_ID_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `		struct object_id_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `		info = (struct object_id_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `		 * Do not leak the user passkey as the object ID.`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] `		 * Use zeroed object ID for all users.`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `		memset(info->objid, 0, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `		info->extended_info.magic = cpu_to_le32(EXTENDED_INFO_MAGIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `		info->extended_info.version = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `		info->extended_info.release = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `		info->extended_info.rel_date = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [MEM_BOUNDS|] `		memcpy(info->extended_info.version_string, "1.1.0", strlen("1.1.0"));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01699 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(64);`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `		min_output_len = 48;`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	case FS_SECTOR_SIZE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `		struct smb3_fs_ss_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `		unsigned int sector_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `			min_t(unsigned int, path.mnt->mnt_sb->s_blocksize, 4096);`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `		info = (struct smb3_fs_ss_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `		info->LogicalBytesPerSector = cpu_to_le32(sector_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `		info->PhysicalBytesPerSectorForAtomicity =`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `				cpu_to_le32(sector_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `		info->PhysicalBytesPerSectorForPerf = cpu_to_le32(sector_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `		info->FSEffPhysicalBytesPerSectorForAtomicity =`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `				cpu_to_le32(sector_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `		info->Flags = cpu_to_le32(SSINFO_FLAGS_ALIGNED_DEVICE |`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `				    SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `		info->ByteOffsetForSectorAlignment = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `		info->ByteOffsetForPartitionAlignment = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(28);`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `		min_output_len = 28;`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	case FS_CONTROL_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `		 * TODO : The current implementation is based on`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `		 * test result with win7(NTFS) server. It's need to`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `		 * modify this to get valid Quota values`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `		 * from Linux kernel`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `		struct smb2_fs_control_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `		info = (struct smb2_fs_control_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `		info->FreeSpaceStartFiltering = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `		info->FreeSpaceThreshold = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `		info->FreeSpaceStopFiltering = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [PROTO_GATE|] `		info->DefaultQuotaThreshold = cpu_to_le64(SMB2_NO_FID);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01740 [PROTO_GATE|] `		info->DefaultQuotaLimit = cpu_to_le64(SMB2_NO_FID);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01741 [NONE] `		info->Padding = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(48);`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] `		min_output_len = 48;`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `	case FS_POSIX_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `		struct filesystem_posix_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `		info = (struct filesystem_posix_info *)(rsp->Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `		info->OptimalTransferSize = cpu_to_le32(stfs.f_bsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `		info->BlockSize = cpu_to_le32(stfs.f_bsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] `		info->TotalBlocks = cpu_to_le64(stfs.f_blocks);`
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `		info->BlocksAvail = cpu_to_le64(stfs.f_bfree);`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `		info->UserBlocksAvail = cpu_to_le64(stfs.f_bavail);`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `		info->TotalFileNodes = cpu_to_le64(stfs.f_files);`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] `		info->FreeFileNodes = cpu_to_le64(stfs.f_ffree);`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(56);`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `		min_output_len = 56;`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `		rc = ksmbd_dispatch_info(work, NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [PROTO_GATE|] `					 SMB2_O_INFO_FILESYSTEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01765 [NONE] `					 fsinfoclass,`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `					 KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `					 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `					 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `					 &qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `			path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `	rc = buffer_check_err(le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `			      rsp, work->response_buf, min_output_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `	path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `static int smb2_get_info_sec(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `			     struct smb2_query_info_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `			     struct smb2_query_info_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `	struct smb_ntsd *pntsd = (struct smb_ntsd *)rsp->Buffer, *ppntsd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	struct smb_fattr fattr = {{0}};`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `	__u32 secdesclen = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `	int addition_info = le32_to_cpu(req->AdditionalInformation);`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `	int rc = 0, ppntsd_size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `	if (addition_info & ~(OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `			      SACL_SECINFO | LABEL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `			      ATTRIBUTE_SECINFO | SCOPE_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `			      BACKUP_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `			      PROTECTED_DACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `			      UNPROTECTED_DACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `			      PROTECTED_SACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `			      UNPROTECTED_SACL_SECINFO)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `		ksmbd_debug(SMB, "Unsupported addition info: 0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `		       addition_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `		 * Per MS-SMB2 3.3.5.20.3: when the client requests`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `		 * security information flags that the server does not`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `		 * support, return a minimal self-relative security`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `		 * descriptor with no owner, group, SACL, or DACL.`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `		 * This is intentional -- it signals to the client that`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `		 * the requested information is not available without`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `		 * failing the entire query.`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `		pntsd->revision = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `		pntsd->type = cpu_to_le16(SELF_RELATIVE | DACL_PROTECTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `		pntsd->osidoffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `		pntsd->gsidoffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `		pntsd->sacloffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `		pntsd->dacloffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `		secdesclen = sizeof(struct smb_ntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(secdesclen);`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `		if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] `			ksmbd_debug(SMB, "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] `				    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `			id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `			pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `	if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `		id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `		pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `	fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01852 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `	 * Per MS-SMB2 3.3.5.20.3: querying OWNER, GROUP, or DACL`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `	 * security info requires READ_CONTROL access.  Querying`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `	 * SACL requires ACCESS_SYSTEM_SECURITY.`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `	if (addition_info & (OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `		if (!(fp->daccess & FILE_READ_CONTROL_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01862 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `	if (addition_info & SACL_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `		if (!(fp->daccess & FILE_ACCESS_SYSTEM_SECURITY_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01868 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `	idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `	user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `	ksmbd_acls_fattr(&fattr, idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	ksmbd_acls_fattr(&fattr, user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `	if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] `				   KSMBD_SHARE_FLAG_ACL_XATTR))`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `		ppntsd_size = ksmbd_vfs_get_sd_xattr(work->conn, idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `		ppntsd_size = ksmbd_vfs_get_sd_xattr(work->conn, user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `						     fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `						     &ppntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `	/* Check if sd buffer size exceeds response buffer size */`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `	if (smb2_resp_buf_len(work, 8) > ppntsd_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `		unsigned int resp_buf_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `			(unsigned int)smb2_resp_buf_len(work, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `		rc = build_sec_desc(idmap, pntsd, ppntsd, ppntsd_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `		rc = build_sec_desc(user_ns, pntsd, ppntsd, ppntsd_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `				    addition_info, &secdesclen,`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `				    &fattr, resp_buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `	posix_acl_release(fattr.cf_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `	posix_acl_release(fattr.cf_dacls);`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `	kfree(ppntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `	rsp->OutputBufferLength = cpu_to_le32(secdesclen);`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `	 * Per MS-SMB2 3.3.5.20.3: if the security descriptor is`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `	 * larger than the client's OutputBufferLength, return`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [PROTO_GATE|] `	 * STATUS_BUFFER_TOO_SMALL with the required size so the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01919 [NONE] `	 * client can retry with a larger buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `	if (secdesclen > le32_to_cpu(req->OutputBufferLength)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01923 [NONE] `		*(__be32 *)work->response_buf =`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `			cpu_to_be32(sizeof(struct smb2_hdr));`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01926 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] ` * smb2_query_info() - handler for smb2 query info command`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] ` * @work:	smb work containing query info request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `int smb2_query_info(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `	struct smb2_query_info_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] `	struct smb2_query_info_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `	unsigned int qout_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `	ksmbd_debug(SMB, "Received request smb2 query info request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] `	if (ksmbd_override_fsids(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01951 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `	switch (req->InfoType) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [PROTO_GATE|] `	case SMB2_O_INFO_FILE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01955 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILE\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01956 [NONE] `		rc = smb2_get_info_file(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [PROTO_GATE|] `	case SMB2_O_INFO_FILESYSTEM:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01959 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILESYSTEM\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01960 [NONE] `		rc = smb2_get_info_filesystem(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [PROTO_GATE|] `	case SMB2_O_INFO_SECURITY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01963 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_SECURITY\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01964 [NONE] `		rc = smb2_get_info_sec(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [PROTO_GATE|] `	case SMB2_O_INFO_QUOTA:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01967 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `		struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `		unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `		unsigned int qout_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_QUOTA\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01973 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `		if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `			if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `				id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `				pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `		if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `			id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `			pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `		fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `		if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `			rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [PROTO_GATE|] `						 SMB2_O_INFO_QUOTA,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01993 [NONE] `						 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] `						 KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `						 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `						 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `						 &qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `			if (rc == -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `				 * If quota handlers are not registered, keep`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `				 * behavior probe-friendly by returning an empty`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `				 * response rather than failing the request.`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `				rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `				qout_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `			if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `				rsp->OutputBufferLength = cpu_to_le32(qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] `			 * Validate InfoType range before dispatching to hook`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] `			 * handlers.  MS-SMB2 defines InfoType values 1..4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] `			 * reject anything outside that range to avoid passing`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `			 * unexpected values to registered hooks.`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [PROTO_GATE|] `			if (req->InfoType < SMB2_O_INFO_FILE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02021 [PROTO_GATE|] `			    req->InfoType > SMB2_O_INFO_QUOTA) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02022 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] `					    "Invalid InfoType %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] `					    req->InfoType);`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `			rc = ksmbd_dispatch_info(work, NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `						 req->InfoType,`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `						 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `						 KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `						 rsp->Buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `						 le32_to_cpu(req->OutputBufferLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `						 &qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `			if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `				rsp->OutputBufferLength = cpu_to_le32(qout_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `				ksmbd_debug(SMB, "InfoType %d unsupported\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `					    req->InfoType);`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `	if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(72);`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `				       offsetof(struct smb2_query_info_rsp, Buffer) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `					le32_to_cpu(rsp->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `	if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] `		if (rc == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02055 [NONE] `		else if (rc == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02057 [NONE] `		else if (rc == -EIO)`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02059 [NONE] `		else if (rc == -ENOMEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02061 [NONE] `		else if (rc == -ENOSYS)`
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02063 [NONE] `		else if (rc == -EOPNOTSUPP || rsp->hdr.Status == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02065 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `		ksmbd_debug(SMB, "error while processing smb2 query rc = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `			    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `static int smb2_rename(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `		       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] `		       struct smb2_file_rename_info *file_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `		       struct nls_table *local_nls)`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `	struct ksmbd_share_config *share = fp->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `	char *new_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] `	int rc, flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `	ksmbd_debug(SMB, "setting FILE_RENAME_INFO\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `	new_name = smb2_get_name(file_info->FileName,`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] `				 le32_to_cpu(file_info->FileNameLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `				 local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] `	if (IS_ERR(new_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] `		return PTR_ERR(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] `	 * G.7: If RootDirectory is non-zero, it is a volatile FID for`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `	 * the directory relative to which FileName is resolved.`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] `	 * Prepend the root's share-relative path to new_name.`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] `	if (file_info->RootDirectory) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `		struct ksmbd_file *root_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `		char *root_path, *combined;`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `		root_fp = ksmbd_lookup_fd_fast(work, file_info->RootDirectory);`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] `		if (!root_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] `			kfree(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02104 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] `		root_path = convert_to_nt_pathname(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] `						   &root_fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] `		ksmbd_fd_put(work, root_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] `		if (IS_ERR(root_path)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `			kfree(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] `			return PTR_ERR(root_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] `		/* Combine root_path + "/" + new_name (strip leading '/') */`
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] `		if (new_name[0] == '/' || new_name[0] == '\\')`
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] `			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `					     root_path, new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [NONE] `			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s/%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] `					     root_path, new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `		kfree(root_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] `		kfree(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] `		if (!combined)`
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02123 [NONE] `		new_name = combined;`
  Review: Low-risk line; verify in surrounding control flow.
- L02124 [NONE] `		ksmbd_debug(SMB, "RootDirectory resolved new name: %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02125 [NONE] `			    new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `	if (fp->is_posix_ctxt == false && strchr(new_name, ':')) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `		int s_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [NONE] `		char *xattr_stream_name, *stream_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02131 [NONE] `		size_t xattr_stream_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `		int len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] `		rc = parse_stream_name(new_name, &stream_name, &s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02136 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02137 [NONE] `			 * parse_stream_name returns -ENOENT for "::$DATA"`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] `			 * (the default data stream).  Per MS-FSA 2.1.5.14.11,`
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] `			 * renaming a named stream to ::$DATA means removing`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] `			 * the named stream (promoting its data to the default`
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `			 * stream is not supported for xattr-backed streams,`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] `			 * so we just delete the source xattr).`
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] `			if (rc == -ENOENT && !stream_name &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] `			    s_type == DATA_STREAM && ksmbd_stream_fd(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `				rc = ksmbd_vfs_remove_xattr(`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `					file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `					&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] `					fp->stream.name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `				if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [ERROR_PATH|] `					pr_err("rename to default stream: remove xattr failed %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02152 [NONE] `					       rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] `				else`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] `					rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02157 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] `		len = strlen(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] `		if (len > 0 && new_name[len - 1] != '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [ERROR_PATH|] `			pr_err("not allow base filename in rename\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02162 [NONE] `			rc = -ESHARE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02164 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [NONE] `		rc = ksmbd_vfs_xattr_stream_name(stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02167 [NONE] `						 &xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] `						 &xattr_stream_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [NONE] `						 s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] `		rc = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] `					&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] `					xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [NONE] `					NULL, 0, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02178 [ERROR_PATH|] `			pr_err("failed to store stream name in xattr: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02179 [NONE] `			       rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02182 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02184 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02185 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02187 [NONE] `	ksmbd_debug(SMB, "new name %s\n", new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] `	if (ksmbd_share_veto_filename(share, new_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] `		rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `		ksmbd_debug(SMB, "Can't rename vetoed file: %s\n", new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02192 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] `	 * POSIX rename semantics: always allow atomic replace of the`
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [NONE] `	 * target, even if it is currently open. This matches the`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] `	 * POSIX rename(2) behavior.`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `	if (!file_info->ReplaceIfExists && !fp->is_posix_ctxt)`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] `		flags = RENAME_NOREPLACE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] `	smb_break_all_handle_lease(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] `	rc = ksmbd_vfs_rename(work, &fp->filp->f_path, new_name, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `	kfree(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] `static int smb2_rename(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [NONE] `		       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] `		       struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `		       struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `		       struct smb2_file_rename_info *file_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [NONE] `		       struct nls_table *local_nls)`
  Review: Low-risk line; verify in surrounding control flow.
- L02218 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] `	struct ksmbd_share_config *share = fp->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] `	char *new_name = NULL, *abs_oldname = NULL, *old_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] `	char *pathname = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] `	bool file_present = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] `	bool same_name = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `	ksmbd_debug(SMB, "setting FILE_RENAME_INFO\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [MEM_BOUNDS|] `	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02229 [NONE] `	if (!pathname)`
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] `	abs_oldname = file_path(fp->filp, pathname, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `	if (IS_ERR(abs_oldname)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02236 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02237 [NONE] `	old_name = strrchr(abs_oldname, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `	if (old_name && old_name[1] != '\0') {`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] `		old_name++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [NONE] `		ksmbd_debug(SMB, "can't get last component in path %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] `			    abs_oldname);`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] `		rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02245 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `	new_name = smb2_get_name(file_info->FileName,`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] `				 le32_to_cpu(file_info->FileNameLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `				 local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `	if (IS_ERR(new_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `		rc = PTR_ERR(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02253 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] `	 * G.7: If RootDirectory is non-zero, look up the root FD and`
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [NONE] `	 * prepend its share-relative path to new_name.`
  Review: Low-risk line; verify in surrounding control flow.
- L02258 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] `	if (file_info->RootDirectory) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `		struct ksmbd_file *root_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] `		char *root_path, *combined;`
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `		root_fp = ksmbd_lookup_fd_fast(work, file_info->RootDirectory);`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `		if (!root_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02267 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `		root_path = convert_to_nt_pathname(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] `						   &root_fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] `		ksmbd_fd_put(work, root_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] `		if (IS_ERR(root_path)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `			rc = PTR_ERR(root_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02274 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] `		if (new_name[0] == '/' || new_name[0] == '\\')`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] `			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] `					     root_path, new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `			combined = kasprintf(KSMBD_DEFAULT_GFP, "%s/%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `					     root_path, new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `		kfree(root_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `		kfree(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] `		if (!combined) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] `			new_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] `			rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02287 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `		new_name = combined;`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `		ksmbd_debug(SMB, "RootDirectory resolved new name: %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [NONE] `			    new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `	if (fp->is_posix_ctxt == false && strchr(new_name, ':')) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `		int s_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [NONE] `		char *xattr_stream_name, *stream_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02296 [NONE] `		size_t xattr_stream_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] `		int len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] `		rc = parse_stream_name(new_name, &stream_name, &s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02301 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `			 * parse_stream_name returns -ENOENT for "::$DATA"`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `			 * (the default data stream).  Per MS-FSA 2.1.5.14.11,`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `			 * renaming a named stream to ::$DATA means removing`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `			 * the named stream (promoting its data to the default`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] `			 * stream is not supported for xattr-backed streams,`
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [NONE] `			 * so we just delete the source xattr).`
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] `			if (rc == -ENOENT && !stream_name &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `			    s_type == DATA_STREAM && ksmbd_stream_fd(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `				rc = ksmbd_vfs_remove_xattr(`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `					idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02315 [NONE] `				rc = ksmbd_vfs_remove_xattr(`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `					user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `					&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `					fp->stream.name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] `				if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [ERROR_PATH|] `					pr_err("rename to default stream: remove xattr failed %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02322 [NONE] `					       rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `				else`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `					rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02327 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] `		len = strlen(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `		if (len > 0 && new_name[len - 1] != '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [ERROR_PATH|] `			pr_err("not allow base filename in rename\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02332 [NONE] `			rc = -ESHARE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02334 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] `		rc = ksmbd_vfs_xattr_stream_name(stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] `						 &xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] `						 &xattr_stream_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] `						 s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] `		rc = ksmbd_vfs_setxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] `		rc = ksmbd_vfs_setxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `					&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] `					xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `					NULL, 0, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] `		if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [ERROR_PATH|] `			pr_err("failed to store stream name in xattr: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02353 [NONE] `			       rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02356 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02359 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [NONE] `	ksmbd_debug(SMB, "new name %s\n", new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02362 [NONE] `	rc = ksmbd_vfs_kern_path(work, new_name, LOOKUP_NO_SYMLINKS, &path, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [NONE] `		if (rc != -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02366 [NONE] `		file_present = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] `		 * Save the name comparison result before path_put()`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [NONE] `		 * releases the dentry reference.`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `		same_name = !strcmp(old_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] `				    path.dentry->d_name.name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] `	if (ksmbd_share_veto_filename(share, new_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [NONE] `		rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L02379 [NONE] `		ksmbd_debug(SMB, "Can't rename vetoed file: %s\n", new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02381 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] `	 * POSIX rename semantics: always allow atomic replace of the`
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] `	 * target, even if it is currently open.`
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] `	if (file_info->ReplaceIfExists || fp->is_posix_ctxt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `		if (file_present) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] `			rc = ksmbd_vfs_remove_file(work, new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] `				if (rc != -ENOTEMPTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] `					rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [NONE] `				ksmbd_debug(SMB, "cannot delete %s, rc %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02394 [NONE] `					    new_name, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02396 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `		if (file_present && !same_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `			rc = -EEXIST;`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [NONE] `				    "cannot rename already existing file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02404 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `	smb_break_all_handle_lease(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02409 [NONE] `	 * Break the source parent directory lease before rename.`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `	smb_break_parent_dir_lease(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] `	 * Break the destination parent directory lease before rename.`
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `	 * Look up the destination directory by resolving the parent`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] `	 * component of new_name.`
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `		struct path dst_dir_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] `		char *slash;`
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [NONE] `		slash = strrchr(new_name, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L02422 [NONE] `		if (slash && slash != new_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `			*slash = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `			if (!ksmbd_vfs_kern_path(work, new_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `						 LOOKUP_NO_SYMLINKS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `						 &dst_dir_path, 1)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] `				smb_break_dir_lease_by_dentry(`
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] `					dst_dir_path.dentry, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `				path_put(&dst_dir_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `			*slash = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] `		} else if (slash == new_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `			/* Destination is in share root */`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] `			smb_break_dir_lease_by_dentry(`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] `				fp->filp->f_path.mnt->mnt_root, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] `	rc = ksmbd_vfs_fp_rename(work, fp, new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] `	kfree(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `	if (!IS_ERR(new_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] `		kfree(new_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02444 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] `static int smb2_create_link(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [NONE] `			    struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `			    struct smb2_file_link_info *file_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] `			    unsigned int buf_len, struct file *filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [NONE] `			    struct nls_table *local_nls)`
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [NONE] `	char *link_name = NULL, *target_name = NULL, *pathname = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] `	if (buf_len < (u64)sizeof(struct smb2_file_link_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] `			le32_to_cpu(file_info->FileNameLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `	ksmbd_debug(SMB, "setting FILE_LINK_INFORMATION\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [MEM_BOUNDS|] `	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02463 [NONE] `	if (!pathname)`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `	link_name = smb2_get_name(file_info->FileName,`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] `				  le32_to_cpu(file_info->FileNameLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `				  local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `	if (IS_ERR(link_name) || S_ISDIR(file_inode(filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02472 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02474 [NONE] `	ksmbd_debug(SMB, "link name is %s\n", link_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02475 [NONE] `	target_name = file_path(filp, pathname, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [NONE] `	if (IS_ERR(target_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02477 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02478 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02479 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [NONE] `	ksmbd_debug(SMB, "target name is %s\n", target_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02482 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02483 [NONE] `	rc = ksmbd_vfs_kern_path_locked(work, link_name, LOOKUP_NO_SYMLINKS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [NONE] `					&path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02485 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02486 [NONE] `	rc = ksmbd_vfs_kern_path(work, link_name, LOOKUP_NO_SYMLINKS, &path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02487 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02488 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02489 [NONE] `		if (rc != -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L02490 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02491 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02492 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02493 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02494 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `		if (file_info->ReplaceIfExists) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02497 [NONE] `			rc = ksmbd_vfs_remove_file(work, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `			rc = ksmbd_vfs_remove_file(work, link_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02501 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02502 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] `				ksmbd_debug(SMB, "cannot delete %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `					    link_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02506 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [NONE] `			rc = -EEXIST;`
  Review: Low-risk line; verify in surrounding control flow.
- L02509 [NONE] `			ksmbd_debug(SMB, "link already exists\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02510 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02511 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02512 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] `		ksmbd_vfs_kern_path_unlock(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02515 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02516 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] `	 * Break the destination parent directory lease before creating`
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] `	 * the hard link.  A new directory entry is being added.`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02521 [NONE] `		struct path dst_dir_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02522 [NONE] `		char *slash;`
  Review: Low-risk line; verify in surrounding control flow.
- L02523 [NONE] `		char *link_name_copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L02524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] `		link_name_copy = kstrdup(link_name, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [NONE] `		if (link_name_copy) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02527 [NONE] `			slash = strrchr(link_name_copy, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L02528 [NONE] `			if (slash && slash != link_name_copy) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02529 [NONE] `				*slash = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] `				if (!ksmbd_vfs_kern_path(work, link_name_copy,`
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] `							 LOOKUP_NO_SYMLINKS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] `							 &dst_dir_path, 1)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] `					smb_break_dir_lease_by_dentry(`
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] `						dst_dir_path.dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] `					path_put(&dst_dir_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02538 [NONE] `			kfree(link_name_copy);`
  Review: Low-risk line; verify in surrounding control flow.
- L02539 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [NONE] `	rc = ksmbd_vfs_link(work, target_name, link_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02543 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02544 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02545 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [NONE] `	if (!IS_ERR(link_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L02548 [NONE] `		kfree(link_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `	kfree(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] `static int set_file_basic_info(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] `			       struct smb2_file_basic_info *file_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [NONE] `			       struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L02556 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02557 [NONE] `	struct iattr attrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L02558 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02560 [NONE] `	struct timespec64 saved_ctime;`
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02562 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L02563 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L02565 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02566 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] `	if (!(fp->daccess & FILE_WRITE_ATTRIBUTES_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02570 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [NONE] `	attrs.ia_valid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02572 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [NONE] `	inode = file_inode(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02574 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02575 [NONE] `	idmap = file_mnt_idmap(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02576 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02577 [NONE] `	user_ns = file_mnt_user_ns(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02578 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02580 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] `	 * Save the current ctime before any operations that may`
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [NONE] `	 * implicitly update it (xattr writes, notify_change, etc.).`
  Review: Low-risk line; verify in surrounding control flow.
- L02583 [NONE] `	 * SMB semantics: ChangeTime=0 means "don't change", so we`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [NONE] `	 * must restore the original ctime if the client didn't`
  Review: Low-risk line; verify in surrounding control flow.
- L02585 [NONE] `	 * provide an explicit ChangeTime value.`
  Review: Low-risk line; verify in surrounding control flow.
- L02586 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02587 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [NONE] `	saved_ctime = inode_get_ctime(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02589 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] `	saved_ctime = inode->i_ctime;`
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02593 [NONE] `	if (file_info->CreationTime)`
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `		fp->create_time = le64_to_cpu(file_info->CreationTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] `	if (file_info->LastAccessTime) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [NONE] `		attrs.ia_atime = ksmbd_NTtimeToUnix(file_info->LastAccessTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02598 [NONE] `		attrs.ia_valid |= (ATTR_ATIME | ATTR_ATIME_SET);`
  Review: Low-risk line; verify in surrounding control flow.
- L02599 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02601 [NONE] `	if (file_info->LastWriteTime) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02602 [NONE] `		attrs.ia_mtime = ksmbd_NTtimeToUnix(file_info->LastWriteTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] `		attrs.ia_valid |= (ATTR_MTIME | ATTR_MTIME_SET);`
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02606 [NONE] `	if (file_info->Attributes) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [NONE] `		if (!S_ISDIR(inode->i_mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02608 [NONE] `		    file_info->Attributes & ATTR_DIRECTORY_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02609 [ERROR_PATH|] `			pr_err("can't change a file to a directory\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02610 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02611 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02612 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02613 [NONE] `		if (S_ISDIR(inode->i_mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] `		    file_info->Attributes & ATTR_TEMPORARY_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [ERROR_PATH|] `			pr_err("can't set temporary attribute on a directory\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02616 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02617 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02618 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] `		if (!(S_ISDIR(inode->i_mode) && file_info->Attributes == ATTR_NORMAL_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] `			fp->f_ci->m_fattr = file_info->Attributes |`
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] `				(fp->f_ci->m_fattr & ATTR_DIRECTORY_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [NONE] `	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_STORE_DOS_ATTRS) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02625 [NONE] `	    (file_info->CreationTime || file_info->Attributes)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02626 [NONE] `		struct xattr_dos_attrib da = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02628 [NONE] `		da.version = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [NONE] `		da.itime = fp->itime;`
  Review: Low-risk line; verify in surrounding control flow.
- L02630 [NONE] `		da.create_time = fp->create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L02631 [NONE] `		da.attr = le32_to_cpu(fp->f_ci->m_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [NONE] `		da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |`
  Review: Low-risk line; verify in surrounding control flow.
- L02633 [NONE] `			XATTR_DOSINFO_ITIME;`
  Review: Low-risk line; verify in surrounding control flow.
- L02634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02635 [NONE] `		rc = compat_ksmbd_vfs_set_dos_attrib_xattr(&filp->f_path, &da,`
  Review: Low-risk line; verify in surrounding control flow.
- L02636 [NONE] `				true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02638 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02639 [NONE] `				    "failed to restore file attribute in EA\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02643 [NONE] `	if (attrs.ia_valid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `		struct dentry *dentry = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `		struct inode *inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02647 [NONE] `		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02650 [NONE] `		inode_lock(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02651 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02652 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02653 [NONE] `		rc = notify_change(idmap, dentry, &attrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02654 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02655 [NONE] `		rc = notify_change(user_ns, dentry, &attrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] `		rc = notify_change(dentry, &attrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] `		inode_unlock(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02663 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02665 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02666 [NONE] `	 * Apply ChangeTime after all operations that may implicitly`
  Review: Low-risk line; verify in surrounding control flow.
- L02667 [NONE] `	 * update ctime (notify_change, xattr writes, etc.).`
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] `	 * If the client specified an explicit ChangeTime, use it.`
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `	 * If ChangeTime is zero ("don't change"), restore the ctime`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [NONE] `	 * we saved before any modifications were made.`
  Review: Low-risk line; verify in surrounding control flow.
- L02671 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02672 [NONE] `	if (file_info->ChangeTime) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [NONE] `		inode_set_ctime_to_ts(inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02675 [NONE] `				ksmbd_NTtimeToUnix(file_info->ChangeTime));`
  Review: Low-risk line; verify in surrounding control flow.
- L02676 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02677 [NONE] `		inode->i_ctime = ksmbd_NTtimeToUnix(file_info->ChangeTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [NONE] `		inode_set_ctime_to_ts(inode, saved_ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02682 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] `		inode->i_ctime = saved_ctime;`
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02690 [NONE] `static int set_file_allocation_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [NONE] `				    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02692 [NONE] `				    struct smb2_file_alloc_info *file_alloc_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02694 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [NONE] `	 * TODO : It's working fine only when store dos attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L02696 [NONE] `	 * is not yes. need to implement a logic which works`
  Review: Low-risk line; verify in surrounding control flow.
- L02697 [NONE] `	 * properly with any smb.conf option`
  Review: Low-risk line; verify in surrounding control flow.
- L02698 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [NONE] `	loff_t alloc_blks;`
  Review: Low-risk line; verify in surrounding control flow.
- L02701 [NONE] `	u64 cur_alloc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02702 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02703 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02706 [NONE] `	if (!(fp->daccess & FILE_WRITE_DATA_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02709 [NONE] `	if (ksmbd_stream_fd(fp) == true)`
  Review: Low-risk line; verify in surrounding control flow.
- L02710 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02711 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02712 [NONE] `	rc = vfs_getattr(&fp->filp->f_path, &stat, STATX_BASIC_STATS | STATX_BTIME,`
  Review: Low-risk line; verify in surrounding control flow.
- L02713 [NONE] `			 AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L02714 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [NONE] `		u64 alloc_sz = le64_to_cpu(file_alloc_info->AllocationSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L02719 [NONE] `		u64 alloc_rounded;`
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [MEM_BOUNDS|] `		if (check_add_overflow(alloc_sz, (u64)511, &alloc_rounded)) {`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02722 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02723 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02724 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] `		alloc_blks = alloc_rounded >> 9;`
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02727 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02730 [NONE] `	 * Use the cached allocation size (data-only) for comparison`
  Review: Low-risk line; verify in surrounding control flow.
- L02731 [NONE] `	 * instead of stat.blocks, which on ext4 may include external`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [NONE] `	 * xattr blocks (e.g., security.NTACL) that inflate the count.`
  Review: Low-risk line; verify in surrounding control flow.
- L02733 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] `	cur_alloc = ksmbd_alloc_size(fp, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `	if ((loff_t)(cur_alloc >> 9) < alloc_blks) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] `		smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `		rc = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [NONE] `				   (loff_t)alloc_blks << 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L02740 [NONE] `		if (rc && rc != -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [ERROR_PATH|] `			pr_err("vfs_fallocate is failed : %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02742 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] `	} else if ((loff_t)(cur_alloc >> 9) > alloc_blks) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] `		loff_t size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02748 [NONE] `		 * Allocation size could be smaller than original one`
  Review: Low-risk line; verify in surrounding control flow.
- L02749 [NONE] `		 * which means allocated blocks in file should be`
  Review: Low-risk line; verify in surrounding control flow.
- L02750 [NONE] `		 * deallocated. use truncate to cut out it, but inode`
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] `		 * size is also updated with truncate offset.`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] `		 * inode size is retained by backup inode size.`
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [NONE] `		size = i_size_read(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02755 [NONE] `		rc = ksmbd_vfs_truncate(work, fp, alloc_blks * 512);`
  Review: Low-risk line; verify in surrounding control flow.
- L02756 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [ERROR_PATH|] `			pr_err("truncate failed!, err %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02758 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [NONE] `		if (size < alloc_blks * 512)`
  Review: Low-risk line; verify in surrounding control flow.
- L02761 [NONE] `			i_size_write(inode, size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02762 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] `	/* Cache the requested allocation size for accurate reporting */`
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] `	if (fp->f_ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] `		fp->f_ci->m_cached_alloc = (loff_t)alloc_blks << 9;`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [NONE] `static int set_end_of_file_info(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02773 [NONE] `				struct smb2_file_eof_info *file_eof_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L02774 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02775 [NONE] `	loff_t newsize;`
  Review: Low-risk line; verify in surrounding control flow.
- L02776 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02777 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02779 [NONE] `	if (!(fp->daccess & FILE_WRITE_DATA_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L02780 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02781 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02782 [NONE] `	newsize = le64_to_cpu(file_eof_info->EndOfFile);`
  Review: Low-risk line; verify in surrounding control flow.
- L02783 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02784 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02785 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02786 [NONE] `	 * If FILE_END_OF_FILE_INFORMATION of set_info_file is called`
  Review: Low-risk line; verify in surrounding control flow.
- L02787 [NONE] `	 * on FAT32 shared device, truncate execution time is too long`
  Review: Low-risk line; verify in surrounding control flow.
- L02788 [NONE] `	 * and network error could cause from windows client. because`
  Review: Low-risk line; verify in surrounding control flow.
- L02789 [NONE] `	 * truncate of some filesystem like FAT32 fill zero data in`
  Review: Low-risk line; verify in surrounding control flow.
- L02790 [NONE] `	 * truncated range.`
  Review: Low-risk line; verify in surrounding control flow.
- L02791 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02792 [NONE] `	if (inode->i_sb->s_magic != MSDOS_SUPER_MAGIC &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02793 [NONE] `	    ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02794 [NONE] `		ksmbd_debug(SMB, "truncated to newsize %lld\n", newsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L02795 [NONE] `		rc = ksmbd_vfs_truncate(work, fp, newsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L02796 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02797 [NONE] `			ksmbd_debug(SMB, "truncate failed!, err %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02798 [NONE] `			if (rc != -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L02799 [NONE] `				rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L02800 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02801 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02802 [NONE] `		/* Invalidate cached allocation; data size changed */`
  Review: Low-risk line; verify in surrounding control flow.
- L02803 [NONE] `		if (fp->f_ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L02804 [NONE] `			fp->f_ci->m_cached_alloc = -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02805 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02806 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02807 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02808 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02809 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02810 [NONE] `static int set_rename_info(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02811 [NONE] `			   struct smb2_file_rename_info *rename_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L02812 [NONE] `			   unsigned int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02813 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02814 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L02815 [NONE] `	struct dentry *parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02816 [NONE] `	struct path parent_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02817 [NONE] `	__le32 daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L02818 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02820 [NONE] `	if (!sess->user)`
  Review: Low-risk line; verify in surrounding control flow.
- L02821 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02822 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02823 [NONE] `	 * Do NOT reject guest users here.  On guest-ok shares (guest ok = yes,`
  Review: Low-risk line; verify in surrounding control flow.
- L02824 [NONE] `	 * read only = no), guests must be able to rename just like any other`
  Review: Low-risk line; verify in surrounding control flow.
- L02825 [NONE] `	 * user.  The correct access control already happens via:`
  Review: Low-risk line; verify in surrounding control flow.
- L02826 [NONE] `	 *   1. KSMBD_TREE_CONN_FLAG_WRITABLE check in smb2_set_info()`
  Review: Low-risk line; verify in surrounding control flow.
- L02827 [NONE] `	 *   2. fp->daccess check below (needs FILE_DELETE_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02828 [NONE] `	 *   3. NTACL DACL check via smb_check_perm_dacl (if an ACL exists)`
  Review: Low-risk line; verify in surrounding control flow.
- L02829 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02830 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02831 [NONE] `	daccess = FILE_DELETE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02832 [NONE] `	rc = smb_check_perm_dacl(work->conn, &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02833 [NONE] `				 &daccess, sess->user->uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02834 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02835 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02837 [NONE] `	parent = dget_parent(fp->filp->f_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02838 [NONE] `	parent_path.mnt = fp->filp->f_path.mnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02839 [NONE] `	parent_path.dentry = parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02840 [NONE] `	daccess = FILE_DELETE_CHILD_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02841 [NONE] `	rc = smb_check_perm_dacl(work->conn, &parent_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02842 [NONE] `				 &daccess, sess->user->uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02843 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02844 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02845 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02846 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02847 [NONE] `	if (!(fp->daccess & FILE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02848 [ERROR_PATH|] `		pr_err("no right to delete : 0x%x\n", fp->daccess);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02849 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02850 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02852 [NONE] `	if (buf_len < (u64)sizeof(struct smb2_file_rename_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02853 [NONE] `			le32_to_cpu(rename_info->FileNameLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L02854 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02856 [NONE] `	if (!le32_to_cpu(rename_info->FileNameLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L02857 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02858 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02859 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02860 [NONE] `	 * MS-SMB2 §3.3.5.21.1: Check that all other open handles on the`
  Review: Low-risk line; verify in surrounding control flow.
- L02861 [NONE] `	 * file being renamed have FILE_SHARE_DELETE in their share access.`
  Review: Low-risk line; verify in surrounding control flow.
- L02862 [PROTO_GATE|] `	 * If not, the rename must fail with STATUS_SHARING_VIOLATION.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02863 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02864 [NONE] `	if (fp->f_ci) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02865 [NONE] `		struct ksmbd_file *other_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02866 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02867 [LOCK|] `		down_read(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02868 [NONE] `		list_for_each_entry(other_fp, &fp->f_ci->m_fp_list, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02869 [NONE] `			if (other_fp == fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02870 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02871 [NONE] `			if (other_fp->attrib_only)`
  Review: Low-risk line; verify in surrounding control flow.
- L02872 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02873 [NONE] `			if (!(other_fp->saccess & FILE_SHARE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02874 [NONE] `				up_read(&fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02875 [ERROR_PATH|] `				return -ESHARE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02876 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02877 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02878 [NONE] `		up_read(&fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02879 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02880 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02881 [NONE] `	rc = smb2_rename(work, fp, rename_info, work->conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02882 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02883 [NONE] `	 * On Windows, renaming a file causes FILE_NOTIFY_CHANGE_ATTRIBUTES`
  Review: Low-risk line; verify in surrounding control flow.
- L02884 [NONE] `	 * because the file's ctime is updated by the rename.  Replicate this`
  Review: Low-risk line; verify in surrounding control flow.
- L02885 [NONE] `	 * by re-writing the DOS attribute xattr at the new path; vfs_setxattr`
  Review: Low-risk line; verify in surrounding control flow.
- L02886 [NONE] `	 * fires fsnotify_xattr() → FS_ATTRIB, which is mapped to MODIFIED`
  Review: Low-risk line; verify in surrounding control flow.
- L02887 [NONE] `	 * and completes any CHANGE_NOTIFY watching for ATTRIBUTES changes.`
  Review: Low-risk line; verify in surrounding control flow.
- L02888 [NONE] `	 * Skip this for alternate-data-stream renames (their xattr write is`
  Review: Low-risk line; verify in surrounding control flow.
- L02889 [NONE] `	 * already done inside smb2_rename).`
  Review: Low-risk line; verify in surrounding control flow.
- L02890 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02891 [NONE] `	if (!rc && fp->f_ci && !ksmbd_stream_fd(fp) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02892 [NONE] `	    test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02893 [NONE] `				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02894 [NONE] `		struct xattr_dos_attrib da = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02895 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02896 [NONE] `		da.version = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02897 [NONE] `		da.attr = le32_to_cpu(fp->f_ci->m_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02898 [NONE] `		da.itime = da.create_time = fp->create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L02899 [NONE] `		da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |`
  Review: Low-risk line; verify in surrounding control flow.
- L02900 [NONE] `			   XATTR_DOSINFO_ITIME;`
  Review: Low-risk line; verify in surrounding control flow.
- L02901 [NONE] `		compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02902 [NONE] `						      &da, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02903 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02904 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02905 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02906 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02907 [NONE] `static int set_rename_info(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02908 [NONE] `			   struct smb2_file_rename_info *rename_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L02909 [NONE] `			   unsigned int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02910 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02911 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02912 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L02913 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02914 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L02915 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02916 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L02917 [NONE] `	struct ksmbd_file *parent_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02918 [NONE] `	struct dentry *parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02919 [NONE] `	struct path parent_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02920 [NONE] `	struct dentry *dentry = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02921 [NONE] `	__le32 daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L02922 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02923 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02924 [NONE] `	if (!sess->user)`
  Review: Low-risk line; verify in surrounding control flow.
- L02925 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02926 [NONE] `	/* guest check removed — see comment in >= 6.4.0 variant above */`
  Review: Low-risk line; verify in surrounding control flow.
- L02927 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02928 [NONE] `	daccess = FILE_DELETE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02929 [NONE] `	ret = smb_check_perm_dacl(work->conn, &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02930 [NONE] `				  &daccess, sess->user->uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02931 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L02932 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02934 [NONE] `	parent = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02935 [NONE] `	parent_path.mnt = fp->filp->f_path.mnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02936 [NONE] `	parent_path.dentry = parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02937 [NONE] `	daccess = FILE_DELETE_CHILD_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02938 [NONE] `	ret = smb_check_perm_dacl(work->conn, &parent_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02939 [NONE] `				  &daccess, sess->user->uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02940 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02941 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L02942 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02943 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02944 [NONE] `	if (!(fp->daccess & FILE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02945 [ERROR_PATH|] `		pr_err("no right to delete : 0x%x\n", fp->daccess);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02946 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02947 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02948 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02949 [NONE] `	if (buf_len < (u64)sizeof(struct smb2_file_rename_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02950 [NONE] `			le32_to_cpu(rename_info->FileNameLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L02951 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02953 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02954 [NONE] `	idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02955 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02956 [NONE] `	user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02957 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02958 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L02959 [ERROR_PATH|] `		goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02961 [NONE] `	parent = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02962 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02963 [NONE] `	ret = ksmbd_vfs_lock_parent(idmap, parent, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02964 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02965 [NONE] `	ret = ksmbd_vfs_lock_parent(user_ns, parent, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02966 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02967 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02968 [NONE] `		dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02969 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02970 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02972 [NONE] `	parent_fp = ksmbd_lookup_fd_inode(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02973 [NONE] `	inode_unlock(d_inode(parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L02974 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02975 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02976 [NONE] `	if (parent_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02977 [NONE] `		if (parent_fp->daccess & FILE_DELETE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02978 [ERROR_PATH|] `			pr_err("parent dir is opened with delete access\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02979 [NONE] `			ksmbd_fd_put(work, parent_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02980 [ERROR_PATH|] `			return -ESHARE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02981 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02982 [NONE] `		ksmbd_fd_put(work, parent_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02983 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02984 [NONE] `next:`
  Review: Low-risk line; verify in surrounding control flow.
- L02985 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02986 [NONE] `	 * MS-SMB2 §3.3.5.21.1: Check that all other open handles on the`
  Review: Low-risk line; verify in surrounding control flow.
- L02987 [NONE] `	 * file being renamed have FILE_SHARE_DELETE in their share access.`
  Review: Low-risk line; verify in surrounding control flow.
- L02988 [PROTO_GATE|] `	 * If not, the rename must fail with STATUS_SHARING_VIOLATION.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02989 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02990 [NONE] `	if (fp->f_ci) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02991 [NONE] `		struct ksmbd_file *other_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02992 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02993 [LOCK|] `		down_read(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02994 [NONE] `		list_for_each_entry(other_fp, &fp->f_ci->m_fp_list, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02995 [NONE] `			if (other_fp == fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02996 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02997 [NONE] `			if (other_fp->attrib_only)`
  Review: Low-risk line; verify in surrounding control flow.
- L02998 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02999 [NONE] `			if (!(other_fp->saccess & FILE_SHARE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03000 [NONE] `				up_read(&fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03001 [ERROR_PATH|] `				return -ESHARE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03002 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03003 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03004 [NONE] `		up_read(&fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03005 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03007 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03008 [NONE] `	ret = smb2_rename(work, fp, idmap, rename_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L03009 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03010 [NONE] `	ret = smb2_rename(work, fp, user_ns, rename_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L03011 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03012 [NONE] `			  work->conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L03013 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03014 [NONE] `	 * On Windows, renaming a file causes FILE_NOTIFY_CHANGE_ATTRIBUTES`
  Review: Low-risk line; verify in surrounding control flow.
- L03015 [NONE] `	 * because the file's ctime is updated by the rename.  Replicate this`
  Review: Low-risk line; verify in surrounding control flow.
- L03016 [NONE] `	 * by re-writing the DOS attribute xattr at the new path; vfs_setxattr`
  Review: Low-risk line; verify in surrounding control flow.
- L03017 [NONE] `	 * fires fsnotify_xattr() → FS_ATTRIB, which is mapped to MODIFIED`
  Review: Low-risk line; verify in surrounding control flow.
- L03018 [NONE] `	 * and completes any CHANGE_NOTIFY watching for ATTRIBUTES changes.`
  Review: Low-risk line; verify in surrounding control flow.
- L03019 [NONE] `	 * Skip this for alternate-data-stream renames (their xattr write is`
  Review: Low-risk line; verify in surrounding control flow.
- L03020 [NONE] `	 * already done inside smb2_rename).`
  Review: Low-risk line; verify in surrounding control flow.
- L03021 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03022 [NONE] `	if (!ret && fp->f_ci && !ksmbd_stream_fd(fp) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03023 [NONE] `	    test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L03024 [NONE] `				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03025 [NONE] `		struct xattr_dos_attrib da = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L03026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03027 [NONE] `		da.version = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L03028 [NONE] `		da.attr = le32_to_cpu(fp->f_ci->m_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L03029 [NONE] `		da.itime = da.create_time = fp->create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L03030 [NONE] `		da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |`
  Review: Low-risk line; verify in surrounding control flow.
- L03031 [NONE] `			   XATTR_DOSINFO_ITIME;`
  Review: Low-risk line; verify in surrounding control flow.
- L03032 [NONE] `		compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L03033 [NONE] `						      &da, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L03034 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03035 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03036 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03037 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03039 [NONE] `static int set_file_disposition_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L03040 [NONE] `				     struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03041 [NONE] `				     struct smb2_file_disposition_info *file_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L03042 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03043 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L03044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03045 [NONE] `	if (!(fp->daccess & FILE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03046 [ERROR_PATH|] `		pr_err("no right to delete : 0x%x\n", fp->daccess);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03047 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03048 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03050 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03051 [NONE] `	if (file_info->DeletePending) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03052 [NONE] `		if (fp->f_ci->m_fattr & ATTR_READONLY_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03053 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L03054 [NONE] `				    "delete disposition on read-only file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03055 [ERROR_PATH|] `			return -EROFS;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03056 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03057 [NONE] `		if (S_ISDIR(inode->i_mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03058 [NONE] `		    ksmbd_vfs_empty_dir(fp) == -ENOTEMPTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L03059 [ERROR_PATH|] `			return -EBUSY;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03060 [NONE] `		smb_break_all_handle_lease(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03061 [NONE] `		ksmbd_set_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03062 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03063 [NONE] `		ksmbd_clear_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03064 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03065 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03066 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03068 [NONE] `#define FILE_DISPOSITION_DELETE			0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L03069 [NONE] `#define FILE_DISPOSITION_POSIX_SEMANTICS	0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L03070 [NONE] `#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK 0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L03071 [NONE] `#define FILE_DISPOSITION_ON_CLOSE		0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L03072 [NONE] `#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L03073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03074 [NONE] `struct smb2_file_disposition_info_ex {`
  Review: Low-risk line; verify in surrounding control flow.
- L03075 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L03076 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L03077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03078 [NONE] `static int set_file_disposition_info_ex(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L03079 [NONE] `					struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03080 [NONE] `					struct smb2_file_disposition_info_ex *file_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L03081 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03082 [NONE] `	struct smb2_file_disposition_info legacy = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L03083 [NONE] `	u32 flags = le32_to_cpu(file_info->Flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L03084 [NONE] `	u32 valid_flags = FILE_DISPOSITION_DELETE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03085 [NONE] `			  FILE_DISPOSITION_POSIX_SEMANTICS |`
  Review: Low-risk line; verify in surrounding control flow.
- L03086 [NONE] `			  FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK |`
  Review: Low-risk line; verify in surrounding control flow.
- L03087 [NONE] `			  FILE_DISPOSITION_ON_CLOSE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03088 [NONE] `			  FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;`
  Review: Low-risk line; verify in surrounding control flow.
- L03089 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03091 [NONE] `	if (flags & ~valid_flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L03092 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03094 [NONE] `	if (flags & FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03095 [NONE] `		if (!(fp->daccess & FILE_WRITE_ATTRIBUTES_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03096 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L03097 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03098 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03099 [NONE] `		fp->f_ci->m_fattr &= ~ATTR_READONLY_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L03100 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03102 [NONE] `	legacy.DeletePending = !!(flags & FILE_DISPOSITION_DELETE);`
  Review: Low-risk line; verify in surrounding control flow.
- L03103 [NONE] `	return set_file_disposition_info(work, fp, &legacy);`
  Review: Low-risk line; verify in surrounding control flow.
- L03104 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03105 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03108 [NONE] `#define FILE_RENAME_REPLACE_IF_EXISTS			0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L03109 [NONE] `#define FILE_RENAME_POSIX_SEMANTICS			0x00000002`
  Review: Low-risk line; verify in surrounding control flow.
- L03110 [NONE] `#define FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE	0x00000004`
  Review: Low-risk line; verify in surrounding control flow.
- L03111 [NONE] `#define FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE 0x00000008`
  Review: Low-risk line; verify in surrounding control flow.
- L03112 [NONE] `#define FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE		0x00000010`
  Review: Low-risk line; verify in surrounding control flow.
- L03113 [NONE] `#define FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE		0x00000020`
  Review: Low-risk line; verify in surrounding control flow.
- L03114 [NONE] `#define FILE_RENAME_IGNORE_READONLY_ATTRIBUTE		0x00000040`
  Review: Low-risk line; verify in surrounding control flow.
- L03115 [NONE] `#define FILE_RENAME_FORCE_RESIZE_TARGET_SR		0x00000080`
  Review: Low-risk line; verify in surrounding control flow.
- L03116 [NONE] `#define FILE_RENAME_FORCE_RESIZE_SOURCE_SR		0x00000100`
  Review: Low-risk line; verify in surrounding control flow.
- L03117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03118 [NONE] `struct smb2_file_rename_info_ex {`
  Review: Low-risk line; verify in surrounding control flow.
- L03119 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L03120 [NONE] `	__u32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L03121 [NONE] `	__u64 RootDirectory;`
  Review: Low-risk line; verify in surrounding control flow.
- L03122 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L03123 [NONE] `	char FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L03124 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L03125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03126 [NONE] `static int set_rename_info_ex(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03127 [NONE] `			      struct smb2_file_rename_info_ex *file_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L03128 [NONE] `			      unsigned int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03129 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03130 [NONE] `	struct smb2_file_rename_info *legacy;`
  Review: Low-risk line; verify in surrounding control flow.
- L03131 [NONE] `	unsigned int name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03132 [NONE] `	unsigned int valid_off = offsetof(struct smb2_file_rename_info_ex, FileName);`
  Review: Low-risk line; verify in surrounding control flow.
- L03133 [NONE] `	u32 flags = le32_to_cpu(file_info->Flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L03134 [NONE] `	u32 valid_flags = FILE_RENAME_REPLACE_IF_EXISTS |`
  Review: Low-risk line; verify in surrounding control flow.
- L03135 [NONE] `			  FILE_RENAME_POSIX_SEMANTICS |`
  Review: Low-risk line; verify in surrounding control flow.
- L03136 [NONE] `			  FILE_RENAME_SUPPRESS_PIN_STATE_INHERITANCE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03137 [NONE] `			  FILE_RENAME_SUPPRESS_STORAGE_RESERVE_INHERITANCE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03138 [NONE] `			  FILE_RENAME_NO_INCREASE_AVAILABLE_SPACE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03139 [NONE] `			  FILE_RENAME_NO_DECREASE_AVAILABLE_SPACE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03140 [NONE] `			  FILE_RENAME_IGNORE_READONLY_ATTRIBUTE |`
  Review: Low-risk line; verify in surrounding control flow.
- L03141 [NONE] `			  FILE_RENAME_FORCE_RESIZE_TARGET_SR |`
  Review: Low-risk line; verify in surrounding control flow.
- L03142 [NONE] `			  FILE_RENAME_FORCE_RESIZE_SOURCE_SR;`
  Review: Low-risk line; verify in surrounding control flow.
- L03143 [NONE] `	size_t legacy_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03144 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03146 [NONE] `	if (flags & ~valid_flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L03147 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03149 [NONE] `	if (buf_len < valid_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L03150 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03152 [NONE] `	name_len = le32_to_cpu(file_info->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L03153 [NONE] `	if (name_len > buf_len - valid_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L03154 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03156 [NONE] `	legacy_len = sizeof(*legacy) + name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03157 [MEM_BOUNDS|] `	legacy = kzalloc(legacy_len, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L03158 [NONE] `	if (!legacy)`
  Review: Low-risk line; verify in surrounding control flow.
- L03159 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03161 [NONE] `	legacy->ReplaceIfExists = !!(flags & FILE_RENAME_REPLACE_IF_EXISTS);`
  Review: Low-risk line; verify in surrounding control flow.
- L03162 [NONE] `	legacy->RootDirectory = file_info->RootDirectory;`
  Review: Low-risk line; verify in surrounding control flow.
- L03163 [NONE] `	legacy->FileNameLength = cpu_to_le32(name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03164 [MEM_BOUNDS|] `	memcpy(legacy->FileName, file_info->FileName, name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L03165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03166 [NONE] `	rc = set_rename_info(work, fp, legacy, legacy_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03167 [NONE] `	kfree(legacy);`
  Review: Low-risk line; verify in surrounding control flow.
- L03168 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03169 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03171 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L03172 [NONE] `int set_file_position_info(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03173 [NONE] `				  struct smb2_file_pos_info *file_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L03174 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03175 [NONE] `	loff_t current_byte_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L03176 [NONE] `	unsigned long sector_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L03177 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L03178 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03179 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03180 [NONE] `	current_byte_offset = le64_to_cpu(file_info->CurrentByteOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03181 [NONE] `	sector_size = inode->i_sb->s_blocksize;`
  Review: Low-risk line; verify in surrounding control flow.
- L03182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03183 [NONE] `	if (current_byte_offset < 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L03184 [NONE] `	    (fp->coption == FILE_NO_INTERMEDIATE_BUFFERING_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03185 [NONE] `	     current_byte_offset & (sector_size - 1))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03186 [ERROR_PATH|] `		pr_err("CurrentByteOffset is not valid : %llu\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03187 [NONE] `		       current_byte_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03188 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03189 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03191 [NONE] `	if (ksmbd_stream_fd(fp) == false)`
  Review: Low-risk line; verify in surrounding control flow.
- L03192 [NONE] `		fp->filp->f_pos = current_byte_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L03193 [NONE] `	else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03194 [NONE] `		if (current_byte_offset > XATTR_SIZE_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L03195 [NONE] `			current_byte_offset = XATTR_SIZE_MAX;`
  Review: Low-risk line; verify in surrounding control flow.
- L03196 [NONE] `		fp->stream.pos = current_byte_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L03197 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03198 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03199 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03200 [NONE] `EXPORT_SYMBOL_IF_KUNIT(set_file_position_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L03201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03202 [NONE] `VISIBLE_IF_KUNIT`
  Review: Low-risk line; verify in surrounding control flow.
- L03203 [NONE] `int set_file_mode_info(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03204 [NONE] `			      struct smb2_file_mode_info *file_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L03205 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03206 [NONE] `	__le32 mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L03207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03208 [NONE] `	mode = file_info->Mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L03209 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03210 [NONE] `	if ((mode & ~FILE_MODE_INFO_MASK) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L03211 [NONE] `	    (mode & FILE_SYNCHRONOUS_IO_ALERT_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03212 [NONE] `	     mode & FILE_SYNCHRONOUS_IO_NONALERT_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03213 [ERROR_PATH|] `		pr_err("Mode is not valid : 0x%x\n", le32_to_cpu(mode));`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03214 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03215 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03217 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03218 [NONE] `	 * TODO : need to implement consideration for`
  Review: Low-risk line; verify in surrounding control flow.
- L03219 [NONE] `	 * FILE_SYNCHRONOUS_IO_ALERT and FILE_SYNCHRONOUS_IO_NONALERT`
  Review: Low-risk line; verify in surrounding control flow.
- L03220 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03221 [NONE] `	ksmbd_vfs_set_fadvise(fp->filp, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L03222 [NONE] `	fp->coption = mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L03223 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03224 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03225 [NONE] `EXPORT_SYMBOL_IF_KUNIT(set_file_mode_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L03226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03227 [NONE] `static int set_file_object_id_info(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03228 [NONE] `				   const char *buffer, unsigned int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03229 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03230 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03232 [NONE] `	if (!(fp->daccess & FILE_WRITE_ATTRIBUTES_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L03233 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03235 [NONE] `	if (buf_len < 16)`
  Review: Low-risk line; verify in surrounding control flow.
- L03236 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03238 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03239 [NONE] `	rc = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L03240 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03241 [NONE] `	rc = ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L03242 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03243 [NONE] `				&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L03244 [NONE] `				XATTR_NAME_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L03245 [NONE] `				(void *)buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L03246 [NONE] `				16, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L03247 [NONE] `	if (rc == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L03248 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03249 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03250 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03252 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03253 [NONE] ` * smb2_set_info_file() - handler for smb2 set info command`
  Review: Low-risk line; verify in surrounding control flow.
- L03254 [NONE] ` * @work:	smb work containing set info command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L03255 [NONE] ` * @fp:		ksmbd_file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L03256 [NONE] ` * @req:	request buffer pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L03257 [NONE] ` * @share:	ksmbd_share_config pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L03258 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03259 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03260 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03261 [NONE] `static int smb2_set_info_file(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03262 [NONE] `			      struct smb2_set_info_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L03263 [NONE] `			      struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L03264 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03265 [NONE] `	unsigned int buf_len = le32_to_cpu(req->BufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L03266 [NONE] `	char *buffer = (char *)req + le16_to_cpu(req->BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03267 [NONE] `	unsigned int consumed_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03268 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03270 [NONE] `	switch (req->FileInfoClass) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03271 [NONE] `	case FILE_BASIC_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03272 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03273 [NONE] `		if (buf_len < sizeof(struct smb2_file_basic_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03274 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03276 [NONE] `		return set_file_basic_info(fp, (struct smb2_file_basic_info *)buffer, share);`
  Review: Low-risk line; verify in surrounding control flow.
- L03277 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03278 [NONE] `	case FILE_ALLOCATION_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03279 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03280 [NONE] `		if (buf_len < sizeof(struct smb2_file_alloc_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03281 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03283 [NONE] `		return set_file_allocation_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03284 [NONE] `						(struct smb2_file_alloc_info *)buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L03285 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03286 [NONE] `	case FILE_END_OF_FILE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03287 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03288 [NONE] `		if (buf_len < sizeof(struct smb2_file_eof_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03289 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03290 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03291 [NONE] `		return set_end_of_file_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03292 [NONE] `					    (struct smb2_file_eof_info *)buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L03293 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03294 [NONE] `	case FILE_RENAME_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03295 [NONE] `	case FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK:`
  Review: Low-risk line; verify in surrounding control flow.
- L03296 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03297 [NONE] `		if (buf_len < sizeof(struct smb2_file_rename_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03298 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03299 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03300 [NONE] `		return set_rename_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03301 [NONE] `				       (struct smb2_file_rename_info *)buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L03302 [NONE] `				       buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03303 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03304 [NONE] `	case FILE_RENAME_INFORMATION_EX:`
  Review: Low-risk line; verify in surrounding control flow.
- L03305 [NONE] `	case FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK:`
  Review: Low-risk line; verify in surrounding control flow.
- L03306 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03307 [NONE] `		if (buf_len < offsetof(struct smb2_file_rename_info_ex, FileName))`
  Review: Low-risk line; verify in surrounding control flow.
- L03308 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03310 [NONE] `		return set_rename_info_ex(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03311 [NONE] `					(struct smb2_file_rename_info_ex *)buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L03312 [NONE] `					buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03313 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03314 [NONE] `	case FILE_LINK_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03315 [NONE] `	case FILE_LINK_INFORMATION_BYPASS_ACCESS_CHECK:`
  Review: Low-risk line; verify in surrounding control flow.
- L03316 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03317 [NONE] `		if (buf_len < sizeof(struct smb2_file_link_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03318 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03320 [NONE] `		return smb2_create_link(work, work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L03321 [NONE] `					(struct smb2_file_link_info *)buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L03322 [NONE] `					buf_len, fp->filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03323 [NONE] `					work->conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L03324 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03325 [NONE] `	case FILE_DISPOSITION_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03326 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03327 [NONE] `		if (buf_len < sizeof(struct smb2_file_disposition_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03328 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03330 [NONE] `		return set_file_disposition_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03331 [NONE] `						 (struct smb2_file_disposition_info *)buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L03332 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03333 [NONE] `	case FILE_DISPOSITION_INFORMATION_EX:`
  Review: Low-risk line; verify in surrounding control flow.
- L03334 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03335 [NONE] `		if (buf_len < sizeof(struct smb2_file_disposition_info_ex))`
  Review: Low-risk line; verify in surrounding control flow.
- L03336 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03338 [NONE] `		return set_file_disposition_info_ex(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03339 [NONE] `					(struct smb2_file_disposition_info_ex *)buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L03340 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03341 [NONE] `	case FILE_FULL_EA_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03342 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03343 [NONE] `		if (!(fp->daccess & FILE_WRITE_EA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03344 [ERROR_PATH|] `			pr_err("Not permitted to write ext  attr: 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03345 [NONE] `			       fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L03346 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03347 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03349 [NONE] `		if (buf_len < sizeof(struct smb2_ea_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03350 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03352 [NONE] `		return smb2_set_ea((struct smb2_ea_info *)buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L03353 [NONE] `				   buf_len, &fp->filp->f_path, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L03354 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03355 [NONE] `	case FILE_POSITION_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03356 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03357 [NONE] `		if (buf_len < sizeof(struct smb2_file_pos_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03358 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03360 [NONE] `		return set_file_position_info(fp, (struct smb2_file_pos_info *)buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L03361 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03362 [NONE] `	case FILE_MODE_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03363 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03364 [NONE] `		if (buf_len < sizeof(struct smb2_file_mode_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L03365 [ERROR_PATH|] `			return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03366 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03367 [NONE] `		return set_file_mode_info(fp, (struct smb2_file_mode_info *)buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L03368 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03369 [NONE] `	case FILE_OBJECT_ID_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L03370 [NONE] `		return set_file_object_id_info(fp, buffer, buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03371 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03373 [NONE] `	rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03374 [PROTO_GATE|] `				 SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03375 [NONE] `				 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L03376 [NONE] `				 KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L03377 [NONE] `				 buffer, buf_len, &consumed_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03378 [NONE] `	if (!rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L03379 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03381 [NONE] `	ksmbd_debug(SMB, "FileInfoClass %d unsupported\n", req->FileInfoClass);`
  Review: Low-risk line; verify in surrounding control flow.
- L03382 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03383 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03384 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03385 [NONE] `static int smb2_set_info_sec(struct ksmbd_file *fp, int addition_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L03386 [NONE] `			     char *buffer, int buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03387 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03388 [NONE] `	struct smb_ntsd *pntsd = (struct smb_ntsd *)buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L03389 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03391 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03392 [NONE] `	 * Enforce SMB access-mask checks on the open handle.`
  Review: Low-risk line; verify in surrounding control flow.
- L03393 [NONE] `	 * OWNER/GROUP updates require WRITE_OWNER, DACL updates require`
  Review: Low-risk line; verify in surrounding control flow.
- L03394 [NONE] `	 * WRITE_DAC, and SACL updates require ACCESS_SYSTEM_SECURITY.`
  Review: Low-risk line; verify in surrounding control flow.
- L03395 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03396 [NONE] `	if (addition_info & (OWNER_SECINFO | GROUP_SECINFO)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03397 [NONE] `		if (!(fp->daccess & FILE_WRITE_OWNER_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L03398 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03399 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03400 [NONE] `	if (addition_info & DACL_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03401 [NONE] `		if (!(fp->daccess & FILE_WRITE_DAC_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L03402 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03403 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03404 [NONE] `	if (addition_info & SACL_SECINFO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03405 [NONE] `		if (!(fp->daccess & FILE_ACCESS_SYSTEM_SECURITY_LE))`
  Review: Low-risk line; verify in surrounding control flow.
- L03406 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03407 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03409 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03410 [NONE] `	 * Validate addition_info before performing security descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L03411 [NONE] `	 * operations.  Only recognised flags should be accepted.`
  Review: Low-risk line; verify in surrounding control flow.
- L03412 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03413 [NONE] `	if (addition_info & ~(OWNER_SECINFO | GROUP_SECINFO | DACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03414 [NONE] `			      SACL_SECINFO | LABEL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03415 [NONE] `			      ATTRIBUTE_SECINFO | SCOPE_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03416 [NONE] `			      BACKUP_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03417 [NONE] `			      PROTECTED_DACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03418 [NONE] `			      UNPROTECTED_DACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03419 [NONE] `			      PROTECTED_SACL_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L03420 [NONE] `			      UNPROTECTED_SACL_SECINFO))`
  Review: Low-risk line; verify in surrounding control flow.
- L03421 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03423 [NONE] `	rc = set_info_sec(fp->conn, fp->tcon, &fp->filp->f_path, pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L03424 [NONE] `			  buf_len, false, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L03425 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L03426 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03428 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03429 [NONE] `	 * Only grant FILE_SHARE_DELETE when the DACL was actually changed,`
  Review: Low-risk line; verify in surrounding control flow.
- L03430 [NONE] `	 * to avoid unintended side-effects on share access from other`
  Review: Low-risk line; verify in surrounding control flow.
- L03431 [NONE] `	 * security descriptor operations (e.g. owner/SACL-only changes).`
  Review: Low-risk line; verify in surrounding control flow.
- L03432 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03433 [NONE] `	if (addition_info & DACL_SECINFO)`
  Review: Low-risk line; verify in surrounding control flow.
- L03434 [NONE] `		fp->saccess |= FILE_SHARE_DELETE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L03435 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03436 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03438 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03439 [NONE] ` * smb2_set_info() - handler for smb2 set info command handler`
  Review: Low-risk line; verify in surrounding control flow.
- L03440 [NONE] ` * @work:	smb work containing set info request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L03441 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03442 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03443 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03444 [NONE] `int smb2_set_info(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L03445 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03446 [NONE] `	struct smb2_set_info_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L03447 [NONE] `	struct smb2_set_info_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L03448 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03449 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03450 [NONE] `	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L03451 [NONE] `	char *set_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03452 [NONE] `	unsigned int set_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03453 [NONE] `	unsigned int consumed_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03455 [NONE] `	ksmbd_debug(SMB, "Received smb2 set info request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03457 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03458 [NONE] `		req = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L03459 [NONE] `		rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L03460 [NONE] `		if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03461 [NONE] `			ksmbd_debug(SMB, "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L03462 [NONE] `				    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L03463 [NONE] `			id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L03464 [NONE] `			pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L03465 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03466 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03467 [NONE] `		req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L03468 [NONE] `		rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L03469 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03471 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03472 [NONE] `	 * Validate that BufferOffset + BufferLength from the client`
  Review: Low-risk line; verify in surrounding control flow.
- L03473 [NONE] `	 * does not exceed the actual request buffer, preventing`
  Review: Low-risk line; verify in surrounding control flow.
- L03474 [NONE] `	 * out-of-bounds reads from crafted packets.`
  Review: Low-risk line; verify in surrounding control flow.
- L03475 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03476 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03477 [NONE] `		unsigned int buf_off = le16_to_cpu(req->BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03478 [NONE] `		unsigned int buf_len = le32_to_cpu(req->BufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L03479 [NONE] `		unsigned int rfc_len = get_rfc1002_len(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L03480 [NONE] `		unsigned int req_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03482 [NONE] `		/* Guard against underflow in compound requests */`
  Review: Low-risk line; verify in surrounding control flow.
- L03483 [NONE] `		if (rfc_len < work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03484 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03485 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03486 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03487 [NONE] `		req_len = rfc_len - work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L03488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03489 [NONE] `		if (buf_off < offsetof(struct smb2_set_info_req, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L03490 [NONE] `		    buf_off > req_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L03491 [NONE] `		    buf_len > req_len - buf_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03492 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03493 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03494 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03495 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03497 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03498 [NONE] `		ksmbd_debug(SMB, "User does not have write permission\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03499 [ERROR_PATH|] `		pr_err("User does not have write permission\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03500 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L03501 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03502 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03504 [NONE] `	if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03505 [NONE] `		id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L03506 [NONE] `		pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L03507 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03509 [NONE] `	fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L03510 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03511 [NONE] `		ksmbd_debug(SMB, "Invalid id for close: %u\n", id);`
  Review: Low-risk line; verify in surrounding control flow.
- L03512 [NONE] `		rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L03513 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03514 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03516 [NONE] `	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence */`
  Review: Low-risk line; verify in surrounding control flow.
- L03517 [NONE] `	if (smb2_check_channel_sequence(work, fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03518 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03519 [NONE] `		rc = -EAGAIN;`
  Review: Low-risk line; verify in surrounding control flow.
- L03520 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03521 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03523 [NONE] `	set_buf = (char *)req + le16_to_cpu(req->BufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03524 [NONE] `	set_buf_len = le32_to_cpu(req->BufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L03525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03526 [NONE] `	switch (req->InfoType) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03527 [PROTO_GATE|] `	case SMB2_O_INFO_FILE:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03528 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILE\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03529 [NONE] `		if (ksmbd_override_fsids(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03530 [NONE] `			rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L03531 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03532 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03533 [NONE] `		rc = smb2_set_info_file(work, fp, req, work->tcon->share_conf);`
  Review: Low-risk line; verify in surrounding control flow.
- L03534 [NONE] `		ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L03535 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03536 [PROTO_GATE|] `	case SMB2_O_INFO_FILESYSTEM:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03537 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_FILESYSTEM\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03538 [NONE] `		rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03539 [PROTO_GATE|] `					 SMB2_O_INFO_FILESYSTEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03540 [NONE] `					 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L03541 [NONE] `					 KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L03542 [NONE] `					 set_buf, set_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03543 [NONE] `					 &consumed_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03544 [NONE] `		if (!rc && consumed_len > set_buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03545 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03546 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03547 [PROTO_GATE|] `	case SMB2_O_INFO_SECURITY:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03548 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_SECURITY\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03549 [NONE] `		rc = smb2_set_info_sec(fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03550 [NONE] `				       le32_to_cpu(req->AdditionalInformation),`
  Review: Low-risk line; verify in surrounding control flow.
- L03551 [NONE] `				       set_buf, set_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03552 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03553 [PROTO_GATE|] `	case SMB2_O_INFO_QUOTA:`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03554 [PROTO_GATE|] `		ksmbd_debug(SMB, "GOT SMB2_O_INFO_QUOTA\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03555 [NONE] `		rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03556 [PROTO_GATE|] `					 SMB2_O_INFO_QUOTA,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03557 [NONE] `					 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L03558 [NONE] `					 KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L03559 [NONE] `					 set_buf, set_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03560 [NONE] `					 &consumed_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03561 [NONE] `		if (!rc && consumed_len > set_buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03562 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03563 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03564 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L03565 [NONE] `		/* Validate InfoType range before dispatching to hooks */`
  Review: Low-risk line; verify in surrounding control flow.
- L03566 [PROTO_GATE|] `		if (req->InfoType < SMB2_O_INFO_FILE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03567 [PROTO_GATE|] `		    req->InfoType > SMB2_O_INFO_QUOTA) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03568 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03569 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03570 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03571 [NONE] `		rc = ksmbd_dispatch_info(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03572 [NONE] `					 req->InfoType,`
  Review: Low-risk line; verify in surrounding control flow.
- L03573 [NONE] `					 req->FileInfoClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L03574 [NONE] `					 KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L03575 [NONE] `					 set_buf, set_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03576 [NONE] `					 &consumed_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L03577 [NONE] `		if (!rc && consumed_len > set_buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03578 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03579 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03580 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03581 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03582 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03583 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03584 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03585 [NONE] `	 * After a successful SET_INFO on a child file, break the parent`
  Review: Low-risk line; verify in surrounding control flow.
- L03586 [NONE] `	 * directory lease.  Per MS-SMB2 3.3.4.7, modifying a child file's`
  Review: Low-risk line; verify in surrounding control flow.
- L03587 [NONE] `	 * attributes (timestamps, size, rename, etc.) invalidates the`
  Review: Low-risk line; verify in surrounding control flow.
- L03588 [NONE] `	 * parent directory's cached view.`
  Review: Low-risk line; verify in surrounding control flow.
- L03589 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03590 [NONE] `	if (!S_ISDIR(file_inode(fp->filp)->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L03591 [NONE] `		smb_break_parent_dir_lease(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03592 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03593 [NONE] `	rsp->StructureSize = cpu_to_le16(2);`
  Review: Low-risk line; verify in surrounding control flow.
- L03594 [NONE] `	rc = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03595 [NONE] `			       sizeof(struct smb2_set_info_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L03596 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L03597 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03598 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03599 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03601 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03602 [NONE] `	if (rc == -EACCES || rc == -EPERM || rc == -EXDEV)`
  Review: Low-risk line; verify in surrounding control flow.
- L03603 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03604 [NONE] `	else if (rc == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L03605 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03606 [NONE] `	else if (rc == -EMSGSIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L03607 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INFO_LENGTH_MISMATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03608 [NONE] `	else if (rc == -ESHARE)`
  Review: Low-risk line; verify in surrounding control flow.
- L03609 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_SHARING_VIOLATION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03610 [NONE] `	else if (rc == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L03611 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_OBJECT_NAME_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03612 [NONE] `	else if (rc == -EBUSY || rc == -ENOTEMPTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L03613 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_DIRECTORY_NOT_EMPTY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03614 [NONE] `	else if (rc == -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L03615 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03616 [NONE] `	else if (rc == -EBADF || rc == -ESTALE)`
  Review: Low-risk line; verify in surrounding control flow.
- L03617 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03618 [NONE] `	else if (rc == -EROFS)`
  Review: Low-risk line; verify in surrounding control flow.
- L03619 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_CANNOT_DELETE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03620 [NONE] `	else if (rc == -EEXIST)`
  Review: Low-risk line; verify in surrounding control flow.
- L03621 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03622 [NONE] `	else if (rsp->hdr.Status == 0 || rc == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L03623 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03624 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L03625 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03626 [NONE] `	ksmbd_debug(SMB, "error while processing smb2 query rc = %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L03627 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03628 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03630 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03631 [NONE] ` * smb2_read_pipe() - handler for smb2 read from IPC pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L03632 [NONE] ` * @work:	smb work containing read IPC pipe command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L03633 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03634 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03635 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
