# Line-by-line Review: src/protocol/smb2/smb2ops.c

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
- L00007 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "ksmbd_dfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `static struct smb_version_values smb20_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `	.version_string = SMB20_VERSION_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	.protocol_id = SMB20_PROT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	.capabilities = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	.max_read_size = CIFS_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	.max_write_size = CIFS_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	.max_trans_size = CIFS_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00025 [NONE] `	.large_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [PROTO_GATE|] `	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00027 [PROTO_GATE|] `	.shared_lock_type = SMB2_LOCKFLAG_SHARED,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00028 [PROTO_GATE|] `	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [NONE] `	.header_size = sizeof(struct smb2_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [PROTO_GATE|] `	.max_header_size = MAX_SMB2_HDR_SIZE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00031 [NONE] `	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [PROTO_GATE|] `	.lock_cmd = SMB2_LOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00033 [NONE] `	.cap_unix = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [PROTO_GATE|] `	.cap_nt_find = SMB2_NT_FIND,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [PROTO_GATE|] `	.cap_large_files = SMB2_LARGE_FILES,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00036 [NONE] `	.create_lease_size = sizeof(struct create_lease),`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	.create_durable_size = sizeof(struct create_durable_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	.create_mxac_size = sizeof(struct create_mxac_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	.create_disk_id_size = sizeof(struct create_disk_id_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	.create_posix_size = sizeof(struct create_posix_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `static struct smb_version_values smb21_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	.version_string = SMB21_VERSION_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	.protocol_id = SMB21_PROT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [PROTO_GATE|] `	.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00047 [NONE] `	.max_read_size = SMB21_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	.max_write_size = SMB21_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	.max_trans_size = SMB21_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [NONE] `	.large_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [PROTO_GATE|] `	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `	.shared_lock_type = SMB2_LOCKFLAG_SHARED,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [NONE] `	.header_size = sizeof(struct smb2_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [PROTO_GATE|] `	.max_header_size = MAX_SMB2_HDR_SIZE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [NONE] `	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [PROTO_GATE|] `	.lock_cmd = SMB2_LOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [NONE] `	.cap_unix = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [PROTO_GATE|] `	.cap_nt_find = SMB2_NT_FIND,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `	.cap_large_files = SMB2_LARGE_FILES,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [NONE] `	.create_lease_size = sizeof(struct create_lease),`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	.create_durable_size = sizeof(struct create_durable_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	.create_mxac_size = sizeof(struct create_mxac_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	.create_disk_id_size = sizeof(struct create_disk_id_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	.create_posix_size = sizeof(struct create_posix_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `static struct smb_version_values smb30_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	.version_string = SMB30_VERSION_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	.protocol_id = SMB30_PROT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [PROTO_GATE|] `	.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [NONE] `	.max_read_size = SMB3_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	.max_write_size = SMB3_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	.max_trans_size = SMB3_DEFAULT_TRANS_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00077 [NONE] `	.large_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [PROTO_GATE|] `	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [PROTO_GATE|] `	.shared_lock_type = SMB2_LOCKFLAG_SHARED,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00080 [PROTO_GATE|] `	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00081 [NONE] `	.header_size = sizeof(struct smb2_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [PROTO_GATE|] `	.max_header_size = MAX_SMB2_HDR_SIZE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [NONE] `	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [PROTO_GATE|] `	.lock_cmd = SMB2_LOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [NONE] `	.cap_unix = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [PROTO_GATE|] `	.cap_nt_find = SMB2_NT_FIND,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [PROTO_GATE|] `	.cap_large_files = SMB2_LARGE_FILES,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00088 [NONE] `	.create_lease_size = sizeof(struct create_lease_v2),`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	.create_durable_size = sizeof(struct create_durable_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	.create_durable_v2_size = sizeof(struct create_durable_v2_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	.create_mxac_size = sizeof(struct create_mxac_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	.create_disk_id_size = sizeof(struct create_disk_id_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	.create_posix_size = sizeof(struct create_posix_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `static struct smb_version_values smb302_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	.version_string = SMB302_VERSION_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	.protocol_id = SMB302_PROT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [PROTO_GATE|] `	.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00100 [NONE] `	.max_read_size = SMB3_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	.max_write_size = SMB3_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	.max_trans_size = SMB3_DEFAULT_TRANS_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00104 [NONE] `	.large_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [PROTO_GATE|] `	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00106 [PROTO_GATE|] `	.shared_lock_type = SMB2_LOCKFLAG_SHARED,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00107 [PROTO_GATE|] `	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00108 [NONE] `	.header_size = sizeof(struct smb2_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [PROTO_GATE|] `	.max_header_size = MAX_SMB2_HDR_SIZE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00110 [NONE] `	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [PROTO_GATE|] `	.lock_cmd = SMB2_LOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00112 [NONE] `	.cap_unix = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [PROTO_GATE|] `	.cap_nt_find = SMB2_NT_FIND,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00114 [PROTO_GATE|] `	.cap_large_files = SMB2_LARGE_FILES,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00115 [NONE] `	.create_lease_size = sizeof(struct create_lease_v2),`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	.create_durable_size = sizeof(struct create_durable_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	.create_durable_v2_size = sizeof(struct create_durable_v2_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	.create_mxac_size = sizeof(struct create_mxac_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	.create_disk_id_size = sizeof(struct create_disk_id_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	.create_posix_size = sizeof(struct create_posix_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `static struct smb_version_values smb311_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	.version_string = SMB311_VERSION_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	.protocol_id = SMB311_PROT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	/* Advertise server-to-client notification support (MS-SMB2 §2.2.4) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [PROTO_GATE|] `	.capabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_NOTIFICATIONS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00128 [NONE] `	.max_read_size = SMB3_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	.max_write_size = SMB3_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	.max_trans_size = SMB3_DEFAULT_TRANS_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00132 [NONE] `	.large_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [PROTO_GATE|] `	.exclusive_lock_type = SMB2_LOCKFLAG_EXCLUSIVE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00134 [PROTO_GATE|] `	.shared_lock_type = SMB2_LOCKFLAG_SHARED,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00135 [PROTO_GATE|] `	.unlock_lock_type = SMB2_LOCKFLAG_UNLOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [NONE] `	.header_size = sizeof(struct smb2_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [PROTO_GATE|] `	.max_header_size = MAX_SMB2_HDR_SIZE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00138 [NONE] `	.read_rsp_size = sizeof(struct smb2_read_rsp) - 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [PROTO_GATE|] `	.lock_cmd = SMB2_LOCK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00140 [NONE] `	.cap_unix = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [PROTO_GATE|] `	.cap_nt_find = SMB2_NT_FIND,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00142 [PROTO_GATE|] `	.cap_large_files = SMB2_LARGE_FILES,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00143 [NONE] `	.create_lease_size = sizeof(struct create_lease_v2),`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	.create_durable_size = sizeof(struct create_durable_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	.create_durable_v2_size = sizeof(struct create_durable_v2_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	.create_mxac_size = sizeof(struct create_mxac_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	.create_disk_id_size = sizeof(struct create_disk_id_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	.create_posix_size = sizeof(struct create_posix_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `static struct smb_version_ops smb2_0_server_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	.get_cmd_val		=	get_smb2_cmd_val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	.init_rsp_hdr		=	init_smb2_rsp_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	.set_rsp_status		=	set_smb2_rsp_status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	.allocate_rsp_buf       =       smb2_allocate_rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	.set_rsp_credits	=	smb2_set_rsp_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	.check_user_session	=	smb2_check_user_session,`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	.get_ksmbd_tcon		=	smb2_get_ksmbd_tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	.is_sign_req		=	smb2_is_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	.check_sign_req		=	smb2_check_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	.set_sign_rsp		=	smb2_set_sign_rsp`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `static struct smb_version_ops smb3_0_server_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	.get_cmd_val		=	get_smb2_cmd_val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	.init_rsp_hdr		=	init_smb2_rsp_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	.set_rsp_status		=	set_smb2_rsp_status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	.allocate_rsp_buf       =       smb2_allocate_rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	.set_rsp_credits	=	smb2_set_rsp_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	.check_user_session	=	smb2_check_user_session,`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	.get_ksmbd_tcon		=	smb2_get_ksmbd_tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	.is_sign_req		=	smb2_is_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	.check_sign_req		=	smb3_check_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	.set_sign_rsp		=	smb3_set_sign_rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	.generate_signingkey	=	ksmbd_gen_smb30_signingkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	.generate_encryptionkey	=	ksmbd_gen_smb30_encryptionkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	.is_transform_hdr	=	smb3_is_transform_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	.decrypt_req		=	smb3_decrypt_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	.encrypt_resp		=	smb3_encrypt_resp`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `static struct smb_version_ops smb3_11_server_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	.get_cmd_val		=	get_smb2_cmd_val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	.init_rsp_hdr		=	init_smb2_rsp_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	.set_rsp_status		=	set_smb2_rsp_status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	.allocate_rsp_buf       =       smb2_allocate_rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	.set_rsp_credits	=	smb2_set_rsp_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	.check_user_session	=	smb2_check_user_session,`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	.get_ksmbd_tcon		=	smb2_get_ksmbd_tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	.is_sign_req		=	smb2_is_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	.check_sign_req		=	smb3_check_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	.set_sign_rsp		=	smb3_set_sign_rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	.generate_signingkey	=	ksmbd_gen_smb311_signingkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	.generate_encryptionkey	=	ksmbd_gen_smb311_encryptionkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	.is_transform_hdr	=	smb3_is_transform_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	.decrypt_req		=	smb3_decrypt_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	.encrypt_resp		=	smb3_encrypt_resp`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [PROTO_GATE|] `static struct smb_version_cmds smb2_0_server_cmds[NUMBER_OF_SMB2_COMMANDS] = {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00201 [PROTO_GATE|] `	[SMB2_NEGOTIATE_HE]	=	{ .proc = smb2_negotiate_request, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00202 [PROTO_GATE|] `	[SMB2_SESSION_SETUP_HE] =	{ .proc = smb2_sess_setup, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00203 [PROTO_GATE|] `	[SMB2_TREE_CONNECT_HE]  =	{ .proc = smb2_tree_connect,},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00204 [PROTO_GATE|] `	[SMB2_TREE_DISCONNECT_HE]  =	{ .proc = smb2_tree_disconnect,},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00205 [PROTO_GATE|] `	[SMB2_LOGOFF_HE]	=	{ .proc = smb2_session_logoff,},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00206 [PROTO_GATE|] `	[SMB2_CREATE_HE]	=	{ .proc = smb2_open},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00207 [PROTO_GATE|] `	[SMB2_QUERY_INFO_HE]	=	{ .proc = smb2_query_info},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00208 [PROTO_GATE|] `	[SMB2_QUERY_DIRECTORY_HE] =	{ .proc = smb2_query_dir},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00209 [PROTO_GATE|] `	[SMB2_CLOSE_HE]		=	{ .proc = smb2_close},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00210 [PROTO_GATE|] `	[SMB2_ECHO_HE]		=	{ .proc = smb2_echo},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00211 [PROTO_GATE|] `	[SMB2_SET_INFO_HE]      =       { .proc = smb2_set_info},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00212 [PROTO_GATE|] `	[SMB2_READ_HE]		=	{ .proc = smb2_read},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00213 [PROTO_GATE|] `	[SMB2_WRITE_HE]		=	{ .proc = smb2_write},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00214 [PROTO_GATE|] `	[SMB2_FLUSH_HE]		=	{ .proc = smb2_flush},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00215 [PROTO_GATE|] `	[SMB2_CANCEL_HE]	=	{ .proc = smb2_cancel},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [PROTO_GATE|] `	[SMB2_LOCK_HE]		=	{ .proc = smb2_lock},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00217 [PROTO_GATE|] `	[SMB2_IOCTL_HE]		=	{ .proc = smb2_ioctl},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00218 [PROTO_GATE|] `	[SMB2_OPLOCK_BREAK_HE]	=	{ .proc = smb2_oplock_break},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00219 [PROTO_GATE|] `	[SMB2_CHANGE_NOTIFY_HE]	=	{ .proc = smb2_notify},`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00220 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` * init_smb2_0_server() - initialize a smb server connection with smb2.0`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` *			command dispatcher`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `int init_smb2_0_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	conn->vals = kmemdup(&smb20_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `			     sizeof(smb20_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	conn->ops = &smb2_0_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	conn->cmds = smb2_0_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb2_0_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	conn->signing_algorithm = SIGNING_ALG_HMAC_SHA256;`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ` * init_smb2_1_server() - initialize a smb server connection with smb2.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ` *			command dispatcher`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `int init_smb2_1_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	conn->vals = kmemdup(&smb21_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `			     sizeof(smb21_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	conn->ops = &smb2_0_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	conn->cmds = smb2_0_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb2_0_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	conn->signing_algorithm = SIGNING_ALG_HMAC_SHA256;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_LEASES)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00259 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_LEASING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	if (ksmbd_dfs_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_DFS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` * init_smb3_0_server() - initialize a smb server connection with smb3.0`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ` *			command dispatcher`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `int init_smb3_0_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	conn->vals = kmemdup(&smb30_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `			     sizeof(smb30_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	conn->ops = &smb3_0_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	conn->cmds = smb2_0_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb2_0_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	conn->signing_algorithm = SIGNING_ALG_AES_CMAC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_LEASES)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00285 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_LEASING |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00286 [PROTO_GATE|] `			SMB2_GLOBAL_CAP_DIRECTORY_LEASING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00289 [PROTO_GATE|] `	    (!(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00290 [PROTO_GATE|] `	     conn->cli_cap & SMB2_GLOBAL_CAP_ENCRYPTION))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00291 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_MULTI_CHANNEL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00295 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	if (ksmbd_dfs_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_DFS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` * init_smb3_02_server() - initialize a smb server connection with smb3.02`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ` *			command dispatcher`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `int init_smb3_02_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	conn->vals = kmemdup(&smb302_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `			     sizeof(smb302_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	conn->ops = &smb3_0_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	conn->cmds = smb2_0_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb2_0_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	conn->signing_algorithm = SIGNING_ALG_AES_CMAC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_LEASES)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00320 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_LEASING |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00321 [PROTO_GATE|] `			SMB2_GLOBAL_CAP_DIRECTORY_LEASING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00324 [PROTO_GATE|] `	    (!(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00325 [PROTO_GATE|] `	     conn->cli_cap & SMB2_GLOBAL_CAP_ENCRYPTION))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00326 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_MULTI_CHANNEL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_PERSISTENT_HANDLES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	if (ksmbd_dfs_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_DFS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * init_smb3_11_server() - initialize a smb server connection with smb3.11`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` *			command dispatcher`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `int init_smb3_11_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	conn->vals = kmemdup(&smb311_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `			     sizeof(smb311_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	conn->ops = &smb3_11_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	conn->cmds = smb2_0_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb2_0_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	 * For SMB 3.1.1, the signing algorithm is negotiated via the`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [PROTO_GATE|] `	 * SMB2_SIGNING_CAPABILITIES context which is decoded before this`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00358 [NONE] `	 * function runs.  Only set the default AES-CMAC if the client did`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	 * not include a signing capabilities context.`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	if (!conn->signing_negotiated)`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		conn->signing_algorithm = SIGNING_ALG_AES_CMAC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [PROTO_GATE|] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_LEASES)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00365 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_LEASING |`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00366 [PROTO_GATE|] `			SMB2_GLOBAL_CAP_DIRECTORY_LEASING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_MULTI_CHANNEL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_PERSISTENT_HANDLES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	if (ksmbd_dfs_enabled())`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_DFS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [PROTO_GATE|] `	 * B.5: MS-SMB2 §2.2.4 — SMB2_GLOBAL_CAP_ENCRYPTION (0x0040) should`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [NONE] `	 * also be advertised for SMB 3.1.1 for compatibility with strict`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	 * clients that check the capability bit before offering encryption`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	 * contexts.  For 3.1.1 the actual cipher negotiation uses negotiate`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	 * contexts, but some Windows clients check this bit first.`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [PROTO_GATE|] `	if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00385 [PROTO_GATE|] `		conn->vals->capabilities |= SMB2_GLOBAL_CAP_ENCRYPTION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	INIT_LIST_HEAD(&conn->preauth_sess_table);`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `void init_smb2_max_read_size(unsigned int sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	sz = clamp_val(sz, SMB3_MIN_IOSIZE, SMB3_MAX_IOSIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	smb21_server_values.max_read_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	smb30_server_values.max_read_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	smb302_server_values.max_read_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	smb311_server_values.max_read_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `void init_smb2_max_write_size(unsigned int sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `	sz = clamp_val(sz, SMB3_MIN_IOSIZE, SMB3_MAX_IOSIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	smb21_server_values.max_write_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	smb30_server_values.max_write_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	smb302_server_values.max_write_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	smb311_server_values.max_write_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `void init_smb2_max_trans_size(unsigned int sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	sz = clamp_val(sz, SMB3_MIN_IOSIZE, SMB3_MAX_IOSIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	smb21_server_values.max_trans_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	smb30_server_values.max_trans_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	smb302_server_values.max_trans_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	smb311_server_values.max_trans_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `void init_smb2_max_credits(unsigned int sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	if (sz < 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [ERROR_PATH|] `		pr_warn("Invalid max credits value %u, setting to 1\n", sz);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00422 [NONE] `		sz = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	smb21_server_values.max_credits = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	smb30_server_values.max_credits = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	smb302_server_values.max_credits = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	smb311_server_values.max_credits = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
