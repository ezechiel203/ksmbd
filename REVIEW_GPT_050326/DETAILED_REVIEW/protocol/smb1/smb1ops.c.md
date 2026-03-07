# Line-by-line Review: src/protocol/smb1/smb1ops.c

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
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "smb1pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `static struct smb_version_values smb1_server_values = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `	.version_string = SMB1_VERSION_STRING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `	.protocol_id = SMB10_PROT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	.capabilities = SMB1_SERVER_CAPS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `	.max_read_size = CIFS_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	.max_write_size = MAX_STREAM_PROT_LEN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `	.max_trans_size = CIFS_DEFAULT_IOSIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	.large_lock_type = LOCKING_ANDX_LARGE_FILES,`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	.exclusive_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	.shared_lock_type = LOCKING_ANDX_SHARED_LOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	.unlock_lock_type = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	.header_size = sizeof(struct smb_hdr),`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	.max_header_size = MAX_CIFS_HDR_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	.read_rsp_size = sizeof(struct smb_com_read_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [PROTO_GATE|] `	.lock_cmd = cpu_to_le16(SMB_COM_LOCKING_ANDX),`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00029 [NONE] `	.cap_unix = CAP_UNIX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	.cap_nt_find = CAP_NT_SMBS | CAP_NT_FIND,`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	.cap_large_files = CAP_LARGE_FILES,`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	.signing_enabled = SECMODE_SIGN_ENABLED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	.signing_required = SECMODE_SIGN_REQUIRED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [PROTO_GATE|] `	.max_credits = SMB2_MAX_CREDITS,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `static struct smb_version_ops smb1_server_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	.get_cmd_val = get_smb_cmd_val,`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	.init_rsp_hdr = init_smb_rsp_hdr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	.set_rsp_status = set_smb_rsp_status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	.allocate_rsp_buf = smb_allocate_rsp_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	.check_user_session = smb_check_user_session,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	.is_sign_req = smb1_is_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	.check_sign_req = smb1_check_sign_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	.set_sign_rsp = smb1_set_sign_rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	.get_ksmbd_tcon = smb_get_ksmbd_tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `static struct smb_version_cmds smb1_server_cmds[256] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [PROTO_GATE|] `	[SMB_COM_CREATE_DIRECTORY]	= { .proc = smb_mkdir, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00051 [PROTO_GATE|] `	[SMB_COM_DELETE_DIRECTORY]	= { .proc = smb_rmdir, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [PROTO_GATE|] `	[SMB_COM_CLOSE]			= { .proc = smb_close, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [PROTO_GATE|] `	[SMB_COM_FLUSH]			= { .proc = smb_flush, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [PROTO_GATE|] `	[SMB_COM_DELETE]		= { .proc = smb_unlink, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00055 [PROTO_GATE|] `	[SMB_COM_RENAME]		= { .proc = smb_rename, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00056 [PROTO_GATE|] `	[SMB_COM_QUERY_INFORMATION]	= { .proc = smb_query_info, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00057 [PROTO_GATE|] `	[SMB_COM_SETATTR]		= { .proc = smb_setattr, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00058 [PROTO_GATE|] `	[SMB_COM_LOCKING_ANDX]		= { .proc = smb_locking_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [PROTO_GATE|] `	[SMB_COM_TRANSACTION]		= { .proc = smb_trans, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00060 [PROTO_GATE|] `	[SMB_COM_ECHO]			= { .proc = smb_echo, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00061 [PROTO_GATE|] `	[SMB_COM_OPEN_ANDX]		= { .proc = smb_open_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00062 [PROTO_GATE|] `	[SMB_COM_READ_ANDX]		= { .proc = smb_read_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00063 [PROTO_GATE|] `	[SMB_COM_WRITE_ANDX]		= { .proc = smb_write_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00064 [PROTO_GATE|] `	[SMB_COM_TRANSACTION2]		= { .proc = smb_trans2, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00065 [PROTO_GATE|] `	[SMB_COM_FIND_CLOSE2]		= { .proc = smb_closedir, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00066 [PROTO_GATE|] `	[SMB_COM_TREE_DISCONNECT]	= { .proc = smb_tree_disconnect, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [PROTO_GATE|] `	[SMB_COM_NEGOTIATE]		= { .proc = smb_negotiate_request, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00068 [PROTO_GATE|] `	[SMB_COM_SESSION_SETUP_ANDX]	= { .proc = smb_session_setup_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00069 [PROTO_GATE|] `	[SMB_COM_LOGOFF_ANDX]           = { .proc = smb_session_disconnect, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00070 [PROTO_GATE|] `	[SMB_COM_TREE_CONNECT_ANDX]	= { .proc = smb_tree_connect_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00071 [PROTO_GATE|] `	[SMB_COM_QUERY_INFORMATION_DISK] = { .proc = smb_query_information_disk, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [PROTO_GATE|] `	[SMB_COM_NT_TRANSACT]		= { .proc = smb_nt_transact, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00073 [PROTO_GATE|] `	[SMB_COM_NT_TRANSACT_SECONDARY]	= { .proc = smb_nt_transact_secondary, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00074 [PROTO_GATE|] `	[SMB_COM_NT_CREATE_ANDX]	= { .proc = smb_nt_create_andx, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00075 [PROTO_GATE|] `	[SMB_COM_NT_CANCEL]		= { .proc = smb_nt_cancel, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [PROTO_GATE|] `	[SMB_COM_NT_RENAME]		= { .proc = smb_nt_rename, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00077 [PROTO_GATE|] `	[SMB_COM_WRITE]			= { .proc = smb_write, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00078 [PROTO_GATE|] `	[SMB_COM_CHECK_DIRECTORY]	= { .proc = smb_checkdir, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00079 [PROTO_GATE|] `	[SMB_COM_PROCESS_EXIT]		= { .proc = smb_process_exit, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00080 [NONE] `	/* A.2: QUERY_INFORMATION2 and SET_INFORMATION2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [PROTO_GATE|] `	[SMB_COM_QUERY_INFORMATION2]	= { .proc = smb_query_information2, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00082 [PROTO_GATE|] `	[SMB_COM_SET_INFORMATION2]	= { .proc = smb_set_information2, },`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00083 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ` * init_smb1_server() - initialize a smb server connection with smb1`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` *			command dispatcher`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `int init_smb1_server(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	conn->vals = kmemdup(&smb1_server_values,`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `			     sizeof(smb1_server_values), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	if (!conn->vals)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	conn->ops = &smb1_server_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	conn->cmds = smb1_server_cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	conn->max_cmds = ARRAY_SIZE(smb1_server_cmds);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	conn->smb1_conn = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
