# Line-by-line Review: src/core/server.c

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
- L00007 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/sched/signal.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/sysfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/moduleparam.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "crypto_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "ksmbd_dfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "ksmbd_reparse.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "ksmbd_resilient.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "ksmbd_quota.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "ksmbd_app_instance.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "ksmbd_rsvd.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "ksmbd_fsctl_extra.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "ksmbd_hooks.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "ksmbd_branchcache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "ksmbd_md4.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "mgmt/ksmbd_witness.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * ksmbd_debug_types is read from hot paths (ksmbd_debug() macro)`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * and written only from the sysfs debug_store handler.  A torn read`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * is benign -- it may briefly show stale debug flags -- so we`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [LIFETIME|] ` * deliberately avoid atomic_t / locking overhead here.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00050 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `int ksmbd_debug_types;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `struct ksmbd_server_config server_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `enum SERVER_CTRL_TYPE {`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	SERVER_CTRL_TYPE_INIT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	SERVER_CTRL_TYPE_RESET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `struct server_ctrl_struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	int			type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	struct work_struct	ctrl_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `static DEFINE_MUTEX(ctrl_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `static int ___server_conf_set(int idx, char *val)`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	if (idx >= ARRAY_SIZE(server_conf.conf))`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	if (!val || val[0] == 0x00)`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	kfree(server_conf.conf[idx]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	server_conf.conf[idx] = kstrdup(val, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	if (!server_conf.conf[idx])`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00079 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `int ksmbd_set_netbios_name(char *v)`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	return ___server_conf_set(SERVER_CONF_NETBIOS_NAME, v);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `int ksmbd_set_server_string(char *v)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	return ___server_conf_set(SERVER_CONF_SERVER_STRING, v);`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `int ksmbd_set_work_group(char *v)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	return ___server_conf_set(SERVER_CONF_WORK_GROUP, v);`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `char *ksmbd_netbios_name(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	return server_conf.conf[SERVER_CONF_NETBIOS_NAME];`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `char *ksmbd_server_string(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	return server_conf.conf[SERVER_CONF_SERVER_STRING];`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `char *ksmbd_work_group(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	return server_conf.conf[SERVER_CONF_WORK_GROUP];`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` * check_conn_state() - check state of server thread connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` * @work:     smb work containing server thread information`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * Return:	0 on valid connection, otherwise 1 to reconnect`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `static inline int check_conn_state(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	struct smb_hdr *rsp_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	if (ksmbd_conn_exiting(work->conn) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	    ksmbd_conn_need_reconnect(work->conn) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	    ksmbd_conn_releasing(work->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		rsp_hdr = work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [PROTO_GATE|] `		rsp_hdr->Status.CifsError = STATUS_CONNECTION_DISCONNECTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00127 [NONE] `		return 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `#define SERVER_HANDLER_CONTINUE		0`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `#define SERVER_HANDLER_ABORT		1`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `static int __process_request(struct ksmbd_work *work, struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `			     u16 *cmd)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	struct smb_version_cmds *cmds;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	u16 command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	if (check_conn_state(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		return SERVER_HANDLER_CONTINUE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	 * Per-command state used by SMB2 credit settlement.`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	 * Must be reset before message verification for each subcommand`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	 * in a compound request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	work->credit_charge_tracked = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	ret = ksmbd_verify_smb_message(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		 * Return code 2 = credit exhaustion (insufficient credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		 * to process the request).  Per MS-SMB2, the server SHOULD`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [PROTO_GATE|] `		 * return STATUS_INSUFFICIENT_RESOURCES.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00158 [NONE] `		 * Return code 1 = structural validation failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		__le32 err_status = (ret == 2) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [PROTO_GATE|] `			STATUS_INSUFFICIENT_RESOURCES :`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00162 [PROTO_GATE|] `			STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `			 * In a compound chain, set the error on the`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `			 * current response position without clobbering`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `			 * previous responses.  Continue processing so`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			 * that credits are granted and the chain`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			 * advances properly.`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `			struct smb2_hdr *rsp_hdr =`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `				ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `			rsp_hdr->Status = err_status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `			*cmd = get_smb2_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `			return SERVER_HANDLER_CONTINUE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		conn->ops->set_rsp_status(work, err_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		return SERVER_HANDLER_ABORT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	command = conn->ops->get_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	*cmd = command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `andx_again:`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	if (command >= conn->max_cmds) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [PROTO_GATE|] `		conn->ops->set_rsp_status(work, STATUS_INVALID_PARAMETER);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00190 [NONE] `		return SERVER_HANDLER_CONTINUE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	cmds = &conn->cmds[command];`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	if (!cmds->proc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		ksmbd_debug(SMB, "*** not implemented yet cmd = %x\n", command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [PROTO_GATE|] `		conn->ops->set_rsp_status(work, STATUS_NOT_IMPLEMENTED);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00197 [NONE] `		return SERVER_HANDLER_CONTINUE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	if (work->sess && conn->ops->is_sign_req(work, command)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `		ret = conn->ops->check_sign_req(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [PROTO_GATE|] `			conn->ops->set_rsp_status(work, STATUS_ACCESS_DENIED);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00204 [NONE] `			return SERVER_HANDLER_CONTINUE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	 * Re-check connection state right before dispatching.`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	 * A connection may have entered releasing state while`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	 * we were doing signature verification or other pre-dispatch`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	 * work above.`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	if (ksmbd_conn_releasing(work->conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [PROTO_GATE|] `		conn->ops->set_rsp_status(work, STATUS_CONNECTION_DISCONNECTED);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00216 [NONE] `		return SERVER_HANDLER_ABORT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		unsigned long cmd_start = jiffies;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		ret = cmds->proc(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		if (time_after(jiffies, cmd_start + 10 * HZ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [ERROR_PATH|] `			pr_warn("ksmbd: cmd 0x%x handler took %u ms (pid=%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00226 [NONE] `				command,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `				jiffies_to_msecs(jiffies - cmd_start),`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `				current->pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		ksmbd_debug(CONN, "Failed to process %u [%d]\n", command, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	/* AndX commands - chained request can return positive values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	else if (ret > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		command = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		*cmd = command;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [ERROR_PATH|] `		goto andx_again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00238 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	if (work->send_no_response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		return SERVER_HANDLER_ABORT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	return SERVER_HANDLER_CONTINUE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `static bool __handle_ksmbd_work(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `				struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	u16 command = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	bool is_chained = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	 * Handle compressed requests: decompress before any other`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	 * processing. After decompression, the request buffer contains`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	 * a standard SMB2 message (or an encrypted transform message`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	 * that was compressed).`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	if (smb2_is_compression_transform_hdr(work->request_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		rc = smb2_decompress_req(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	if (conn->ops->is_transform_hdr &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	    conn->ops->is_transform_hdr(work->request_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		rc = conn->ops->decrypt_req(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		work->encrypted = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	if (conn->ops->allocate_rsp_buf(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	rc = conn->ops->init_rsp_hdr(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		/* either uid or tid is not correct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [PROTO_GATE|] `		conn->ops->set_rsp_status(work, STATUS_INVALID_HANDLE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00279 [ERROR_PATH|] `		goto send;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00280 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		 * If the connection is shutting down, break out of`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		 * the compound processing loop immediately.  This`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		 * handles the case where a kworker entered`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		 * __handle_ksmbd_work before the connection was set`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		 * to releasing, and releasing was set mid-processing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `		if (ksmbd_conn_releasing(conn) || !ksmbd_conn_alive(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		 * Compound error propagation per MS-SMB2 3.3.5.2.3:`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		 * When a CREATE in a related compound chain fails, all`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `		 * subsequent related operations MUST return the same`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `		 * error status (the compound handle was never`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `		 * established, so nothing can operate on it).`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `		 * However, if a valid compound file handle exists`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `		 * (established by a prior successful CREATE),`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `		 * intermediate operation failures (e.g. WRITE`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `		 * returning ACCESS_DENIED on a read-only handle) MUST`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `		 * NOT be propagated -- the handle is still valid and`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `		 * subsequent operations should execute independently.`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `		 * Errors from non-CREATE operations (e.g. READ`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		 * returning END_OF_FILE) are also NOT propagated; the`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `		 * next related request gets its own validation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `			struct smb2_hdr *req_hdr = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [PROTO_GATE|] `			if (req_hdr->Flags & SMB2_FLAGS_RELATED_OPERATIONS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00316 [NONE] `				if (work->compound_err_status !=`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [PROTO_GATE|] `				    STATUS_SUCCESS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00318 [NONE] `					struct smb2_hdr *rsp_hdr =`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `						ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `					rsp_hdr->Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `						work->compound_err_status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `					smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `					command = get_smb2_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [ERROR_PATH|] `					goto compound_continue;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00326 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		if (conn->ops->check_user_session) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `			rc = conn->ops->check_user_session(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `			if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `				struct smb2_hdr *rsp_hdr =`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `					ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `				rsp_hdr->Status = (rc == -EINVAL) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [PROTO_GATE|] `					STATUS_INVALID_PARAMETER :`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00338 [PROTO_GATE|] `					STATUS_USER_SESSION_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00339 [NONE] `				smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `				command = get_smb2_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [ERROR_PATH|] `				goto compound_continue;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00342 [NONE] `			} else if (rc > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `				rc = conn->ops->get_ksmbd_tcon(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `					struct smb2_hdr *rsp_hdr =`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `						ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `					rsp_hdr->Status = (rc == -EINVAL) ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [PROTO_GATE|] `						STATUS_INVALID_PARAMETER :`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00350 [PROTO_GATE|] `						STATUS_NETWORK_NAME_DELETED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00351 [NONE] `					smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `					command = get_smb2_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [ERROR_PATH|] `					goto compound_continue;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00354 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		 * MS-SMB2 §3.3.5.2.5: If Session.EncryptData is TRUE and the`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `		 * request was not encrypted, the server MUST disconnect the`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `		 * connection (except for NEGOTIATE and SESSION_SETUP which`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		 * establish the encrypted channel).`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		 * Note: sess->enc is set whenever encryption keys are generated`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		 * (all SMB3 sessions); sess->enc_forced is set only when the`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [PROTO_GATE|] `		 * server actually set SMB2_SESSION_FLAG_ENCRYPT_DATA in the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00367 [NONE] `		 * SESSION_SETUP response (global flag or per-client request).`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		 * Only enforce when encryption was actually required.`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `		if (work->sess && work->sess->enc_forced && !work->encrypted) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `			command = get_smb2_cmd_val(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [PROTO_GATE|] `			if (command != SMB2_NEGOTIATE_HE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00373 [PROTO_GATE|] `			    command != SMB2_SESSION_SETUP_HE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00374 [NONE] `				struct smb2_hdr *rsp_hdr =`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `					ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [ERROR_PATH|] `				pr_warn_ratelimited("Unencrypted request (cmd=0x%x) on encrypted session, disconnecting [off=%d]\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00378 [NONE] `						    command, work->next_smb2_rcv_hdr_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [PROTO_GATE|] `				rsp_hdr->Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00380 [NONE] `				smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `				ksmbd_conn_set_exiting(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [ERROR_PATH|] `				goto compound_continue;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00383 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		rc = __process_request(work, conn, &command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		if (rc == SERVER_HANDLER_ABORT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `			 * Grant credits even on abort so the client does not`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `			 * deplete its credit budget.  This matters for scan /`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			 * probe traffic (e.g. smb2.scan) where unknown opcodes`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `			 * are rejected before validate_credit is reached; without`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `			 * this the per-request credit charge is never replenished`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `			 * and the client stalls with 0 available credits.`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `			 * smb2_set_rsp_credits() handles send_no_response`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			 * internally (early-returns 0), so it is safe to call`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `			 * unconditionally here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `			if (conn->ops->set_rsp_credits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `				conn->ops->set_rsp_credits(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `		 * Call smb2_set_rsp_credits() function to set number of credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		 * granted in hdr of smb2 response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		if (conn->ops->set_rsp_credits) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `				    "credit_rsp: dispatch cmd=%u total=%u out=%u granted_total=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `				    command, conn->total_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `				    conn->outstanding_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `				    work->credits_granted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `			rc = conn->ops->set_rsp_credits(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `			if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [ERROR_PATH|] `				pr_err_ratelimited("Failed to set credits for cmd %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00417 [NONE] `						   command);`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `compound_continue:`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		is_chained = is_chained_smb2_message(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		if (work->sess &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		    (work->sess->sign || smb3_11_final_sess_setup_resp(work) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		     conn->ops->is_sign_req(work, command)))`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `			conn->ops->set_sign_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	} while (is_chained == true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `send:`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	 * If the connection is shutting down, skip all post-processing`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	 * (signing, encryption, compression, write).  The transport and`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	 * session state may already be torn down by the connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	 * handler thread.  Accessing them would be use-after-free.`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	if (ksmbd_conn_releasing(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `		if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `			ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		if (work->tcon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `			ksmbd_tree_connect_put(work->tcon);`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `	if (work->tcon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		ksmbd_tree_connect_put(work->tcon);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	smb3_preauth_hash_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	 * In a compound request, smb2_check_user_session() releases`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `	 * work->sess when a non-related sub-request carries an invalid`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	 * session ID (e.g. smb2.compound.invalid2: CLOSEs with a fake`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	 * session in the middle of the chain).  If the original request`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	 * was encrypted we still need a valid session to encrypt the`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	 * compound response.  Re-fetch from the first SMB2 header's`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	 * SessionId, which is always the real session used to decrypt`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	 * the Transform packet.`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	if (work->encrypted && !work->sess && conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `		struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `		work->sess = ksmbd_session_lookup_all(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `						      le64_to_cpu(hdr->SessionId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		 * If the inner SMB2 header had an invalid session ID (e.g.`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `		 * smb2.tcon "invalid VUID" subtest), fall back to the session`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		 * that was used to decrypt the TRANSFORM header.  Without this`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		 * the server sends an unencrypted error response, causing the`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [PROTO_GATE|] `		 * client to disconnect (NT_STATUS_CONNECTION_DISCONNECTED).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00468 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `		if (!work->sess && work->tr_sess_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `			work->sess = ksmbd_session_lookup_all(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `							      work->tr_sess_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	 * Skip encrypt/compress for async pending work (send_no_response).`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	 * The response buffer is owned by the async subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	 * (e.g. CHANGE_NOTIFY) which will sign/encrypt/send it`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	 * when the operation completes or is cancelled.`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	 * Running encrypt_resp here would corrupt the IOV state`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	 * (allocate tr_buf, overwrite iov[0]) making the async`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	 * completion path fail.`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	if (!work->send_no_response) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `		if (work->sess && work->sess->enc && work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `		    conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `			rc = conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `			if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `				conn->ops->set_rsp_status(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [PROTO_GATE|] `							  STATUS_DATA_ERROR);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00489 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `			 * Compress the response if compression was negotiated`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `			 * and the response is not encrypted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `			smb2_compress_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	if (work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `		ksmbd_user_session_put(work->sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	 * For async pending work (CHANGE_NOTIFY), dequeue from the`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	 * synchronous request list NOW, while we still have a valid`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	 * reference to the work struct.  After this point, we must`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [PROTO_GATE|] `	 * NOT touch the work again -- a concurrent SMB2_CANCEL on`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00505 [NONE] `	 * another kworker may have already freed it (or will free`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	 * it the instant we release the request_lock).`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	 * We save pending_async in a local before dequeuing because`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	 * handle_ksmbd_work needs to know whether to free the work.`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	if (work->pending_async) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [LOCK|] `		spin_lock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00513 [NONE] `		list_del_init(&work->request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [LOCK|] `		spin_unlock(&conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00515 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `		 * Do NOT access 'work' after this point.`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `		 * ksmbd_conn_write is skipped because`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `		 * send_no_response was already set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ` * handle_ksmbd_work() - process pending smb work requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ` * @wk:	smb work containing request command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ` * called by kworker threads to processing remaining smb work requests`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `static void handle_ksmbd_work(struct work_struct *wk)`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	unsigned long start_jiffies = jiffies;`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	bool is_async;`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	 * If the connection is already shutting down, skip all`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	 * processing.  The transport may be torn down and accessing`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	 * it (e.g. via ksmbd_conn_write) would hang or crash.`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	if (ksmbd_conn_releasing(conn) || ksmbd_conn_exiting(conn)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `		ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		ksmbd_conn_r_count_dec(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		ksmbd_conn_free(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `		module_put(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	atomic64_inc(&conn->stats.request_served);`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	is_async = __handle_ksmbd_work(work, conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	if (time_after(jiffies, start_jiffies + 30 * HZ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [ERROR_PATH|] `		pr_warn_ratelimited("ksmbd: handle_ksmbd_work took %u ms\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00560 [NONE] `				    jiffies_to_msecs(jiffies - start_jiffies));`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	 * If __handle_ksmbd_work returned true (pending_async path),`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	 * it already dequeued the work from conn->requests and the`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	 * async subsystem now owns the work lifetime.  A concurrent`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [PROTO_GATE|] `	 * SMB2_CANCEL on another kworker may have already freed the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00567 [NONE] `	 * work, so we MUST NOT touch 'work' at all.  Just decrement`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	 * the connection reference count using our saved 'conn'.`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	 * For non-async work (returned false), the work is still`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	 * valid and we free it normally.`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	if (!is_async) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `		ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	ksmbd_conn_r_count_dec(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	 * Drop the per-work connection reference taken in`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	 * queue_ksmbd_work().  This may be the final reference`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	 * (if the handler thread already exited), triggering`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	 * connection cleanup.`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	ksmbd_conn_free(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	module_put(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ` * queue_ksmbd_work() - queue a smb request to worker thread queue`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ` *		for processing smb command and sending response`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ` * read remaining data from socket create and submit work.`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `static int queue_ksmbd_work(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	struct ksmbd_work *work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	err = ksmbd_init_smb_server(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	work = ksmbd_alloc_work_struct();`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	if (!work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [ERROR_PATH|] `		pr_err("allocation for work failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00607 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00608 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	work->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	 * Ownership transfer: the request buffer moves from the`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	 * connection to the work struct.  After this assignment,`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	 * conn->request_buf is set to NULL to indicate the connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	 * no longer owns the buffer.  The work struct (and ultimately`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `	 * ksmbd_free_work_struct()) is now responsible for freeing it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	 * This pattern must be maintained: every buffer must have`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	 * exactly one owner at any point in time.`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `	WARN_ON_ONCE(!conn->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	work->request_buf = conn->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	conn->request_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	ksmbd_conn_enqueue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	ksmbd_conn_r_count_inc(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `	 * Take a connection reference for the kworker.  This ensures`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `	 * the connection stays alive until the work item finishes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	 * even if the handler thread exits and drops its initial`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	 * reference in the meantime.  The matching ksmbd_conn_free()`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	 * is in handle_ksmbd_work().`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	 * Also take a module reference so rmmod cannot unload the`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	 * module while kworkers are still executing.  The matching`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	 * module_put() is in handle_ksmbd_work().`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [LIFETIME|] `	refcount_inc(&conn->refcnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00639 [NONE] `	__module_get(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	/* update activity on connection */`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	WRITE_ONCE(conn->last_active, jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `	INIT_WORK(&work->work, handle_ksmbd_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	ksmbd_queue_work(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `static int ksmbd_server_process_request(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	return queue_ksmbd_work(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `static int ksmbd_server_terminate_conn(struct ksmbd_conn *conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	ksmbd_sessions_deregister(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	destroy_lease_table(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `static void ksmbd_server_tcp_callbacks_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	struct ksmbd_conn_ops ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	ops.process_fn = ksmbd_server_process_request;`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	ops.terminate_fn = ksmbd_server_terminate_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	ksmbd_conn_init_server_callbacks(&ops);`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `static void server_conf_free(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	for (i = 0; i < ARRAY_SIZE(server_conf.conf); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		kfree(server_conf.conf[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `		server_conf.conf[i] = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `static int server_conf_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	WRITE_ONCE(server_conf.state, SERVER_STATE_STARTING_UP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	server_conf.min_protocol = ksmbd_min_protocol();`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	server_conf.max_protocol = ksmbd_max_protocol();`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	server_conf.auth_mechs = KSMBD_AUTH_NTLMSSP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `	server_conf.auth_mechs |= KSMBD_AUTH_KRB5 |`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `				KSMBD_AUTH_MSKRB5;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [PROTO_GATE|] `	server_conf.max_inflight_req = SMB2_MAX_CREDITS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00688 [NONE] `	server_conf.max_async_credits = 512;`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `static void server_ctrl_handle_init(struct server_ctrl_struct *ctrl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	ret = ksmbd_conn_transport_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `		server_queue_ctrl_reset_work();`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `	WRITE_ONCE(server_conf.state, SERVER_STATE_RUNNING);`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `static void server_ctrl_handle_reset(struct server_ctrl_struct *ctrl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	ksmbd_ipc_soft_reset();`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	 * Stop the durable scavenger BEFORE tearing down transports.`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	 * The scavenger thread holds a module reference; stopping it`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	 * first drops that ref so rmmod can proceed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	ksmbd_stop_durable_scavenger();`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	ksmbd_conn_transport_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	ksmbd_free_global_file_table();`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	server_conf_free();`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	server_conf_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	WRITE_ONCE(server_conf.state, SERVER_STATE_STARTING_UP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `static void server_ctrl_handle_work(struct work_struct *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	struct server_ctrl_struct *ctrl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	ctrl = container_of(work, struct server_ctrl_struct, ctrl_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [LOCK|] `	mutex_lock(&ctrl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00728 [NONE] `	switch (ctrl->type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	case SERVER_CTRL_TYPE_INIT:`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `		server_ctrl_handle_init(ctrl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	case SERVER_CTRL_TYPE_RESET:`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `		server_ctrl_handle_reset(ctrl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [ERROR_PATH|] `		pr_err("Unknown server work type: %d\n", ctrl->type);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00737 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [LOCK|] `	mutex_unlock(&ctrl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00739 [NONE] `	kfree(ctrl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `	module_put(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `static int __queue_ctrl_work(int type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	struct server_ctrl_struct *ctrl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [MEM_BOUNDS|] `	ctrl = kmalloc(sizeof(struct server_ctrl_struct), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00748 [NONE] `	if (!ctrl)`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	__module_get(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	ctrl->type = type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `	INIT_WORK(&ctrl->ctrl_work, server_ctrl_handle_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	queue_work(system_long_wq, &ctrl->ctrl_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `int server_queue_ctrl_init_work(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	return __queue_ctrl_work(SERVER_CTRL_TYPE_INIT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `int server_queue_ctrl_reset_work(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `	return __queue_ctrl_work(SERVER_CTRL_TYPE_RESET);`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `static ssize_t stats_show(const struct class *class, const struct class_attribute *attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `static ssize_t stats_show(struct class *class, struct class_attribute *attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `			  char *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	 * Inc this each time you change stats output format,`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	 * so user space will know what to do.`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	static int stats_version = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	static const char * const state[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `		"startup",`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `		"running",`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `		"reset",`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `		"shutdown"`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	unsigned int cur_state = READ_ONCE(server_conf.state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	if (cur_state >= ARRAY_SIZE(state))`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `		cur_state = SERVER_STATE_SHUTTING_DOWN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	return sysfs_emit(buf, "%d %s %d %lu\n", stats_version,`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `			  state[cur_state],`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `			  READ_ONCE(server_conf.tcp_port),`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			  READ_ONCE(server_conf.ipc_last_active) / HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `static ssize_t kill_server_store(const struct class *class,`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `				 const struct class_attribute *attr, const char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `static ssize_t kill_server_store(struct class *class,`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `				 struct class_attribute *attr, const char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `				 size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	if (!sysfs_streq(buf, "hard"))`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `		return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [LOCK|] `	mutex_lock(&ctrl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00809 [NONE] `	WRITE_ONCE(server_conf.state, SERVER_STATE_RESETTING);`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	__module_get(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	server_ctrl_handle_reset(NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	module_put(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [LOCK|] `	mutex_unlock(&ctrl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00814 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `static const char * const debug_type_strings[] = {"smb", "auth", "vfs",`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `						  "oplock", "ipc", "conn",`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `						  "rdma"};`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `static ssize_t debug_show(const struct class *class, const struct class_attribute *attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `static ssize_t debug_show(struct class *class, struct class_attribute *attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `			  char *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	ssize_t sz = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `	int i, pos = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		if ((ksmbd_debug_types >> i) & 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `			pos = sysfs_emit_at(buf, sz, "[%s] ", debug_type_strings[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `			pos = sysfs_emit_at(buf, sz, "%s ", debug_type_strings[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `		sz += pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	sz += sysfs_emit_at(buf, sz, "\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	return sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `static ssize_t debug_store(const struct class *class, const struct class_attribute *attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `static ssize_t debug_store(struct class *class, struct class_attribute *attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `			   const char *buf, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `		if (sysfs_streq(buf, "all")) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `			if (ksmbd_debug_types == KSMBD_DEBUG_ALL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `				ksmbd_debug_types = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `				ksmbd_debug_types = KSMBD_DEBUG_ALL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `		if (sysfs_streq(buf, debug_type_strings[i])) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `			if (ksmbd_debug_types & (1 << i))`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `				ksmbd_debug_types &= ~(1 << i);`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `				ksmbd_debug_types |= (1 << i);`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `static CLASS_ATTR_RO(stats);`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `static CLASS_ATTR_WO(kill_server);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `static CLASS_ATTR_RW(debug);`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `static struct attribute *ksmbd_control_class_attrs[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	&class_attr_stats.attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	&class_attr_kill_server.attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `	&class_attr_debug.attr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `ATTRIBUTE_GROUPS(ksmbd_control_class);`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `static struct class ksmbd_control_class = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	.name		= "ksmbd-control",`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `	.class_groups	= ksmbd_control_class_groups,`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `static int ksmbd_server_shutdown(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	WRITE_ONCE(server_conf.state, SERVER_STATE_SHUTTING_DOWN);`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	ksmbd_debugfs_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	class_unregister(&ksmbd_control_class);`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	 * Shutdown order:`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	 * 1. Stop the durable scavenger (releases module ref)`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	 * 2. Tear down transports + drain connections`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `	 * 3. Destroy workqueue (must outlive all work items)`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	 * 4. Release IPC + crypto`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `	 * 5. Free global file table (all connections dead)`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `	ksmbd_stop_durable_scavenger();`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `	ksmbd_conn_transport_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `	ksmbd_workqueue_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	ksmbd_ipc_release();`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `	ksmbd_crypto_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	ksmbd_free_global_file_table();`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	destroy_lease_table(NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	ksmbd_oplock_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	ksmbd_work_pool_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	ksmbd_buffer_pool_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `	ksmbd_exit_file_cache();`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `	server_conf_free();`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `	ksmbd_config_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `static int __init ksmbd_server_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `	ret = ksmbd_config_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [ERROR_PATH|] `		pr_err("Failed to initialize configuration subsystem\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00930 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `	ret = ksmbd_md4_register();`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [ERROR_PATH|] `		goto err_config_exit;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00936 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	ret = class_register(&ksmbd_control_class);`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [ERROR_PATH|] `		pr_err("Unable to register ksmbd-control class\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00940 [ERROR_PATH|] `		goto err_md4_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00941 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	ksmbd_server_tcp_callbacks_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	ret = server_conf_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [ERROR_PATH|] `		goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00948 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	ret = ksmbd_work_pool_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [ERROR_PATH|] `		goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	ret = ksmbd_buffer_pool_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [ERROR_PATH|] `		goto err_destroy_work_pools;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	ret = ksmbd_init_file_cache();`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [ERROR_PATH|] `		goto err_destroy_buffer_pool;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	ret = ksmbd_oplock_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [ERROR_PATH|] `		goto err_exit_file_cache;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	ret = ksmbd_ipc_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [ERROR_PATH|] `		goto err_exit_oplock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00968 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	ret = ksmbd_init_global_file_table();`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [ERROR_PATH|] `		goto err_ipc_release;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00972 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	ret = ksmbd_inode_hash_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [ERROR_PATH|] `		goto err_destroy_file_table;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00976 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	ret = ksmbd_crypto_create();`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [ERROR_PATH|] `		goto err_release_inode_hash;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	ret = ksmbd_workqueue_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [ERROR_PATH|] `		goto err_crypto_destroy;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `	/* Generate random BranchCache server secret */`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	ksmbd_branchcache_generate_secret();`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `	/* Initialize Fruit SMB extensions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `	ret = fruit_init_module();`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [ERROR_PATH|] `		goto err_workqueue_destroy;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00992 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	ret = ksmbd_debugfs_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [ERROR_PATH|] `		goto err_debugfs;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00996 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `	ret = ksmbd_fsctl_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [ERROR_PATH|] `		goto err_fsctl;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	ret = ksmbd_dfs_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [ERROR_PATH|] `		goto err_dfs;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `	ret = ksmbd_vss_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [ERROR_PATH|] `		goto err_vss;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	ret = ksmbd_create_ctx_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [ERROR_PATH|] `		goto err_create_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	ret = ksmbd_info_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [ERROR_PATH|] `		goto err_info;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `	ret = ksmbd_notify_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [ERROR_PATH|] `		goto err_notify;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `	ret = ksmbd_reparse_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [ERROR_PATH|] `		goto err_reparse;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	ret = ksmbd_resilient_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [ERROR_PATH|] `		goto err_resilient;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	ret = ksmbd_quota_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [ERROR_PATH|] `		goto err_quota;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	ret = ksmbd_app_instance_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [ERROR_PATH|] `		goto err_app_instance;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `	ret = ksmbd_rsvd_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [ERROR_PATH|] `		goto err_rsvd;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	ret = ksmbd_fsctl_extra_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [ERROR_PATH|] `		goto err_fsctl_extra;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `	ret = ksmbd_hooks_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [ERROR_PATH|] `		goto err_hooks;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	ret = ksmbd_witness_init();`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [ERROR_PATH|] `		goto err_witness;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `err_witness:`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `	ksmbd_hooks_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `err_hooks:`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	ksmbd_fsctl_extra_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `err_fsctl_extra:`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	ksmbd_rsvd_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `err_rsvd:`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `	ksmbd_app_instance_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `err_app_instance:`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	ksmbd_quota_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `err_quota:`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `	ksmbd_resilient_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `err_resilient:`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	ksmbd_reparse_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `err_reparse:`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	ksmbd_notify_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `err_notify:`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	ksmbd_info_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `err_info:`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	ksmbd_create_ctx_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `err_create_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	ksmbd_vss_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `err_vss:`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `	ksmbd_dfs_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `err_dfs:`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `	ksmbd_fsctl_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `err_fsctl:`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `	ksmbd_debugfs_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `err_debugfs:`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	fruit_cleanup_module();`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `err_workqueue_destroy:`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	ksmbd_workqueue_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `err_crypto_destroy:`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	ksmbd_crypto_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `err_release_inode_hash:`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	ksmbd_release_inode_hash();`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `err_destroy_file_table:`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	ksmbd_free_global_file_table();`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `err_ipc_release:`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `	ksmbd_ipc_release();`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `err_exit_oplock:`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `	ksmbd_oplock_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `err_exit_file_cache:`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `	ksmbd_exit_file_cache();`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `err_destroy_buffer_pool:`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `	ksmbd_buffer_pool_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `err_destroy_work_pools:`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	ksmbd_work_pool_destroy();`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	class_unregister(&ksmbd_control_class);`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `err_md4_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `	ksmbd_md4_unregister();`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `err_config_exit:`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `	ksmbd_config_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] ` * ksmbd_server_exit() - shutdown forker thread and free memory at module exit`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `static void __exit ksmbd_server_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	ksmbd_witness_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	ksmbd_hooks_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `	ksmbd_fsctl_extra_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	ksmbd_rsvd_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	ksmbd_app_instance_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	ksmbd_quota_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `	ksmbd_resilient_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	ksmbd_reparse_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	ksmbd_info_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	ksmbd_create_ctx_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	ksmbd_vss_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	ksmbd_dfs_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `	ksmbd_fsctl_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `	 * ksmbd_server_shutdown closes all connections and file handles.`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	 * ksmbd_notify_exit must come AFTER so that file-handle close`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `	 * paths can still call ksmbd_notify_cleanup_file() to detach`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	 * fsnotify marks properly before the group is destroyed.`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	ksmbd_server_shutdown();`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	ksmbd_notify_exit();`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [LIFETIME|] `	rcu_barrier();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01140 [NONE] `	ksmbd_release_inode_hash();`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	/* Cleanup Fruit SMB extensions */`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	fruit_cleanup_module();`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	ksmbd_md4_unregister();`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `MODULE_AUTHOR("Namjae Jeon <linkinjeon@kernel.org>");`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `MODULE_VERSION(KSMBD_VERSION);`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `MODULE_DESCRIPTION("Linux kernel CIFS/SMB SERVER");`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `MODULE_LICENSE("GPL");`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `MODULE_SOFTDEP("pre: ecb");`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `MODULE_SOFTDEP("pre: hmac");`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `MODULE_SOFTDEP("pre: md4");`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `MODULE_SOFTDEP("pre: md5");`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `MODULE_SOFTDEP("pre: nls");`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `MODULE_SOFTDEP("pre: aes");`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `MODULE_SOFTDEP("pre: cmac");`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `MODULE_SOFTDEP("pre: sha256");`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `MODULE_SOFTDEP("pre: sha512");`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `MODULE_SOFTDEP("pre: aead2");`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `MODULE_SOFTDEP("pre: ccm");`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `MODULE_SOFTDEP("pre: gcm");`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `MODULE_SOFTDEP("pre: crc32");`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `module_init(ksmbd_server_init)`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `module_exit(ksmbd_server_exit)`
  Review: Low-risk line; verify in surrounding control flow.
