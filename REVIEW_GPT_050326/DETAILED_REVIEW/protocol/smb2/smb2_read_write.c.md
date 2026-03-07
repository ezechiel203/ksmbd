# Line-by-line Review: src/protocol/smb2/smb2_read_write.c

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
- L00006 [PROTO_GATE|] ` *   smb2_read_write.c - SMB2_READ + SMB2_WRITE + SMB2_FLUSH handlers`
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
- L00043 [NONE] `#include "ksmbd_branchcache.h"`
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
- L00062 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * smb2_read_pipe_cancel() - cancel callback for async pipe read`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * @argv: cancel argument array (argv[0] is unused/NULL for pipe reads)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [PROTO_GATE|] ` * Called from the SMB2 CANCEL path.  Sends STATUS_CANCELLED to the client`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [NONE] ` * and frees the async work.`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `static void smb2_read_pipe_cancel(void **argv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	struct ksmbd_work *work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	struct smb2_read_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	 * argv[0] contains the work pointer for pipe read cancellation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	 * If NULL, the work was already completed or freed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	if (!argv || !argv[0])`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	work = argv[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [PROTO_GATE|] `	rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00085 [NONE] `	rsp->hdr.Id.AsyncId = cpu_to_le64(work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_CANCELLED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	if (ksmbd_iov_pin_rsp(work, rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `			      sizeof(struct smb2_hdr) + 2))`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	if (work->sess && work->sess->enc && work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	    work->conn->ops->encrypt_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		int rc = work->conn->ops->encrypt_resp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [ERROR_PATH|] `			pr_err_ratelimited("ksmbd: pipe read cancel encrypt failed: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00100 [NONE] `					   rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	 * The async handler set send_no_response = 1 to suppress the`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	 * main dispatch path's response.  Clear it so the cancel`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	 * response is actually transmitted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	work->send_no_response = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	ksmbd_conn_write(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	/* Remove from async_requests list before freeing */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [LOCK|] `	spin_lock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00113 [NONE] `	list_del_init(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [LOCK|] `	spin_unlock(&work->conn->request_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	ksmbd_conn_try_dequeue_request(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	/* Decrement outstanding async count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	if (READ_ONCE(server_conf.max_async_credits))`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [LIFETIME|] `		atomic_dec(&work->conn->outstanding_async);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	ksmbd_free_work_struct(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [PROTO_GATE|] ` * smb2_read_pipe_async() - make a pipe read go async (STATUS_PENDING)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00127 [NONE] ` * @work: smb work to pend`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * Called when a pipe read has no data available.  Sets up async work`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [PROTO_GATE|] ` * and sends STATUS_PENDING to the client.  The work remains pending`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00131 [NONE] ` * until cancelled or the connection is torn down.`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` *         -ENOSPC means the async credit limit is reached; caller`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [PROTO_GATE|] ` *         should return STATUS_INSUFFICIENT_RESOURCES synchronously.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00136 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `static int smb2_read_pipe_async(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	struct smb2_read_rsp *rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	void **argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [MEM_BOUNDS|] `	argv = kmalloc(sizeof(void *), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00144 [NONE] `	if (!argv) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00146 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00148 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	rc = setup_async_work(work, smb2_read_pipe_cancel, argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `		kfree(argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00154 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	/* Store work pointer in cancel argv so cancel can find it */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	argv[0] = work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	/* Transfer work ownership to async subsystem */`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	work->pending_async = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	 * Grant credits in the interim response.  Call set_rsp_credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	 * BEFORE smb2_send_interim_resp so the CreditRequest field is`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	 * set in the response header, and the interim copy inherits it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	 * This must happen before setting send_no_response, otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	 * set_rsp_credits would bail out immediately.`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	if (work->conn->ops->set_rsp_credits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		work->conn->ops->set_rsp_credits(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [PROTO_GATE|] `	/* Send STATUS_PENDING interim response */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00175 [PROTO_GATE|] `	smb2_send_interim_resp(work, STATUS_PENDING);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	/* Suppress the normal response path */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ` * smb2_read_pipe() - handler for smb2 read from IPC pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ` * @work:	smb work containing read IPC pipe command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `static noinline int smb2_read_pipe(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	int nbytes = 0, err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	unsigned int remain_bytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	u64 id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	struct ksmbd_rpc_command *rpc_resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	struct smb2_read_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	struct smb2_read_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	unsigned int length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	length = le32_to_cpu(req->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	rpc_resp = ksmbd_rpc_read(work->sess, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	if (rpc_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `		void *aux_payload_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `		if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `			kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `			rpc_resp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [ERROR_PATH|] `			goto no_data;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00211 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `		if (rpc_resp->flags != KSMBD_RPC_OK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `			kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `			rpc_resp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [ERROR_PATH|] `			goto no_data;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00217 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		if (rpc_resp->payload_sz == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `			kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `			rpc_resp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [ERROR_PATH|] `			goto no_data;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00223 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		 * We have pipe data available.`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		nbytes = rpc_resp->payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		if (length == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `			 * Zero-length read but data exists: go async.`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `			 * The read stays pending since the client`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `			 * cannot receive data with length=0.`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `			kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `			return smb2_read_pipe_async(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		 * Cap the response to the client's requested length.`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		 * If the pipe has more data than the client asked for,`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [PROTO_GATE|] `		 * return STATUS_BUFFER_OVERFLOW with truncated data.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00244 [NONE] `		 * Track how many bytes remain so DataRemaining can be set`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		 * correctly in the response (MS-SMB2 §2.2.20, D.6).`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		if (nbytes > length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00249 [NONE] `			remain_bytes = nbytes - length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			nbytes = length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		aux_payload_buf =`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [MEM_BOUNDS|] `			kvmalloc(nbytes, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00255 [NONE] `		if (!aux_payload_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `			err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00258 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [MEM_BOUNDS|] `		memcpy(aux_payload_buf, rpc_resp->payload, nbytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		err = ksmbd_iov_pin_rsp_read(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `					     offsetof(struct smb2_read_rsp, Buffer),`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `					     aux_payload_buf, nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00267 [NONE] `		kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `no_data:`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		 * No data available on the pipe.  Per MS-SMB2, when a`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		 * named pipe has no data, the server should pend the`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		 * read and complete it when data arrives.  Since ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		 * communicates with the RPC daemon synchronously, we`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		 * go async here and leave the request pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		return smb2_read_pipe_async(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	rsp->StructureSize = cpu_to_le16(17);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	/* D.1: DataOffset is relative to start of SMB2 message header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	rsp->DataLength = cpu_to_le32(nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	 * D.6: MS-SMB2 §2.2.20 — DataRemaining indicates bytes still in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [PROTO_GATE|] `	 * pipe buffer that could not fit in this response (STATUS_BUFFER_OVERFLOW`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00288 [NONE] `	 * case).  Set it to the actual remaining byte count so the client knows`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	 * how much more data to request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	rsp->DataRemaining = cpu_to_le32(remain_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	if (!rsp->hdr.Status)`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00298 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `static int smb2_set_remote_key_for_rdma(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `					struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `					__le32 Channel,`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `					__le16 ChannelInfoLength)`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	unsigned int i, ch_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	if (work->conn->dialect == SMB30_PROT_ID &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [PROTO_GATE|] `	    Channel != SMB2_CHANNEL_RDMA_V1)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00312 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	ch_count = le16_to_cpu(ChannelInfoLength) / sizeof(*desc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	if (ksmbd_debug_types & KSMBD_DEBUG_RDMA) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `		for (i = 0; i < ch_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `			pr_info("RDMA r/w request %#x: token %#x, length %#x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `				i,`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `				le32_to_cpu(desc[i].token),`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `				le32_to_cpu(desc[i].length));`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	if (!ch_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	work->need_invalidate_rkey =`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [PROTO_GATE|] `		(Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00328 [PROTO_GATE|] `	if (Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00329 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		 * D.5: Store the first descriptor's token for RDMA_V1_INVALIDATE.`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		 * MS-SMB2 §3.3.5.12/13 allows multi-descriptor RDMA buffers`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `		 * (ch_count > 1).  The ksmbd_work struct only has a single`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		 * remote_key field, and the RDMA transport layer (transport_rdma.c)`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		 * only supports invalidating one Memory Region per send via`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		 * IB_WR_SEND_WITH_INV.  Full multi-descriptor invalidation would`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `		 * require extending ksmbd_work with an array of tokens and updating`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `		 * the transport send path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		 * In practice, real-world RDMA clients (including Windows) send`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `		 * exactly one descriptor per SMB2 READ/WRITE when using`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		 * RDMA_V1_INVALIDATE, so this limitation does not cause`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		 * interoperability problems.  Emit a rate-limited warning if a`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		 * client ever sends more than one descriptor so the condition can`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		 * be diagnosed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `		if (ch_count > 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [ERROR_PATH|] `			pr_warn_ratelimited("ksmbd: RDMA_V1_INVALIDATE with %u descriptors; only first token (0x%x) will be invalidated\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00348 [NONE] `					    ch_count, le32_to_cpu(desc->token));`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		work->remote_key = le32_to_cpu(desc->token);`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `static ssize_t smb2_read_rdma_channel(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `				      struct smb2_read_req *req, void *data_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `				      size_t length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	unsigned int ch_offset = le16_to_cpu(req->ReadChannelInfoOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	unsigned int ch_len = le16_to_cpu(req->ReadChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	if (ch_offset < offsetof(struct smb2_read_req, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	    ch_offset > req_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	    ch_len > req_len - ch_offset)`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	err = ksmbd_conn_rdma_write(work->conn, data_buf, length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `				    (struct smb2_buffer_desc_v1 *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `				    ((char *)req + ch_offset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `				    ch_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	return length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * smb2_read() - handler for smb2 read from file`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` * @work:	smb work containing read command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `int smb2_read(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	struct smb2_read_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	struct smb2_read_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	loff_t offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	size_t length, mincount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	ssize_t nbytes = 0, remain_bytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	bool is_rdma_channel = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	unsigned int max_read_size = conn->vals->max_read_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	unsigned int id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	void *aux_payload_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	ksmbd_debug(SMB, "Received smb2 read request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `				   KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		ksmbd_debug(SMB, "IPC pipe read request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		return smb2_read_pipe(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		req = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `		rsp = ksmbd_resp_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `			ksmbd_debug(SMB, "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `					work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `			id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `			pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `		req = smb2_get_msg(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		rsp = smb2_get_msg(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `		id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [PROTO_GATE|] `	if (req->Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00427 [PROTO_GATE|] `	    req->Channel == SMB2_CHANNEL_RDMA_V1) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00428 [NONE] `		is_rdma_channel = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		max_read_size = get_smbd_max_read_write_size();`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	if (is_rdma_channel == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `		unsigned int ch_offset = le16_to_cpu(req->ReadChannelInfoOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `		unsigned int ch_len = le16_to_cpu(req->ReadChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `		if (ch_offset < offsetof(struct smb2_read_req, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		    ch_offset > req_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		    ch_len > req_len - ch_offset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00442 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		err = smb2_set_remote_key_for_rdma(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `						   (struct smb2_buffer_desc_v1 *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `						   ((char *)req + ch_offset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `						   req->Channel,`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `						   req->ReadChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00450 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `	fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00456 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_READ_ATTRIBUTES_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [ERROR_PATH|] `		pr_err("Not permitted to read : 0x%x\n", fp->daccess);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00460 [NONE] `		err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00462 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	offset = le64_to_cpu(req->Offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	if (offset < 0 || offset > MAX_LFS_FILESIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		ksmbd_debug(SMB, "invalid read offset %lld\n", offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00469 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	length = le32_to_cpu(req->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	mincount = le32_to_cpu(req->MinimumCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	 * MS-SMB2 §3.3.5.12: reject reads where offset + length would`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	 * overflow the maximum addressable file offset.  A read at`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	 * (INT64_MAX, length=1) would wrap to a negative position;`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	 * detect this before the VFS call to return INVALID_PARAMETER`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [PROTO_GATE|] `	 * rather than STATUS_END_OF_FILE.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00479 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	if (length > 0 && offset > MAX_LFS_FILESIZE - (loff_t)length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00483 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	if (length > max_read_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `		ksmbd_debug(SMB, "limiting read size to max size(%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `			    max_read_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00490 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	 * D.4: MS-SMB2 §3.3.5.12 — inspect per-request read flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	 * The Flags byte in the wire format (MS-SMB2 §2.2.19, 1 byte after`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	 * Padding) maps to req->Reserved in the ksmbd struct definition.`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [PROTO_GATE|] `	 * SMB2_READFLAG_READ_UNBUFFERED (0x01): the client requests that the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00497 [NONE] `	 * server bypass its page cache and read directly from the backing`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	 * store (equivalent to O_DIRECT).  ksmbd uses buffered reads via`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	 * kernel_read(); direct I/O is not currently supported.  Log the`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	 * request so administrators can identify clients using this feature.`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [PROTO_GATE|] `	if (req->Reserved & SMB2_READFLAG_READ_UNBUFFERED)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00503 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [PROTO_GATE|] `			    "SMB2_READFLAG_READ_UNBUFFERED set but not supported; using buffered read\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	ksmbd_debug(SMB, "filename %pD, offset %lld, len %zu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		    fp->filp, offset, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	 * Try zero-copy path: send file data directly to the socket`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	 * without an intermediate buffer copy. This is eligible when:`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	 * - Not encrypted (encryption needs to process the data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	 * - Not signed (signing needs to hash the data payload)`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	 * - Not a compound request (need contiguous response)`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	 * - Not an RDMA channel (uses different transfer mechanism)`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `	 * - Not a stream file (streams need special handling)`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	 * - Transport supports sendfile`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	if (!work->encrypted &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	    !(work->sess && work->sess->sign) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [PROTO_GATE|] `	    !(req->hdr.Flags & SMB2_FLAGS_SIGNED) &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00522 [NONE] `	    !work->next_smb2_rcv_hdr_off &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [PROTO_GATE|] `	    !req->hdr.NextCommand &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00524 [NONE] `	    !is_rdma_channel &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	    !ksmbd_stream_fd(fp) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	    conn->transport->ops->sendfile) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		nbytes = ksmbd_vfs_sendfile(work, fp, offset, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		if (nbytes == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [ERROR_PATH|] `			goto buffered_read;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `		if (nbytes < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `			err = nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00534 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `		if ((nbytes == 0 && length != 0) || nbytes < mincount) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_END_OF_FILE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00538 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [ERROR_PATH|] `			return -ENODATA;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00541 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `		ksmbd_debug(SMB, "zero-copy nbytes %zu, offset %lld\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `			    nbytes, offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `		rsp->StructureSize = cpu_to_le16(17);`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `		/* D.1: DataOffset is relative to start of SMB2 message header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `		rsp->DataLength = cpu_to_le32(nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		rsp->DataRemaining = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `		 * Pin just the header; file data will be sent by the`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `		 * transport sendfile op after the header is written.`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `		err = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `					offsetof(struct smb2_read_rsp, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00562 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		/* Include the file data length in the rfc1002 length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `		inc_rfc1001_len(work->iov[0].iov_base, nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		/* Set up sendfile state on the work struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		work->sendfile = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		work->sendfile_filp = get_file(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		work->sendfile_offset = offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		work->sendfile_count = nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `buffered_read:`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	aux_payload_buf = ksmbd_buffer_pool_get(ALIGN(length, 8));`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	if (!aux_payload_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `		err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00581 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	nbytes = ksmbd_vfs_read(work, fp, length, &offset, aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	if (nbytes < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		ksmbd_buffer_pool_put(aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `		err = nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00588 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	if ((nbytes == 0 && length != 0) || nbytes < mincount) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		ksmbd_buffer_pool_put(aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_END_OF_FILE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00593 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [ERROR_PATH|] `		return -ENODATA;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00596 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	ksmbd_debug(SMB, "nbytes %zu, offset %lld mincount %zu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `		    nbytes, offset, mincount);`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	if (is_rdma_channel == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		/* write data to the client using rdma channel */`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		remain_bytes = smb2_read_rdma_channel(work, req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `						      aux_payload_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `						      nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		ksmbd_buffer_pool_put(aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		aux_payload_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		if (remain_bytes < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `			err = (int)remain_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00612 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	rsp->StructureSize = cpu_to_le16(17);`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `	/* D.1: DataOffset is relative to start of SMB2 message header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	rsp->DataOffset = offsetof(struct smb2_read_rsp, Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	rsp->DataLength = cpu_to_le32(nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	rsp->DataRemaining = cpu_to_le32(remain_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		 * Compound request: copy data inline into the response`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		 * buffer so the entire response (header + body + data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		 * is contiguous.  This ensures that the 8-byte padding`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		 * added by init_chained_smb2_rsp() between compound`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		 * members is correctly visible to the client, which`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		 * parses the compound response as a single contiguous`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `		 * byte stream.  With a separate aux iov, the`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `		 * scatter-gather layout can cause the padding to be`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `		 * invisible to the client's compound parser.`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [MEM_BOUNDS|] `		memcpy(rsp->Buffer, aux_payload_buf, nbytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00636 [NONE] `		ksmbd_buffer_pool_put(aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		err = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `					offsetof(struct smb2_read_rsp, Buffer) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `					nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00642 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `		err = ksmbd_iov_pin_rsp_read(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `					     offsetof(struct smb2_read_rsp, Buffer),`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `					     aux_payload_buf, nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `			ksmbd_buffer_pool_put(aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00649 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `		if (err == -EISDIR)`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00658 [NONE] `		else if (err == -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00660 [NONE] `		else if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00662 [NONE] `		else if (err == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00664 [NONE] `		else if (err == -ESHARE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_SHARING_VIOLATION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00666 [NONE] `		else if (err == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00668 [NONE] `		else if (err == -EBUSY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DELETE_PENDING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00670 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] ` * smb2_write_pipe() - handler for smb2 write on IPC pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ` * @work:	smb work containing write IPC pipe command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `static noinline int smb2_write_pipe(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	struct smb2_write_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	struct smb2_write_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	struct ksmbd_rpc_command *rpc_resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	u64 id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	char *data_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	size_t length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	length = le32_to_cpu(req->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	if ((u64)le16_to_cpu(req->DataOffset) + length >`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	    get_rfc1002_len(work->request_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [ERROR_PATH|] `		pr_err_ratelimited("invalid write data offset %u, smb_len %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00703 [NONE] `				   le16_to_cpu(req->DataOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `				   get_rfc1002_len(work->request_buf));`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00707 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [PROTO_GATE|] `	data_buf = (char *)(((char *)&req->hdr.ProtocolId) +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00710 [NONE] `			   le16_to_cpu(req->DataOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	rpc_resp = ksmbd_rpc_write(work->sess, id, data_buf, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	if (rpc_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `			kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `			rpc_resp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [ERROR_PATH|] `			goto write_rsp;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00718 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		if (rpc_resp->flags != KSMBD_RPC_OK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `			 * D.2: MS-SMB2 §3.3.5.13 — pipe write failures should`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [PROTO_GATE|] `			 * return STATUS_PIPE_DISCONNECTED (not STATUS_INVALID_HANDLE).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00723 [NONE] `			 * Also return a proper negative errno so the caller's`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `			 * compound chain does not treat this as a success.`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_PIPE_DISCONNECTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00727 [NONE] `			smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `			kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [ERROR_PATH|] `			return -EPIPE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00730 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `write_rsp:`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	rsp->StructureSize = cpu_to_le16(17);`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	rsp->DataOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	rsp->DataLength = cpu_to_le32(length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	rsp->DataRemaining = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	err = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `				offsetof(struct smb2_write_rsp, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00746 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `static ssize_t smb2_write_rdma_channel(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `				       struct smb2_write_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `				       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `				       loff_t offset, size_t length, bool sync)`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	char *data_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	ssize_t nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	unsigned int ch_offset = le16_to_cpu(req->WriteChannelInfoOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	unsigned int ch_len = le16_to_cpu(req->WriteChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	if (ch_offset < offsetof(struct smb2_write_req, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `	    ch_offset > req_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `	    ch_len > req_len - ch_offset)`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00768 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	 * D.3: MS-SMB2 §2.2.21 — for RDMA channels, RemainingBytes carries`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `	 * the transfer length.  A zero-length RDMA write is valid; skip the`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	 * RDMA read entirely and proceed directly to writing zero bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	if (length == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `		nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [ERROR_PATH|] `		goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00777 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	data_buf = ksmbd_buffer_pool_get(length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	if (!data_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	ret = ksmbd_conn_rdma_read(work->conn, data_buf, length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `				   (struct smb2_buffer_desc_v1 *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `				   ((char *)req + ch_offset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `				   ch_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `		ksmbd_buffer_pool_put(data_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `	ret = ksmbd_vfs_write(work, fp, data_buf, length, &offset, sync, &nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `	ksmbd_buffer_pool_put(data_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `	if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `done:`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	return nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ` * smb2_write() - handler for smb2 write from file`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] ` * @work:	smb work containing write command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `int smb2_write(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `	struct smb2_write_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	struct smb2_write_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	loff_t offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	size_t length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	ssize_t nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	char *data_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	bool writethrough = false, is_rdma_channel = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	bool write_to_eof = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `	unsigned int max_write_size = work->conn->vals->max_write_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	ksmbd_debug(SMB, "Received smb2 write request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	if (test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `		ksmbd_debug(SMB, "IPC pipe write request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `		return smb2_write_pipe(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	 * MS-SMB2 §3.3.5.13: 0xFFFFFFFFFFFFFFFF is the write-to-EOF sentinel,`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `	 * but only for FILE_APPEND_DATA-only handles (no FILE_WRITE_DATA).`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	 * We defer sentinel detection to after fp lookup so we can check`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	 * the granted access.  For now, just parse the offset; the sentinel`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	 * value (all-ones) casts to loff_t -1 which the "offset < 0" check`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `	 * will catch for non-append handles.`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `		__le64 raw_offset = req->Offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `		write_to_eof = (raw_offset == cpu_to_le64(0xFFFFFFFFFFFFFFFFULL));`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `		if (write_to_eof) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `			offset = 0; /* placeholder; resolved after fp lookup */`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `			offset = le64_to_cpu(raw_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `			if (offset < 0 || offset > MAX_LFS_FILESIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00849 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	length = le32_to_cpu(req->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `	/* Reject writes where offset + length would overflow MAX_LFS_FILESIZE */`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	if (length > 0 && offset > 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	    offset > MAX_LFS_FILESIZE - (loff_t)length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00859 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `	 * MS-SMB2: NTFS maximum file size is 0xfffffff0000.`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `	 * Writing at or beyond MAXFILESIZE is INVALID_PARAMETER.`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	 * Writing below MAXFILESIZE but extending past it is DISK_FULL.`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [PROTO_GATE|] `#define SMB2_MAX_FILE_OFFSET ((loff_t)0xfffffff0000ULL)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00867 [PROTO_GATE|] `	if (length > 0 && offset >= SMB2_MAX_FILE_OFFSET) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00868 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00870 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [PROTO_GATE|] `	if (length > 0 && offset + (loff_t)length >= SMB2_MAX_FILE_OFFSET) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00872 [NONE] `		err = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00874 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [PROTO_GATE|] `	if (req->Channel == SMB2_CHANNEL_RDMA_V1 ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00877 [PROTO_GATE|] `	    req->Channel == SMB2_CHANNEL_RDMA_V1_INVALIDATE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00878 [NONE] `		is_rdma_channel = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `		max_write_size = get_smbd_max_read_write_size();`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `		length = le32_to_cpu(req->RemainingBytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	if (is_rdma_channel == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `		unsigned int ch_offset = le16_to_cpu(req->WriteChannelInfoOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `		unsigned int ch_len = le16_to_cpu(req->WriteChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `		if (req->Length != 0 || req->DataOffset != 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `		    ch_offset < offsetof(struct smb2_write_req, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		    ch_offset > req_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		    ch_len > req_len - ch_offset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00894 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `		err = smb2_set_remote_key_for_rdma(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `						   (struct smb2_buffer_desc_v1 *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `						   ((char *)req + ch_offset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `						   req->Channel,`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `						   req->WriteChannelInfoLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00902 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		ksmbd_debug(SMB, "User does not have write permission\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00908 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		u64 volatile_id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `		u64 persistent_id = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `		if (work->next_smb2_rcv_hdr_off &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `		    !has_file_id(volatile_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `				    "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `				    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `			volatile_id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `			persistent_id = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `		fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00928 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [ERROR_PATH|] `		pr_err("Not permitted to write : 0x%x\n", fp->daccess);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00932 [NONE] `		err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00934 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence */`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	if (smb2_check_channel_sequence(work, fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00939 [NONE] `		err = -EAGAIN;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00941 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	 * MS-SMB2 §3.3.5.13: resolve the write-to-EOF sentinel and enforce`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	 * append-only semantics for FILE_APPEND_DATA-without-FILE_WRITE_DATA.`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	 * The sentinel (offset == 0xFFFFFFFFFFFFFFFF) is only valid when the`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	 * handle has FILE_APPEND_DATA but NOT FILE_WRITE_DATA.  For handles`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	 * with FILE_WRITE_DATA, this offset is simply invalid (negative when`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	 * cast to loff_t).`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `	if (write_to_eof) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `		if (!(fp->daccess & FILE_APPEND_DATA_LE) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `		    (fp->daccess & FILE_WRITE_DATA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `			 * Not an append-only handle: offset 0xFFFFFFFFFFFFFFFF`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `			 * is not a valid sentinel, reject as invalid offset.`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00961 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `		offset = i_size_read(file_inode(fp->filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	if (length > max_write_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `		ksmbd_debug(SMB, "limiting write size to max size(%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `			    max_write_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00970 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `	 * Time Machine quota enforcement: reject writes when the`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `	 * share's Time Machine max size has been exceeded.`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	if (work->tcon && work->tcon->share_conf &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	    work->conn->is_fruit) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		err = ksmbd_fruit_check_tm_quota(`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `				work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `				&work->tcon->share_conf->vfs_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `				    "Fruit TM quota exceeded, rejecting write\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00986 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `	ksmbd_debug(SMB, "flags %u\n", le32_to_cpu(req->Flags));`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [PROTO_GATE|] `	if (le32_to_cpu(req->Flags) & SMB2_WRITEFLAG_WRITE_THROUGH)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00992 [NONE] `		writethrough = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `	 * D.4: MS-SMB2 §3.3.5.13 — inspect per-request write flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [PROTO_GATE|] `	 * SMB2_WRITEFLAG_WRITE_UNBUFFERED (0x02): the client requests that`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00997 [NONE] `	 * the server write data directly to the backing store without`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	 * intermediate buffering (equivalent to O_DIRECT semantics).  ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `	 * uses buffered writes; direct I/O is not currently supported.  Log`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `	 * the request so administrators can identify clients using this`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	 * feature.  WRITE_THROUGH (fsync after write) is handled above.`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [PROTO_GATE|] `	if (le32_to_cpu(req->Flags) & SMB2_WRITEFLAG_WRITE_UNBUFFERED)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01004 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [PROTO_GATE|] `			    "SMB2_WRITEFLAG_WRITE_UNBUFFERED set but not supported; using buffered write\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	if (is_rdma_channel == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `		unsigned int data_off = le16_to_cpu(req->DataOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `		unsigned int req_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `		if (data_off < offsetof(struct smb2_write_req, Buffer)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01014 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		 * Compute the available request buffer length relative to`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [PROTO_GATE|] `		 * the current sub-request's ProtocolId.  For compound`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01019 [NONE] `		 * requests, subtract the compound header offset so we`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		 * don't allow the write data to spill into adjacent`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `		 * sub-requests.`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `		req_buf_len = get_rfc1002_len(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		if (work->next_smb2_rcv_hdr_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `			req_buf_len -= work->next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `		if ((u64)data_off + length > req_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [ERROR_PATH|] `			pr_err_ratelimited("write data overflow: off=%u len=%zu buf=%u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01029 [NONE] `					   data_off, length, req_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01032 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [PROTO_GATE|] `		data_buf = (char *)(((char *)&req->hdr.ProtocolId) +`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01035 [NONE] `				    le16_to_cpu(req->DataOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `		ksmbd_debug(SMB, "filename %pD, offset %lld, len %zu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `			    fp->filp, offset, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `		err = ksmbd_vfs_write(work, fp, data_buf, length, &offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `				      writethrough, &nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `		if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01043 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `		/* read data from the client using rdma channel, and`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `		 * write the data.`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `		nbytes = smb2_write_rdma_channel(work, req, fp, offset, length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `						 writethrough);`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `		if (nbytes < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `			err = (int)nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01052 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `	/* Invalidate BranchCache hashes on successful write */`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `	ksmbd_branchcache_invalidate(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	rsp->StructureSize = cpu_to_le16(17);`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	rsp->DataOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	rsp->DataLength = cpu_to_le32(nbytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `	rsp->DataRemaining = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	err = ksmbd_iov_pin_rsp(work, rsp, offsetof(struct smb2_write_rsp, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01067 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `	if (err == -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01073 [NONE] `	else if (err == -ENOSPC || err == -EFBIG)`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01075 [NONE] `	else if (err == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01077 [NONE] `	else if (err == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01079 [NONE] `	else if (err == -ESHARE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_SHARING_VIOLATION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01081 [NONE] `	else if (err == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01083 [NONE] `	else if (err == -EBUSY)`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_DELETE_PENDING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01085 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] ` * smb2_flush() - handler for smb2 flush file - fsync`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] ` * @work:	smb work containing flush command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `int smb2_flush(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	struct smb2_flush_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	struct smb2_flush_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `	bool fullsync = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `	u64 id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `	if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `		if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `			ksmbd_debug(SMB, "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `				    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `			id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `			pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `		id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `		pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `	ksmbd_debug(SMB, "Received smb2 flush request(fid : %llu)\n", id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	/* MS-SMB2 §3.3.5.9: look up fp for access check and ChannelSequence */`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [PROTO_GATE|] `		/* MS-SMB2 §3.3.5.9: closed file handle → STATUS_FILE_CLOSED */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01130 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01131 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01133 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	 * MS-SMB2 §3.3.5.9 (FLUSH-1): caller must have write or append`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	 * access before we honour the flush request.`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `		ksmbd_debug(SMB, "Flush: insufficient access (daccess=0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `			    fp->daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01144 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01146 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	/* MS-SMB2 §3.3.5.2.10: validate ChannelSequence before flushing */`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `	err = smb2_check_channel_sequence(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01153 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	 * Apple F_FULLFSYNC: macOS Time Machine sends`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `	 * Reserved1=0xFFFF to request a full device flush.`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `	if (work->conn->is_fruit && le16_to_cpu(req->Reserved1) == 0xFFFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `		fullsync = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `	err = ksmbd_vfs_fsync(work, id, pid, fullsync);`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01169 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	rsp->StructureSize = cpu_to_le16(4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	return ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_flush_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
