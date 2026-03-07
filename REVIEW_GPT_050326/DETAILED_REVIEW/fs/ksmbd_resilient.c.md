# Line-by-line Review: src/fs/ksmbd_resilient.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Resilient handle support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Implements FSCTL_LMR_REQUEST_RESILIENCY (0x001401D4) which allows`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   clients to request that the server keep file handles open for a`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   specified timeout after a network disconnection.  This enables`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   the client to reconnect and resume operations without data loss.`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "ksmbd_resilient.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * NETWORK_RESILIENCY_REQUEST structure ([MS-SMB2] 2.2.31.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * Timeout:  Requested timeout in milliseconds that the server should`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` *           keep the file handle alive after a network disconnect.`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * Reserved: Must be zero; ignored on receipt.`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `struct network_resiliency_request {`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	__le32	timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	__le32	reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `/* Maximum resilient timeout: 5 minutes (in milliseconds) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define KSMBD_MAX_RESILIENT_TIMEOUT_MS	(5 * 60 * 1000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * ksmbd_fsctl_request_resiliency() - Handle FSCTL_LMR_REQUEST_RESILIENCY`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * @in_buf:	    input buffer containing NETWORK_RESILIENCY_REQUEST`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * Parses the NETWORK_RESILIENCY_REQUEST structure from the input`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` * buffer, validates the timeout, and marks the file handle as`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` * resilient.  The server will keep the handle open for the`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` * specified timeout after a network disconnection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * Per [MS-SMB2] 3.3.5.15.9, the response has no output data.`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `static int ksmbd_fsctl_request_resiliency(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `					  u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `					  unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `					  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `					  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `					  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	struct network_resiliency_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	unsigned int timeout_ms;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	if (in_buf_len < sizeof(struct network_resiliency_request)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00073 [NONE] `			"resilient handle: input buffer too short: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `			in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00076 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00077 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	req = (struct network_resiliency_request *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	timeout_ms = le32_to_cpu(req->timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [ERROR_PATH|] `		pr_err_ratelimited("resilient handle: file not found\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00085 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00086 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00087 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	 * Cap the timeout to a server-defined maximum to prevent`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	 * clients from requesting unreasonably long hold times.`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	if (timeout_ms > KSMBD_MAX_RESILIENT_TIMEOUT_MS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		timeout_ms = KSMBD_MAX_RESILIENT_TIMEOUT_MS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	fp->is_resilient = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	fp->resilient_timeout = timeout_ms;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		    "resilient handle: fid=%llu timeout=%u ms\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		    id, timeout_ms);`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `/* FSCTL handler descriptor */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `static struct ksmbd_fsctl_handler resilient_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	.ctl_code = FSCTL_LMR_REQUEST_RESILIENCY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	.handler  = ksmbd_fsctl_request_resiliency,`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * ksmbd_resilient_init() - Initialize resilient handle subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * Registers the FSCTL handler for FSCTL_LMR_REQUEST_RESILIENCY`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * (0x001401D4).`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `int ksmbd_resilient_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	ret = ksmbd_register_fsctl(&resilient_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [ERROR_PATH|] `		pr_err("Failed to register FSCTL_LMR_REQUEST_RESILIENCY: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00130 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	ksmbd_debug(SMB, "Resilient handle subsystem initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * ksmbd_resilient_exit() - Tear down resilient handle subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * Unregisters the FSCTL_LMR_REQUEST_RESILIENCY handler.`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `void ksmbd_resilient_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	ksmbd_unregister_fsctl(&resilient_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
