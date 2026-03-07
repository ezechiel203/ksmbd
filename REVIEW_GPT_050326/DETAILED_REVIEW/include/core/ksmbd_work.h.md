# Line-by-line Review: src/include/core/ksmbd_work.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2019 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __KSMBD_WORK_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __KSMBD_WORK_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/ctype.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `struct ksmbd_session;`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `struct ksmbd_tree_connect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	KSMBD_WORK_ACTIVE = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `	KSMBD_WORK_CANCELLED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `	KSMBD_WORK_CLOSED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `struct aux_read {`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	void *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	struct list_head entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `/* one of these for every pending CIFS request at the connection */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `struct ksmbd_work {`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	/* Server corresponding to this mid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	struct ksmbd_conn               *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	struct ksmbd_session            *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	struct ksmbd_tree_connect       *tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	/* Pointer to received SMB header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	void                            *request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	/* Response buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	void                            *response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	struct list_head		aux_read_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	struct kvec			*iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	int				iov_alloc_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	int				iov_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	int				iov_idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	/* Next cmd hdr in compound req buf*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	int                             next_smb2_rcv_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	/* Next cmd hdr in compound rsp buf*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	int                             next_smb2_rsp_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	/* Current cmd hdr in compound rsp buf*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	int                             curr_smb2_rsp_hdr_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	 * Current Local FID assigned compound response if SMB2 CREATE`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	 * command is present in compound request`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	u64				compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	u64				compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	u64				compound_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	 * When a CREATE in a compound chain fails, this records`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	 * the error status so that subsequent related operations`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	 * can propagate it.  Set in init_chained_smb2_rsp() when`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	 * a CREATE response has a non-success status.`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__le32				compound_err_status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	const struct cred		*saved_cred;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	int				saved_cred_depth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	/* Number of granted credits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	unsigned int			credits_granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	 * True if this SMB2 command successfully charged outstanding credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	 * in request validation.  Response credit settlement must only`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	 * decrement outstanding_credits when this is set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	bool				credit_charge_tracked;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	/* response smb header size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	unsigned int                    response_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	void				*tr_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	 * Session ID from the SMB2 TRANSFORM header.  Saved in`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	 * smb3_decrypt_req() before the buffer is overwritten so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	 * the response can be encrypted with the transport session even`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	 * when the inner SMB2 header carries an invalid session ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	 * (e.g. smb2.tcon "invalid VUID" subtest).`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	u64				tr_sess_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	unsigned char			state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	/* No response for cancelled request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	bool                            send_no_response:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	/* Request is encrypted */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	bool                            encrypted:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	/* Is this SYNC or ASYNC ksmbd_work */`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	bool                            asynchronous:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	bool                            need_invalidate_rkey:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	/* Zero-copy sendfile for read response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	bool                            sendfile:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	/* Async work owned by subsystem (notify), worker must not free */`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	bool                            pending_async:1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	unsigned int                    remote_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	/* Zero-copy sendfile state */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	struct file			*sendfile_filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	loff_t				sendfile_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	size_t				sendfile_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	/* cancel works */`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	int                             async_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	void                            **cancel_argv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	void                            (*cancel_fn)(void **argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	struct work_struct              work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	/* List head at conn->requests */`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	struct list_head                request_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	/* List head at conn->async_requests */`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	struct list_head                async_request_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	struct list_head                fp_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	/* Read data buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	void                            *aux_payload_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	/* Read data count */`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	unsigned int                    aux_payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	/* response smb header size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	unsigned int                    resp_hdr_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` * ksmbd_resp_buf_next - Get next buffer on compound response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * @work: smb work containing response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `static inline void *ksmbd_resp_buf_next(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	return work->response_buf + work->next_smb2_rsp_hdr_off + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * ksmbd_resp_buf_curr - Get current buffer on compound response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * @work: smb work containing response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `static inline void *ksmbd_resp_buf_curr(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	return work->response_buf + work->curr_smb2_rsp_hdr_off + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` * ksmbd_req_buf_next - Get next buffer on compound request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` * @work: smb work containing response buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `static inline void *ksmbd_req_buf_next(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	return work->request_buf + work->next_smb2_rcv_hdr_off + 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `struct ksmbd_work *ksmbd_alloc_work_struct(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `void ksmbd_free_work_struct(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `void ksmbd_work_pool_destroy(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `int ksmbd_work_pool_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `int ksmbd_workqueue_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `void ksmbd_workqueue_destroy(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `bool ksmbd_queue_work(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `int ksmbd_iov_pin_rsp_read(struct ksmbd_work *work, void *ib, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `			   void *aux_buf, unsigned int aux_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `int ksmbd_iov_pin_rsp(struct ksmbd_work *work, void *ib, int len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `int allocate_interim_rsp_buf(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `#endif /* __KSMBD_WORK_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
