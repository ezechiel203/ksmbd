# Line-by-line Review: src/core/ksmbd_work.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2019 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/mm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `static struct kmem_cache *work_cache;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `static struct workqueue_struct *ksmbd_wq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `struct ksmbd_work *ksmbd_alloc_work_struct(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	struct ksmbd_work *work = kmem_cache_zalloc(work_cache, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	if (work) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `		work->compound_fid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `		work->compound_pfid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `		INIT_LIST_HEAD(&work->request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `		INIT_LIST_HEAD(&work->async_request_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `		INIT_LIST_HEAD(&work->fp_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `		INIT_LIST_HEAD(&work->aux_read_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `		work->iov_alloc_cnt = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [MEM_BOUNDS|] `		work->iov = kzalloc(sizeof(struct kvec) * work->iov_alloc_cnt,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00033 [NONE] `				    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `		if (!work->iov) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `			kmem_cache_free(work_cache, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `			work = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	return work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `void ksmbd_free_work_struct(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	struct aux_read *ar, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [ERROR_PATH|] `	WARN_ON(work->saved_cred != NULL);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	 * Release the async ID while conn is still guaranteed alive.`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	 * This must happen before any operation that might drop the`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	 * last reference to the connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	if (work->async_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `		ksmbd_release_id(&work->conn->async_ida, work->async_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	kvfree(work->response_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	kvfree(work->aux_payload_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	list_for_each_entry_safe(ar, tmp, &work->aux_read_list, entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `		ksmbd_buffer_pool_put(ar->buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `		list_del(&ar->entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `		kfree(ar);`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	kvfree(work->tr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	kvfree(work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	kfree(work->iov);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	if (work->sendfile_filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		fput(work->sendfile_filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	kmem_cache_free(work_cache, work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `void ksmbd_work_pool_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	kmem_cache_destroy(work_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	work_cache = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `int ksmbd_work_pool_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	work_cache = kmem_cache_create("ksmbd_work_cache",`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `				       sizeof(struct ksmbd_work), 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `				       SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `				       NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	if (!work_cache)`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00091 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `int ksmbd_workqueue_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	ksmbd_wq = alloc_workqueue("ksmbd-io", WQ_PERCPU, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	ksmbd_wq = alloc_workqueue("ksmbd-io", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	if (!ksmbd_wq)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00103 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `void ksmbd_workqueue_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	destroy_workqueue(ksmbd_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	ksmbd_wq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `bool ksmbd_queue_work(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	return queue_work(ksmbd_wq, &work->work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `static inline void __ksmbd_iov_pin(struct ksmbd_work *work, void *ib,`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `				   unsigned int ib_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	work->iov_idx++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	work->iov[work->iov_idx].iov_base = ib;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	work->iov[work->iov_idx].iov_len = ib_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	work->iov_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `static int __ksmbd_iov_pin_rsp(struct ksmbd_work *work, void *ib, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `			       void *aux_buf, unsigned int aux_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	struct aux_read *ar = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	int need_iov_cnt = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	if (aux_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		need_iov_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [MEM_BOUNDS|] `		ar = kmalloc(sizeof(struct aux_read), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00135 [NONE] `		if (!ar)`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00137 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	if (work->iov_alloc_cnt < work->iov_idx + 1 + need_iov_cnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		struct kvec *new;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		work->iov_alloc_cnt += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		new = krealloc(work->iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `			       sizeof(struct kvec) * work->iov_alloc_cnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `			       KSMBD_DEFAULT_GFP | __GFP_ZERO);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		if (!new) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `			kfree(ar);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `			work->iov_alloc_cnt -= 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00150 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		work->iov = new;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	/* Plus rfc_length size on first iov */`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	if (!work->iov_idx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		work->iov[work->iov_idx].iov_base = work->response_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		*(__be32 *)work->iov[0].iov_base = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `		work->iov[work->iov_idx].iov_len = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		work->iov_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	__ksmbd_iov_pin(work, ib, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	inc_rfc1001_len(work->iov[0].iov_base, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	if (aux_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		__ksmbd_iov_pin(work, aux_buf, aux_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		inc_rfc1001_len(work->iov[0].iov_base, aux_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		ar->buf = aux_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		list_add(&ar->entry, &work->aux_read_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `int ksmbd_iov_pin_rsp(struct ksmbd_work *work, void *ib, int len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	return __ksmbd_iov_pin_rsp(work, ib, len, NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `int ksmbd_iov_pin_rsp_read(struct ksmbd_work *work, void *ib, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `			   void *aux_buf, unsigned int aux_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	return __ksmbd_iov_pin_rsp(work, ib, len, aux_buf, aux_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `int allocate_interim_rsp_buf(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [MEM_BOUNDS|] `	work->response_buf = kzalloc(MAX_CIFS_SMALL_BUFFER_SIZE, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00190 [NONE] `	if (!work->response_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00192 [NONE] `	work->response_sz = MAX_CIFS_SMALL_BUFFER_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
