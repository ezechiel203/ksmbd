# Line-by-line Review: src/include/fs/ksmbd_info.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Info-level handler registration API for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [LIFETIME|] ` *   Provides an RCU-protected hash table for SMB2 QUERY_INFO and SET_INFO`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00009 [NONE] ` *   handler dispatch, keyed on (info_type, info_class, op).`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#ifndef __KSMBD_INFO_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#define __KSMBD_INFO_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * enum ksmbd_info_op - info operation type`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * @KSMBD_INFO_GET: query/get information (QUERY_INFO)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * @KSMBD_INFO_SET: set/modify information (SET_INFO)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `enum ksmbd_info_op {`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` * struct ksmbd_info_handler - Info-level dispatch entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * @info_type:  SMB2 info type (FILE, FILESYSTEM, SECURITY, QUOTA)`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` * @info_class: File/FS info class (e.g., FileBasicInformation)`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * @op:         GET or SET operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * @handler:    callback function`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *              For GET: fills buf, sets *out_len, returns 0 or -errno`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` *              For SET: reads buf of buf_len bytes, returns 0 or -errno`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * @owner:      module owning this handler (for reference counting)`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * @node:       hash table linkage`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [LIFETIME|] ` * @rcu:        RCU callback head for safe removal`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00044 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * Each registered handler is hashed by a composite key of`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [LIFETIME|] ` * (info_type, info_class, op) into an RCU-protected hash table.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00047 [LIFETIME|] ` * The dispatch path looks up handlers under rcu_read_lock and`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00048 [NONE] ` * invokes the callback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `struct ksmbd_info_handler {`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	u8 info_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	u8 info_class;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	enum ksmbd_info_op op;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	int (*handler)(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `		       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `		       void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `		       unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `		       unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	struct module *owner;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	struct hlist_node node;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [LIFETIME|] `	struct rcu_head rcu;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00062 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * ksmbd_register_info_handler() - Register an info-level handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * @h: handler descriptor (caller must keep alive until unregistered)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [LIFETIME|] ` * Adds the handler to the RCU-protected dispatch table.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00069 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * Return: 0 on success, -EEXIST if (info_type, info_class, op) already`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` *         registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `int ksmbd_register_info_handler(struct ksmbd_info_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * ksmbd_unregister_info_handler() - Unregister an info-level handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` * @h: handler descriptor previously passed to ksmbd_register_info_handler()`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [LIFETIME|] ` * Removes the handler and waits for an RCU grace period so that`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00080 [NONE] ` * in-flight lookups complete safely.`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` * ksmbd_dispatch_info() - Look up and invoke a registered info handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ` * @work:       smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` * @fp:         ksmbd file pointer (may be NULL for filesystem-level queries)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * @info_type:  SMB2 info type`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * @info_class: info class within the type`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * @op:         GET or SET operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * @buf:        pointer to data buffer (response buffer for GET, request`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` *              buffer for SET)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * @buf_len:    buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * @out_len:    [out] number of bytes written (GET) or consumed (SET)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` *         handler is registered for the given key.`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `int ksmbd_dispatch_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `			struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `			u8 info_type, u8 info_class,`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			enum ksmbd_info_op op,`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `			void *buf, unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `			unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * ksmbd_info_get_file_stat_lx() - FileStatLxInformation (class 71) handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * @fp:      ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * @buf:     response buffer to fill`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * @buf_len: available space in @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * @out_len: [out] bytes written to @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` * Called directly (not via dispatch) from smb2_get_info_file() case 71`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` * because FILE_CASE_SENSITIVE_INFORMATION is also class 71 and occupies`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [PROTO_GATE|] ` * the dispatch slot for (SMB2_O_INFO_FILE, 71, KSMBD_INFO_GET).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00117 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `int ksmbd_info_get_file_stat_lx(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `				void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `				unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` * ksmbd_info_init() - Initialize the info-level dispatch table`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * Currently empty — no handlers are migrated yet.  Infrastructure is`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` * ready for incremental migration from the monolithic switch statements`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` * in smb2pdu.c (smb2_get_info_file, smb2_set_info_file,`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` * smb2_get_info_filesystem).`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `int ksmbd_info_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * ksmbd_info_exit() - Tear down the info-level dispatch table`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * Currently empty — no handlers registered yet.`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `void ksmbd_info_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `#endif /* __KSMBD_INFO_H */`
  Review: Low-risk line; verify in surrounding control flow.
