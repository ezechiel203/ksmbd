# Line-by-line Review: src/fs/ksmbd_info.c

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
- L00006 [NONE] ` *   Info-level handler registration table for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [LIFETIME|] ` *   Provides an RCU-protected hash table for dispatching SMB2 QUERY_INFO`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00009 [NONE] ` *   and SET_INFO requests, keyed on (info_type, info_class, op).`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   Handlers can be registered by core and extension modules.`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/path.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <linux/nls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <linux/fileattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "xattr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `/* 256 buckets (2^8) -- sufficient for all SMB2 info classes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define KSMBD_INFO_HASH_BITS	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `static DEFINE_HASHTABLE(info_handlers, KSMBD_INFO_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `static DEFINE_SPINLOCK(info_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * info_hash_key() - compute hash key from info type, class, and operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * @info_type:  SMB2 info type (FILE, FILESYSTEM, SECURITY, QUOTA)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` * @info_class: info class within the type`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * @op:         GET or SET operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` * Return: composite 32-bit hash key`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `static inline u32 info_hash_key(u8 info_type, u8 info_class,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `				enum ksmbd_info_op op)`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	return (u32)info_type << 16 | (u32)info_class << 8 | (u32)op;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * ksmbd_register_info_handler() - Register an info-level handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * @h: handler descriptor (caller must keep alive until unregistered)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * Adds the handler to the hash table under spinlock using hash_add_rcu.`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * Checks for duplicates before insertion.`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * Return: 0 on success, -EEXIST if (info_type, info_class, op) already`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` *         registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `int ksmbd_register_info_handler(struct ksmbd_info_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	struct ksmbd_info_handler *cur;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	u32 key = info_hash_key(h->info_type, h->info_class, h->op);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [LOCK|] `	spin_lock(&info_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00077 [NONE] `	hash_for_each_possible_rcu(info_handlers, cur, node, key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		if (cur->info_type == h->info_type &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `		    cur->info_class == h->info_class &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `		    cur->op == h->op) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [LOCK|] `			spin_unlock(&info_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00082 [ERROR_PATH|] `			pr_err("Info handler (type=%u, class=%u, op=%d) already registered\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00083 [NONE] `			       h->info_type, h->info_class, h->op);`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [ERROR_PATH|] `			return -EEXIST;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00085 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	hash_add_rcu(info_handlers, &h->node, key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [LOCK|] `	spin_unlock(&info_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00089 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * ksmbd_unregister_info_handler() - Unregister an info-level handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * @h: handler descriptor previously registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [LIFETIME|] ` * Removes the handler under spinlock and waits for an RCU grace period`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00097 [NONE] ` * so that in-flight lookups complete safely.`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [LOCK|] `	spin_lock(&info_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00102 [NONE] `	hash_del_rcu(&h->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [LOCK|] `	spin_unlock(&info_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00104 [NONE] `	synchronize_rcu();`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * ksmbd_dispatch_info() - Look up and invoke a registered info handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * @work:       smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * @fp:         ksmbd file pointer (may be NULL for filesystem-level queries)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * @info_type:  SMB2 info type`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * @info_class: info class within the type`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` * @op:         GET or SET operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` * @buf:        pointer to data buffer (response buffer for GET, request`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` *              buffer for SET)`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * @buf_len:    buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * @out_len:    [out] number of bytes written (GET) or consumed (SET)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [LIFETIME|] ` * Performs an RCU-protected hash lookup, takes a module reference on the`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00120 [NONE] ` * owning module, and invokes the handler callback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` *         handler is registered for the given key.`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `int ksmbd_dispatch_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `			struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `			u8 info_type, u8 info_class,`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `			enum ksmbd_info_op op,`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `			void *buf, unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `			unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	struct ksmbd_info_handler *h;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	u32 key = info_hash_key(info_type, info_class, op);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	int ret = -EOPNOTSUPP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00139 [NONE] `	hash_for_each_possible_rcu(info_handlers, h, node, key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		if (h->info_type != info_type ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		    h->info_class != info_class ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		    h->op != op)`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		if (!try_module_get(h->owner)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00147 [ERROR_PATH|] `			return -ENODEV;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00148 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		ret = h->handler(work, fp, buf, buf_len, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `		module_put(h->owner);`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ` * FILE_NAME_INFORMATION (class 9) GET handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` * Returns the file path relative to the share root encoded as`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * UTF-16LE.  The response layout is:`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` *   4 bytes  FileNameLength (in bytes, of the UTF-16LE name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` *   variable FileName[]     (UTF-16LE, NOT null-terminated)`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` * ksmbd_info_get_file_name() - FILE_NAME_INFORMATION query handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` * @fp:      ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ` * @buf:     response buffer to fill`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ` * @buf_len: available space in @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ` * @out_len: [out] bytes written to @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ` * Retrieves the file path relative to the share root, converts it`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] ` * to UTF-16LE, and writes FileNameLength + FileName into @buf.`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `static int ksmbd_info_get_file_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `				    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `				    void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `				    unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `				    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	char *filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	__le32 *name_len_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	unsigned int min_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	unsigned int max_utf16_chars;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	/* Need at least 4 bytes for FileNameLength */`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	min_len = sizeof(__le32);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	if (buf_len < min_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00202 [NONE] `	max_utf16_chars = (buf_len - min_len) / sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	if (!max_utf16_chars)`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	filename = convert_to_nt_pathname(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `					  &fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `		return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		    "FILE_NAME_INFORMATION: filename = %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `		    filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	name_len_ptr = (__le32 *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	 * Convert filename to UTF-16LE after the 4-byte length`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	 * field.  smbConvertToUTF16 returns the number of`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	 * UTF-16 code units written.`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	conv_len = smbConvertToUTF16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `			(__le16 *)((char *)buf + sizeof(__le32)),`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `			filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `			max_utf16_chars,`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `			conn->local_nls,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `			0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00231 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	conv_len *= 2; /* code units -> bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	if (sizeof(__le32) + conv_len > buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00237 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	*name_len_ptr = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	*out_len = sizeof(__le32) + conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` * FS_CONTROL_INFORMATION (class 6) SET handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ` * Accepts and validates an smb2_fs_control_info structure from the`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` * client.  Quota control is not supported by most Linux filesystems`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` * so this handler accepts the request and returns success, matching`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ` * Windows server behavior for non-quota filesystems.`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ` * ksmbd_info_set_fs_control() - FS_CONTROL_INFORMATION set handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ` * @fp:      ksmbd file pointer (may be NULL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ` * @buf:     request data buffer containing smb2_fs_control_info`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ` * @buf_len: length of request data`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ` * @out_len: [out] bytes consumed from @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` * Validates the buffer size and accepts the FS control information.`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` * Quota enforcement is not implemented; the handler returns success`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ` * to match typical Windows server behavior on non-quota volumes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ` * Return: 0 on success, -EMSGSIZE if buffer too small`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `static int ksmbd_info_set_fs_control(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `				     struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `				     void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `				     unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `				     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	if (buf_len < sizeof(struct smb2_fs_control_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		    "FS_CONTROL_INFORMATION SET: accepted (quota not enforced)\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	*out_len = sizeof(struct smb2_fs_control_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] ` * FILE_PIPE_INFORMATION (class 23) GET handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ` * Returns pipe read mode and completion mode.  Since ksmbd does not`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ` * serve named pipes directly, return default values (byte-stream`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] ` * mode, blocking completion).`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ` * ksmbd_info_get_pipe() - FILE_PIPE_INFORMATION query handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ` * @fp:      ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ` * @buf:     response buffer to fill`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ` * @buf_len: available space in @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ` * @out_len: [out] bytes written to @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `static int ksmbd_info_get_pipe(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `			       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `			       void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `			       unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `			       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	struct smb2_file_pipe_info *pipe_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	if (buf_len < sizeof(struct smb2_file_pipe_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	pipe_info = (struct smb2_file_pipe_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	pipe_info->ReadMode = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	pipe_info->CompletionMode = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	*out_len = sizeof(struct smb2_file_pipe_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `		    "FILE_PIPE_INFORMATION: default response\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] ` * FILE_PIPE_LOCAL_INFORMATION (class 24) GET handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ` * Returns local pipe information.  Since ksmbd does not serve named`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ` * pipes directly, return default values for all fields.`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ` * ksmbd_info_get_pipe_local() - FILE_PIPE_LOCAL_INFORMATION query handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ` * @fp:      ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ` * @buf:     response buffer to fill`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] ` * @buf_len: available space in @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ` * @out_len: [out] bytes written to @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `static int ksmbd_info_get_pipe_local(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `				     struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				     void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `				     unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `				     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	struct smb2_file_pipe_local_info *pipe_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	if (buf_len < sizeof(struct smb2_file_pipe_local_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	pipe_info = (struct smb2_file_pipe_local_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	pipe_info->NamedPipeType = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	pipe_info->NamedPipeConfiguration = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	pipe_info->MaximumInstances = cpu_to_le32(0xFFFFFFFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	pipe_info->CurrentInstances = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	pipe_info->InboundQuota = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	pipe_info->ReadDataAvailable = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	pipe_info->OutboundQuota = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	pipe_info->WriteQuotaAvailable = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	pipe_info->NamedPipeState = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	pipe_info->NamedPipeEnd = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	*out_len = sizeof(struct smb2_file_pipe_local_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		    "FILE_PIPE_LOCAL_INFORMATION: default response\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `struct smb2_file_pipe_remote_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	__le64 CollectDataTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	__le32 MaximumCollectionCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	__le32 CollectDataTimeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `static int ksmbd_info_get_pipe_remote(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `				      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `				      void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `				      unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `				      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	struct smb2_file_pipe_remote_info *pipe_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	if (buf_len < sizeof(*pipe_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00388 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	pipe_info = (struct smb2_file_pipe_remote_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	memset(pipe_info, 0, sizeof(*pipe_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	*out_len = sizeof(*pipe_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `struct smb2_file_mailslot_query_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	__le32 MaximumMessageSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	__le32 MailslotQuota;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	__le32 NextMessageSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	__le32 MessagesAvailable;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	__le64 ReadTimeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `struct smb2_file_mailslot_set_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	__le64 ReadTimeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `static int ksmbd_info_get_mailslot_query(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `					 struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `					 void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `					 unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	struct smb2_file_mailslot_query_info *mail_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	if (buf_len < sizeof(*mail_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	mail_info = (struct smb2_file_mailslot_query_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	memset(mail_info, 0, sizeof(*mail_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	*out_len = sizeof(*mail_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `static int ksmbd_info_set_mailslot(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `				   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `				   void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `				   unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `				   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	if (buf_len < sizeof(struct smb2_file_mailslot_set_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	*out_len = sizeof(struct smb2_file_mailslot_set_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `static int ksmbd_info_set_pipe_info(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `				    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `				    void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `				    unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `				    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	if (buf_len < sizeof(struct smb2_file_pipe_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `	*out_len = sizeof(struct smb2_file_pipe_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `static int ksmbd_info_set_pipe_remote(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `				      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `				      void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `				      unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `				      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	if (buf_len < sizeof(struct smb2_file_pipe_remote_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	*out_len = sizeof(struct smb2_file_pipe_remote_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `static int ksmbd_info_set_noop_consume(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `				       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `				       void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `				       unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		    "SET_INFO noop: silently consuming %u bytes (unimplemented info class)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `		    buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	*out_len = buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `struct smb2_file_links_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	__le32 BytesNeeded;`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	__le32 EntriesReturned;`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `struct smb2_file_link_entry_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	__le32 NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	__u8 ParentFileId[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	__le16 FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ` * Context for iterate_dir callback that collects filenames whose inode`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ` * number matches a target inode (hard link siblings).`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `struct ksmbd_hardlink_scan_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	struct dir_context ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	u64 target_ino;          /* inode number to match */`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	/* Output buffer management */`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	char *buf;               /* response buffer start */`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	unsigned int buf_len;    /* total buffer capacity */`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	unsigned int written;    /* bytes written so far */`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	/* Entries written */`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	u32 entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	/* Pointer to previous entry for NextEntryOffset chain */`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	struct smb2_file_link_entry_info *prev_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	/* NLS for UTF-16 conversion */`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	struct nls_table *nls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	/* Total bytes needed (even if we ran out of buffer space) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	u32 bytes_needed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	int error;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `static bool ksmbd_hardlink_filldir(struct dir_context *ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `				   const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `				   loff_t offset, u64 ino,`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `				   unsigned int d_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `static int ksmbd_hardlink_filldir(struct dir_context *ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `				  const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `				  loff_t offset, u64 ino,`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `				  unsigned int d_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	struct ksmbd_hardlink_scan_ctx *scan_ctx =`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		container_of(ctx, struct ksmbd_hardlink_scan_ctx, ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	struct smb2_file_link_entry_info *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	unsigned int entry_hdr_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	unsigned int name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	unsigned int entry_total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	/* Only interested in entries matching the target inode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	if (ino != scan_ctx->target_ino)`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [ERROR_PATH|] `		goto cont;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	/* Skip . and .. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	if (namlen <= 2 && name[0] == '.' &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	    (namlen == 1 || name[1] == '.'))`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [ERROR_PATH|] `		goto cont;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	entry_hdr_size = offsetof(struct smb2_file_link_entry_info, FileName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	 * Estimate name size: worst case is 2 bytes per source byte.`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	 * Actual conversion may differ, so we pre-convert into a temporary`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	 * buffer to get the real size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `		__le16 *tmp_utf16;`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `		unsigned int max_chars;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `		/* Allocate temporary buffer for UTF-16 conversion */`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `		tmp_utf16 = kcalloc(namlen + 1, sizeof(__le16),`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `				    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		if (!tmp_utf16) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `			scan_ctx->error = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00565 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		max_chars = namlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		conv_len = smbConvertToUTF16(tmp_utf16, name, max_chars,`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `					     scan_ctx->nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `		if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `			kfree(tmp_utf16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [ERROR_PATH|] `			goto cont;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00574 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		name_bytes = (unsigned int)conv_len * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		/* Align to 8 bytes for NextEntryOffset chain */`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `		entry_total = ALIGN(entry_hdr_size + name_bytes, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `		/* Track how much space this would need */`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		scan_ctx->bytes_needed += entry_total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `		/* Check if we have room in the output buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `		if (scan_ctx->written + sizeof(struct smb2_file_links_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `		    entry_total <= scan_ctx->buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `			entry = (struct smb2_file_link_entry_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `				(scan_ctx->buf +`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `				 sizeof(struct smb2_file_links_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `				 scan_ctx->written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `			/* Link previous entry to this one */`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `			if (scan_ctx->prev_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `				scan_ctx->prev_entry->NextEntryOffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `					cpu_to_le32(entry_total);`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `			entry->NextEntryOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `			memset(entry->ParentFileId, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `			       sizeof(entry->ParentFileId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `			entry->FileNameLength = cpu_to_le32(name_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [MEM_BOUNDS|] `			memcpy(entry->FileName, tmp_utf16, name_bytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `			scan_ctx->written += entry_total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `			scan_ctx->entries++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `			scan_ctx->prev_entry = entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `		kfree(tmp_utf16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `cont:`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `static int ksmbd_info_get_hard_link(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `				    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `				    void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `				    unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `				    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	struct smb2_file_links_info *links_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	struct path parent_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `	struct file *parent_filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `	struct ksmbd_hardlink_scan_ctx scan_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `	/* Need at least the links_info header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	if (buf_len < sizeof(*links_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	ret = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	links_info = (struct smb2_file_links_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	 * If nlink == 1, fast path: only one link exists (the current file).`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	 * Return a single entry using the current file's name.`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	if (stat.nlink <= 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `		struct smb2_file_link_entry_info *entry_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `		char *filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		__le16 *utf16_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `		unsigned int name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		unsigned int needed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `		int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		filename = convert_to_nt_pathname(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `						  &fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `		if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `			return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `		/* Use just the base name (last component after last '\') */`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `			char *base = strrchr(filename, '\\');`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `			if (base)`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `				base++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `				base = filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `			utf16_name = kcalloc(PATH_MAX + 1, sizeof(__le16),`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `					     KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `			if (!utf16_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `				kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00675 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `			conv_len = smbConvertToUTF16(utf16_name, base, PATH_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `						     conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `			if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `				kfree(utf16_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `				kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [ERROR_PATH|] `				return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00683 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `		name_bytes = conv_len * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `		needed = sizeof(*links_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `			 offsetof(struct smb2_file_link_entry_info, FileName) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `			 name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `		if (buf_len < needed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `			kfree(utf16_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `			kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `			links_info->BytesNeeded = cpu_to_le32(needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `			links_info->EntriesReturned = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `			*out_len = sizeof(*links_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00698 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `		entry_info = (struct smb2_file_link_entry_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `			((char *)buf + sizeof(*links_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `		links_info->BytesNeeded = cpu_to_le32(needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `		links_info->EntriesReturned = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `		entry_info->NextEntryOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `		memset(entry_info->ParentFileId, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `		       sizeof(entry_info->ParentFileId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `		entry_info->FileNameLength = cpu_to_le32(name_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [MEM_BOUNDS|] `		memcpy(entry_info->FileName, utf16_name, name_bytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00710 [NONE] `		*out_len = needed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		kfree(utf16_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	 * nlink > 1: enumerate all sibling hard links by opening the parent`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `	 * directory and iterating its entries for matching inode numbers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	parent_path.mnt = fp->filp->f_path.mnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	parent_path.dentry = dget_parent(fp->filp->f_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	parent_filp = dentry_open(&parent_path, O_RDONLY | O_DIRECTORY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `				  current_cred());`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	dput(parent_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `	if (IS_ERR(parent_filp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `		 * Cannot open parent — fall back to single-entry response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `		 * This can happen if the client lacks read access to the parent.`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [ERROR_PATH|] `		goto fallback_single;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00733 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	memset(&scan_ctx, 0, sizeof(scan_ctx));`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	scan_ctx.target_ino = stat.ino;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	scan_ctx.buf = (char *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	scan_ctx.buf_len = buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	scan_ctx.written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `	scan_ctx.entries = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	scan_ctx.prev_entry = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	scan_ctx.nls = conn->local_nls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	scan_ctx.bytes_needed = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	set_ctx_actor(&scan_ctx.ctx, ksmbd_hardlink_filldir);`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `	ret = iterate_dir(parent_filp, &scan_ctx.ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	fput(parent_filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	if (scan_ctx.error) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `		if (scan_ctx.error == -ENOMEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00752 [ERROR_PATH|] `		goto fallback_single;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00753 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	if (scan_ctx.entries == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `		/* Nothing found in parent (race?) -- fall back */`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [ERROR_PATH|] `		goto fallback_single;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00758 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	links_info->BytesNeeded =`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `		cpu_to_le32(sizeof(*links_info) + scan_ctx.bytes_needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	links_info->EntriesReturned = cpu_to_le32(scan_ctx.entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	*out_len = sizeof(*links_info) + scan_ctx.written;`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `fallback_single:`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	 * Fallback: return the single current-name entry.`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	 * Same as the nlink==1 fast path above.`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `		struct smb2_file_link_entry_info *entry_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `		char *filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `		char *base;`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `		__le16 *utf16_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `		unsigned int name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `		unsigned int needed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `		int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `		filename = convert_to_nt_pathname(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `						  &fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `		if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `			return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `		base = strrchr(filename, '\\');`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `		if (base)`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `			base++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `			base = filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `		utf16_name = kcalloc(PATH_MAX + 1, sizeof(__le16),`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `				     KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `		if (!utf16_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `			kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00796 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `		conv_len = smbConvertToUTF16(utf16_name, base, PATH_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `					     conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `		if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `			kfree(utf16_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `			kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00804 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `		name_bytes = conv_len * sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `		needed = sizeof(*links_info) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `			 offsetof(struct smb2_file_link_entry_info, FileName) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `			 name_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `		if (buf_len < needed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `			kfree(utf16_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `			kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `			links_info->BytesNeeded = cpu_to_le32(needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `			links_info->EntriesReturned = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `			*out_len = sizeof(*links_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00818 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `		entry_info = (struct smb2_file_link_entry_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `			((char *)buf + sizeof(*links_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `		links_info->BytesNeeded = cpu_to_le32(needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `		links_info->EntriesReturned = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `		entry_info->NextEntryOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `		memset(entry_info->ParentFileId, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `		       sizeof(entry_info->ParentFileId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `		entry_info->FileNameLength = cpu_to_le32(name_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [MEM_BOUNDS|] `		memcpy(entry_info->FileName, utf16_name, name_bytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00830 [NONE] `		*out_len = needed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		kfree(utf16_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] ` * FILE_VALID_DATA_LENGTH_INFORMATION (class 39) SET handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] ` * Sets the valid data length for a file.  Uses vfs_fallocate()`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ` * with FALLOC_FL_KEEP_SIZE to pre-allocate without changing`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] ` * the file size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] ` * ksmbd_info_set_valid_data_length() - FILE_VALID_DATA_LENGTH set handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] ` * @fp:      ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] ` * @buf:     request data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ` * @buf_len: length of request data`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] ` * @out_len: [out] bytes consumed from @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `static int ksmbd_info_set_valid_data_length(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `					    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `					    void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `					    unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `					    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `	struct smb2_file_valid_data_length_info *vdl_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `	loff_t length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00868 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `	if (buf_len < sizeof(struct smb2_file_valid_data_length_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00871 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	vdl_info = (struct smb2_file_valid_data_length_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	length = le64_to_cpu(vdl_info->ValidDataLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `	if (length < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `		    "FILE_VALID_DATA_LENGTH_INFORMATION SET: length=%lld\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `		    length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `	smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `	rc = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0, length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	if (rc && rc != -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [ERROR_PATH|] `		pr_err("vfs_fallocate for valid data length failed: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00887 [NONE] `		       rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `	*out_len = sizeof(struct smb2_file_valid_data_length_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] ` * FILE_NORMALIZED_NAME_INFORMATION (class 48) GET handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] ` * Returns the normalized (canonical) name of the file using the`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] ` * dentry path.  The response layout matches FILE_NAME_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] ` *   4 bytes  FileNameLength (in bytes, of the UTF-16LE name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] ` *   variable FileName[]     (UTF-16LE, NOT null-terminated)`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] ` * ksmbd_info_get_normalized_name() - FILE_NORMALIZED_NAME query handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] ` * @fp:      ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] ` * @buf:     response buffer to fill`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] ` * @buf_len: available space in @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ` * @out_len: [out] bytes written to @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `static int ksmbd_info_get_normalized_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `					  struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `					  void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `					  unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `					  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	char *filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `	__le32 *name_len_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `	unsigned int min_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	unsigned int max_utf16_chars;`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00929 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `	 * FILE_NORMALIZED_NAME_INFORMATION is only valid for SMB 3.1.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	 * and later (MS-SMB2 2.2.37).  Return -ENOSYS for earlier`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [PROTO_GATE|] `	 * dialects, which the caller maps to STATUS_NOT_SUPPORTED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00934 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `	if (conn->dialect < SMB311_PROT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [ERROR_PATH|] `		return -ENOSYS;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00937 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	/* Need at least 4 bytes for FileNameLength */`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	min_len = sizeof(__le32);`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	if (buf_len < min_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00942 [NONE] `	max_utf16_chars = (buf_len - min_len) / sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	if (!max_utf16_chars)`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00945 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	filename = convert_to_nt_pathname(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `					  &fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `		return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `		    "FILE_NORMALIZED_NAME_INFORMATION: filename = %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `		    filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `	name_len_ptr = (__le32 *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `	 * Per MS-FSCC 2.1.5 / smbtorture expectations: the root of`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `	 * a share (just "\") should return an empty (zero-length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `	 * normalized name.`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	if (!strcmp(filename, "\\")) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `		*name_len_ptr = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `		*out_len = sizeof(__le32);`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	 * Per MS-FSCC 2.1.7, the normalized name is relative to the`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	 * share root and does not include a leading path separator.`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	 * convert_to_nt_pathname returns a leading '\' which we skip.`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `	 * For stream handles, append the stream name (":streamname")`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `	 * to match the format the client used when opening.`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `		char *name_start = filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		char *full_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `		if (*name_start == '\\')`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `			name_start++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `		 * If this is a stream handle, append the stream name.`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `		 * fp->stream.name has the xattr format:`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `		 *   "user.DosStream.<name>:<type>"`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `		 * Extract just the "<name>" part.`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `		if (ksmbd_stream_fd(fp) && fp->stream.name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `			const char *sname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `			const char *colon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `			size_t sname_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `			sname = &fp->stream.name[XATTR_NAME_STREAM_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `			/* Strip the :$DATA or :$INDEX_ALLOCATION suffix */`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `			colon = strrchr(sname, ':');`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `			sname_len = colon ? (size_t)(colon - sname) : strlen(sname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `			full_name = kasprintf(KSMBD_DEFAULT_GFP,`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `					      "%s:%.*s", name_start,`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `					      (int)sname_len, sname);`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `			if (!full_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `				kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01006 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `			name_start = full_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `		conv_len = smbConvertToUTF16(`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `				(__le16 *)((char *)buf + sizeof(__le32)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `				name_start,`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `				max_utf16_chars,`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `				conn->local_nls,`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `				0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		kfree(full_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `	if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01022 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `	conv_len *= 2; /* code units -> bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	if (sizeof(__le32) + conv_len > buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01028 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `	*name_len_ptr = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `	*out_len = sizeof(__le32) + conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `struct smb2_file_process_ids_using_file_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	__le32 NumberOfProcessIdsInList;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	__le64 ProcessIdList[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `static int ksmbd_info_get_process_ids_using_file(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `						 struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `						 void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `						 unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `						 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	struct smb2_file_process_ids_using_file_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `	info = (struct smb2_file_process_ids_using_file_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `	info->NumberOfProcessIdsInList = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `	info->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `struct smb2_file_network_physical_name_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `	__le32 FileNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	__le16 FileName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `static int ksmbd_info_get_network_physical_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `						struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `						void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `						unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `						unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `	struct ksmbd_share_config *share = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	char *filename, *network_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	__le32 *name_len_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `	unsigned int max_utf16_chars;`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `	if (!fp || !share || !share->name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `	if (buf_len < sizeof(__le32))`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01084 [NONE] `	max_utf16_chars = (buf_len - sizeof(__le32)) / sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	if (!max_utf16_chars)`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	filename = convert_to_nt_pathname(share, &fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `		return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	if (filename[0] == '\\' || filename[0] == '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `		network_name = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\%s%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `					 ksmbd_netbios_name(), share->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `					 filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `		network_name = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\%s\\%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `					 ksmbd_netbios_name(), share->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `					 filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	kfree(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	if (!network_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	ksmbd_conv_path_to_windows(network_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `	name_len_ptr = (__le32 *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `	conv_len = smbConvertToUTF16((__le16 *)((char *)buf + sizeof(__le32)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `				     network_name, max_utf16_chars,`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `				     conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `	kfree(network_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `	if (conv_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `	conv_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	if (sizeof(__le32) + conv_len > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	*name_len_ptr = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `	*out_len = sizeof(__le32) + conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `struct smb2_file_volume_name_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	__le32 DeviceNameLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	__le16 DeviceName[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `static int ksmbd_info_get_volume_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `				      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `				      void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `				      unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `				      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	struct ksmbd_share_config *share = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	char *volume_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	__le32 *name_len_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `	unsigned int max_utf16_chars;`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	if (!share || !share->name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	if (buf_len < sizeof(__le32))`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01147 [NONE] `	max_utf16_chars = (buf_len - sizeof(__le32)) / sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `	if (!max_utf16_chars)`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	volume_name = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s", share->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `	if (!volume_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `	name_len_ptr = (__le32 *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `	conv_len = smbConvertToUTF16((__le16 *)((char *)buf + sizeof(__le32)),`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `				     volume_name, max_utf16_chars,`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `				     conn->local_nls, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `	kfree(volume_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	if (conv_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `	conv_len *= 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `	if (sizeof(__le32) + conv_len > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `	*name_len_ptr = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `	*out_len = sizeof(__le32) + conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `struct smb2_file_is_remote_device_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `static int ksmbd_info_get_is_remote_device(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `					   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `					   void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `					   unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `					   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `	struct smb2_file_is_remote_device_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `	info = (struct smb2_file_is_remote_device_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `	info->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] ` * FILE_REMOTE_PROTOCOL_INFORMATION (class 55) response.`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] ` * MS-FSCC defines a fixed-size structure that reports the network`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] ` * redirector protocol and version details.`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `struct smb2_file_remote_protocol_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	__le16 StructureVersion;`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	__le16 StructureSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `	__le32 Protocol;`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `	__le16 ProtocolMajorVersion;`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `	__le16 ProtocolMinorVersion;`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	__le16 ProtocolRevision;`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `	__le32 GenericReserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	__le32 ProtocolSpecificReserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `#define KSMBD_REMOTE_PROTOCOL_WNNC_NET_LANMAN	0x00020000`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `static void ksmbd_info_fill_remote_protocol_version(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `						    struct smb2_file_remote_protocol_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `	u16 major = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	u16 minor = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `	u16 rev = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	if (!conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	switch (conn->dialect) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	case SMB20_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `		major = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `		minor = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `		rev = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	case SMB21_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `		major = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `		minor = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `		rev = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	case SMB30_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `		major = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `		minor = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `		rev = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	case SMB302_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `		major = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `		minor = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `		rev = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	case SMB311_PROT_ID:`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `		major = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `		minor = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `		rev = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	info->ProtocolMajorVersion = cpu_to_le16(major);`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `	info->ProtocolMinorVersion = cpu_to_le16(minor);`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	info->ProtocolRevision = cpu_to_le16(rev);`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `static int ksmbd_info_get_remote_protocol(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `					  struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `					  void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `					  unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `					  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	struct smb2_file_remote_protocol_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `	info = (struct smb2_file_remote_protocol_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	memset(info, 0, sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	info->StructureVersion = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	info->StructureSize = cpu_to_le16(sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	info->Protocol = cpu_to_le32(KSMBD_REMOTE_PROTOCOL_WNNC_NET_LANMAN);`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	ksmbd_info_fill_remote_protocol_version(work->conn, info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `struct smb2_file_case_sensitive_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `static int ksmbd_info_get_case_sensitive(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `					 struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `					 void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `					 unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	struct smb2_file_case_sensitive_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	info = (struct smb2_file_case_sensitive_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	info->Flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `static int ksmbd_info_set_case_sensitive(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `					 struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `					 void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `					 unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	struct smb2_file_case_sensitive_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `	struct file_kattr fa;`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `	u32 flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	u32 cur_iflags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	info = (struct smb2_file_case_sensitive_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `	flags = le32_to_cpu(info->Flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `	if (flags & ~FILE_CS_FLAG_CASE_SENSITIVE_DIR)`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	dentry = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	 * Read current file attributes so we can modify just the`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `	 * FS_CASEFOLD_FL bit without disturbing other flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `	memset(&fa, 0, sizeof(fa));`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `	ret = vfs_fileattr_get(dentry, &fa);`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `		 * If the filesystem does not support fileattr, treat as`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] `		 * not supported.`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `		if (ret == -ENOTTY || ret == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [ERROR_PATH|] `			return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01340 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	cur_iflags = fa.flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `	if (flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `		/* Enable case-sensitive (disable casefolding) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `		cur_iflags &= ~FS_CASEFOLD_FL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `		/* Disable case-sensitive (enable casefolding) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `		cur_iflags |= FS_CASEFOLD_FL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `	 * Only issue the set call if the flag actually changed, to`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	 * avoid unnecessary permission checks.`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	if (cur_iflags == fa.flags) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `		*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	fileattr_fill_flags(&fa, cur_iflags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	ret = vfs_fileattr_set(file_mnt_idmap(fp->filp), dentry, &fa);`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	ret = vfs_fileattr_set(file_mnt_user_ns(fp->filp), dentry, &fa);`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `		if (ret == -EOPNOTSUPP || ret == -ENOTTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [ERROR_PATH|] `			return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01372 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `struct smb2_fs_driver_path_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	__u8 DriverInPath;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	__u8 Reserved[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `static int ksmbd_info_get_fs_driver_path(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `					 struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `					 void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `					 unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `	struct smb2_fs_driver_path_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	info = (struct smb2_fs_driver_path_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `	memset(info, 0, sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `struct smb2_fs_label_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `	__le32 VolumeLabelLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `	__le16 VolumeLabel[];`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `static int ksmbd_info_set_fs_label(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `				   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `				   void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `				   unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `				   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `	struct smb2_fs_label_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `	unsigned int consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `	u32 label_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `	info = (struct smb2_fs_label_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `	label_len = le32_to_cpu(info->VolumeLabelLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `	if (label_len & 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01423 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `	consumed = offsetof(struct smb2_fs_label_info, VolumeLabel) + label_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `	if (consumed > buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `	*out_len = consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `static int ksmbd_info_set_fs_object_id(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `				       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `				       void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `				       unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `	if (buf_len < sizeof(struct object_id_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [ERROR_PATH|] `		return -EMSGSIZE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `	*out_len = sizeof(struct object_id_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [PROTO_GATE|] ` * QUOTA_INFORMATION (type=SMB2_O_INFO_QUOTA, class=FILE_QUOTA_INFORMATION)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01447 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] ` * ksmbd currently does not implement full on-disk quota accounting in`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] ` * protocol responses. Return an empty result for GET and accept SET as a`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] ` * no-op for interoperability with clients that probe quota support.`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `static int ksmbd_info_get_quota(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `				void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `				unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `				unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] ` * ksmbd_info_set_quota - Quota SET handler (stub)`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] ` * Quota setting is not implemented in ksmbd.  Return success for`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] ` * compatibility with Windows clients that may attempt to set quota`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] ` * information.  The request payload is consumed but no quota is`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] ` * actually enforced on the underlying filesystem.`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `static int ksmbd_info_set_quota(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `				void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `				unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `				unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `		    "QUOTA SET: silently consuming %u bytes (quota not implemented)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `		    buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `	*out_len = buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] ` * G.3 — FileStatInformation (class 70 = 0x46, MS-FSCC §2.4.47)`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] ` * SMB3.1.1 extension providing large-file stat information.`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] ` * Layout (56 bytes):`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] ` *   FileId           __le64  inode number`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] ` *   CreationTime     __le64  FILETIME`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] ` *   LastAccessTime   __le64  FILETIME`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] ` *   LastWriteTime    __le64  FILETIME`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] ` *   ChangeTime       __le64  FILETIME`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] ` *   AllocationSize   __le64  blocks * 512`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] ` *   EndOfFile        __le64  file size`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] ` *   NumberOfLinks    __le32  nlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] ` *   DeletePending    __u8`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] ` *   Directory        __u8`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] ` *   Reserved         __le16  (padding)`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `#define FILE_STAT_INFORMATION		70`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `struct smb2_file_stat_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `	__le64 FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `	__le32 NumberOfLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `	__u8   DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `	__u8   Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `} __packed; /* 56 bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `static int ksmbd_info_get_file_stat(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `				    struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `				    void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `				    unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `				    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `	struct smb2_file_stat_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `	unsigned int delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `	ret = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `	delete_pending = ksmbd_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `	info = (struct smb2_file_stat_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	memset(info, 0, sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `	info->FileId = cpu_to_le64(stat.ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `	info->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `	info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `	info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `	info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] `	if (ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] `		info->AllocationSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `			cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `		info->EndOfFile =`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `			S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `		info->AllocationSize = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `		info->EndOfFile = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `	info->NumberOfLinks =`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `		cpu_to_le32(get_nlink(&stat) - delete_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] `	info->DeletePending = delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `	info->Directory = S_ISDIR(stat.mode) ? 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `	info->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] ` * G.4 — FileStatLxInformation (class 71 = 0x47, MS-FSCC §2.4.48)`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] ` * WSL/POSIX extension extending FileStatInformation with Linux-specific`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] ` * fields.  Try to read LxUid/LxGid/LxMode from xattrs (user.LXUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] ` * user.LXGID, user.LXMOD); fall back to uid/gid/mode from kstat.`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] ` * Note: FILE_CASE_SENSITIVE_INFORMATION is also numbered 71 in this`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] ` * codebase and is registered separately in the dispatch table under`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] ` * the same class number.  Since the dispatch table uses a hash lookup`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] ` * and the FILE_CASE_SENSITIVE handler is registered after this one,`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] ` * the CASE_SENSITIVE handler (from ksmbd_case_sensitive_get_handler)`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] ` * will shadow this entry.  FileStatLxInformation is therefore only`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] ` * reachable when explicitly requested via a FILE_STAT_LX_INFORMATION`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] ` * switch case added in smb2_get_info_file().`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `#define FILE_STAT_LX_INFORMATION	71`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `#define KSMBD_XATTR_NAME_LXUID  "user.LXUID"`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `#define KSMBD_XATTR_NAME_LXGID  "user.LXGID"`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `#define KSMBD_XATTR_NAME_LXMOD  "user.LXMOD"`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `struct smb2_file_stat_lx_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `	__le64 FileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `	__le64 CreationTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `	__le64 LastAccessTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] `	__le64 LastWriteTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] `	__le64 ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `	__le64 AllocationSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `	__le64 EndOfFile;`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `	__le32 NumberOfLinks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `	__u8   DeletePending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `	__u8   Directory;`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `	__le32 LxFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `	__le32 LxUid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `	__le32 LxGid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `	__le32 LxMode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `	__le32 LxDeviceIdMajor;`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `	__le32 LxDeviceIdMinor;`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `} __packed; /* 80 bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `int ksmbd_info_get_file_stat_lx(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `				struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `				void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `				unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `				unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `	struct smb2_file_stat_lx_info *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `	unsigned int delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `	u32 lx_uid, lx_gid, lx_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `	char *xattr_val = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `	ssize_t xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `	if (buf_len < sizeof(*info))`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `	ret = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `	delete_pending = ksmbd_inode_pending_delete(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `	info = (struct smb2_file_stat_lx_info *)buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `	memset(info, 0, sizeof(*info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `	info->FileId = cpu_to_le64(stat.ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `	info->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `	info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `	info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `	if (ksmbd_stream_fd(fp) == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `		info->AllocationSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `			cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `		info->EndOfFile =`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `			S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `		info->AllocationSize = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `		info->EndOfFile = cpu_to_le64(fp->stream.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `	info->NumberOfLinks =`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `		cpu_to_le32(get_nlink(&stat) - delete_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `	info->DeletePending = delete_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `	info->Directory = S_ISDIR(stat.mode) ? 1 : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `	 * Read LxUid/LxGid/LxMode from xattrs; fall back to uid/gid/mode`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `	 * from kstat when xattrs are absent.`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `				       KSMBD_XATTR_NAME_LXUID, &xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `	if (xattr_len == sizeof(u32) && xattr_val)`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [MEM_BOUNDS|] `		memcpy(&lx_uid, xattr_val, sizeof(u32));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01681 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `		lx_uid = from_kuid(&init_user_ns, stat.uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `	kfree(xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `	xattr_val = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `				       KSMBD_XATTR_NAME_LXGID, &xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `	if (xattr_len == sizeof(u32) && xattr_val)`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [MEM_BOUNDS|] `		memcpy(&lx_gid, xattr_val, sizeof(u32));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01695 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `		lx_gid = from_kgid(&init_user_ns, stat.gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `	kfree(xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `	xattr_val = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `				       KSMBD_XATTR_NAME_LXMOD, &xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `	if (xattr_len == sizeof(u32) && xattr_val)`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [MEM_BOUNDS|] `		memcpy(&lx_mode, xattr_val, sizeof(u32));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01709 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `		lx_mode = stat.mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `	kfree(xattr_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `	/* LxFlags: 0 = normal file */`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `	info->LxFlags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `	info->LxUid = cpu_to_le32(lx_uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `	info->LxGid = cpu_to_le32(lx_gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `	info->LxMode = cpu_to_le32(lx_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `	info->LxDeviceIdMajor = cpu_to_le32(MAJOR(stat.rdev));`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `	info->LxDeviceIdMinor = cpu_to_le32(MINOR(stat.rdev));`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `	*out_len = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `/* Static handler descriptors for built-in info-level handlers */`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `static struct ksmbd_info_handler ksmbd_file_name_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01728 [NONE] `	.info_class	= FILE_NAME_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `	.handler	= ksmbd_info_get_file_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `static struct ksmbd_info_handler ksmbd_fs_control_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILESYSTEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01736 [NONE] `	.info_class	= FS_CONTROL_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `	.handler	= ksmbd_info_set_fs_control,`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] `static struct ksmbd_info_handler ksmbd_fs_driver_path_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILESYSTEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01744 [NONE] `	.info_class	= FS_DRIVER_PATH_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `	.handler	= ksmbd_info_get_fs_driver_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `static struct ksmbd_info_handler ksmbd_fs_label_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILESYSTEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01752 [NONE] `	.info_class	= FS_LABEL_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `	.handler	= ksmbd_info_set_fs_label,`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `static struct ksmbd_info_handler ksmbd_fs_object_id_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILESYSTEM,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01760 [NONE] `	.info_class	= FS_OBJECT_ID_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `	.handler	= ksmbd_info_set_fs_object_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `static struct ksmbd_info_handler ksmbd_pipe_info_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01768 [NONE] `	.info_class	= FILE_PIPE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `	.handler	= ksmbd_info_get_pipe,`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `static struct ksmbd_info_handler ksmbd_pipe_local_info_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01776 [NONE] `	.info_class	= FILE_PIPE_LOCAL_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `	.handler	= ksmbd_info_get_pipe_local,`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `static struct ksmbd_info_handler ksmbd_pipe_remote_info_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01784 [NONE] `	.info_class	= FILE_PIPE_REMOTE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `	.handler	= ksmbd_info_get_pipe_remote,`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `static struct ksmbd_info_handler ksmbd_mailslot_query_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01792 [NONE] `	.info_class	= FILE_MAILSLOT_QUERY_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `	.handler	= ksmbd_info_get_mailslot_query,`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `static struct ksmbd_info_handler ksmbd_hard_link_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01800 [NONE] `	.info_class	= FILE_HARD_LINK_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `	.handler	= ksmbd_info_get_hard_link,`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `static struct ksmbd_info_handler ksmbd_pipe_info_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01808 [NONE] `	.info_class	= FILE_PIPE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `	.handler	= ksmbd_info_set_pipe_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `static struct ksmbd_info_handler ksmbd_pipe_remote_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01816 [NONE] `	.info_class	= FILE_PIPE_REMOTE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `	.handler	= ksmbd_info_set_pipe_remote,`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `static struct ksmbd_info_handler ksmbd_mailslot_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01824 [NONE] `	.info_class	= FILE_MAILSLOT_SET_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `	.handler	= ksmbd_info_set_mailslot,`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `static struct ksmbd_info_handler ksmbd_move_cluster_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01832 [NONE] `	.info_class	= FILE_MOVE_CLUSTER_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `	.handler	= ksmbd_info_set_noop_consume,`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] `static struct ksmbd_info_handler ksmbd_tracking_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01840 [NONE] `	.info_class	= FILE_TRACKING_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `	.handler	= ksmbd_info_set_noop_consume,`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `static struct ksmbd_info_handler ksmbd_short_name_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01848 [NONE] `	.info_class	= FILE_SHORT_NAME_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `	.handler	= ksmbd_info_set_noop_consume,`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `static struct ksmbd_info_handler ksmbd_sfio_reserve_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01856 [NONE] `	.info_class	= FILE_SFIO_RESERVE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `	.handler	= ksmbd_info_set_noop_consume,`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] `static struct ksmbd_info_handler ksmbd_sfio_volume_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01864 [NONE] `	.info_class	= FILE_SFIO_VOLUME_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `	.handler	= ksmbd_info_set_noop_consume,`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `static struct ksmbd_info_handler ksmbd_valid_data_length_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01872 [NONE] `	.info_class	= FILE_VALID_DATA_LENGTH_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `	.handler	= ksmbd_info_set_valid_data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `static struct ksmbd_info_handler ksmbd_normalized_name_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01880 [NONE] `	.info_class	= FILE_NORMALIZED_NAME_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `	.handler	= ksmbd_info_get_normalized_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `static struct ksmbd_info_handler ksmbd_process_ids_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01888 [NONE] `	.info_class	= FILE_PROCESS_IDS_USING_FILE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `	.handler	= ksmbd_info_get_process_ids_using_file,`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `static struct ksmbd_info_handler ksmbd_network_physical_name_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01896 [NONE] `	.info_class	= FILE_NETWORK_PHYSICAL_NAME_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `	.handler	= ksmbd_info_get_network_physical_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] `static struct ksmbd_info_handler ksmbd_volume_name_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01904 [NONE] `	.info_class	= FILE_VOLUME_NAME_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `	.handler	= ksmbd_info_get_volume_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `static struct ksmbd_info_handler ksmbd_is_remote_device_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01912 [NONE] `	.info_class	= FILE_IS_REMOTE_DEVICE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] `	.handler	= ksmbd_info_get_is_remote_device,`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `static struct ksmbd_info_handler ksmbd_case_sensitive_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01920 [NONE] `	.info_class	= FILE_CASE_SENSITIVE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `	.handler	= ksmbd_info_get_case_sensitive,`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `static struct ksmbd_info_handler ksmbd_case_sensitive_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01928 [NONE] `	.info_class	= FILE_CASE_SENSITIVE_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] `	.handler	= ksmbd_info_set_case_sensitive,`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] `static struct ksmbd_info_handler ksmbd_remote_protocol_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01936 [NONE] `	.info_class	= FILE_REMOTE_PROTOCOL_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `	.handler	= ksmbd_info_get_remote_protocol,`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `static struct ksmbd_info_handler ksmbd_quota_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_QUOTA,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01944 [NONE] `	.info_class	= FILE_QUOTA_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `	.handler	= ksmbd_info_get_quota,`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] `static struct ksmbd_info_handler ksmbd_quota_set_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_QUOTA,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01952 [NONE] `	.info_class	= FILE_QUOTA_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `	.op		= KSMBD_INFO_SET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `	.handler	= ksmbd_info_set_quota,`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `static struct ksmbd_info_handler ksmbd_file_stat_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_FILE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01960 [NONE] `	.info_class	= FILE_STAT_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `	.handler	= ksmbd_info_get_file_stat,`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `static struct ksmbd_info_handler *builtin_info_handlers[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `	&ksmbd_file_name_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `	&ksmbd_fs_control_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `	&ksmbd_fs_driver_path_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `	&ksmbd_fs_label_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `	&ksmbd_fs_object_id_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `	&ksmbd_pipe_info_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `	&ksmbd_pipe_local_info_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `	&ksmbd_pipe_remote_info_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `	&ksmbd_mailslot_query_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `	&ksmbd_hard_link_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `	&ksmbd_pipe_info_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] `	&ksmbd_pipe_remote_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `	&ksmbd_mailslot_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `	&ksmbd_move_cluster_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `	&ksmbd_tracking_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `	&ksmbd_short_name_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] `	&ksmbd_sfio_reserve_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] `	&ksmbd_sfio_volume_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `	&ksmbd_valid_data_length_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `	&ksmbd_normalized_name_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [NONE] `	&ksmbd_process_ids_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] `	&ksmbd_network_physical_name_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `	&ksmbd_volume_name_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] `	&ksmbd_is_remote_device_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `	&ksmbd_case_sensitive_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `	&ksmbd_case_sensitive_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] `	&ksmbd_remote_protocol_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] `	&ksmbd_quota_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `	&ksmbd_quota_set_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `	&ksmbd_file_stat_get_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] ` * ksmbd_info_init() - Initialize the info-level dispatch table`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] ` * Registers built-in info-level handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `int ksmbd_info_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `	hash_init(info_handlers);`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `	for (i = 0; i < ARRAY_SIZE(builtin_info_handlers); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `		ret = ksmbd_register_info_handler(builtin_info_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [ERROR_PATH|] `			pr_err("Failed to register info handler (type=%u, class=%u, op=%d): %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02016 [NONE] `			       builtin_info_handlers[i]->info_type,`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] `			       builtin_info_handlers[i]->info_class,`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `			       builtin_info_handlers[i]->op, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [ERROR_PATH|] `			goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02020 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] `	ksmbd_debug(SMB, "Info-level handler table initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `	while (--i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `		ksmbd_unregister_info_handler(builtin_info_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] ` * ksmbd_info_exit() - Tear down the info-level dispatch table`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] ` * Unregisters all built-in info-level handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `void ksmbd_info_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `	for (i = ARRAY_SIZE(builtin_info_handlers) - 1; i >= 0; i--)`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `		ksmbd_unregister_info_handler(builtin_info_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
