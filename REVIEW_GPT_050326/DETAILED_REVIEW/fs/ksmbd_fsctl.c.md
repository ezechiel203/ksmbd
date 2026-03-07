# Line-by-line Review: src/fs/ksmbd_fsctl.c

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
- L00006 [NONE] ` *   FSCTL handler registration table for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Replaces the monolithic switch-case dispatch in smb2_ioctl() with an`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [LIFETIME|] ` *   RCU-protected hash table.  Built-in handlers are registered at module`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00010 [NONE] ` *   init; additional handlers can be registered by extension modules.`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/jhash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/random.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include <linux/ethtool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "ksmbd_branchcache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "ksmbd_netlink.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "xattr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `/* 256 buckets (2^8) — sufficient for the ~20 built-in FSCTLs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define KSMBD_FSCTL_HASH_BITS	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `static DEFINE_HASHTABLE(fsctl_handlers, KSMBD_FSCTL_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `static DEFINE_SPINLOCK(fsctl_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * ksmbd_register_fsctl() - Register an FSCTL handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * @h: handler descriptor`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * Adds the handler to the hash table under spinlock using hash_add_rcu.`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * Return: 0 on success, -EEXIST if a handler for the same ctl_code`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` *         is already registered.`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	struct ksmbd_fsctl_handler *cur;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [LOCK|] `	spin_lock(&fsctl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00077 [NONE] `	hash_for_each_possible_rcu(fsctl_handlers, cur, node, h->ctl_code) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		if (cur->ctl_code == h->ctl_code) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [LOCK|] `			spin_unlock(&fsctl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00080 [ERROR_PATH|] `			pr_err("FSCTL handler 0x%08x already registered\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00081 [NONE] `			       h->ctl_code);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [ERROR_PATH|] `			return -EEXIST;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00083 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	hash_add_rcu(fsctl_handlers, &h->node, h->ctl_code);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [LOCK|] `	spin_unlock(&fsctl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00087 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * ksmbd_unregister_fsctl() - Unregister an FSCTL handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * @h: handler descriptor previously registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [LIFETIME|] ` * Removes the handler under spinlock and waits for an RCU grace period.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00095 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [LOCK|] `	spin_lock(&fsctl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00099 [NONE] `	hash_del_rcu(&h->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [LOCK|] `	spin_unlock(&fsctl_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00101 [NONE] `	synchronize_rcu();`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` * ksmbd_dispatch_fsctl() - Look up and invoke a registered FSCTL handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * @ctl_code:	    FSCTL control code (host byte order)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * @in_buf:	    pointer to input buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` * @out_len:	    [out] number of output bytes written by the handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [LIFETIME|] ` * Performs an RCU-protected hash lookup, takes a module reference on the`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00116 [NONE] ` * owning module, and invokes the handler callback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` *         handler is registered for the given ctl_code.`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `int ksmbd_dispatch_fsctl(struct ksmbd_work *work, u32 ctl_code,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `			 u64 id, void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `			 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `			 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `			 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	struct ksmbd_fsctl_handler *h;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	int ret = -EOPNOTSUPP;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00133 [NONE] `	hash_for_each_possible_rcu(fsctl_handlers, h, node, ctl_code) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		if (h->ctl_code != ctl_code)`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		if (!try_module_get(h->owner)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00139 [ERROR_PATH|] `			return -ENODEV;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00140 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [LIFETIME|] `		rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		ret = h->handler(work, id, in_buf, in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `				 max_out_len, rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		module_put(h->owner);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` *  Built-in FSCTL handler implementations`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ` * These are extracted from smb2_ioctl() in smb2pdu.c.  Each follows`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ` * the unified handler signature defined in ksmbd_fsctl.h.`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `static void ksmbd_fsctl_build_fallback_object_id(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `						 u8 *object_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	struct inode *inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	__le64 ino = cpu_to_le64(inode->i_ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	__le32 gen = cpu_to_le32(inode->i_generation);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	__le32 dev = cpu_to_le32((u32)new_encode_dev(inode->i_sb->s_dev));`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	memset(object_id, 0, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [MEM_BOUNDS|] `	memcpy(object_id, &ino, sizeof(ino));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00172 [MEM_BOUNDS|] `	memcpy(object_id + sizeof(ino), &gen, sizeof(gen));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00173 [MEM_BOUNDS|] `	memcpy(object_id + sizeof(ino) + sizeof(gen), &dev, sizeof(dev));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00174 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `static int ksmbd_fsctl_get_object_id(struct ksmbd_file *fp, u8 *object_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	char *xattr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	ssize_t xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `				       XATTR_NAME_OBJECT_ID, &xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `				       XATTR_NAME_OBJECT_ID, &xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	if (xattr_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		if (xattr_len == -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `			ksmbd_fsctl_build_fallback_object_id(fp, object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		return (int)xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	if (xattr_len != 16) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		kfree(xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00201 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [MEM_BOUNDS|] `	memcpy(object_id, xattr_buf, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00204 [NONE] `	kfree(xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `static int ksmbd_fsctl_set_object_id(struct ksmbd_file *fp, const u8 *object_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	ret = ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	ret = ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `				 &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `				 XATTR_NAME_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `				 (void *)object_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `				 16, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	if (ret == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `static int ksmbd_fsctl_delete_object_id(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	ret = ksmbd_vfs_remove_xattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	ret = ksmbd_vfs_remove_xattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `				     &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `				     (char *)XATTR_NAME_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `				     true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	if (ret == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `static int ksmbd_fsctl_get_or_create_object_id(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `						u8 *object_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	ret = ksmbd_fsctl_get_object_id(fp, object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	if (!ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	if (ret != -ENOENT && ret != -ENODATA && ret != -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	get_random_bytes(object_id, 16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	return ksmbd_fsctl_set_object_id(fp, object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `static int ksmbd_fsctl_fill_object_id_rsp(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `					  bool create_if_missing,`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `					  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `					  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `					  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	struct file_object_buf_type1_ioctl_rsp *obj_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	u8 object_id[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	if (max_out_len < sizeof(*obj_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00271 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00272 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	if (create_if_missing)`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `		ret = ksmbd_fsctl_get_or_create_object_id(fp, object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `		ret = ksmbd_fsctl_get_object_id(fp, object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		if (ret == -EACCES || ret == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00281 [NONE] `		else if (ret == -ENOENT || ret == -ENODATA)`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00283 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00285 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	obj_rsp = (struct file_object_buf_type1_ioctl_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	memset(obj_rsp, 0, sizeof(*obj_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [MEM_BOUNDS|] `	memcpy(obj_rsp->ObjectId, object_id, sizeof(obj_rsp->ObjectId));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00292 [MEM_BOUNDS|] `	memcpy(obj_rsp->BirthObjectId, object_id,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00293 [NONE] `	       sizeof(obj_rsp->BirthObjectId));`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	*out_len = sizeof(*obj_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] ` * fsctl_create_or_get_object_id_handler() - FSCTL_CREATE_OR_GET_OBJECT_ID`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ` * Returns a stable 16-byte object ID persisted in xattr, and fills the`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` * type-1 FILE_OBJECTID_BUFFER response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `static int fsctl_create_or_get_object_id_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `						  u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `						  unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `						  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `						  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `						  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00317 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00318 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	ret = ksmbd_fsctl_fill_object_id_rsp(fp, true, max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `					     rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `static int fsctl_get_object_id_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00339 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00340 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	ret = ksmbd_fsctl_fill_object_id_rsp(fp, false, max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `					     rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `static int fsctl_set_object_id_common_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `					      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `					      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `					      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `					      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00359 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00360 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	if (in_buf_len < 16) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00364 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00365 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00370 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00371 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `	ret = ksmbd_fsctl_set_object_id(fp, (u8 *)in_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `		if (ret == -EACCES || ret == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00377 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00379 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `static int fsctl_set_object_id_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	return fsctl_set_object_id_common_handler(work, id, in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `						  in_buf_len, rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `static int fsctl_set_object_id_extended_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `						u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `						unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `						unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `						struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `						unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	return fsctl_set_object_id_common_handler(work, id, in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `						  in_buf_len, rsp, out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `static int fsctl_delete_object_id_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `					  u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `					  unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `					  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `					  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `					  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00419 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00420 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00425 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00426 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	ret = ksmbd_fsctl_delete_object_id(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `	if (ret == -ENOENT || ret == -ENODATA)`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	else if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `		if (ret == -EACCES || ret == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00434 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00436 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `static int fsctl_get_compression_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `	__le16 *compression_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	if (max_out_len < sizeof(__le16)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00455 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00456 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00461 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00462 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	compression_state = (__le16 *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	if (fp->f_ci->m_fattr & ATTR_COMPRESSED_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		*compression_state = cpu_to_le16(COMPRESSION_FORMAT_LZNT1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `		*compression_state = cpu_to_le16(COMPRESSION_FORMAT_NONE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	*out_len = sizeof(__le16);`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `static int fsctl_persist_dos_attrs(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `				   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `				   __le32 old_fattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	struct xattr_dos_attrib da;`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	if (fp->f_ci->m_fattr == old_fattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	if (!test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `				    KSMBD_SHARE_FLAG_STORE_DOS_ATTRS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	ret = compat_ksmbd_vfs_get_dos_attrib_xattr(&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `						    fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `						    &da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	if (ret <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	da.attr = le32_to_cpu(fp->f_ci->m_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	ret = compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `						    &da, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		fp->f_ci->m_fattr = old_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `static int fsctl_set_compression_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	__le32 old_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	__le16 compression_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	u16 state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00519 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00520 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	if (in_buf_len < sizeof(__le16)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00524 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00525 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [MEM_BOUNDS|] `	memcpy(&compression_state, in_buf, sizeof(compression_state));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00528 [NONE] `	state = le16_to_cpu(compression_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	if (state != COMPRESSION_FORMAT_NONE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	    state != COMPRESSION_FORMAT_LZNT1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00532 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00533 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00538 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00539 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	old_fattr = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	 * F7: Set/clear the ATTR_COMPRESSED attribute flag on the file.`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	 * This mirrors Windows/NTFS behavior: setting the compression flag`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	 * does NOT immediately recompress existing file data.  NTFS compresses`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	 * data lazily — only newly written extents are stored compressed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	 * Existing data is recompressed in the background or when re-written.`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	 * On Linux, actual data compression is filesystem-dependent:`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	 *   - Btrfs: transparent compression via mount option (zstd/lzo/zlib);`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	 *     per-file compression can be set with ioctl(FS_IOC_SETFLAGS) but`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	 *     this is out of scope for the SMB layer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	 *   - ext4/xfs: no transparent file compression.`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	 *   - OverlayFS: inherits from lower filesystem.`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	 * We set the flag in the ksmbd attribute cache and persist it as an`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	 * xattr, matching the lazy (flag-only) Windows behavior.  Clients`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	 * that read the attribute back via QUERY_INFO will see the flag set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `	if (state == COMPRESSION_FORMAT_LZNT1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		fp->f_ci->m_fattr |= ATTR_COMPRESSED_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `		fp->f_ci->m_fattr &= ~ATTR_COMPRESSED_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	ret = fsctl_persist_dos_attrs(work, fp, old_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `static int fsctl_is_pathname_valid_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `					   u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `					   unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `					   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `					   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `					   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `static int fsctl_is_volume_dirty_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	__le32 *volume_dirty;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	if (max_out_len < sizeof(__le32)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00596 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00597 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	volume_dirty = (__le32 *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	*volume_dirty = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	*out_len = sizeof(__le32);`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `static int fsctl_stub_noop_success_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `					   u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `					   unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `					   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `					   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `					   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [PROTO_GATE|] ` * fsctl_not_supported_handler() - Return STATUS_NOT_SUPPORTED`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00618 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] ` * For FSCTLs that reference features with no Linux equivalent (USN journal,`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] ` * FAT BPB, raw encrypted, etc.), return an honest error instead of faking`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ` * success.`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `static int fsctl_not_supported_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00631 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [ERROR_PATH|] `	return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00633 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `struct fsctl_pipe_peek_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	__le32 NamedPipeState;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	__le32 ReadDataAvailable;`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `	__le32 NumberOfMessages;`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	__le32 MessageLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ` * Named pipe state constants per MS-FSCC §2.3.32:`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ` *   1 = FILE_PIPE_DISCONNECTED_STATE`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ` *   2 = FILE_PIPE_LISTENING_STATE`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ` *   3 = FILE_PIPE_CONNECTED_STATE`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ` *   4 = FILE_PIPE_CLOSING_STATE`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `#define FILE_PIPE_DISCONNECTED_STATE	1`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `#define FILE_PIPE_CONNECTED_STATE	3`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `static int fsctl_pipe_peek_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `				   u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `				   unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `				   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `				   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `				   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	struct fsctl_pipe_peek_rsp *peek_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	if (max_out_len < sizeof(*peek_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00664 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00665 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	peek_rsp = (struct fsctl_pipe_peek_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	memset(peek_rsp, 0, sizeof(*peek_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	 * MS-FSCC §2.3.32: NamedPipeState MUST be one of the defined`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	 * states. Return CONNECTED (3) for open pipe handles,`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	 * DISCONNECTED (1) if the handle is not found.`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	if (fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `		peek_rsp->NamedPipeState = cpu_to_le32(FILE_PIPE_CONNECTED_STATE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `		peek_rsp->NamedPipeState = cpu_to_le32(FILE_PIPE_DISCONNECTED_STATE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	*out_len = sizeof(*peek_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `struct fsctl_ntfs_volume_data_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	__le64 VolumeSerialNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	__le64 NumberSectors;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	__le64 TotalClusters;`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	__le64 FreeClusters;`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	__le64 TotalReserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	__le32 BytesPerSector;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	__le32 BytesPerCluster;`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	__le32 BytesPerFileRecordSegment;`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	__le32 ClustersPerFileRecordSegment;`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	__le64 MftValidDataLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	__le64 MftStartLcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	__le64 Mft2StartLcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	__le64 MftZoneStart;`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	__le64 MftZoneEnd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `static int fsctl_get_ntfs_volume_data_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `					      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `					      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `					      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `					      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `					      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	struct fsctl_ntfs_volume_data_rsp *vol_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	struct kstatfs stfs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	u32 bytes_per_sector = 512;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	u32 bytes_per_cluster;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	u64 total_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	if (max_out_len < sizeof(*vol_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00722 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00723 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `	share = work->tcon ? work->tcon->share_conf : NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	if (!share || !share->path) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00728 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00729 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	ret = kern_path(share->path, LOOKUP_NO_SYMLINKS, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00734 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	ret = vfs_statfs(&path, &stfs);`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00741 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `	vol_rsp = (struct fsctl_ntfs_volume_data_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `	memset(vol_rsp, 0, sizeof(*vol_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	bytes_per_cluster = max_t(u32, stfs.f_bsize, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	if (bytes_per_cluster < bytes_per_sector)`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `		bytes_per_sector = bytes_per_cluster;`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `	total_bytes = (u64)stfs.f_blocks * stfs.f_bsize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `	vol_rsp->VolumeSerialNumber =`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `		cpu_to_le64((u64)new_encode_dev(path.mnt->mnt_sb->s_dev));`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	vol_rsp->NumberSectors = cpu_to_le64(total_bytes / bytes_per_sector);`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `	vol_rsp->TotalClusters = cpu_to_le64(stfs.f_blocks);`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	vol_rsp->FreeClusters = cpu_to_le64(stfs.f_bfree);`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	vol_rsp->TotalReserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	vol_rsp->BytesPerSector = cpu_to_le32(bytes_per_sector);`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	vol_rsp->BytesPerCluster = cpu_to_le32(bytes_per_cluster);`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	vol_rsp->BytesPerFileRecordSegment = cpu_to_le32(bytes_per_cluster);`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	vol_rsp->ClustersPerFileRecordSegment = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	*out_len = sizeof(*vol_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `struct fsctl_starting_vcn_input {`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `	__le64 StartingVcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `struct fsctl_retrieval_pointers_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	__le32 ExtentCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	__le32 Reserved;	/* alignment padding per MS-FSCC 2.3.33 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	__le64 StartingVcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `struct fsctl_retrieval_pointer_extent {`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	__le64 NextVcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	__le64 Lcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `struct fsctl_retrieval_pointers_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `	struct fsctl_retrieval_pointers_hdr hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `	struct fsctl_retrieval_pointer_extent extents[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `static int fsctl_get_retrieval_pointers_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `						u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `						unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `						unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `						struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `						unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	struct fsctl_starting_vcn_input *in;`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	struct fsctl_retrieval_pointers_hdr *out_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `	struct fsctl_retrieval_pointers_rsp *out_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	u64 starting_vcn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `	u64 total_clusters;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	u32 cluster_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	if (in_buf_len < sizeof(*in)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00806 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00807 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00812 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00813 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	in = (struct fsctl_starting_vcn_input *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	starting_vcn = le64_to_cpu(in->StartingVcn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	cluster_bytes = max_t(u32, i_blocksize(inode), 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `	total_clusters = DIV_ROUND_UP_ULL(i_size_read(inode), cluster_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	if (!total_clusters || starting_vcn >= total_clusters) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `		if (max_out_len < sizeof(*out_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00825 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00826 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `		out_hdr = (struct fsctl_retrieval_pointers_hdr *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `		out_hdr->ExtentCount = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `		out_hdr->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `		out_hdr->StartingVcn = cpu_to_le64(starting_vcn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		*out_len = sizeof(*out_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	if (max_out_len < sizeof(*out_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00840 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00841 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `	out_rsp = (struct fsctl_retrieval_pointers_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `	out_rsp->hdr.ExtentCount = cpu_to_le32(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	out_rsp->hdr.Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	out_rsp->hdr.StartingVcn = cpu_to_le64(starting_vcn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	out_rsp->extents[0].NextVcn = cpu_to_le64(total_clusters);`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `	out_rsp->extents[0].Lcn = cpu_to_le64(starting_vcn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `	*out_len = sizeof(*out_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `static __be32 fsctl_idev_ipv4_address(struct in_device *idev)`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `	__be32 addr = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	struct in_ifaddr *ifa;`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00861 [NONE] `	in_dev_for_each_ifa_rcu(ifa, idev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `		if (ifa->ifa_flags & IFA_F_SECONDARY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `		addr = ifa->ifa_address;`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00869 [NONE] `	return addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `static int fsctl_query_network_interface_info_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `						      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `						      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `						      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `						      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `						      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	struct network_interface_info_ioctl_rsp *nii_rsp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `	struct sockaddr_storage_rsp *sockaddr_storage;`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	struct net_device *netdev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `	unsigned int flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	unsigned long long speed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `	unsigned int nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	rtnl_lock();`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	for_each_netdev(&init_net, netdev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `		bool ipv4_set = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		if (netdev->type == ARPHRD_LOOPBACK)`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		if (!ksmbd_find_netdev_name_iface_list(netdev->name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		flags = netif_get_flags(netdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		flags = dev_get_flags(netdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `		if (!(flags & IFF_RUNNING))`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `ipv6_retry:`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `		if (max_out_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		    nbytes + sizeof(struct network_interface_info_ioctl_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `			rtnl_unlock();`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00908 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00909 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		nii_rsp = (struct network_interface_info_ioctl_rsp *)&rsp->Buffer[nbytes];`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `		nii_rsp->IfIndex = cpu_to_le32(netdev->ifindex);`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `		nii_rsp->Capability = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `		if (netdev->real_num_tx_queues > 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `			nii_rsp->Capability |= cpu_to_le32(RSS_CAPABLE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `		if (ksmbd_rdma_capable_netdev(netdev))`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `			nii_rsp->Capability |= cpu_to_le32(RDMA_CAPABLE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `		nii_rsp->Next = cpu_to_le32(152);`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `		nii_rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `		if (netdev->ethtool_ops->get_link_ksettings) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `			struct ethtool_link_ksettings cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `			netdev->ethtool_ops->get_link_ksettings(netdev, &cmd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `			speed = cmd.base.speed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `			speed = SPEED_1000;`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `		speed *= 1000000;`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `		/* MS-SMB2 §2.2.32.5: LinkSpeed is in bytes/second */`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		nii_rsp->LinkSpeed = cpu_to_le64(speed / 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `		sockaddr_storage =`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `			(struct sockaddr_storage_rsp *)nii_rsp->SockAddr_Storage;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `		memset(sockaddr_storage, 0, 128);`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `		if (!ipv4_set) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `			struct in_device *idev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `			sockaddr_storage->Family = cpu_to_le16(INTERNETWORK);`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `			sockaddr_storage->addr4.Port = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `			idev = __in_dev_get_rtnl(netdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `			if (!idev)`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `			sockaddr_storage->addr4.IPv4address =`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `				fsctl_idev_ipv4_address(idev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `			nbytes += sizeof(struct network_interface_info_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `			ipv4_set = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [ERROR_PATH|] `			goto ipv6_retry;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00953 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `			struct inet6_dev *idev6;`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `			struct inet6_ifaddr *ifa;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `			__u8 *ipv6_addr = sockaddr_storage->addr6.IPv6address;`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `			sockaddr_storage->Family = cpu_to_le16(INTERNETWORKV6);`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `			sockaddr_storage->addr6.Port = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `			sockaddr_storage->addr6.FlowInfo = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `			idev6 = __in6_dev_get(netdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `			if (!idev6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [LIFETIME|] `			 * F2: Use RCU read lock when iterating IPv6 addresses.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00968 [NONE] `			 * Although we hold rtnl_lock, inet6_ifaddr objects can be`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [LIFETIME|] `			 * freed via RCU when an IPv6 address is removed concurrently`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00970 [LIFETIME|] `			 * (e.g., by a netlink message on another CPU).  The RCU lock`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00971 [NONE] `			 * ensures we don't dereference a freed inet6_ifaddr.`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [LIFETIME|] `			rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00974 [NONE] `			list_for_each_entry_rcu(ifa, &idev6->addr_list, if_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `				if (ifa->flags & (IFA_F_TENTATIVE |`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `						  IFA_F_DEPRECATED))`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [MEM_BOUNDS|] `				memcpy(ipv6_addr, ifa->addr.s6_addr, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00979 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00982 [NONE] `			sockaddr_storage->addr6.ScopeId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `			nbytes += sizeof(struct network_interface_info_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	rtnl_unlock();`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `	if (nii_rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `		nii_rsp->Next = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [PROTO_GATE|] `	rsp->PersistentFileId = SMB2_NO_FID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00992 [PROTO_GATE|] `	rsp->VolatileFileId = SMB2_NO_FID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00993 [NONE] `	*out_len = nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `static int fsctl_request_resume_key_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `					    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `					    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `					    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `					    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `					    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `	struct resume_key_ioctl_rsp *key_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	if (max_out_len < sizeof(*key_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01009 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01010 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01015 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01016 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `	key_rsp = (struct resume_key_ioctl_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `	memset(key_rsp, 0, sizeof(*key_rsp));`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `	key_rsp->ResumeKey[0] = cpu_to_le64(fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `	key_rsp->ResumeKey[1] = cpu_to_le64(fp->persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `	rsp->VolatileFileId = fp->volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `	rsp->PersistentFileId = fp->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `	*out_len = sizeof(*key_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `static int fsctl_copychunk_common(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `				  struct copychunk_ioctl_req *ci_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `				  unsigned int cnt_code,`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `				  unsigned int input_count,`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `				  u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `				  struct smb2_ioctl_rsp *rsp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `	struct copychunk_ioctl_rsp *ci_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	struct ksmbd_file *src_fp = NULL, *dst_fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	struct srv_copychunk *chunks;`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	unsigned int i, chunk_count, chunk_count_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	unsigned int chunk_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	loff_t total_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `	ci_rsp = (struct copychunk_ioctl_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `	rsp->VolatileFileId = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [PROTO_GATE|] `	rsp->PersistentFileId = SMB2_NO_FID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	 * Initialize response to zero.  The server maximum values are`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [PROTO_GATE|] `	 * only returned when STATUS_INVALID_PARAMETER is set (MS-FSCC`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01052 [NONE] `	 * 2.3.12.1 -- limits exceeded).  For all other errors/successes`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	 * the response must carry actual counts.`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `	ci_rsp->ChunksWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `	ci_rsp->ChunkBytesWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `	ci_rsp->TotalBytesWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	chunks = (struct srv_copychunk *)&ci_req->Chunks[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	chunk_count = le32_to_cpu(ci_req->ChunkCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	if (chunk_count == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	/* MS-FSCC §2.3.12: reject only when ChunkCount EXCEEDS max (> not >=) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `	if (chunk_count > ksmbd_server_side_copy_max_chunk_count() ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `	    input_count < offsetof(struct copychunk_ioctl_req, Chunks) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `			 chunk_count * sizeof(struct srv_copychunk)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `		ci_rsp->ChunksWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `		ci_rsp->ChunkBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `		ci_rsp->TotalBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_total_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01075 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01076 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `	for (i = 0; i < chunk_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `		if (le32_to_cpu(chunks[i].Length) == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `		    le32_to_cpu(chunks[i].Length) >`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `			    ksmbd_server_side_copy_max_chunk_size())`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `		total_size_written += le32_to_cpu(chunks[i].Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	if (i < chunk_count ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	    total_size_written > ksmbd_server_side_copy_max_total_size()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `		ci_rsp->ChunksWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `		ci_rsp->ChunkBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `		ci_rsp->TotalBytesWritten =`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `			cpu_to_le32(ksmbd_server_side_copy_max_total_size());`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01095 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01096 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `	src_fp = ksmbd_lookup_foreign_fd(work, le64_to_cpu(ci_req->ResumeKey[0]));`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `	dst_fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `	ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	if (!src_fp ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	    src_fp->persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01104 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01105 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `	if (!dst_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01109 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01110 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `	rsp->PersistentFileId = dst_fp->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `	 * MS-SMB2 §3.3.5.15.6: access check for copy chunk.`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	 * Source needs FILE_READ_DATA or FILE_EXECUTE.`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	 * FSCTL_COPYCHUNK: destination needs FILE_WRITE_DATA.`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	 * FSCTL_COPYCHUNK_WRITE: destination needs FILE_READ_DATA.`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01123 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01124 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	 * Destination write check (both COPYCHUNK and COPYCHUNK_WRITE`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	 * need write access on destination).`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `	if (!(dst_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01132 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01133 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	 * FSCTL_COPYCHUNK additionally requires FILE_READ_DATA on`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	 * the destination (MS-SMB2 §3.3.5.15.6.1).`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	 * FSCTL_COPYCHUNK_WRITE does not require read access on dest.`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	if (cnt_code == FSCTL_COPYCHUNK &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `	    !(dst_fp->daccess & FILE_READ_DATA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01143 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01144 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	ret = ksmbd_vfs_copy_file_ranges(work, src_fp, dst_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `					 chunks, chunk_count,`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `					 &chunk_count_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `					 &chunk_size_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `					 &total_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `		if (ret == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01154 [NONE] `		else if (ret == -EAGAIN)`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01156 [NONE] `		else if (ret == -EBADF)`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01158 [NONE] `		else if (ret == -EFBIG || ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01160 [NONE] `		else if (ret == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01162 [NONE] `		else if (ret == -EISDIR)`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01164 [NONE] `		else if (ret == -E2BIG)`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_VIEW_SIZE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01166 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01168 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	 * MS-FSCC 2.3.12.1: ChunkBytesWritten MUST be zero when all`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	 * requested chunks completed successfully.  It is non-zero only`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	 * for a partial write (some chunks succeeded, but one failed),`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	 * containing the byte count written for the last chunk attempted.`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `	if (chunk_count_written == chunk_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `		ci_rsp->ChunkBytesWritten = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `		ci_rsp->ChunkBytesWritten = cpu_to_le32(chunk_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	ci_rsp->TotalBytesWritten = cpu_to_le32(total_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `	if (!ret && work->conn->is_fruit && src_fp && dst_fp &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `		ksmbd_vfs_copy_xattrs(src_fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `				      dst_fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `				      &dst_fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `	ksmbd_fd_put(work, src_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `	ksmbd_fd_put(work, dst_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `static int fsctl_copychunk_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `				   u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `				   unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `				   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `				   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `				   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01208 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01209 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01213 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01214 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `	if (max_out_len < sizeof(struct copychunk_ioctl_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01218 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01219 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	ret = fsctl_copychunk_common(work, (struct copychunk_ioctl_req *)in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `				     FSCTL_COPYCHUNK, in_buf_len, id, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	*out_len = sizeof(struct copychunk_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `static int fsctl_copychunk_write_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01238 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01239 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `	if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01243 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01244 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	if (max_out_len < sizeof(struct copychunk_ioctl_rsp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01248 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01249 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	ret = fsctl_copychunk_common(work, (struct copychunk_ioctl_req *)in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `				     FSCTL_COPYCHUNK_WRITE, in_buf_len, id, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	*out_len = sizeof(struct copychunk_ioctl_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `static int fsctl_duplicate_extents_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `					   u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `					   unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `					   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `					   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `					   unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	struct ksmbd_file *fp_in = NULL, *fp_out = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	struct duplicate_extents_to_file *dup_ext;`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	loff_t src_off, dst_off, length, cloned;`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01271 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01272 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	if (in_buf_len < sizeof(*dup_ext)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01276 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01277 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	dup_ext = (struct duplicate_extents_to_file *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `				     dup_ext->PersistentFileHandle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `	if (!fp_in) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01284 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01285 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	fp_out = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `	if (!fp_out) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `		ksmbd_fd_put(work, fp_in);`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01291 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01292 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `	/* MS-SMB2 §3.3.5.15.7: source needs READ, destination needs WRITE */`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	if (!(fp_in->daccess & FILE_READ_DATA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01298 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01299 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	if (!(fp_out->daccess & FILE_WRITE_DATA_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01303 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01304 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `	src_off = le64_to_cpu(dup_ext->SourceFileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `	length = le64_to_cpu(dup_ext->ByteCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `	/* Validate offset+length doesn't overflow */`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	if (length > 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	    (src_off + length < src_off || dst_off + length < dst_off)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01315 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01316 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	cloned = vfs_clone_file_range(fp_in->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `				      fp_out->filp, dst_off, length, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	if (cloned != length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `		/* Clone failed or partial — fall back to copy */`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `		cloned = vfs_copy_file_range(fp_in->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `					     fp_out->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `					     length, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `		if (cloned != length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `			if (cloned < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `				ret = cloned;`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `				ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `		if (ret == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01336 [NONE] `		else if (ret == -ENOSPC || ret == -EFBIG)`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01338 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01340 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	rsp->VolatileFileId = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	rsp->PersistentFileId = fp_out->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `	ksmbd_fd_put(work, fp_in);`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `	ksmbd_fd_put(work, fp_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] ` * MS-FSCC 2.3.8 FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] ` * Extended version with Flags field. Key flag:`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] ` * DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC.`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `#define DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC 0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `struct duplicate_extents_data_ex {`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	__le32 StructureSize;`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `	__u64  PersistentFileHandle;  /* opaque endianness */`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `	__u64  VolatileFileHandle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	__le64 SourceFileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `	__le64 TargetFileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	__le64 ByteCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `static int fsctl_duplicate_extents_ex_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `					      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `					      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `					      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `					      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `					      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	struct duplicate_extents_data_ex *dup_ext;`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	struct ksmbd_file *fp_in = NULL, *fp_out = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	loff_t src_off, dst_off, length, cloned;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01385 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01386 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `	if (in_buf_len < sizeof(*dup_ext)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01390 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01391 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `	dup_ext = (struct duplicate_extents_data_ex *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `	 * F4: MS-FSCC 2.3.8 Flags field — explicit ATOMIC flag handling.`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `	 * DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC (0x00000001): client`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `	 * requests that the extent duplication be performed atomically so`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `	 * the source range is never observed in a partial state.  The spec`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `	 * says the server SHOULD support this; it is not MUST.`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `	 * vfs_clone_file_range() on reflink-capable filesystems (btrfs, xfs)`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `	 * is inherently atomic at the VFS level, so this flag is honored`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `	 * implicitly for those filesystems.  For the vfs_copy_file_range()`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `	 * fallback path, full atomicity cannot be guaranteed, but we proceed`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `	 * rather than reject — consistent with the SHOULD requirement.`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	if (le32_to_cpu(dup_ext->Flags) & DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC)`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `			    "DUPLICATE_EXTENTS_EX: ATOMIC flag set — "`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `			    "honored via vfs_clone_file_range() where supported\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `	fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `				     dup_ext->PersistentFileHandle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	if (!fp_in) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01418 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01419 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `	fp_out = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `	if (!fp_out) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `		ksmbd_fd_put(work, fp_in);`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01425 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01426 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `	src_off = le64_to_cpu(dup_ext->SourceFileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `	dst_off = le64_to_cpu(dup_ext->TargetFileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `	length = le64_to_cpu(dup_ext->ByteCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `	 * Use vfs_clone_file_range() which is atomic on filesystems`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `	 * that support reflink (btrfs, xfs). The ATOMIC flag is`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `	 * honored implicitly. Fall back to vfs_copy_file_range()`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `	 * if clone is not supported.`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `	cloned = vfs_clone_file_range(fp_in->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `				      fp_out->filp, dst_off, length, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `	if (cloned != length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `		/* Clone failed or partial — fall back to copy */`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `		cloned = vfs_copy_file_range(fp_in->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `					     fp_out->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `					     length, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `		if (cloned != length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `			if (cloned < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `				ret = cloned;`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `				ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `	rsp->VolatileFileId = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `	rsp->PersistentFileId = fp_out->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `	ksmbd_fd_put(work, fp_in);`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `	ksmbd_fd_put(work, fp_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] ` * MS-FSCC 2.3.39 MARK_HANDLE_INFO — input buffer for FSCTL_MARK_HANDLE.`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] ` * Fields:`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] ` *   UsnSourceInfo  - advisory hint about the source of the change (USN journal).`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] ` *                    Values: 0x00000001 (DATA_MANAGEMENT),`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] ` *                            0x00000002 (AUXILIARY_DATA),`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] ` *                            0x00000004 (REPLICATION_MANAGEMENT).`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] ` *   VolumeGuid     - GUID of the volume; must be zero for non-ReFS volumes.`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] ` *   HandleInfo     - flags for the handle (e.g., MARK_HANDLE_READ_COPY = 0x80).`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] ` *   CopyNumber     - advisory hint: which storage copy to read from (ReFS/SMB 3.1.1).`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `struct mark_handle_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `	__le32 UsnSourceInfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `	__u8   VolumeGuid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `	__le32 HandleInfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `	__le32 CopyNumber;`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ` * fsctl_mark_handle_handler() - FSCTL_MARK_HANDLE`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] ` * Marks a file handle for special behavior (USN journal, backup`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] ` * semantics, CopyNumber hint for multi-copy ReFS storage).`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] ` * Accept as advisory hint with file handle validation.`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] ` * MS-SMB2 §3.3.5.15.19: pass-through to object store.  Linux has no`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] ` * equivalent for USN journal marking; log the advisory fields at debug`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] ` * level and succeed.`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `static int fsctl_mark_handle_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `				     u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `				     unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `				     unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `				     struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `				     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01504 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01505 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `	 * F5: Parse and log UsnSourceInfo and CopyNumber advisory fields.`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `	 * These are hints — no behavior change is required on Linux, but`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `	 * they should not be silently dropped per spec (MS-FSCC §2.3.39).`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `	if (in_buf_len >= sizeof(struct mark_handle_info)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `		const struct mark_handle_info *mhi =`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `			(const struct mark_handle_info *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `			    "MARK_HANDLE: UsnSourceInfo=0x%08x HandleInfo=0x%08x "`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `			    "CopyNumber=%u (advisory, no Linux equivalent)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `			    le32_to_cpu(mhi->UsnSourceInfo),`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `			    le32_to_cpu(mhi->HandleInfo),`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `			    le32_to_cpu(mhi->CopyNumber));`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `static int fsctl_set_sparse_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `				    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `				    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `				    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `				    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `				    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `	struct file_sparse *sparse;`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `	__le32 old_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01544 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01545 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `	/* MS-FSCC §2.3.64: FSCTL_SET_SPARSE is not valid on directories */`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `	if (S_ISDIR(file_inode(fp->filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01551 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `	old_fattr = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `	 * MS-FSCC §2.3.64: If the InputBuffer is not large enough to`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `	 * contain the FSCTL_SET_SPARSE buffer, the file is set to sparse.`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	if (in_buf_len >= sizeof(struct file_sparse)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `		sparse = (struct file_sparse *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `		if (sparse->SetSparse)`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `			fp->f_ci->m_fattr |= ATTR_SPARSE_FILE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `			fp->f_ci->m_fattr &= ~ATTR_SPARSE_FILE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `		fp->f_ci->m_fattr |= ATTR_SPARSE_FILE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `	ret = fsctl_persist_dos_attrs(work, fp, old_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `static int fsctl_set_zero_data_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `	struct file_zero_data_information *zero_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `	loff_t off, len, bfz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01591 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01592 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `	if (in_buf_len < sizeof(*zero_data)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01596 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01597 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] `	zero_data = (struct file_zero_data_information *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `	off = le64_to_cpu(zero_data->FileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `	bfz = le64_to_cpu(zero_data->BeyondFinalZero);`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `	if (off < 0 || bfz < 0 || off > bfz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01604 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01605 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `	len = bfz - off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `	if (len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `		fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `		if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01612 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01613 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `		 * Verify the file handle was opened with write access.`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `		 * The tree-level writable check above guards the share,`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `		 * but the individual handle must also carry write`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `		 * permission in its daccess mask.`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `		if (!(fp->daccess & (FILE_WRITE_DATA_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `				     FILE_APPEND_DATA_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01625 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01626 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `		ret = ksmbd_vfs_zero_data(work, fp, off, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `		if (ret == -EAGAIN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01632 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `static int fsctl_query_allocated_ranges_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `						u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `						unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `						unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `						struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `						unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `	struct file_allocated_range_buffer *in_range;`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `	struct file_allocated_range_buffer *out_range;`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `	unsigned int max_entries, out_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `	loff_t start, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `	if (in_buf_len < sizeof(*in_range)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01658 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01659 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `	max_entries = max_out_len / sizeof(*out_range);`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `	if (!max_entries) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01664 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01665 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01670 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01671 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `	in_range = (struct file_allocated_range_buffer *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `	start = le64_to_cpu(in_range->file_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `	length = le64_to_cpu(in_range->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `	if (start < 0 || length < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01679 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01680 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `	out_range = (struct file_allocated_range_buffer *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `	ret = ksmbd_vfs_fqar_lseek(fp, start, length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `				   out_range, max_entries, &out_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `	if (ret == -E2BIG) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01689 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] `	} else if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `		out_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `	*out_len = out_count * sizeof(*out_range);`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] ` * fsctl_validate_negotiate_info_handler() - FSCTL_VALIDATE_NEGOTIATE_INFO`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] ` * Validates that the negotiation parameters match what the server`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] ` * agreed on, preventing downgrade attacks (MS-SMB2 §3.3.5.15.12).`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] ` * On validation mismatch MS-SMB2 §3.3.5.15.12 requires the server to`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] ` * terminate the transport connection WITHOUT sending an error response.`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `VISIBLE_IF_KUNIT int fsctl_validate_negotiate_info_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `						  u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `						  unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `						  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `						  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `						  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `	struct validate_negotiate_info_req *neg_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `	struct validate_negotiate_info_rsp *neg_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `	int dialect;`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `	if (in_buf_len < offsetof(struct validate_negotiate_info_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `				  Dialects))`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `	if (max_out_len < sizeof(struct validate_negotiate_info_rsp))`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `	neg_req = (struct validate_negotiate_info_req *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `	if (in_buf_len < offsetof(struct validate_negotiate_info_req, Dialects) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `			le16_to_cpu(neg_req->DialectCount) * sizeof(__le16))`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01732 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `	dialect = ksmbd_lookup_dialect_by_id(neg_req->Dialects,`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `					     neg_req->DialectCount);`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `	if (dialect == BAD_PROT_ID || dialect != conn->dialect)`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [ERROR_PATH|] `		goto vni_mismatch;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01737 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [PROTO_GATE|] `	if (memcmp(neg_req->Guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01739 [ERROR_PATH|] `		goto vni_mismatch;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01740 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `	if (le16_to_cpu(neg_req->SecurityMode) != conn->cli_sec_mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [ERROR_PATH|] `		goto vni_mismatch;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01743 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `	if (le32_to_cpu(neg_req->Capabilities) != conn->cli_cap)`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [ERROR_PATH|] `		goto vni_mismatch;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	neg_rsp = (struct validate_negotiate_info_rsp *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `	neg_rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] `	 * MS-SMB2 §2.2.32.6: ServerGuid MUST be the server's GUID as`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `	 * returned in the NEGOTIATE response (F.7).`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(neg_rsp->Guid, server_conf.server_guid, SMB2_CLIENT_GUID_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01754 [NONE] `	neg_rsp->SecurityMode = cpu_to_le16(conn->srv_sec_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `	neg_rsp->Dialect = cpu_to_le16(conn->dialect);`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [PROTO_GATE|] `	rsp->PersistentFileId = SMB2_NO_FID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01758 [PROTO_GATE|] `	rsp->VolatileFileId = SMB2_NO_FID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `	*out_len = sizeof(struct validate_negotiate_info_rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `vni_mismatch:`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `	 * MS-SMB2 §3.3.5.15.12: "If the validation fails, the server MUST`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `	 * terminate the transport connection."  Do NOT send an error response.`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `		    "VALIDATE_NEGOTIATE_INFO mismatch - terminating connection\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `	ksmbd_conn_set_exiting(conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `	work->send_no_response = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [ERROR_PATH|] `	return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01773 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `EXPORT_SYMBOL_IF_KUNIT(fsctl_validate_negotiate_info_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] ` * fsctl_pipe_transceive_handler() - FSCTL_PIPE_TRANSCEIVE`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] ` * Forwards an RPC request to the userspace daemon and copies`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] ` * the response into the SMB2 output buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `static int fsctl_pipe_transceive_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `					  u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `					  unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `					  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `					  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `					  unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `	struct ksmbd_rpc_command *rpc_resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `	unsigned int capped_out_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `	int nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	capped_out_len = min_t(u32, KSMBD_IPC_MAX_PAYLOAD, max_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	rpc_resp = ksmbd_rpc_ioctl(work->sess, id, in_buf, in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `	if (rpc_resp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `		if (rpc_resp->flags == KSMBD_RPC_SOME_NOT_MAPPED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [PROTO_GATE|] `			 * set STATUS_SOME_NOT_MAPPED response`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01800 [NONE] `			 * for unknown domain sid.`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_SOME_NOT_MAPPED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01803 [NONE] `		} else if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `			 * Gracefully allow clients probing pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `			 * transceive capability on configurations`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `			 * without userspace RPC backend support.`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `			nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01811 [NONE] `		} else if (rpc_resp->flags != KSMBD_RPC_OK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01813 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01814 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `		nbytes = rpc_resp->payload_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `		if (rpc_resp->payload_sz > capped_out_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01819 [NONE] `			nbytes = capped_out_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `		if (!rpc_resp->payload_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01824 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01825 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [MEM_BOUNDS|] `		memcpy((char *)rsp->Buffer, rpc_resp->payload, nbytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01828 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `	kvfree(rpc_resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `	*out_len = nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] ` * MS-FSCC 2.3.22 FSCTL_FILESYSTEM_GET_STATISTICS`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] ` * Return filesystem type + basic statistics. Since Linux doesn't expose`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] ` * per-type stats in the Windows format, we return the base structure with`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] ` * NTFS type identifier and zero-filled counters.`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `#define FILESYSTEM_STATISTICS_TYPE_NTFS	0x0002`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `struct filesystem_statistics {`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `	__le16 FileSystemType;`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `	__le16 Version;`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `	__le32 SizeOfCompleteStructure;`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `	__le32 UserFileReads;`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `	__le32 UserFileReadBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `	__le32 UserDiskReads;`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `	__le32 UserFileWrites;`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `	__le32 UserFileWriteBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `	__le32 UserDiskWrites;`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `	__le32 MetaDataReads;`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `	__le32 MetaDataReadBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `	__le32 MetaDataDiskReads;`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `	__le32 MetaDataWrites;`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `	__le32 MetaDataWriteBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `	__le32 MetaDataDiskWrites;`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `static int fsctl_filesystem_get_stats_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `					      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `					      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `					      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] `					      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `					      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `	struct filesystem_statistics *stats;`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] `	unsigned int struct_sz = sizeof(struct filesystem_statistics);`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `	if (max_out_len < struct_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01875 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01876 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `	stats = (struct filesystem_statistics *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `	memset(stats, 0, struct_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	stats->FileSystemType = cpu_to_le16(FILESYSTEM_STATISTICS_TYPE_NTFS);`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `	stats->Version = cpu_to_le16(1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `	stats->SizeOfCompleteStructure = cpu_to_le32(struct_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] `	*out_len = struct_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] ` * fsctl_set_zero_on_dealloc_handler() - FSCTL_SET_ZERO_ON_DEALLOCATION`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] ` * Hint that deallocated space should be zeroed. Linux filesystems`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] ` * already zero deallocated blocks (ext4/xfs/btrfs), so accept as hint.`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `static int fsctl_set_zero_on_dealloc_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `					     u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `					     unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `					     unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `					     struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `					     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01906 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01907 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] ` * fsctl_set_encryption_handler() - FSCTL_SET_ENCRYPTION`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] ` * Per-file encryption (EFS). fscrypt key management model doesn't map`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [PROTO_GATE|] ` * to the SMB SET_ENCRYPTION request. Return STATUS_NOT_SUPPORTED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01919 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `static int fsctl_set_encryption_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `					u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `					unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `					unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `					struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [NONE] `					unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01928 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [ERROR_PATH|] `	return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01930 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] ` * MS-FSCC 2.3.39 FSCTL_QUERY_FILE_REGIONS`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] ` * Returns information about file regions.  Uses vfs_llseek(SEEK_DATA) and`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] ` * vfs_llseek(SEEK_HOLE) to enumerate actual data regions in sparse files`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] ` * (F3 — verified: Track F commit 49e3c3f).  Falls back to returning the`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] ` * full requested range as a single valid-data region on filesystems that`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] ` * do not support sparse seeking (returns -ENXIO or -EOPNOTSUPP).`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `struct file_region_input {`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] `	__le64 FileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `	__le64 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `	__le32 DesiredUsage;`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `#define FILE_REGION_USAGE_VALID_CACHED_DATA	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [NONE] `struct file_region_output {`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `	__le32 TotalRegionEntryCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `	__le32 RegionEntryCount;`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `struct file_region_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] `	__le64 FileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] `	__le64 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `	__le32 Usage;`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `static int fsctl_query_file_regions_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `					    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `					    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `					    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `					    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `					    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `	struct file_region_input *input;`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `	struct file_region_output *output;`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `	struct file_region_info *region;`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `	u64 req_offset, req_length, file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] `	unsigned int hdr_sz = sizeof(*output);`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `	unsigned int entry_sz = sizeof(*region);`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `	unsigned int max_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `	unsigned int region_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `	loff_t data_start, hole_start, cur;`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] `	loff_t end_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `	if (max_out_len < hdr_sz + entry_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01987 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01988 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01993 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01994 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `	file_size = i_size_read(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `	if (in_buf_len >= sizeof(*input)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `		input = (struct file_region_input *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `		req_offset = le64_to_cpu(input->FileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `		req_length = le64_to_cpu(input->Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `		req_offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `		req_length = file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `	/* Clamp to file size */`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `	if (req_offset >= file_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `		req_offset = file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `		req_length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `	} else if (req_offset + req_length > file_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `		req_length = file_size - req_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] `	output = (struct file_region_output *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] `	memset(output, 0, hdr_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `	region = (struct file_region_info *)((char *)output + hdr_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [NONE] `	max_entries = (max_out_len - hdr_sz) / entry_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [NONE] `	if (max_entries == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02024 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02025 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `	end_offset = (loff_t)(req_offset + req_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `	cur = (loff_t)req_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `	 * Use SEEK_DATA / SEEK_HOLE to enumerate actual data regions.`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `	 * If the filesystem does not support sparse seeking (returns -ENXIO`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `	 * or -EOPNOTSUPP), fall back to returning the full requested range`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `	 * as a single valid-data region.`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `	data_start = vfs_llseek(fp->filp, cur, SEEK_DATA);`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `	if (data_start < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `		/* Filesystem does not support sparse seek — return full range */`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `		if (req_length > 0 && region_count < max_entries) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `			memset(&region[0], 0, entry_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `			region[0].FileOffset = cpu_to_le64(req_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `			region[0].Length = cpu_to_le64(req_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `			region[0].Usage =`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] `				cpu_to_le32(FILE_REGION_USAGE_VALID_CACHED_DATA);`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `			region_count = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [ERROR_PATH|] `		goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02048 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `	/* Walk data/hole pairs within the requested range */`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] `	while (cur < end_offset && region_count < max_entries) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `		loff_t region_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [NONE] `		data_start = vfs_llseek(fp->filp, cur, SEEK_DATA);`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [NONE] `		if (data_start < 0 || data_start >= end_offset)`
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [NONE] `		hole_start = vfs_llseek(fp->filp, data_start, SEEK_HOLE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02059 [NONE] `		if (hole_start < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `			hole_start = end_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [NONE] `		if (hole_start > end_offset)`
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [NONE] `			hole_start = end_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [NONE] `		/* Clamp start to requested range */`
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `		if (data_start < cur)`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `			data_start = cur;`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `		region_end = hole_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `		if (data_start >= region_end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `			cur = hole_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `		memset(&region[region_count], 0, entry_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `		region[region_count].FileOffset = cpu_to_le64((u64)data_start);`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] `		region[region_count].Length =`
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `			cpu_to_le64((u64)(region_end - data_start));`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] `		region[region_count].Usage =`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `			cpu_to_le32(FILE_REGION_USAGE_VALID_CACHED_DATA);`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `		region_count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `		cur = hole_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] `	if (region_count == 0 && req_length > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] `		 * No data regions found (file is entirely sparse in range).`
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] `		 * Return empty output with zero region count — correct.`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `done:`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] `	output->TotalRegionEntryCount = cpu_to_le32(region_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `	output->RegionEntryCount = cpu_to_le32(region_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `	/* Restore file position (it was modified by vfs_llseek) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `	vfs_llseek(fp->filp, 0, SEEK_SET);`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `	*out_len = hdr_sz + region_count * entry_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] ` * MS-FSCC 2.3.49 / 2.3.65 FSCTL_GET/SET_INTEGRITY_INFORMATION`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] ` * On Windows, used with ReFS for data integrity streams. On Linux,`
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] ` * btrfs has checksumming (always on), ext4 has metadata checksums.`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] ` * Return default settings matching non-ReFS behavior.`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] `struct fsctl_get_integrity_info_output {`
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] `	__le16 ChecksumAlgorithm;`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `	__le16 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [NONE] `	__le32 ChecksumChunkSizeInBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] `	__le32 ClusterSizeInBytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] `#define CHECKSUM_TYPE_NONE		0x0000`
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [NONE] `#define FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF 0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L02123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02124 [NONE] `static int fsctl_get_integrity_info_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02125 [NONE] `					    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `					    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] `					    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `					    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `					    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02131 [NONE] `	struct fsctl_get_integrity_info_output *info;`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `	unsigned int sz = sizeof(*info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] `	if (max_out_len < sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02136 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02137 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] `	info = (struct fsctl_get_integrity_info_output *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] `	memset(info, 0, sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `	info->ChecksumAlgorithm = cpu_to_le16(CHECKSUM_TYPE_NONE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] `	info->Flags = cpu_to_le32(FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [NONE] `	info->ChecksumChunkSizeInBytes = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] `	info->ClusterSizeInBytes = cpu_to_le32(4096);`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `	*out_len = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] ` * fsctl_set_integrity_info_handler() - FSCTL_SET_INTEGRITY_INFORMATION`
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] ` * Accept silently. Linux filesystems handle integrity internally`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] ` * (btrfs checksums, ext4 metadata checksums). Matches Windows`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] ` * behavior on non-ReFS volumes.`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02157 [NONE] `static int fsctl_set_integrity_info_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] `					    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] `					    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] `					    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `					    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [NONE] `					    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [NONE] ` * MS-FSCC 2.3.53 / 2.3.55 FSCTL_OFFLOAD_READ / FSCTL_OFFLOAD_WRITE`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] ` * ODX (Offload Data Transfer) uses opaque tokens.  OFFLOAD_READ generates`
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [NONE] ` * a server-local token encoding the source inode identity and range.`
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] ` * OFFLOAD_WRITE validates the token, locates the source file within the`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] ` * session's open handles, and uses vfs_copy_file_range() to perform the`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] ` * data transfer.`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02178 [NONE] `#define STORAGE_OFFLOAD_TOKEN_SIZE	512`
  Review: Low-risk line; verify in surrounding control flow.
- L02179 [NONE] `#define KSMBD_ODX_TOKEN_MAGIC		0x4B534D42  /* "KSMB" */`
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [NONE] `struct ksmbd_odx_token {`
  Review: Low-risk line; verify in surrounding control flow.
- L02182 [NONE] `	__le32 magic;`
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [NONE] `	__le64 file_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02184 [NONE] `	__le64 offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02185 [NONE] `	__le64 length;`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [NONE] `	__le64 generation;`
  Review: Low-risk line; verify in surrounding control flow.
- L02187 [NONE] `	u8     nonce[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] `	u8     reserved[STORAGE_OFFLOAD_TOKEN_SIZE -`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] `			sizeof(__le32) - sizeof(__le64) * 4 - 16];`
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] `static_assert(sizeof(struct ksmbd_odx_token) == STORAGE_OFFLOAD_TOKEN_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] `	      "ksmbd_odx_token must be exactly STORAGE_OFFLOAD_TOKEN_SIZE bytes");`
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [NONE] ` * Server-side ODX token registry.  Each token issued by OFFLOAD_READ is`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] ` * recorded here keyed by its random nonce.  OFFLOAD_WRITE validates`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] ` * tokens by looking them up in this table, which prevents forgery --`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] ` * an attacker cannot construct a valid token without the server having`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] ` * issued it.`
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] `/* Default ODX token lifetime when client specifies 0: 30 seconds */`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] `#define KSMBD_ODX_DEFAULT_TTL_MS	30000`
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `struct ksmbd_odx_token_entry {`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `	struct hlist_node	node;`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] `	u8			nonce[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] `	__le64			file_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] `	__le64			offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [NONE] `	__le64			length;`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [NONE] `	__le64			generation;`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] `	unsigned long		expire_jiffies; /* absolute expiry time */`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] `	__u64			session_id;	/* session that created this token */`
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `#define KSMBD_ODX_TOKEN_HASH_BITS	8`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [NONE] `static DEFINE_HASHTABLE(odx_token_table, KSMBD_ODX_TOKEN_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L02218 [NONE] `static DEFINE_SPINLOCK(odx_token_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] `static u32 odx_nonce_hash(const u8 *nonce)`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] `	 * Use jhash over all 16 nonce bytes to produce a well-distributed`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] `	 * hash key, avoiding the O(n) collision degradation that occurs`
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `	 * when only the first 4 bytes are used (P1-ODX-01).`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `	return jhash(nonce, 16, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [NONE] `static void odx_token_store(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02231 [NONE] `			    const struct ksmbd_odx_token *token,`
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] `			    u32 ttl_ms)`
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `	struct ksmbd_odx_token_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [MEM_BOUNDS|] `	entry = kmalloc(sizeof(*entry), GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02237 [NONE] `	if (!entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [MEM_BOUNDS|] `	memcpy(entry->nonce, token->nonce, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02241 [NONE] `	entry->file_id = token->file_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] `	entry->offset = token->offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] `	entry->length = token->length;`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] `	entry->generation = token->generation;`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] `	/* F1: Bind token to the issuing session to prevent cross-session reuse */`
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `	entry->session_id = work->sess ? work->sess->id : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `	/* F.9: Respect client-provided TTL; default to 30s if zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `	if (ttl_ms == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `		ttl_ms = KSMBD_ODX_DEFAULT_TTL_MS;`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [NONE] `	entry->expire_jiffies = jiffies + msecs_to_jiffies(ttl_ms);`
  Review: Low-risk line; verify in surrounding control flow.
- L02253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02254 [LOCK|] `	spin_lock(&odx_token_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02255 [NONE] `	hash_add(odx_token_table, &entry->node,`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] `		 odx_nonce_hash(entry->nonce));`
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [LOCK|] `	spin_unlock(&odx_token_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02258 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `static bool odx_token_validate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] `			       const struct ksmbd_odx_token *token)`
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `	struct ksmbd_odx_token_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `	struct hlist_node *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] `	u32 key = odx_nonce_hash(token->nonce);`
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [NONE] `	unsigned long now = jiffies;`
  Review: Low-risk line; verify in surrounding control flow.
- L02267 [NONE] `	__u64 caller_session_id = work->sess ? work->sess->id : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `	bool found = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [LOCK|] `	spin_lock(&odx_token_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02271 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `	 * F.9: Use hash_for_each_possible_safe so we can lazily expire stale`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [NONE] `	 * tokens in the same pass without needing a second lock acquisition.`
  Review: Low-risk line; verify in surrounding control flow.
- L02274 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] `	hash_for_each_possible_safe(odx_token_table, entry, tmp, node, key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] `		/* Lazily expire stale tokens we encounter in this bucket */`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] `		if (time_after(now, entry->expire_jiffies)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `			ksmbd_debug(SMB, "ODX: expiring stale token\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `			hash_del(&entry->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `			kfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] `		if (memcmp(entry->nonce, token->nonce, 16) == 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] `		    entry->file_id == token->file_id &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] `		    entry->offset == token->offset &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] `		    entry->length == token->length &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `		    entry->generation == token->generation) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [NONE] `			 * F1: Security check — reject cross-session token use.`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [NONE] `			 * A token issued by session A MUST NOT be redeemable by`
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] `			 * session B.  This prevents an attacker who has captured`
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `			 * a nonce from impersonating another session's ODX token.`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [NONE] `			if (entry->session_id != caller_session_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02296 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] `					    "ODX: cross-session token rejected "`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] `					    "(token sess %llu, caller sess %llu)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] `					    entry->session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [NONE] `					    caller_session_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02301 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `			/* Consume the token: one-time use */`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `			hash_del(&entry->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `			kfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] `			found = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [LOCK|] `	spin_unlock(&odx_token_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `	return found;`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02315 [NONE] `static void odx_token_cleanup(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] `	struct ksmbd_odx_token_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `	struct hlist_node *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `	int bkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [LOCK|] `	spin_lock(&odx_token_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02322 [NONE] `	hash_for_each_safe(odx_token_table, bkt, tmp, entry, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `		hash_del(&entry->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `		kfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [LOCK|] `	spin_unlock(&odx_token_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02327 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] `struct offload_read_input {`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `	__le32 Size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] `	__le32 TokenTimeToLive;`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] `	__le32 Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [NONE] `	__le64 FileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] `	__le64 CopyLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] `struct offload_read_output {`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] `	__le32 Size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `	__le64 TransferLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] `	u8     Token[STORAGE_OFFLOAD_TOKEN_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `/* MS-FSCC 2.3.55 FSCTL_OFFLOAD_WRITE input/output */`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] `struct offload_write_input {`
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `	__le32 Size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] `	__le64 FileOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `	__le64 CopyLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] `	__le64 TransferOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [NONE] `	u8     Token[STORAGE_OFFLOAD_TOKEN_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] `struct offload_write_output {`
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [NONE] `	__le32 Size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02357 [NONE] `	__le32 Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `	__le64 LengthWritten;`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [NONE] `static int fsctl_offload_read_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02362 [NONE] `				      u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] `				      unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [NONE] `				      unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [NONE] `				      struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02366 [NONE] `				      unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] `	struct offload_read_input *input;`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] `	struct offload_read_output *output;`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [NONE] `	struct ksmbd_odx_token *token;`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] `	u64 offset, length, file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] `	unsigned int out_sz = sizeof(*output);`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] `	if (in_buf_len < sizeof(*input)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02378 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02379 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] `	if (max_out_len < out_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02383 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02384 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `	input = (struct offload_read_input *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `	/* Validate the input Size field per MS-FSCC */`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] `	if (le32_to_cpu(input->Size) < sizeof(*input)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02391 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02392 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02394 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [NONE] `	 * MS-FSCC §2.3.53: TokenTimeToLive is in milliseconds; 0 means`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] `	 * server chooses default TTL (KSMBD_ODX_DEFAULT_TTL_MS = 30s).`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] `	 * The TTL is passed to odx_token_store() and enforced during`
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] `	 * OFFLOAD_WRITE validation via lazy expiry (F.9).`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `	ksmbd_debug(SMB, "OFFLOAD_READ: TokenTimeToLive=%u ms\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [NONE] `		    le32_to_cpu(input->TokenTimeToLive));`
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [NONE] `	offset = le64_to_cpu(input->FileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02404 [NONE] `	length = le64_to_cpu(input->CopyLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02409 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02410 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] `	/* Verify the handle has read access */`
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] `	if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02416 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02417 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] `	file_size = i_size_read(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02422 [NONE] `	/* Clamp transfer length to available data */`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `	if (offset >= file_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `		length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `	else if (offset + length > file_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `		length = file_size - offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] `	output = (struct offload_read_output *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `	memset(output, 0, out_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] `	output->Size = cpu_to_le32(out_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `	output->TransferLength = cpu_to_le64(length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `	/* Build server-local token */`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] `	token = (struct ksmbd_odx_token *)output->Token;`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] `	memset(token, 0, STORAGE_OFFLOAD_TOKEN_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] `	token->magic = cpu_to_le32(KSMBD_ODX_TOKEN_MAGIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] `	token->file_id = cpu_to_le64(inode->i_ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] `	token->offset = cpu_to_le64(offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] `	token->length = cpu_to_le64(length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] `	token->generation = cpu_to_le64(inode->i_generation);`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `	get_random_bytes(token->nonce, sizeof(token->nonce));`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [NONE] `	/* Store the token server-side so OFFLOAD_WRITE can validate it */`
  Review: Low-risk line; verify in surrounding control flow.
- L02444 [NONE] `	odx_token_store(work, token, le32_to_cpu(input->TokenTimeToLive));`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] `	*out_len = out_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [NONE] ` * fsctl_offload_write_handler() - Handle FSCTL_OFFLOAD_WRITE (ODX write)`
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] ` * Validates the server-local ODX token produced by a prior OFFLOAD_READ,`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] ` * locates the source file by inode number within the session's open handles,`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] ` * and uses vfs_copy_file_range() to perform the data transfer.`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] ` * MS-FSCC 2.3.55: The token encodes the source file identity and the range`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [NONE] ` * to copy.  TransferOffset selects the starting position within the`
  Review: Low-risk line; verify in surrounding control flow.
- L02460 [NONE] ` * token-described range.`
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] `static int fsctl_offload_write_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `	struct offload_write_input *input;`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [NONE] `	struct offload_write_output *output;`
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [NONE] `	struct ksmbd_odx_token *token;`
  Review: Low-risk line; verify in surrounding control flow.
- L02472 [NONE] `	struct ksmbd_file *dst_fp = NULL, *src_fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [NONE] `	struct inode *src_inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02474 [NONE] `	loff_t src_off, dst_off, copy_len, token_off, token_len, xfer_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L02475 [NONE] `	loff_t remaining, copied_total = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [NONE] `	ssize_t copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L02477 [NONE] `	unsigned int out_sz = sizeof(*output);`
  Review: Low-risk line; verify in surrounding control flow.
- L02478 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02482 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02483 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02485 [NONE] `	if (in_buf_len < sizeof(*input)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02486 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02487 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02488 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02489 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02490 [NONE] `	if (max_out_len < out_sz) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02491 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02492 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02493 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `	input = (struct offload_write_input *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [NONE] `	token = (struct ksmbd_odx_token *)input->Token;`
  Review: Low-risk line; verify in surrounding control flow.
- L02497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] `	/* Validate the input Size field per MS-FSCC */`
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `	if (le32_to_cpu(input->Size) < sizeof(*input)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02501 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02502 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `	/* Validate the ODX token magic */`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [NONE] `	if (le32_to_cpu(token->magic) != KSMBD_ODX_TOKEN_MAGIC) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02506 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `			    "OFFLOAD_WRITE: invalid token magic 0x%08x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [NONE] `			    le32_to_cpu(token->magic));`
  Review: Low-risk line; verify in surrounding control flow.
- L02509 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_TOKEN;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02510 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02511 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [NONE] `	 * Validate the token against the server-side registry.`
  Review: Low-risk line; verify in surrounding control flow.
- L02515 [NONE] `	 * This prevents forged tokens -- only tokens issued by a prior`
  Review: Low-risk line; verify in surrounding control flow.
- L02516 [NONE] `	 * OFFLOAD_READ are accepted.  The token is consumed (one-time use).`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] `	if (!odx_token_validate(work, token)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [NONE] `			    "OFFLOAD_WRITE: token validation failed (forged or reused)\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02521 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_TOKEN;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02522 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02523 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] `	token_off = le64_to_cpu(token->offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [NONE] `	token_len = le64_to_cpu(token->length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02527 [NONE] `	dst_off = le64_to_cpu(input->FileOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02528 [NONE] `	copy_len = le64_to_cpu(input->CopyLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L02529 [NONE] `	xfer_off = le64_to_cpu(input->TransferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] `	 * TransferOffset is an offset into the token's range.`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] `	 * The actual source offset = token->offset + TransferOffset.`
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] `	 * The available length from that point = token->length - TransferOffset.`
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] `	if (token_off < 0 || xfer_off < 0 || xfer_off > token_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02538 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02539 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] `	/* Guard against signed overflow in token_off + xfer_off */`
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [MEM_BOUNDS|] `	if (check_add_overflow(token_off, xfer_off, &src_off)) {`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02543 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02544 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02545 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [NONE] `	/* Clamp copy length to the available token range */`
  Review: Low-risk line; verify in surrounding control flow.
- L02548 [NONE] `	if (copy_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `		copy_len = token_len - xfer_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] `	else if (copy_len > token_len - xfer_off)`
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [NONE] `		copy_len = token_len - xfer_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L02552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] `	if (copy_len <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] `		/* Nothing to copy -- return zero bytes written */`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [ERROR_PATH|] `		goto out_success;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02556 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02558 [NONE] `	/* Look up the destination file */`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [NONE] `	dst_fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02560 [NONE] `	if (!dst_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02562 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02563 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02565 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02566 [NONE] `	 * Find the source file by inode number from the token.`
  Review: Low-risk line; verify in surrounding control flow.
- L02567 [NONE] `	 * The token encodes the inode number and generation from`
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] `	 * the OFFLOAD_READ that created it.`
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02570 [NONE] `	src_fp = ksmbd_lookup_fd_inode_sess(work, le64_to_cpu(token->file_id));`
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [NONE] `	if (!src_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02572 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [NONE] `			    "OFFLOAD_WRITE: source inode %llu not found in session\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02574 [NONE] `			    le64_to_cpu(token->file_id));`
  Review: Low-risk line; verify in surrounding control flow.
- L02575 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02576 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L02577 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02578 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02580 [NONE] `	/* Verify the source handle has read access */`
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] `	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02583 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02585 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02586 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02587 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [NONE] `	 * Validate the inode generation to ensure the source file`
  Review: Low-risk line; verify in surrounding control flow.
- L02589 [NONE] `	 * is the same one that was originally read (i.e., the inode`
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] `	 * number has not been recycled).`
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [NONE] `	src_inode = file_inode(src_fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02593 [NONE] `	if (src_inode->i_generation != (u32)le64_to_cpu(token->generation)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] `			    "OFFLOAD_WRITE: generation mismatch (%u vs %llu)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] `			    src_inode->i_generation,`
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [NONE] `			    le64_to_cpu(token->generation));`
  Review: Low-risk line; verify in surrounding control flow.
- L02598 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02599 [NONE] `		ret = -ESTALE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02601 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02602 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] `	/* Break any level-II oplocks on the destination */`
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [NONE] `	smb_break_all_levII_oplock(work, dst_fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02606 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [NONE] `	 * Perform the copy using vfs_copy_file_range().  This handles`
  Review: Low-risk line; verify in surrounding control flow.
- L02608 [NONE] `	 * reflink, server-side copy, and splice fallback transparently.`
  Review: Low-risk line; verify in surrounding control flow.
- L02609 [NONE] `	 * Loop to handle partial copies.`
  Review: Low-risk line; verify in surrounding control flow.
- L02610 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02611 [NONE] `	remaining = copy_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02612 [NONE] `	while (remaining > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02613 [NONE] `		copied = vfs_copy_file_range(src_fp->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] `					     dst_fp->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [NONE] `					     remaining, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02616 [NONE] `		if (copied <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02617 [NONE] `			if (copied == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02618 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] `			if (copied == -EOPNOTSUPP || copied == -EXDEV) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] `				 * Filesystem does not support copy_file_range`
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] `				 * between these files.  Report what we have`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] `				 * copied so far; the client can fall back to`
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [NONE] `				 * COPYCHUNK for the remainder.`
  Review: Low-risk line; verify in surrounding control flow.
- L02625 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02626 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02628 [NONE] `			ret = copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [NONE] `			if (ret == -ENOSPC || ret == -EFBIG)`
  Review: Low-risk line; verify in surrounding control flow.
- L02630 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02631 [NONE] `			else if (ret == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02633 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L02634 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02635 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02636 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [NONE] `		src_off += copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L02638 [NONE] `		dst_off += copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L02639 [NONE] `		remaining -= copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] `		copied_total += copied;`
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02643 [NONE] `out_success:`
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `	output = (struct offload_write_output *)&rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `	memset(output, 0, out_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [NONE] `	output->Size = cpu_to_le32(out_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L02647 [NONE] `	output->LengthWritten = cpu_to_le64(copied_total);`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [NONE] `	*out_len = out_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L02649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02650 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02651 [NONE] `	ksmbd_fd_put(work, src_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02652 [NONE] `	ksmbd_fd_put(work, dst_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02653 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02654 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] ` * fsctl_srv_read_hash_handler() - FSCTL_SRV_READ_HASH (BranchCache)`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] ` * BranchCache content information retrieval per MS-PCCRC.`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] ` * Computes Content Information V1 (SHA-256) hashes for the requested`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] ` * file range and returns them to the client for peer-to-peer caching.`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02663 [NONE] `static int fsctl_srv_read_hash_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [NONE] `				       u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02665 [NONE] `				       unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02666 [NONE] `				       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02667 [NONE] `				       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] `				       unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02671 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02672 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] `	if (in_buf_len < sizeof(struct srv_read_hash_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02675 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02676 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02677 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02682 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `	ret = ksmbd_branchcache_read_hash(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `					  in_buf, in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] `					  &rsp->Buffer[0],`
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `					  max_out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02690 [NONE] `	if (ret == -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_HASH_NOT_PRESENT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02692 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02694 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [NONE] `	if (ret == -E2BIG) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02696 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02697 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02698 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02699 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [NONE] `	if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02701 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02702 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02703 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [NONE] `	*out_len = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02706 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02709 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02710 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02711 [NONE] ` *  Built-in handler table`
  Review: Low-risk line; verify in surrounding control flow.
- L02712 [NONE] ` * ============================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02713 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02714 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `static struct ksmbd_fsctl_handler builtin_fsctl_handlers[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] `		.ctl_code = FSCTL_GET_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [NONE] `		.handler  = fsctl_get_object_id_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02719 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02722 [NONE] `		.ctl_code = FSCTL_SET_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02723 [NONE] `		.handler  = fsctl_set_object_id_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02724 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02727 [NONE] `		.ctl_code = FSCTL_DELETE_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] `		.handler  = fsctl_delete_object_id_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02730 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02731 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [NONE] `		.ctl_code = FSCTL_SET_OBJECT_ID_EXTENDED,`
  Review: Low-risk line; verify in surrounding control flow.
- L02733 [NONE] `		.handler  = fsctl_set_object_id_extended_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] `		.ctl_code = FSCTL_CREATE_OR_GET_OBJECT_ID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `		.handler  = fsctl_create_or_get_object_id_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02740 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02742 [NONE] `		.ctl_code = FSCTL_GET_COMPRESSION,`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] `		.handler  = fsctl_get_compression_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [NONE] `		.ctl_code = FSCTL_SET_COMPRESSION,`
  Review: Low-risk line; verify in surrounding control flow.
- L02748 [NONE] `		.handler  = fsctl_set_compression_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02749 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02750 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] `		.ctl_code = FSCTL_QUERY_NETWORK_INTERFACE_INFO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] `		.handler  = fsctl_query_network_interface_info_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02755 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02756 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [NONE] `		.ctl_code = FSCTL_REQUEST_RESUME_KEY,`
  Review: Low-risk line; verify in surrounding control flow.
- L02758 [NONE] `		.handler  = fsctl_request_resume_key_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02761 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02762 [NONE] `		.ctl_code = FSCTL_SET_SPARSE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] `		.handler  = fsctl_set_sparse_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] `		.ctl_code = FSCTL_COPYCHUNK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] `		.handler  = fsctl_copychunk_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [NONE] `		.ctl_code = FSCTL_COPYCHUNK_WRITE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02773 [NONE] `		.handler  = fsctl_copychunk_write_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02774 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02775 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02776 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02777 [NONE] `		.ctl_code = FSCTL_DUPLICATE_EXTENTS_TO_FILE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02778 [NONE] `		.handler  = fsctl_duplicate_extents_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02779 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02780 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02781 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02782 [NONE] `			.ctl_code = FSCTL_SET_ZERO_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L02783 [NONE] `			.handler  = fsctl_set_zero_data_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02784 [NONE] `			.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02785 [NONE] `		},`
  Review: Low-risk line; verify in surrounding control flow.
- L02786 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02787 [NONE] `			.ctl_code = FSCTL_QUERY_ALLOCATED_RANGES,`
  Review: Low-risk line; verify in surrounding control flow.
- L02788 [NONE] `			.handler  = fsctl_query_allocated_ranges_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02789 [NONE] `			.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02790 [NONE] `		},`
  Review: Low-risk line; verify in surrounding control flow.
- L02791 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02792 [NONE] `			.ctl_code = FSCTL_IS_PATHNAME_VALID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02793 [NONE] `			.handler  = fsctl_is_pathname_valid_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02794 [NONE] `			.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02795 [NONE] `		},`
  Review: Low-risk line; verify in surrounding control flow.
- L02796 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02797 [NONE] `		.ctl_code = FSCTL_IS_VOLUME_DIRTY,`
  Review: Low-risk line; verify in surrounding control flow.
- L02798 [NONE] `		.handler  = fsctl_is_volume_dirty_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02799 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02800 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02801 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02802 [NONE] `		.ctl_code = FSCTL_ALLOW_EXTENDED_DASD_IO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02803 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02804 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02805 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02806 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02807 [NONE] `		.ctl_code = FSCTL_ENCRYPTION_FSCTL_IO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02808 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02809 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02810 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02811 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02812 [NONE] `		.ctl_code = FSCTL_FILESYSTEM_GET_STATS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02813 [NONE] `		.handler  = fsctl_filesystem_get_stats_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02814 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02815 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02816 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02817 [NONE] `		.ctl_code = FSCTL_FIND_FILES_BY_SID,`
  Review: Low-risk line; verify in surrounding control flow.
- L02818 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02819 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02820 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02821 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02822 [NONE] `			.ctl_code = FSCTL_GET_NTFS_VOLUME_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L02823 [NONE] `			.handler  = fsctl_get_ntfs_volume_data_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02824 [NONE] `			.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02825 [NONE] `		},`
  Review: Low-risk line; verify in surrounding control flow.
- L02826 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02827 [NONE] `			.ctl_code = FSCTL_GET_RETRIEVAL_POINTERS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02828 [NONE] `			.handler  = fsctl_get_retrieval_pointers_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02829 [NONE] `			.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02830 [NONE] `		},`
  Review: Low-risk line; verify in surrounding control flow.
- L02831 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02832 [NONE] `		.ctl_code = FSCTL_LMR_GET_LINK_TRACK_INF,`
  Review: Low-risk line; verify in surrounding control flow.
- L02833 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02834 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02835 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02836 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02837 [NONE] `		.ctl_code = FSCTL_LMR_SET_LINK_TRACK_INF,`
  Review: Low-risk line; verify in surrounding control flow.
- L02838 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02839 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02840 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02841 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02842 [NONE] `		.ctl_code = FSCTL_LOCK_VOLUME,`
  Review: Low-risk line; verify in surrounding control flow.
- L02843 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02844 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02845 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02846 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L02847 [NONE] `			.ctl_code = FSCTL_PIPE_PEEK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02848 [NONE] `			.handler  = fsctl_pipe_peek_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02849 [NONE] `			.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02850 [NONE] `		},`
  Review: Low-risk line; verify in surrounding control flow.
- L02851 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02852 [NONE] `		.ctl_code = FSCTL_QUERY_FAT_BPB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02853 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02854 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02855 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02856 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02857 [NONE] `		.ctl_code = FSCTL_QUERY_SPARING_INFO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02858 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02859 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02860 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02861 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02862 [NONE] `		.ctl_code = FSCTL_READ_FILE_USN_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L02863 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02864 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02865 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02866 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02867 [NONE] `		.ctl_code = FSCTL_READ_RAW_ENCRYPTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L02868 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02869 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02870 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02871 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02872 [NONE] `		.ctl_code = FSCTL_RECALL_FILE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02873 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02874 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02875 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02876 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02877 [NONE] `		.ctl_code = FSCTL_REQUEST_BATCH_OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02878 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02879 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02880 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02881 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02882 [NONE] `		.ctl_code = FSCTL_REQUEST_FILTER_OPLOCK,`
  Review: Low-risk line; verify in surrounding control flow.
- L02883 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02884 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02885 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02886 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02887 [NONE] `		.ctl_code = FSCTL_REQUEST_OPLOCK_LEVEL_1,`
  Review: Low-risk line; verify in surrounding control flow.
- L02888 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02889 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02890 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02891 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02892 [NONE] `		.ctl_code = FSCTL_REQUEST_OPLOCK_LEVEL_2,`
  Review: Low-risk line; verify in surrounding control flow.
- L02893 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02894 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02895 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02896 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02897 [NONE] `		.ctl_code = FSCTL_SET_DEFECT_MANAGEMENT,`
  Review: Low-risk line; verify in surrounding control flow.
- L02898 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02899 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02900 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02901 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02902 [NONE] `		.ctl_code = FSCTL_SET_ENCRYPTION,`
  Review: Low-risk line; verify in surrounding control flow.
- L02903 [NONE] `		.handler  = fsctl_set_encryption_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02904 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02905 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02906 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02907 [NONE] `		.ctl_code = FSCTL_SET_SHORT_NAME_BEHAVIOR,`
  Review: Low-risk line; verify in surrounding control flow.
- L02908 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02909 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02910 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02911 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02912 [NONE] `		.ctl_code = FSCTL_SET_ZERO_ON_DEALLOC,`
  Review: Low-risk line; verify in surrounding control flow.
- L02913 [NONE] `		.handler  = fsctl_set_zero_on_dealloc_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02914 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02915 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02916 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02917 [NONE] `		.ctl_code = FSCTL_SIS_COPYFILE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02918 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02919 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02920 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02921 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02922 [NONE] `		.ctl_code = FSCTL_SIS_LINK_FILES,`
  Review: Low-risk line; verify in surrounding control flow.
- L02923 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02924 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02925 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02926 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02927 [NONE] `		.ctl_code = FSCTL_UNLOCK_VOLUME,`
  Review: Low-risk line; verify in surrounding control flow.
- L02928 [NONE] `		.handler  = fsctl_stub_noop_success_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02929 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02930 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02931 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02932 [NONE] `		.ctl_code = FSCTL_WRITE_RAW_ENCRYPTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L02933 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02934 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02935 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02936 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02937 [NONE] `		.ctl_code = FSCTL_WRITE_USN_CLOSE_RECORD,`
  Review: Low-risk line; verify in surrounding control flow.
- L02938 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02939 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02940 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02941 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02942 [NONE] `		.ctl_code = FSCTL_VALIDATE_NEGOTIATE_INFO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02943 [NONE] `		.handler  = fsctl_validate_negotiate_info_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02944 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02945 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02946 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02947 [NONE] `		.ctl_code = FSCTL_PIPE_TRANSCEIVE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02948 [NONE] `		.handler  = fsctl_pipe_transceive_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02949 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02950 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02951 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02952 [NONE] `		.ctl_code = FSCTL_QUERY_FILE_REGIONS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02953 [NONE] `		.handler  = fsctl_query_file_regions_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02954 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02955 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02956 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02957 [NONE] `		.ctl_code = FSCTL_GET_INTEGRITY_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L02958 [NONE] `		.handler  = fsctl_get_integrity_info_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02959 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02960 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02961 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02962 [NONE] `		.ctl_code = FSCTL_SET_INTEGRITY_INFORMATION,`
  Review: Low-risk line; verify in surrounding control flow.
- L02963 [NONE] `		.handler  = fsctl_set_integrity_info_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02964 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02965 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02966 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02967 [NONE] `		.ctl_code = FSCTL_SET_INTEGRITY_INFORMATION_EX,`
  Review: Low-risk line; verify in surrounding control flow.
- L02968 [NONE] `		.handler  = fsctl_set_integrity_info_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02969 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02970 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02971 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02972 [NONE] `		.ctl_code = FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX,`
  Review: Low-risk line; verify in surrounding control flow.
- L02973 [NONE] `		.handler  = fsctl_duplicate_extents_ex_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02974 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02975 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02976 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02977 [NONE] `		.ctl_code = FSCTL_MARK_HANDLE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02978 [NONE] `		.handler  = fsctl_mark_handle_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02979 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02980 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02981 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02982 [NONE] `		.ctl_code = FSCTL_OFFLOAD_READ,`
  Review: Low-risk line; verify in surrounding control flow.
- L02983 [NONE] `		.handler  = fsctl_offload_read_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02984 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02985 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02986 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02987 [NONE] `		.ctl_code = FSCTL_OFFLOAD_WRITE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02988 [NONE] `		.handler  = fsctl_offload_write_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02989 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02990 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02991 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02992 [NONE] `		.ctl_code = FSCTL_SRV_READ_HASH,`
  Review: Low-risk line; verify in surrounding control flow.
- L02993 [NONE] `		.handler  = fsctl_srv_read_hash_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02994 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02995 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L02996 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02997 [NONE] `		/* MS-SMB2 §2.2.31.1.1.5: not supported on non-NTFS volumes */`
  Review: Low-risk line; verify in surrounding control flow.
- L02998 [NONE] `		.ctl_code = FSCTL_QUERY_ON_DISK_VOLUME_INFO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02999 [NONE] `		.handler  = fsctl_not_supported_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L03000 [NONE] `		.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L03001 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L03002 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L03003 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03004 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03005 [NONE] ` * ksmbd_fsctl_init() - Initialize FSCTL dispatch table with built-in handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L03006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03007 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L03008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03009 [NONE] `int ksmbd_fsctl_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L03010 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03011 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03013 [NONE] `	hash_init(fsctl_handlers);`
  Review: Low-risk line; verify in surrounding control flow.
- L03014 [NONE] `	hash_init(odx_token_table);`
  Review: Low-risk line; verify in surrounding control flow.
- L03015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03016 [NONE] `	for (i = 0; i < ARRAY_SIZE(builtin_fsctl_handlers); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03017 [NONE] `		ret = ksmbd_register_fsctl(&builtin_fsctl_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L03018 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03019 [ERROR_PATH|] `			pr_err("Failed to register FSCTL 0x%08x: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03020 [NONE] `			       builtin_fsctl_handlers[i].ctl_code, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L03021 [ERROR_PATH|] `			goto err_unregister;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03022 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03023 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03025 [NONE] `	ksmbd_debug(SMB, "Registered %zu built-in FSCTL handlers\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L03026 [NONE] `		    ARRAY_SIZE(builtin_fsctl_handlers));`
  Review: Low-risk line; verify in surrounding control flow.
- L03027 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03029 [NONE] `err_unregister:`
  Review: Low-risk line; verify in surrounding control flow.
- L03030 [NONE] `	while (--i >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03031 [NONE] `		ksmbd_unregister_fsctl(&builtin_fsctl_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L03032 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03033 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03035 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03036 [NONE] ` * ksmbd_fsctl_exit() - Unregister all FSCTL handlers and clean up`
  Review: Low-risk line; verify in surrounding control flow.
- L03037 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03038 [NONE] `void ksmbd_fsctl_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L03039 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03040 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L03041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03042 [NONE] `	for (i = 0; i < ARRAY_SIZE(builtin_fsctl_handlers); i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L03043 [NONE] `		ksmbd_unregister_fsctl(&builtin_fsctl_handlers[i]);`
  Review: Low-risk line; verify in surrounding control flow.
- L03044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03045 [NONE] `	/* Free any outstanding ODX tokens */`
  Review: Low-risk line; verify in surrounding control flow.
- L03046 [NONE] `	odx_token_cleanup();`
  Review: Low-risk line; verify in surrounding control flow.
- L03047 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
