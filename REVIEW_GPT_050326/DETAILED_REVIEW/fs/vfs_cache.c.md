# Line-by-line Review: src/fs/vfs_cache.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` * Copyright (C) 2019 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/vmalloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/kthread.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/freezer.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define S_DEL_PENDING			1`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define S_DEL_ON_CLS			2`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define S_DEL_ON_CLS_STREAM		8`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define S_POSIX_OPENED			16`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `static unsigned int inode_hash_mask __read_mostly;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `static unsigned int inode_hash_shift __read_mostly;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * struct ksmbd_inode_hash_bucket - per-bucket inode hash entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * @head:	hash chain list head`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * @lock:	per-bucket rwlock for reduced contention`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `struct ksmbd_inode_hash_bucket {`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	struct hlist_head	head;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	rwlock_t		lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `static struct ksmbd_inode_hash_bucket *inode_hashtable __read_mostly;`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `static struct ksmbd_file_table global_ft;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [LIFETIME|] `static atomic_long_t fd_limit;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00051 [NONE] `static struct kmem_cache *filp_cache;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `static bool durable_scavenger_running;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `static DEFINE_MUTEX(durable_scavenger_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `static wait_queue_head_t dh_wq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `void ksmbd_set_fd_limit(unsigned long limit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	limit = min(limit, get_max_files());`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [LIFETIME|] `	atomic_long_set(&fd_limit, limit);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00061 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `static bool fd_limit_depleted(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [LIFETIME|] `	long v = atomic_long_dec_return(&fd_limit);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	if (v >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [LIFETIME|] `	atomic_long_inc(&fd_limit);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00070 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `static void fd_limit_close(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [LIFETIME|] `	atomic_long_inc(&fd_limit);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00076 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * INODE hash`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `static unsigned long inode_hash(struct super_block *sb, unsigned long hashval)`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	unsigned long tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		L1_CACHE_BYTES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> inode_hash_shift);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	return tmp & inode_hash_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `static struct ksmbd_inode *__ksmbd_inode_lookup(struct dentry *de)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	unsigned long bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		inode_hash(d_inode(de)->i_sb, (unsigned long)de);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	struct ksmbd_inode *ci = NULL, *ret_ci = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	hlist_for_each_entry(ci, &inode_hashtable[bucket].head, m_hash) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		if (ci->m_de == de) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [LIFETIME|] `			if (atomic_inc_not_zero(&ci->m_count))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00101 [NONE] `				ret_ci = ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	return ret_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `static struct ksmbd_inode *ksmbd_inode_lookup(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	return __ksmbd_inode_lookup(fp->filp->f_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `struct ksmbd_inode *ksmbd_inode_lookup_lock(struct dentry *d)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	unsigned long bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		inode_hash(d_inode(d)->i_sb, (unsigned long)d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	read_lock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	ci = __ksmbd_inode_lookup(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	read_unlock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	return ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `int ksmbd_query_inode_status(struct dentry *dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [PROTO_GATE|] `	int ret = KSMBD_INODE_STATUS_UNKNOWN;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00130 [NONE] `	unsigned long bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `		inode_hash(d_inode(dentry)->i_sb, (unsigned long)dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	read_lock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	ci = __ksmbd_inode_lookup(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	read_unlock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	if (!ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00140 [NONE] `	if (ci->m_flags & (S_DEL_PENDING | S_DEL_ON_CLS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [PROTO_GATE|] `		ret = KSMBD_INODE_STATUS_PENDING_DELETE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00142 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [PROTO_GATE|] `		ret = KSMBD_INODE_STATUS_OK;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00144 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	ksmbd_inode_put(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `bool ksmbd_inode_pending_delete(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00156 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	 * Only S_DEL_PENDING (set via FileDispositionInformation) blocks new`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [PROTO_GATE|] `	 * opens with STATUS_DELETE_PENDING.  S_DEL_ON_CLS is a per-handle`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00159 [NONE] `	 * property (FILE_DELETE_ON_CLOSE in CreateOptions); the file is simply`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	 * deleted when the last handle closes, but new opens are permitted in`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	 * the meantime -- matching Windows Server behaviour per MS-SMB2`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	 * §3.3.5.9.6.`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	ret = (ci->m_flags & S_DEL_PENDING);`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `bool ksmbd_inode_clear_pending_delete_if_only(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	bool cleared = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00176 [NONE] `	if ((ci->m_flags & (S_DEL_PENDING | S_DEL_ON_CLS)) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	    list_is_singular(&ci->m_fp_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		ci->m_flags &= ~(S_DEL_PENDING | S_DEL_ON_CLS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		cleared = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	return cleared;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `void ksmbd_set_inode_pending_delete(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00191 [NONE] `	ci->m_flags |= S_DEL_PENDING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00193 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `void ksmbd_clear_inode_pending_delete(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00200 [NONE] `	ci->m_flags &= ~S_DEL_PENDING;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00202 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `void ksmbd_fd_set_delete_on_close(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `				  int file_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	fp->is_delete_on_close = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00211 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		ci->m_flags |= S_DEL_ON_CLS_STREAM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		ci->m_flags |= S_DEL_ON_CLS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00216 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ` * ksmbd_inode_set_posix() - mark inode as having a POSIX context handle`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ` * @ci:	ksmbd inode`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ` * Must be called with ci->m_lock held for writing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `void ksmbd_inode_set_posix(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	ci->m_flags |= S_POSIX_OPENED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `static void ksmbd_inode_hash(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	unsigned long bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		inode_hash(d_inode(ci->m_de)->i_sb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `			   (unsigned long)ci->m_de);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	hlist_add_head(&ci->m_hash, &inode_hashtable[bucket].head);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `static void ksmbd_inode_unhash(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	unsigned long bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		inode_hash(d_inode(ci->m_de)->i_sb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `			   (unsigned long)ci->m_de);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	write_lock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	hlist_del_init(&ci->m_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	write_unlock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `static int ksmbd_inode_init(struct ksmbd_inode *ci, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [LIFETIME|] `	atomic_set(&ci->m_count, 1);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00252 [LIFETIME|] `	atomic_set(&ci->op_count, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00253 [LIFETIME|] `	atomic_set(&ci->sop_count, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00254 [NONE] `	ci->m_flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `	ci->m_fattr = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	ci->m_cached_alloc = -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	INIT_LIST_HEAD(&ci->m_fp_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	INIT_LIST_HEAD(&ci->m_op_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	init_rwsem(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	ci->m_de = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `static struct ksmbd_inode *ksmbd_inode_get(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	struct ksmbd_inode *ci, *tmpci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	struct dentry *de = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	unsigned long bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		inode_hash(d_inode(de)->i_sb, (unsigned long)de);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	read_lock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	ci = ksmbd_inode_lookup(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	read_unlock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	if (ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `		return ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [MEM_BOUNDS|] `	ci = kmalloc(sizeof(struct ksmbd_inode), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00279 [NONE] `	if (!ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	rc = ksmbd_inode_init(ci, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [ERROR_PATH|] `		pr_err("inode initialized failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00285 [NONE] `		kfree(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	write_lock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	tmpci = ksmbd_inode_lookup(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	if (!tmpci) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `		ksmbd_inode_hash(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		kfree(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `		ci = tmpci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	write_unlock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	return ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `static void ksmbd_inode_free(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	ksmbd_inode_unhash(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	kfree(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `void ksmbd_inode_put(struct ksmbd_inode *ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [LIFETIME|] `	if (atomic_dec_and_test(&ci->m_count))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00310 [NONE] `		ksmbd_inode_free(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `int __init ksmbd_inode_hash_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	unsigned int loop;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	unsigned long numentries = 16384;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	unsigned long bucketsize = sizeof(struct ksmbd_inode_hash_bucket);`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	unsigned long size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	inode_hash_shift = ilog2(numentries);`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `	inode_hash_mask = (1 << inode_hash_shift) - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	size = bucketsize << inode_hash_shift;`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	/* init master fp hash table with per-bucket locks */`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [MEM_BOUNDS|] `	inode_hashtable = vmalloc(size);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00327 [NONE] `	if (!inode_hashtable)`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	for (loop = 0; loop < (1U << inode_hash_shift); loop++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		INIT_HLIST_HEAD(&inode_hashtable[loop].head);`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `		rwlock_init(&inode_hashtable[loop].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `void ksmbd_release_inode_hash(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	vfree(inode_hashtable);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	inode_hashtable = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `static void __ksmbd_inode_close(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `	struct dentry *dir, *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	if (ksmbd_stream_fd(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		bool remove_stream_xattr = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [LOCK|] `		down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00358 [NONE] `		if (ci->m_flags & S_DEL_ON_CLS_STREAM) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `			ci->m_flags &= ~S_DEL_ON_CLS_STREAM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `			remove_stream_xattr = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [LOCK|] `		up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		if (remove_stream_xattr) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `			err = ksmbd_vfs_remove_xattr(file_mnt_idmap(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `			err = ksmbd_vfs_remove_xattr(file_mnt_user_ns(filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `						     &filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `						     fp->stream.name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `						     true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [ERROR_PATH|] `				pr_err("remove xattr failed : %s\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00375 [NONE] `				       fp->stream.name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	 * Delete-on-close / delete-pending semantics per MS-SMB2 §3.3.5.9.6`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	 * and Windows NTFS semantics:`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	 * FILE_DELETE_ON_CLOSE (S_DEL_ON_CLS): when the handle that set this`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	 * flag closes, the file is unlinked from the namespace immediately,`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	 * even if other handles remain open -- matching Windows behaviour`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	 * (similar to POSIX unlink).  The remaining handles retain access to`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	 * the file data via their open file descriptor until they close, but`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	 * the name is freed immediately so new creates on the same path`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	 * succeed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	 * If the immediate unlink fails (e.g., ENOTEMPTY for a non-empty`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	 * directory), we fall back to deferred deletion at last-handle close.`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	 * S_DEL_PENDING (set via FileDispositionInformation) is a file-level`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	 * attribute that is NOT cleared here; it persists until the client`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	 * explicitly clears it or the file is deleted on last close.`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	 * ksmbd_inode_pending_delete() only checks S_DEL_PENDING, so new`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	 * opens are not blocked by S_DEL_ON_CLS alone -- callers may open a`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	 * file that has an outstanding delete-on-close handle.`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [LIFETIME|] `	if (!atomic_dec_and_test(&ci->m_count)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00403 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		 * Other handles still open.  If the closing handle had`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `		 * FILE_DELETE_ON_CLOSE set, attempt an immediate unlink to`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		 * match Windows NTFS semantics (unlink-on-DOC-close).`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `		 * (fp->node was already removed from m_fp_list by`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `		 *  __ksmbd_remove_fd before we get here.)`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		if (fp->is_delete_on_close && !ksmbd_stream_fd(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `			bool do_unlink = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [LOCK|] `			down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00414 [NONE] `			if (ci->m_flags & S_DEL_ON_CLS) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `				ci->m_flags &= ~S_DEL_ON_CLS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `				do_unlink = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [LOCK|] `			up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			if (do_unlink) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `				int unlink_err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `				unlink_err = ksmbd_vfs_unlink(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `				{`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `					struct dentry *ud = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `					struct dentry *udir = ud->d_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `					unlink_err = ksmbd_vfs_unlink(`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `						file_mnt_idmap(filp), udir, ud);`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `				{`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `					struct dentry *ud = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `					struct dentry *udir = ud->d_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `					unlink_err = ksmbd_vfs_unlink(`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `						file_mnt_user_ns(filp), udir, ud);`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `				if (unlink_err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `					 * Unlink failed (e.g., ENOTEMPTY).`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `					 * Restore S_DEL_ON_CLS so the`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `					 * last-handle close can retry.`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [LOCK|] `					down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00451 [NONE] `					ci->m_flags |= S_DEL_ON_CLS;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [LOCK|] `					up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00453 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		bool do_unlink = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [LOCK|] `		down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00460 [NONE] `		if (ci->m_flags & (S_DEL_ON_CLS | S_DEL_PENDING)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `			ci->m_flags &= ~(S_DEL_ON_CLS | S_DEL_PENDING);`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `			do_unlink = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [LOCK|] `		up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		if (do_unlink) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `			dentry = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `			dir = dentry->d_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `			ksmbd_vfs_unlink(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `			ksmbd_vfs_unlink(file_mnt_idmap(filp), dir, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `			ksmbd_vfs_unlink(file_mnt_user_ns(filp), dir, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `		ksmbd_inode_free(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `static void __ksmbd_remove_durable_fd(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `	if (!has_file_id(fp->persistent_id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	idr_remove(global_ft.idr, fp->persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `static void ksmbd_remove_durable_fd(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	write_lock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `	__ksmbd_remove_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	write_unlock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	if (waitqueue_active(&dh_wq))`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `		wake_up(&dh_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `static void __ksmbd_remove_fd(struct ksmbd_file_table *ft, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	if (!has_file_id(fp->volatile_id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [LOCK|] `	down_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00510 [NONE] `	list_del_init(&fp->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [LOCK|] `	up_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	write_lock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	idr_remove(ft->idr, fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `static void __ksmbd_close_fd(struct ksmbd_file_table *ft, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `	struct ksmbd_lock *smb_lock, *tmp_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `	/* C.5: cancel the durable expiry timer before freeing the fp */`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	timer_delete_sync(&fp->durable_expire_timer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	fd_limit_close();`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	ksmbd_remove_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	if (ft)`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		__ksmbd_remove_fd(ft, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	close_id_del_oplock(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	__ksmbd_inode_close(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	 * Remove POSIX locks synchronously before fput().`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	 * fput() defers __fput() via task_work in kthreads, so`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	 * POSIX locks may remain visible to concurrent lock`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	 * requests if we rely on deferred cleanup.  This fixes`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	 * the "NT byte range lock bug" where closing a handle`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	 * didn't immediately release its POSIX locks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	if (!IS_ERR_OR_NULL(filp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `		locks_remove_posix(filp, filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	if (!IS_ERR_OR_NULL(filp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	/* because the reference count of fp is 0, it is guaranteed that`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	 * there are not accesses to fp->lock_list.`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	list_for_each_entry_safe(smb_lock, tmp_lock, &fp->lock_list, flist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [LOCK|] `		spin_lock(&fp->conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00555 [NONE] `		list_del(&smb_lock->clist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [LOCK|] `		spin_unlock(&fp->conn->llist_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `		list_del(&smb_lock->flist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		locks_free_lock(smb_lock->fl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `		kfree(smb_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `	kfree(fp->filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `		kfree(fp->stream.name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	kmem_cache_free(filp_cache, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `static struct ksmbd_file *ksmbd_fp_get(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	if (fp->f_state != FP_INITED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [LIFETIME|] `	if (!refcount_inc_not_zero(&fp->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00576 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `static struct ksmbd_file *__ksmbd_lookup_fd(struct ksmbd_file_table *ft,`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `					    u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	if (!has_file_id(id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `	read_lock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `	fp = idr_find(ft->idr, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	if (fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		fp = ksmbd_fp_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	read_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `static void __put_fd_final(struct ksmbd_work *work, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	__ksmbd_close_fd(&work->sess->file_table, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [LIFETIME|] `	atomic_dec(&work->conn->stats.open_files_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00600 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `static void set_close_state_blocked_works(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	struct ksmbd_work *cancel_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [LOCK|] `	spin_lock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00607 [NONE] `	list_for_each_entry(cancel_work, &fp->blocked_works,`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `				 fp_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		struct smb2_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		 * Skip CHANGE_NOTIFY entries — they are handled`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		 * by ksmbd_notify_cleanup_file() which safely`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		 * drops the lock before doing I/O and freeing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `		hdr = smb2_get_msg(cancel_work->request_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [PROTO_GATE|] `		if (hdr->Command == SMB2_CHANGE_NOTIFY ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00618 [NONE] `		    cancel_work->cancel_fn == ksmbd_notify_cancel)`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `		cancel_work->state = KSMBD_WORK_CLOSED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		if (cancel_work->cancel_fn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `			cancel_work->cancel_fn(cancel_work->cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [LOCK|] `	spin_unlock(&fp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00626 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `int ksmbd_close_fd(struct ksmbd_work *work, u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `	struct ksmbd_file	*fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `	struct ksmbd_file_table	*ft;`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	if (!has_file_id(id))`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	ft = &work->sess->file_table;`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `	write_lock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `	fp = idr_find(ft->idr, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	if (fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `		set_close_state_blocked_works(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `		if (fp->f_state != FP_INITED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `			fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `		else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `			fp->f_state = FP_CLOSED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [LIFETIME|] `			if (!refcount_dec_and_test(&fp->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00647 [NONE] `				fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00654 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [PROTO_GATE|] `	 * Notify cleanup sends STATUS_NOTIFY_CLEANUP responses over`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00657 [NONE] `	 * TCP (sleepable) and takes mutexes, so it MUST be called`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	 * outside write_lock(&ft->lock).  fp is safe here because we`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	 * hold the final refcount and f_state is FP_CLOSED, preventing`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	 * new lookups.`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	ksmbd_notify_cleanup_file(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	__put_fd_final(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `void ksmbd_fd_put(struct ksmbd_work *work, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [LIFETIME|] `	if (!refcount_dec_and_test(&fp->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00673 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	__put_fd_final(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `static bool __sanity_check(struct ksmbd_tree_connect *tcon, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	if (fp->tcon != tcon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `struct ksmbd_file *ksmbd_lookup_foreign_fd(struct ksmbd_work *work, u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	return __ksmbd_lookup_fd(&work->sess->file_table, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_fast(struct ksmbd_work *work, u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	struct ksmbd_file *fp = __ksmbd_lookup_fd(&work->sess->file_table, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	if (__sanity_check(work->tcon, fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_slow(struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `					u64 pid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `		id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `		pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	fp = __ksmbd_lookup_fd(&work->sess->file_table, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `	if (!__sanity_check(work->tcon, fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	if (fp->persistent_id != pid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `struct ksmbd_file *ksmbd_lookup_global_fd(unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	return __ksmbd_lookup_fd(&global_ft, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `struct ksmbd_file *ksmbd_lookup_durable_fd(unsigned long long id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	fp = __ksmbd_lookup_fd(&global_ft, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	if (fp && (fp->is_scavenger_claimed ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `		   fp->conn ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `		   (fp->durable_scavenger_timeout &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `		    (fp->durable_scavenger_timeout <`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `		     jiffies_to_msecs(jiffies))))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `		fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `void ksmbd_put_durable_fd(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [LIFETIME|] `	if (!refcount_dec_and_test(&fp->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00749 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `	__ksmbd_close_fd(NULL, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_cguid(char *cguid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	struct ksmbd_file	*fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	unsigned int		id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	read_lock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	idr_for_each_entry(global_ft.idr, fp, id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `		if (!memcmp(fp->create_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `			    cguid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [PROTO_GATE|] `			    SMB2_CREATE_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00764 [NONE] `			fp = ksmbd_fp_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	read_unlock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_filename(struct ksmbd_work *work, char *filename)`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	struct ksmbd_file	*fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	unsigned int		id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `	char			*pathname;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [MEM_BOUNDS|] `	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00781 [NONE] `	if (!pathname)`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `	read_lock(&work->sess->file_table.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `	idr_for_each_entry(work->sess->file_table.idr, fp, id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `		char *path = d_path(&fp->filp->f_path, pathname, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `		if (IS_ERR(path))`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `		if (!strcmp(path, filename)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `			fp = ksmbd_fp_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	read_unlock(&work->sess->file_table.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	kfree(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_inode(struct dentry *dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	struct ksmbd_file	*lfp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	struct ksmbd_inode	*ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	struct inode		*inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	unsigned long		bucket =`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `		inode_hash(inode->i_sb, (unsigned long)dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	read_lock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	ci = __ksmbd_inode_lookup(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	read_unlock(&inode_hashtable[bucket].lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	if (!ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00818 [NONE] `	list_for_each_entry(lfp, &ci->m_fp_list, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `		if (inode == file_inode(lfp->filp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `			lfp = ksmbd_fp_get(lfp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `			up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `			ksmbd_inode_put(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `			return lfp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `	ksmbd_inode_put(ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] ` * ksmbd_lookup_fd_inode_sess() - Find an open file by inode number`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] ` *                                in the session's file table`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] ` * @work:  smb work containing the session reference`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] ` * @ino:   inode number to search for`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] ` * Iterates the session's file table under the read lock, looking for`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ` * an open file handle whose backing inode number matches @ino.`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] ` * Returns a reference-counted ksmbd_file on success, NULL if not found.`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] ` * The caller must call ksmbd_fd_put() when done with the returned file.`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_inode_sess(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `					      u64 ino)`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	unsigned int entry_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `	if (!work->sess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	read_lock(&work->sess->file_table.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	idr_for_each_entry(work->sess->file_table.idr, fp, entry_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `		struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `		if (!fp->filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		if (fp->f_state != FP_INITED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `		inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `		if (inode->i_ino == ino) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `			fp = ksmbd_fp_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `	read_unlock(&work->sess->file_table.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `#define OPEN_ID_TYPE_VOLATILE_ID	(0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `#define OPEN_ID_TYPE_PERSISTENT_ID	(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `static void __open_id_set(struct ksmbd_file *fp, u64 id, int type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	if (type == OPEN_ID_TYPE_VOLATILE_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `		fp->volatile_id = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `	if (type == OPEN_ID_TYPE_PERSISTENT_ID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `		fp->persistent_id = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `static int __open_id(struct ksmbd_file_table *ft, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `		     int type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	u64			id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	int			ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `	if (type == OPEN_ID_TYPE_VOLATILE_ID && fd_limit_depleted()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		__open_id_set(fp, KSMBD_NO_FID, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [ERROR_PATH|] `		return -EMFILE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00893 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `	idr_preload(KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	write_lock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	ret = idr_alloc_cyclic(ft->idr, fp, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `			       IS_SMB2(fp->conn) ? INT_MAX - 1 : 0xFFFF,`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `			       GFP_NOWAIT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	ret = idr_alloc_cyclic(ft->idr, fp, 0, INT_MAX - 1, GFP_NOWAIT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	if (ret >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		id = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `		id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `		fd_limit_close();`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	__open_id_set(fp, id, type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	idr_preload_end();`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `unsigned int ksmbd_open_durable_fd(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `	__open_id(&global_ft, fp, OPEN_ID_TYPE_PERSISTENT_ID);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `	return fp->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `/* Forward declaration for C.5 durable expiry timer callback */`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `static void ksmbd_durable_expire_cb(struct timer_list *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `struct ksmbd_file *ksmbd_open_fd(struct ksmbd_work *work, struct file *filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] `	fp = kmem_cache_zalloc(filp_cache, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [ERROR_PATH|] `		pr_err("Failed to allocate memory\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00935 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	INIT_LIST_HEAD(&fp->blocked_works);`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	INIT_LIST_HEAD(&fp->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	INIT_LIST_HEAD(&fp->lock_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	spin_lock_init(&fp->f_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `	spin_lock_init(&fp->lock_seq_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	memset(fp->lock_seq, 0xFF, sizeof(fp->lock_seq));`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [LIFETIME|] `	refcount_set(&fp->refcount, 1);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00945 [NONE] `	/* C.5: initialize durable handle expiry timer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	timer_setup(&fp->durable_expire_timer, ksmbd_durable_expire_cb, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	fp->filp		= filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	fp->conn		= work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	fp->tcon		= work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	fp->volatile_id		= KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `	fp->persistent_id	= KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	fp->f_state		= FP_NEW;`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	fp->f_ci		= ksmbd_inode_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `	if (!fp->f_ci) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00959 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	ret = __open_id(&work->sess->file_table, fp, OPEN_ID_TYPE_VOLATILE_ID);`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `		ksmbd_inode_put(fp->f_ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00965 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [LIFETIME|] `	atomic_inc(&work->conn->stats.open_files_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00968 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	kmem_cache_free(filp_cache, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	return ERR_PTR(ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `void ksmbd_update_fstate(struct ksmbd_file_table *ft, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `			 unsigned int state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	if (!fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	write_lock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	fp->f_state = state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `static int`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `__close_file_table_ids(struct ksmbd_file_table *ft,`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `		       struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `		       bool (*skip)(struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `				    struct ksmbd_file *fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	unsigned int id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	int num = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [WAIT_LOOP|] `	while (1) {`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00997 [NONE] `		write_lock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `		fp = idr_get_next(ft->idr, &id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `		if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `			write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `		if (skip(tcon, fp) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [LIFETIME|] `		    !refcount_dec_and_test(&fp->refcount)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01006 [NONE] `			id++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `			write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `		set_close_state_blocked_works(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `		idr_remove(ft->idr, fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `		fp->volatile_id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `		write_unlock(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		 * Notify cleanup sends TCP responses (sleepable),`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		 * so must be called outside write_lock(&ft->lock).`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		ksmbd_notify_cleanup_file(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [LOCK|] `		down_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01023 [NONE] `		list_del_init(&fp->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [LOCK|] `		up_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		__ksmbd_close_fd(ft, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		num++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `		id++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `	return num;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `static inline bool is_reconnectable(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `	struct oplock_info *opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	bool reconn = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	if (!opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `	if (opinfo->op_state != OPLOCK_STATE_NONE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `		opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `	if (fp->is_resilient || fp->is_persistent)`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `		reconn = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `	else if (fp->is_durable && opinfo->is_lease &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [PROTO_GATE|] `		 opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01052 [NONE] `		reconn = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [PROTO_GATE|] `	else if (fp->is_durable && opinfo->level == SMB2_OPLOCK_LEVEL_BATCH)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01055 [NONE] `		reconn = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `	opinfo_put(opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	return reconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `static bool tree_conn_fd_check(struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `			       struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	return fp->tcon != tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `static bool ksmbd_durable_scavenger_alive(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `	if (!durable_scavenger_running)`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	if (kthread_should_stop())`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	if (idr_is_empty(global_ft.idr))`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `static int ksmbd_durable_scavenger(void *dummy)`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	unsigned int id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	unsigned int min_timeout = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	bool found_fp_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	unsigned long remaining_jiffies;`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	__module_get(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `	set_freezable();`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	while (ksmbd_durable_scavenger_alive()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `		if (try_to_freeze())`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `		found_fp_timeout = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `rescan:`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [WAIT_LOOP|] `		remaining_jiffies = wait_event_timeout(dh_wq,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01100 [NONE] `				   ksmbd_durable_scavenger_alive() == false,`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `				   __msecs_to_jiffies(min_timeout));`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `		if (remaining_jiffies)`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `			min_timeout = jiffies_to_msecs(remaining_jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `			min_timeout = DURABLE_HANDLE_MAX_TIMEOUT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `		write_lock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `		idr_for_each_entry(global_ft.idr, fp, id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `			if (!fp->durable_timeout &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `			    !(fp->is_resilient && fp->resilient_timeout))`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `			if (fp->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `			found_fp_timeout = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `			if (fp->durable_scavenger_timeout <=`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `			    jiffies_to_msecs(jiffies)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `				 * Take a reference before claiming. If`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `				 * someone else already holds a reference`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `				 * (e.g. a reconnecting client), skip.`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [LIFETIME|] `				if (!refcount_inc_not_zero(&fp->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01125 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [LIFETIME|] `				if (refcount_read(&fp->refcount) != 2) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01128 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `					 * Another thread acquired a ref`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `					 * between our check and inc.`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `					 * Drop our ref and skip.`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [LIFETIME|] `					refcount_dec(&fp->refcount);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01134 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `				fp->is_scavenger_claimed = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `				__ksmbd_remove_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `				write_unlock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `				 * fp->node is still linked in the`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `				 * inode's m_fp_list.  Properly remove`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `				 * it under m_lock before disposing`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `				 * (m_lock is a semaphore, so must be`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `				 * taken outside the spinlock).`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `				if (fp->f_ci) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [LOCK|] `					down_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01150 [NONE] `					list_del_init(&fp->node);`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [LOCK|] `					up_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01152 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [LIFETIME|] `				if (!refcount_dec_and_test(&fp->refcount))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01155 [NONE] `					fp->is_scavenger_claimed = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `				else`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `					__ksmbd_close_fd(NULL, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `				 * Restart the IDR scan — the lock was`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `				 * dropped so entries may have changed.`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [ERROR_PATH|] `				goto rescan;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01164 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `				unsigned long durable_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `				durable_timeout =`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `					fp->durable_scavenger_timeout -`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `						jiffies_to_msecs(jiffies);`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `				if (min_timeout > durable_timeout)`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `					min_timeout = durable_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `		write_unlock(&global_ft.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `		if (found_fp_timeout == false)`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	durable_scavenger_running = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `	module_put(THIS_MODULE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `void ksmbd_launch_ksmbd_durable_scavenger(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [LOCK|] `	mutex_lock(&durable_scavenger_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01194 [NONE] `	if (durable_scavenger_running == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [LOCK|] `		mutex_unlock(&durable_scavenger_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01196 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `	durable_scavenger_running = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	server_conf.dh_task = kthread_run(ksmbd_durable_scavenger,`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `				     (void *)NULL, "ksmbd-durable-scavenger");`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `	if (IS_ERR(server_conf.dh_task))`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [ERROR_PATH|] `		pr_err("cannot start conn thread, err : %ld\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01205 [NONE] `		       PTR_ERR(server_conf.dh_task));`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [LOCK|] `	mutex_unlock(&durable_scavenger_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01207 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `void ksmbd_stop_durable_scavenger(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE))`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [LOCK|] `	mutex_lock(&durable_scavenger_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01215 [NONE] `	if (!durable_scavenger_running) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [LOCK|] `		mutex_unlock(&durable_scavenger_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01217 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `	durable_scavenger_running = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	if (waitqueue_active(&dh_wq))`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `		wake_up(&dh_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [LOCK|] `	mutex_unlock(&durable_scavenger_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01224 [NONE] `	kthread_stop(server_conf.dh_task);`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] ` * C.5: Timer callback for durable handle expiry.`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] ` * Fired when a disconnected durable handle's reconnect window expires.`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] ` * Simply wakes the durable scavenger thread, which will find the handle`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] ` * with an expired durable_scavenger_timeout and close it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] ` * This avoids complex locking in timer context — the scavenger already`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] ` * handles all the heavy lifting safely.`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `static void ksmbd_durable_expire_cb(struct timer_list *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `	/* Wake scavenger so it reclaims the expired handle */`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	if (waitqueue_active(&dh_wq))`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `		wake_up(&dh_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `static bool session_fd_check(struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `			     struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	struct oplock_info *op;`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	if (!is_reconnectable(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `	conn = fp->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01255 [NONE] `	list_for_each_entry_rcu(op, &ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `		if (op->conn != conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `		if (op->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `			ksmbd_conn_free(op->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `		op->conn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	fp->conn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	fp->tcon = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `	fp->volatile_id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `	if (fp->durable_timeout) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `		fp->durable_scavenger_timeout =`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `			jiffies_to_msecs(jiffies) + fp->durable_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `		 * C.5: arm the per-handle expiry timer so the scavenger`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `		 * is woken precisely when this handle's reconnect window`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `		 * closes.  MS-SMB2 §3.3.5.9.7: server SHOULD apply a`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `		 * reconnect timeout to durable handles.`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `		mod_timer(&fp->durable_expire_timer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `			  jiffies + msecs_to_jiffies(fp->durable_timeout));`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	} else if (fp->is_resilient && fp->resilient_timeout) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `		fp->durable_scavenger_timeout =`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `			jiffies_to_msecs(jiffies) + fp->resilient_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `		mod_timer(&fp->durable_expire_timer,`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `			  jiffies + msecs_to_jiffies(fp->resilient_timeout));`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `void ksmbd_close_tree_conn_fds(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `	int num = __close_file_table_ids(&work->sess->file_table,`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `					 work->tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `					 tree_conn_fd_check);`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [LIFETIME|] `	atomic_sub(num, &work->conn->stats.open_files_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01296 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `void ksmbd_close_session_fds(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	int num = __close_file_table_ids(&work->sess->file_table,`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `					 work->tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `					 session_fd_check);`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [LIFETIME|] `	atomic_sub(num, &work->conn->stats.open_files_count);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01305 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `int ksmbd_init_global_file_table(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `	return ksmbd_init_file_table(&global_ft);`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `void ksmbd_free_global_file_table(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	struct ksmbd_file	*fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `	unsigned int		id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	if (!global_ft.idr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	idr_for_each_entry(global_ft.idr, fp, id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `		__ksmbd_remove_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `		fp->persistent_id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `		__ksmbd_close_fd(NULL, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `	idr_destroy(global_ft.idr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	kfree(global_ft.idr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	global_ft.idr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `int ksmbd_file_table_flush(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	struct ksmbd_file	*fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	unsigned int		id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `	int			ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `	read_lock(&work->sess->file_table.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `	idr_for_each_entry(work->sess->file_table.idr, fp, id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `		ret = ksmbd_vfs_fsync(work, fp->volatile_id, KSMBD_NO_FID, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	read_unlock(&work->sess->file_table.lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `int ksmbd_validate_name_reconnect(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `				  struct ksmbd_file *fp, char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `	char *pathname, *ab_pathname;`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [MEM_BOUNDS|] `	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01354 [NONE] `	if (!pathname)`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	ab_pathname = d_path(&fp->filp->f_path, pathname, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `	if (IS_ERR(ab_pathname)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `		kfree(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01361 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `	if (name && strcmp(&ab_pathname[share->path_sz + 1], name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `		ksmbd_debug(SMB, "invalid name reconnect %s\n", name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `	kfree(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `int ksmbd_reopen_durable_fd(struct ksmbd_work *work, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `	struct ksmbd_inode *ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	struct oplock_info *op;`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	if (!fp->is_durable || fp->conn || fp->tcon) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [ERROR_PATH|] `		pr_err("Invalid durable fd [%p:%p]\n", fp->conn, fp->tcon);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01380 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01381 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `	if (has_file_id(fp->volatile_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [ERROR_PATH|] `		pr_err("Still in use durable fd: %llu\n", fp->volatile_id);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01385 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01386 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `	 * Clear scavenger timeout so the scavenger thread will not`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `	 * attempt to expire this handle while it is being reclaimed.`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	fp->durable_scavenger_timeout = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `	fp->conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	fp->tcon = work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `	ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [LOCK|] `	down_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01399 [NONE] `	list_for_each_entry_rcu(op, &ci->m_op_list, op_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `		if (op->conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `		op->conn = fp->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [LIFETIME|] `		refcount_inc(&op->conn->refcnt);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01404 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [LOCK|] `	up_write(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `	fp->f_state = FP_NEW;`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `	__open_id(&work->sess->file_table, fp, OPEN_ID_TYPE_VOLATILE_ID);`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	if (!has_file_id(fp->volatile_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `		fp->conn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `		fp->tcon = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01413 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `int ksmbd_init_file_table(struct ksmbd_file_table *ft)`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [MEM_BOUNDS|] `	ft->idr = kzalloc(sizeof(struct idr), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01420 [NONE] `	if (!ft->idr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `	idr_init(ft->idr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `	rwlock_init(&ft->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `void ksmbd_destroy_file_table(struct ksmbd_file_table *ft)`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `	if (!ft->idr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `	__close_file_table_ids(ft, NULL, session_fd_check);`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `	idr_destroy(ft->idr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `	kfree(ft->idr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `	ft->idr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `int ksmbd_init_file_cache(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `	filp_cache = kmem_cache_create("ksmbd_file_cache",`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `				       sizeof(struct ksmbd_file), 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `				       SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `				       NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `	if (!filp_cache)`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `	init_waitqueue_head(&dh_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [ERROR_PATH|] `	pr_err("failed to allocate file cache\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01454 [ERROR_PATH|] `	return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01455 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `void ksmbd_exit_file_cache(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	kmem_cache_destroy(filp_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `	filp_cache = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
