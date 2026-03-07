# Line-by-line Review: src/fs/vfs.c

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
- L00007 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/uaccess.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/backing-dev.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/writeback.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/xattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/fsnotify.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/dcache.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/vmalloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include <linux/blkdev.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <linux/crc32c.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <linux/sched/xacct.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include <linux/mount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include <linux/splice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `extern int vfs_path_lookup(struct dentry *, struct vfsmount *,`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `			   const char *, unsigned int, struct path *);`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * ksmbd_vfs_path_is_within_share() - Verify file is within share root`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * @file:	opened file`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * @share_root:	share root path`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * Post-open defense-in-depth check to confirm the opened file has not`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * escaped the share boundary via a symlink race (TOCTOU).`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * Return: true if file is within share root, false otherwise`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `static bool`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `ksmbd_vfs_path_is_within_share(struct file *file,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `			       const struct path *share_root)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	return path_is_under(&file->f_path, share_root);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `static char *extract_last_component(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	char *p = strrchr(path, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	if (p && p[1] != '\0') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		*p = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		p = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	return p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `static void ksmbd_vfs_inherit_owner(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `				    struct inode *parent_inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `				    struct inode *inode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	if (!test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `				    KSMBD_SHARE_FLAG_INHERIT_OWNER))`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	i_uid_write(inode, i_uid_read(parent_inode));`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * ksmbd_vfs_lock_parent() - lock parent dentry if it is stable`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * @parent: parent dentry`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * @child: child dentry`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * Returns: %0 on success, %-ENOENT if the parent dentry is not stable`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `int ksmbd_vfs_lock_parent(struct dentry *parent, struct dentry *child)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	inode_lock_nested(d_inode(parent), I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	if (child->d_parent != parent) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		inode_unlock(d_inode(parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00119 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `VISIBLE_IF_KUNIT int ksmbd_vfs_path_lookup(struct ksmbd_share_config *share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `				 char *pathname, unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `				 struct path *path, bool do_lock)`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	struct qstr last;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	struct filename *filename __free(putname) = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	struct filename *filename = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	const struct path *root_share_path = &share_conf->vfs_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	int err, type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	struct dentry *d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	if (pathname[0] == '\0') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		pathname = share_conf->path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		root_share_path = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		flags |= LOOKUP_BENEATH;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	filename = getname_kernel(pathname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	if (IS_ERR(filename))`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `		return PTR_ERR(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	err = vfs_path_parent_lookup(filename, flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `				     path, &last, &type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `				     root_share_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	if (unlikely(type != LAST_NORM)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00165 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	if (do_lock) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `		err = mnt_want_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `			path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `			putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00175 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `		inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		d = lookup_one_qstr_excl(&last, path->dentry, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		if (!IS_ERR(d)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `			if (d_is_negative(d)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `				dput(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `				inode_unlock(path->dentry->d_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `				mnt_drop_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `				path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `				putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [ERROR_PATH|] `				return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00189 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `			dput(path->dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `			path->dentry = d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `			putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `		inode_unlock(path->dentry->d_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `		mnt_drop_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	d = lookup_noperm_unlocked(&last, path->dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	inode_lock_nested(path->dentry->d_inode, I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	d = lookup_one_qstr_excl(&last, path->dentry, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	inode_unlock(path->dentry->d_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	if (!IS_ERR(d) && d_is_negative(d)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		dput(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		d = ERR_PTR(-ENOENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	if (IS_ERR(d)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00224 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	dput(path->dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	path->dentry = d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	if (test_share_config_flag(share_conf, KSMBD_SHARE_FLAG_CROSSMNT)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		err = follow_down(path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		if (err < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `			path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `			putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00236 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	putname(filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_vfs_path_lookup);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ` * ksmbd_vfs_lock_parent() - lock parent dentry if it is stable`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ` * the parent dentry got by dget_parent or @parent could be`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ` * unstable, we try to lock a parent inode and lookup the`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` * child dentry again.`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ` * the reference count of @parent isn't incremented.`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `int ksmbd_vfs_lock_parent(struct mnt_idmap *idmap, struct dentry *parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `int ksmbd_vfs_lock_parent(struct user_namespace *user_ns, struct dentry *parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `			  struct dentry *child)`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	inode_lock_nested(d_inode(parent), I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	dentry = lookup_one(idmap, &child->d_name, parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	dentry = lookup_one(idmap, child->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `			    child->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	dentry = lookup_one(user_ns, child->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `			    child->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	dentry = lookup_one_len(child->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `				child->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	if (IS_ERR(dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `		ret = PTR_ERR(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00280 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	if (dentry != child) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		ret = -ESTALE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00286 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	inode_unlock(d_inode(parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `int ksmbd_vfs_may_delete(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `int ksmbd_vfs_may_delete(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `			 struct dentry *dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	struct dentry *parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	parent = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	ret = ksmbd_vfs_lock_parent(idmap, parent, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	ret = ksmbd_vfs_lock_parent(user_ns, parent, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `		dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	ret = inode_permission(idmap, d_inode(parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `	ret = inode_permission(user_ns, d_inode(parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `			       MAY_EXEC | MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	ret = inode_permission(d_inode(parent), MAY_EXEC | MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	inode_unlock(d_inode(parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `void ksmbd_vfs_query_maximal_access(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `				   struct dentry *dentry, __le32 *daccess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `	*daccess = cpu_to_le32(FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	if (!inode_permission(idmap, d_inode(dentry), MAY_OPEN | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `		*daccess |= cpu_to_le32(WRITE_DAC | WRITE_OWNER |`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `				FILE_WRITE_DATA | FILE_APPEND_DATA |`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `				FILE_DELETE_CHILD);`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	if (!inode_permission(idmap, d_inode(dentry), MAY_OPEN | MAY_READ)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		*daccess |= FILE_READ_DATA_LE | FILE_READ_EA_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `		 * In SMB semantics, FILE_EXECUTE means the right to read`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		 * data for execution - it is always granted when`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		 * FILE_READ_DATA is granted, regardless of Unix execute`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		 * permission.`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		*daccess |= FILE_EXECUTE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	if (!inode_permission(idmap, d_inode(dentry->d_parent), MAY_EXEC | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		*daccess |= FILE_DELETE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `int ksmbd_vfs_query_maximal_access(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `int ksmbd_vfs_query_maximal_access(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `				   struct dentry *dentry, __le32 *daccess)`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	struct dentry *parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	*daccess = cpu_to_le32(FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `	if (!inode_permission(idmap, d_inode(dentry), MAY_OPEN | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	if (!inode_permission(user_ns, d_inode(dentry), MAY_OPEN | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	if (!inode_permission(d_inode(dentry), MAY_OPEN | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		*daccess |= cpu_to_le32(WRITE_DAC | WRITE_OWNER |`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `				FILE_WRITE_DATA | FILE_APPEND_DATA |`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `				FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `				FILE_DELETE_CHILD);`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	if (!inode_permission(idmap, d_inode(dentry), MAY_OPEN | MAY_READ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	if (!inode_permission(user_ns, d_inode(dentry), MAY_OPEN | MAY_READ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	if (!inode_permission(d_inode(dentry), MAY_OPEN | MAY_READ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		*daccess |= FILE_READ_DATA_LE | FILE_READ_EA_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `		/* SMB FILE_EXECUTE = right to read for execution */`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `		*daccess |= FILE_EXECUTE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	parent = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	ret = ksmbd_vfs_lock_parent(idmap, parent, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `	ret = ksmbd_vfs_lock_parent(user_ns, parent, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	if (!inode_permission(idmap, d_inode(parent), MAY_EXEC | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	if (!inode_permission(user_ns, d_inode(parent), MAY_EXEC | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	if (!inode_permission(d_inode(parent), MAY_EXEC | MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		*daccess |= FILE_DELETE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `	inode_unlock(d_inode(parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ` * ksmbd_vfs_create() - vfs helper for smb create file`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ` * @name:	file name that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ` * @mode:	file create mode`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `int ksmbd_vfs_create(struct ksmbd_work *work, const char *name, umode_t mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	dentry = ksmbd_vfs_kern_path_create(work, name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `					    LOOKUP_NO_SYMLINKS, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `	if (IS_ERR(dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `		err = PTR_ERR(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `		if (err != -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [ERROR_PATH|] `			pr_err("path create failed for %s, err %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00451 [NONE] `			       name, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `	mode |= S_IFREG;`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	err = vfs_create(mnt_idmap(path.mnt), dentry, mode, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `	err = vfs_create(mnt_idmap(path.mnt), d_inode(path.dentry),`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `			 dentry, mode, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	err = vfs_create(mnt_user_ns(path.mnt), d_inode(path.dentry),`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `			 dentry, mode, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	err = vfs_create(d_inode(path.dentry), dentry, mode, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	if (!err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry),`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `					d_inode(dentry));`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [ERROR_PATH|] `		pr_err("File(%s): creation failed (err:%d)\n", name, err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00476 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	end_creating_path(&path, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	done_path_create(&path, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ` * ksmbd_vfs_mkdir() - vfs helper for smb create directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ` * @name:	directory name that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] ` * @mode:	directory create mode`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `int ksmbd_vfs_mkdir(struct ksmbd_work *work, const char *name, umode_t mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `	struct dentry *dentry, *d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	dentry = ksmbd_vfs_kern_path_create(work, name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `					    LOOKUP_NO_SYMLINKS | LOOKUP_DIRECTORY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `					    &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	if (IS_ERR(dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `		err = PTR_ERR(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `		if (err != -EEXIST)`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `			ksmbd_debug(VFS, "path create failed for %s, err %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `				    name, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `	idmap = mnt_idmap(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `	user_ns = mnt_user_ns(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `	mode |= S_IFDIR;`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	d = dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	dentry = vfs_mkdir(idmap, d_inode(path.dentry), dentry, mode, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	dentry = vfs_mkdir(idmap, d_inode(path.dentry), dentry, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	if (IS_ERR(dentry))`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `		err = PTR_ERR(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	else if (d_is_negative(dentry))`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	if (!err && dentry != d)`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry), d_inode(dentry));`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	err = vfs_mkdir(idmap, d_inode(path.dentry), dentry, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	err = vfs_mkdir(user_ns, d_inode(path.dentry), dentry, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	err = vfs_mkdir(d_inode(path.dentry), dentry, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	if (!err && d_unhashed(dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		struct dentry *d;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `		d = lookup_one(idmap, &dentry->d_name, dentry->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `		d = lookup_one(idmap, dentry->d_name.name, dentry->d_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `			       dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		d = lookup_one(user_ns, dentry->d_name.name, dentry->d_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `			       dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `		d = lookup_one_len(dentry->d_name.name, dentry->d_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `				   dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `		if (IS_ERR(d)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `			err = PTR_ERR(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00568 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		if (unlikely(d_is_negative(d))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `			dput(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `			err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [ERROR_PATH|] `			goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00573 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		ksmbd_vfs_inherit_owner(work, d_inode(path.dentry), d_inode(d));`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		dput(d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `	end_creating_path(&path, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	done_path_create(&path, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [ERROR_PATH|] `		pr_err("mkdir(%s): creation failed (err:%d)\n", name, err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00588 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `static ssize_t ksmbd_vfs_getcasexattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `static ssize_t ksmbd_vfs_getcasexattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `				      struct dentry *dentry, char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `				      int attr_name_len, char **attr_value)`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	char *name, *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	ssize_t value_len = -ENOENT, xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	if (xattr_list_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	for (name = xattr_list; name - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `			name += strlen(name) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		if (strncasecmp(attr_name, name, attr_name_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		value_len = ksmbd_vfs_getxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		value_len = ksmbd_vfs_getxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `					       dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `					       name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `					       attr_value);`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		if (value_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [ERROR_PATH|] `			pr_err("failed to get xattr in file\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00622 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	return value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `static int ksmbd_vfs_stream_read(struct ksmbd_file *fp, char *buf, loff_t *pos,`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `				 size_t count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	ssize_t v_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `	char *stream_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `	ksmbd_debug(VFS, "read stream data pos : %llu, count : %zd\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		    *pos, count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `	v_len = ksmbd_vfs_getcasexattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `	v_len = ksmbd_vfs_getcasexattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `				       fp->stream.name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `				       fp->stream.size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `				       &stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	if ((int)v_len <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `		 * AFP_AfpInfo synthesis: when the DosStream xattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		 * doesn't exist, try to build a 60-byte AfpInfo`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `		 * from the native com.apple.FinderInfo xattr.`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		 * This handles files migrated from netatalk/AFP.`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `		if (fp->stream.name &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		    strstr(fp->stream.name, AFP_AFPINFO_STREAM)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [MEM_BOUNDS|] `			stream_buf = kvzalloc(AFP_AFPINFO_SIZE,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00659 [NONE] `					      KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `			if (!stream_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [ERROR_PATH|] `				return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `			v_len = fruit_synthesize_afpinfo(`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `					file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `					fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `					stream_buf, AFP_AFPINFO_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `			if ((int)v_len <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `				kvfree(stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `				return (int)v_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [ERROR_PATH|] `			goto have_data;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00672 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `#endif /* CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `		return (int)v_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `have_data:`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	if (v_len <= *pos) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `		count = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [ERROR_PATH|] `		goto free_buf;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00683 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `	if (v_len - *pos < count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `		count = v_len - *pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	fp->stream.pos = v_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [MEM_BOUNDS|] `	memcpy(buf, &stream_buf[*pos], count);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `free_buf:`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	kvfree(stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	return count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ` * check_lock_range() - vfs helper for smb byte range file locking`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ` * @filp:	the file to apply the lock to`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ` * @start:	lock start byte offset`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] ` * @end:	lock end byte offset`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] ` * @type:	byte range type read/write`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `static int check_lock_range(struct file *filp, loff_t start, loff_t end,`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `			    unsigned char type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `	struct file_lock *flock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	struct file_lock_context *ctx = locks_inode_context(file_inode(filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	struct file_lock_context *ctx = file_inode(filp)->i_flctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	int error = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	if (start == end)`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `	if (!ctx || list_empty_careful(&ctx->flc_posix))`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [LOCK|] `	spin_lock(&ctx->flc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00723 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	for_each_file_lock(flock, &ctx->flc_posix) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `	list_for_each_entry(flock, &ctx->flc_posix, fl_list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `		/* check conflict locks */`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `		if (flock->fl_end >= start && end >= flock->fl_start) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `			if (lock_is_read(flock)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `			if (flock->fl_type == F_RDLCK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `				if (type == WRITE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [ERROR_PATH|] `					pr_err("not allow write by shared lock\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00737 [NONE] `					error = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00739 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `			} else if (lock_is_write(flock)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `			} else if (flock->fl_type == F_WRLCK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `				/* check owner in lock */`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `				if (flock->c.flc_file != filp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `				if (flock->fl_file != filp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `					error = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [ERROR_PATH|] `					pr_err("not allow rw access by exclusive lock from other opens\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00753 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00754 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [LOCK|] `	spin_unlock(&ctx->flc_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00760 [NONE] `	return error;`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] ` * ksmbd_vfs_read() - vfs helper for smb file read`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] ` * @work:	smb work`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ` * @count:	read byte count`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] ` * @pos:	file pos`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] ` * @rbuf:	read data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ` * Return:	number of read bytes on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `int ksmbd_vfs_read(struct ksmbd_work *work, struct ksmbd_file *fp, size_t count,`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `		   loff_t *pos, char *rbuf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	struct file *filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	ssize_t nbytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `	struct inode *inode = file_inode(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	if (S_ISDIR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [ERROR_PATH|] `		return -EISDIR;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	if (unlikely(count == 0))`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	if (work->conn->connection_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `		if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [ERROR_PATH|] `			pr_err("no right to read(%pD)\n", fp->filp);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00789 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00790 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		return ksmbd_vfs_stream_read(fp, rbuf, pos, count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	if (!work->tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		ret = check_lock_range(filp, *pos, *pos + count - 1, READ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [ERROR_PATH|] `			pr_err("unable to read due to lock\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00802 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00803 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	nbytes = kernel_read(filp, rbuf, count, pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	if (nbytes < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [ERROR_PATH|] `		pr_err("smb read failed, err = %zd\n", nbytes);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00809 [NONE] `		return nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `	filp->f_pos = *pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `	return nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] ` * ksmbd_vfs_sendfile() - validate and prepare zero-copy file read`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] ` * @work:	smb work context (contains connection/socket)`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ` * @offset:	file offset to start reading from`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] ` * @count:	number of bytes requested`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] ` * Validates that the file can be read at the given offset and`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ` * computes the actual number of bytes available for a zero-copy`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ` * transfer. The actual data transfer is performed later by the`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] ` * transport layer's sendfile operation in ksmbd_conn_write().`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] ` * Return:	number of bytes available to send, or negative errno`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `ssize_t ksmbd_vfs_sendfile(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `			   loff_t offset, size_t count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	struct file *filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	struct inode *inode = file_inode(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `	loff_t file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	ssize_t avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	if (S_ISDIR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [ERROR_PATH|] `		return -EISDIR;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00841 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	if (unlikely(count == 0))`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	if (conn->connection_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `		if (!(fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [ERROR_PATH|] `			pr_err("no right to read(%pD)\n", fp->filp);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00848 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00849 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	/* Zero-copy is not supported for stream files */`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	if (ksmbd_stream_fd(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	if (!work->tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		ret = check_lock_range(filp, offset, offset + count - 1, READ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [ERROR_PATH|] `			pr_err("unable to read due to lock\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00862 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00863 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	/* Compute available bytes from file size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `	file_size = i_size_read(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `	if (offset >= file_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	avail = min_t(loff_t, count, file_size - offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	filp->f_pos = offset + avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	return avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `static int ksmbd_vfs_stream_write(struct ksmbd_file *fp, char *buf, loff_t *pos,`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `				  size_t count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `	char *stream_buf = NULL, *wbuf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	size_t size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	ssize_t v_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	ksmbd_debug(VFS, "write stream data pos : %llu, count : %zd\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `		    *pos, count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	if (XATTR_SIZE_MAX <= *pos) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [ERROR_PATH|] `		pr_err("stream write position %lld is out of bounds\n",	*pos);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00894 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00895 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	size = *pos + count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `	if (size > XATTR_SIZE_MAX) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		size = XATTR_SIZE_MAX;`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `		count = XATTR_SIZE_MAX - *pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] `	v_len = ksmbd_vfs_getcasexattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `	v_len = ksmbd_vfs_getcasexattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `				       fp->stream.name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `				       fp->stream.size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `				       &stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	if (v_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [ERROR_PATH|] `		pr_err("not found stream in xattr : %zd\n", v_len);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00914 [NONE] `		err = v_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00916 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `	if (v_len < size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [MEM_BOUNDS|] `		wbuf = kvzalloc(size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00920 [NONE] `		if (!wbuf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `			err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00923 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `		if (v_len > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [MEM_BOUNDS|] `			memcpy(wbuf, stream_buf, v_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00927 [NONE] `		kvfree(stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `		stream_buf = wbuf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [MEM_BOUNDS|] `	memcpy(&stream_buf[*pos], buf, count);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00932 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `	err = ksmbd_vfs_setxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	err = ksmbd_vfs_setxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `				 &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `				 fp->stream.name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `				 (void *)stream_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `				 size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `				 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `				 true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00946 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	if (fp->stream.name &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	    strstr(fp->stream.name, "AFP_AfpInfo") &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	    size >= 48) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `		int wb_err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `		/* Write-back FinderInfo (bytes 16-47) to native xattr */`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `		wb_err = ksmbd_vfs_setxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `		wb_err = ksmbd_vfs_setxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `					    &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `					    APPLE_FINDER_INFO_XATTR_USER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `					    (void *)(stream_buf + 16), 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `					    0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `		if (wb_err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `			ksmbd_debug(VFS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `				    "Failed to write-back FinderInfo: %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `				    wb_err);`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	fp->stream.pos = size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	kvfree(stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] ` * ksmbd_vfs_write() - vfs helper for smb file write`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] ` * @buf:	buf containing data for writing`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] ` * @count:	read byte count`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] ` * @pos:	file pos`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] ` * @sync:	fsync after write`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] ` * @written:	number of bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `int ksmbd_vfs_write(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `		    char *buf, size_t count, loff_t *pos, bool sync,`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `		    ssize_t *written)`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	loff_t	offset = *pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `	if (work->conn->connection_type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `		if (!(fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `		    (S_ISDIR(file_inode(fp->filp)->i_mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `		     !ksmbd_stream_fd(fp))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [ERROR_PATH|] `			pr_err("no right to write(%pD)\n", fp->filp);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01001 [NONE] `			err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01003 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `	if (ksmbd_stream_fd(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `		err = ksmbd_vfs_stream_write(fp, buf, pos, count);`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `		if (!err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `			*written = count;`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01013 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `	if (!work->tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `		err = check_lock_range(filp, *pos, *pos + count - 1, WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [ERROR_PATH|] `			pr_err("unable to write due to lock\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01019 [NONE] `			err = -EAGAIN;`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01021 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `	/* Reserve lease break for parent dir at closing time */`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	fp->reserve_lease_break = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	/* Do we need to break any of a levelII oplock? */`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `	smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `	err = kernel_write(filp, buf, count, pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `	if (err < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `		ksmbd_debug(VFS, "smb write failed, err = %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01034 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `	filp->f_pos = *pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `	*written = err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	/* Invalidate cached AllocationSize; data blocks may have changed */`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	if (fp->f_ci)`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `		fp->f_ci->m_cached_alloc = -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `	if (sync) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `		err = vfs_fsync_range(filp, offset, offset + *written, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `		if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [ERROR_PATH|] `			pr_err("fsync failed for filename = %pD, err = %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01048 [NONE] `			       fp->filp, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] ` * ksmbd_vfs_getattr() - vfs helper for smb getattr`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] ` * @path:	path of dentry`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] ` * @stat:	pointer to returned kernel stat structure`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `int ksmbd_vfs_getattr(const struct path *path, struct kstat *stat)`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `	err = vfs_getattr(path, stat, STATX_BASIC_STATS | STATX_BTIME,`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `			AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [ERROR_PATH|] `		pr_err("getattr failed, err %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01069 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] ` * smb_check_attrs() - sanitize inode attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] ` * @inode:	inode`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] ` * @attrs:	inode attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `static void smb_check_attrs(struct inode *inode, struct iattr *attrs)`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `	/* sanitize the mode change */`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `	if (attrs->ia_valid & ATTR_MODE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `		attrs->ia_mode &= S_IALLUGO;`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `		attrs->ia_mode |= (inode->i_mode & ~S_IALLUGO);`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	/* Revoke setuid/setgid on chown */`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	if (!S_ISDIR(inode->i_mode) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	    (((attrs->ia_valid & ATTR_UID) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	      !uid_eq(attrs->ia_uid, inode->i_uid)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	     ((attrs->ia_valid & ATTR_GID) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `	      !gid_eq(attrs->ia_gid, inode->i_gid)))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `		attrs->ia_valid |= ATTR_KILL_PRIV;`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `		if (attrs->ia_valid & ATTR_MODE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `			/* we're setting mode too, just clear the s*id bits */`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `			attrs->ia_mode &= ~S_ISUID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `			if (attrs->ia_mode & 0010)`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `				attrs->ia_mode &= ~S_ISGID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `			/* set ATTR_KILL_* bits and let VFS handle it */`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `			attrs->ia_valid |= (ATTR_KILL_SUID | ATTR_KILL_SGID);`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ` * ksmbd_vfs_setattr() - vfs helper for smb setattr`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] ` * @name:	file name`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] ` * @fid:	file id of open file`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] ` * @attrs:	inode attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `int ksmbd_vfs_setattr(struct ksmbd_work *work, const char *name, u64 fid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `		      struct iattr *attrs)`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	bool update_size = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `	if (name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `		unsigned int lookup_flags = LOOKUP_BENEATH;`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `		err = kern_path(name, lookup_flags, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `			ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `			ksmbd_debug(VFS, "lookup failed for %s, err = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `				    name, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01142 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `		dentry = path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `		inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `		idmap = mnt_idmap(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `		user_ns = mnt_user_ns(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `		fp = ksmbd_lookup_fd_fast(work, fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `		if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `			ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [ERROR_PATH|] `			pr_err("failed to get filp for fid %llu\n", fid);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01155 [ERROR_PATH|] `			return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01156 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `		filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `		dentry = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `		inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `		idmap = file_mnt_idmap(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `		user_ns = file_mnt_user_ns(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `	err = inode_permission(idmap, d_inode(dentry), MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	err = inode_permission(user_ns, d_inode(dentry), MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	err = inode_permission(d_inode(dentry), MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `	/* no need to update mode of symlink */`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	if (S_ISLNK(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `		attrs->ia_valid &= ~ATTR_MODE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `	/* skip setattr, if nothing to update */`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	if (!attrs->ia_valid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `		err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01188 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `	smb_check_attrs(inode, attrs);`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	if (attrs->ia_valid & ATTR_SIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `		err = get_write_access(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01195 [NONE] `		update_size = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `	attrs->ia_valid |= ATTR_CTIME;`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	inode_lock(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `	err = notify_change(idmap, dentry, attrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	err = notify_change(user_ns, dentry, attrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	err = notify_change(dentry, attrs, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `	inode_unlock(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `	if (update_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `		put_write_access(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	if (!err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `		sync_inode_metadata(inode, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `		ksmbd_debug(VFS, "fid %llu, setattr done\n", fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	if (name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] ` * ksmbd_vfs_symlink() - vfs helper for creating smb symlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] ` * @name:	source file name`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] ` * @symname:	symlink name`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `int ksmbd_vfs_symlink(struct ksmbd_work *work, const char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `		      const char *symname)`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	/* Prevent symlink targets that escape the share boundary */`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	if (name[0] == '/' || strstr(name, "..")) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [ERROR_PATH|] `		pr_err("Symlink target '%s' escapes share boundary\n", name);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01245 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01246 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `	dentry = start_creating_path(AT_FDCWD, symname, &path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	dentry = kern_path_create(AT_FDCWD, symname, &path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	if (IS_ERR(dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `		ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `		err = PTR_ERR(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [ERROR_PATH|] `		pr_err("path create failed for %s, err %d\n", name, err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01260 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	err = vfs_symlink(mnt_idmap(path.mnt), d_inode(dentry->d_parent), dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `	err = vfs_symlink(mnt_user_ns(path.mnt), d_inode(dentry->d_parent), dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `	err = vfs_symlink(d_inode(dentry->d_parent), dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	if (err && (err != -EEXIST || err != -ENOSPC))`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `		ksmbd_debug(VFS, "failed to create symlink, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	end_creating_path(&path, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `	done_path_create(&path, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ` * ksmbd_vfs_readlink() - vfs helper for reading value of symlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] ` * @path:	path of symlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] ` * @buf:	destination buffer for symlink value`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] ` * @lenp:	destination buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] ` * Return:	symlink value length on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `int ksmbd_vfs_readlink(struct path *path, char *buf, int lenp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	int err, len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `	const char *link;`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `	DEFINE_DELAYED_CALL(done);`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `	mm_segment_t old_fs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	if (!path)`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `	inode = d_inode(path->dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	if (!S_ISLNK(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	link = vfs_get_link(path->dentry, &done);`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	if (IS_ERR(link)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `		err = PTR_ERR(link);`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [ERROR_PATH|] `		pr_err("readlink failed, err = %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01315 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	len = strlen(link);`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `	if (len > lenp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `		len = lenp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [MEM_BOUNDS|] `	memcpy(buf, link, len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01323 [NONE] `	do_delayed_call(&done);`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	old_fs = get_fs();`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	set_fs(KERNEL_DS);`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `	err = vfs_readlink(path->dentry, (char __user *)buf, lenp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `	set_fs(old_fs);`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `	if (err < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [ERROR_PATH|] `		pr_err("readlink failed, err = %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01333 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `	len = lenp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `int ksmbd_vfs_readdir_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `			   struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `			   struct ksmbd_kstat *ksmbd_kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `			   const char *de_name, int de_name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `			   const char *dir_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `int ksmbd_vfs_readdir_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `			   struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `			   struct ksmbd_kstat *ksmbd_kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `			   const char *de_name, int de_name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `			   const char *dir_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `	int rc, file_pathlen, dir_pathlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	char *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] `	dir_pathlen = strlen(dir_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `	/* 1 for '/'*/`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	file_pathlen = dir_pathlen +  de_name_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [MEM_BOUNDS|] `	name = kmalloc(file_pathlen + 1, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01363 [NONE] `	if (!name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [MEM_BOUNDS|] `	memcpy(name, dir_path, dir_pathlen);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01367 [NONE] `	memset(name + dir_pathlen, '/', 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [MEM_BOUNDS|] `	memcpy(name + dir_pathlen + 1, de_name, de_name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01369 [NONE] `	name[file_pathlen] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `	rc = ksmbd_vfs_kern_path(work, name, LOOKUP_NO_SYMLINKS, &path, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [ERROR_PATH|] `		pr_err("lookup failed: %s [%d]\n", name, rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01374 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01376 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	ksmbd_vfs_fill_dentry_attrs(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `				    idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `				    user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `				    path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `				    ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] ` * ksmbd_vfs_fsync() - vfs helper for smb fsync`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] ` * @fid:	file id of open file`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] ` * @p_id:	persistent file id`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `int ksmbd_vfs_fsync(struct ksmbd_work *work, u64 fid, u64 p_id, bool fullsync)`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `	fp = ksmbd_lookup_fd_slow(work, fid, p_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [ERROR_PATH|] `		pr_err("failed to get filp for fid %llu\n", fid);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01408 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01409 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `	err = vfs_fsync(fp->filp, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `	if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [ERROR_PATH|] `		pr_err("smb fsync failed, err = %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `	 * F_FULLFSYNC: flush the block device write cache.`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `	 * macOS Time Machine sends Reserved1=0xFFFF in SMB2 FLUSH`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `	 * to request this. Without it, data can be lost on power`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `	 * failure even though vfs_fsync() returned success.`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `	if (!err && fullsync) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `		struct block_device *bdev;`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `		bdev = fp->filp->f_path.dentry->d_sb->s_bdev;`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `		if (bdev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `			err = blkdev_issue_flush(bdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [ERROR_PATH|] `				pr_err("smb fullfsync flush failed, err = %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01428 [NONE] `				       err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] ` * ksmbd_vfs_remove_file() - vfs helper for smb rmdir or unlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] ` * @path:	path of dentry`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `int ksmbd_vfs_remove_file(struct ksmbd_work *work, const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `	struct dentry *parent = path->dentry->d_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `	if (!d_inode(path->dentry)->i_nlink) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01456 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `	idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `	if (S_ISDIR(d_inode(path->dentry)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `		err = vfs_rmdir(idmap, d_inode(parent), path->dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `		err = vfs_rmdir(idmap, d_inode(parent), path->dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `		if (err && err != -ENOTEMPTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `			ksmbd_debug(VFS, "rmdir failed, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `		err = vfs_unlink(idmap, d_inode(parent), path->dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `			ksmbd_debug(VFS, "unlink failed, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] ` * ksmbd_vfs_remove_file() - vfs helper for smb rmdir or unlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] ` * @name:	directory or file name that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `int ksmbd_vfs_remove_file(struct ksmbd_work *work, char *name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `	struct dentry *parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `	err = ksmbd_vfs_kern_path(work, name, LOOKUP_NO_SYMLINKS, &path, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `		ksmbd_debug(VFS, "can't get %s, err %d\n", name, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `		ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `	idmap = mnt_idmap(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `	user_ns = mnt_user_ns(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `	parent = dget_parent(path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `	err = ksmbd_vfs_lock_parent(idmap, parent, path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `	err = ksmbd_vfs_lock_parent(user_ns, parent, path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `		dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `		ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	if (!d_inode(path.dentry)->i_nlink) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `		err = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01526 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `	if (S_ISDIR(d_inode(path.dentry)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `		err = vfs_rmdir(idmap, d_inode(parent), path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `		err = vfs_rmdir(user_ns, d_inode(parent), path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `		err = vfs_rmdir(d_inode(parent), path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `		if (err && err != -ENOTEMPTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `			ksmbd_debug(VFS, "%s: rmdir failed, err %d\n", name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `				    err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `		err = vfs_unlink(idmap, d_inode(parent), path.dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `		err = vfs_unlink(user_ns, d_inode(parent), path.dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `		err = vfs_unlink(d_inode(parent), path.dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] `			ksmbd_debug(VFS, "%s: unlink failed, err %d\n", name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] `				    err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `	inode_unlock(d_inode(parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `	path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] ` * ksmbd_vfs_link() - vfs helper for creating smb hardlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] ` * @oldname:	source file name`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] ` * @newname:	hardlink name that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] `int ksmbd_vfs_link(struct ksmbd_work *work, const char *oldname,`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `		   const char *newname)`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `	struct path oldpath, newpath;`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `		unsigned int lookup_flags =`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `			LOOKUP_NO_SYMLINKS | LOOKUP_BENEATH;`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `		err = kern_path(oldname, lookup_flags, &oldpath);`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [ERROR_PATH|] `		pr_err("cannot get linux path for %s, err = %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01590 [NONE] `		       oldname, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [ERROR_PATH|] `		goto out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01592 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `	dentry = ksmbd_vfs_kern_path_create(work, newname,`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `					    LOOKUP_NO_SYMLINKS | LOOKUP_REVAL,`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `					    &newpath);`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `	if (IS_ERR(dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] `		err = PTR_ERR(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [ERROR_PATH|] `		pr_err("path create err for %s, err %d\n", newname, err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01600 [ERROR_PATH|] `		goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01601 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `	err = -EXDEV;`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `	if (oldpath.mnt != newpath.mnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [ERROR_PATH|] `		pr_err("vfs_link failed err %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01606 [ERROR_PATH|] `		goto out3;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01607 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `	err = vfs_link(oldpath.dentry, mnt_idmap(newpath.mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `		       d_inode(newpath.dentry),`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `		       dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `	err = vfs_link(oldpath.dentry, mnt_user_ns(newpath.mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `		       d_inode(newpath.dentry),`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `		       dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `	err = vfs_link(oldpath.dentry, d_inode(newpath.dentry), dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `		ksmbd_debug(VFS, "vfs_link failed err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `out3:`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `	end_creating_path(&newpath, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `	done_path_create(&newpath, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `out2:`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `	path_put(&oldpath);`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `out1:`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `int ksmbd_vfs_rename(struct ksmbd_work *work, const struct path *old_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `		     char *newname, int flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `	struct dentry *old_parent, *new_dentry, *trap;`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `	struct dentry *old_child = old_path->dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `	struct path new_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `	struct qstr new_last;`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `	struct renamedata rd;`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `	struct filename *to;`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `	struct ksmbd_file *parent_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `	struct ksmbd_share_config *share_conf = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `	int new_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `	int err, lookup_flags = LOOKUP_NO_SYMLINKS;`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `	int target_lookup_flags = LOOKUP_RENAME_TARGET | LOOKUP_CREATE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `	to = getname_kernel(newname);`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `	if (IS_ERR(to)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `		err = PTR_ERR(to);`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [ERROR_PATH|] `		goto revert_fsids;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01663 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `	 * explicitly handle file overwrite case, for compatibility with`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `	 * filesystems that may not support rename flags (e.g: fuse)`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `	if (flags & RENAME_NOREPLACE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `		target_lookup_flags |= LOOKUP_EXCL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `	flags &= ~(RENAME_NOREPLACE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `retry:`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `	err = vfs_path_parent_lookup(to, lookup_flags | LOOKUP_BENEATH,`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `				     &new_path, &new_last, &new_type,`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `				     &share_conf->vfs_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [ERROR_PATH|] `		goto out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `	if (old_path->mnt != new_path.mnt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `		err = -EXDEV;`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [ERROR_PATH|] `		goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01685 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `	err = mnt_want_write(old_path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [ERROR_PATH|] `		goto out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `	trap = lock_rename_child(old_child, new_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `	if (IS_ERR(trap)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `		err = PTR_ERR(trap);`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [ERROR_PATH|] `		goto out_drop_write;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01695 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `	old_parent = dget(old_child->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `	if (d_unhashed(old_child)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [ERROR_PATH|] `		goto out3;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01701 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `	 * MS-FSA: if the parent directory is open with DELETE access,`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [PROTO_GATE|] `	 * block the rename with STATUS_SHARING_VIOLATION.  This matches`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01706 [NONE] `	 * upstream ksmbd behavior and Windows semantics.`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `	parent_fp = ksmbd_lookup_fd_inode(old_child->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `	if (parent_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `		if (parent_fp->daccess & FILE_DELETE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `			ksmbd_debug(VFS,`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `				    "parent dir is opened with delete access\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `			err = -ESHARE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `			ksmbd_fd_put(work, parent_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [ERROR_PATH|] `			goto out3;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01716 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `		ksmbd_fd_put(work, parent_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `	 * If renaming a directory, check that no child files/dirs`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] `	 * are currently open.  An open child handle prevents the`
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [PROTO_GATE|] `	 * rename (Windows semantics: STATUS_ACCESS_DENIED).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01724 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	 * We iterate the dentry children under d_lock to safely`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `	 * walk the list, grabbing a reference (dget) to each`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `	 * positive child.  We then release d_lock before calling`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `	 * ksmbd_lookup_fd_inode (which may sleep).`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `	if (d_is_dir(old_child)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `		struct dentry *child;`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `		struct ksmbd_file *child_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [LOCK|] `		spin_lock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01736 [NONE] `		for (child = d_first_child(old_child); child;`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `		     child = d_next_sibling(child)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `			if (d_really_is_negative(child))`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `			dget(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [LOCK|] `			spin_unlock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01742 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] `			child_fp = ksmbd_lookup_fd_inode(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `			if (child_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `				ksmbd_fd_put(work, child_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `				dput(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `				ksmbd_debug(VFS,`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `					    "Forbid rename, sub file/dir is in use\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `				err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [ERROR_PATH|] `				goto out3;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01751 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `			dput(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [LOCK|] `			spin_lock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01754 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [LOCK|] `		spin_unlock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01756 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [LOCK|] `		spin_lock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01758 [NONE] `		list_for_each_entry(child, &old_child->d_subdirs, d_child) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `			if (d_really_is_negative(child))`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `			dget(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [LOCK|] `			spin_unlock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `			child_fp = ksmbd_lookup_fd_inode(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `			if (child_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `				ksmbd_fd_put(work, child_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `				dput(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `				ksmbd_debug(VFS,`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `					    "Forbid rename, sub file/dir is in use\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `				err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [ERROR_PATH|] `				goto out3;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01772 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `			dput(child);`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [LOCK|] `			spin_lock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01775 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [LOCK|] `		spin_unlock(&old_child->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01777 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] `	new_dentry = lookup_one_qstr_excl(&new_last, new_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `					  lookup_flags | target_lookup_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `	new_dentry = lookup_one_qstr_excl(&new_last, new_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `					  lookup_flags | LOOKUP_RENAME_TARGET);`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `	if (IS_ERR(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `		err = PTR_ERR(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [ERROR_PATH|] `		goto out3;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01790 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `	if (d_is_symlink(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `		err = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [ERROR_PATH|] `		goto out4;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01795 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `	 * explicitly handle file overwrite case, for compatibility with`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `	 * filesystems that may not support rename flags (e.g: fuse)`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `	if ((flags & RENAME_NOREPLACE) && d_is_positive(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `		err = -EEXIST;`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [ERROR_PATH|] `		goto out4;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01805 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `	flags &= ~(RENAME_NOREPLACE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	if (old_child == trap) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [ERROR_PATH|] `		goto out4;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01812 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `	if (new_dentry == trap) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `		err = -ENOTEMPTY;`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [ERROR_PATH|] `		goto out4;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01817 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	rd.mnt_idmap		= mnt_idmap(old_path->mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `	rd.old_mnt_idmap	= mnt_idmap(old_path->mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `	rd.old_parent		= old_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `	rd.old_dir		= d_inode(old_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `	rd.old_dentry		= old_child,`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `	rd.new_mnt_idmap	= mnt_idmap(new_path.mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `	rd.new_parent		= new_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `	rd.new_dir		= new_path.dentry->d_inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] `	rd.new_dentry		= new_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `	rd.flags		= flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	rd.delegated_inode	= NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `	err = vfs_rename(&rd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `		ksmbd_debug(VFS, "vfs_rename failed err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `out4:`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `	dput(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `out3:`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `	dput(old_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `	unlock_rename(old_parent, new_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `out_drop_write:`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `	mnt_drop_write(old_path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `out2:`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `	path_put(&new_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `	if (retry_estale(err, lookup_flags)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `		lookup_flags |= LOOKUP_REVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [ERROR_PATH|] `		goto retry;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01858 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `out1:`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `	putname(to);`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `revert_fsids:`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] `static int ksmbd_validate_entry_in_use(struct dentry *src_dent)`
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `	struct dentry *dst_dent;`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [LOCK|] `	spin_lock(&src_dent->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01872 [NONE] `	list_for_each_entry(dst_dent, &src_dent->d_subdirs, d_child) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `		struct ksmbd_file *child_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `		if (d_really_is_negative(dst_dent))`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `		child_fp = ksmbd_lookup_fd_inode(dst_dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `		if (child_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [LOCK|] `			spin_unlock(&src_dent->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01881 [NONE] `			ksmbd_debug(VFS, "Forbid rename, sub file/dir is in use\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [ERROR_PATH|] `			return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01883 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [LOCK|] `	spin_unlock(&src_dent->d_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01886 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `static int __ksmbd_vfs_rename(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `			      struct mnt_idmap *src_idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `			      struct dentry *src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `			      struct dentry *src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `			      struct mnt_idmap *dst_idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `			      struct dentry *dst_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] `			      struct dentry *trap_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] `			      char *dst_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `static int __ksmbd_vfs_rename(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `			      struct user_namespace *src_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] `			      struct dentry *src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `			      struct dentry *src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `			      struct user_namespace *dst_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `			      struct dentry *dst_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `			      struct dentry *trap_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `			      char *dst_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `	struct dentry *dst_dent;`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] `	if (!work->tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] `		err = ksmbd_validate_entry_in_use(src_dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `			return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `	if (d_really_is_negative(src_dent_parent))`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01921 [NONE] `	if (d_really_is_negative(dst_dent_parent))`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01923 [NONE] `	if (d_really_is_negative(src_dent))`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01925 [NONE] `	if (src_dent == trap_dent)`
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01927 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] `		struct qstr dst_qstr = QSTR_INIT(dst_name, strlen(dst_name));`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] `		dst_dent = lookup_one(dst_idmap, &dst_qstr, dst_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `	dst_dent = lookup_one(dst_idmap, dst_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `			      dst_dent_parent, strlen(dst_name));`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] `	dst_dent = lookup_one(dst_user_ns, dst_name, dst_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `			      strlen(dst_name));`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] `	dst_dent = lookup_one_len(dst_name, dst_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `				  strlen(dst_name));`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `	err = PTR_ERR(dst_dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] `	if (IS_ERR(dst_dent)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [ERROR_PATH|] `		pr_err("lookup failed %s [%d]\n", dst_name, err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01949 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01950 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] `	err = -ENOTEMPTY;`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `	if (dst_dent != trap_dent &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `	    (!d_really_is_positive(dst_dent) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `	     (work && work->tcon && work->tcon->posix_extensions))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `		struct renamedata rd = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] `			.old_mnt_idmap	= src_idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] `			.old_dir	= d_inode(src_dent_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `			.old_dentry	= src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `			.new_mnt_idmap	= dst_idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `			.new_dir	= d_inode(dst_dent_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `			.new_dentry	= dst_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `		};`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `		struct renamedata rd = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `			.old_mnt_userns	= src_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `			.old_dir	= d_inode(src_dent_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `			.old_dentry	= src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `			.new_mnt_userns	= dst_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `			.new_dir	= d_inode(dst_dent_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `			.new_dentry	= dst_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] `		};`
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `		err = vfs_rename(&rd);`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] `		err = vfs_rename(d_inode(src_dent_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `				 src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `				 d_inode(dst_dent_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `				 dst_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `				 NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] `				 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [ERROR_PATH|] `		pr_err("vfs_rename failed err %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01988 [NONE] `	if (dst_dent)`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `		dput(dst_dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `int ksmbd_vfs_fp_rename(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `			char *newname)`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `	struct path dst_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `	struct dentry *src_dent_parent, *dst_dent_parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `	struct dentry *src_dent, *trap_dent, *src_child;`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `	char *dst_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `	dst_name = extract_last_component(newname);`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `	if (!dst_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `		dst_name = newname;`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `		newname = "";`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] `	src_dent_parent = dget_parent(fp->filp->f_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] `	src_dent = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `	err = ksmbd_vfs_kern_path(work, newname,`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `				  LOOKUP_NO_SYMLINKS | LOOKUP_DIRECTORY,`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [NONE] `				  &dst_path, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] `		ksmbd_debug(VFS, "Cannot get path for %s [%d]\n", newname, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02024 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `	dst_dent_parent = dst_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `	trap_dent = lock_rename(src_dent_parent, dst_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `	dget(src_dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `	dget(dst_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `	idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `	user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `	src_child = lookup_one(idmap, &src_dent->d_name, src_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `	src_child = lookup_one(idmap, src_dent->d_name.name, src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `			       src_dent->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `	src_child = lookup_one(user_ns, src_dent->d_name.name, src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `			       src_dent->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] `	src_child = lookup_one_len(src_dent->d_name.name, src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `				   src_dent->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `	if (IS_ERR(src_child)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `		err = PTR_ERR(src_child);`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [ERROR_PATH|] `		goto out_lock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02050 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `	if (src_child != src_dent) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] `		err = -ESTALE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [NONE] `		dput(src_child);`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [ERROR_PATH|] `		goto out_lock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02056 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `	dput(src_child);`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02059 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `	err = __ksmbd_vfs_rename(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [NONE] `				 idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [NONE] `				 src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] `				 src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [NONE] `				 mnt_idmap(dst_path.mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `				 dst_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `				 trap_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `				 dst_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] `	err = __ksmbd_vfs_rename(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `				 user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `				 src_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `				 src_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] `				 mnt_user_ns(dst_path.mnt),`
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `				 dst_dent_parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `				 trap_dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `				 dst_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `out_lock:`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] `	dput(src_dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `	dput(dst_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `	unlock_rename(src_dent_parent, dst_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] `	path_put(&dst_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `	dput(src_dent_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] ` * ksmbd_vfs_truncate() - vfs helper for smb file truncate`
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] ` * @work:	work`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] ` * @fp:		ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] ` * @size:	truncate to given size`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `int ksmbd_vfs_truncate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `		       struct ksmbd_file *fp, loff_t size)`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] `	if (size < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] `	filp = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] `	/* Do we need to break any of a levelII oplock? */`
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `	smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] `	if (!work->tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] `		struct inode *inode = file_inode(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] `		if (size < inode->i_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `			err = check_lock_range(filp, size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `					       inode->i_size - 1, WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [NONE] `		} else if (size > inode->i_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] `			err = check_lock_range(filp, inode->i_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `					       size - 1, WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [NONE] `		if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02123 [ERROR_PATH|] `			pr_err("failed due to lock\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02124 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02125 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `	err = vfs_truncate(&filp->f_path, size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [ERROR_PATH|] `		pr_err("truncate failed, err %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02131 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02136 [NONE] ` * ksmbd_vfs_resolve_fileid() - resolve inode number to path relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L02137 [NONE] ` * @share_path:	the share root path`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] ` * @ino:	inode number to resolve`
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] ` * @buf:	output buffer for the resolved path (UTF-8)`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] ` * @buflen:	size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] ` * Used by Apple kAAPL_RESOLVE_ID to convert a file ID (inode number)`
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [NONE] ` * back to its full path for alias/symlink resolution.`
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] ` * Return:	length of path on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `int ksmbd_vfs_resolve_fileid(const struct path *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `			     u64 ino, char *buf, int buflen)`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] `	char *path_buf, *resolved;`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] `	int len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] `	inode = ilookup(share_path->dentry->d_sb, ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [NONE] `	if (!inode)`
  Review: Low-risk line; verify in surrounding control flow.
- L02157 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] `	dentry = d_find_alias(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] `	iput(inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `	if (!dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [NONE] `	/* Verify resolved file is within the share boundary */`
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] `	if (!is_subdir(dentry, share_path->dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [ERROR_PATH|] `		pr_err("resolve_fileid: inode %llu is outside share boundary\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02167 [NONE] `		       ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] `		dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02170 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [MEM_BOUNDS|] `	path_buf = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02173 [NONE] `	if (!path_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] `		dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02176 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02178 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02179 [NONE] `	 * Use dentry_path_raw to get path relative to the filesystem root,`
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] `	 * then strip the share path prefix to get share-relative path.`
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02182 [NONE] `	resolved = dentry_path_raw(dentry, path_buf, PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [NONE] `	dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02185 [NONE] `	if (IS_ERR(resolved)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [NONE] `		kfree(path_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02187 [NONE] `		return PTR_ERR(resolved);`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `	len = strlen(resolved);`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] `	if (len >= buflen) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] `		kfree(path_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [ERROR_PATH|] `		return -ENAMETOOLONG;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02194 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [MEM_BOUNDS|] `	memcpy(buf, resolved, len + 1);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02197 [NONE] `	kfree(path_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `	return len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] ` * ksmbd_vfs_copy_xattrs() - copy all user.* xattrs from src to dst`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] ` * @src_dentry:	source dentry`
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] ` * @dst_dentry:	destination dentry`
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] ` * @dst_path:	destination path (needed for ksmbd_vfs_setxattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] ` * Used by Apple COPYFILE support to preserve metadata (FinderInfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] ` * resource forks, DosStream attributes) during server-side copy.`
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [NONE] ` * Return:	0 on success (partial failures are logged but not fatal),`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [NONE] ` *		negative errno if xattr enumeration fails`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] `int ksmbd_vfs_copy_xattrs(struct dentry *src_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `			   struct dentry *dst_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] `			   const struct path *dst_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [NONE] `	char *xattr_list = NULL, *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L02218 [NONE] `	ssize_t list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] `	int idx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] `	list_len = ksmbd_vfs_listxattr(src_dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] `	if (list_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] `		return list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `	while (idx < list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] `		ssize_t val_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `		char *val_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02229 [NONE] `		name = xattr_list + idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [NONE] `		idx += strlen(name) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] `		/* Only copy user.* namespace xattrs */`
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [NONE] `		/* Skip CIFS-internal xattrs that should not be copied */`
  Review: Low-risk line; verify in surrounding control flow.
- L02237 [NONE] `		if (!strcmp(name, XATTR_NAME_DOS_ATTRIBUTE) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `		    !strncmp(name, XATTR_NAME_STREAM, XATTR_NAME_STREAM_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [NONE] `		/* Read source xattr value */`
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] `		val_len = ksmbd_vfs_getxattr(&nop_mnt_idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] `		val_len = ksmbd_vfs_getxattr(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `					     src_dentry, name, &val_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] `		if (val_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `			ksmbd_debug(VFS, "copy xattr: skip %s (read err %zd)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `				    name, val_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02254 [NONE] `		/* Write to destination */`
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] `		ksmbd_vfs_setxattr(&nop_mnt_idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02258 [NONE] `		ksmbd_vfs_setxattr(&init_user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `				   dst_path, name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] `				   val_buf, val_len, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `		kvfree(val_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02267 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] `#endif /* CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] ` * ksmbd_vfs_listxattr() - vfs helper for smb list extended attributes`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [NONE] ` * @dentry:	dentry of file for listing xattrs`
  Review: Low-risk line; verify in surrounding control flow.
- L02274 [NONE] ` * @list:	destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] ` * Return:	xattr list length on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `ssize_t ksmbd_vfs_listxattr(struct dentry *dentry, char **list)`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `	ssize_t size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `	char *vlist = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `	int retries = 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] `retry:`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] `	size = vfs_listxattr(dentry, NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] `	if (size <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] `		return size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [MEM_BOUNDS|] `	vlist = kvzalloc(size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02290 [NONE] `	if (!vlist)`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `	*list = vlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `	size = vfs_listxattr(dentry, vlist, size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [NONE] `	if (size == -ERANGE && --retries > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02296 [NONE] `		kvfree(vlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] `		*list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [ERROR_PATH|] `		goto retry;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02299 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02301 [NONE] `	if (size < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `		ksmbd_debug(VFS, "listxattr failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `		kvfree(vlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `		*list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [NONE] `	return size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `static ssize_t ksmbd_vfs_xattr_len(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `static ssize_t ksmbd_vfs_xattr_len(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02315 [NONE] `				   struct dentry *dentry, char *xattr_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `	return vfs_getxattr(idmap, dentry, xattr_name, NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [NONE] `	return vfs_getxattr(user_ns, dentry, xattr_name, NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02322 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `	return vfs_getxattr(dentry, xattr_name, NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] ` * ksmbd_vfs_getxattr() - vfs helper for smb get extended attributes value`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `+  @idmap:	idmap`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] `+  @user_ns:	user namespace`
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] ` * @dentry:	dentry of file for getting xattrs`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] ` * @xattr_name:	name of xattr name to query`
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] ` * @xattr_buf:	destination buffer xattr value`
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] ` * Return:	read xattr value length on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] `ssize_t ksmbd_vfs_getxattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] `ssize_t ksmbd_vfs_getxattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] `			   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `			   char *xattr_name, char **xattr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] `	ssize_t xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `	char *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [NONE] `	*xattr_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] `	xattr_len = ksmbd_vfs_xattr_len(idmap, dentry, xattr_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [NONE] `	xattr_len = ksmbd_vfs_xattr_len(user_ns, dentry, xattr_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02357 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `	if (xattr_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `		return xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [MEM_BOUNDS|] `	buf = kmalloc(xattr_len + 1, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02362 [NONE] `	if (!buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02366 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] `	xattr_len = vfs_getxattr(idmap, dentry, xattr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] `	xattr_len = vfs_getxattr(user_ns, dentry, xattr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] `				 (void *)buf, xattr_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] `	xattr_len = vfs_getxattr(dentry, xattr_name, (void *)buf, xattr_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] `	if (xattr_len > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] `		*xattr_buf = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [NONE] `		kfree(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02379 [NONE] `	return xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] ` * ksmbd_vfs_setxattr() - vfs helper for smb set extended attributes value`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] ` * @idmap:	idmap of the relevant mount`
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] ` * @user_ns:	user namespace`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] ` * @path:	path of dentry to set XATTR at`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [NONE] ` * @attr_name:	xattr name for setxattr`
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] ` * @attr_value:	xattr value to set`
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] ` * @attr_size:	size of xattr value`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [NONE] ` * @flags:	destination buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L02394 [NONE] ` * @get_write:	get write access to a mount`
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `int ksmbd_vfs_setxattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [NONE] `int ksmbd_vfs_setxattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [NONE] `		       const struct path *path, const char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02404 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] `		       void *attr_value, size_t attr_size, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] `		       bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [NONE] `		       const void *attr_value, size_t attr_size, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L02409 [NONE] `		       bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `	if (get_write == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] `		err = mnt_want_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `			return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02422 [NONE] `	err = vfs_setxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `	err = vfs_setxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `			   path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] `	err = vfs_setxattr(path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] `			   attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `			   attr_value,`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] `			   attr_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `			   flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] `		ksmbd_debug(VFS, "setxattr failed, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] `	if (get_write == true)`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] `		mnt_drop_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] `int ksmbd_vfs_fsetxattr(struct ksmbd_work *work, const char *filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [NONE] `			const char *attr_name, const void *attr_value,`
  Review: Low-risk line; verify in surrounding control flow.
- L02444 [NONE] `			size_t attr_size, int flags)`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `	if (ksmbd_override_fsids(work))`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [NONE] `		unsigned int lookup_flags = LOOKUP_BENEATH;`
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] `		err = kern_path(filename, lookup_flags, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] `		ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [NONE] `		ksmbd_debug(VFS, "cannot get linux path %s, err %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02460 [NONE] `			    filename, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] `	err = vfs_setxattr(mnt_idmap(path.mnt), path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `	err = vfs_setxattr(mnt_user_ns(path.mnt), path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [NONE] `	err = vfs_setxattr(path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02472 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [NONE] `			   attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02474 [NONE] `			   attr_value,`
  Review: Low-risk line; verify in surrounding control flow.
- L02475 [NONE] `			   attr_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [NONE] `			   flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02477 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02478 [NONE] `		ksmbd_debug(VFS, "setxattr failed, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L02479 [NONE] `	path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02482 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02483 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02485 [NONE] `struct dentry *ksmbd_vfs_kern_path_create(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02486 [NONE] `					  const char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02487 [NONE] `					  unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L02488 [NONE] `					  struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L02489 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02490 [NONE] `	char *abs_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L02491 [NONE] `	struct dentry *dent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02492 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02493 [NONE] `	abs_name = convert_to_unix_name(work->tcon->share_conf, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02494 [NONE] `	if (IS_ERR(abs_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `		return ERR_CAST(abs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02497 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] `	dent = start_creating_path(AT_FDCWD, abs_name, path, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [NONE] `	dent = kern_path_create(AT_FDCWD, abs_name, path, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02501 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02502 [NONE] `	kfree(abs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] `	return dent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02506 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `int ksmbd_vfs_remove_acl_xattrs(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [NONE] `				const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L02509 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02510 [NONE] `int ksmbd_vfs_remove_acl_xattrs(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02511 [NONE] `				const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L02512 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [NONE] `	char *name, *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02515 [NONE] `	ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02516 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] `	if (xattr_list_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02521 [NONE] `	} else if (!xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02522 [NONE] `		ksmbd_debug(SMB, "empty xattr in the file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02523 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02524 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [NONE] `	err = mnt_want_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02527 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02528 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] `	for (name = xattr_list; name - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] `	     name += strlen(name) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] `		ksmbd_debug(SMB, "%s, len %zd\n", name, strlen(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] `		if (!strncmp(name, XATTR_NAME_POSIX_ACL_ACCESS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] `			     sizeof(XATTR_NAME_POSIX_ACL_ACCESS) - 1) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] `		    !strncmp(name, XATTR_NAME_POSIX_ACL_DEFAULT,`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [NONE] `			     sizeof(XATTR_NAME_POSIX_ACL_DEFAULT) - 1)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02538 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02539 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] `			err = vfs_remove_acl(idmap, path->dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [NONE] `			err = vfs_remove_acl(user_ns, path->dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02543 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02544 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02545 [NONE] `			err = ksmbd_vfs_remove_xattr(user_ns, path, name, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02548 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `					    "remove acl xattr failed : %s\n", name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02552 [NONE] `	mnt_drop_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02556 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02558 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [NONE] `int ksmbd_vfs_remove_sd_xattrs(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02560 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [NONE] `int ksmbd_vfs_remove_sd_xattrs(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02562 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02563 [NONE] `			       const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02565 [NONE] `	char *name, *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02566 [NONE] `	ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02567 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02570 [NONE] `	if (xattr_list_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02572 [NONE] `	} else if (!xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [NONE] `		ksmbd_debug(SMB, "empty xattr in the file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02574 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02575 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02576 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02577 [NONE] `	for (name = xattr_list; name - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02578 [NONE] `			name += strlen(name) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02579 [NONE] `		ksmbd_debug(SMB, "%s, len %zd\n", name, strlen(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L02580 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] `		if (!strncmp(name, XATTR_NAME_SD, XATTR_NAME_SD_LEN)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02583 [NONE] `			err = ksmbd_vfs_remove_xattr(idmap, path, name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02585 [NONE] `			err = ksmbd_vfs_remove_xattr(user_ns, path, name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L02586 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02587 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [NONE] `				ksmbd_debug(SMB, "remove xattr failed : %s\n", name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02589 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02593 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [NONE] `static struct xattr_smb_acl *ksmbd_vfs_make_xattr_posix_acl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02598 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02599 [NONE] `static struct xattr_smb_acl *ksmbd_vfs_make_xattr_posix_acl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02601 [NONE] `							    struct inode *inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02602 [NONE] `							    int acl_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [NONE] `	struct xattr_smb_acl *smb_acl = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02605 [NONE] `	struct posix_acl *posix_acls;`
  Review: Low-risk line; verify in surrounding control flow.
- L02606 [NONE] `	struct posix_acl_entry *pa_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [NONE] `	struct xattr_acl_entry *xa_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02608 [NONE] `	size_t alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02609 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L02610 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02611 [NONE] `	if (!IS_ENABLED(CONFIG_FS_POSIX_ACL))`
  Review: Low-risk line; verify in surrounding control flow.
- L02612 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [NONE] `	posix_acls = get_inode_acl(inode, acl_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02616 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02617 [NONE] `	posix_acls = get_acl(inode, acl_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02618 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] `	if (IS_ERR_OR_NULL(posix_acls))`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] `	if (check_mul_overflow(sizeof(struct xattr_acl_entry),`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] `			       (size_t)posix_acls->a_count, &alloc_size) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [MEM_BOUNDS|] `	    check_add_overflow(sizeof(struct xattr_smb_acl), alloc_size, &alloc_size))`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02625 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [MEM_BOUNDS|] `	smb_acl = kzalloc(alloc_size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02628 [NONE] `	if (!smb_acl)`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02631 [NONE] `	smb_acl->count = posix_acls->a_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [NONE] `	pa_entry = posix_acls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L02633 [NONE] `	xa_entry = smb_acl->entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L02634 [NONE] `	for (i = 0; i < posix_acls->a_count; i++, pa_entry++, xa_entry++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02635 [NONE] `		switch (pa_entry->e_tag) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02636 [NONE] `		case ACL_USER:`
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [NONE] `			xa_entry->type = SMB_ACL_USER;`
  Review: Low-risk line; verify in surrounding control flow.
- L02638 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02639 [NONE] `			xa_entry->uid = posix_acl_uid_translate(idmap, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [NONE] `			xa_entry->uid = posix_acl_uid_translate(user_ns, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02642 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02643 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `		case ACL_USER_OBJ:`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `			xa_entry->type = SMB_ACL_USER_OBJ;`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02647 [NONE] `		case ACL_GROUP:`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [NONE] `			xa_entry->type = SMB_ACL_GROUP;`
  Review: Low-risk line; verify in surrounding control flow.
- L02649 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02650 [NONE] `			xa_entry->gid = posix_acl_gid_translate(idmap, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02651 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02652 [NONE] `			xa_entry->gid = posix_acl_gid_translate(user_ns, pa_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02653 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02654 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02655 [NONE] `		case ACL_GROUP_OBJ:`
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `			xa_entry->type = SMB_ACL_GROUP_OBJ;`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] `		case ACL_OTHER:`
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] `			xa_entry->type = SMB_ACL_OTHER;`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] `		case ACL_MASK:`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [NONE] `			xa_entry->type = SMB_ACL_MASK;`
  Review: Low-risk line; verify in surrounding control flow.
- L02663 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L02665 [ERROR_PATH|] `			pr_err("unknown type : 0x%x\n", pa_entry->e_tag);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02666 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02667 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `		if (pa_entry->e_perm & ACL_READ)`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [NONE] `			xa_entry->perm |= SMB_ACL_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L02671 [NONE] `		if (pa_entry->e_perm & ACL_WRITE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02672 [NONE] `			xa_entry->perm |= SMB_ACL_WRITE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] `		if (pa_entry->e_perm & ACL_EXECUTE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [NONE] `			xa_entry->perm |= SMB_ACL_EXECUTE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02675 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02676 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02677 [NONE] `	posix_acl_release(posix_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `	return smb_acl;`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [NONE] `int ksmbd_vfs_set_sd_xattr(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02682 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] `			   struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `			   struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `			   const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `			   struct smb_ntsd *pntsd, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [NONE] `			   bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L02690 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02692 [NONE] `	struct ndr sd_ndr = {0}, acl_ndr = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [NONE] `	struct xattr_ntacl acl = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02694 [NONE] `	struct xattr_smb_acl *smb_acl, *def_smb_acl = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [NONE] `	struct dentry *dentry = path->dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02696 [NONE] `	struct inode *inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02698 [NONE] `	acl.version = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02699 [NONE] `	acl.hash_type = XATTR_SD_HASH_TYPE_SHA256;`
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [NONE] `	acl.current_time = ksmbd_UnixTimeToNT(current_time(inode));`
  Review: Low-risk line; verify in surrounding control flow.
- L02701 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02702 [MEM_BOUNDS|] `	memcpy(acl.desc, "posix_acl", 9);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02703 [NONE] `	acl.desc_len = 10;`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [NONE] `	if (le32_to_cpu(pntsd->osidoffset) > UINT_MAX - NDR_NTSD_OFFSETOF ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02706 [NONE] `	    le32_to_cpu(pntsd->gsidoffset) > UINT_MAX - NDR_NTSD_OFFSETOF ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [NONE] `	    le32_to_cpu(pntsd->dacloffset) > UINT_MAX - NDR_NTSD_OFFSETOF)`
  Review: Low-risk line; verify in surrounding control flow.
- L02708 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02710 [NONE] `	pntsd->osidoffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L02711 [NONE] `		cpu_to_le32(le32_to_cpu(pntsd->osidoffset) + NDR_NTSD_OFFSETOF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02712 [NONE] `	pntsd->gsidoffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L02713 [NONE] `		cpu_to_le32(le32_to_cpu(pntsd->gsidoffset) + NDR_NTSD_OFFSETOF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02714 [NONE] `	pntsd->dacloffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `		cpu_to_le32(le32_to_cpu(pntsd->dacloffset) + NDR_NTSD_OFFSETOF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] `	acl.sd_buf = (char *)pntsd;`
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [NONE] `	acl.sd_size = len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] `	rc = ksmbd_gen_sd_hash(conn, acl.sd_buf, acl.sd_size, acl.hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02722 [ERROR_PATH|] `		pr_err("failed to generate hash for ndr acl\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02723 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02724 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02727 [NONE] `	smb_acl = ksmbd_vfs_make_xattr_posix_acl(idmap, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [NONE] `	smb_acl = ksmbd_vfs_make_xattr_posix_acl(user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02730 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02731 [NONE] `						 ACL_TYPE_ACCESS);`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [NONE] `	if (S_ISDIR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L02733 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] `		def_smb_acl = ksmbd_vfs_make_xattr_posix_acl(idmap, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `		def_smb_acl = ksmbd_vfs_make_xattr_posix_acl(user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `							     ACL_TYPE_DEFAULT);`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02740 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [NONE] `	rc = ndr_encode_posix_acl(&acl_ndr, idmap, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02742 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] `	rc = ndr_encode_posix_acl(&acl_ndr, user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] `				  smb_acl, def_smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [ERROR_PATH|] `		pr_err("failed to encode ndr to posix acl\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02748 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02749 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] `	rc = ksmbd_gen_sd_hash(conn, acl_ndr.data, acl_ndr.offset,`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] `			       acl.posix_acl_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [ERROR_PATH|] `		pr_err("failed to generate hash for ndr acl\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02755 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02756 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02758 [NONE] `	rc = ndr_encode_v4_ntacl(&sd_ndr, &acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [ERROR_PATH|] `		pr_err("failed to encode ndr to posix acl\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02761 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02762 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] `	rc = ksmbd_vfs_setxattr(idmap, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] `	rc = ksmbd_vfs_setxattr(user_ns, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `				XATTR_NAME_SD, sd_ndr.data,`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `				sd_ndr.offset, 0, get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [ERROR_PATH|] `		pr_err("Failed to store XATTR ntacl :%d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02774 [NONE] `	kfree(sd_ndr.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02775 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02776 [NONE] `	kfree(acl_ndr.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02777 [NONE] `	kfree(smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02778 [NONE] `	kfree(def_smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02779 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02780 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02781 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02782 [NONE] `int ksmbd_vfs_get_sd_xattr(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02783 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02784 [NONE] `			   struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02785 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02786 [NONE] `			   struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02787 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02788 [NONE] `			   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02789 [NONE] `			   struct smb_ntsd **pntsd)`
  Review: Low-risk line; verify in surrounding control flow.
- L02790 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02791 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02792 [NONE] `	struct ndr n;`
  Review: Low-risk line; verify in surrounding control flow.
- L02793 [NONE] `	struct inode *inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02794 [NONE] `	struct ndr acl_ndr = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02795 [NONE] `	struct xattr_ntacl acl;`
  Review: Low-risk line; verify in surrounding control flow.
- L02796 [NONE] `	struct xattr_smb_acl *smb_acl = NULL, *def_smb_acl = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02797 [NONE] `	__u8 cmp_hash[XATTR_SD_HASH_SIZE] = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02799 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02800 [NONE] `	rc = ksmbd_vfs_getxattr(idmap, dentry, XATTR_NAME_SD, &n.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02801 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02802 [NONE] `	rc = ksmbd_vfs_getxattr(user_ns, dentry, XATTR_NAME_SD, &n.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02803 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02804 [NONE] `	if (rc <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02805 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02806 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02807 [NONE] `	n.length = rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02808 [NONE] `	rc = ndr_decode_v4_ntacl(&n, &acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02809 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02810 [ERROR_PATH|] `		goto free_n_data;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02812 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02813 [NONE] `	smb_acl = ksmbd_vfs_make_xattr_posix_acl(idmap, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02814 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02815 [NONE] `	smb_acl = ksmbd_vfs_make_xattr_posix_acl(user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02816 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02817 [NONE] `						 ACL_TYPE_ACCESS);`
  Review: Low-risk line; verify in surrounding control flow.
- L02818 [NONE] `	if (S_ISDIR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L02819 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02820 [NONE] `		def_smb_acl = ksmbd_vfs_make_xattr_posix_acl(idmap, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02821 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02822 [NONE] `		def_smb_acl = ksmbd_vfs_make_xattr_posix_acl(user_ns, inode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02823 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02824 [NONE] `							     ACL_TYPE_DEFAULT);`
  Review: Low-risk line; verify in surrounding control flow.
- L02825 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02826 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02827 [NONE] `	rc = ndr_encode_posix_acl(&acl_ndr, idmap, inode, smb_acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L02828 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02829 [NONE] `	rc = ndr_encode_posix_acl(&acl_ndr, user_ns, inode, smb_acl,`
  Review: Low-risk line; verify in surrounding control flow.
- L02830 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02831 [NONE] `				  def_smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02832 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02833 [ERROR_PATH|] `		pr_err("failed to encode ndr to posix acl\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02834 [ERROR_PATH|] `		goto out_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02835 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02837 [NONE] `	rc = ksmbd_gen_sd_hash(conn, acl_ndr.data, acl_ndr.offset, cmp_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L02838 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02839 [ERROR_PATH|] `		pr_err("failed to generate hash for ndr acl\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02840 [ERROR_PATH|] `		goto out_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02841 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02843 [NONE] `	if (memcmp(cmp_hash, acl.posix_acl_hash, XATTR_SD_HASH_SIZE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02844 [ERROR_PATH|] `		pr_err("hash value diff\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02845 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02846 [ERROR_PATH|] `		goto out_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02847 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02848 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02849 [NONE] `	*pntsd = acl.sd_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02850 [NONE] `	if (acl.sd_size < sizeof(struct smb_ntsd)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02851 [ERROR_PATH|] `		pr_err("sd size is invalid\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02852 [ERROR_PATH|] `		goto out_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02853 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02854 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02855 [NONE] `	if (le32_to_cpu((*pntsd)->osidoffset) < NDR_NTSD_OFFSETOF ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02856 [NONE] `	    le32_to_cpu((*pntsd)->gsidoffset) < NDR_NTSD_OFFSETOF ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02857 [NONE] `	    le32_to_cpu((*pntsd)->dacloffset) < NDR_NTSD_OFFSETOF) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02858 [ERROR_PATH|] `		pr_err("invalid NTSD offset: underflow detected\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02859 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02860 [ERROR_PATH|] `		goto out_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02861 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02862 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02863 [NONE] `	(*pntsd)->osidoffset = cpu_to_le32(le32_to_cpu((*pntsd)->osidoffset) -`
  Review: Low-risk line; verify in surrounding control flow.
- L02864 [NONE] `					   NDR_NTSD_OFFSETOF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02865 [NONE] `	(*pntsd)->gsidoffset = cpu_to_le32(le32_to_cpu((*pntsd)->gsidoffset) -`
  Review: Low-risk line; verify in surrounding control flow.
- L02866 [NONE] `					   NDR_NTSD_OFFSETOF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02867 [NONE] `	(*pntsd)->dacloffset = cpu_to_le32(le32_to_cpu((*pntsd)->dacloffset) -`
  Review: Low-risk line; verify in surrounding control flow.
- L02868 [NONE] `					   NDR_NTSD_OFFSETOF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02870 [NONE] `	rc = acl.sd_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02871 [NONE] `out_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L02872 [NONE] `	kfree(acl_ndr.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02873 [NONE] `	kfree(smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02874 [NONE] `	kfree(def_smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02875 [NONE] `	if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02876 [NONE] `		kfree(acl.sd_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L02877 [NONE] `		*pntsd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02878 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02879 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02880 [NONE] `free_n_data:`
  Review: Low-risk line; verify in surrounding control flow.
- L02881 [NONE] `	kfree(n.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02882 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02883 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02885 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02886 [NONE] `int ksmbd_vfs_set_dos_attrib_xattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02887 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02888 [NONE] `int ksmbd_vfs_set_dos_attrib_xattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02889 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02890 [NONE] `				   const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02891 [NONE] `				   struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L02892 [NONE] `				   bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L02893 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02894 [NONE] `	struct ndr n;`
  Review: Low-risk line; verify in surrounding control flow.
- L02895 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02896 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02897 [NONE] `	err = ndr_encode_dos_attr(&n, da);`
  Review: Low-risk line; verify in surrounding control flow.
- L02898 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02899 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02900 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02901 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02902 [NONE] `	err = ksmbd_vfs_setxattr(idmap, path, XATTR_NAME_DOS_ATTRIBUTE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02903 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02904 [NONE] `	err = ksmbd_vfs_setxattr(user_ns, path, XATTR_NAME_DOS_ATTRIBUTE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02905 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02906 [NONE] `				 (void *)n.data, n.offset, 0, get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L02907 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L02908 [NONE] `		ksmbd_debug(SMB, "failed to store dos attribute in xattr\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02909 [NONE] `	kfree(n.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02911 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02912 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02913 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02914 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02915 [NONE] `int ksmbd_vfs_get_dos_attrib_xattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02916 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02917 [NONE] `int ksmbd_vfs_get_dos_attrib_xattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02918 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02919 [NONE] `				   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02920 [NONE] `				   struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L02921 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02922 [NONE] `	struct ndr n;`
  Review: Low-risk line; verify in surrounding control flow.
- L02923 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02924 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02925 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02926 [NONE] `	err = ksmbd_vfs_getxattr(idmap, dentry, XATTR_NAME_DOS_ATTRIBUTE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02927 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02928 [NONE] `	err = ksmbd_vfs_getxattr(user_ns, dentry, XATTR_NAME_DOS_ATTRIBUTE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02929 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02930 [NONE] `				 (char **)&n.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02931 [NONE] `	if (err > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02932 [NONE] `		n.length = err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02933 [NONE] `		if (ndr_decode_dos_attr(&n, da))`
  Review: Low-risk line; verify in surrounding control flow.
- L02934 [NONE] `			err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02935 [NONE] `		kfree(n.data);`
  Review: Low-risk line; verify in surrounding control flow.
- L02936 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02937 [NONE] `		ksmbd_debug(SMB, "failed to load dos attribute in xattr\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02938 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02939 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02940 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02941 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02943 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02944 [NONE] ` * ksmbd_vfs_set_fadvise() - convert smb IO caching options to linux options`
  Review: Low-risk line; verify in surrounding control flow.
- L02945 [NONE] ` * @filp:	file pointer for IO`
  Review: Low-risk line; verify in surrounding control flow.
- L02946 [NONE] ` * @option:	smb IO options`
  Review: Low-risk line; verify in surrounding control flow.
- L02947 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02948 [NONE] `void ksmbd_vfs_set_fadvise(struct file *filp, __le32 option)`
  Review: Low-risk line; verify in surrounding control flow.
- L02949 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02950 [NONE] `	struct address_space *mapping;`
  Review: Low-risk line; verify in surrounding control flow.
- L02951 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02952 [NONE] `	mapping = filp->f_mapping;`
  Review: Low-risk line; verify in surrounding control flow.
- L02953 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02954 [NONE] `	if (!option || !mapping)`
  Review: Low-risk line; verify in surrounding control flow.
- L02955 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02957 [NONE] `	if (option & FILE_WRITE_THROUGH_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02958 [NONE] `		filp->f_flags |= O_SYNC;`
  Review: Low-risk line; verify in surrounding control flow.
- L02959 [NONE] `	} else if (option & FILE_SEQUENTIAL_ONLY_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02960 [NONE] `		filp->f_ra.ra_pages = inode_to_bdi(mapping->host)->ra_pages * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02961 [LOCK|] `		spin_lock(&filp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02962 [NONE] `		filp->f_mode &= ~FMODE_RANDOM;`
  Review: Low-risk line; verify in surrounding control flow.
- L02963 [LOCK|] `		spin_unlock(&filp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02964 [NONE] `	} else if (option & FILE_RANDOM_ACCESS_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02965 [LOCK|] `		spin_lock(&filp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02966 [NONE] `		filp->f_mode |= FMODE_RANDOM;`
  Review: Low-risk line; verify in surrounding control flow.
- L02967 [LOCK|] `		spin_unlock(&filp->f_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02968 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02969 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02970 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02971 [NONE] `int ksmbd_vfs_zero_data(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02972 [NONE] `			loff_t off, loff_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02973 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02974 [NONE] `	/* MS-FSCC §2.3.67: fail if zero range overlaps a byte-range lock */`
  Review: Low-risk line; verify in surrounding control flow.
- L02975 [NONE] `	if (len > 0 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02976 [NONE] `	    check_lock_range(fp->filp, off, off + len - 1, WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L02977 [ERROR_PATH|] `		return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02979 [NONE] `	smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02980 [NONE] `	if (fp->f_ci->m_fattr & ATTR_SPARSE_FILE_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02981 [NONE] `		return vfs_fallocate(fp->filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02982 [NONE] `				     FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L02983 [NONE] `				     off, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02984 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02985 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02986 [NONE] `	 * For non-sparse files, clamp the zero range to the current file`
  Review: Low-risk line; verify in surrounding control flow.
- L02987 [NONE] `	 * size.  MS-FSCC 2.3.67 says SET_ZERO_DATA should not extend`
  Review: Low-risk line; verify in surrounding control flow.
- L02988 [NONE] `	 * the file.`
  Review: Low-risk line; verify in surrounding control flow.
- L02989 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02990 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02991 [NONE] `		loff_t fsize = i_size_read(file_inode(fp->filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02992 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02993 [NONE] `		if (off >= fsize)`
  Review: Low-risk line; verify in surrounding control flow.
- L02994 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02995 [NONE] `		if (off + len > fsize)`
  Review: Low-risk line; verify in surrounding control flow.
- L02996 [NONE] `			len = fsize - off;`
  Review: Low-risk line; verify in surrounding control flow.
- L02997 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02998 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02999 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03000 [NONE] `	 * Use a manual zero-fill instead of FALLOC_FL_ZERO_RANGE because`
  Review: Low-risk line; verify in surrounding control flow.
- L03001 [NONE] `	 * some filesystems (e.g. ext4) convert zero-range extents to`
  Review: Low-risk line; verify in surrounding control flow.
- L03002 [NONE] `	 * "unwritten" status, which SEEK_DATA then treats as holes.  That`
  Review: Low-risk line; verify in surrounding control flow.
- L03003 [NONE] `	 * breaks FSCTL_QUERY_ALLOCATED_RANGES for non-sparse files, where`
  Review: Low-risk line; verify in surrounding control flow.
- L03004 [NONE] `	 * Windows keeps the region allocated-but-zeroed.`
  Review: Low-risk line; verify in surrounding control flow.
- L03005 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03006 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L03007 [NONE] `		char *zbuf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03008 [NONE] `		loff_t pos = off;`
  Review: Low-risk line; verify in surrounding control flow.
- L03009 [NONE] `		loff_t end = off + len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03010 [NONE] `		int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03012 [MEM_BOUNDS|] `		zbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L03013 [NONE] `		if (!zbuf)`
  Review: Low-risk line; verify in surrounding control flow.
- L03014 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03016 [NONE] `		while (pos < end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03017 [NONE] `			size_t chunk = min_t(loff_t, end - pos,`
  Review: Low-risk line; verify in surrounding control flow.
- L03018 [NONE] `					     (loff_t)PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L03019 [NONE] `			ssize_t written;`
  Review: Low-risk line; verify in surrounding control flow.
- L03020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03021 [NONE] `			written = kernel_write(fp->filp, zbuf, chunk, &pos);`
  Review: Low-risk line; verify in surrounding control flow.
- L03022 [NONE] `			if (written < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03023 [NONE] `				ret = (int)written;`
  Review: Low-risk line; verify in surrounding control flow.
- L03024 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03025 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03026 [NONE] `			if (written == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03027 [NONE] `				ret = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L03028 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03029 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03030 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03031 [NONE] `		kfree(zbuf);`
  Review: Low-risk line; verify in surrounding control flow.
- L03032 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03033 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03034 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03036 [NONE] `int ksmbd_vfs_fqar_lseek(struct ksmbd_file *fp, loff_t start, loff_t length,`
  Review: Low-risk line; verify in surrounding control flow.
- L03037 [NONE] `			 struct file_allocated_range_buffer *ranges,`
  Review: Low-risk line; verify in surrounding control flow.
- L03038 [NONE] `			 unsigned int in_count, unsigned int *out_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L03039 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03040 [NONE] `	struct file *f = fp->filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L03041 [NONE] `	struct inode *inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03042 [NONE] `	loff_t maxbytes = (u64)inode->i_sb->s_maxbytes, end;`
  Review: Low-risk line; verify in surrounding control flow.
- L03043 [NONE] `	loff_t extent_start, extent_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L03044 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03046 [NONE] `	if (start > maxbytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L03047 [ERROR_PATH|] `		return -EFBIG;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03049 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03050 [NONE] `	 * Shrink request scope to what the fs can actually handle.`
  Review: Low-risk line; verify in surrounding control flow.
- L03051 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03052 [NONE] `	if (length > maxbytes || (maxbytes - length) < start)`
  Review: Low-risk line; verify in surrounding control flow.
- L03053 [NONE] `		length = maxbytes - start;`
  Review: Low-risk line; verify in surrounding control flow.
- L03054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03055 [NONE] `	if (start + length > inode->i_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L03056 [NONE] `		length = inode->i_size - start;`
  Review: Low-risk line; verify in surrounding control flow.
- L03057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03058 [NONE] `	*out_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03059 [NONE] `	end = start + length;`
  Review: Low-risk line; verify in surrounding control flow.
- L03060 [NONE] `	while (start < end && *out_count < in_count) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03061 [NONE] `		extent_start = vfs_llseek(f, start, SEEK_DATA);`
  Review: Low-risk line; verify in surrounding control flow.
- L03062 [NONE] `		if (extent_start < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03063 [NONE] `			if (extent_start != -ENXIO)`
  Review: Low-risk line; verify in surrounding control flow.
- L03064 [NONE] `				ret = (int)extent_start;`
  Review: Low-risk line; verify in surrounding control flow.
- L03065 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03066 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03068 [NONE] `		if (extent_start >= end)`
  Review: Low-risk line; verify in surrounding control flow.
- L03069 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03071 [NONE] `		extent_end = vfs_llseek(f, extent_start, SEEK_HOLE);`
  Review: Low-risk line; verify in surrounding control flow.
- L03072 [NONE] `		if (extent_end < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03073 [NONE] `			if (extent_end != -ENXIO)`
  Review: Low-risk line; verify in surrounding control flow.
- L03074 [NONE] `				ret = (int)extent_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L03075 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03076 [NONE] `		} else if (extent_start >= extent_end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03077 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03078 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03080 [NONE] `		ranges[*out_count].file_offset = cpu_to_le64(extent_start);`
  Review: Low-risk line; verify in surrounding control flow.
- L03081 [NONE] `		ranges[(*out_count)++].length =`
  Review: Low-risk line; verify in surrounding control flow.
- L03082 [NONE] `			cpu_to_le64(min(extent_end, end) - extent_start);`
  Review: Low-risk line; verify in surrounding control flow.
- L03083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03084 [NONE] `		start = extent_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L03085 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03087 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03088 [NONE] `	 * If we filled the output buffer and there might be more data ranges`
  Review: Low-risk line; verify in surrounding control flow.
- L03089 [NONE] `	 * remaining, signal truncation so the caller can return`
  Review: Low-risk line; verify in surrounding control flow.
- L03090 [PROTO_GATE|] `	 * STATUS_BUFFER_OVERFLOW per MS-FSCC.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03091 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03092 [NONE] `	if (!ret && *out_count == in_count && start < end) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03093 [NONE] `		extent_start = vfs_llseek(f, start, SEEK_DATA);`
  Review: Low-risk line; verify in surrounding control flow.
- L03094 [NONE] `		if (extent_start >= 0 && extent_start < end)`
  Review: Low-risk line; verify in surrounding control flow.
- L03095 [NONE] `			ret = -E2BIG;`
  Review: Low-risk line; verify in surrounding control flow.
- L03096 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03098 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03099 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03101 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03102 [NONE] `int ksmbd_vfs_remove_xattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L03103 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03104 [NONE] `int ksmbd_vfs_remove_xattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L03105 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03106 [NONE] `			   const struct path *path, char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03107 [NONE] `			   bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L03108 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03109 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03111 [NONE] `	if (get_write == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03112 [NONE] `		err = mnt_want_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L03113 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03114 [NONE] `			return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03115 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03117 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03118 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03119 [NONE] `	err = vfs_removexattr(idmap, path->dentry, attr_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03120 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03121 [NONE] `	err = vfs_removexattr(user_ns, path->dentry, attr_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03122 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03123 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03124 [NONE] `	err = vfs_removexattr(path->dentry, attr_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03125 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03126 [NONE] `	if (get_write == true)`
  Review: Low-risk line; verify in surrounding control flow.
- L03127 [NONE] `		mnt_drop_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L03128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03129 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03130 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03132 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03133 [NONE] `int ksmbd_vfs_unlink(struct file *filp)`
  Review: Low-risk line; verify in surrounding control flow.
- L03134 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03135 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03136 [NONE] `	struct dentry *dir, *dentry = filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L03137 [NONE] `	struct mnt_idmap *idmap = file_mnt_idmap(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03139 [NONE] `	err = mnt_want_write(filp->f_path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L03140 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03141 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03143 [NONE] `	dir = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03144 [NONE] `	err = ksmbd_vfs_lock_parent(dir, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03145 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03146 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03147 [NONE] `	dget(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03149 [NONE] `	if (S_ISDIR(d_inode(dentry)->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L03150 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03151 [NONE] `		err = vfs_rmdir(idmap, d_inode(dir), dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L03152 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03153 [NONE] `		err = vfs_rmdir(idmap, d_inode(dir), dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03154 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03155 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03156 [NONE] `		err = vfs_unlink(idmap, d_inode(dir), dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L03157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03158 [NONE] `	dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03159 [NONE] `	inode_unlock(d_inode(dir));`
  Review: Low-risk line; verify in surrounding control flow.
- L03160 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03161 [NONE] `		ksmbd_debug(VFS, "failed to delete, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L03162 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03163 [NONE] `	dput(dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L03164 [NONE] `	mnt_drop_write(filp->f_path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L03165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03166 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03167 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03168 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03169 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03170 [NONE] `int ksmbd_vfs_unlink(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L03171 [NONE] `		     struct dentry *dir, struct dentry *dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L03172 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03173 [NONE] `int ksmbd_vfs_unlink(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L03174 [NONE] `		     struct dentry *dir, struct dentry *dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L03175 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03176 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03177 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03178 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03179 [NONE] `	err = ksmbd_vfs_lock_parent(idmap, dir, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03180 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03181 [NONE] `	err = ksmbd_vfs_lock_parent(user_ns, dir, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03182 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03183 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03184 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03186 [NONE] `	dget(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03187 [NONE] `	if (S_ISDIR(d_inode(dentry)->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L03188 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03189 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03190 [NONE] `		err = vfs_rmdir(idmap, d_inode(dir), dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03191 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03192 [NONE] `		err = vfs_unlink(idmap, d_inode(dir), dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L03193 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03194 [NONE] `		err = vfs_rmdir(user_ns, d_inode(dir), dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03195 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03196 [NONE] `		err = vfs_unlink(user_ns, d_inode(dir), dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L03197 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03198 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03199 [NONE] `		err = vfs_rmdir(d_inode(dir), dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03200 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03201 [NONE] `		err = vfs_unlink(d_inode(dir), dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L03202 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03204 [NONE] `	dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03205 [NONE] `	inode_unlock(d_inode(dir));`
  Review: Low-risk line; verify in surrounding control flow.
- L03206 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03207 [NONE] `		ksmbd_debug(VFS, "failed to delete, err %d\n", err);`
  Review: Low-risk line; verify in surrounding control flow.
- L03208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03209 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03210 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03211 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03213 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L03214 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03215 [NONE] ` * ksmbd_vfs_dentry_open() - open a dentry and provide fid for it`
  Review: Low-risk line; verify in surrounding control flow.
- L03216 [NONE] ` * @work:	smb work ptr`
  Review: Low-risk line; verify in surrounding control flow.
- L03217 [NONE] ` * @path:	path of dentry to be opened`
  Review: Low-risk line; verify in surrounding control flow.
- L03218 [NONE] ` * @flags:	open flags`
  Review: Low-risk line; verify in surrounding control flow.
- L03219 [NONE] ` * @ret_id:	fid returned on this`
  Review: Low-risk line; verify in surrounding control flow.
- L03220 [NONE] ` * @option:	file access pattern options for fadvise`
  Review: Low-risk line; verify in surrounding control flow.
- L03221 [NONE] ` * @fexist:	file already present or not`
  Review: Low-risk line; verify in surrounding control flow.
- L03222 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03223 [NONE] ` * Return:	allocated struct ksmbd_file on success, otherwise error pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L03224 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03225 [NONE] `struct ksmbd_file *ksmbd_vfs_dentry_open(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L03226 [NONE] `					 const struct path *path, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L03227 [NONE] `					 __le32 option, int fexist)`
  Review: Low-risk line; verify in surrounding control flow.
- L03228 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03229 [NONE] `	struct file *filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L03230 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03231 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03233 [NONE] `	filp = dentry_open(path, flags | O_LARGEFILE, current_cred());`
  Review: Low-risk line; verify in surrounding control flow.
- L03234 [NONE] `	if (IS_ERR(filp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03235 [NONE] `		err = PTR_ERR(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03236 [ERROR_PATH|] `		pr_err("dentry open failed, err %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03237 [NONE] `		return ERR_PTR(err);`
  Review: Low-risk line; verify in surrounding control flow.
- L03238 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03240 [NONE] `	/* Post-open TOCTOU check: verify file is within share root */`
  Review: Low-risk line; verify in surrounding control flow.
- L03241 [NONE] `	if (!ksmbd_vfs_path_is_within_share(filp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03242 [NONE] `			&work->tcon->share_conf->vfs_path)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03243 [ERROR_PATH|] `		pr_err_ratelimited("path escapes share root\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03244 [NONE] `		fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03245 [NONE] `		return ERR_PTR(-EACCES);`
  Review: Low-risk line; verify in surrounding control flow.
- L03246 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03248 [NONE] `	ksmbd_vfs_set_fadvise(filp, option);`
  Review: Low-risk line; verify in surrounding control flow.
- L03249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03250 [NONE] `	fp = ksmbd_open_fd(work, filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03251 [NONE] `	if (IS_ERR(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03252 [NONE] `		fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03253 [NONE] `		err = PTR_ERR(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03254 [ERROR_PATH|] `		pr_err("id insert failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03255 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03256 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03258 [NONE] `	if (flags & O_TRUNC) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03259 [NONE] `		if (fexist)`
  Review: Low-risk line; verify in surrounding control flow.
- L03260 [NONE] `			smb_break_all_oplock(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03261 [NONE] `		err = vfs_truncate((struct path *)path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L03262 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03263 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03264 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03265 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L03266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03267 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03268 [NONE] `	if (!IS_ERR(fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L03269 [NONE] `		ksmbd_close_fd(work, fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L03270 [NONE] `	if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03271 [NONE] `		fp = ERR_PTR(err);`
  Review: Low-risk line; verify in surrounding control flow.
- L03272 [ERROR_PATH|] `		pr_err("err : %d\n", err);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03273 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03274 [NONE] `	return fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L03275 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03276 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03278 [NONE] `static inline bool ksmbd_is_dot_dotdot(const char *name, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03279 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03280 [NONE] `	return len && unlikely(name[0] == '.') &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03281 [NONE] `		(len == 1 || (len == 2 && name[1] == '.'));`
  Review: Low-risk line; verify in surrounding control flow.
- L03282 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03284 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03285 [NONE] `static bool __dir_empty(struct dir_context *ctx, const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L03286 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03287 [NONE] `static int __dir_empty(struct dir_context *ctx, const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L03288 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03289 [NONE] `		       loff_t offset, u64 ino, unsigned int d_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L03290 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03291 [NONE] `	struct ksmbd_readdir_data *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03293 [NONE] `	buf = container_of(ctx, struct ksmbd_readdir_data, ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L03294 [NONE] `	if (!ksmbd_is_dot_dotdot(name, namlen))`
  Review: Low-risk line; verify in surrounding control flow.
- L03295 [NONE] `		buf->dirent_count++;`
  Review: Low-risk line; verify in surrounding control flow.
- L03296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03297 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03298 [NONE] `	return !buf->dirent_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L03299 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03300 [NONE] `	if (buf->dirent_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L03301 [ERROR_PATH|] `		return -ENOTEMPTY;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03302 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03303 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03304 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03306 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03307 [NONE] ` * ksmbd_vfs_empty_dir() - check for empty directory`
  Review: Low-risk line; verify in surrounding control flow.
- L03308 [NONE] ` * @fp:	ksmbd file pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L03309 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03310 [NONE] ` * Return:	true if directory empty, otherwise false`
  Review: Low-risk line; verify in surrounding control flow.
- L03311 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03312 [NONE] `int ksmbd_vfs_empty_dir(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L03313 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03314 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03315 [NONE] `	struct ksmbd_readdir_data readdir_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L03316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03317 [NONE] `	memset(&readdir_data, 0, sizeof(struct ksmbd_readdir_data));`
  Review: Low-risk line; verify in surrounding control flow.
- L03318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03319 [NONE] `	set_ctx_actor(&readdir_data.ctx, __dir_empty);`
  Review: Low-risk line; verify in surrounding control flow.
- L03320 [NONE] `	readdir_data.dirent_count = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03322 [NONE] `	err = iterate_dir(fp->filp, &readdir_data.ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L03323 [NONE] `	if (readdir_data.dirent_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L03324 [NONE] `		err = -ENOTEMPTY;`
  Review: Low-risk line; verify in surrounding control flow.
- L03325 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03326 [NONE] `		err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03327 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03328 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03330 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03331 [NONE] `static bool __caseless_lookup(struct dir_context *ctx, const char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03332 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03333 [NONE] `static int __caseless_lookup(struct dir_context *ctx, const char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03334 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03335 [NONE] `			     int namlen, loff_t offset, u64 ino,`
  Review: Low-risk line; verify in surrounding control flow.
- L03336 [NONE] `			     unsigned int d_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L03337 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03338 [NONE] `	struct ksmbd_readdir_data *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03339 [NONE] `	int cmp = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03341 [NONE] `	buf = container_of(ctx, struct ksmbd_readdir_data, ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L03342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03343 [NONE] `	if (buf->used != namlen)`
  Review: Low-risk line; verify in surrounding control flow.
- L03344 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03345 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L03346 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03347 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03348 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03349 [NONE] `	if (IS_ENABLED(CONFIG_UNICODE) && buf->um) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03350 [NONE] `		const struct qstr q_buf = {.name = buf->private,`
  Review: Low-risk line; verify in surrounding control flow.
- L03351 [NONE] `					   .len = buf->used};`
  Review: Low-risk line; verify in surrounding control flow.
- L03352 [NONE] `		const struct qstr q_name = {.name = name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03353 [NONE] `					    .len = namlen};`
  Review: Low-risk line; verify in surrounding control flow.
- L03354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03355 [NONE] `		cmp = utf8_strncasecmp(buf->um, &q_buf, &q_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03356 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03357 [NONE] `	if (cmp < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03358 [NONE] `		cmp = strncasecmp((char *)buf->private, name, namlen);`
  Review: Low-risk line; verify in surrounding control flow.
- L03359 [NONE] `	if (!cmp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03360 [MEM_BOUNDS|] `		memcpy((char *)buf->private, name, buf->used);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L03361 [NONE] `		buf->dirent_count = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03362 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03363 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L03364 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03365 [ERROR_PATH|] `		return -EEXIST;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03366 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03367 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03368 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03369 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L03370 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03371 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03372 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03373 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03375 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03376 [NONE] ` * ksmbd_vfs_lookup_in_dir() - lookup a file in a directory`
  Review: Low-risk line; verify in surrounding control flow.
- L03377 [NONE] ` * @dir:	path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03378 [NONE] ` * @name:	filename to lookup`
  Review: Low-risk line; verify in surrounding control flow.
- L03379 [NONE] ` * @namelen:	filename length`
  Review: Low-risk line; verify in surrounding control flow.
- L03380 [NONE] ` * @um:		&struct unicode_map to use`
  Review: Low-risk line; verify in surrounding control flow.
- L03381 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03382 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03383 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03384 [NONE] `static int ksmbd_vfs_lookup_in_dir(const struct path *dir, char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03385 [NONE] `				   size_t namelen, struct unicode_map *um)`
  Review: Low-risk line; verify in surrounding control flow.
- L03386 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03387 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03388 [NONE] `	struct file *dfilp;`
  Review: Low-risk line; verify in surrounding control flow.
- L03389 [NONE] `	int flags = O_RDONLY | O_LARGEFILE;`
  Review: Low-risk line; verify in surrounding control flow.
- L03390 [NONE] `	struct ksmbd_readdir_data readdir_data = {`
  Review: Low-risk line; verify in surrounding control flow.
- L03391 [NONE] `		.ctx.actor	= __caseless_lookup,`
  Review: Low-risk line; verify in surrounding control flow.
- L03392 [NONE] `		.private	= name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03393 [NONE] `		.used		= namelen,`
  Review: Low-risk line; verify in surrounding control flow.
- L03394 [NONE] `		.dirent_count	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L03395 [NONE] `		.um		= um,`
  Review: Low-risk line; verify in surrounding control flow.
- L03396 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L03397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03398 [NONE] `	dfilp = dentry_open(dir, flags, current_cred());`
  Review: Low-risk line; verify in surrounding control flow.
- L03399 [NONE] `	if (IS_ERR(dfilp))`
  Review: Low-risk line; verify in surrounding control flow.
- L03400 [NONE] `		return PTR_ERR(dfilp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03402 [NONE] `	ret = iterate_dir(dfilp, &readdir_data.ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L03403 [NONE] `	if (readdir_data.dirent_count > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03404 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03405 [NONE] `	fput(dfilp);`
  Review: Low-risk line; verify in surrounding control flow.
- L03406 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03407 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03409 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03410 [NONE] `static`
  Review: Low-risk line; verify in surrounding control flow.
- L03411 [NONE] `int __ksmbd_vfs_kern_path(struct ksmbd_work *work, char *filepath,`
  Review: Low-risk line; verify in surrounding control flow.
- L03412 [NONE] `			  unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L03413 [NONE] `			  struct path *path, bool caseless, bool do_lock)`
  Review: Low-risk line; verify in surrounding control flow.
- L03414 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03415 [NONE] `	struct ksmbd_share_config *share_conf = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03416 [NONE] `	struct path parent_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L03417 [NONE] `	size_t path_len, remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03418 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03420 [NONE] `retry:`
  Review: Low-risk line; verify in surrounding control flow.
- L03421 [NONE] `	err = ksmbd_vfs_path_lookup(share_conf, filepath, flags, path, do_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03422 [NONE] `	if (!err || !caseless)`
  Review: Low-risk line; verify in surrounding control flow.
- L03423 [NONE] `		return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03425 [NONE] `	path_len = strlen(filepath);`
  Review: Low-risk line; verify in surrounding control flow.
- L03426 [NONE] `	remain_len = path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03427 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03428 [NONE] `	parent_path = share_conf->vfs_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L03429 [NONE] `	path_get(&parent_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03431 [NONE] `	while (d_can_lookup(parent_path.dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03432 [NONE] `		char *filename = filepath + path_len - remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03433 [NONE] `		char *next = strchrnul(filename, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L03434 [NONE] `		size_t filename_len = next - filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L03435 [NONE] `		bool is_last = !next[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L03436 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03437 [NONE] `		if (filename_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03438 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03440 [NONE] `		err = ksmbd_vfs_lookup_in_dir(&parent_path, filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L03441 [NONE] `					      filename_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03442 [NONE] `					      work->conn->um);`
  Review: Low-risk line; verify in surrounding control flow.
- L03443 [NONE] `		path_put(&parent_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03444 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03445 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03446 [NONE] `		if (is_last) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03447 [NONE] `			caseless = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L03448 [ERROR_PATH|] `			goto retry;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03449 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03450 [NONE] `		next[0] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L03451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03452 [NONE] `		err = vfs_path_lookup(share_conf->vfs_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L03453 [NONE] `				      share_conf->vfs_path.mnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L03454 [NONE] `				      filepath,`
  Review: Low-risk line; verify in surrounding control flow.
- L03455 [NONE] `				      flags | LOOKUP_BENEATH,`
  Review: Low-risk line; verify in surrounding control flow.
- L03456 [NONE] `				      &parent_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03457 [NONE] `		next[0] = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L03458 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03459 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03461 [NONE] `		remain_len -= filename_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03462 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03463 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03464 [NONE] `	err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03465 [NONE] `	path_put(&parent_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03466 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03467 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03468 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03469 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03470 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03471 [NONE] ` * ksmbd_vfs_kern_path() - lookup a file and get path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03472 [NONE] ` * @work:		work`
  Review: Low-risk line; verify in surrounding control flow.
- L03473 [NONE] ` * @filepath:		file path that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L03474 [NONE] ` * @flags:		lookup flags`
  Review: Low-risk line; verify in surrounding control flow.
- L03475 [NONE] ` * @path:		if lookup succeed, return path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03476 [NONE] ` * @caseless:	caseless filename lookup`
  Review: Low-risk line; verify in surrounding control flow.
- L03477 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03478 [NONE] ` * Perform the lookup, possibly crossing over any mount point.`
  Review: Low-risk line; verify in surrounding control flow.
- L03479 [NONE] ` * On return no locks will be held and write-access to filesystem`
  Review: Low-risk line; verify in surrounding control flow.
- L03480 [NONE] ` * won't have been checked.`
  Review: Low-risk line; verify in surrounding control flow.
- L03481 [NONE] ` * Return:	0 if file was found, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03482 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03483 [NONE] `int ksmbd_vfs_kern_path(struct ksmbd_work *work, char *filepath,`
  Review: Low-risk line; verify in surrounding control flow.
- L03484 [NONE] `			unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L03485 [NONE] `			struct path *path, bool caseless)`
  Review: Low-risk line; verify in surrounding control flow.
- L03486 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03487 [NONE] `	return __ksmbd_vfs_kern_path(work, filepath, flags, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L03488 [NONE] `				     caseless, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L03489 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03490 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03491 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03492 [NONE] ` * ksmbd_vfs_kern_path_locked() - lookup a file and get path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03493 [NONE] ` * @work:		work`
  Review: Low-risk line; verify in surrounding control flow.
- L03494 [NONE] ` * @filepath:		file path that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L03495 [NONE] ` * @flags:		lookup flags`
  Review: Low-risk line; verify in surrounding control flow.
- L03496 [NONE] ` * @path:		if lookup succeed, return path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03497 [NONE] ` * @caseless:	caseless filename lookup`
  Review: Low-risk line; verify in surrounding control flow.
- L03498 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03499 [NONE] ` * Perform the lookup, but don't cross over any mount point.`
  Review: Low-risk line; verify in surrounding control flow.
- L03500 [NONE] ` * On return the parent of path->dentry will be locked and write-access to`
  Review: Low-risk line; verify in surrounding control flow.
- L03501 [NONE] ` * filesystem will have been gained.`
  Review: Low-risk line; verify in surrounding control flow.
- L03502 [NONE] ` * Return:	0 on if file was found, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03503 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03504 [NONE] `int ksmbd_vfs_kern_path_locked(struct ksmbd_work *work, char *filepath,`
  Review: Low-risk line; verify in surrounding control flow.
- L03505 [NONE] `			       unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L03506 [NONE] `			       struct path *path, bool caseless)`
  Review: Low-risk line; verify in surrounding control flow.
- L03507 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03508 [NONE] `	return __ksmbd_vfs_kern_path(work, filepath, flags, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L03509 [NONE] `				     caseless, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L03510 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03512 [NONE] `void ksmbd_vfs_kern_path_unlock(const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L03513 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03514 [NONE] `	/* While lock is still held, ->d_parent is safe */`
  Review: Low-risk line; verify in surrounding control flow.
- L03515 [NONE] `	inode_unlock(d_inode(path->dentry->d_parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L03516 [NONE] `	mnt_drop_write(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L03517 [NONE] `	path_put(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03518 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03519 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03520 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03521 [NONE] ` * ksmbd_vfs_kern_path() - lookup a file and get path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03522 [NONE] ` * @name:	file path that is relative to share`
  Review: Low-risk line; verify in surrounding control flow.
- L03523 [NONE] ` * @flags:	lookup flags`
  Review: Low-risk line; verify in surrounding control flow.
- L03524 [NONE] ` * @path:	if lookup succeed, return path info`
  Review: Low-risk line; verify in surrounding control flow.
- L03525 [NONE] ` * @caseless:	caseless filename lookup`
  Review: Low-risk line; verify in surrounding control flow.
- L03526 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03527 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L03528 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03529 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03530 [NONE] `int ksmbd_vfs_kern_path(struct ksmbd_work *work, char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03531 [NONE] `			unsigned int flags, struct path *path, bool caseless)`
  Review: Low-risk line; verify in surrounding control flow.
- L03532 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03533 [NONE] `	struct ksmbd_share_config *share_conf = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03534 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03536 [NONE] `	flags |= LOOKUP_BENEATH;`
  Review: Low-risk line; verify in surrounding control flow.
- L03537 [NONE] `	err = vfs_path_lookup(share_conf->vfs_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L03538 [NONE] `			      share_conf->vfs_path.mnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L03539 [NONE] `			      name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03540 [NONE] `			      flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L03541 [NONE] `			      path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03542 [NONE] `	if (!err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03543 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03545 [NONE] `	if (caseless) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03546 [NONE] `		char *filepath;`
  Review: Low-risk line; verify in surrounding control flow.
- L03547 [NONE] `		struct path parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L03548 [NONE] `		size_t path_len, remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03549 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03550 [NONE] `		filepath = kstrdup(name, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L03551 [NONE] `		if (!filepath)`
  Review: Low-risk line; verify in surrounding control flow.
- L03552 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03554 [NONE] `		path_len = strlen(filepath);`
  Review: Low-risk line; verify in surrounding control flow.
- L03555 [NONE] `		remain_len = path_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03556 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03557 [NONE] `		parent = share_conf->vfs_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L03558 [NONE] `		path_get(&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03559 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03560 [NONE] `		while (d_can_lookup(parent.dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03561 [NONE] `			char *filename = filepath + path_len - remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03562 [NONE] `			char *next = strchrnul(filename, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L03563 [NONE] `			size_t filename_len = next - filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L03564 [NONE] `			bool is_last = !next[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L03565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03566 [NONE] `			if (filename_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03567 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03569 [NONE] `			err = ksmbd_vfs_lookup_in_dir(&parent, filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L03570 [NONE] `						      filename_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03571 [NONE] `						      work->conn->um);`
  Review: Low-risk line; verify in surrounding control flow.
- L03572 [NONE] `			path_put(&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03573 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03574 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03575 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03576 [NONE] `			next[0] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L03577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03578 [NONE] `			err = vfs_path_lookup(share_conf->vfs_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L03579 [NONE] `					      share_conf->vfs_path.mnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L03580 [NONE] `					      filepath,`
  Review: Low-risk line; verify in surrounding control flow.
- L03581 [NONE] `					      flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L03582 [NONE] `					      &parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03583 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03584 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03585 [NONE] `			else if (is_last) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03586 [NONE] `				*path = parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L03587 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03588 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03590 [NONE] `			next[0] = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L03591 [NONE] `			remain_len -= filename_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03592 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03594 [NONE] `		path_put(&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03595 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03596 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03597 [NONE] `		kfree(filepath);`
  Review: Low-risk line; verify in surrounding control flow.
- L03598 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03599 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03600 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03601 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03602 [NONE] `int ksmbd_vfs_kern_path(struct ksmbd_work *work, char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03603 [NONE] `			unsigned int flags, struct path *path, bool caseless)`
  Review: Low-risk line; verify in surrounding control flow.
- L03604 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03605 [NONE] `	char *abs_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L03606 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03608 [NONE] `	abs_name = convert_to_unix_name(work->tcon->share_conf, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03609 [NONE] `	if (IS_ERR(abs_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L03610 [NONE] `		return PTR_ERR(abs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03612 [NONE] `	err = kern_path(abs_name, flags | LOOKUP_BENEATH, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L03613 [NONE] `	if (!err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03614 [NONE] `		err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03615 [ERROR_PATH|] `		goto free_abs_name;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03616 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03617 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03618 [NONE] `	if (caseless) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03619 [NONE] `		char *filepath;`
  Review: Low-risk line; verify in surrounding control flow.
- L03620 [NONE] `		struct path parent;`
  Review: Low-risk line; verify in surrounding control flow.
- L03621 [NONE] `		size_t path_len, remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03623 [NONE] `		filepath = kstrdup(abs_name, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L03624 [NONE] `		if (!filepath) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03625 [NONE] `			err = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L03626 [ERROR_PATH|] `			goto free_abs_name;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03627 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03629 [NONE] `		path_len = strlen(filepath);`
  Review: Low-risk line; verify in surrounding control flow.
- L03630 [NONE] `		remain_len = path_len - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03632 [NONE] `		err = kern_path("/", flags, &parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03633 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03634 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03636 [NONE] `		while (d_can_lookup(parent.dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03637 [NONE] `			char *filename = filepath + path_len - remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03638 [NONE] `			char *next = strchrnul(filename, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L03639 [NONE] `			size_t filename_len = next - filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L03640 [NONE] `			bool is_last = !next[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L03641 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03642 [NONE] `			if (filename_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03643 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03644 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03645 [NONE] `			err = ksmbd_vfs_lookup_in_dir(&parent, filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L03646 [NONE] `						      filename_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03647 [NONE] `						      work->conn->um);`
  Review: Low-risk line; verify in surrounding control flow.
- L03648 [NONE] `			if (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03649 [NONE] `				path_put(&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03650 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03651 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03652 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03653 [NONE] `			path_put(&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03654 [NONE] `			next[0] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L03655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03656 [NONE] `			err = kern_path(filepath,`
  Review: Low-risk line; verify in surrounding control flow.
- L03657 [NONE] `					flags | LOOKUP_BENEATH,`
  Review: Low-risk line; verify in surrounding control flow.
- L03658 [NONE] `					&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03659 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L03660 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03661 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03662 [NONE] `			if (is_last) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03663 [NONE] `				path->mnt = parent.mnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L03664 [NONE] `				path->dentry = parent.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L03665 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03666 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03668 [NONE] `			next[0] = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L03669 [NONE] `			remain_len -= filename_len + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03670 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03672 [NONE] `		path_put(&parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L03673 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03674 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03675 [NONE] `		kfree(filepath);`
  Review: Low-risk line; verify in surrounding control flow.
- L03676 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03677 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03678 [NONE] `free_abs_name:`
  Review: Low-risk line; verify in surrounding control flow.
- L03679 [NONE] `	kfree(abs_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03680 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L03681 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03682 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03683 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03685 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03686 [NONE] ` * ksmbd_vfs_init_kstat() - convert unix stat information to smb stat format`
  Review: Low-risk line; verify in surrounding control flow.
- L03687 [NONE] ` * @p:          destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L03688 [NONE] ` * @ksmbd_kstat:      ksmbd kstat wrapper`
  Review: Low-risk line; verify in surrounding control flow.
- L03689 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03690 [NONE] ` * Returns: pointer to the converted &struct file_directory_info`
  Review: Low-risk line; verify in surrounding control flow.
- L03691 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03692 [NONE] `void *ksmbd_vfs_init_kstat(char **p, struct ksmbd_kstat *ksmbd_kstat)`
  Review: Low-risk line; verify in surrounding control flow.
- L03693 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03694 [NONE] `	struct file_directory_info *info = (struct file_directory_info *)(*p);`
  Review: Low-risk line; verify in surrounding control flow.
- L03695 [NONE] `	struct kstat *kstat = ksmbd_kstat->kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L03696 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L03697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03698 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03699 [NONE] `	 * FileIndex is populated during the first (reservation) pass in`
  Review: Low-risk line; verify in surrounding control flow.
- L03700 [NONE] `	 * reserve_populate_dentry() from the dir_context offset value.`
  Review: Low-risk line; verify in surrounding control flow.
- L03701 [NONE] `	 * Do not zero it here — preserve the value set by that pass so that`
  Review: Low-risk line; verify in surrounding control flow.
- L03702 [PROTO_GATE|] `	 * clients using SMB2_INDEX_SPECIFIED get correct resume positions.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L03703 [NONE] `	 * MS-FSCC §2.4.13: FileIndex is the file-system-specific position.`
  Review: Low-risk line; verify in surrounding control flow.
- L03704 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03705 [NONE] `	info->CreationTime = cpu_to_le64(ksmbd_kstat->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L03706 [NONE] `	time = ksmbd_UnixTimeToNT(kstat->atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L03707 [NONE] `	info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L03708 [NONE] `	time = ksmbd_UnixTimeToNT(kstat->mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L03709 [NONE] `	info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L03710 [NONE] `	time = ksmbd_UnixTimeToNT(kstat->ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L03711 [NONE] `	info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L03712 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03713 [NONE] `	if (ksmbd_kstat->file_attributes & ATTR_DIRECTORY_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03714 [NONE] `		info->EndOfFile = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03715 [NONE] `		info->AllocationSize = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03716 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03717 [NONE] `		info->EndOfFile = cpu_to_le64(kstat->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L03718 [NONE] `		info->AllocationSize = cpu_to_le64(kstat->blocks << 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L03719 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03720 [NONE] `	info->ExtFileAttributes = ksmbd_kstat->file_attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L03721 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03722 [NONE] `	return info;`
  Review: Low-risk line; verify in surrounding control flow.
- L03723 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03724 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03725 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03726 [NONE] `int ksmbd_vfs_fill_dentry_attrs(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L03727 [NONE] `				struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L03728 [NONE] `				struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L03729 [NONE] `				struct ksmbd_kstat *ksmbd_kstat)`
  Review: Low-risk line; verify in surrounding control flow.
- L03730 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03731 [NONE] `int ksmbd_vfs_fill_dentry_attrs(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L03732 [NONE] `				struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L03733 [NONE] `				struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L03734 [NONE] `				struct ksmbd_kstat *ksmbd_kstat)`
  Review: Low-risk line; verify in surrounding control flow.
- L03735 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03736 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03737 [NONE] `	struct ksmbd_share_config *share_conf = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03738 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L03739 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03740 [NONE] `	struct path path = {`
  Review: Low-risk line; verify in surrounding control flow.
- L03741 [NONE] `		.mnt = share_conf->vfs_path.mnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L03742 [NONE] `		.dentry = dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L03743 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L03744 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03745 [NONE] `	rc = vfs_getattr(&path, ksmbd_kstat->kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L03746 [NONE] `			 STATX_BASIC_STATS | STATX_BTIME,`
  Review: Low-risk line; verify in surrounding control flow.
- L03747 [NONE] `			 AT_STATX_SYNC_AS_STAT);`
  Review: Low-risk line; verify in surrounding control flow.
- L03748 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L03749 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L03750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03751 [NONE] `	time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L03752 [NONE] `	ksmbd_kstat->create_time = time;`
  Review: Low-risk line; verify in surrounding control flow.
- L03753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03754 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03755 [NONE] `	 * set default value for the case that store dos attributes is not yes`
  Review: Low-risk line; verify in surrounding control flow.
- L03756 [NONE] `	 * or that acl is disable in server's filesystem and the config is yes.`
  Review: Low-risk line; verify in surrounding control flow.
- L03757 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03758 [NONE] `	if (S_ISDIR(ksmbd_kstat->kstat->mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L03759 [NONE] `		ksmbd_kstat->file_attributes = ATTR_DIRECTORY_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L03760 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03761 [NONE] `		ksmbd_kstat->file_attributes = ATTR_ARCHIVE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L03762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03763 [NONE] `	if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L03764 [NONE] `				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03765 [NONE] `		struct xattr_dos_attrib da;`
  Review: Low-risk line; verify in surrounding control flow.
- L03766 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03767 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03768 [NONE] `		rc = ksmbd_vfs_get_dos_attrib_xattr(idmap, dentry, &da);`
  Review: Low-risk line; verify in surrounding control flow.
- L03769 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03770 [NONE] `		rc = ksmbd_vfs_get_dos_attrib_xattr(user_ns, dentry, &da);`
  Review: Low-risk line; verify in surrounding control flow.
- L03771 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03772 [NONE] `		if (rc > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03773 [NONE] `			ksmbd_kstat->file_attributes = cpu_to_le32(da.attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L03774 [NONE] `			ksmbd_kstat->create_time = da.create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L03775 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03776 [NONE] `			ksmbd_debug(VFS, "fail to load dos attribute.\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03777 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03778 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03780 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03781 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03783 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03784 [NONE] `ssize_t ksmbd_vfs_casexattr_len(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L03785 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03786 [NONE] `ssize_t ksmbd_vfs_casexattr_len(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L03787 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03788 [NONE] `				struct dentry *dentry, char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03789 [NONE] `				int attr_name_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03790 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03791 [NONE] `	char *name, *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03792 [NONE] `	ssize_t value_len = -ENOENT, xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03793 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03794 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L03795 [NONE] `	if (xattr_list_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03796 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03798 [NONE] `	for (name = xattr_list; name - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03799 [NONE] `			name += strlen(name) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03800 [NONE] `		ksmbd_debug(VFS, "%s, len %zd\n", name, strlen(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L03801 [NONE] `		if (strncasecmp(attr_name, name, attr_name_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L03802 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L03803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03804 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03805 [NONE] `		value_len = ksmbd_vfs_xattr_len(idmap, dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03806 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03807 [NONE] `		value_len = ksmbd_vfs_xattr_len(user_ns, dentry, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L03808 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03809 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03810 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03812 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L03813 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L03814 [NONE] `	return value_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03815 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03816 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03817 [NONE] `int ksmbd_vfs_xattr_stream_name(char *stream_name, char **xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L03818 [NONE] `				size_t *xattr_stream_name_size, int s_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L03819 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03820 [NONE] `	char *type, *buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03821 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03822 [NONE] `	if (s_type == DIR_STREAM)`
  Review: Low-risk line; verify in surrounding control flow.
- L03823 [NONE] `		type = ":$INDEX_ALLOCATION";`
  Review: Low-risk line; verify in surrounding control flow.
- L03824 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L03825 [NONE] `		type = ":$DATA";`
  Review: Low-risk line; verify in surrounding control flow.
- L03826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03827 [NONE] `	buf = kasprintf(KSMBD_DEFAULT_GFP, "%s%s%s",`
  Review: Low-risk line; verify in surrounding control flow.
- L03828 [NONE] `			XATTR_NAME_STREAM, stream_name,	type);`
  Review: Low-risk line; verify in surrounding control flow.
- L03829 [NONE] `	if (!buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L03830 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03831 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03832 [NONE] `	*xattr_stream_name = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L03833 [NONE] `	*xattr_stream_name_size = strlen(buf) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03835 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03836 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03837 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03838 [NONE] `int ksmbd_vfs_copy_file_ranges(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L03839 [NONE] `			       struct ksmbd_file *src_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03840 [NONE] `			       struct ksmbd_file *dst_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L03841 [NONE] `			       struct srv_copychunk *chunks,`
  Review: Low-risk line; verify in surrounding control flow.
- L03842 [NONE] `			       unsigned int chunk_count,`
  Review: Low-risk line; verify in surrounding control flow.
- L03843 [NONE] `			       unsigned int *chunk_count_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L03844 [NONE] `			       unsigned int *chunk_size_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L03845 [NONE] `			       loff_t *total_size_written)`
  Review: Low-risk line; verify in surrounding control flow.
- L03846 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03847 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L03848 [NONE] `	loff_t src_off, dst_off, src_file_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L03849 [NONE] `	size_t len;`
  Review: Low-risk line; verify in surrounding control flow.
- L03850 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03852 [NONE] `	*chunk_count_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03853 [NONE] `	*chunk_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03854 [NONE] `	*total_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03856 [NONE] `	if (!(src_fp->daccess & (FILE_READ_DATA_LE | FILE_EXECUTE_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03857 [ERROR_PATH|] `		pr_err("no right to read(%pD)\n", src_fp->filp);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03858 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03859 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03860 [NONE] `	if (!(dst_fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03861 [ERROR_PATH|] `		pr_err("no right to write(%pD)\n", dst_fp->filp);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03862 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03863 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03864 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03865 [NONE] `	if (ksmbd_stream_fd(src_fp) || ksmbd_stream_fd(dst_fp))`
  Review: Low-risk line; verify in surrounding control flow.
- L03866 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03867 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03868 [NONE] `	smb_break_all_levII_oplock(work, dst_fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L03869 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03870 [NONE] `	if (!work->tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03871 [NONE] `		for (i = 0; i < chunk_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03872 [NONE] `			src_off = le64_to_cpu(chunks[i].SourceOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03873 [NONE] `			dst_off = le64_to_cpu(chunks[i].TargetOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03874 [NONE] `			len = le32_to_cpu(chunks[i].Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L03875 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03876 [NONE] `			if (check_lock_range(src_fp->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03877 [NONE] `					     src_off + len - 1, READ))`
  Review: Low-risk line; verify in surrounding control flow.
- L03878 [ERROR_PATH|] `				return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03879 [NONE] `			if (check_lock_range(dst_fp->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03880 [NONE] `					     dst_off + len - 1, WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L03881 [ERROR_PATH|] `				return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03882 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03883 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03885 [NONE] `	src_file_size = i_size_read(file_inode(src_fp->filp));`
  Review: Low-risk line; verify in surrounding control flow.
- L03886 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03887 [NONE] `	for (i = 0; i < chunk_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03888 [NONE] `		src_off = le64_to_cpu(chunks[i].SourceOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03889 [NONE] `		dst_off = le64_to_cpu(chunks[i].TargetOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L03890 [NONE] `		len = le32_to_cpu(chunks[i].Length);`
  Review: Low-risk line; verify in surrounding control flow.
- L03891 [NONE] `		*chunk_size_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03893 [NONE] `		if (src_off + len > src_file_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03894 [NONE] `			ret = -E2BIG;`
  Review: Low-risk line; verify in surrounding control flow.
- L03895 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03896 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03897 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03898 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03899 [NONE] `		 * vfs_copy_file_range does not allow overlapped copying`
  Review: Low-risk line; verify in surrounding control flow.
- L03900 [NONE] `		 * within the same file.  Use a bounce buffer to handle`
  Review: Low-risk line; verify in surrounding control flow.
- L03901 [NONE] `		 * overlapping same-inode copies safely.`
  Review: Low-risk line; verify in surrounding control flow.
- L03902 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03903 [NONE] `		if (file_inode(src_fp->filp) == file_inode(dst_fp->filp) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03904 [NONE] `				dst_off + len > src_off &&`
  Review: Low-risk line; verify in surrounding control flow.
- L03905 [NONE] `				dst_off < src_off + len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03906 [NONE] `			void *bounce;`
  Review: Low-risk line; verify in surrounding control flow.
- L03907 [NONE] `			loff_t rd_off = src_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L03908 [NONE] `			loff_t wr_off = dst_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L03909 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03910 [MEM_BOUNDS|] `			bounce = kvmalloc(len, GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L03911 [NONE] `			if (!bounce) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03912 [NONE] `				ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L03913 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03914 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03915 [NONE] `			ret = kernel_read(src_fp->filp, bounce, len, &rd_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L03916 [NONE] `			if (ret == len)`
  Review: Low-risk line; verify in surrounding control flow.
- L03917 [NONE] `				ret = kernel_write(dst_fp->filp, bounce, len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03918 [NONE] `						   &wr_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L03919 [NONE] `			kvfree(bounce);`
  Review: Low-risk line; verify in surrounding control flow.
- L03920 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03921 [NONE] `			ret = vfs_copy_file_range(src_fp->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03922 [NONE] `						  dst_fp->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03923 [NONE] `						  len, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L03924 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03925 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03926 [NONE] `		if (ret == -EOPNOTSUPP || ret == -EXDEV)`
  Review: Low-risk line; verify in surrounding control flow.
- L03927 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03928 [NONE] `			ret = vfs_copy_file_range(src_fp->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03929 [NONE] `						  dst_fp->filp, dst_off, len,`
  Review: Low-risk line; verify in surrounding control flow.
- L03930 [NONE] `						  COPY_FILE_SPLICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L03931 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03932 [NONE] `			ret = generic_copy_file_range(src_fp->filp, src_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03933 [NONE] `						      dst_fp->filp, dst_off,`
  Review: Low-risk line; verify in surrounding control flow.
- L03934 [NONE] `						      len, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L03935 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03936 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03937 [NONE] `		if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03938 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L03939 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03940 [NONE] `		*chunk_count_written += 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L03941 [NONE] `		*chunk_size_written = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03942 [NONE] `		*total_size_written += ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03943 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03945 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03946 [NONE] `	 * If some chunks were successfully copied before the error,`
  Review: Low-risk line; verify in surrounding control flow.
- L03947 [NONE] `	 * report partial progress so the caller can return accurate`
  Review: Low-risk line; verify in surrounding control flow.
- L03948 [NONE] `	 * copychunk response fields to the client.`
  Review: Low-risk line; verify in surrounding control flow.
- L03949 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03950 [NONE] `	if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03951 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03952 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03953 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03954 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03955 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03956 [NONE] `void ksmbd_vfs_posix_lock_wait(struct file_lock *flock)`
  Review: Low-risk line; verify in surrounding control flow.
- L03957 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03958 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L03959 [NONE] `	 * Use interruptible wait to avoid D-state if the lock holder`
  Review: Low-risk line; verify in surrounding control flow.
- L03960 [NONE] `	 * disconnects.  The caller (smb2_lock) already handles retry`
  Review: Low-risk line; verify in surrounding control flow.
- L03961 [NONE] `	 * on signal/timeout.`
  Review: Low-risk line; verify in surrounding control flow.
- L03962 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L03963 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03964 [WAIT_LOOP|] `	wait_event_interruptible(flock->c.flc_wait, !flock->c.flc_blocker);`
  Review: Bounded wait and cancellation path must be guaranteed.
- L03965 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03966 [WAIT_LOOP|] `	wait_event_interruptible(flock->fl_wait, !flock->fl_blocker);`
  Review: Bounded wait and cancellation path must be guaranteed.
- L03967 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03968 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03969 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03970 [NONE] `int ksmbd_vfs_posix_lock_wait_timeout(struct file_lock *flock, long timeout)`
  Review: Low-risk line; verify in surrounding control flow.
- L03971 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03972 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03973 [WAIT_LOOP|] `	return wait_event_interruptible_timeout(flock->c.flc_wait,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L03974 [NONE] `						!flock->c.flc_blocker,`
  Review: Low-risk line; verify in surrounding control flow.
- L03975 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03976 [WAIT_LOOP|] `	return wait_event_interruptible_timeout(flock->fl_wait,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L03977 [NONE] `						!flock->fl_blocker,`
  Review: Low-risk line; verify in surrounding control flow.
- L03978 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03979 [NONE] `						timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L03980 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03981 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03982 [NONE] `void ksmbd_vfs_posix_lock_unblock(struct file_lock *flock)`
  Review: Low-risk line; verify in surrounding control flow.
- L03983 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03984 [NONE] `	locks_delete_block(flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03985 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03986 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03987 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03988 [NONE] `int ksmbd_vfs_set_init_posix_acl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L03989 [NONE] `				 const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L03990 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03991 [NONE] `int ksmbd_vfs_set_init_posix_acl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L03992 [NONE] `				 const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L03993 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03994 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03995 [NONE] `	struct posix_acl_state acl_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L03996 [NONE] `	struct posix_acl *acls;`
  Review: Low-risk line; verify in surrounding control flow.
- L03997 [NONE] `	struct dentry *dentry = path->dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L03998 [NONE] `	struct inode *inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L03999 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L04000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04001 [NONE] `	if (!IS_ENABLED(CONFIG_FS_POSIX_ACL))`
  Review: Low-risk line; verify in surrounding control flow.
- L04002 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L04003 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04004 [NONE] `	ksmbd_debug(SMB, "Set posix acls\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L04005 [NONE] `	rc = init_acl_state(&acl_state, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L04006 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L04007 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L04008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04009 [NONE] `	/* Set default owner group */`
  Review: Low-risk line; verify in surrounding control flow.
- L04010 [NONE] `	acl_state.owner.allow = (inode->i_mode & 0700) >> 6;`
  Review: Low-risk line; verify in surrounding control flow.
- L04011 [NONE] `	acl_state.group.allow = (inode->i_mode & 0070) >> 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L04012 [NONE] `	acl_state.other.allow = inode->i_mode & 0007;`
  Review: Low-risk line; verify in surrounding control flow.
- L04013 [NONE] `	acl_state.users->aces[acl_state.users->n].uid = inode->i_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L04014 [NONE] `	acl_state.users->aces[acl_state.users->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L04015 [NONE] `		acl_state.owner.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L04016 [NONE] `	acl_state.groups->aces[acl_state.groups->n].gid = inode->i_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L04017 [NONE] `	acl_state.groups->aces[acl_state.groups->n++].perms.allow =`
  Review: Low-risk line; verify in surrounding control flow.
- L04018 [NONE] `		acl_state.group.allow;`
  Review: Low-risk line; verify in surrounding control flow.
- L04019 [NONE] `	acl_state.mask.allow = 0x07;`
  Review: Low-risk line; verify in surrounding control flow.
- L04020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04021 [NONE] `	acls = posix_acl_alloc(6, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L04022 [NONE] `	if (!acls) {`
  Review: Low-risk line; verify in surrounding control flow.
- L04023 [NONE] `		free_acl_state(&acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L04024 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L04025 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L04026 [NONE] `	posix_state_to_acl(&acl_state, acls->a_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L04027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04028 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04029 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04030 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04031 [NONE] `	rc = set_posix_acl(idmap, dentry, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04032 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04033 [NONE] `	rc = set_posix_acl(user_ns, dentry, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04034 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04035 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04036 [NONE] `	rc = set_posix_acl(user_ns, inode, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04037 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04038 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04039 [NONE] `	rc = set_posix_acl(inode, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04040 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04041 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04042 [NONE] `		ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L04043 [NONE] `			    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L04044 [NONE] `	else if (S_ISDIR(inode->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L04045 [NONE] `		posix_state_to_acl(&acl_state, acls->a_entries);`
  Review: Low-risk line; verify in surrounding control flow.
- L04046 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04047 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04048 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04049 [NONE] `		rc = set_posix_acl(idmap, dentry, ACL_TYPE_DEFAULT, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04050 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04051 [NONE] `		rc = set_posix_acl(user_ns, dentry, ACL_TYPE_DEFAULT, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04052 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04053 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04054 [NONE] `		rc = set_posix_acl(user_ns, inode, ACL_TYPE_DEFAULT, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04055 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04056 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04057 [NONE] `		rc = set_posix_acl(inode, ACL_TYPE_DEFAULT, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04058 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04059 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04060 [NONE] `			ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L04061 [NONE] `				    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L04062 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L04063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04064 [NONE] `	free_acl_state(&acl_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L04065 [NONE] `	posix_acl_release(acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04066 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L04067 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L04068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04069 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04070 [NONE] `int ksmbd_vfs_inherit_posix_acl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L04071 [NONE] `				const struct path *path, struct inode *parent_inode)`
  Review: Low-risk line; verify in surrounding control flow.
- L04072 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04073 [NONE] `int ksmbd_vfs_inherit_posix_acl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L04074 [NONE] `				const struct path *path, struct inode *parent_inode)`
  Review: Low-risk line; verify in surrounding control flow.
- L04075 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04076 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L04077 [NONE] `	struct posix_acl *acls;`
  Review: Low-risk line; verify in surrounding control flow.
- L04078 [NONE] `	struct posix_acl_entry *pace;`
  Review: Low-risk line; verify in surrounding control flow.
- L04079 [NONE] `	struct dentry *dentry = path->dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L04080 [NONE] `	struct inode *inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L04081 [NONE] `	int rc, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L04082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04083 [NONE] `	if (!IS_ENABLED(CONFIG_FS_POSIX_ACL))`
  Review: Low-risk line; verify in surrounding control flow.
- L04084 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L04085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04086 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04087 [NONE] `	acls = get_inode_acl(parent_inode, ACL_TYPE_DEFAULT);`
  Review: Low-risk line; verify in surrounding control flow.
- L04088 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04089 [NONE] `	acls = get_acl(parent_inode, ACL_TYPE_DEFAULT);`
  Review: Low-risk line; verify in surrounding control flow.
- L04090 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04091 [NONE] `	if (IS_ERR_OR_NULL(acls))`
  Review: Low-risk line; verify in surrounding control flow.
- L04092 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L04093 [NONE] `	pace = acls->a_entries;`
  Review: Low-risk line; verify in surrounding control flow.
- L04094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04095 [NONE] `	for (i = 0; i < acls->a_count; i++, pace++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L04096 [NONE] `		if (pace->e_tag == ACL_MASK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L04097 [NONE] `			pace->e_perm = 0x07;`
  Review: Low-risk line; verify in surrounding control flow.
- L04098 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L04099 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L04100 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L04101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04102 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04103 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04104 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04105 [NONE] `	rc = set_posix_acl(idmap, dentry, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04106 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04107 [NONE] `	rc = set_posix_acl(user_ns, dentry, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04108 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04109 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04110 [NONE] `	rc = set_posix_acl(user_ns, inode, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04111 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04112 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04113 [NONE] `	rc = set_posix_acl(inode, ACL_TYPE_ACCESS, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04114 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04115 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04116 [NONE] `		ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_ACCESS) failed, rc : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L04117 [NONE] `			    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L04118 [NONE] `	if (S_ISDIR(inode->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L04119 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04120 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04121 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04122 [NONE] `		rc = set_posix_acl(idmap, dentry, ACL_TYPE_DEFAULT,`
  Review: Low-risk line; verify in surrounding control flow.
- L04123 [NONE] `				   acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04124 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04125 [NONE] `		rc = set_posix_acl(user_ns, dentry, ACL_TYPE_DEFAULT,`
  Review: Low-risk line; verify in surrounding control flow.
- L04126 [NONE] `				   acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04127 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04128 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04129 [NONE] `		rc = set_posix_acl(user_ns, inode, ACL_TYPE_DEFAULT,`
  Review: Low-risk line; verify in surrounding control flow.
- L04130 [NONE] `				   acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04131 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04132 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L04133 [NONE] `		rc = set_posix_acl(inode, ACL_TYPE_DEFAULT, acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04134 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L04135 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L04136 [NONE] `			ksmbd_debug(SMB, "Set posix acl(ACL_TYPE_DEFAULT) failed, rc : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L04137 [NONE] `				    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L04138 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L04139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L04140 [NONE] `	posix_acl_release(acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L04141 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L04142 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
