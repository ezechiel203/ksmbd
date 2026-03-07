# Line-by-line Review: src/include/core/compat.h

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `#ifndef __KSMBD_COMPAT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] `#define __KSMBD_COMPAT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` * LOOKUP_BENEATH was added in Linux 5.6.  Define as no-op on older`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` * kernels so callers can unconditionally OR the flag into lookup_flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#ifndef LOOKUP_BENEATH`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#define LOOKUP_BENEATH 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * disable_work_sync() was introduced in Linux 6.13.`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * On older kernels, fall back to cancel_work_sync().`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `static inline bool disable_work_sync(struct work_struct *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	return cancel_work_sync(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `struct dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `struct inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `struct path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct xattr_dos_attrib;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/* linux vfs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `int compat_inode_permission(struct path *path, struct inode *inode, int mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `/* ksmbd vfs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `ssize_t compat_ksmbd_vfs_getxattr(struct path *path, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `				  char *xattr_name, char **xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `int compat_ksmbd_vfs_get_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `					  struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `					  struct xattr_dos_attrib *da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `int compat_ksmbd_vfs_set_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `					  struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `					  bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
