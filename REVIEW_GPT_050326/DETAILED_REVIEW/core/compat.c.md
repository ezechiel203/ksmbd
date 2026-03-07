# Line-by-line Review: src/core/compat.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef STATX_BASIC_STATS`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define STATX_BASIC_STATS 0x000007ffU`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `int compat_inode_permission(struct path *path, struct inode *inode, int mask)`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `	return inode_permission(mnt_idmap(path->mnt), inode, mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `int compat_ksmbd_vfs_get_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `					  struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `					  struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	return ksmbd_vfs_get_dos_attrib_xattr(mnt_idmap(path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `					      da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `int compat_ksmbd_vfs_set_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `					  struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `					  bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	return ksmbd_vfs_set_dos_attrib_xattr(mnt_idmap(path->mnt), path, da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `			get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `ssize_t compat_ksmbd_vfs_getxattr(struct path *path, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `				  char *xattr_name, char **xattr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	return ksmbd_vfs_getxattr(mnt_idmap(path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `				  xattr_name, xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `int compat_inode_permission(struct path *path, struct inode *inode, int mask)`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	return inode_permission(mnt_idmap(path->mnt), inode, mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `int compat_ksmbd_vfs_get_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `					  struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `					  struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	return ksmbd_vfs_get_dos_attrib_xattr(mnt_idmap(path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `					      da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `int compat_ksmbd_vfs_set_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `					  struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `					  bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	return ksmbd_vfs_set_dos_attrib_xattr(mnt_idmap(path->mnt), path, da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `			get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `ssize_t compat_ksmbd_vfs_getxattr(struct path *path, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `				  char *xattr_name, char **xattr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	return ksmbd_vfs_getxattr(mnt_idmap(path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `				  xattr_name, xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `int compat_inode_permission(struct path *path, struct inode *inode, int mask)`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	return inode_permission(mnt_user_ns(path->mnt), inode, mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `int compat_ksmbd_vfs_get_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `					  struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `					  struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	return ksmbd_vfs_get_dos_attrib_xattr(mnt_user_ns(path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `					      da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `int compat_ksmbd_vfs_set_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `					  struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `					  bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	return ksmbd_vfs_set_dos_attrib_xattr(mnt_user_ns(path->mnt), path, da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `			get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `ssize_t compat_ksmbd_vfs_getxattr(struct path *path, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `				  char *xattr_name, char **xattr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	return ksmbd_vfs_getxattr(mnt_user_ns(path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `				  xattr_name, xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `int compat_inode_permission(struct path *path, struct inode *inode, int mask)`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	return inode_permission(inode, mask);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `int compat_ksmbd_vfs_get_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `					  struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `					  struct xattr_dos_attrib *da)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	return ksmbd_vfs_get_dos_attrib_xattr(&init_user_ns, dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `					      da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `int compat_ksmbd_vfs_set_dos_attrib_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `					  struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `					  bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	return ksmbd_vfs_set_dos_attrib_xattr(&init_user_ns, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `					      da, get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `ssize_t compat_ksmbd_vfs_getxattr(struct path *path, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `				  char *xattr_name, char **xattr_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	return ksmbd_vfs_getxattr(&init_user_ns, dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `				  xattr_name, xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) */`
  Review: Low-risk line; verify in surrounding control flow.
