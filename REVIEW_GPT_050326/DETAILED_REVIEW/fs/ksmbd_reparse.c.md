# Line-by-line Review: src/fs/ksmbd_reparse.c

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
- L00006 [NONE] ` *   Reparse point FSCTL handlers for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   Registers FSCTL handlers for FSCTL_SET_REPARSE_POINT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   FSCTL_GET_REPARSE_POINT, and FSCTL_DELETE_REPARSE_POINT.`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   Supports IO_REPARSE_TAG_SYMLINK and IO_REPARSE_TAG_MOUNT_POINT`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   for Windows symlink and junction point interoperability.`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "ksmbd_reparse.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "xattr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * Reparse data buffer structures per MS-FSCC 2.1.2.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `/* Generic reparse data buffer header */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `struct reparse_data_buf_hdr {`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	__le32	reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	__le16	reparse_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	__le16	reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	__u8	data_buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `/* Symlink reparse data buffer (IO_REPARSE_TAG_SYMLINK) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `struct reparse_symlink_data_buf {`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	__le32	reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	__le16	reparse_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	__le16	reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	__le16	substitute_name_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	__le16	substitute_name_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	__le16	print_name_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	__le16	print_name_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	__le32	flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	__u8	path_buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `/* Mount point (junction) reparse data buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `struct reparse_mount_point_data_buf {`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	__le32	reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	__le16	reparse_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	__le16	reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	__le16	substitute_name_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	__le16	substitute_name_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	__le16	print_name_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	__le16	print_name_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	__u8	path_buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#define SYMLINK_FLAG_RELATIVE	0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `/* Maximum symlink target path length we support */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define REPARSE_MAX_PATH_LEN	4096`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `static int ksmbd_reparse_store_opaque(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `				      const void *buf, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	return ksmbd_vfs_setxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	return ksmbd_vfs_setxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `				  &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `				  XATTR_NAME_REPARSE_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `				  (void *)buf, len, 0, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `static int ksmbd_reparse_load_opaque(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `				     char **buf, size_t *len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	ssize_t xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `				       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `				       XATTR_NAME_REPARSE_DATA, buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	if (xattr_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `		return xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	*len = xattr_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `static int ksmbd_reparse_remove_opaque(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	return ksmbd_vfs_remove_xattr(file_mnt_idmap(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	return ksmbd_vfs_remove_xattr(file_mnt_user_ns(fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `				      &fp->filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				      (char *)XATTR_NAME_REPARSE_DATA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `				      true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * ksmbd_convert_slashes() - Convert backslashes to forward slashes`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` * @path:	path string to convert in-place`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `VISIBLE_IF_KUNIT void ksmbd_convert_slashes(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	char *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	for (p = path; *p; p++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `		if (*p == '\\')`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `			*p = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_convert_slashes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` * ksmbd_strip_nt_prefix() - Strip NT-style path prefix`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` * @path:	path string to strip in-place`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * Removes /??/ or //?/ prefixes from NT-style paths.`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `VISIBLE_IF_KUNIT void ksmbd_strip_nt_prefix(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	int len = strlen(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	if (len > 4 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	    (strncmp(path, "/??/", 4) == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	     strncmp(path, "//?/", 4) == 0)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [MEM_BOUNDS|] `		memmove(path, path + 4, len - 4 + 1);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00157 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_strip_nt_prefix);`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` * ksmbd_normalize_path() - Normalize a path in-place`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` * @path:	path string to normalize (modified in place)`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` * Collapses consecutive slashes, strips trailing slashes, and`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ` * converts backslashes to forward slashes.  This prevents bypass`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * of path containment checks via redundant separators or`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * trailing slashes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `VISIBLE_IF_KUNIT void ksmbd_normalize_path(char *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	char *src, *dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	if (!path || !*path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	/* Convert any remaining backslashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	for (src = path; *src; src++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		if (*src == '\\')`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `			*src = '/';`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	/* Collapse consecutive slashes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	src = dst = path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	while (*src) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `		*dst++ = *src;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		if (*src == '/') {`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `			while (src[1] == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `				src++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `		src++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	*dst = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	/* Strip trailing slash(es) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	while (dst > path + 1 && *(dst - 1) == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `		*--dst = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_normalize_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `VISIBLE_IF_KUNIT bool ksmbd_is_safe_reparse_target(const char *target)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	const char *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	if (!target || !*target)`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	/* Reject Windows-style path separators that could bypass checks */`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	if (strchr(target, '\\'))`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	/* Reparse targets must remain share-relative. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	if (target[0] == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	p = target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	while (*p) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `		const char *seg = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		size_t seglen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `		while (*p && *p != '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `			p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		seglen = p - seg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		/* Reject empty segments (consecutive slashes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		if (seglen == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `			if (*p == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `				p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		if (seglen == 1 && seg[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		if (seglen == 2 && seg[0] == '.' && seg[1] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `			return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		if (*p == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `			p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `EXPORT_SYMBOL_IF_KUNIT(ksmbd_is_safe_reparse_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `static int ksmbd_reparse_replace_with_symlink(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `					      const char *target,`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `					      const struct path *share_root)`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	struct dentry *parent, *dentry, *new_dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	struct inode *dir_inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	struct path symlink_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	dentry = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	parent = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	dir_inode = d_inode(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	ret = mnt_want_write(fp->filp->f_path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	 * Hold the parent directory inode lock across both unlink and`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	 * symlink creation to close the TOCTOU race window where an`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	 * attacker could place a malicious entry between the two ops.`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	inode_lock_nested(dir_inode, I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	/* Verify the dentry is still parented correctly */`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	if (dentry->d_parent != parent) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00286 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	/* Unlink the existing file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	dget(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	if (S_ISDIR(d_inode(dentry)->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		ret = vfs_rmdir(idmap, dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `		ret = vfs_rmdir(idmap, dir_inode, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `		ret = vfs_rmdir(user_ns, dir_inode, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `		ret = vfs_rmdir(dir_inode, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		ret = vfs_unlink(idmap, dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		ret = vfs_unlink(user_ns, dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `		ret = vfs_unlink(dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00317 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	/* Look up a new (negative) dentry at the same name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	new_dentry = lookup_one(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `				(struct qstr *)&dentry->d_name, parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	new_dentry = lookup_one(idmap, dentry->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `				dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	new_dentry = lookup_one(user_ns, dentry->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `				dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `	new_dentry = lookup_one_len(dentry->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `				    dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `	if (IS_ERR(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		ret = PTR_ERR(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00335 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	if (d_is_positive(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `		/* Something raced and created an entry - bail out */`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `		dput(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `		ret = -EEXIST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00342 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `	/* Create the symlink */`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `	ret = vfs_symlink(idmap, dir_inode, new_dentry, target, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `	ret = vfs_symlink(idmap, dir_inode, new_dentry, target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	ret = vfs_symlink(user_ns, dir_inode, new_dentry, target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	ret = vfs_symlink(dir_inode, new_dentry, target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	 * After creation, validate the new symlink resolves within`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	 * the share boundary to prevent escape via crafted targets.`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	if (!ret && share_root) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		symlink_path.mnt = fp->filp->f_path.mnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		symlink_path.dentry = new_dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		if (!path_is_under(&symlink_path, share_root)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [ERROR_PATH|] `			pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00368 [NONE] `				"reparse symlink escapes share boundary\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `			/* Remove the offending symlink */`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `			vfs_unlink(idmap, dir_inode, new_dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `			vfs_unlink(user_ns, dir_inode, new_dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `			vfs_unlink(dir_inode, new_dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `			ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	dput(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `out_unlock:`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	inode_unlock(dir_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	mnt_drop_write(fp->filp->f_path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `static int ksmbd_reparse_replace_with_regular_file(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	struct dentry *parent, *dentry, *new_dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	struct inode *dir_inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	struct user_namespace *user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	dentry = fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `	parent = dget_parent(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	dir_inode = d_inode(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `	idmap = file_mnt_idmap(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `	user_ns = file_mnt_user_ns(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `	ret = mnt_want_write(fp->filp->f_path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `		dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	 * Hold the parent directory inode lock across both unlink and`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	 * file creation to close the TOCTOU race window where an`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `	 * attacker could place a malicious entry between the two ops.`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `	inode_lock_nested(dir_inode, I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `	/* Verify the dentry is still parented correctly */`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	if (dentry->d_parent != parent) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `		ret = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00430 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `	/* Unlink the existing symlink */`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	dget(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	if (S_ISDIR(d_inode(dentry)->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		ret = vfs_rmdir(idmap, dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		ret = vfs_rmdir(idmap, dir_inode, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		ret = vfs_rmdir(user_ns, dir_inode, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `		ret = vfs_rmdir(dir_inode, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] `		ret = vfs_unlink(idmap, dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `		ret = vfs_unlink(user_ns, dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `		ret = vfs_unlink(dir_inode, dentry, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	dput(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	/* Look up a new (negative) dentry at the same name */`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `	new_dentry = lookup_one(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `				(struct qstr *)&dentry->d_name, parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	new_dentry = lookup_one(idmap, dentry->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `				dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	new_dentry = lookup_one(user_ns, dentry->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `				dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	new_dentry = lookup_one_len(dentry->d_name.name, parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `				    dentry->d_name.len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	if (IS_ERR(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `		ret = PTR_ERR(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00479 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	if (d_is_positive(new_dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `		/* Something raced and created an entry - bail out */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `		dput(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `		ret = -EEXIST;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [ERROR_PATH|] `		goto out_unlock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00486 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	/* Create the regular file */`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	ret = vfs_create(idmap, new_dentry, S_IFREG | 0644, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	ret = vfs_create(idmap, dir_inode, new_dentry, S_IFREG | 0644, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `	ret = vfs_create(user_ns, dir_inode, new_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `			 S_IFREG | 0644, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	ret = vfs_create(dir_inode, new_dentry, S_IFREG | 0644, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `	dput(new_dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `out_unlock:`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	inode_unlock(dir_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	mnt_drop_write(fp->filp->f_path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	dput(parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] ` * ksmbd_extract_symlink_target() - Extract UTF-8 target from`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] ` *                                  symlink reparse data`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ` * @symdata:	symlink reparse data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] ` * @in_buf_len:	total input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] ` * @codepage:	NLS codepage for UTF-16 conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ` * @target:	[out] allocated UTF-8 target string`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ` * Validates the reparse data structure and extracts the`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ` * SubstituteName as a UTF-8 string suitable for VFS operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `static int ksmbd_extract_symlink_target(`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		struct reparse_symlink_data_buf *symdata,`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `		const struct nls_table *codepage,`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `		char **target)`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	unsigned int sub_off, sub_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	char *utf8_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	sub_off = le16_to_cpu(symdata->substitute_name_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	sub_len = le16_to_cpu(symdata->substitute_name_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	/* Validate against actual input buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	if (offsetof(struct reparse_symlink_data_buf, path_buffer)`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	    + sub_off + sub_len > in_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00542 [NONE] `			"reparse symlink: substitute name overflows buf\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00544 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	if (sub_len == 0 || sub_len > REPARSE_MAX_PATH_LEN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00548 [NONE] `			"reparse symlink: invalid sub name len %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `			sub_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00551 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	 * smb_strndup_from_utf16 allocates and converts the`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	 * UTF-16LE string to a UTF-8 string.`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	utf8_target = smb_strndup_from_utf16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `			(const char *)(symdata->path_buffer + sub_off),`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `			sub_len, true, codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	if (IS_ERR(utf8_target)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00562 [NONE] `			"reparse symlink: UTF-16 conversion failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		return PTR_ERR(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	ksmbd_convert_slashes(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	ksmbd_strip_nt_prefix(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	ksmbd_normalize_path(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `	*target = utf8_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] ` * ksmbd_extract_mount_point_target() - Extract UTF-8 target from`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] ` *                                      mount point reparse data`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ` * @mpdata:	mount point reparse data buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ` * @in_buf_len:	total input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ` * @codepage:	NLS codepage for UTF-16 conversion`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ` * @target:	[out] allocated UTF-8 target string`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ` * Validates the reparse data structure and extracts the`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] ` * SubstituteName as a UTF-8 string suitable for VFS operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `static int ksmbd_extract_mount_point_target(`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `		struct reparse_mount_point_data_buf *mpdata,`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `		unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `		const struct nls_table *codepage,`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		char **target)`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	unsigned int sub_off, sub_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	char *utf8_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `	sub_off = le16_to_cpu(mpdata->substitute_name_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	sub_len = le16_to_cpu(mpdata->substitute_name_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	/* Validate against actual input buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	if (offsetof(struct reparse_mount_point_data_buf, path_buffer)`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	    + sub_off + sub_len > in_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00603 [NONE] `			"reparse junction: sub name overflows buf\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00605 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	if (sub_len == 0 || sub_len > REPARSE_MAX_PATH_LEN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00609 [NONE] `			"reparse junction: invalid sub name len %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `			sub_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00612 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	utf8_target = smb_strndup_from_utf16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `			(const char *)(mpdata->path_buffer + sub_off),`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `			sub_len, true, codepage);`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	if (IS_ERR(utf8_target)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00619 [NONE] `			"reparse junction: UTF-16 conversion failed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		return PTR_ERR(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	ksmbd_convert_slashes(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	ksmbd_strip_nt_prefix(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	ksmbd_normalize_path(utf8_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	*target = utf8_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ` * ksmbd_fsctl_set_reparse_point() - Handle FSCTL_SET_REPARSE_POINT`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ` * @in_buf:	    input buffer containing reparse data`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] ` * Parses the reparse data buffer and validates the symlink or`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ` * junction point target for IO_REPARSE_TAG_SYMLINK and`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ` * IO_REPARSE_TAG_MOUNT_POINT tags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `static int ksmbd_fsctl_set_reparse_point(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	struct reparse_data_buf_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	char *target = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `	const struct nls_table *codepage;`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	__le32 tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00663 [ERROR_PATH|] `		return -EACCES;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00664 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	if (in_buf_len < sizeof(struct reparse_data_buf_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00668 [NONE] `			"set reparse: input buffer too short: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `			in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00671 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00672 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	hdr = (struct reparse_data_buf_hdr *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	tag = hdr->reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	if (in_buf_len < sizeof(*hdr) + le16_to_cpu(hdr->reparse_data_length)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00678 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00679 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [ERROR_PATH|] `		pr_err_ratelimited("set reparse: file not found\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00684 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00685 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00686 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	codepage = work->conn->local_nls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	switch (le32_to_cpu(tag)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `	case IO_REPARSE_TAG_SYMLINK:`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `		struct reparse_symlink_data_buf *symdata;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `		if (in_buf_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		    sizeof(struct reparse_symlink_data_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `			rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [PROTO_GATE|] `				STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00700 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00701 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `		symdata = (struct reparse_symlink_data_buf *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `		ret = ksmbd_extract_symlink_target(symdata,`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `						   in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `						   codepage,`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `						   &target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `			rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [PROTO_GATE|] `				STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00711 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00712 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `	case IO_REPARSE_TAG_MOUNT_POINT:`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `		struct reparse_mount_point_data_buf *mpdata;`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		if (in_buf_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `		    sizeof(struct reparse_mount_point_data_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `			rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [PROTO_GATE|] `				STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00724 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00725 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `		mpdata = (struct reparse_mount_point_data_buf *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `		ret = ksmbd_extract_mount_point_target(mpdata,`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `						       in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `						       codepage,`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `						       &target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `			rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [PROTO_GATE|] `				STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00735 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00736 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `		 * Keep unsupported-name-surrogate tags as opaque reparse`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `		 * data so clients using custom tags can round-trip`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `		 * FSCTL_SET/GET/DELETE_REPARSE_POINT.`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		ret = ksmbd_reparse_store_opaque(fp, in_buf, in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `			if (ret == -EACCES || ret == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00749 [NONE] `			else if (ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00751 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00753 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00754 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00759 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `	/* Prevent symlink targets that escape share boundary */`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	if (!target) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00765 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00766 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	if (!ksmbd_is_safe_reparse_target(target)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00770 [NONE] `			"set reparse: target '%s' escapes share\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `			target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `		ret = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00774 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00775 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	ksmbd_debug(SMB, "set reparse: tag 0x%x -> %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `		    le32_to_cpu(tag), target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	ret = ksmbd_reparse_replace_with_symlink(fp, target,`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `					&work->tcon->share_conf->vfs_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `		if (ret == -EACCES || ret == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00785 [NONE] `		else if (ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DISK_FULL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00787 [NONE] `		else if (ret == -ENOTEMPTY)`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_DIRECTORY_NOT_EMPTY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00789 [NONE] `		else if (ret == -EEXIST)`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00791 [NONE] `		else if (ret == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00793 [NONE] `		else if (ret == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00795 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00797 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00798 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `	ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	kfree(target);`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ` * ksmbd_fsctl_get_reparse_point() - Handle FSCTL_GET_REPARSE_POINT`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] ` * @in_buf:	    input buffer (unused)`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] ` * Reads the reparse data for the file identified by @id.`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ` * For symlinks, constructs a SYMLINK reparse data buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] ` * For other special files, returns the appropriate reparse tag`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] ` * with an empty data buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `static int ksmbd_fsctl_get_reparse_point(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `					 u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `					 unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `					 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `					 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `					 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `	struct reparse_data_buf_hdr *opaque_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `	struct reparse_data_buffer *reparse_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	struct reparse_symlink_data_buf *symdata;`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `	const struct nls_table *codepage;`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	char *opaque_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	size_t opaque_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `	unsigned int ucs2_bytes, total_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [ERROR_PATH|] `		pr_err_ratelimited("get reparse: file not found\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00848 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00849 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00850 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	codepage = work->conn->local_nls;`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	ret = ksmbd_reparse_load_opaque(fp, &opaque_buf, &opaque_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		if (opaque_len < sizeof(*opaque_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `			kfree(opaque_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00861 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00862 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `		opaque_hdr = (struct reparse_data_buf_hdr *)opaque_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `		if (opaque_len < sizeof(*opaque_hdr) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `				 le16_to_cpu(opaque_hdr->reparse_data_length)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `			kfree(opaque_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00870 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00871 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `		if (opaque_len > max_out_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `			kfree(opaque_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00877 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00878 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [MEM_BOUNDS|] `		memcpy(&rsp->Buffer[0], opaque_buf, opaque_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00881 [NONE] `		kfree(opaque_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `		*out_len = opaque_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	if (ret != -ENODATA && ret != -ENOENT && ret != -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00889 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `	if (S_ISLNK(inode->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		const char *link;`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `		char *link_copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `		__le16 *ucs2_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `		int link_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		DEFINE_DELAYED_CALL(done);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		if (max_out_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `		    sizeof(struct reparse_symlink_data_buf)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00903 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00904 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		/* Read the symlink target */`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] `		link = vfs_get_link(fp->filp->f_path.dentry, &done);`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `		if (IS_ERR(link)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_A_REPARSE_POINT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00911 [NONE] `			return PTR_ERR(link);`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `		link_len = strlen(link);`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `		/* Copy link target so we can release the delayed call */`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [MEM_BOUNDS|] `		link_copy = kzalloc(link_len + 1, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00918 [NONE] `		if (!link_copy) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `			do_delayed_call(&done);`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00922 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [MEM_BOUNDS|] `		memcpy(link_copy, link, link_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00924 [NONE] `		do_delayed_call(&done);`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `		 * Convert UTF-8 path to UTF-16LE in a temporary`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `		 * buffer first to calculate the size before writing`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `		 * into the response buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [MEM_BOUNDS|] `		ucs2_buf = kzalloc((link_len + 1) * 2,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00932 [NONE] `				   KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		if (!ucs2_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `			kfree(link_copy);`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00937 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `		conv_len = smbConvertToUTF16(ucs2_buf, link_copy,`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `					     link_len, codepage, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `		kfree(link_copy);`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `		if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `			kfree(ucs2_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00947 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00948 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `		ucs2_bytes = conv_len * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `		 * Total size: fixed header + SubstituteName +`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `		 * PrintName (both same content).`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `		total_len = sizeof(struct reparse_symlink_data_buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `			    + ucs2_bytes * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `		if (total_len > max_out_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `			kfree(ucs2_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00962 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00963 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `		symdata = (struct reparse_symlink_data_buf *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `			  &rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `		memset(symdata, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `		       sizeof(struct reparse_symlink_data_buf));`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `		symdata->reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `			cpu_to_le32(IO_REPARSE_TAG_SYMLINK);`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `		symdata->reparse_data_length = cpu_to_le16(`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `			total_len -`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `			offsetof(struct reparse_symlink_data_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `				 substitute_name_offset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `		symdata->substitute_name_offset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `		symdata->substitute_name_length =`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `			cpu_to_le16(ucs2_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		symdata->print_name_offset =`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `			cpu_to_le16(ucs2_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `		symdata->print_name_length =`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `			cpu_to_le16(ucs2_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `		symdata->flags =`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `			cpu_to_le32(SYMLINK_FLAG_RELATIVE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `		/* Copy SubstituteName */`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [MEM_BOUNDS|] `		memcpy(symdata->path_buffer, ucs2_buf, ucs2_bytes);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00988 [NONE] `		/* Copy PrintName (same content, after SubstituteName) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [MEM_BOUNDS|] `		memcpy(symdata->path_buffer + ucs2_bytes,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00990 [NONE] `		       ucs2_buf, ucs2_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `		kfree(ucs2_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `		*out_len = total_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `		 * Non-symlink special files: return the appropriate`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `		 * reparse tag with empty data, matching the existing`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `		 * behavior in smb2pdu.c.`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `		if (S_ISFIFO(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `			reparse_tag = IO_REPARSE_TAG_LX_FIFO_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `		else if (S_ISSOCK(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `			reparse_tag = IO_REPARSE_TAG_AF_UNIX_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `		else if (S_ISCHR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `			reparse_tag = IO_REPARSE_TAG_LX_CHR_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `		else if (S_ISBLK(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `			reparse_tag = IO_REPARSE_TAG_LX_BLK_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `		else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NOT_A_REPARSE_POINT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01013 [NONE] `			*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01015 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `		if (max_out_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		    sizeof(struct reparse_data_buffer)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01021 [ERROR_PATH|] `			return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01022 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		reparse_ptr = (struct reparse_data_buffer *)`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `			      &rsp->Buffer[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		reparse_ptr->ReparseTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `		reparse_ptr->ReparseDataLength = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		*out_len = sizeof(struct reparse_data_buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] ` * ksmbd_fsctl_delete_reparse_point() - Handle FSCTL_DELETE_REPARSE_POINT`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] ` * @in_buf:	    input buffer containing reparse tag`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] ` * Validates the reparse tag in the delete request matches the`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] ` * file's actual reparse tag, then removes the reparse data.`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] ` * For symlinks, this removes the symbolic link.`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `static int ksmbd_fsctl_delete_reparse_point(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `					    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `					    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `					    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `					    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `					    unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	struct reparse_data_buf_hdr *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	struct reparse_data_buf_hdr *opaque_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	struct inode *inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `	char *opaque_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	size_t opaque_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `	if (in_buf_len < sizeof(struct reparse_data_buf_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [ERROR_PATH|] `		pr_err_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01068 [NONE] `			"delete reparse: buf too short: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `			in_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01071 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01072 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `	hdr = (struct reparse_data_buf_hdr *)in_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	fp = ksmbd_lookup_fd_fast(work, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `	if (!fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [ERROR_PATH|] `		pr_err_ratelimited("delete reparse: not found\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01079 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_HANDLE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01080 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01081 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `	ret = ksmbd_reparse_load_opaque(fp, &opaque_buf, &opaque_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `		if (opaque_len < sizeof(*opaque_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_IO_REPARSE_DATA_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01087 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01089 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `		opaque_hdr = (struct reparse_data_buf_hdr *)opaque_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `		if (hdr->reparse_tag != opaque_hdr->reparse_tag) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_IO_REPARSE_TAG_MISMATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01094 [NONE] `			ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01096 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] `		ret = ksmbd_reparse_remove_opaque(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `		if (ret && ret != -ENOENT && ret != -ENODATA) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01101 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01102 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `		ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01107 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `	if (ret != -ENODATA && ret != -ENOENT && ret != -EOPNOTSUPP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01110 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01111 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `	inode = file_inode(fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `	/* Verify the file is actually a reparse point */`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	if (!S_ISLNK(inode->i_mode) && S_ISREG(inode->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `		ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOT_A_REPARSE_POINT;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01119 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01120 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `	/* Verify reparse tag matches */`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	if (S_ISLNK(inode->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `		__le32 exp_sym =`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `			cpu_to_le32(IO_REPARSE_TAG_SYMLINK);`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `		__le32 exp_mp =`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `			cpu_to_le32(IO_REPARSE_TAG_MOUNT_POINT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `		if (hdr->reparse_tag != exp_sym &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `		    hdr->reparse_tag != exp_mp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `			rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [PROTO_GATE|] `				STATUS_IO_REPARSE_TAG_MISMATCH;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01134 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01135 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	 * Convert reparse symlink to a regular file by replacing`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `	 * the symlink dentry atomically from the same pathname.`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	ksmbd_debug(SMB, "delete reparse: tag 0x%x on ino %lu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `		    le32_to_cpu(hdr->reparse_tag), inode->i_ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	if (S_ISLNK(inode->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `		ret = ksmbd_reparse_replace_with_regular_file(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01149 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01150 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `	ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `	kfree(opaque_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `/* FSCTL handler descriptors */`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `static struct ksmbd_fsctl_handler set_reparse_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `	.ctl_code = FSCTL_SET_REPARSE_POINT,`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `	.handler  = ksmbd_fsctl_set_reparse_point,`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `static struct ksmbd_fsctl_handler get_reparse_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `	.ctl_code = FSCTL_GET_REPARSE_POINT,`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `	.handler  = ksmbd_fsctl_get_reparse_point,`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `static struct ksmbd_fsctl_handler delete_reparse_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	.ctl_code = FSCTL_DELETE_REPARSE_POINT,`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `	.handler  = ksmbd_fsctl_delete_reparse_point,`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `	.owner    = THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] ` * ksmbd_reparse_init() - Initialize reparse point subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] ` * Registers FSCTL handlers for FSCTL_SET_REPARSE_POINT`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] ` * (0x000900A4), FSCTL_GET_REPARSE_POINT (0x000900A8), and`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] ` * FSCTL_DELETE_REPARSE_POINT (0x000900AC).`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `int ksmbd_reparse_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `	ret = ksmbd_register_fsctl(&set_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [ERROR_PATH|] `		pr_err("Failed to register FSCTL_SET_REPARSE: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01196 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	ret = ksmbd_register_fsctl(&get_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [ERROR_PATH|] `		pr_err("Failed to register FSCTL_GET_REPARSE: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01203 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [ERROR_PATH|] `		goto err_unregister_set;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01205 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	ret = ksmbd_register_fsctl(&delete_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [ERROR_PATH|] `		pr_err("Failed to register FSCTL_DELETE_REPARSE: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01210 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [ERROR_PATH|] `		goto err_unregister_get;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01212 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `	ksmbd_debug(SMB, "Reparse point subsystem initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `err_unregister_get:`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `	ksmbd_unregister_fsctl(&get_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `err_unregister_set:`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `	ksmbd_unregister_fsctl(&set_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] ` * ksmbd_reparse_exit() - Tear down reparse point subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] ` * Unregisters all reparse point FSCTL handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `void ksmbd_reparse_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	ksmbd_unregister_fsctl(&delete_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	ksmbd_unregister_fsctl(&get_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] `	ksmbd_unregister_fsctl(&set_reparse_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
