# Line-by-line Review: src/include/fs/vfs.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
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
- L00007 [NONE] `#ifndef __KSMBD_VFS_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_VFS_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/file.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <uapi/linux/xattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/posix_acl.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/unicode.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "xattr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * Enumeration for stream type.`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	DATA_STREAM	= 1,	/* type $DATA */`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	DIR_STREAM		/* type $INDEX_ALLOCATION */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `/* CreateOptions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `/* Flag is set, it must not be a file , valid for directory only */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define FILE_DIRECTORY_FILE_LE			cpu_to_le32(0x00000001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define FILE_WRITE_THROUGH_LE			cpu_to_le32(0x00000002)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define FILE_SEQUENTIAL_ONLY_LE			cpu_to_le32(0x00000004)`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/* Should not buffer on server*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define FILE_NO_INTERMEDIATE_BUFFERING_LE	cpu_to_le32(0x00000008)`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `/* MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define FILE_SYNCHRONOUS_IO_ALERT_LE		cpu_to_le32(0x00000010)`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `/* MBZ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define FILE_SYNCHRONOUS_IO_NONALERT_LE		cpu_to_le32(0x00000020)`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `/* Flaf must not be set for directory */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define FILE_NON_DIRECTORY_FILE_LE		cpu_to_le32(0x00000040)`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `/* Should be zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define CREATE_TREE_CONNECTION			cpu_to_le32(0x00000080)`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#define FILE_COMPLETE_IF_OPLOCKED_LE		cpu_to_le32(0x00000100)`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#define FILE_NO_EA_KNOWLEDGE_LE			cpu_to_le32(0x00000200)`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define FILE_OPEN_REMOTE_INSTANCE		cpu_to_le32(0x00000400)`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * Doc says this is obsolete "open for recovery" flag should be zero`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` * in any case.`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#define CREATE_OPEN_FOR_RECOVERY		cpu_to_le32(0x00000400)`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define FILE_RANDOM_ACCESS_LE			cpu_to_le32(0x00000800)`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define FILE_DELETE_ON_CLOSE_LE			cpu_to_le32(0x00001000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#define FILE_OPEN_BY_FILE_ID_LE			cpu_to_le32(0x00002000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define FILE_OPEN_FOR_BACKUP_INTENT_LE		cpu_to_le32(0x00004000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#define FILE_NO_COMPRESSION_LE			cpu_to_le32(0x00008000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/* Should be zero*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#define FILE_OPEN_REQUIRING_OPLOCK		cpu_to_le32(0x00010000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#define FILE_DISALLOW_EXCLUSIVE			cpu_to_le32(0x00020000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define FILE_RESERVE_OPFILTER_LE		cpu_to_le32(0x00100000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define FILE_OPEN_REPARSE_POINT_LE		cpu_to_le32(0x00200000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define FILE_OPEN_NO_RECALL_LE			cpu_to_le32(0x00400000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/* Should be zero */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#define FILE_OPEN_FOR_FREE_SPACE_QUERY_LE	cpu_to_le32(0x00800000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define CREATE_OPTIONS_MASK			cpu_to_le32(0x00FFFFFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define CREATE_OPTION_READONLY			0x10000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `/* system. NB not sent over wire */`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define CREATE_OPTION_SPECIAL			0x20000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `struct ksmbd_dir_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	const char	*name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	char		*smb1_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	char		*wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	char		*rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	int		name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	int		out_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	int		num_scan;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	int		num_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	int		data_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	int		last_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	bool		hide_dot_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	int		flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	int		last_entry_off_align;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `struct ksmbd_readdir_data {`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	struct dir_context	ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	union {`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `		void		*private;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		char		*dirent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	unsigned int		used;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	unsigned int		dirent_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	unsigned int		file_attr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	struct unicode_map	*um;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `/* ksmbd kstat wrapper to get valid create time when reading dir entry */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `struct ksmbd_kstat {`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	struct kstat		*kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	struct dentry		*kstat_dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	unsigned long long	create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	__le32			file_attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `static inline struct user_namespace *mnt_user_ns(const struct vfsmount *mnt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	return &init_user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `static inline struct user_namespace *file_mnt_user_ns(struct file *file)`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	return &init_user_ns;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `int ksmbd_vfs_lock_parent(struct dentry *parent, struct dentry *child);`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `int ksmbd_vfs_lock_parent(struct mnt_idmap *idmap, struct dentry *parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `			  struct dentry *child);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `int ksmbd_vfs_may_delete(struct mnt_idmap *idmap, struct dentry *dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `void ksmbd_vfs_query_maximal_access(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `				   struct dentry *dentry, __le32 *daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `int ksmbd_vfs_lock_parent(struct user_namespace *user_ns, struct dentry *parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `			  struct dentry *child);`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `int ksmbd_vfs_may_delete(struct user_namespace *user_ns, struct dentry *dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `int ksmbd_vfs_query_maximal_access(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `				   struct dentry *dentry, __le32 *daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `int ksmbd_vfs_create(struct ksmbd_work *work, const char *name, umode_t mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `int ksmbd_vfs_mkdir(struct ksmbd_work *work, const char *name, umode_t mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `int ksmbd_vfs_read(struct ksmbd_work *work, struct ksmbd_file *fp, size_t count,`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		   loff_t *pos, char *rbuf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `ssize_t ksmbd_vfs_sendfile(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `			   loff_t offset, size_t count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `int ksmbd_vfs_write(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		    char *buf, size_t count, loff_t *pos, bool sync,`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `		    ssize_t *written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `int ksmbd_vfs_fsync(struct ksmbd_work *work, u64 fid, u64 p_id, bool fullsync);`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `int ksmbd_vfs_copy_xattrs(struct dentry *src_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `			   struct dentry *dst_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `			   const struct path *dst_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `int ksmbd_vfs_resolve_fileid(const struct path *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `			     u64 ino, char *buf, int buflen);`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `static inline int ksmbd_vfs_copy_xattrs(struct dentry *src_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `			struct dentry *dst_dentry, const struct path *dst_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `static inline int ksmbd_vfs_resolve_fileid(const struct path *share_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `			u64 ino, char *buf, int buflen)`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00176 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `int ksmbd_vfs_remove_file(struct ksmbd_work *work, const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `int ksmbd_vfs_remove_file(struct ksmbd_work *work, char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `int ksmbd_vfs_link(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `		   const char *oldname, const char *newname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `int ksmbd_vfs_getattr(const struct path *path, struct kstat *stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `int ksmbd_vfs_setattr(struct ksmbd_work *work, const char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		      u64 fid, struct iattr *attrs);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `int ksmbd_vfs_symlink(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `		      const char *name, const char *symname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `int ksmbd_vfs_readlink(struct path *path, char *buf, int lenp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `int ksmbd_vfs_readdir_name(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `			   struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `			   struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `			   struct ksmbd_kstat *ksmbd_kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `			   const char *de_name, int de_name_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `			   const char *dir_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `int ksmbd_vfs_rename(struct ksmbd_work *work, const struct path *old_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		     char *newname, int flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `int ksmbd_vfs_fp_rename(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `			char *newname);`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `int ksmbd_vfs_truncate(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `		       struct ksmbd_file *fp, loff_t size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `struct srv_copychunk;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `int ksmbd_vfs_copy_file_ranges(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `			       struct ksmbd_file *src_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `			       struct ksmbd_file *dst_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `			       struct srv_copychunk *chunks,`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `			       unsigned int chunk_count,`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `			       unsigned int *chunk_count_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `			       unsigned int *chunk_size_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `			       loff_t  *total_size_written);`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `struct ksmbd_file *ksmbd_vfs_dentry_open(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `					 const struct path *path, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `					 __le32 option, int fexist);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `ssize_t ksmbd_vfs_listxattr(struct dentry *dentry, char **list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `ssize_t ksmbd_vfs_getxattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `ssize_t ksmbd_vfs_getxattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `			   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `			   char *xattr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `			   char **xattr_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `ssize_t ksmbd_vfs_casexattr_len(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `ssize_t ksmbd_vfs_casexattr_len(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `				struct dentry *dentry, char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `				int attr_name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `int ksmbd_vfs_setxattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `int ksmbd_vfs_setxattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `		       const struct path *path, const char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		       void *attr_value, size_t attr_size, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		       bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		       const void *attr_value, size_t attr_size, int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		       bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `int ksmbd_vfs_fsetxattr(struct ksmbd_work *work, const char *filename,`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `			const char *attr_name, const void *attr_value,`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `			size_t attr_size, int flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `int ksmbd_vfs_xattr_stream_name(char *stream_name, char **xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `				size_t *xattr_stream_name_size, int s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `int ksmbd_vfs_remove_xattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `int ksmbd_vfs_remove_xattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `			   const struct path *path, char *attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `			   bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `int ksmbd_vfs_kern_path(struct ksmbd_work *work, char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `			unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `			struct path *path, bool caseless);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `int ksmbd_vfs_kern_path_locked(struct ksmbd_work *work, char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			       unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `			       struct path *path, bool caseless);`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `void ksmbd_vfs_kern_path_unlock(const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `int ksmbd_vfs_kern_path(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `			char *name, unsigned int flags, struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `			bool caseless);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `struct dentry *ksmbd_vfs_kern_path_create(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `					  const char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `					  unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `					  struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `int ksmbd_vfs_empty_dir(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `void ksmbd_vfs_set_fadvise(struct file *filp, __le32 option);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `int ksmbd_vfs_zero_data(struct ksmbd_work *work, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `			loff_t off, loff_t len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `struct file_allocated_range_buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `int ksmbd_vfs_fqar_lseek(struct ksmbd_file *fp, loff_t start, loff_t length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `			 struct file_allocated_range_buffer *ranges,`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `			 unsigned int in_count, unsigned int *out_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `int ksmbd_vfs_unlink(struct file *filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `int ksmbd_vfs_unlink(struct mnt_idmap *idmap, struct dentry *dir,`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		     struct dentry *dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `int ksmbd_vfs_unlink(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `		     struct dentry *dir, struct dentry *dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `void *ksmbd_vfs_init_kstat(char **p, struct ksmbd_kstat *ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `int ksmbd_vfs_fill_dentry_attrs(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `				struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `				struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `				struct ksmbd_kstat *ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `int ksmbd_vfs_fill_dentry_attrs(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `				struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `				struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `				struct ksmbd_kstat *ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `void ksmbd_vfs_posix_lock_wait(struct file_lock *flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `int ksmbd_vfs_posix_lock_wait_timeout(struct file_lock *flock, long timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `void ksmbd_vfs_posix_lock_unblock(struct file_lock *flock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `int ksmbd_vfs_remove_acl_xattrs(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `				const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `int ksmbd_vfs_remove_acl_xattrs(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `				const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `int ksmbd_vfs_remove_sd_xattrs(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `int ksmbd_vfs_remove_sd_xattrs(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `			       const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `int ksmbd_vfs_set_sd_xattr(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `			   struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `			   struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `			   const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `			   struct smb_ntsd *pntsd, int len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `			   bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `int ksmbd_vfs_get_sd_xattr(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `			   struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `			   struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `			   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `			   struct smb_ntsd **pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `int ksmbd_vfs_set_dos_attrib_xattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `				   const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `				   struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `				   bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `int ksmbd_vfs_get_dos_attrib_xattr(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `				   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `				   struct xattr_dos_attrib *da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `int ksmbd_vfs_set_dos_attrib_xattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `				   const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `				   struct xattr_dos_attrib *da,`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `				   bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `int ksmbd_vfs_get_dos_attrib_xattr(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `				   struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `				   struct xattr_dos_attrib *da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `int ksmbd_vfs_set_init_posix_acl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `				 const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `int ksmbd_vfs_inherit_posix_acl(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `				const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `				struct inode *parent_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `int ksmbd_vfs_set_init_posix_acl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `				 const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `int ksmbd_vfs_inherit_posix_acl(struct user_namespace *user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `				const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `				struct inode *parent_inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `/* VFS helpers exported for KUnit tests */`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `struct ksmbd_share_config;`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `int ksmbd_vfs_path_lookup(struct ksmbd_share_config *share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `			  char *pathname, unsigned int flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `			  struct path *path, bool do_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `#endif /* __KSMBD_VFS_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
