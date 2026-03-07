# Line-by-line Review: src/protocol/smb2/smb2_create.c

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
- L00006 [PROTO_GATE|] ` *   smb2_create.c - SMB2_CREATE (open) handler + helpers`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/inetdevice.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <net/addrconf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/syscalls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/namei.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/ethtool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/falloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/crc32.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/mount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/filelock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include <crypto/algapi.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "smbfsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#include "auth.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#include "asn1.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#include "transport_ipc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#include "misc.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#include "ksmbd_work.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#include "mgmt/user_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#include "mgmt/tree_connect.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#include "mgmt/ksmbd_ida.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#include "ndr.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include "transport_tcp.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include "ksmbd_fsctl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include "ksmbd_vss.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include "ksmbd_notify.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * smb2_create_open_flags() - convert smb open flags to unix open flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * @file_present:	is file already present`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * @access:		file access flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` * @disposition:	file disposition flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * @may_flags:		set with MAY_ flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * @is_dir:		is creating open flags for directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * Return:      file open flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `VISIBLE_IF_KUNIT int smb2_create_open_flags(bool file_present, __le32 access,`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `					    __le32 disposition,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `					    int *may_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `					    __le32 coptions,`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `					    umode_t mode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	int oflags = O_NONBLOCK | O_LARGEFILE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	if (coptions & FILE_DIRECTORY_FILE_LE || S_ISDIR(mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		access &= ~FILE_WRITE_DESIRE_ACCESS_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		ksmbd_debug(SMB, "Discard write access to a directory\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	if (access & FILE_READ_DESIRED_ACCESS_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	    access & FILE_WRITE_DESIRE_ACCESS_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		oflags |= O_RDWR;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		*may_flags = MAY_OPEN | MAY_READ | MAY_WRITE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	} else if (access & FILE_WRITE_DESIRE_ACCESS_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `		oflags |= O_WRONLY;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		*may_flags = MAY_OPEN | MAY_WRITE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `		oflags |= O_RDONLY;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		*may_flags = MAY_OPEN | MAY_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	if (access == FILE_READ_ATTRIBUTES_LE || S_ISBLK(mode) || S_ISCHR(mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		oflags |= O_PATH;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	if (file_present) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `		switch (disposition & FILE_CREATE_MASK_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `		case FILE_OPEN_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `		case FILE_CREATE_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `		case FILE_SUPERSEDE_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		case FILE_OVERWRITE_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `		case FILE_OVERWRITE_IF_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `			oflags |= O_TRUNC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		switch (disposition & FILE_CREATE_MASK_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		case FILE_SUPERSEDE_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		case FILE_CREATE_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		case FILE_OPEN_IF_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		case FILE_OVERWRITE_IF_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `			oflags |= O_CREAT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `		case FILE_OPEN_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		case FILE_OVERWRITE_LE:`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `			oflags &= ~O_CREAT;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	return oflags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_create_open_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` * smb_check_parent_dacl_deny() - Check parent directory DACL for deny ACEs`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ` * @conn:	SMB connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * @parent:	path to the parent directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` * @uid:	user ID attempting the operation`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * @is_dir:	true if creating a subdirectory, false if creating a file`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * Checks the parent directory's stored Windows ACL for DENY ACEs that`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` * would prevent creating files (SEC_DIR_ADD_FILE = 0x02) or subdirectories`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * (SEC_DIR_ADD_SUBDIR = 0x04) within it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` * This implements Windows-style ACL enforcement for create operations,`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * where DENY ACEs on a parent directory are evaluated before allowing`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * the creation of child entries.`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` * Return:	0 if creation is allowed, -EACCES if denied`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `VISIBLE_IF_KUNIT int smb_check_parent_dacl_deny(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `						 const struct path *parent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `						 int uid, bool is_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	/* S-1-1-0 (Everyone / World) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	static const struct smb_sid everyone_sid = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		1, 1, {0, 0, 0, 0, 0, 1}, {0}`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	struct smb_ntsd *pntsd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	struct smb_acl *pdacl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	struct smb_ace *ace;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	struct smb_sid user_sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	int pntsd_size, acl_size, aces_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	unsigned int dacl_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	size_t dacl_struct_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	unsigned short ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	u32 check_mask;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	int i, rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(parent->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(parent->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	/* FILE_ADD_FILE = 0x02, FILE_ADD_SUBDIRECTORY = 0x04 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	check_mask = is_dir ? 0x04 : 0x02;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	pntsd_size = ksmbd_vfs_get_sd_xattr(conn, user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `					     parent->dentry, &pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	if (pntsd_size <= 0 || !pntsd)`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	dacl_offset = le32_to_cpu(pntsd->dacloffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	if (!dacl_offset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [MEM_BOUNDS|] `	    check_add_overflow(dacl_offset, sizeof(struct smb_acl),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00190 [NONE] `			       &dacl_struct_end) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	    dacl_struct_end > (size_t)pntsd_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	pdacl = (struct smb_acl *)((char *)pntsd + dacl_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	acl_size = pntsd_size - dacl_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	if (le16_to_cpu(pdacl->size) > acl_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	    le16_to_cpu(pdacl->size) < sizeof(struct smb_acl) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	    !pdacl->num_aces) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	/* Build user SID for comparison */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	id_to_sid(uid, uid ? SIDOWNER : SIDUNIX_USER, &user_sid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	 * Walk all ACEs in order (per Windows ACL evaluation: DENY`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	 * ACEs should appear before ALLOW ACEs in a canonical DACL).`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	 * If any applicable DENY ACE blocks the requested access,`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [ERROR_PATH|] `	 * return -EACCES.`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00214 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	ace = (struct smb_ace *)((char *)pdacl + sizeof(struct smb_acl));`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	aces_size = acl_size - sizeof(struct smb_acl);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	for (i = 0; i < le16_to_cpu(pdacl->num_aces); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `		bool applies;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		if (offsetof(struct smb_ace, access_req) > aces_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		ace_size = le16_to_cpu(ace->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		 * Minimum ACE size: type(1) + flags(1) + size(2) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		 * access_req(4) + SID base(8) = 16 bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		 * Note: sizeof(struct smb_ace) includes the max-size`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		 * SID array which is much larger than actual ACEs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `		if (ace_size > aces_size || ace_size < 16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		/* Does this ACE apply to our user? */`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		applies = (!compare_sids(&user_sid, &ace->sid) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `			   !compare_sids(&everyone_sid, &ace->sid));`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		if (applies &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `		    (ace->type == ACCESS_DENIED_ACE_TYPE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `		     ace->type == ACCESS_DENIED_CALLBACK_ACE_TYPE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		    (le32_to_cpu(ace->access_req) & check_mask)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `				    "Parent DACL denies %s creation (ACE type=%d mask=0x%x)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `				    is_dir ? "subdir" : "file",`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `				    ace->type,`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `				    le32_to_cpu(ace->access_req));`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `		aces_size -= ace_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `		ace = (struct smb_ace *)((char *)ace + ace_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb_check_parent_dacl_deny);`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ` * create_smb2_pipe() - create IPC pipe`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ` * @work:	smb work containing request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `static noinline int create_smb2_pipe(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	struct smb2_create_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	struct smb2_create_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	int id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	char *name = ERR_PTR(-EINVAL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	if ((u64)le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	    get_rfc1002_len(work->request_buf) + 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00277 [NONE] `		err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00279 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	name = smb_strndup_from_utf16((char *)req + le16_to_cpu(req->NameOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `				      le16_to_cpu(req->NameLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `				      1, work->conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	if (IS_ERR(name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_MEMORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00286 [NONE] `		err = PTR_ERR(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00288 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	id = ksmbd_session_rpc_open(work->sess, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	if (id < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [ERROR_PATH|] `		pr_err("Unable to open RPC pipe: %d\n", id);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00293 [NONE] `		err = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00295 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [PROTO_GATE|] `	rsp->hdr.Status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00298 [NONE] `	rsp->StructureSize = cpu_to_le16(89);`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [PROTO_GATE|] `	rsp->OplockLevel = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00300 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	rsp->CreateAction = cpu_to_le32(FILE_OPENED);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	rsp->CreationTime = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	rsp->LastAccessTime = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	rsp->ChangeTime = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `	rsp->AllocationSize = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	rsp->EndofFile = cpu_to_le64(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `	rsp->FileAttributes = ATTR_NORMAL_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `	rsp->VolatileFileId = id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	rsp->PersistentFileId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	rsp->CreateContextsOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	rsp->CreateContextsLength = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	err = ksmbd_iov_pin_rsp(work, rsp, offsetof(struct smb2_create_rsp, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `	switch (err) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `	case -EINVAL:`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00326 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `	case -ENOSPC:`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	case -ENOMEM:`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_MEMORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00330 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `	if (!IS_ERR(name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * smb2_set_ea() - handler for setting extended attributes using set`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` *		info command`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` * @eabuf:	set info command buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ` * @buf_len:	set info command buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ` * @path:	dentry path for get ea`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ` * @get_write:	get write access to a mount`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `int smb2_set_ea(struct smb2_ea_info *eabuf, unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		       const struct path *path, bool get_write)`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	char *attr_name = NULL, *value;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `	unsigned int next = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	if (buf_len < sizeof(struct smb2_ea_info) + eabuf->EaNameLength +`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `			le16_to_cpu(eabuf->EaValueLength))`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [MEM_BOUNDS|] `	attr_name = kmalloc(XATTR_NAME_MAX + 1, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00367 [NONE] `	if (!attr_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00369 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		if (!eabuf->EaNameLength)`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [ERROR_PATH|] `			goto next;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `			    "name : <%s>, name_len : %u, value_len : %u, next : %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `			    eabuf->name, eabuf->EaNameLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `			    le16_to_cpu(eabuf->EaValueLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `			    le32_to_cpu(eabuf->NextEntryOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `		if (eabuf->EaNameLength >`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `		    (XATTR_NAME_MAX - XATTR_USER_PREFIX_LEN)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [MEM_BOUNDS|] `		memcpy(attr_name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00387 [MEM_BOUNDS|] `		memcpy(&attr_name[XATTR_USER_PREFIX_LEN], eabuf->name,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00388 [NONE] `		       eabuf->EaNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		attr_name[XATTR_USER_PREFIX_LEN + eabuf->EaNameLength] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `		value = (char *)&eabuf->name + eabuf->EaNameLength + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `		if (!eabuf->EaValueLength) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `			rc = ksmbd_vfs_casexattr_len(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `			rc = ksmbd_vfs_casexattr_len(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `						     path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `						     attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `						     XATTR_USER_PREFIX_LEN +`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `						     eabuf->EaNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `			/* delete the EA only when it exits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `			if (rc > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `				rc = ksmbd_vfs_remove_xattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `				rc = ksmbd_vfs_remove_xattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `							    path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `							    attr_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `							    get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `				if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `						    "remove xattr failed(%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `						    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `			/* if the EA doesn't exist, just do nothing. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `			rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `			rc = ksmbd_vfs_setxattr(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `			rc = ksmbd_vfs_setxattr(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `						path, attr_name, value,`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `						le16_to_cpu(eabuf->EaValueLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `						0, get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `			if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `					    "ksmbd_vfs_setxattr is failed(%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `					    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `next:`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `		next = le32_to_cpu(eabuf->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		if (next == 0 || buf_len < next)`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		buf_len -= next;`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `		eabuf = (struct smb2_ea_info *)((char *)eabuf + next);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `		if (buf_len < sizeof(struct smb2_ea_info)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] `		if (buf_len < sizeof(struct smb2_ea_info) + eabuf->EaNameLength +`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `				le16_to_cpu(eabuf->EaValueLength)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	} while (next != 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	kfree(attr_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `static noinline int smb2_set_stream_name_xattr(const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `					       struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `					       char *stream_name, int s_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	size_t xattr_stream_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	char *xattr_stream_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	rc = ksmbd_vfs_xattr_stream_name(stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `					 &xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `					 &xattr_stream_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `					 s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	fp->stream.name = xattr_stream_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	fp->stream.size = xattr_stream_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	/* Check if there is stream prefix in xattr space */`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	rc = ksmbd_vfs_casexattr_len(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	rc = ksmbd_vfs_casexattr_len(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `				     path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `				     xattr_stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `				     xattr_stream_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	if (rc >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `		 * Stream xattr exists on disk.  Replace fp->stream.name`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `		 * with the on-disk name so that normalized-name queries`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		 * return the canonical (creation-time) casing, not the`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `		 * casing the client used for this particular open.`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `		char *xattr_list = NULL, *n;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `		ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `		xattr_list_len = ksmbd_vfs_listxattr(path->dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `						     &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `		if (xattr_list_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `			for (n = xattr_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `			     n - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `			     n += strlen(n) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `				if (strncasecmp(xattr_stream_name, n,`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `						xattr_stream_size))`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `				if (strcmp(xattr_stream_name, n)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `					char *dup = kstrdup(n,`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `							    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `					if (dup) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `						kfree(fp->stream.name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `						fp->stream.name = dup;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `						fp->stream.size = strlen(dup) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `		kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	if (fp->cdoption == FILE_OPEN_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `		ksmbd_debug(SMB, "XATTR stream name lookup failed: %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00533 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	rc = ksmbd_vfs_setxattr(idmap, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	rc = ksmbd_vfs_setxattr(user_ns, path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `				xattr_stream_name, NULL, 0, 0, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [ERROR_PATH|] `		pr_err("Failed to store XATTR stream name :%d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00543 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `static int smb2_remove_smb_xattrs(const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	char *name, *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	int err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	if (xattr_list_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00560 [NONE] `	} else if (!xattr_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `		ksmbd_debug(SMB, "empty xattr in the file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00563 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `	for (name = xattr_list; name - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `			name += strlen(name) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		ksmbd_debug(SMB, "%s, len %zd\n", name, strlen(name));`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		if (!strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		    !strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `			     STREAM_PREFIX_LEN)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `			err = ksmbd_vfs_remove_xattr(idmap, path, name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `			err = ksmbd_vfs_remove_xattr(user_ns, path, name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `			if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `				ksmbd_debug(SMB, "remove xattr failed : %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `					    name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] ` * C.4: Remove user extended attributes (EAs) that are not SMB streams.`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] ` * MS-SMB2 §3.3.5.9: FILE_SUPERSEDE must reset the file to a clean state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] ` * including removing all user EAs.  Stream xattrs (user.DosStream.*) are`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] ` * already removed by smb2_remove_smb_xattrs(); this function removes the`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] ` * remaining user.* xattrs (i.e. real SMB EAs).`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ` * Errors are non-fatal: best-effort removal only.`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `static void smb2_remove_user_eas(const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	char *name, *xattr_list = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `	ssize_t xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `	int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	xattr_list_len = ksmbd_vfs_listxattr(path->dentry, &xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	if (xattr_list_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	for (name = xattr_list; name - xattr_list < xattr_list_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	     name += strlen(name) + 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		/* Only touch user.* xattrs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		if (strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `		/* Skip stream xattrs — handled by smb2_remove_smb_xattrs() */`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], STREAM_PREFIX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `			     STREAM_PREFIX_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		/* Skip the DOS attribute xattr */`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		if (!strncmp(&name[XATTR_USER_PREFIX_LEN], "DOSATTRIB",`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `			     strlen("DOSATTRIB")))`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		err = ksmbd_vfs_remove_xattr(idmap, path, name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		err = ksmbd_vfs_remove_xattr(user_ns, path, name, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		if (err)`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `				    "C.4: remove user EA failed: %s err=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `				    name, err);`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `	kvfree(xattr_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `static int smb2_create_truncate(const struct path *path, bool is_supersede)`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `	struct mnt_idmap *idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `	struct user_namespace *user_ns = mnt_user_ns(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	int rc = vfs_truncate(path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [ERROR_PATH|] `		pr_err("vfs_truncate failed, rc %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00647 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	rc = smb2_remove_smb_xattrs(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	if (rc == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `			    "ksmbd_truncate_stream_name_xattr failed, rc %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `			    rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	 * C.4: FILE_SUPERSEDE must reset all file metadata.`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `	 * Remove the stored security descriptor xattr so the`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	 * new create's SD (or the inherited SD) takes effect.`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	 * Ignore errors — removal is best-effort on SUPERSEDE.`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `	ksmbd_vfs_remove_sd_xattrs(idmap, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	ksmbd_vfs_remove_sd_xattrs(user_ns, path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	 * C.4 (continued): On FILE_SUPERSEDE only, also remove all`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	 * user extended attributes (SMB EAs).  FILE_OVERWRITE and`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	 * FILE_OVERWRITE_IF preserve EAs; SUPERSEDE must clear them.`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	 * MS-SMB2 §3.3.5.9.`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	if (is_supersede)`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `		smb2_remove_user_eas(path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `static void smb2_new_xattrs(struct ksmbd_tree_connect *tcon, const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `			    struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `	struct xattr_dos_attrib da = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] `	if (!test_share_config_flag(tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `				    KSMBD_SHARE_FLAG_STORE_DOS_ATTRS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `	da.version = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	da.attr = le32_to_cpu(fp->f_ci->m_fattr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	da.itime = da.create_time = fp->create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	da.flags = XATTR_DOSINFO_ATTRIB | XATTR_DOSINFO_CREATE_TIME |`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `		XATTR_DOSINFO_ITIME;`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	rc = compat_ksmbd_vfs_set_dos_attrib_xattr(path, &da, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `		ksmbd_debug(SMB, "failed to store file attribute into xattr\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `static void smb2_update_xattrs(struct ksmbd_tree_connect *tcon,`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] `			       const struct path *path, struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	struct xattr_dos_attrib da;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	fp->f_ci->m_fattr &= ~(ATTR_HIDDEN_LE | ATTR_SYSTEM_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	/* get FileAttributes from XATTR_NAME_DOS_ATTRIBUTE */`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	if (!test_share_config_flag(tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `				    KSMBD_SHARE_FLAG_STORE_DOS_ATTRS))`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	rc = compat_ksmbd_vfs_get_dos_attrib_xattr(path, path->dentry, &da);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	if (rc > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `		fp->f_ci->m_fattr = cpu_to_le32(da.attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `		fp->create_time = da.create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `		fp->itime = da.itime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `static int smb2_creat(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `		      struct path *path, char *name, int open_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `		      umode_t posix_mode, bool is_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `static int smb2_creat(struct ksmbd_work *work, struct path *path, char *name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `		      int open_flags, umode_t posix_mode, bool is_dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	struct ksmbd_tree_connect *tcon = work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	struct ksmbd_share_config *share = tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `	umode_t mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	if (!(open_flags & O_CREAT))`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [ERROR_PATH|] `		return -EBADF;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00740 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	ksmbd_debug(SMB, "file does not exist, so creating\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	if (is_dir == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `		ksmbd_debug(SMB, "creating directory\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		mode = share_config_directory_mode(share, posix_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] `		rc = ksmbd_vfs_mkdir(work, name, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `		ksmbd_debug(SMB, "creating regular file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `		mode = share_config_create_mode(share, posix_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `		rc = ksmbd_vfs_create(work, name, mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `	rc = ksmbd_vfs_kern_path(work, name, 0, path, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [ERROR_PATH|] `		pr_err("cannot get linux path (%s), err = %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00761 [NONE] `		       name, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `VISIBLE_IF_KUNIT int smb2_create_sd_buffer(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `					   struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `					   const struct path *path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `	struct create_context *context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	struct create_sd_buf_req *sd_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	if (!req->CreateContextsOffset)`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00776 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	/* Parse SD BUFFER create contexts */`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [PROTO_GATE|] `	context = smb2_find_context_vals(req, SMB2_CREATE_SD_BUFFER, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00779 [NONE] `	if (!context)`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00781 [NONE] `	else if (IS_ERR(context))`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `		return PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [PROTO_GATE|] `		    "Set ACLs using SMB2_CREATE_SD_BUFFER context\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00786 [NONE] `	sd_buf = (struct create_sd_buf_req *)context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	    le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	    sizeof(struct create_sd_buf_req))`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00791 [NONE] `	return set_info_sec(work->conn, work->tcon, path, &sd_buf->ntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `			    le32_to_cpu(sd_buf->ccontext.DataLength), true, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `EXPORT_SYMBOL_IF_KUNIT(smb2_create_sd_buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `void ksmbd_acls_fattr(struct smb_fattr *fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `			     struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `			     struct user_namespace *mnt_userns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `			     struct inode *inode)`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	vfsuid_t vfsuid = i_uid_into_vfsuid(mnt_userns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	vfsgid_t vfsgid = i_gid_into_vfsgid(mnt_userns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `	fattr->cf_uid = vfsuid_into_kuid(vfsuid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	fattr->cf_gid = vfsgid_into_kgid(vfsgid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	fattr->cf_uid = i_uid_into_mnt(mnt_userns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `	fattr->cf_gid = i_gid_into_mnt(mnt_userns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `	fattr->cf_uid = inode->i_uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `	fattr->cf_gid = inode->i_gid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `	fattr->cf_mode = inode->i_mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `	fattr->cf_acls = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `	fattr->cf_dacls = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	if (IS_ENABLED(CONFIG_FS_POSIX_ACL)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `		fattr->cf_acls = get_inode_acl(inode, ACL_TYPE_ACCESS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		fattr->cf_acls = get_acl(inode, ACL_TYPE_ACCESS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `		if (S_ISDIR(inode->i_mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `			fattr->cf_dacls = get_inode_acl(inode, ACL_TYPE_DEFAULT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `			fattr->cf_dacls = get_acl(inode, ACL_TYPE_DEFAULT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `	DURABLE_RECONN_V2 = 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `	DURABLE_RECONN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `	DURABLE_REQ_V2,`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `	DURABLE_REQ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `struct durable_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	struct ksmbd_file *fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	unsigned short int type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	bool persistent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `	bool reconnected;`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `	bool is_replay;`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	unsigned int timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `	char *CreateGuid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] ` * CR5: Persistent durable handle on-disk state helpers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [PROTO_GATE|] ` * Persistent handles (created with DH2Q + SMB2_DHANDLE_FLAG_PERSISTENT) should`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00864 [NONE] ` * survive server restarts.  The full implementation requires tmpfs-backed state`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] ` * files, but this is complex to do correctly in kernel context.  These stubs`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] ` * mark the points where persistence is needed and emit a WARN_ONCE so that the`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] ` * missing implementation is visible in dmesg.`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] ` * Future work: implement using filp_open("/tmp/ksmbd_ph/<guid>") +`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] ` * kernel_write() in ksmbd_ph_save(), kern_path() + kernel_read() in`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] ` * ksmbd_ph_restore(), and kern_path() + vfs_unlink() in ksmbd_ph_delete().`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] ` * On-disk structure (for future implementation):`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] ` *   struct ksmbd_persistent_handle_state {`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] ` *       __u8  guid[16];           - persistent handle GUID`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] ` *       __u8  lease_key[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] ` *       __u64 session_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] ` *       __u32 tree_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] ` *       char  share_name[256];`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] ` *       char  file_path[1024];`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] ` *       __u32 desired_access;`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] ` *       __u32 file_attributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ` *       __u32 create_options;`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ` *       __u64 durable_timeout_ms;`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] ` *   };`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] ` * ksmbd_ph_save() - Persist a durable handle's state to stable storage.`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] ` * @fp: the ksmbd_file with is_persistent set`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] ` * TODO: write state to /tmp/ksmbd_ph/<guid> using filp_open + kernel_write.`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `static void ksmbd_ph_save(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `	/* TODO: persistent handle state — save to /tmp/ksmbd_ph/<guid> */`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `	WARN_ONCE(1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		  "ksmbd: persistent handle save not implemented (guid %16phN)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		  fp->create_guid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] ` * ksmbd_ph_restore() - Attempt to restore a persistent handle from disk.`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] ` * @persistent_id: the persistent file ID from the DH2C reconnect request`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] ` * @guid: the CreateGuid from the DH2C request`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] ` * TODO: read state from /tmp/ksmbd_ph/<guid> using kern_path + kernel_read.`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] ` * Return: pointer to restored ksmbd_file on success, NULL if not found.`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `static struct ksmbd_file *ksmbd_ph_restore(u64 persistent_id, const char *guid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	/* TODO: persistent handle restore — read from /tmp/ksmbd_ph/<guid> */`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	(void)persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `	(void)guid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] ` * ksmbd_ph_delete() - Remove a persistent handle's state file from disk.`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] ` * @fp: the ksmbd_file whose state file should be deleted`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] ` * Called on handle close (from __ksmbd_close_fd in vfs_cache.c) to clean up`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] ` * the on-disk state for persistent handles.`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] ` * TODO: delete /tmp/ksmbd_ph/<guid> using kern_path + vfs_unlink.`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `static void __maybe_unused ksmbd_ph_delete(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `	/* TODO: persistent handle delete — remove /tmp/ksmbd_ph/<guid> */`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `	(void)fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `VISIBLE_IF_KUNIT int parse_durable_handle_context(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `						   struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `						   struct lease_ctx_info *lc,`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `						   struct durable_info *dh_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	struct create_context *context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	int dh_idx, err = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	u64 persistent_id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `	int req_op_level;`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	static const char * const durable_arr[] = {"DH2C", "DHnC", "DH2Q", "DHnQ"};`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	req_op_level = req->RequestedOplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	for (dh_idx = DURABLE_RECONN_V2; dh_idx <= ARRAY_SIZE(durable_arr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	     dh_idx++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `		context = smb2_find_context_vals(req, durable_arr[dh_idx - 1], 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `		if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `			err = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00952 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `		if (!context)`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `		switch (dh_idx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `		case DURABLE_RECONN_V2:`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `			struct create_durable_reconn_v2_req *recon_v2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `			if (dh_info->type == DURABLE_RECONN ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `			    dh_info->type == DURABLE_REQ_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00965 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `			if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `				le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `			    sizeof(struct create_durable_reconn_v2_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00972 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `			recon_v2 = (struct create_durable_reconn_v2_req *)context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `			persistent_id = recon_v2->Fid.PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `			dh_info->fp = ksmbd_lookup_durable_fd(persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `			if (!dh_info->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `				 * CR5: If the in-memory durable handle was lost`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `				 * (e.g. server restart), attempt to restore from`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `				 * the on-disk persistent handle state.`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `				 * ksmbd_ph_restore() is a stub — full`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `				 * implementation pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `				dh_info->fp = ksmbd_ph_restore(`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `					persistent_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `					recon_v2->CreateGuid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `				if (!dh_info->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `						    "Failed to get durable handle state\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `					err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00993 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `			if (memcmp(dh_info->fp->create_guid, recon_v2->CreateGuid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [PROTO_GATE|] `				   SMB2_CREATE_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00998 [NONE] `				err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `				ksmbd_put_durable_fd(dh_info->fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01001 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `			/* Validate client identity to prevent durable handle theft */`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `			if (memcmp(dh_info->fp->client_guid, conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [PROTO_GATE|] `				   SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01006 [ERROR_PATH|] `				pr_err_ratelimited("durable reconnect v2: client GUID mismatch\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01007 [NONE] `				err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `				ksmbd_put_durable_fd(dh_info->fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01010 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `			dh_info->type = dh_idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `			dh_info->reconnected = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `				"reconnect v2 Persistent-id from reconnect = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `					persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `		case DURABLE_RECONN:`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `			struct create_durable_reconn_req *recon;`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `			if (dh_info->type == DURABLE_RECONN_V2 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `			    dh_info->type == DURABLE_REQ_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01027 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `			if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `				le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `			    sizeof(struct create_durable_reconn_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01034 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `			recon = (struct create_durable_reconn_req *)context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `			persistent_id = recon->Data.Fid.PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `			dh_info->fp = ksmbd_lookup_durable_fd(persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `			if (!dh_info->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `				ksmbd_debug(SMB, "Failed to get durable handle state\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `				err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01043 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `			/* Validate client identity to prevent durable handle theft */`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `			if (memcmp(dh_info->fp->client_guid, conn->ClientGUID,`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [PROTO_GATE|] `				   SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01048 [ERROR_PATH|] `				pr_err_ratelimited("durable reconnect: client GUID mismatch\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01049 [NONE] `				err = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `				ksmbd_put_durable_fd(dh_info->fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01052 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `			dh_info->type = dh_idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `			dh_info->reconnected = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `			ksmbd_debug(SMB, "reconnect Persistent-id from reconnect = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `				    persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `		case DURABLE_REQ_V2:`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `			struct create_durable_req_v2 *durable_v2_blob;`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `			if (dh_info->type == DURABLE_RECONN ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] `			    dh_info->type == DURABLE_RECONN_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01068 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `			if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `				le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `			    sizeof(struct create_durable_req_v2)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01075 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `			durable_v2_blob =`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `				(struct create_durable_req_v2 *)context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `			ksmbd_debug(SMB, "Request for durable v2 open\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `			dh_info->fp = ksmbd_lookup_fd_cguid(durable_v2_blob->CreateGuid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `			if (dh_info->fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `				if (!memcmp(conn->ClientGUID, dh_info->fp->client_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [PROTO_GATE|] `					    SMB2_CLIENT_GUID_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01084 [PROTO_GATE|] `					if (!(req->hdr.Flags & SMB2_FLAGS_REPLAY_OPERATIONS)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01085 [NONE] `						err = -ENOEXEC;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [ERROR_PATH|] `						goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01087 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `					/* DHv2 replay (MS-SMB2 3.3.5.9.10) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `					dh_info->is_replay = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `					dh_info->type = DURABLE_REQ_V2;`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [ERROR_PATH|] `					goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01093 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [PROTO_GATE|] `			if ((lc && (lc->req_state & SMB2_LEASE_HANDLE_CACHING_LE)) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01097 [PROTO_GATE|] `			    req_op_level == SMB2_OPLOCK_LEVEL_BATCH) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01098 [NONE] `				dh_info->CreateGuid =`
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `					durable_v2_blob->CreateGuid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `				dh_info->persistent =`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `					le32_to_cpu(durable_v2_blob->Flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `				dh_info->timeout =`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `					le32_to_cpu(durable_v2_blob->Timeout);`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] `				dh_info->type = dh_idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `		case DURABLE_REQ:`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `			if (dh_info->type == DURABLE_RECONN)`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01111 [NONE] `			if (dh_info->type == DURABLE_RECONN_V2 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `			    dh_info->type == DURABLE_REQ_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `				err = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01115 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [PROTO_GATE|] `			if ((lc && (lc->req_state & SMB2_LEASE_HANDLE_CACHING_LE)) ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01118 [PROTO_GATE|] `			    req_op_level == SMB2_OPLOCK_LEVEL_BATCH) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01119 [NONE] `				ksmbd_debug(SMB, "Request for durable open\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `				dh_info->type = dh_idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `	return err;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `EXPORT_SYMBOL_IF_KUNIT(parse_durable_handle_context);`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `static int smb2_dispatch_create_context_handlers_pass(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `						      struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `						      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] `						      bool app_instance_id_only)`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] `	struct create_context *cc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `	unsigned int next = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	unsigned int remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	if (!req->CreateContextsOffset || !req->CreateContextsLength)`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	cc = (struct create_context *)((char *)req +`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `				       le32_to_cpu(req->CreateContextsOffset));`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	remain_len = le32_to_cpu(req->CreateContextsLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `		struct ksmbd_create_ctx_handler *h;`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `		char *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `		void *ctx_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `		unsigned int name_off, name_len, value_off, value_len, cc_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `		bool is_app_instance_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `		int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `		cc = (struct create_context *)((char *)cc + next);`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `		if (remain_len < offsetof(struct create_context, Buffer))`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `		next = le32_to_cpu(cc->Next);`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `		name_off = le16_to_cpu(cc->NameOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `		name_len = le16_to_cpu(cc->NameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `		value_off = le16_to_cpu(cc->DataOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `		value_len = le32_to_cpu(cc->DataLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `		cc_len = next ? next : remain_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `		if ((next & 0x7) != 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `		    next > remain_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `		    name_off != offsetof(struct create_context, Buffer) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `		    name_len < 4 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `		    name_off + name_len > cc_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `		    (value_off & 0x7) != 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `		    (value_len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `		     value_off < name_off + (name_len < 8 ? 8 : name_len)) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `		    (u64)value_off + value_len > cc_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `		name = (char *)cc + name_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `		ctx_data = (char *)cc + value_off;`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `		is_app_instance_id =`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `			(name_len == 16 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [PROTO_GATE|] `			 !memcmp(name, SMB2_CREATE_APP_INSTANCE_ID, 16));`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01181 [NONE] `		if (is_app_instance_id != app_instance_id_only)`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [ERROR_PATH|] `			goto next_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `		h = ksmbd_find_create_context(name, name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `		if (!h)`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [ERROR_PATH|] `			goto next_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `		if (!h->on_request) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `			ksmbd_put_create_context(h);`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [ERROR_PATH|] `			goto next_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01191 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		rc = h->on_request(work, fp, ctx_data, value_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `		ksmbd_put_create_context(h);`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `next_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `		remain_len -= next;`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	} while (next != 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `static int smb2_dispatch_registered_create_contexts(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `						    struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `						    struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `	 * Process APP_INSTANCE_VERSION before APP_INSTANCE_ID to preserve`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	 * version-aware close semantics regardless of request context order.`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	rc = smb2_dispatch_create_context_handlers_pass(work, req, fp, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `	return smb2_dispatch_create_context_handlers_pass(work, req, fp, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] `static int smb2_resolve_open_by_file_id(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `						struct smb2_create_req *req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `						char **name)`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `	__le64 file_id_le[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `	u64 volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `	u64 persistent_id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	unsigned int name_len = le16_to_cpu(req->NameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	unsigned int name_off = le16_to_cpu(req->NameOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	struct ksmbd_file *id_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	char *path_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	if (name_len != sizeof(__le64) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	    name_len != 2 * sizeof(__le64))`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	if ((u64)name_off + name_len >`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	    get_rfc1002_len(work->request_buf) + 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [MEM_BOUNDS|] `	memcpy(file_id_le, (char *)req + name_off, name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01243 [NONE] `	volatile_id = le64_to_cpu(file_id_le[0]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `	if (name_len == 2 * sizeof(__le64))`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `		persistent_id = le64_to_cpu(file_id_le[1]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	if (persistent_id != KSMBD_NO_FID)`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `		id_fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `		id_fp = ksmbd_lookup_fd_fast(work, volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	if (!id_fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01253 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	path_name = convert_to_nt_pathname(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `					   &id_fp->filp->f_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	ksmbd_fd_put(work, id_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	if (IS_ERR(path_name))`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `		return PTR_ERR(path_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `	ksmbd_conv_path_to_unix(path_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	if (path_name[0] == '/')`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [MEM_BOUNDS|] `		memmove(path_name, path_name + 1, strlen(path_name));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01263 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	*name = path_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] ` * smb2_open() - handler for smb file open request`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] ` * @work:	smb work containing request buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] ` * Return:      0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `int smb2_open(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `	struct ksmbd_session *sess = work->sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `	struct ksmbd_tree_connect *tcon = work->tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `	struct smb2_create_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	struct smb2_create_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	struct path path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `	struct ksmbd_share_config *share = tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `	struct ksmbd_file *fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	struct file *filp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `	struct mnt_idmap *idmap = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `	struct user_namespace *user_ns = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	struct kstat stat;`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `	struct create_context *context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `	struct lease_ctx_info *lc = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] `	struct create_ea_buf_req *ea_buf = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `	struct oplock_info *opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	struct durable_info dh_info = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	__le32 *next_ptr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `	int req_op_level = 0, open_flags = 0, may_flags = 0, file_info = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `	int contxt_cnt = 0, query_disk_id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	int fruit_ctxt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `	bool maximal_access_ctxt = false, posix_ctxt = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `	int s_type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `	int next_off = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `	char *name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `	char *stream_name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `	char *twrp_snap_path = NULL; /* snapshot path from TWrp context */`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `	bool file_present = false, created = false, already_permitted = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `	bool is_fake_file = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	int share_ret, need_truncate = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `	umode_t posix_mode = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	__le32 daccess, maximal_access = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `	int iov_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	ksmbd_debug(SMB, "Received smb2 create request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [PROTO_GATE|] `	if (req->hdr.NextCommand && !work->next_smb2_rcv_hdr_off &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01322 [PROTO_GATE|] `	    (req->hdr.Flags & SMB2_FLAGS_RELATED_OPERATIONS)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01323 [NONE] `		ksmbd_debug(SMB, "invalid flag in chained command\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01325 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01327 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_PIPE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `		ksmbd_debug(SMB, "IPC pipe create request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `		return create_smb2_pipe(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	if (req->CreateContextsOffset && tcon->posix_extensions) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [PROTO_GATE|] `		context = smb2_find_context_vals(req, SMB2_CREATE_TAG_POSIX, 16);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01336 [NONE] `		if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `			rc = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01339 [NONE] `		} else if (context) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `			struct create_posix *posix = (struct create_posix *)context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `			if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `				le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `			    sizeof(struct create_posix) - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01347 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `			ksmbd_debug(SMB, "get posix context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `			posix_mode = le32_to_cpu(posix->Mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `			posix_ctxt = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	if (req->NameLength) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `		/* MS-SMB2 §2.2.13: NameLength MUST be a multiple of 2 (UTF-16LE) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `		if (le16_to_cpu(req->NameLength) & 1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01360 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `		if ((u64)le16_to_cpu(req->NameOffset) + le16_to_cpu(req->NameLength) >`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `		    get_rfc1002_len(work->request_buf) + 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01366 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `		if (req->CreateOptions & FILE_OPEN_BY_FILE_ID_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `			rc = smb2_resolve_open_by_file_id(work, req, &name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] `				if (rc == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `					rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01374 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `			/* Strip the flag so the rest of the path`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `			 * proceeds normally with the resolved name.`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `			req->CreateOptions &= ~FILE_OPEN_BY_FILE_ID_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `			name = smb2_get_name((char *)req + le16_to_cpu(req->NameOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `					     le16_to_cpu(req->NameLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `					     work->conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `			if (IS_ERR(name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `				rc = PTR_ERR(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `				name = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01387 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `		ksmbd_debug(SMB, "converted name = %s\n", name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `		 * Handle NTFS metadata fake files:`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `		 * $Extend\$Quota:$Q:$INDEX_ALLOCATION is a special`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `		 * pseudo-file used by Windows clients to open a handle`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `		 * for quota queries.  Map it to the share root so that`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `		 * subsequent QUERY_INFO / SET_INFO quota requests have`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `		 * a valid file handle bound to the correct filesystem.`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `		if (strncasecmp(name, "$Extend\\$Quota:", 15) == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `		    strncasecmp(name, "$Extend/$Quota:", 15) == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `				    "Quota fake file requested: %s, mapping to share root\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `				    name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `			kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `			name = kstrdup("", KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `			if (!name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `				rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01410 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `			is_fake_file = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] `		if (posix_ctxt == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `			if (strchr(name, ':')) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `				if (!test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `							KSMBD_SHARE_FLAG_STREAMS)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `					rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [ERROR_PATH|] `					goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01420 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `				rc = parse_stream_name(name, &stream_name, &s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `				if (rc < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] `					 * parse_stream_name returns -ENOENT`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `					 * with stream_name=NULL for the`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `					 * default data stream (::$DATA).`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `					 * Treat this as a normal file open.`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `					if (!stream_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `						rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `					} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [ERROR_PATH|] `						goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01433 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `				 * AFP_AfpInfo stream interception: when`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `				 * a macOS client opens the AFP_AfpInfo`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] `				 * named stream, ksmbd serves AFP metadata`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `				 * from xattrs rather than requiring a real`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] `				 * alternate data stream.`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `				if (stream_name &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `				    conn->is_fruit &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `				    ksmbd_fruit_is_afpinfo_stream(stream_name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `					ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `						    "Fruit: AFP_AfpInfo stream for %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `						    name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `			rc = ksmbd_validate_filename(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `			if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01456 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `		if (ksmbd_share_veto_filename(share, name)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `			rc = -ENOENT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `			ksmbd_debug(SMB, "Reject open(), vetoed file: %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `				    name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01463 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `		name = kstrdup("", KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `		if (!name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `			rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01469 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `	req_op_level = req->RequestedOplockLevel;`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `	    req->CreateContextsOffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `		lc = parse_lease_state(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `		rc = parse_durable_handle_context(work, req, lc, &dh_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `			ksmbd_debug(SMB, "error parsing durable handle context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01481 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `		if (dh_info.is_replay) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `			 * DHv2 replay (MS-SMB2 3.3.5.9.10): the handle is`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `			 * still active on this connection.  Validate that`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `			 * replay parameters match the original request.`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `			bool orig_is_lease = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [PROTO_GATE|] `			bool req_is_lease = (req_op_level == SMB2_OPLOCK_LEVEL_LEASE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `			fp = dh_info.fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [LIFETIME|] `			rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01494 [LIFETIME|] `			opinfo = rcu_dereference(fp->f_opinfo);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01495 [NONE] `			if (opinfo && opinfo->is_lease)`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `				orig_is_lease = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01498 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `			/* Reject if oplock type changed or lease key mismatches */`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `			if (orig_is_lease != req_is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `				ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01504 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01505 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `			if (req_is_lease && lc && opinfo && opinfo->o_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `				if (memcmp(lc->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `					   opinfo->o_lease->lease_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [PROTO_GATE|] `					   SMB2_LEASE_KEY_SIZE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01511 [NONE] `					ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `					rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [PROTO_GATE|] `					rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01514 [ERROR_PATH|] `					goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01515 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `			/* Suppress DH2Q if replay has no durable-capable oplock */`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [PROTO_GATE|] `			if (req_op_level != SMB2_OPLOCK_LEVEL_BATCH &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01520 [PROTO_GATE|] `			    req_op_level != SMB2_OPLOCK_LEVEL_LEASE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01521 [NONE] `				dh_info.type = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `			if (ksmbd_override_fsids(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `				rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `				ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01527 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `			file_info = fp->create_action ? fp->create_action`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `						      : FILE_OPENED;`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `			if (fp->replay_cache.valid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `				rsp->StructureSize = cpu_to_le16(89);`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `				rsp->OplockLevel = req_op_level;`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `				rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `				rsp->CreateAction = cpu_to_le32(file_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `				rsp->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `				rsp->LastAccessTime = cpu_to_le64(fp->replay_cache.last_access);`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `				rsp->LastWriteTime = cpu_to_le64(fp->replay_cache.last_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `				rsp->ChangeTime = cpu_to_le64(fp->replay_cache.change);`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `				rsp->AllocationSize = cpu_to_le64(fp->replay_cache.alloc_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `				rsp->EndofFile = cpu_to_le64(fp->replay_cache.end_of_file);`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] `				rsp->FileAttributes = fp->replay_cache.file_attrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `				rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `				rsp->PersistentFileId = fp->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `				rsp->VolatileFileId = fp->volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `				rsp->CreateContextsOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `				rsp->CreateContextsLength = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `				iov_len = offsetof(struct smb2_create_rsp, Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] `				ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [ERROR_PATH|] `				goto durable_create_ctx;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01552 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `			rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `				ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [ERROR_PATH|] `				goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01558 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `			ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [ERROR_PATH|] `			goto reconnected_fp;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01562 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] `		if (dh_info.reconnected == true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `			 * C.7: MS-SMB2 §3.3.5.9.13 step 5 — if the client`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `			 * reconnects with DH2C and Flags has`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [PROTO_GATE|] `			 * SMB2_DHANDLE_FLAG_PERSISTENT set, but the stored`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01569 [NONE] `			 * open is NOT persistent, reject the reconnect.`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `			if (dh_info.type == DURABLE_RECONN_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] `				struct create_context *dh2c_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `				dh2c_ctx = smb2_find_context_vals(req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `								  "DH2C", 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] `				if (!IS_ERR_OR_NULL(dh2c_ctx)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] `					struct create_durable_reconn_v2_req *rv2 =`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `						(struct create_durable_reconn_v2_req *)dh2c_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] `					bool client_wants_persistent =`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `						!!(le32_to_cpu(rv2->Flags) &`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [PROTO_GATE|] `						   SMB2_DHANDLE_FLAG_PERSISTENT);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `					if (client_wants_persistent &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `					    !dh_info.fp->is_persistent) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `						ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `							    "DH2C: client requests persistent but handle is not\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `						rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `						ksmbd_put_durable_fd(dh_info.fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [ERROR_PATH|] `						goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01590 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `			rc = smb2_check_durable_oplock(conn, share, dh_info.fp, lc, name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] `				ksmbd_put_durable_fd(dh_info.fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01598 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] `			rc = ksmbd_reopen_durable_fd(work, dh_info.fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `				ksmbd_put_durable_fd(dh_info.fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01604 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `			if (ksmbd_override_fsids(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `				rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `				ksmbd_put_durable_fd(dh_info.fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01610 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `			fp = dh_info.fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `			file_info = FILE_OPENED;`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `			rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [ERROR_PATH|] `				goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01618 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `			ksmbd_put_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [ERROR_PATH|] `			goto reconnected_fp;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01621 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [PROTO_GATE|] `	} else if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01623 [NONE] `		lc = parse_lease_state(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `	if (le32_to_cpu(req->ImpersonationLevel) > le32_to_cpu(IL_DELEGATE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [ERROR_PATH|] `		pr_err_ratelimited("Invalid impersonationlevel : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01627 [NONE] `				   le32_to_cpu(req->ImpersonationLevel));`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `		rc = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_BAD_IMPERSONATION_LEVEL;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01630 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01631 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `	if (req->CreateOptions && !(req->CreateOptions & CREATE_OPTIONS_MASK)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [ERROR_PATH|] `		pr_err_ratelimited("Invalid create options : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01635 [NONE] `				   le32_to_cpu(req->CreateOptions));`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01638 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `			if (req->CreateOptions & FILE_SEQUENTIAL_ONLY_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `			    req->CreateOptions & FILE_RANDOM_ACCESS_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `				req->CreateOptions &= ~(FILE_SEQUENTIAL_ONLY_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `			if (req->CreateOptions & CREATE_TREE_CONNECTION) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `				rc = -EOPNOTSUPP;`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01646 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `			if (req->CreateOptions & FILE_RESERVE_OPFILTER_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `				rc = -EOPNOTSUPP;`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01651 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `			if (req->CreateOptions & FILE_OPEN_BY_FILE_ID_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `				if (!name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `					rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [ERROR_PATH|] `					goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01657 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `				req->CreateOptions &= ~FILE_OPEN_BY_FILE_ID_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `		if (req->CreateOptions & FILE_DIRECTORY_FILE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `			if (req->CreateOptions & FILE_NON_DIRECTORY_FILE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01665 [NONE] `			} else if (req->CreateOptions & FILE_NO_COMPRESSION_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `				req->CreateOptions &= ~(FILE_NO_COMPRESSION_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `	if (le32_to_cpu(req->CreateDisposition) >`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `	    le32_to_cpu(FILE_OVERWRITE_IF_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [ERROR_PATH|] `		pr_err_ratelimited("Invalid create disposition : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01674 [NONE] `				   le32_to_cpu(req->CreateDisposition));`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01677 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] `	if (!(req->DesiredAccess & DESIRED_ACCESS_MASK)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [ERROR_PATH|] `		pr_err_ratelimited("Invalid desired access : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01681 [NONE] `				   le32_to_cpu(req->DesiredAccess));`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01684 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `	if (req->FileAttributes && !(req->FileAttributes & ATTR_MASK_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [ERROR_PATH|] `		pr_err_ratelimited("Invalid file attribute : 0x%x\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01688 [NONE] `				   le32_to_cpu(req->FileAttributes));`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01691 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `	if ((req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `	    (req->FileAttributes & ATTR_TEMPORARY_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01697 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `	if (req->CreateContextsOffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] `		 * Built-in contexts are parsed inline below. Registered`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] `		 * create context handlers are dispatched post-open once`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `		 * a ksmbd_file exists.`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `		/* Parse non-durable handle create contexts */`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [PROTO_GATE|] `		context = smb2_find_context_vals(req, SMB2_CREATE_EA_BUFFER, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01708 [NONE] `		if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] `			rc = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01711 [NONE] `		} else if (context) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `			ea_buf = (struct create_ea_buf_req *)context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `			if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `			    le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `			    sizeof(struct create_ea_buf_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01718 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `			if (req->CreateOptions & FILE_NO_EA_KNOWLEDGE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01721 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01723 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `		context = smb2_find_context_vals(req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [PROTO_GATE|] `						 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01728 [NONE] `		if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `			rc = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01731 [NONE] `		} else if (context) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `				    "get query maximal access context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `			maximal_access_ctxt = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `		context = smb2_find_context_vals(req,`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [PROTO_GATE|] `						 SMB2_CREATE_TIMEWARP_REQUEST, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01739 [NONE] `		if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `			rc = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [ERROR_PATH|] `			goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01742 [NONE] `		} else if (context) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] `			__le64 *twrp_ts;`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `			u64 nts, unix_ts;`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `			struct tm tm;`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `			char gmt_token[KSMBD_VSS_GMT_TOKEN_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `			char *snap_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `			ksmbd_debug(SMB, "get timewarp context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `			if (le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `			    le32_to_cpu(context->DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] `			    sizeof(__le64)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01756 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `			twrp_ts = (__le64 *)((char *)context +`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `				  le16_to_cpu(context->DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `				  4);`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `			 * Convert Windows FILETIME (100ns intervals`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `			 * since 1601-01-01) to Unix timestamp.`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `			nts = le64_to_cpu(*twrp_ts);`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `			unix_ts = (nts / 10000000ULL) - 11644473600ULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `			time64_to_tm(unix_ts, 0, &tm);`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [MEM_BOUNDS|] `			snprintf(gmt_token, sizeof(gmt_token),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01771 [NONE] `				 "@GMT-%04ld.%02d.%02d-%02d.%02d.%02d",`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `				 tm.tm_year + 1900,`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `				 tm.tm_mon + 1, tm.tm_mday,`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `				 tm.tm_hour, tm.tm_min, tm.tm_sec);`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [MEM_BOUNDS|] `			snap_path = kzalloc(PATH_MAX,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01777 [NONE] `					    KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] `			if (!snap_path) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `				rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01781 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `			rc = ksmbd_vss_resolve_path(share->path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `						    gmt_token,`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `						    snap_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `						    PATH_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `					    "timewarp: no snapshot %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] `					    gmt_token);`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] `				kfree(snap_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `				rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [ERROR_PATH|] `				goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01794 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] `				    "timewarp: resolved snapshot path: %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `				    snap_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `			 * Save the snapshot path; it will replace @name`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `			 * when opening the file so we open the snapshot`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `			 * version rather than the live file.`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `			twrp_snap_path = snap_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	 * C.1/C.10: If a TWrp context resolved to a snapshot path,`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `	 * replace the share-relative filename with the snapshot`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `	 * filesystem path.  The snap_path already contains the full`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `	 * absolute path to the snapshot version of the file.`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `	 * We substitute @name with a relative path derived from`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [NONE] `	 * the snapshot directory so ksmbd_vfs_kern_path can locate it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01815 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `	if (twrp_snap_path) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `		kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] `		name = twrp_snap_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `		twrp_snap_path = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `	if (ksmbd_override_fsids(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01825 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `		 * FILE_OPEN_REPARSE_POINT: open the reparse point (symlink)`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `		 * itself rather than following it.  When this flag is set we`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `		 * must NOT pass LOOKUP_NO_SYMLINKS so the path lookup reaches`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `		 * the symlink dentry without following it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `		unsigned int lookup_flags = LOOKUP_NO_SYMLINKS;`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `		if (req->CreateOptions & FILE_OPEN_REPARSE_POINT_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] `			lookup_flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `		rc = ksmbd_vfs_kern_path(work, name, lookup_flags, &path, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `	if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `		file_present = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `		if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `			 * If file exists with under flags, return access`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `			 * denied error.`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `			if (req->CreateDisposition == FILE_OVERWRITE_IF_LE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `			    req->CreateDisposition == FILE_OPEN_IF_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `				path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01858 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [NONE] `			if (!test_tree_conn_flag(tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] `					    "User does not have write permission\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `				path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01868 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `		} else if (d_is_symlink(path.dentry)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] `			 * FILE_OPEN_REPARSE_POINT: client wants the symlink`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `			 * itself — don't return EACCES; continue with the`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `			 * open so the dentry is passed to dentry_open().`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `			 * For all other opens, symlinks are blocked.`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `			if (!(req->CreateOptions & FILE_OPEN_REPARSE_POINT_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `				path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01882 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `		file_present = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `		idmap = mnt_idmap(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `		user_ns = mnt_user_ns(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `		user_ns = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `		if (rc != -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01898 [NONE] `		ksmbd_debug(SMB, "can not get linux path for %s, rc = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] `			    name, rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `	 * Alternate data streams on directories are valid in SMB.`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `	 * Do NOT reject DATA_STREAM with FILE_DIRECTORY_FILE_LE here;`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `	 * the stream open will proceed on the directory object below.`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `	if (file_present && req->CreateOptions & FILE_NON_DIRECTORY_FILE_LE &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] `	    S_ISDIR(d_inode(path.dentry)->i_mode) && !stream_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `		ksmbd_debug(SMB, "open() argument is a directory: %s, %x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] `			    name, req->CreateOptions);`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01914 [NONE] `		rc = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01916 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `	if (file_present && (req->CreateOptions & FILE_DIRECTORY_FILE_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `	    !(req->CreateDisposition == FILE_CREATE_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] `	    !S_ISDIR(d_inode(path.dentry)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NOT_A_DIRECTORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01922 [NONE] `		rc = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01924 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `	if (!stream_name && file_present &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] `	    req->CreateDisposition == FILE_CREATE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] `		rc = -EEXIST;`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01930 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `	daccess = smb_map_generic_desired_access(req->DesiredAccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] `	if (file_present && !(req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] `		bool had_maximal = !!(daccess & FILE_MAXIMAL_ACCESS_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `		if (!sess->user) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01940 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `		rc = smb_check_perm_dacl(conn, &path, &daccess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `					 sess->user->uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] `		if (rc == -EACCES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `			 * Windows hide-on-access-denied: when the DACL denies`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] `			 * all data access (e.g. an empty DACL with no ACEs),`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [PROTO_GATE|] `			 * return STATUS_OBJECT_NAME_NOT_FOUND to hide the`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01948 [NONE] `			 * file's existence (Windows 7+ behaviour expected by`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `			 * smbtorture --target=win7).  When the DACL grants at`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] `			 * least FILE_READ_ATTRIBUTES the file is "visible" and`
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [PROTO_GATE|] `			 * we return STATUS_ACCESS_DENIED instead.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01952 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `			__le32 ra = FILE_READ_ATTRIBUTES_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `			if (smb_check_perm_dacl(conn, &path, &ra,`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `						 sess->user->uid) == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `				rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01959 [NONE] `		} else if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01961 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `		 * If the original request had MAXIMUM_ALLOWED and`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `		 * smb_check_perm_dacl resolved it using the Windows DACL`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `		 * (replacing daccess with the computed grant, stripping the`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `		 * MAXIMUM_ALLOWED bit), skip the POSIX inode_permission check`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `		 * below — the DACL has already validated access.`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `		if (had_maximal && !(daccess & FILE_MAXIMAL_ACCESS_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `			already_permitted = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `			maximal_access = daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `	if (daccess & FILE_MAXIMAL_ACCESS_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `		if (!file_present) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `			daccess = cpu_to_le32(GENERIC_ALL_FLAGS);`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `			ksmbd_vfs_query_maximal_access(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `						       path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `						       &daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] `			rc = ksmbd_vfs_query_maximal_access(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `							    path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `							    &daccess);`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01989 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] `			already_permitted = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `		maximal_access = daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `	open_flags = smb2_create_open_flags(file_present, daccess,`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `					    req->CreateDisposition,`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `					    &may_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] `					    req->CreateOptions,`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `					    file_present ? d_inode(path.dentry)->i_mode : 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] `	if (!test_tree_conn_flag(tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `		if (open_flags & (O_CREAT | O_TRUNC)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `				    "User does not have write permission\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02007 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `	 * MS-SMB2 3.3.5.9: If the file already exists and the disposition`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `	 * is FILE_OVERWRITE or FILE_OVERWRITE_IF, check for Hidden/System`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `	 * attribute mismatch.  If the existing file has FILE_ATTRIBUTE_HIDDEN`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] `	 * or FILE_ATTRIBUTE_SYSTEM set, and those bits are NOT present in`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] `	 * the request's FileAttributes, the server MUST fail with`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [PROTO_GATE|] `	 * STATUS_ACCESS_DENIED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02017 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `	if (file_present &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `	    (req->CreateDisposition == FILE_OVERWRITE_LE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [NONE] `	     req->CreateDisposition == FILE_OVERWRITE_IF_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [NONE] `	    !S_ISDIR(d_inode(path.dentry)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] `		struct xattr_dos_attrib da = {0};`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] `		int xattr_rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `		xattr_rc = compat_ksmbd_vfs_get_dos_attrib_xattr(&path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `								  path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] `								  &da);`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `		if (xattr_rc >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `			__le32 existing = cpu_to_le32(da.attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `			__le32 requested = req->FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `			if ((existing & ATTR_HIDDEN_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `			    !(requested & ATTR_HIDDEN_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02036 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `			if ((existing & ATTR_SYSTEM_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `			    !(requested & ATTR_SYSTEM_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `				rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02041 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `	/*create file if not present */`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `	if (!file_present) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `		 * Check parent directory DACL for DENY ACEs that`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `		 * would prevent creating files or subdirectories.`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] `		if (sess->user &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `		    test_share_config_flag(tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] `					  KSMBD_SHARE_FLAG_ACL_XATTR)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [NONE] `			struct path parent_path;`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [NONE] `			char *parent_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] `			char *last_sep;`
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `			bool is_dir_create;`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02059 [NONE] `			is_dir_create = !!(req->CreateOptions &`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `					   FILE_DIRECTORY_FILE_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [NONE] `			parent_name = kstrdup(name, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] `			if (parent_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [NONE] `				last_sep = strrchr(parent_name, '/');`
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `				if (last_sep)`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `					*last_sep = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `				else`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `					parent_name[0] = '\0';`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `				rc = ksmbd_vfs_kern_path(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `							 parent_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `							 LOOKUP_NO_SYMLINKS,`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] `							 &parent_path, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `				if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `					rc = smb_check_parent_dacl_deny(`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `						conn, &parent_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] `						sess->user->uid,`
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `						is_dir_create);`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] `					path_put(&parent_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `					/* Parent not found is not a`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] `					 * DACL deny error`
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `					rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] `				kfree(parent_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `				if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [ERROR_PATH|] `					goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02089 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] `		rc = smb2_creat(work, &path, name, open_flags,`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `				posix_mode,`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] `				req->CreateOptions & FILE_DIRECTORY_FILE_LE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] `			if (rc == -ENOENT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `				rc = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_OBJECT_PATH_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02099 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02101 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] `		created = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] `		idmap = mnt_idmap(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] `		user_ns = mnt_user_ns(path.mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `		if (ea_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] `			if (le32_to_cpu(ea_buf->ccontext.DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] `			    sizeof(struct smb2_ea_info)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02114 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `			rc = smb2_set_ea(&ea_buf->ea,`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [NONE] `					 le32_to_cpu(ea_buf->ccontext.DataLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] `					 &path, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `			if (rc == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] `				rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] `			else if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02123 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02124 [NONE] `	} else if (!already_permitted) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02125 [NONE] `		/* FILE_READ_ATTRIBUTE is allowed without inode_permission,`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `		 * because execute(search) permission on a parent directory,`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] `		 * is already granted.`
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `		if (daccess & ~(FILE_READ_ATTRIBUTES_LE | FILE_READ_CONTROL_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02131 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `			rc = inode_permission(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] `			rc = inode_permission(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02136 [NONE] `					      d_inode(path.dentry),`
  Review: Low-risk line; verify in surrounding control flow.
- L02137 [NONE] `					      may_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] `			rc = inode_permission(d_inode(path.dentry), may_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [ERROR_PATH|] `				goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02143 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] `			if ((daccess & FILE_DELETE_LE) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] `			    (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `				rc = inode_permission(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `						      d_inode(path.dentry->d_parent),`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] `						      MAY_EXEC | MAY_WRITE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] `				rc = ksmbd_vfs_may_delete(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] `				rc = ksmbd_vfs_may_delete(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [NONE] `							  path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02157 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] `				if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [ERROR_PATH|] `					goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02160 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [NONE] `	if (!file_present) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] `		rc = ksmbd_query_inode_status(path.dentry->d_parent);`
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [PROTO_GATE|] `		if (rc == KSMBD_INODE_STATUS_PENDING_DELETE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02167 [NONE] `			rc = -EBUSY;`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02169 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [NONE] `	rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] `	filp = dentry_open(&path, open_flags, current_cred());`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] `	if (IS_ERR(filp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] `		rc = PTR_ERR(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [ERROR_PATH|] `		pr_err("dentry open for dir failed, rc %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02177 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02178 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] `	/* Post-open TOCTOU check: verify file is within share root */`
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [NONE] `	if (!path_is_under(&filp->f_path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02182 [NONE] `			   &work->tcon->share_conf->vfs_path)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [ERROR_PATH|] `		pr_err_ratelimited("open path escapes share root\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02184 [NONE] `		fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02185 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] `	if (file_present) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `		if (!(open_flags & O_TRUNC))`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] `			file_info = FILE_OPENED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] `			file_info = FILE_OVERWRITTEN;`
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] `		if ((req->CreateDisposition & FILE_CREATE_MASK_LE) ==`
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [NONE] `		    FILE_SUPERSEDE_LE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] `			file_info = FILE_SUPERSEDED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `	} else if (open_flags & O_CREAT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `		file_info = FILE_CREATED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] `	ksmbd_vfs_set_fadvise(filp, req->CreateOptions);`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] `	/* Obtain Volatile-ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `	fp = ksmbd_open_fd(work, filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `	if (IS_ERR(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] `		fput(filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] `		rc = PTR_ERR(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] `		fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02211 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] `	/* Get Persistent-ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `	ksmbd_open_durable_fd(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] `	if (!has_file_id(fp->persistent_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `		rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02218 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] `	fp->cdoption = req->CreateDisposition;`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] `	fp->daccess = daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] `	fp->saccess = req->ShareAccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] `	fp->coption = req->CreateOptions;`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `	/* Set default windows and posix acls if creating new file */`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] `	if (created) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `		int posix_acl_rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [NONE] `		struct inode *inode = d_inode(path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02231 [NONE] `		posix_acl_rc = ksmbd_vfs_inherit_posix_acl(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] `							   &path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `							   d_inode(path.dentry->d_parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [NONE] `		posix_acl_rc = ksmbd_vfs_inherit_posix_acl(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [NONE] `							   &path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02237 [NONE] `							   d_inode(path.dentry->d_parent));`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] `		if (posix_acl_rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [NONE] `			ksmbd_debug(SMB, "inherit posix acl failed : %d\n", posix_acl_rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] `		 * Apply security descriptor: client-provided SD takes`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] `		 * precedence over inheritance, which takes precedence`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] `		 * over the default POSIX ACL-based SD.`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `		rc = smb2_create_sd_buffer(work, req, &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `			/* No client SD buffer; try Windows DACL inheritance */`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `			if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `						   KSMBD_SHARE_FLAG_ACL_XATTR)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [NONE] `				rc = smb_inherit_dacl(conn, &path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02253 [NONE] `						      sess->user->uid,`
  Review: Low-risk line; verify in surrounding control flow.
- L02254 [NONE] `						      sess->user->gid);`
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02258 [NONE] `				if (posix_acl_rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `					ksmbd_vfs_set_init_posix_acl(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] `								     &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `					ksmbd_vfs_set_init_posix_acl(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `								     &path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02267 [NONE] `				if (test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `							   KSMBD_SHARE_FLAG_ACL_XATTR)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] `					struct smb_fattr fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] `					struct smb_ntsd *pntsd;`
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] `					int pntsd_size, ace_num = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `					unsigned int sd_buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02274 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] `					ksmbd_acls_fattr(&fattr, idmap, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] `					ksmbd_acls_fattr(&fattr, user_ns, inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `					if (fattr.cf_acls)`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `						ace_num = fattr.cf_acls->a_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `					if (fattr.cf_dacls)`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `						ace_num += fattr.cf_dacls->a_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] `					sd_buf_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] `						sizeof(struct smb_ntsd) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] `						sizeof(struct smb_sid) * 3 +`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] `						sizeof(struct smb_acl) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `						sizeof(struct smb_ace) *`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `						ace_num * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [MEM_BOUNDS|] `					pntsd = kmalloc(sd_buf_size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02291 [NONE] `							KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] `					if (!pntsd) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `						posix_acl_release(fattr.cf_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `						posix_acl_release(fattr.cf_dacls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [ERROR_PATH|] `						goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02296 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] `					rc = build_sec_desc(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02301 [NONE] `					rc = build_sec_desc(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `							    pntsd, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `							    OWNER_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `							    GROUP_SECINFO |`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] `							    DACL_SECINFO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [NONE] `							    &pntsd_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [NONE] `							    &fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] `							    sd_buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `					posix_acl_release(fattr.cf_acls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `					posix_acl_release(fattr.cf_dacls);`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `					if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `						kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [ERROR_PATH|] `						goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02315 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] `					rc = ksmbd_vfs_set_sd_xattr(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `								    idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [NONE] `								    user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02322 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `								    &path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `								    pntsd,`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] `								    pntsd_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [NONE] `								    false);`
  Review: Low-risk line; verify in surrounding control flow.
- L02327 [NONE] `					kfree(pntsd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] `					if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [ERROR_PATH|] `						pr_err("failed to store ntacl in xattr : %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02330 [NONE] `						       rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] `	if (stream_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] `		rc = smb2_set_stream_name_xattr(&path,`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] `						fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `						stream_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `						s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02344 [NONE] `		file_info = FILE_CREATED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `	fp->attrib_only = !(req->DesiredAccess & ~(FILE_READ_ATTRIBUTES_LE |`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `			FILE_WRITE_ATTRIBUTES_LE | FILE_SYNCHRONIZE_LE));`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `	fp->is_posix_ctxt = posix_ctxt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [NONE] `	/* fp should be searchable through ksmbd_inode.m_fp_list`
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `	 * after daccess, saccess, attrib_only, and stream are`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] `	 * initialized.`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [LOCK|] `	down_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02357 [NONE] `	list_add(&fp->node, &fp->f_ci->m_fp_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `	if (posix_ctxt)`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `		ksmbd_inode_set_posix(fp->f_ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [LOCK|] `	up_write(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02361 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02362 [NONE] `	if (req->CreateContextsOffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] `		rc = smb2_dispatch_registered_create_contexts(work, req, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02366 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] `	 * Check delete pending among previous fp before oplock break.`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [NONE] `	 * In POSIX mode, allow opens to succeed even when delete is`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] `	 * pending -- the file has already been unlinked from the`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `	 * directory namespace and data persists until the last handle`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] `	 * closes (POSIX unlink semantics).`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] `	if (!posix_ctxt && ksmbd_inode_pending_delete(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] `		if (!ksmbd_inode_clear_pending_delete_if_only(fp)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] `			rc = -EBUSY;`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02379 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] `	if (file_present || created)`
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] `	if (!S_ISDIR(file_inode(filp)->i_mode) && open_flags & O_TRUNC &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `	    !fp->attrib_only && !stream_name) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] `		smb_break_all_oplock(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `		need_truncate = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] `	share_ret = ksmbd_smb_check_shared_mode(fp->filp, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] `	if (!test_share_config_flag(work->tcon->share_conf, KSMBD_SHARE_FLAG_OPLOCKS) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [PROTO_GATE|] `	    (req_op_level == SMB2_OPLOCK_LEVEL_LEASE &&`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02394 [PROTO_GATE|] `	     !(conn->vals->capabilities & SMB2_GLOBAL_CAP_LEASING))) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02395 [NONE] `		if (share_ret < 0 && !S_ISDIR(file_inode(fp->filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] `			rc = share_ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02398 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [PROTO_GATE|] `		if (req_op_level == SMB2_OPLOCK_LEVEL_LEASE && lc) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02401 [NONE] `			if (S_ISDIR(file_inode(filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [PROTO_GATE|] `				lc->req_state &= ~SMB2_LEASE_WRITE_CACHING_LE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02403 [NONE] `				lc->is_dir = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02404 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `			 * Compare parent lease using parent key. If there is no`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [NONE] `			 * a lease that has same parent key, Send lease break`
  Review: Low-risk line; verify in surrounding control flow.
- L02409 [NONE] `			 * notification.`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `			smb_send_parent_lease_break_noti(fp, lc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] `			req_op_level = smb2_map_lease_to_oplock(lc->req_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] `				    "lease req for(%s) req oplock state 0x%x, lease state 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `				    name, req_op_level, lc->req_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `			rc = find_same_lease_key(sess, fp->f_ci, lc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `			if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [ERROR_PATH|] `				goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02420 [NONE] `		} else if (open_flags == O_RDONLY &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [PROTO_GATE|] `			   (req_op_level == SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02422 [PROTO_GATE|] `			    req_op_level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02423 [PROTO_GATE|] `			req_op_level = SMB2_OPLOCK_LEVEL_II;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `		 * CR2: FILE_COMPLETE_IF_OPLOCKED (CreateOptions 0x00000100)`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] `		 * MS-SMB2 §3.3.5.9: If this flag is set and there is an`
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] `		 * existing oplock on the inode that would require a break`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [PROTO_GATE|] `		 * (BATCH or EXCLUSIVE level), return STATUS_OPLOCK_BREAK_IN_PROGRESS`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02430 [NONE] `		 * immediately instead of waiting for the oplock break to complete.`
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `		 * This is an informational (success) status — the CREATE still`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] `		 * succeeds, but the client is told a break is pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] `		if ((req->CreateOptions & FILE_COMPLETE_IF_OPLOCKED_LE) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [LIFETIME|] `		    (atomic_read(&fp->f_ci->op_count) > 0 ||`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02436 [LIFETIME|] `		     atomic_read(&fp->f_ci->sop_count) > 0)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02437 [NONE] `			struct oplock_info *prev_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] `			prev_opinfo = opinfo_get(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] `			if (!prev_opinfo) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `				/* Check inode list for a conflicting oplock */`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [LOCK|] `				down_read(&fp->f_ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02443 [NONE] `				if (!list_empty(&fp->f_ci->m_op_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02444 [NONE] `					struct oplock_info *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] `					tmp = list_first_entry_or_null(`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] `						&fp->f_ci->m_op_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [NONE] `						struct oplock_info, op_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `					if (tmp &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] `					    (tmp->level ==`
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [PROTO_GATE|] `					     SMB2_OPLOCK_LEVEL_BATCH ||`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02452 [NONE] `					     tmp->level ==`
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [PROTO_GATE|] `					     SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02454 [NONE] `						ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] `							    "FILE_COMPLETE_IF_OPLOCKED: oplock break in progress, skipping wait\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] `						up_read(&fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] `						rsp->hdr.Status =`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [PROTO_GATE|] `							STATUS_OPLOCK_BREAK_IN_PROGRESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02459 [ERROR_PATH|] `						goto done_oplock;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02460 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] `				up_read(&fp->f_ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `				opinfo_put(prev_opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `		rc = smb_grant_oplock(work, req_op_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `				      fp->persistent_id, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [NONE] `				      le32_to_cpu(req->hdr.Id.SyncId.TreeId),`
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [NONE] `				      lc, share_ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02472 [NONE] `		if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02474 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02475 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [NONE] `		 * CR3: FILE_OPEN_REQUIRING_OPLOCK (CreateOptions 0x00010000)`
  Review: Low-risk line; verify in surrounding control flow.
- L02477 [NONE] `		 * MS-SMB2 §3.3.5.9: If this flag is set, the open MUST succeed`
  Review: Low-risk line; verify in surrounding control flow.
- L02478 [NONE] `		 * only if the requested oplock can be granted immediately at the`
  Review: Low-risk line; verify in surrounding control flow.
- L02479 [NONE] `		 * level requested.  If the oplock was downgraded (granted at a`
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] `		 * lower level than requested) or not granted at all, close the`
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [PROTO_GATE|] `		 * file and return STATUS_OPLOCK_NOT_GRANTED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02482 [NONE] `		 * Only applies when a non-NONE oplock was requested.`
  Review: Low-risk line; verify in surrounding control flow.
- L02483 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [NONE] `		if ((req->CreateOptions & FILE_OPEN_REQUIRING_OPLOCK) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02485 [PROTO_GATE|] `		    req_op_level != SMB2_OPLOCK_LEVEL_NONE) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02486 [NONE] `			struct oplock_info *granted_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L02487 [PROTO_GATE|] `			int granted_level = SMB2_OPLOCK_LEVEL_NONE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02488 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02489 [LIFETIME|] `			rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02490 [LIFETIME|] `			granted_opinfo = rcu_dereference(fp->f_opinfo);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02491 [NONE] `			if (granted_opinfo)`
  Review: Low-risk line; verify in surrounding control flow.
- L02492 [NONE] `				granted_level = granted_opinfo->level;`
  Review: Low-risk line; verify in surrounding control flow.
- L02493 [LIFETIME|] `			rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `			if (granted_level < req_op_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02497 [NONE] `					    "FILE_OPEN_REQUIRING_OPLOCK: oplock not granted at requested level (req=%d granted=%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] `					    req_op_level, granted_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `				rc = -EPERM;`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_OPLOCK_NOT_GRANTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02501 [ERROR_PATH|] `				goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02502 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `done_oplock:;`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `	if (req->CreateOptions & FILE_DELETE_ON_CLOSE_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02509 [NONE] `		 * MS-SMB2 §3.3.5.9: If FILE_DELETE_ON_CLOSE is requested but`
  Review: Low-risk line; verify in surrounding control flow.
- L02510 [NONE] `		 * GrantedAccess does not include DELETE, the server SHOULD fail`
  Review: Low-risk line; verify in surrounding control flow.
- L02511 [PROTO_GATE|] `		 * with STATUS_ACCESS_DENIED.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02512 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] `		if (!(daccess & FILE_DELETE_LE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02515 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02516 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] `		 * MS-SMB2 §3.3.5.9: If the file has FILE_ATTRIBUTE_READONLY`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [PROTO_GATE|] `		 * set, the server MUST fail with STATUS_CANNOT_DELETE.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02521 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02522 [NONE] `		if (fp->f_ci->m_fattr & ATTR_READONLY_LE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02523 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_CANNOT_DELETE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02524 [NONE] `			rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [NONE] `				    "delete-on-close on read-only file\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02527 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02528 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02529 [NONE] `		ksmbd_fd_set_delete_on_close(fp, file_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] `	if (need_truncate) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] `		bool is_supersede = (file_info == FILE_SUPERSEDED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] `		rc = smb2_create_truncate(&fp->filp->f_path, is_supersede);`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02538 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] `	if (req->CreateContextsOffset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] `		struct create_alloc_size_req *az_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02543 [NONE] `		az_req = (struct create_alloc_size_req *)smb2_find_context_vals(req,`
  Review: Low-risk line; verify in surrounding control flow.
- L02544 [PROTO_GATE|] `					SMB2_CREATE_ALLOCATION_SIZE, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02545 [NONE] `		if (IS_ERR(az_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] `			rc = PTR_ERR(az_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02548 [NONE] `		} else if (az_req) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `			loff_t alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] `			int err;`
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02552 [NONE] `			if (le16_to_cpu(az_req->ccontext.DataOffset) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] `			    le32_to_cpu(az_req->ccontext.DataLength) <`
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] `			    sizeof(struct create_alloc_size_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [NONE] `				rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02556 [ERROR_PATH|] `				goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02557 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02558 [NONE] `			alloc_size = le64_to_cpu(az_req->AllocationSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02560 [NONE] `				    "request smb2 create allocate size : %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [NONE] `				    alloc_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02562 [NONE] `			smb_break_all_levII_oplock(work, fp, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02563 [NONE] `			err = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [NONE] `					    alloc_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02565 [NONE] `			if (err < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02566 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L02567 [NONE] `					    "vfs_fallocate is failed : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] `					    err);`
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L02570 [NONE] `				fp->f_ci->m_cached_alloc = alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [PROTO_GATE|] `		context = smb2_find_context_vals(req, SMB2_CREATE_QUERY_ON_DISK_ID, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02574 [NONE] `		if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02575 [NONE] `			rc = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L02576 [ERROR_PATH|] `			goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02577 [NONE] `		} else if (context) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02578 [NONE] `			ksmbd_debug(SMB, "get query on disk id context\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02579 [NONE] `			query_disk_id = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02580 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L02583 [NONE] `		if ((server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_EXTENSIONS) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [NONE] `		    conn->is_fruit == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02585 [PROTO_GATE|] `			context = smb2_find_context_vals(req, SMB2_CREATE_AAPL, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02586 [NONE] `			if (IS_ERR(context)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02587 [NONE] `				rc = PTR_ERR(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [ERROR_PATH|] `				goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02589 [NONE] `			} else if (context) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] `				const void *context_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `				size_t data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [NONE] `				struct fruit_client_info *client_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L02593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `				if (le16_to_cpu(context->NameLength) == 4 &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] `				    le32_to_cpu(context->DataLength) >= sizeof(struct fruit_client_info)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [NONE] `					context_data = (const __u8 *)context +`
  Review: Low-risk line; verify in surrounding control flow.
- L02598 [NONE] `						le16_to_cpu(context->DataOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L02599 [NONE] `					data_len = le32_to_cpu(context->DataLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02601 [NONE] `					rc = fruit_validate_create_context(context);`
  Review: Low-risk line; verify in surrounding control flow.
- L02602 [NONE] `					if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] `						ksmbd_debug(SMB, "Invalid fruit create context: %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [NONE] `						rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02605 [ERROR_PATH|] `						goto continue_create;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02606 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02608 [MEM_BOUNDS|] `					client_info = kzalloc(sizeof(struct fruit_client_info),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02609 [NONE] `							      KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L02610 [NONE] `					if (!client_info) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02611 [NONE] `						rc = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L02612 [ERROR_PATH|] `						goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02613 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [NONE] `					size_t copy_len = min(data_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02616 [NONE] `							     sizeof(struct fruit_client_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L02617 [MEM_BOUNDS|] `					memcpy(client_info, context_data, copy_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02618 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] `					fruit_debug_client_info(client_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] `					rc = fruit_negotiate_capabilities(conn, client_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] `					if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] `						ksmbd_debug(SMB, "Fruit capability negotiation failed: %d\n", rc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [NONE] `						kfree(client_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02625 [NONE] `						client_info = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02626 [NONE] `						rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [ERROR_PATH|] `						goto continue_create;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02628 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [NONE] `					conn->is_fruit = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02630 [NONE] `					fruit_ctxt = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [NONE] `					kfree(client_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02633 [NONE] `					client_info = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02634 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02635 [NONE] `					ksmbd_debug(SMB, "Fruit context too small: name_len=%u, data_len=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02636 [NONE] `						    le16_to_cpu(context->NameLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [NONE] `						    le32_to_cpu(context->DataLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02638 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02639 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] `		} else if (conn->is_fruit) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [NONE] `			fruit_ctxt = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02642 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02643 [NONE] `continue_create: ;`
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `#endif /* CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02647 [NONE] `	rc = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L02649 [ERROR_PATH|] `		goto err_out1;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02650 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02651 [NONE] `	if (stat.result_mask & STATX_BTIME)`
  Review: Low-risk line; verify in surrounding control flow.
- L02652 [NONE] `		fp->create_time = ksmbd_UnixTimeToNT(stat.btime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02653 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L02654 [NONE] `		fp->create_time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02655 [NONE] `	if (req->FileAttributes || fp->f_ci->m_fattr == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `		fp->f_ci->m_fattr =`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] `			cpu_to_le32(smb2_get_dos_mode(&stat, le32_to_cpu(req->FileAttributes)));`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] `	if (!created)`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] `		smb2_update_xattrs(tcon, &fp->filp->f_path, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [NONE] `		smb2_new_xattrs(tcon, &fp->filp->f_path, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02663 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [MEM_BOUNDS|PROTO_GATE|] `	memcpy(fp->client_guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02666 [NONE] `	if (dh_info.type == DURABLE_REQ_V2 || dh_info.type == DURABLE_REQ) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02667 [NONE] `		if (dh_info.type == DURABLE_REQ_V2 && dh_info.persistent &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] `		    test_share_config_flag(work->tcon->share_conf,`
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `					   KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY))`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [NONE] `			fp->is_persistent = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02671 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L02672 [NONE] `			fp->is_durable = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [NONE] `		if (dh_info.type == DURABLE_REQ_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02675 [MEM_BOUNDS|] `			memcpy(fp->create_guid, dh_info.CreateGuid,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02676 [PROTO_GATE|] `					SMB2_CREATE_GUID_SIZE);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02677 [NONE] `			if (dh_info.timeout)`
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `				fp->durable_timeout =`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] `					min_t(unsigned int, dh_info.timeout,`
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] `					      DURABLE_HANDLE_MAX_TIMEOUT);`
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L02682 [NONE] `				/* Default: 60 seconds in milliseconds */`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] `				fp->durable_timeout = 60000;`
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] `			 * C.5: DHnQ v1 durable handles previously had no`
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `			 * expiry timeout, causing them to leak indefinitely`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `			 * after disconnect.  Assign the Windows default`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [NONE] `			 * reconnect window of 16 seconds (in ms).`
  Review: Low-risk line; verify in surrounding control flow.
- L02690 [NONE] `			 * MS-SMB2 §3.3.5.9.7: server SHOULD apply a timeout.`
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02692 [NONE] `			fp->durable_timeout = 16000;`
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02696 [NONE] `		 * CR5: Persistent handle on-disk state.`
  Review: Low-risk line; verify in surrounding control flow.
- L02697 [NONE] `		 * For persistent handles (fp->is_persistent), save state to`
  Review: Low-risk line; verify in surrounding control flow.
- L02698 [NONE] `		 * stable storage so the handle can survive server restarts.`
  Review: Low-risk line; verify in surrounding control flow.
- L02699 [NONE] `		 * ksmbd_ph_save() is a stub — full implementation pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02701 [NONE] `		if (fp->is_persistent)`
  Review: Low-risk line; verify in surrounding control flow.
- L02702 [NONE] `			ksmbd_ph_save(fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02703 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [NONE] `	/* Save create_action for DHv2 replay (MS-SMB2 3.3.5.9.10) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02706 [NONE] `	fp->create_action = file_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02708 [NONE] `reconnected_fp:`
  Review: Low-risk line; verify in surrounding control flow.
- L02709 [NONE] `	rsp->StructureSize = cpu_to_le16(89);`
  Review: Low-risk line; verify in surrounding control flow.
- L02710 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02711 [LIFETIME|] `	opinfo = rcu_dereference(fp->f_opinfo);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02712 [NONE] `	rsp->OplockLevel = opinfo != NULL ? opinfo->level : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02713 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02714 [NONE] `	rsp->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `	rsp->CreateAction = cpu_to_le32(file_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] `	rsp->CreationTime = cpu_to_le64(fp->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] `	time = ksmbd_UnixTimeToNT(stat.atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [NONE] `	rsp->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L02719 [NONE] `	time = ksmbd_UnixTimeToNT(stat.mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] `	rsp->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [NONE] `	time = ksmbd_UnixTimeToNT(stat.ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02722 [NONE] `	rsp->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L02723 [NONE] `	rsp->AllocationSize = cpu_to_le64(ksmbd_alloc_size(fp, &stat));`
  Review: Low-risk line; verify in surrounding control flow.
- L02724 [NONE] `	rsp->EndofFile = S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] `	rsp->FileAttributes = fp->f_ci->m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02727 [NONE] `	/* Cache response for DHv2 replay (MS-SMB2 3.3.5.9.10) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] `	if (!fp->replay_cache.valid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [NONE] `		fp->replay_cache.last_access = le64_to_cpu(rsp->LastAccessTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02730 [NONE] `		fp->replay_cache.last_write = le64_to_cpu(rsp->LastWriteTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02731 [NONE] `		fp->replay_cache.change = le64_to_cpu(rsp->ChangeTime);`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [NONE] `		fp->replay_cache.alloc_size = le64_to_cpu(rsp->AllocationSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L02733 [NONE] `		fp->replay_cache.end_of_file = le64_to_cpu(rsp->EndofFile);`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] `		fp->replay_cache.file_attrs = rsp->FileAttributes;`
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] `		fp->replay_cache.valid = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [NONE] `	 * NTFS metadata fake files ($Extend\$Quota etc.) are`
  Review: Low-risk line; verify in surrounding control flow.
- L02740 [NONE] `	 * reported with HIDDEN | SYSTEM | DIRECTORY | ARCHIVE`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [NONE] `	 * attributes and zero timestamps, matching Windows Server`
  Review: Low-risk line; verify in surrounding control flow.
- L02742 [NONE] `	 * behavior.`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] `	if (is_fake_file) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] `		rsp->FileAttributes = cpu_to_le32(ATTR_HIDDEN | ATTR_SYSTEM |`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] `						  ATTR_DIRECTORY | ATTR_ARCHIVE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [NONE] `		rsp->CreationTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02748 [NONE] `		rsp->LastAccessTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02749 [NONE] `		rsp->LastWriteTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02750 [NONE] `		rsp->ChangeTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] `		rsp->AllocationSize = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] `		rsp->EndofFile = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02755 [NONE] `	rsp->Reserved2 = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02756 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [NONE] `	rsp->PersistentFileId = fp->persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02758 [NONE] `	rsp->VolatileFileId = fp->volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [NONE] `	rsp->CreateContextsOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02761 [NONE] `	rsp->CreateContextsLength = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02762 [NONE] `	iov_len = offsetof(struct smb2_create_rsp, Buffer);`
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] `durable_create_ctx:`
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] `	/* If lease is request send lease context response */`
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] `	if (opinfo && opinfo->is_lease) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] `		struct create_context *lease_ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `		if (iov_len + conn->vals->create_lease_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `		    work->response_sz - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02773 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02774 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02775 [NONE] `		ksmbd_debug(SMB, "lease granted on(%s) lease state 0x%x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02776 [NONE] `			    name, opinfo->o_lease->state);`
  Review: Low-risk line; verify in surrounding control flow.
- L02777 [PROTO_GATE|] `		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_LEASE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02779 [NONE] `		lease_ccontext = (struct create_context *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02780 [NONE] `		contxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02781 [NONE] `		create_lease_buf(rsp->Buffer, opinfo->o_lease);`
  Review: Low-risk line; verify in surrounding control flow.
- L02782 [NONE] `		le32_add_cpu(&rsp->CreateContextsLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L02783 [NONE] `			     conn->vals->create_lease_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02784 [NONE] `		iov_len += conn->vals->create_lease_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02785 [NONE] `		next_ptr = &lease_ccontext->Next;`
  Review: Low-risk line; verify in surrounding control flow.
- L02786 [NONE] `		next_off = conn->vals->create_lease_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02787 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02788 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02789 [NONE] `	if (maximal_access_ctxt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02790 [NONE] `		struct create_context *mxac_ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L02791 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02792 [NONE] `		if (iov_len + conn->vals->create_mxac_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02793 [NONE] `		    work->response_sz - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02794 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02795 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02796 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02798 [NONE] `		if (maximal_access == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02799 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02800 [NONE] `			ksmbd_vfs_query_maximal_access(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L02801 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02802 [NONE] `			ksmbd_vfs_query_maximal_access(user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02803 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02804 [NONE] `						       fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L02805 [NONE] `						       &maximal_access);`
  Review: Low-risk line; verify in surrounding control flow.
- L02806 [NONE] `		mxac_ccontext = (struct create_context *)(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02807 [NONE] `				le32_to_cpu(rsp->CreateContextsLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02808 [NONE] `		contxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02809 [NONE] `		create_mxac_rsp_buf(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02810 [NONE] `				le32_to_cpu(rsp->CreateContextsLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02811 [NONE] `				le32_to_cpu(maximal_access));`
  Review: Low-risk line; verify in surrounding control flow.
- L02812 [NONE] `		le32_add_cpu(&rsp->CreateContextsLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L02813 [NONE] `			     conn->vals->create_mxac_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02814 [NONE] `		iov_len += conn->vals->create_mxac_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02815 [NONE] `		if (next_ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02816 [NONE] `			*next_ptr = cpu_to_le32(next_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L02817 [NONE] `		next_ptr = &mxac_ccontext->Next;`
  Review: Low-risk line; verify in surrounding control flow.
- L02818 [NONE] `		next_off = conn->vals->create_mxac_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02819 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02821 [NONE] `	if (query_disk_id) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02822 [NONE] `		struct create_context *disk_id_ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L02823 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02824 [NONE] `		if (iov_len + conn->vals->create_disk_id_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02825 [NONE] `		    work->response_sz - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02826 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02827 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02828 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02830 [NONE] `		disk_id_ccontext = (struct create_context *)(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02831 [NONE] `				le32_to_cpu(rsp->CreateContextsLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02832 [NONE] `		contxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02833 [NONE] `		create_disk_id_rsp_buf(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02834 [NONE] `				le32_to_cpu(rsp->CreateContextsLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02835 [NONE] `				stat.ino, tcon->id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02836 [NONE] `		le32_add_cpu(&rsp->CreateContextsLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L02837 [NONE] `			     conn->vals->create_disk_id_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02838 [NONE] `		iov_len += conn->vals->create_disk_id_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02839 [NONE] `		if (next_ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02840 [NONE] `			*next_ptr = cpu_to_le32(next_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L02841 [NONE] `		next_ptr = &disk_id_ccontext->Next;`
  Review: Low-risk line; verify in surrounding control flow.
- L02842 [NONE] `		next_off = conn->vals->create_disk_id_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02843 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02845 [NONE] `	if (dh_info.type == DURABLE_REQ || dh_info.type == DURABLE_REQ_V2 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02846 [NONE] `	    dh_info.type == DURABLE_RECONN || dh_info.type == DURABLE_RECONN_V2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02847 [NONE] `		struct create_context *durable_ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L02848 [NONE] `		bool is_v2 = (dh_info.type == DURABLE_REQ_V2 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02849 [NONE] `			      dh_info.type == DURABLE_RECONN_V2);`
  Review: Low-risk line; verify in surrounding control flow.
- L02850 [NONE] `		unsigned int durable_ctx_size = is_v2 ?`
  Review: Low-risk line; verify in surrounding control flow.
- L02851 [NONE] `			conn->vals->create_durable_v2_size :`
  Review: Low-risk line; verify in surrounding control flow.
- L02852 [NONE] `			conn->vals->create_durable_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02854 [NONE] `		if (iov_len + durable_ctx_size > work->response_sz - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02855 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02856 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02857 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02858 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02859 [NONE] `		durable_ccontext = (struct create_context *)(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02860 [NONE] `				le32_to_cpu(rsp->CreateContextsLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02861 [NONE] `		contxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02862 [NONE] `		if (!is_v2) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02863 [NONE] `			create_durable_rsp_buf(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02864 [NONE] `					le32_to_cpu(rsp->CreateContextsLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02865 [NONE] `			le32_add_cpu(&rsp->CreateContextsLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L02866 [NONE] `					conn->vals->create_durable_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02867 [NONE] `			iov_len += conn->vals->create_durable_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02868 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02869 [NONE] `			create_durable_v2_rsp_buf(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02870 [NONE] `					le32_to_cpu(rsp->CreateContextsLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02871 [NONE] `					fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02872 [NONE] `			le32_add_cpu(&rsp->CreateContextsLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L02873 [NONE] `					conn->vals->create_durable_v2_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02874 [NONE] `			iov_len += conn->vals->create_durable_v2_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02875 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02876 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02877 [NONE] `		if (next_ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02878 [NONE] `			*next_ptr = cpu_to_le32(next_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L02879 [NONE] `		next_ptr = &durable_ccontext->Next;`
  Review: Low-risk line; verify in surrounding control flow.
- L02880 [NONE] `		next_off = is_v2 ?`
  Review: Low-risk line; verify in surrounding control flow.
- L02881 [NONE] `			conn->vals->create_durable_v2_size :`
  Review: Low-risk line; verify in surrounding control flow.
- L02882 [NONE] `			conn->vals->create_durable_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02883 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02885 [NONE] `	if (posix_ctxt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02886 [NONE] `		struct create_context *posix_ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L02887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02888 [NONE] `		if (iov_len + conn->vals->create_posix_size >`
  Review: Low-risk line; verify in surrounding control flow.
- L02889 [NONE] `		    work->response_sz - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02890 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02891 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02892 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02893 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02894 [NONE] `		posix_ccontext = (struct create_context *)(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02895 [NONE] `				le32_to_cpu(rsp->CreateContextsLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02896 [NONE] `		contxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02897 [NONE] `		create_posix_rsp_buf(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02898 [NONE] `				le32_to_cpu(rsp->CreateContextsLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02899 [NONE] `				fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02900 [NONE] `		le32_add_cpu(&rsp->CreateContextsLength,`
  Review: Low-risk line; verify in surrounding control flow.
- L02901 [NONE] `			     conn->vals->create_posix_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02902 [NONE] `		iov_len += conn->vals->create_posix_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02903 [NONE] `		if (next_ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02904 [NONE] `			*next_ptr = cpu_to_le32(next_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L02905 [NONE] `		next_ptr = &posix_ccontext->Next;`
  Review: Low-risk line; verify in surrounding control flow.
- L02906 [NONE] `		next_off = conn->vals->create_posix_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02907 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02909 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L02910 [NONE] `	if (fruit_ctxt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02911 [NONE] `		struct create_context *fruit_ccontext;`
  Review: Low-risk line; verify in surrounding control flow.
- L02912 [NONE] `		size_t fruit_size = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02913 [NONE] `		size_t max_fruit_size = offsetof(struct create_fruit_rsp, model) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02914 [NONE] `					sizeof(server_conf.fruit_model) * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02915 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02916 [NONE] `		if (iov_len + max_fruit_size > work->response_sz - 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02917 [NONE] `			rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02918 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02919 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02920 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02921 [NONE] `		fruit_ccontext = (struct create_context *)(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02922 [NONE] `				le32_to_cpu(rsp->CreateContextsLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L02923 [NONE] `		contxt_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02924 [NONE] `		create_fruit_rsp_buf(rsp->Buffer +`
  Review: Low-risk line; verify in surrounding control flow.
- L02925 [NONE] `				le32_to_cpu(rsp->CreateContextsLength),`
  Review: Low-risk line; verify in surrounding control flow.
- L02926 [NONE] `				conn, &fruit_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02927 [NONE] `		le32_add_cpu(&rsp->CreateContextsLength, fruit_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02928 [NONE] `		iov_len += fruit_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02929 [NONE] `		if (next_ptr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02930 [NONE] `			*next_ptr = cpu_to_le32(next_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L02931 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02932 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02933 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02934 [NONE] `	if (contxt_cnt > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02935 [NONE] `		rsp->CreateContextsOffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L02936 [NONE] `			cpu_to_le32(offsetof(struct smb2_create_rsp, Buffer));`
  Review: Low-risk line; verify in surrounding control flow.
- L02937 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02939 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02940 [NONE] `	if (rc && (file_present || created))`
  Review: Low-risk line; verify in surrounding control flow.
- L02941 [NONE] `		path_put(&path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02942 [NONE] `err_out1:`
  Review: Low-risk line; verify in surrounding control flow.
- L02943 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02944 [NONE] `err_out2:`
  Review: Low-risk line; verify in surrounding control flow.
- L02945 [NONE] `	if (!rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02946 [NONE] `		ksmbd_update_fstate(&work->sess->file_table, fp, FP_INITED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02947 [NONE] `		rc = ksmbd_iov_pin_rsp(work, (void *)rsp, iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02948 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02949 [NONE] `		if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02950 [PROTO_GATE|] `		/* If status was pre-set (e.g. STATUS_CANNOT_DELETE), keep it */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02951 [PROTO_GATE|] `		if (rsp->hdr.Status == STATUS_SUCCESS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02952 [NONE] `			if (rc == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L02953 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02954 [NONE] `			else if (rc == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L02955 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02956 [NONE] `			else if (rc == -EACCES || rc == -ESTALE || rc == -EXDEV)`
  Review: Low-risk line; verify in surrounding control flow.
- L02957 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02958 [NONE] `			else if (rc == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L02959 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_OBJECT_NAME_INVALID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02960 [NONE] `			else if (rc == -EPERM)`
  Review: Low-risk line; verify in surrounding control flow.
- L02961 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_SHARING_VIOLATION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02962 [NONE] `			else if (rc == -EBUSY)`
  Review: Low-risk line; verify in surrounding control flow.
- L02963 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_DELETE_PENDING;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02964 [NONE] `			else if (rc == -EBADF)`
  Review: Low-risk line; verify in surrounding control flow.
- L02965 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02966 [NONE] `			else if (rc == -ENOEXEC)`
  Review: Low-risk line; verify in surrounding control flow.
- L02967 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_DUPLICATE_OBJECTID;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02968 [NONE] `			else if (rc == -ENXIO)`
  Review: Low-risk line; verify in surrounding control flow.
- L02969 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_NO_SUCH_DEVICE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02970 [NONE] `			else if (rc == -EEXIST)`
  Review: Low-risk line; verify in surrounding control flow.
- L02971 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_OBJECT_NAME_COLLISION;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02972 [NONE] `			else if (rc == -EMFILE)`
  Review: Low-risk line; verify in surrounding control flow.
- L02973 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02974 [NONE] `			else if (rc == -ENOKEY)`
  Review: Low-risk line; verify in surrounding control flow.
- L02975 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_PRIVILEGE_NOT_HELD;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02976 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L02977 [PROTO_GATE|] `				rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02978 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02979 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02981 [NONE] `		if (fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L02982 [NONE] `			ksmbd_fd_put(work, fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02983 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02984 [NONE] `		ksmbd_debug(SMB, "Error response: %x\n", rsp->hdr.Status);`
  Review: Low-risk line; verify in surrounding control flow.
- L02985 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02986 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02987 [NONE] `	kfree(name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02988 [NONE] `	kfree(lc);`
  Review: Low-risk line; verify in surrounding control flow.
- L02989 [NONE] `	kfree(twrp_snap_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L02990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02991 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L02992 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
