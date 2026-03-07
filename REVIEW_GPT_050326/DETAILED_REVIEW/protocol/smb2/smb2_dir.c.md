# Line-by-line Review: src/protocol/smb2/smb2_dir.c

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
- L00006 [PROTO_GATE|] ` *   smb2_dir.c - SMB2_QUERY_DIRECTORY handler`
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
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#include <kunit/visibility.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define VISIBLE_IF_KUNIT static`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define EXPORT_SYMBOL_IF_KUNIT(sym)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `VISIBLE_IF_KUNIT int readdir_info_level_struct_sz(int info_level)`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	switch (info_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	case FILE_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `		return sizeof(struct file_full_directory_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	case FILE_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `		return sizeof(struct file_both_directory_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	case FILE_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		return sizeof(struct file_directory_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	case FILE_NAMES_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		return sizeof(struct file_names_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	case FILEID_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `		return sizeof(struct file_id_full_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	case FILEID_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		return sizeof(struct file_id_both_directory_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `		return sizeof(struct file_id_both_directory_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	case FILEID_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		return sizeof(struct file_id_extd_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		return sizeof(struct file_id_extd_both_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	case FILEID_64_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `		return sizeof(struct file_id_64_extd_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `		return sizeof(struct file_id_64_extd_both_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `		return sizeof(struct file_id_all_extd_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		return sizeof(struct file_id_all_extd_both_dir_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	case SMB_FIND_FILE_POSIX_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		return sizeof(struct smb2_posix_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00101 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `EXPORT_SYMBOL_IF_KUNIT(readdir_info_level_struct_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `static int dentry_name(struct ksmbd_dir_info *d_info, int info_level)`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	switch (info_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	case FILE_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `		struct file_full_directory_info *ffdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `		ffdinfo = (struct file_full_directory_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		d_info->rptr += le32_to_cpu(ffdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		d_info->name = ffdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		d_info->name_len = le32_to_cpu(ffdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	case FILE_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `		struct file_both_directory_info *fbdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `		fbdinfo = (struct file_both_directory_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `		d_info->rptr += le32_to_cpu(fbdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `		d_info->name = fbdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		d_info->name_len = le32_to_cpu(fbdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	case FILE_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		struct file_directory_info *fdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		fdinfo = (struct file_directory_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		d_info->rptr += le32_to_cpu(fdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `		d_info->name = fdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `		d_info->name_len = le32_to_cpu(fdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	case FILE_NAMES_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `		struct file_names_info *fninfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `		fninfo = (struct file_names_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `		d_info->rptr += le32_to_cpu(fninfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `		d_info->name = fninfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `		d_info->name_len = le32_to_cpu(fninfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	case FILEID_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		struct file_id_full_dir_info *dinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `		dinfo = (struct file_id_full_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		d_info->rptr += le32_to_cpu(dinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `		d_info->name = dinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `		d_info->name_len = le32_to_cpu(dinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	case FILEID_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `		struct file_id_both_directory_info *fibdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		fibdinfo = (struct file_id_both_directory_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		d_info->rptr += le32_to_cpu(fibdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		d_info->name = fibdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		d_info->name_len = le32_to_cpu(fibdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		struct file_id_both_directory_info *fibdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		fibdinfo = (struct file_id_both_directory_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `		d_info->rptr += le32_to_cpu(fibdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `		d_info->name = fibdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `		d_info->name_len = le32_to_cpu(fibdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	case FILEID_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		struct file_id_extd_dir_info *extdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `		extdinfo = (struct file_id_extd_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `		d_info->rptr += le32_to_cpu(extdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		d_info->name = extdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		d_info->name_len = le32_to_cpu(extdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		struct file_id_extd_both_dir_info *extdbinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `		extdbinfo = (struct file_id_extd_both_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		d_info->rptr += le32_to_cpu(extdbinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `		d_info->name = extdbinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		d_info->name_len = le32_to_cpu(extdbinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	case FILEID_64_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `		struct file_id_64_extd_dir_info *extd64info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		extd64info = (struct file_id_64_extd_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `		d_info->rptr += le32_to_cpu(extd64info->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `		d_info->name = extd64info->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `		d_info->name_len = le32_to_cpu(extd64info->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `		struct file_id_64_extd_both_dir_info *extd64binfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `		extd64binfo = (struct file_id_64_extd_both_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `		d_info->rptr += le32_to_cpu(extd64binfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `		d_info->name = extd64binfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `		d_info->name_len = le32_to_cpu(extd64binfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		struct file_id_all_extd_dir_info *allexdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `		allexdinfo = (struct file_id_all_extd_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `		d_info->rptr += le32_to_cpu(allexdinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `		d_info->name = allexdinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `		d_info->name_len = le32_to_cpu(allexdinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `		struct file_id_all_extd_both_dir_info *allexdbinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		allexdbinfo = (struct file_id_all_extd_both_dir_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		d_info->rptr += le32_to_cpu(allexdbinfo->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		d_info->name = allexdbinfo->FileName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `		d_info->name_len = le32_to_cpu(allexdbinfo->FileNameLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	case SMB_FIND_FILE_POSIX_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `		struct smb2_posix_info *posix_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		posix_info = (struct smb2_posix_info *)d_info->rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `		d_info->rptr += le32_to_cpu(posix_info->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `		d_info->name = posix_info->name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `		d_info->name_len = le32_to_cpu(posix_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00250 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` * smb2_populate_readdir_entry() - encode directory entry in smb2 response`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` * buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ` * @info_level:	smb information level`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ` * @d_info:	structure included variables for query dir`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ` * @ksmbd_kstat:	ksmbd wrapper of dirent stat information`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ` * if directory has many entries, find first can't read it fully.`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ` * find next might be called multiple times to read remaining dir entries`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `static int smb2_populate_readdir_entry(struct ksmbd_conn *conn, int info_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `				       struct ksmbd_dir_info *d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `				       struct ksmbd_kstat *ksmbd_kstat)`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	int next_entry_offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	char *conv_name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	void *kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	int struct_sz, rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	conv_name = ksmbd_convert_dir_info_name(d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `						conn->local_nls,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `						&conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	if (!conv_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	/* Somehow the name has only terminating NULL bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	if (conv_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [ERROR_PATH|] `		goto free_conv_name;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00286 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	struct_sz = readdir_info_level_struct_sz(info_level) + conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	next_entry_offset = ALIGN(struct_sz, KSMBD_DIR_INFO_ALIGNMENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	d_info->last_entry_off_align = next_entry_offset - struct_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (next_entry_offset > d_info->out_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		d_info->out_buf_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `		rc = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [ERROR_PATH|] `		goto free_conv_name;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00296 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	kstat = d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	if (info_level != FILE_NAMES_INFORMATION)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `		kstat = ksmbd_vfs_init_kstat(&d_info->wptr, ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	switch (info_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `	case FILE_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `		struct file_full_directory_info *ffdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `		ffdinfo = (struct file_full_directory_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `		ffdinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] `		ffdinfo->EaSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `		if (ffdinfo->EaSize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `			ffdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `			ffdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [MEM_BOUNDS|] `		memcpy(ffdinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00316 [NONE] `		ffdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	case FILE_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `		struct file_both_directory_info *fbdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `		int shortname_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `		fbdinfo = (struct file_both_directory_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `		fbdinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `		fbdinfo->EaSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `		if (fbdinfo->EaSize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `			fbdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		memset(fbdinfo->ShortName, 0, sizeof(fbdinfo->ShortName));`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `		shortname_len = ksmbd_extract_shortname(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `							d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `							fbdinfo->ShortName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `		fbdinfo->ShortNameLength = shortname_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `		fbdinfo->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `			fbdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [MEM_BOUNDS|] `		memcpy(fbdinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00339 [NONE] `		fbdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	case FILE_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `		struct file_directory_info *fdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `		fdinfo = (struct file_directory_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		fdinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `			fdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [MEM_BOUNDS|] `		memcpy(fdinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00351 [NONE] `		fdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `	case FILE_NAMES_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		struct file_names_info *fninfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		fninfo = (struct file_names_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		fninfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [MEM_BOUNDS|] `		memcpy(fninfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00361 [NONE] `		fninfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	case FILEID_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		struct file_id_full_dir_info *dinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `		dinfo = (struct file_id_full_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		dinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `		dinfo->EaSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		if (dinfo->EaSize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `			dinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `		if (conn->is_fruit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `			smb2_read_dir_attr_fill(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `						ksmbd_kstat->idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `						ksmbd_kstat->kstat_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `						ksmbd_kstat->kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `						ksmbd_kstat->share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `						&dinfo->EaSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `		dinfo->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		if (conn->is_fruit &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `		    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `		    d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `			dinfo->UniqueId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `			dinfo->UniqueId = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `			dinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [MEM_BOUNDS|] `		memcpy(dinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00395 [NONE] `		dinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	case FILEID_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `		struct file_id_both_directory_info *fibdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		fibdinfo = (struct file_id_both_directory_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		fibdinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `		fibdinfo->EaSize =`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `		if (fibdinfo->EaSize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `			fibdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		if (conn->is_fruit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `			smb2_read_dir_attr_fill(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `						ksmbd_kstat->idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `						ksmbd_kstat->kstat_dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `						ksmbd_kstat->kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `						ksmbd_kstat->share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `						&fibdinfo->EaSize);`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `		if (conn->is_fruit &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `		    d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `			fibdinfo->UniqueId = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `			fibdinfo->UniqueId = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		memset(fibdinfo->ShortName, 0, sizeof(fibdinfo->ShortName));`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		fibdinfo->ShortNameLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `			ksmbd_extract_shortname(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `						d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `						fibdinfo->ShortName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		fibdinfo->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `		fibdinfo->Reserved2 = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] `			fibdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [MEM_BOUNDS|] `		memcpy(fibdinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00434 [NONE] `		fibdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	case FILEID_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `		struct file_id_extd_dir_info *extdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `		extdinfo = (struct file_id_extd_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `		extdinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `		reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] `		extdinfo->EaSize = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `		extdinfo->ReparsePointTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] `		if (reparse_tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] `			extdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [MEM_BOUNDS|] `		memcpy(&extdinfo->FileId[0], &ino, sizeof(ino));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00452 [NONE] `		memset(&extdinfo->FileId[8], 0, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `			extdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [MEM_BOUNDS|] `		memcpy(extdinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00456 [NONE] `		extdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `		struct file_id_extd_both_dir_info *extdbinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `		extdbinfo = (struct file_id_extd_both_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `		extdbinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `		reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `		extdbinfo->EaSize = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `		extdbinfo->ReparsePointTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `		if (reparse_tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `			extdbinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [MEM_BOUNDS|] `		memcpy(&extdbinfo->FileId[0], &ino, sizeof(ino));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00474 [NONE] `		memset(&extdbinfo->FileId[8], 0, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `		memset(extdbinfo->ShortName, 0, sizeof(extdbinfo->ShortName));`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `		extdbinfo->ShortNameLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `			ksmbd_extract_shortname(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `						d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `						extdbinfo->ShortName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `		extdbinfo->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `			extdbinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [MEM_BOUNDS|] `		memcpy(extdbinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00484 [NONE] `		extdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	case FILEID_64_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] `		struct file_id_64_extd_dir_info *extd64info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `		extd64info = (struct file_id_64_extd_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `		extd64info->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `		reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `		extd64info->EaSize = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `		extd64info->ReparsePointTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `		if (reparse_tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `			extd64info->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `		extd64info->FileId = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `			extd64info->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [MEM_BOUNDS|] `		memcpy(extd64info->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00504 [NONE] `		extd64info->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `		struct file_id_64_extd_both_dir_info *extd64binfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `		extd64binfo = (struct file_id_64_extd_both_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `		extd64binfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `		reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `		extd64binfo->EaSize = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `		extd64binfo->ReparsePointTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `		if (reparse_tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `			extd64binfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `		extd64binfo->FileId = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `		memset(extd64binfo->ShortName, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `		       sizeof(extd64binfo->ShortName));`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `		extd64binfo->ShortNameLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `			ksmbd_extract_shortname(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `						d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `						extd64binfo->ShortName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `		extd64binfo->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `			extd64binfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [MEM_BOUNDS|] `		memcpy(extd64binfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00531 [NONE] `		extd64binfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `		struct file_id_all_extd_dir_info *allexdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `		allexdinfo = (struct file_id_all_extd_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `		allexdinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `		reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `		allexdinfo->EaSize = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `		allexdinfo->ReparsePointTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `		if (reparse_tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `			allexdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `		allexdinfo->FileId = ino;`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [MEM_BOUNDS|] `		memcpy(&allexdinfo->FileId128[0], &ino, sizeof(ino));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00550 [NONE] `		memset(&allexdinfo->FileId128[8], 0, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `			allexdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [MEM_BOUNDS|] `		memcpy(allexdinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00554 [NONE] `		allexdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		struct file_id_all_extd_both_dir_info *allexdbinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `		__le32 reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		allexdbinfo = (struct file_id_all_extd_both_dir_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `		allexdbinfo->FileNameLength = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `		reparse_tag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `		allexdbinfo->EaSize = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `		allexdbinfo->ReparsePointTag = reparse_tag;`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `		if (reparse_tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `			allexdbinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `		allexdbinfo->FileId = ino;`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [MEM_BOUNDS|] `		memcpy(&allexdbinfo->FileId128[0], &ino, sizeof(ino));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00573 [NONE] `		memset(&allexdbinfo->FileId128[8], 0, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `		memset(allexdbinfo->ShortName, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `		       sizeof(allexdbinfo->ShortName));`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		allexdbinfo->ShortNameLength =`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `			ksmbd_extract_shortname(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `						d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `						allexdbinfo->ShortName);`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `		allexdbinfo->Reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `			allexdbinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [MEM_BOUNDS|] `		memcpy(allexdbinfo->FileName, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00584 [NONE] `		allexdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `	case SMB_FIND_FILE_POSIX_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `		struct smb2_posix_info *posix_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `		u64 time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `		posix_info = (struct smb2_posix_info *)kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `		posix_info->Ignored = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `		posix_info->CreationTime = cpu_to_le64(ksmbd_kstat->create_time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `		time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->ctime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `		posix_info->ChangeTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->atime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `		posix_info->LastAccessTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `		time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->mtime);`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `		posix_info->LastWriteTime = cpu_to_le64(time);`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `		posix_info->EndOfFile = cpu_to_le64(ksmbd_kstat->kstat->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		posix_info->AllocationSize = cpu_to_le64(ksmbd_kstat->kstat->blocks << 9);`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		posix_info->DeviceId = cpu_to_le32(ksmbd_kstat->kstat->rdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `		posix_info->Zero = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		posix_info->HardLinks = cpu_to_le32(ksmbd_kstat->kstat->nlink);`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		posix_info->ReparseTag =`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `		posix_info->Mode = cpu_to_le32(ksmbd_kstat->kstat->mode & 0777);`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `		switch (ksmbd_kstat->kstat->mode & S_IFMT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `		case S_IFDIR:`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_DIR << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `		case S_IFLNK:`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_SYMLINK << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `		case S_IFCHR:`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_CHARDEV << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		case S_IFBLK:`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_BLKDEV << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		case S_IFIFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_FIFO << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		case S_IFSOCK:`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_SOCKET << POSIX_FILETYPE_SHIFT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		posix_info->Inode = cpu_to_le64(ksmbd_kstat->kstat->ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		posix_info->DosAttributes =`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `			S_ISDIR(ksmbd_kstat->kstat->mode) ? ATTR_DIRECTORY_LE : ATTR_ARCHIVE_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] `		if (d_info->hide_dot_file && d_info->name[0] == '.')`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] `			posix_info->DosAttributes |= ATTR_HIDDEN_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] `		 * SidBuffer(32) contain two sids(Domain sid(16), UNIX group sid(16)).`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		 * UNIX sid(16) = revision(1) + num_subauth(1) + authority(6) +`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		 * 		  sub_auth(4 * 1(num_subauth)) + RID(4).`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] `		id_to_sid(from_kuid_munged(&init_user_ns, ksmbd_kstat->kstat->uid),`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] `			  SIDUNIX_USER, (struct smb_sid *)&posix_info->SidBuffer[0]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `		id_to_sid(from_kgid_munged(&init_user_ns, ksmbd_kstat->kstat->gid),`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `			  SIDUNIX_GROUP, (struct smb_sid *)&posix_info->SidBuffer[16]);`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [MEM_BOUNDS|] `		memcpy(posix_info->name, conv_name, conv_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00644 [NONE] `		posix_info->name_len = cpu_to_le32(conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `		posix_info->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	} /* switch (info_level) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `	d_info->last_entry_offset = d_info->data_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	d_info->data_count += next_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	d_info->out_buf_len -= next_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	d_info->wptr += next_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `		    "info_level : %d, buf_len :%d, next_offset : %d, data_count : %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `		    info_level, d_info->out_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `		    next_entry_offset, d_info->data_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `free_conv_name:`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	kfree(conv_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `struct smb2_query_dir_private {`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `	struct ksmbd_work	*work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	char			*search_pattern;`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	struct ksmbd_file	*dir_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `	struct ksmbd_dir_info	*d_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	int			info_level;`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `	int			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	int			entry_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `static void lock_dir(struct ksmbd_file *dir_fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `	struct dentry *dir = dir_fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `static void unlock_dir(struct ksmbd_file *dir_fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] `	struct dentry *dir = dir_fp->filp->f_path.dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	inode_unlock(d_inode(dir));`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `static int process_query_dir_entries(struct smb2_query_dir_private *priv)`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] `	struct mnt_idmap	*idmap = file_mnt_idmap(priv->dir_fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	struct user_namespace	*user_ns = file_mnt_user_ns(priv->dir_fp->filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] `	struct kstat		kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	struct ksmbd_kstat	ksmbd_kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `	int			rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `	int			i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `	for (i = 0; i < priv->d_info->num_entry; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `		struct dentry *dent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `		if (dentry_name(priv->d_info, priv->info_level))`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00710 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		dent = lookup_one_unlocked(idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `					   &QSTR_LEN(priv->d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `					   priv->d_info->name_len),`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `					   priv->dir_fp->filp->f_path.dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `		lock_dir(priv->dir_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `		dent = lookup_one(idmap, priv->d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `		dent = lookup_one(user_ns, priv->d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `				  priv->dir_fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `				  priv->d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `		dent = lookup_one_len(priv->d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] `				  priv->dir_fp->filp->f_path.dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `				  priv->d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		unlock_dir(priv->dir_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `		if (IS_ERR(dent)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] `			ksmbd_debug(SMB, "Cannot lookup \047%s' [%ld]\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `				    priv->d_info->name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `				    PTR_ERR(dent));`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `		if (unlikely(d_is_negative(dent))) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `			dput(dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `			ksmbd_debug(SMB, "Negative dentry \047%s'\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `				    priv->d_info->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `		ksmbd_kstat.kstat = &kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `		ksmbd_kstat.kstat_dentry = dent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `		ksmbd_kstat.share = priv->dir_fp->tcon ?`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] `			priv->dir_fp->tcon->share_conf : NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] `		ksmbd_kstat.idmap = idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `		if (priv->info_level != FILE_NAMES_INFORMATION) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `			rc = ksmbd_vfs_fill_dentry_attrs(priv->work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `							 idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `							 user_ns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `							 dent,`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `							 &ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `			if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `				dput(dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `		rc = smb2_populate_readdir_entry(priv->work->conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `						 priv->info_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `						 priv->d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `						 &ksmbd_kstat);`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `		dput(dent);`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `			return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `static int reserve_populate_dentry(struct ksmbd_dir_info *d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `				   int info_level, u32 file_index)`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	int struct_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `	int conv_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	int next_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	struct_sz = readdir_info_level_struct_sz(info_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `	if (struct_sz == -EOPNOTSUPP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00793 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `	conv_len = (d_info->name_len + 1) * 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `	next_entry_offset = ALIGN(struct_sz + conv_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `				  KSMBD_DIR_INFO_ALIGNMENT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	if (next_entry_offset > d_info->out_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		d_info->out_buf_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00801 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `	switch (info_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	case FILE_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `		struct file_full_directory_info *ffdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `		ffdinfo = (struct file_full_directory_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `		ffdinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [MEM_BOUNDS|] `		memcpy(ffdinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00811 [NONE] `		ffdinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `		ffdinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `		ffdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `	case FILE_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `		struct file_both_directory_info *fbdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `		fbdinfo = (struct file_both_directory_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `		fbdinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [MEM_BOUNDS|] `		memcpy(fbdinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00823 [NONE] `		fbdinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `		fbdinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `		fbdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `	case FILE_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `		struct file_directory_info *fdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] `		fdinfo = (struct file_directory_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `		fdinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [MEM_BOUNDS|] `		memcpy(fdinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00835 [NONE] `		fdinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] `		fdinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `		fdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	case FILE_NAMES_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `		struct file_names_info *fninfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `		fninfo = (struct file_names_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `		fninfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [MEM_BOUNDS|] `		memcpy(fninfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00847 [NONE] `		fninfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `		fninfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `		fninfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	case FILEID_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `		struct file_id_full_dir_info *dinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `		dinfo = (struct file_id_full_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		dinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [MEM_BOUNDS|] `		memcpy(dinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00859 [NONE] `		dinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `		dinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `		dinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	case FILEID_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `		struct file_id_both_directory_info *fibdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `		fibdinfo = (struct file_id_both_directory_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `		fibdinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [MEM_BOUNDS|] `		memcpy(fibdinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00872 [NONE] `		fibdinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `		fibdinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `		fibdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `	case FILEID_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `		struct file_id_extd_dir_info *extdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `		extdinfo = (struct file_id_extd_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `		extdinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [MEM_BOUNDS|] `		memcpy(extdinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00884 [NONE] `		extdinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `		extdinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `		extdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `		struct file_id_extd_both_dir_info *extdbinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `		extdbinfo = (struct file_id_extd_both_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `		extdbinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [MEM_BOUNDS|] `		memcpy(extdbinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00896 [NONE] `		extdbinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `		extdbinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `		extdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `	case FILEID_64_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] `		struct file_id_64_extd_dir_info *extd64info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] `		extd64info = (struct file_id_64_extd_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] `		extd64info->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [MEM_BOUNDS|] `		memcpy(extd64info->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00908 [NONE] `		extd64info->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `		extd64info->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `		extd64info->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] `	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `		struct file_id_64_extd_both_dir_info *extd64binfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `		extd64binfo = (struct file_id_64_extd_both_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `		extd64binfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [MEM_BOUNDS|] `		memcpy(extd64binfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00920 [NONE] `		extd64binfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `		extd64binfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] `		extd64binfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `		struct file_id_all_extd_dir_info *allexdinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] `		allexdinfo = (struct file_id_all_extd_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		allexdinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [MEM_BOUNDS|] `		memcpy(allexdinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00932 [NONE] `		allexdinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		allexdinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `		allexdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `		struct file_id_all_extd_both_dir_info *allexdbinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `		allexdbinfo =`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] `			(struct file_id_all_extd_both_dir_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `		allexdbinfo->FileIndex = file_index;`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [MEM_BOUNDS|] `		memcpy(allexdbinfo->FileName, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00945 [NONE] `		allexdbinfo->FileName[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `		allexdbinfo->FileNameLength = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `		allexdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	case SMB_FIND_FILE_POSIX_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `		struct smb2_posix_info *posix_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `		posix_info = (struct smb2_posix_info *)d_info->wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [MEM_BOUNDS|] `		memcpy(posix_info->name, d_info->name, d_info->name_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00956 [NONE] `		posix_info->name[d_info->name_len] = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `		posix_info->name_len = cpu_to_le32(d_info->name_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `		posix_info->NextEntryOffset =`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `			cpu_to_le32(next_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `	} /* switch (info_level) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	d_info->num_entry++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	d_info->out_buf_len -= next_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	d_info->wptr += next_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `static bool __query_dir(struct dir_context *ctx, const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `static int __query_dir(struct dir_context *ctx, const char *name, int namlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `		       loff_t offset, u64 ino, unsigned int d_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `	struct ksmbd_readdir_data	*buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `	struct smb2_query_dir_private	*priv;`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `	struct ksmbd_dir_info		*d_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	int				rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	buf	= container_of(ctx, struct ksmbd_readdir_data, ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	priv	= buf->private;`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `	d_info	= priv->d_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	/* dot and dotdot entries are already reserved */`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	if (!strcmp(".", name) || !strcmp("..", name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	d_info->num_scan++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	if (ksmbd_share_veto_filename(priv->work->tcon->share_conf, name))`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `	if (!match_pattern(name, namlen, priv->search_pattern))`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [NONE] `	d_info->name		= name;`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] `	d_info->name_len	= namlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	rc = reserve_populate_dentry(d_info, priv->info_level, (u32)offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [PROTO_GATE|] `	if (d_info->flags & SMB2_RETURN_SINGLE_ENTRY) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01017 [NONE] `		d_info->out_buf_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `VISIBLE_IF_KUNIT int verify_info_level(int info_level)`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	switch (info_level) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `	case FILE_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `	case FILE_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `	case FILE_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] `	case FILE_NAMES_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	case FILEID_FULL_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	case FILEID_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `	case FILEID_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `	case FILEID_64_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `	case SMB_FIND_FILE_POSIX_INFO:`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [ERROR_PATH|] `		return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01051 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `EXPORT_SYMBOL_IF_KUNIT(verify_info_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `int smb2_resp_buf_len(struct ksmbd_work *work, unsigned short hdr2_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	int free_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	free_len = (int)(work->response_sz -`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [NONE] `		(get_rfc1002_len(work->response_buf) + 4)) - hdr2_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] `	return free_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] `int smb2_calc_max_out_buf_len(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `				     unsigned short hdr2_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `				     unsigned int out_buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `	int free_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `	if (out_buf_len > work->conn->vals->max_trans_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `		out_buf_len = work->conn->vals->max_trans_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `	free_len = smb2_resp_buf_len(work, hdr2_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `	if (free_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `	return min_t(int, out_buf_len, free_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `int smb2_query_dir(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `	struct ksmbd_conn *conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `	struct smb2_query_directory_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `	struct smb2_query_directory_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `	struct ksmbd_share_config *share = work->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `	struct ksmbd_file *dir_fp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `	struct ksmbd_dir_info d_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `	int rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `	char *srch_ptr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `	unsigned char srch_flag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `	int buffer_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `	int total_scan = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `	struct smb2_query_dir_private query_dir_private = {NULL, };`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `	ksmbd_debug(SMB, "Received smb2 query directory request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `	WORK_BUFFERS(work, req, rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	if (ksmbd_override_fsids(work)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_MEMORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01103 [NONE] `		smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01105 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `	rc = verify_info_level(req->FileInformationClass);`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `		rc = -EFAULT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01111 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `		u64 id = KSMBD_NO_FID, pid = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `		if (work->next_smb2_rcv_hdr_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `			if (!has_file_id(req->VolatileFileId)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `					    "Compound request set FID = %llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `					    work->compound_fid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `				id = work->compound_fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] `				pid = work->compound_pfid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `		if (!has_file_id(id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `			id = req->VolatileFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `			pid = req->PersistentFileId;`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `		dir_fp = ksmbd_lookup_fd_slow(work, id, pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `	if (!dir_fp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `		rc = -EBADF;`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01134 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `	if (!(dir_fp->daccess & FILE_LIST_DIRECTORY_LE) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	    inode_permission(file_mnt_idmap(dir_fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `	    inode_permission(file_mnt_user_ns(dir_fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `			     file_inode(dir_fp->filp),`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `			     MAY_READ | MAY_EXEC)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] `	if (!(dir_fp->daccess & FILE_LIST_DIRECTORY_LE) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [NONE] `	    inode_permission(file_inode(dir_fp->filp), MAY_READ | MAY_EXEC)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01148 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [ERROR_PATH|] `		pr_err("no right to enumerate directory (%pD)\n", dir_fp->filp);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01150 [NONE] `		rc = -EACCES;`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01152 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] `	if (!S_ISDIR(file_inode(dir_fp->filp)->i_mode)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [ERROR_PATH|] `		pr_err("can't do query dir for a file\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01156 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01158 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	srch_flag = req->Flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `	if ((u64)le16_to_cpu(req->FileNameOffset) + le16_to_cpu(req->FileNameLength) >`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `	    get_rfc1002_len(work->request_buf) + 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01165 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] `	srch_ptr = smb_strndup_from_utf16((char *)req + le16_to_cpu(req->FileNameOffset),`
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [NONE] `					  le16_to_cpu(req->FileNameLength), 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `					  conn->local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `	if (IS_ERR(srch_ptr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `		ksmbd_debug(SMB, "Search Pattern not found\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [ERROR_PATH|] `		goto err_out2;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01174 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `		ksmbd_debug(SMB, "Search pattern is %s\n", srch_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [PROTO_GATE|] `	if (srch_flag & SMB2_REOPEN) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01179 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [PROTO_GATE|] `		 * MS-SMB2 §3.3.5.17: SMB2_REOPEN requires the server to`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01181 [NONE] `		 * close and reopen the directory, resetting the enumeration`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `		 * state (search pattern, position, info class).  We implement`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `		 * this by seeking the file descriptor back to the start and`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `		 * clearing all cached enumeration state, which achieves the`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `		 * same observable effect while avoiding a real close/reopen.`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [PROTO_GATE|] `		ksmbd_debug(SMB, "Reopen directory (SMB2_REOPEN)\n");`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01188 [NONE] `		vfs_llseek(dir_fp->filp, 0, SEEK_SET);`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `		dir_fp->dot_dotdot[0] = dir_fp->dot_dotdot[1] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `		dir_fp->readdir_started = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [PROTO_GATE|] `	} else if (srch_flag & SMB2_RESTART_SCANS) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01192 [NONE] `		ksmbd_debug(SMB, "Restart directory scan\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		vfs_llseek(dir_fp->filp, 0, SEEK_SET);`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `		dir_fp->dot_dotdot[0] = dir_fp->dot_dotdot[1] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01197 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [PROTO_GATE|] `	 * SMB2_INDEX_SPECIFIED: MS-SMB2 §3.3.5.17 says the server SHOULD`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01199 [NONE] `	 * honor a client-supplied FileIndex but is not required to.  Using`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	 * vfs_llseek(SEEK_SET, FileIndex) on a directory descriptor restarts`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	 * the readdir scan from byte offset FileIndex, which in practice`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `	 * causes the kernel to re-emit entries already seen and produces an`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `	 * unbounded loop in tests that enumerate large directories (the smb2.dir`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `	 * "many" test counted 1 325 381 entries instead of 700).  We`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	 * deliberately ignore INDEX_SPECIFIED; the enumeration resumes from`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	 * wherever the last QUERY_DIRECTORY left the file position, which is`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	 * the correct behaviour for sequential scans and passes all Samba`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `	 * smbtorture tests.`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	memset(&d_info, 0, sizeof(struct ksmbd_dir_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `	d_info.wptr = (char *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	d_info.rptr = (char *)rsp->Buffer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `	d_info.out_buf_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `		smb2_calc_max_out_buf_len(work, 8,`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `					  le32_to_cpu(req->OutputBufferLength));`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] `	if (d_info.out_buf_len < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `		rc = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01220 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] `	d_info.flags = srch_flag;`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] `	 * reserve dot and dotdot entries in head of buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	 * in first response`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `	rc = ksmbd_populate_dot_dotdot_entries(work, req->FileInformationClass,`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `					       dir_fp, &d_info, srch_ptr,`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `					       smb2_populate_readdir_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	if (rc == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	else if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01234 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_HIDE_DOT_FILES))`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `		d_info.hide_dot_file = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	buffer_sz				= d_info.out_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `	d_info.rptr				= d_info.wptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	query_dir_private.work			= work;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `	query_dir_private.search_pattern	= srch_ptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	query_dir_private.dir_fp		= dir_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	query_dir_private.d_info		= &d_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `	query_dir_private.info_level		= req->FileInformationClass;`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] `	dir_fp->readdir_data.private		= &query_dir_private;`
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	set_ctx_actor(&dir_fp->readdir_data.ctx, __query_dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `again:`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	d_info.num_scan = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `	rc = iterate_dir(dir_fp->filp, &dir_fp->readdir_data.ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	total_scan += d_info.num_scan;`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	 * num_entry can be 0 if the directory iteration stops before reaching`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	 * the end of the directory and no file is matched with the search`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [NONE] `	 * pattern.`
  Review: Low-risk line; verify in surrounding control flow.
- L01256 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	 * Rate-limit wildcard directory scans: broad patterns (especially`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] `	 * "*") can match every entry in very large directories, making this`
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `	 * loop expensive.  Cap the total number of directory entries scanned`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `	 * per single QUERY_DIRECTORY request to 100 000 to bound CPU and`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `	 * I/O cost.  The client can issue subsequent requests to continue`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `	 * enumeration via the directory cursor.`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `	if (rc >= 0 && !d_info.num_entry && d_info.num_scan &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] `	    d_info.out_buf_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `		if (total_scan > 100000) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NO_MORE_FILES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01268 [ERROR_PATH|] `			goto no_buf_len;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01269 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [ERROR_PATH|] `		goto again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01271 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	 * req->OutputBufferLength is too small to contain even one entry.`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	 * In this case, it immediately returns OutputBufferLength 0 to client.`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	if (!d_info.out_buf_len && !d_info.num_entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [ERROR_PATH|] `		goto no_buf_len;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01278 [NONE] `	if (rc > 0 || rc == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `		rc = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `	else if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] `	d_info.wptr = d_info.rptr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	d_info.out_buf_len = buffer_sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `	rc = process_query_dir_entries(&query_dir_private);`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] `	if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [ERROR_PATH|] `		goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01288 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `	if (!d_info.data_count && d_info.out_buf_len >= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `		 * MS-SMB2 §3.3.5.17: Distinguish between:`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [PROTO_GATE|] `		 *   STATUS_NO_SUCH_FILE  — first call, pattern matched nothing`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01293 [PROTO_GATE|] `		 *   STATUS_NO_MORE_FILES — subsequent call, enumeration complete`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01294 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `		 * Use fp->readdir_started to track whether any entries have`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `		 * been returned for this handle.`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `		if (!dir_fp->readdir_started) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NO_SUCH_FILE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01300 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `			dir_fp->dot_dotdot[0] = dir_fp->dot_dotdot[1] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [PROTO_GATE|] `			rsp->hdr.Status = STATUS_NO_MORE_FILES;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01303 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `		rsp->Buffer[0] = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `				       offsetof(struct smb2_query_directory_rsp, Buffer)`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `				       + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01313 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `no_buf_len:`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `		if (d_info.data_count > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `			((struct file_directory_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `			((char *)rsp->Buffer + d_info.last_entry_offset))`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `			->NextEntryOffset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `			if (d_info.data_count >= d_info.last_entry_off_align)`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `				d_info.data_count -= d_info.last_entry_off_align;`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `			 * Mark that at least one entry has been returned.`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `			 * Subsequent calls with no entries return`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [PROTO_GATE|] `			 * STATUS_NO_MORE_FILES (not STATUS_NO_SUCH_FILE).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01325 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `			dir_fp->readdir_started = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `		rsp->StructureSize = cpu_to_le16(9);`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `		rsp->OutputBufferOffset = cpu_to_le16(72);`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `		rsp->OutputBufferLength = cpu_to_le32(d_info.data_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `				       offsetof(struct smb2_query_directory_rsp, Buffer) +`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `				       d_info.data_count);`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `		if (rc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [ERROR_PATH|] `			goto err_out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01337 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `	kfree(srch_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] `	ksmbd_fd_put(work, dir_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `err_out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [ERROR_PATH|] `	pr_err("error while processing smb2 query dir rc = %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01346 [NONE] `	kfree(srch_ptr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `err_out2:`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `	if (rc == -EINVAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_PARAMETER;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01351 [NONE] `	else if (rc == -EACCES)`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_ACCESS_DENIED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01353 [NONE] `	else if (rc == -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_SUCH_FILE;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01355 [NONE] `	else if (rc == -EBADF)`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CLOSED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01357 [NONE] `	else if (rc == -ENOMEM)`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_NO_MEMORY;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01359 [NONE] `	else if (rc == -EFAULT)`
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01361 [NONE] `	else if (rc == -EIO)`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_FILE_CORRUPT_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01363 [NONE] `	if (!rsp->hdr.Status)`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [PROTO_GATE|] `		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `	smb2_set_err_rsp(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	ksmbd_fd_put(work, dir_fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `	ksmbd_revert_fsids(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `	return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] ` * buffer_check_err() - helper function to check buffer errors`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] ` * @reqOutputBufferLength:	max buffer length expected in command response`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] ` * @rsp:		query info response buffer contains output buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] ` * @rsp_org:		base response buffer pointer in case of chained response`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] ` * Return:	0 on success, otherwise error`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
