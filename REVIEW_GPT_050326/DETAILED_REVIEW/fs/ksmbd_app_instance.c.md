# Line-by-line Review: src/fs/ksmbd_app_instance.c

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
- L00006 [NONE] ` *   APP_INSTANCE_ID / APP_INSTANCE_VERSION create context handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` *   APP_INSTANCE_ID (MS-SMB2 2.2.13.2.13) allows a client to associate`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   an application instance GUID with a file open.  If a new open`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   arrives with the same APP_INSTANCE_ID on the same file, the server`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   closes the previous open.  This is critical for failover clustering.`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *   APP_INSTANCE_VERSION (MS-SMB2 2.2.13.2.18) extends this with`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *   version tracking -- the old handle is only closed if the new`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *   version is higher.`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/uuid.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include <linux/unaligned.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "ksmbd_app_instance.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "ksmbd_create_ctx.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * APP_INSTANCE_ID create context structure (MS-SMB2 2.2.13.2.13)`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * StructureSize:  Must be 20`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * Reserved:       Must be 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * AppInstanceId:  16-byte application instance GUID`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define APP_INSTANCE_ID_STRUCT_SIZE	20`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define APP_INSTANCE_ID_GUID_OFFSET	4`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define APP_INSTANCE_ID_GUID_LEN	16`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * APP_INSTANCE_VERSION create context structure (MS-SMB2 2.2.13.2.18)`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * StructureSize:  Must be 24`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * Reserved:       Must be 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * Padding:        4 bytes padding`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * AppInstanceVersionHigh: 8 bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * AppInstanceVersionLow:  8 bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define APP_INSTANCE_VERSION_STRUCT_SIZE	24`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define APP_INSTANCE_VERSION_HIGH_OFFSET	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#define APP_INSTANCE_VERSION_LOW_OFFSET		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [PROTO_GATE|] ` * Binary tag for SMB2_CREATE_APP_INSTANCE_ID`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00054 [NONE] ` * GUID: 45BCA66A-EFA7-F74A-9008-FA462E144D74`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `static const char app_instance_id_tag[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	0x45, 0xBC, 0xA6, 0x6A, 0xEF, 0xA7, 0xF7, 0x4A,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	0x90, 0x08, 0xFA, 0x46, 0x2E, 0x14, 0x4D, 0x74`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [PROTO_GATE|] ` * Binary tag for SMB2_CREATE_APP_INSTANCE_VERSION`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00063 [NONE] ` * GUID: B982D0B7-3B56-074F-A07B-524A8116A010`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `static const char app_instance_version_tag[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	0xB9, 0x82, 0xD0, 0xB7, 0x3B, 0x56, 0x07, 0x4F,`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	0xA0, 0x7B, 0x52, 0x4A, 0x81, 0x16, 0xA0, 0x10`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * close_previous_app_instance() - Close prior opens with same app instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * @work:	smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * @fp:		the newly opened file (already in the inode fp list)`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * @version_high: app instance version high from the new open`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * @version_low: app instance version low from the new open`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * @has_version: true if APP_INSTANCE_VERSION context was supplied`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * Walk the inode's file list looking for an existing open that has the`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * same app_instance_id on the same inode.  If found, close it only`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * when the new version is strictly higher (or when no version context`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * was supplied, which implies unconditional close).`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `static void close_previous_app_instance(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `					struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `					u64 version_high,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `					u64 version_low,`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `					bool has_version)`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	struct ksmbd_inode *ci = fp->f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	struct ksmbd_file *prev_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	u64 found_id = KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	 * Serialize access to the fp list with ci->m_lock.  We capture`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	 * the volatile_id under the lock and then use ksmbd_close_fd()`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	 * after releasing it.  This is safe against a concurrent close`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	 * racing between the unlock and ksmbd_close_fd(): the latter`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	 * performs its own idr_find() under ft->lock and gracefully`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	 * handles the case where the id has already been removed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [LOCK|] `	down_read(&ci->m_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00102 [NONE] `	list_for_each_entry(prev_fp, &ci->m_fp_list, node) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `		if (prev_fp == fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		if (!prev_fp->has_app_instance_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `		if (memcmp(prev_fp->app_instance_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `			   fp->app_instance_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `			   APP_INSTANCE_ID_GUID_LEN))`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		 * Same app instance ID on same inode.  If the new open`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `		 * carries a version, only close if (high, low) is strictly`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		 * higher than the previous open's version tuple.`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `		if (has_version) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `			if (prev_fp->app_instance_version > version_high)`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `			if (prev_fp->app_instance_version == version_high &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `			    prev_fp->app_instance_version_low >= version_low)`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `		 * Capture the volatile ID while protected by ci->m_lock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `		 * Do not retain a raw pointer after unlocking -- only`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `		 * the integer id is safe to use after the lock is dropped.`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `		found_id = prev_fp->volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	up_read(&ci->m_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	if (has_file_id(found_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `			    "Closing previous app instance open fid=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `			    found_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `		ksmbd_close_fd(work, found_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * app_instance_id_on_request() - Handle APP_INSTANCE_ID create context`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * @work:	smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * @fp:		the file being opened`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` * @ctx_data:	raw context data blob (after the tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` * @ctx_len:	length of the context data`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` * Parses the 16-byte application instance GUID from the context data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` * stores it on the ksmbd_file, and closes any prior opens with the`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` * same app instance ID on the same inode.`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `static int app_instance_id_on_request(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `				      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `				      const void *ctx_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `				      unsigned int ctx_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	const u8 *data = ctx_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	static const u8 zero_guid[APP_INSTANCE_ID_GUID_LEN] = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	if (ctx_len < APP_INSTANCE_ID_STRUCT_SIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `			    "APP_INSTANCE_ID: context too short (%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `			    ctx_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00171 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	/* Skip StructureSize (2 bytes) and Reserved (2 bytes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [MEM_BOUNDS|] `	memcpy(fp->app_instance_id, data + APP_INSTANCE_ID_GUID_OFFSET,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00175 [NONE] `	       APP_INSTANCE_ID_GUID_LEN);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	/* A zero GUID means "no app instance" -- ignore it */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	if (!memcmp(fp->app_instance_id, zero_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `		    APP_INSTANCE_ID_GUID_LEN)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		ksmbd_debug(SMB, "APP_INSTANCE_ID: zero GUID, ignoring\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	fp->has_app_instance_id = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	ksmbd_debug(SMB, "APP_INSTANCE_ID: set on fid=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		    fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	close_previous_app_instance(work, fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `				    fp->app_instance_version,`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `				    fp->app_instance_version_low,`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `				    fp->has_app_instance_version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * app_instance_version_on_request() - Handle APP_INSTANCE_VERSION context`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` * @work:	smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` * @fp:		the file being opened`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` * @ctx_data:	raw context data blob (after the tag)`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` * @ctx_len:	length of the context data`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * Parses the version from the context data and stores it on the`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * ksmbd_file.  If an APP_INSTANCE_ID was already set on this file,`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` * re-evaluates existing opens with version comparison -- the old`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` * handle is closed only when the new version is strictly higher.`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `static int app_instance_version_on_request(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `					   struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `					   const void *ctx_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `					   unsigned int ctx_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	const u8 *data = ctx_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	u64 ver_high, ver_low;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	if (ctx_len < APP_INSTANCE_VERSION_STRUCT_SIZE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `			    "APP_INSTANCE_VERSION: context too short (%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `			    ctx_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00223 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	 * AppInstanceVersionHigh at offset 8,`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	 * AppInstanceVersionLow at offset 16.`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	 * Per MS-SMB2, compare high first, then low if equal.`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	 * We store the high part as the primary version since it`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	 * dominates the comparison.`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	ver_high = get_unaligned_le64(data +`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `				      APP_INSTANCE_VERSION_HIGH_OFFSET);`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	ver_low = get_unaligned_le64(data +`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `				     APP_INSTANCE_VERSION_LOW_OFFSET);`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	fp->has_app_instance_version = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	fp->app_instance_version = ver_high;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	fp->app_instance_version_low = ver_low;`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		    "APP_INSTANCE_VERSION: high=%llu low=%llu on fid=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `		    ver_high, ver_low, fp->volatile_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	 * If this file already has an app instance ID set (the`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	 * APP_INSTANCE_ID context is typically processed first),`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	 * try to close previous opens with version comparison.`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	if (fp->has_app_instance_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `		close_previous_app_instance(work, fp, ver_high, ver_low, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `/* Create context handler descriptors */`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `static struct ksmbd_create_ctx_handler app_instance_id_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	.tag		= app_instance_id_tag,`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	.tag_len	= sizeof(app_instance_id_tag),`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	.on_request	= app_instance_id_on_request,`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	.on_response	= NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `static struct ksmbd_create_ctx_handler app_instance_version_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	.tag		= app_instance_version_tag,`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	.tag_len	= sizeof(app_instance_version_tag),`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	.on_request	= app_instance_version_on_request,`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	.on_response	= NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ` * ksmbd_app_instance_init() - Initialize app instance create contexts`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ` * Registers the APP_INSTANCE_ID and APP_INSTANCE_VERSION create`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ` * context handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `int ksmbd_app_instance_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	ret = ksmbd_register_create_context(&app_instance_id_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [ERROR_PATH|] `		pr_err("Failed to register APP_INSTANCE_ID handler: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00288 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	ret = ksmbd_register_create_context(&app_instance_version_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [ERROR_PATH|] `		pr_err("Failed to register APP_INSTANCE_VERSION handler: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00295 [NONE] `		       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [ERROR_PATH|] `		goto err_unregister_id;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00297 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `	ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `		    "APP_INSTANCE_ID/VERSION create contexts initialized\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `err_unregister_id:`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	ksmbd_unregister_create_context(&app_instance_id_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ` * ksmbd_app_instance_exit() - Tear down app instance create contexts`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ` * Unregisters the APP_INSTANCE_ID and APP_INSTANCE_VERSION handlers.`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `void ksmbd_app_instance_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	ksmbd_unregister_create_context(&app_instance_version_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	ksmbd_unregister_create_context(&app_instance_id_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
