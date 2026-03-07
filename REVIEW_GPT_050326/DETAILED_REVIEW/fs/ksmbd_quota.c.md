# Line-by-line Review: src/fs/ksmbd_quota.c

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
- L00006 [NONE] ` *   SMB2 quota query support for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [PROTO_GATE|] ` *   Implements the SMB2_O_INFO_QUOTA info-level handler that maps`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00009 [NONE] ` *   Windows SIDs to Linux uids and queries the VFS quota subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   via dquot_get_dqblk() when CONFIG_QUOTA is enabled.`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/quota.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/quotaops.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <linux/overflow.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "smbacl.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "ksmbd_info.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "ksmbd_quota.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * SMB2 QUERY_QUOTA_INFO input buffer — [MS-SMB2] 2.2.37.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * Sent in the InputBuffer of an SMB2 QUERY_INFO request when`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [PROTO_GATE|] ` * InfoType == SMB2_O_INFO_QUOTA.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00035 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `struct smb2_query_quota_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	__u8	ReturnSingle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	__u8	RestartScan;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	__le16	Reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	__le32	SidListLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	__le32	StartSidLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	__le32	StartSidOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * FILE_GET_QUOTA_INFORMATION — [MS-FSCC] 2.4.33.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` * Each entry in the SidList of the query request.`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `struct file_get_quota_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	__le32	NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	__le32	SidLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	__u8	Sid[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` * FILE_QUOTA_INFORMATION — [MS-FSCC] 2.4.33`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` * Each entry in the output buffer of a quota query response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `struct smb2_file_quota_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	__le32	NextEntryOffset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	__le32	SidLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	__le64	ChangeTime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	__le64	QuotaUsed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	__le64	QuotaThreshold;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	__le64	QuotaLimit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__u8	Sid[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * ksmbd_sid_byte_len() - compute total byte size of a packed SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * @sid: pointer to an smb_sid structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * Return: total byte length of the SID (base + sub-authorities)`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `static inline unsigned int ksmbd_sid_byte_len(const struct smb_sid *sid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	return CIFS_SID_BASE_SIZE +`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	       sizeof(__le32) * sid->num_subauth;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` * ksmbd_sid_to_uid() - Extract a Linux uid from a Windows SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` * @sid:     the Windows SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ` * @sid_len: byte length of the SID buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ` * @uid_out: [out] the resulting uid`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * Uses the domain-aware SID-to-UID mapping from smbacl.c to convert`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * a Windows SID to a Linux UID.  This ensures that SIDs from`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * different domains with the same RID map to different UIDs,`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * preventing quota bypass in multi-domain AD environments.`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `static int ksmbd_sid_to_uid(const struct smb_sid *sid, unsigned int sid_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `			    uid_t *uid_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	if (sid->num_subauth == 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	    sid->num_subauth > SID_MAX_SUB_AUTHORITIES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	/* Validate that the buffer is large enough for all sub-authorities */`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	if (sid_len < CIFS_SID_BASE_SIZE +`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `		      (unsigned int)sid->num_subauth * sizeof(__le32))`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	 * Use domain-aware mapping: the RID is offset by a hash of the`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	 * domain prefix for foreign-domain SIDs, preventing UID collisions.`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	return ksmbd_validate_sid_to_uid((struct smb_sid *)sid, uid_out);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `#ifdef CONFIG_QUOTA`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * ksmbd_fill_quota_info() - Fill one FILE_QUOTA_INFORMATION entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * @sb:        super_block of the share filesystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * @sid:       the Windows SID for this user`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * @sid_len:   byte length of @sid`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` * @uid:       Linux uid whose quota to query`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * @out:       output buffer pointer`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` * @buf_rem:   remaining bytes in output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` * @out_len:   [out] bytes written to @out`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` * Queries the Linux quota subsystem for @uid's quota on @sb and`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] ` * formats a FILE_QUOTA_INFORMATION entry into @out.`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `static int ksmbd_fill_quota_info(struct super_block *sb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `				 const struct smb_sid *sid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `				 unsigned int sid_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `				 uid_t uid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `				 void *out,`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `				 unsigned int buf_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `				 unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	struct smb2_file_quota_info *qi;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	struct qc_dqblk dqblk;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	struct kqid qid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	unsigned int entry_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	entry_size = sizeof(struct smb2_file_quota_info) + sid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	/* Align to 8 bytes for potential chaining */`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	entry_size = ALIGN(entry_size, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	if (buf_rem < entry_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00152 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	memset(out, 0, entry_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	qi = (struct smb2_file_quota_info *)out;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	qid = make_kqid(&init_user_ns, USRQUOTA, uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	if (!qid_valid(qid)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00161 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	memset(&dqblk, 0, sizeof(dqblk));`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	ret = dquot_get_dqblk(sb, qid, &dqblk);`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		 * If quota lookup fails (e.g., quotas not enabled for`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `		 * this user), return an entry with zeroed quota values.`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		 * This is more informative than skipping the entry.`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `			    "dquot_get_dqblk failed for uid %u: %d, returning zeros\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `			    uid, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `		memset(&dqblk, 0, sizeof(dqblk));`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	qi->NextEntryOffset = 0; /* caller chains entries */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	qi->SidLength = cpu_to_le32(sid_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	qi->ChangeTime = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	qi->QuotaUsed = cpu_to_le64(dqblk.d_space);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	qi->QuotaThreshold = cpu_to_le64(dqblk.d_spc_softlimit);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	qi->QuotaLimit = cpu_to_le64(dqblk.d_spc_hardlimit);`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [MEM_BOUNDS|] `	memcpy(qi->Sid, sid, sid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	*out_len = entry_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `#endif /* CONFIG_QUOTA */`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [PROTO_GATE|] ` * ksmbd_quota_query() - SMB2_O_INFO_QUOTA GET handler`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00192 [NONE] ` * @work:    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ` * @fp:      ksmbd file pointer (used to locate the filesystem)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ` * @buf:     response buffer to fill with FILE_QUOTA_INFORMATION`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ` * @buf_len: available space in @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` * @out_len: [out] total bytes written to @buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [PROTO_GATE|] ` * Handles SMB2 QUERY_INFO requests with InfoType == SMB2_O_INFO_QUOTA.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00199 [NONE] ` * Extracts SIDs from the request input buffer, maps each SID to a`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` * Linux uid, queries the VFS quota subsystem, and formats the`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ` * response as FILE_QUOTA_INFORMATION entries.`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * If the filesystem does not support quotas or CONFIG_QUOTA is not`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * enabled, returns an empty response (zero-length output) which`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` * signals to the client that no quota data is available.`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `static int ksmbd_quota_query(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `			     struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `			     void *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `			     unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `			     unsigned int *out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `#ifdef CONFIG_QUOTA`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	struct smb2_query_info_req *req = ksmbd_req_buf_next(work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	struct super_block *sb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	struct smb2_query_quota_info *qqi;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	unsigned int input_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	unsigned int total_written = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	void *input_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	void *prev_entry = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	if (!fp || !fp->filp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `		ksmbd_debug(SMB, "Quota query: no file pointer\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00229 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	sb = fp->filp->f_path.dentry->d_sb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	if (!sb) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `		ksmbd_debug(SMB, "Quota query: no super_block\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00235 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	/* Check if user quotas are enabled on this filesystem */`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	if (!sb_has_quota_active(sb, USRQUOTA)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `			    "Quota query: quotas not active on filesystem\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [PROTO_GATE|] `	/* Parse the input buffer (SMB2_QUERY_QUOTA_INFO) */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00246 [NONE] `	input_buf_len = le32_to_cpu(req->InputBufferLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	if (input_buf_len < sizeof(struct smb2_query_quota_info)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `			    "Quota query: input buffer too small (%u < %zu)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `			    input_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `			    sizeof(struct smb2_query_quota_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `		*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		unsigned int ibo = le16_to_cpu(req->InputBufferOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `		if (ibo < sizeof(struct smb2_hdr) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `		    ibo - sizeof(struct smb2_hdr) + sizeof(struct smb2_query_quota_info) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `		    input_buf_len + sizeof(struct smb2_hdr)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `				    "Quota query: InputBufferOffset %u out of bounds\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `				    ibo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `			*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `		input_buf = (void *)req + ibo - sizeof(struct smb2_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	qqi = (struct smb2_query_quota_info *)input_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	 * Process the SID list if present.  Each entry is a`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	 * FILE_GET_QUOTA_INFORMATION structure containing a SID`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	 * whose quota data the client wants.`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	if (le32_to_cpu(qqi->SidListLength) > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `		unsigned int sid_list_len = le32_to_cpu(qqi->SidListLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `		void *sid_list = (void *)qqi + sizeof(*qqi);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		unsigned int offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `		if (sizeof(*qqi) + sid_list_len > input_buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `				    "Quota query: SidListLength %u exceeds buffer (%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `				    sid_list_len, input_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `			*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `		while (offset < sid_list_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `			struct file_get_quota_info *gqi;`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `			struct smb_sid *sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `			unsigned int sid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `			unsigned int entry_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `			uid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `			int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `			if (offset + sizeof(*gqi) > sid_list_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `			gqi = (struct file_get_quota_info *)(sid_list + offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `			sid_len = le32_to_cpu(gqi->SidLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `			if (sid_len < CIFS_SID_BASE_SIZE ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `			    offset + sizeof(*gqi) + sid_len > sid_list_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `			sid = (struct smb_sid *)gqi->Sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `			ret = ksmbd_sid_to_uid(sid, sid_len, &uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `			if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `				ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `					    "Quota: failed to map SID to uid\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `				/* Skip this SID */`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `				if (le32_to_cpu(gqi->NextEntryOffset) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `				offset += le32_to_cpu(gqi->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `			ret = ksmbd_fill_quota_info(sb, sid, sid_len, uid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `						    (u8 *)buf + total_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `						    buf_len - total_written,`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `						    &entry_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `			if (ret == -ENOSPC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] `			if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `			/* Chain previous entry to this one */`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `			if (prev_entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `				struct smb2_file_quota_info *prev =`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `					(struct smb2_file_quota_info *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `					prev_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `				prev->NextEntryOffset = cpu_to_le32(`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `					(u8 *)buf + total_written -`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `					(u8 *)prev_entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `			prev_entry = (u8 *)buf + total_written;`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `			total_written += entry_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `			if (qqi->ReturnSingle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `			if (le32_to_cpu(gqi->NextEntryOffset) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `			offset += le32_to_cpu(gqi->NextEntryOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	} else if (le32_to_cpu(qqi->StartSidLength) > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] `		 * StartSid-based enumeration: query quota for the`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `		 * single user identified by the StartSid.`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `		unsigned int start_sid_off = le32_to_cpu(qqi->StartSidOffset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		unsigned int start_sid_len = le32_to_cpu(qqi->StartSidLength);`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		unsigned int start_sid_end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `		struct smb_sid *sid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		unsigned int entry_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `		uid_t uid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `		int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [MEM_BOUNDS|] `		if (check_add_overflow(start_sid_off, start_sid_len,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00364 [NONE] `				       &start_sid_end) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `		    start_sid_end > input_buf_len ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		    start_sid_len < CIFS_SID_BASE_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [ERROR_PATH|] `			goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `		sid = (struct smb_sid *)((u8 *)qqi + start_sid_off);`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `		ret = ksmbd_sid_to_uid(sid, start_sid_len, &uid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [ERROR_PATH|] `			goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00374 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `		ret = ksmbd_fill_quota_info(sb, sid, start_sid_len, uid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `					    buf, buf_len, &entry_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `		if (ret == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `			total_written = entry_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `done:`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `	*out_len = total_written;`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `	/* CONFIG_QUOTA not enabled — return empty response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	*out_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `#endif /* CONFIG_QUOTA */`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `static struct ksmbd_info_handler ksmbd_quota_get_handler = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [PROTO_GATE|] `	.info_type	= SMB2_O_INFO_QUOTA,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00393 [NONE] `	.info_class	= 0, /* quota queries do not use info class */`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	.op		= KSMBD_INFO_GET,`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	.handler	= ksmbd_quota_query,`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	.owner		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] ` * ksmbd_quota_init() - Initialize quota query handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [PROTO_GATE|] ` * Registers the SMB2_O_INFO_QUOTA GET handler in the info-level`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00403 [NONE] ` * dispatch table.`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `int ksmbd_quota_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	ret = ksmbd_register_info_handler(&ksmbd_quota_get_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [ERROR_PATH|] `		pr_err("Failed to register quota info handler: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00414 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	ksmbd_debug(SMB, "Quota query handler registered\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ` * ksmbd_quota_exit() - Tear down quota query handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ` * Unregisters the quota info-level handler.`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `void ksmbd_quota_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	ksmbd_unregister_info_handler(&ksmbd_quota_get_handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
