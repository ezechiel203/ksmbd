# Line-by-line Review: src/include/protocol/smb2pdu_internal.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * Internal header for smb2pdu decomposed files.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` * Functions that were static in smb2pdu.c but are now needed`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` * across multiple decomposed compilation units.`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef __SMB2PDU_INTERNAL_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __SMB2PDU_INTERNAL_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "smb2pdu.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "mgmt/user_session.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/* WORK_BUFFERS helper macro — used across many files */`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `void __wbuf(struct ksmbd_work *work, void **req, void **rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#define WORK_BUFFERS(w, rq, rs)	__wbuf((w), (void **)&(rq), (void **)&(rs))`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `/* Cap lock count to prevent memory exhaustion from single request */`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#define KSMBD_MAX_LOCK_COUNT	64`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * check_session_id() - check for valid session id in smb header`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * @conn:	connection instance`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * @id:		session id from smb header`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * Return:      1 if valid session id, otherwise 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `static inline bool check_session_id(struct ksmbd_conn *conn, u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	struct ksmbd_session *sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	if (id == 0 || id == (u64)-1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	sess = ksmbd_session_lookup_all(conn, id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	if (sess) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `		ksmbd_user_session_put(sess);`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [ERROR_PATH|] `	pr_err_ratelimited("Invalid user session id: %llu\n", id);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00040 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `/* Shared helpers from smb2_pdu_common.c */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `__le32 smb2_get_reparse_tag_special_file(umode_t mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `int smb2_get_dos_mode(struct kstat *stat, int attribute);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `/* smb2_get_name is used by create and query_set */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `char *smb2_get_name(const char *src, const int maxlen,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `		    struct nls_table *local_nls);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `/* Shared helpers used across dir/query_set */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `int smb2_resp_buf_len(struct ksmbd_work *work, unsigned short hdr2_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `int smb2_calc_max_out_buf_len(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `			      unsigned short hdr2_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `			      unsigned int out_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `/* Functions from smb2_create.c needed by smb2_query_set.c */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `struct smb_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `void ksmbd_acls_fattr(struct smb_fattr *fattr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `		      struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `		      struct user_namespace *mnt_userns,`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `		      struct inode *inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `int smb2_set_ea(struct smb2_ea_info *eabuf, unsigned int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `		const struct path *path, bool get_write);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#endif /* __SMB2PDU_INTERNAL_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
