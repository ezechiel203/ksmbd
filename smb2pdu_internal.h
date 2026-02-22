/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Internal header for smb2pdu decomposed files.
 * Functions that were static in smb2pdu.c but are now needed
 * across multiple decomposed compilation units.
 */
#ifndef __SMB2PDU_INTERNAL_H__
#define __SMB2PDU_INTERNAL_H__

#include "smb2pdu.h"

/* WORK_BUFFERS helper macro — used across many files */
void __wbuf(struct ksmbd_work *work, void **req, void **rsp);
#define WORK_BUFFERS(w, rq, rs)	__wbuf((w), (void **)&(rq), (void **)&(rs))

/* Cap lock count to prevent memory exhaustion from single request */
#define KSMBD_MAX_LOCK_COUNT	64

/**
 * check_session_id() - check for valid session id in smb header
 * @conn:	connection instance
 * @id:		session id from smb header
 *
 * Return:      1 if valid session id, otherwise 0
 */
static inline bool check_session_id(struct ksmbd_conn *conn, u64 id)
{
	struct ksmbd_session *sess;

	if (id == 0 || id == -1)
		return false;

	sess = ksmbd_session_lookup_all(conn, id);
	if (sess) {
		ksmbd_user_session_put(sess);
		return true;
	}
	pr_err_ratelimited("Invalid user session id: %llu\n", id);
	return false;
}

/* Shared helpers from smb2_pdu_common.c */
__le32 smb2_get_reparse_tag_special_file(umode_t mode);
int smb2_get_dos_mode(struct kstat *stat, int attribute);

/* smb2_get_name is used by create and query_set */
char *smb2_get_name(const char *src, const int maxlen,
		    struct nls_table *local_nls);

/* Shared helpers used across dir/query_set */
int smb2_resp_buf_len(struct ksmbd_work *work, unsigned short hdr2_len);
int smb2_calc_max_out_buf_len(struct ksmbd_work *work,
			      unsigned short hdr2_len,
			      unsigned int out_buf_len);

/* Functions from smb2_create.c needed by smb2_query_set.c */
struct smb_fattr;
void ksmbd_acls_fattr(struct smb_fattr *fattr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		      struct mnt_idmap *idmap,
#else
		      struct user_namespace *mnt_userns,
#endif
		      struct inode *inode);

int smb2_set_ea(struct smb2_ea_info *eabuf, unsigned int buf_len,
		const struct path *path, bool get_write);

#endif /* __SMB2PDU_INTERNAL_H__ */
