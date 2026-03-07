/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __KSMBD_OPLOCK_H
#define __KSMBD_OPLOCK_H

#include <linux/refcount.h>
#include "smb_common.h"

#define OPLOCK_WAIT_TIME	(35 * HZ)

/* Handle-caching break mode for oplock_break() req_op_level. */
#define OPLOCK_BREAK_HANDLE_CACHING	0x10
/* Handle break that blocks until ACK (for rename into directory). */
#define OPLOCK_BREAK_HANDLE_CACHING_WAIT	0x11

#ifdef CONFIG_SMB_INSECURE_SERVER
/* SMB Oplock levels */
#define OPLOCK_NONE      0
#define OPLOCK_EXCLUSIVE 1
#define OPLOCK_BATCH     2
#define OPLOCK_READ      3  /* level 2 oplock */
#endif

/* Oplock states */
#define OPLOCK_STATE_NONE	0x00
#define OPLOCK_ACK_WAIT		0x01
#define OPLOCK_CLOSING		0x02

#define OPLOCK_WRITE_TO_READ		0x01
#define OPLOCK_READ_HANDLE_TO_READ	0x02
#define OPLOCK_WRITE_TO_NONE		0x04
#define OPLOCK_READ_TO_NONE		0x08
#define OPLOCK_WRITE_HANDLE_TO_WRITE	0x10

/*
 * C.8: Bitmask covering Read and Handle caching bits for lease v2
 * parent-lease key comparison.  Used to mask out other flags when
 * comparing lease states to avoid spurious break notifications due
 * to extra flag bits.
 * MS-SMB2 §3.3.4.7 / §3.3.5.22.
 */
#define LEASE_RH_MASK	(SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE)

struct lease_ctx_info {
	__u8			lease_key[SMB2_LEASE_KEY_SIZE];
	__le32			req_state;
	__le32			flags;
	__le64			duration;
	__u8			parent_lease_key[SMB2_LEASE_KEY_SIZE];
	__le16			epoch;
	int			version;
	bool			is_dir;
};

struct lease_table {
	char			client_guid[SMB2_CLIENT_GUID_SIZE];
	struct list_head	lease_list;
	struct list_head	l_entry;
	spinlock_t		lb_lock;
	struct rcu_head		rcu_head;
};

struct lease {
	__u8			lease_key[SMB2_LEASE_KEY_SIZE];
	__le32			state;
	__le32			new_state;
	__le32			flags;
	__le64			duration;
	__u8			parent_lease_key[SMB2_LEASE_KEY_SIZE];
	int			version;
	unsigned short		epoch;
	bool			is_dir;
	struct lease_table	*l_lb;
};

struct oplock_info {
	struct ksmbd_conn	*conn;
	struct ksmbd_session	*sess;
	struct ksmbd_work	*work;
	struct ksmbd_file	*o_fp;
	int                     level;
	int                     op_state;
	unsigned long		pending_break;
	u64			fid;
	atomic_t		breaking_cnt;
	refcount_t		refcount;
	__u16                   Tid;
	bool			is_lease;
#ifdef CONFIG_SMB_INSECURE_SERVER
	bool			is_smb2;
#endif
	bool			open_trunc;	/* truncate on open */
	int			notified_level;	/* OB-01: oplock level sent in break notification */
	bool			nowait_ack;	/* send break but don't wait for ack */
	/* M-12: break reason for lease break notification (SMB2_LEASE_BREAK_REASON_*) */
	__le32			break_reason;
	struct lease		*o_lease;
	struct file_lease	*fl_lease;	/* kernel VFS lease */
	struct list_head        op_entry;
	struct list_head        lease_entry;
	wait_queue_head_t oplock_q; /* Other server threads */
	wait_queue_head_t oplock_brk; /* oplock breaking wait */
};

struct lease_break_info {
	__le32			curr_state;
	__le32			new_state;
	__le16			epoch;
	/* M-12: MS-SMB2 §2.2.23.2 — BreakReason (0 = NONE, 2 = PARENT_LEASE_KEY_CHANGED) */
	__le32			break_reason;
	char			lease_key[SMB2_LEASE_KEY_SIZE];
};

struct oplock_break_info {
	int level;
	int open_trunc;
	int fid;
};

int smb_grant_oplock(struct ksmbd_work *work, int req_op_level,
		     u64 pid, struct ksmbd_file *fp, __u16 tid,
		     struct lease_ctx_info *lctx, int share_ret);
void smb_break_all_levII_oplock(struct ksmbd_work *work,
				struct ksmbd_file *fp, int is_trunc);
int opinfo_write_to_read(struct oplock_info *opinfo);
int opinfo_read_handle_to_read(struct oplock_info *opinfo);
int opinfo_write_handle_to_write(struct oplock_info *opinfo);
int opinfo_write_to_none(struct oplock_info *opinfo);
int opinfo_read_to_none(struct oplock_info *opinfo);
void close_id_del_oplock(struct ksmbd_file *fp);
void smb_break_all_oplock(struct ksmbd_work *work, struct ksmbd_file *fp);
void smb_break_all_handle_lease(struct ksmbd_work *work, struct ksmbd_file *fp,
				bool wait);
void ksmbd_inode_store_doc_parent_key(struct ksmbd_file *fp);
void smb_dirlease_break_on_delete(struct ksmbd_file *fp);
void smb_break_target_handle_lease(struct ksmbd_work *work,
				   struct ksmbd_inode *ci);
struct oplock_info *opinfo_get(struct ksmbd_file *fp);
void opinfo_put(struct oplock_info *opinfo);

/* Lease related functions */
void create_lease_buf(u8 *rbuf, struct lease *lease);
struct lease_ctx_info *parse_lease_state(void *open_req);
__u8 smb2_map_lease_to_oplock(__le32 lease_state);
int lease_read_to_write(struct oplock_info *opinfo);

/* Durable related functions */
void create_durable_rsp_buf(char *cc);
void create_durable_v2_rsp_buf(char *cc, struct ksmbd_file *fp);
void create_mxac_rsp_buf(char *cc, int maximal_access);
void create_disk_id_rsp_buf(char *cc, __u64 file_id, __u64 vol_id);
void create_posix_rsp_buf(char *cc, struct ksmbd_file *fp);
#ifdef CONFIG_KSMBD_FRUIT
int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn, size_t *out_size);
#else
static inline int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn,
				       size_t *out_size)
{ return -EOPNOTSUPP; }
#endif
struct create_context *smb2_find_context_vals(void *open_req, const char *tag, int tag_len);
struct oplock_info *lookup_lease_in_table(struct ksmbd_conn *conn,
					  char *lease_key);
int find_same_lease_key(struct ksmbd_session *sess, struct ksmbd_inode *ci,
			struct lease_ctx_info *lctx);
void destroy_lease_table(struct ksmbd_conn *conn);
void smb_send_parent_lease_break_noti(struct ksmbd_file *fp,
				      struct lease_ctx_info *lctx);
void smb_lazy_parent_lease_break_close(struct ksmbd_file *fp);
void smb_break_parent_dir_lease(struct ksmbd_file *fp);
void smb_break_parent_dir_lease_level(struct ksmbd_file *fp, int break_level);
void smb_break_dir_lease_by_dentry(struct dentry *d, struct ksmbd_file *fp);
void smb_break_dir_lease_by_dentry_level(struct dentry *d,
					 struct ksmbd_file *fp,
					 int break_level);
int smb2_check_durable_oplock(struct ksmbd_conn *conn,
			      struct ksmbd_share_config *share,
			      struct ksmbd_file *fp,
			      struct lease_ctx_info *lctx,
			      char *name);
int ksmbd_restore_oplock(struct ksmbd_work *work, struct ksmbd_file *fp,
			 int level, struct lease_ctx_info *lctx);
int ksmbd_oplock_init(void);
void ksmbd_oplock_exit(void);

#if IS_ENABLED(CONFIG_KUNIT)
int alloc_lease(struct oplock_info *opinfo, struct lease_ctx_info *lctx);
int lease_none_upgrade(struct oplock_info *opinfo, __le32 new_state);
void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,
			struct lease_ctx_info *lctx);
void grant_read_oplock(struct oplock_info *opinfo_new,
		       struct lease_ctx_info *lctx);
void grant_none_oplock(struct oplock_info *opinfo_new,
		       struct lease_ctx_info *lctx);
int compare_guid_key(struct oplock_info *opinfo,
		     const char *guid1, const char *key1);
struct oplock_info *same_client_has_lease(struct ksmbd_inode *ci,
					  char *client_guid,
					  struct lease_ctx_info *lctx);
struct oplock_info *opinfo_get_list(struct ksmbd_inode *ci);
int oplock_break_pending(struct oplock_info *opinfo, int req_op_level);
int oplock_break(struct oplock_info *brk_opinfo, int req_op_level,
		 struct ksmbd_work *in_work);
void set_oplock_level(struct oplock_info *opinfo, int level,
		      struct lease_ctx_info *lctx);
void copy_lease(struct oplock_info *op1, struct oplock_info *op2);
int add_lease_global_list(struct oplock_info *opinfo);
void ksmbd_apply_disconnected_only_lease_policy(int *req_op_level,
						struct lease_ctx_info *lctx);
void ksmbd_apply_read_handle_lease_policy(int *req_op_level,
					  struct lease_ctx_info *lctx);
bool ksmbd_is_strict_stat_open(const struct ksmbd_file *fp);
#endif /* CONFIG_KUNIT */

#endif /* __KSMBD_OPLOCK_H */
