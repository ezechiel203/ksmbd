# Line-by-line Review: src/include/fs/oplock.h

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
- L00007 [NONE] `#ifndef __KSMBD_OPLOCK_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_OPLOCK_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/refcount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#define OPLOCK_WAIT_TIME	(35 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `/* Handle-caching break mode for oplock_break() req_op_level. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#define OPLOCK_BREAK_HANDLE_CACHING	0x10`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `/* SMB Oplock levels */`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define OPLOCK_NONE      0`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define OPLOCK_EXCLUSIVE 1`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define OPLOCK_BATCH     2`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define OPLOCK_READ      3  /* level 2 oplock */`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `/* Oplock states */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define OPLOCK_STATE_NONE	0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define OPLOCK_ACK_WAIT		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define OPLOCK_CLOSING		0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define OPLOCK_WRITE_TO_READ		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define OPLOCK_READ_HANDLE_TO_READ	0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define OPLOCK_WRITE_TO_NONE		0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define OPLOCK_READ_TO_NONE		0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define OPLOCK_WRITE_HANDLE_TO_WRITE	0x10`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * C.8: Bitmask covering Read and Handle caching bits for lease v2`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * parent-lease key comparison.  Used to mask out other flags when`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * comparing lease states to avoid spurious break notifications due`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * to extra flag bits.`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * MS-SMB2 §3.3.4.7 / §3.3.5.22.`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [PROTO_GATE|] `#define LEASE_RH_MASK	(SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00045 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `struct lease_ctx_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [PROTO_GATE|] `	__u8			lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00048 [NONE] `	__le32			req_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	__le32			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	__le64			duration;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [PROTO_GATE|] `	__u8			parent_lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00052 [NONE] `	__le16			epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	int			version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	bool			is_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `struct lease_table {`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [PROTO_GATE|] `	char			client_guid[SMB2_CLIENT_GUID_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00059 [NONE] `	struct list_head	lease_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	struct list_head	l_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	spinlock_t		lb_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [LIFETIME|] `	struct rcu_head		rcu_head;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00063 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `struct lease {`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [PROTO_GATE|] `	__u8			lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00067 [NONE] `	__le32			state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	__le32			new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	__le32			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	__le64			duration;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [PROTO_GATE|] `	__u8			parent_lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00072 [NONE] `	int			version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	unsigned short		epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	bool			is_dir;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	struct lease_table	*l_lb;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `struct oplock_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	struct ksmbd_conn	*conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	struct ksmbd_session	*sess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `	struct ksmbd_work	*work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	struct ksmbd_file	*o_fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	int                     level;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	int                     op_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	unsigned long		pending_break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	u64			fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [LIFETIME|] `	atomic_t		breaking_cnt;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00088 [LIFETIME|] `	refcount_t		refcount;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00089 [NONE] `	__u16                   Tid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	bool			is_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	bool			is_smb2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	bool			open_trunc;	/* truncate on open */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	bool			nowait_ack;	/* send break but don't wait for ack */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	struct lease		*o_lease;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	struct list_head        op_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	struct list_head        lease_entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	wait_queue_head_t oplock_q; /* Other server threads */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	wait_queue_head_t oplock_brk; /* oplock breaking wait */`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `struct lease_break_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	__le32			curr_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	__le32			new_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	__le16			epoch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [PROTO_GATE|] `	char			lease_key[SMB2_LEASE_KEY_SIZE];`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00108 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `struct oplock_break_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	int level;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	int open_trunc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	int fid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `int smb_grant_oplock(struct ksmbd_work *work, int req_op_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `		     u64 pid, struct ksmbd_file *fp, __u16 tid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		     struct lease_ctx_info *lctx, int share_ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `void smb_break_all_levII_oplock(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `				struct ksmbd_file *fp, int is_trunc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `int opinfo_write_to_read(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `int opinfo_read_handle_to_read(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `int opinfo_write_handle_to_write(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `int opinfo_write_to_none(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `int opinfo_read_to_none(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `void close_id_del_oplock(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `void smb_break_all_oplock(struct ksmbd_work *work, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `void smb_break_all_handle_lease(struct ksmbd_work *work, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `struct oplock_info *opinfo_get(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `void opinfo_put(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `/* Lease related functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `void create_lease_buf(u8 *rbuf, struct lease *lease);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `struct lease_ctx_info *parse_lease_state(void *open_req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `__u8 smb2_map_lease_to_oplock(__le32 lease_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `int lease_read_to_write(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `/* Durable related functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `void create_durable_rsp_buf(char *cc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `void create_durable_v2_rsp_buf(char *cc, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `void create_mxac_rsp_buf(char *cc, int maximal_access);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `void create_disk_id_rsp_buf(char *cc, __u64 file_id, __u64 vol_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `void create_posix_rsp_buf(char *cc, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn, size_t *out_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `static inline int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `				       size_t *out_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00150 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `struct create_context *smb2_find_context_vals(void *open_req, const char *tag, int tag_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `struct oplock_info *lookup_lease_in_table(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `					  char *lease_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `int find_same_lease_key(struct ksmbd_session *sess, struct ksmbd_inode *ci,`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `			struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `void destroy_lease_table(struct ksmbd_conn *conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `void smb_send_parent_lease_break_noti(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `				      struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `void smb_lazy_parent_lease_break_close(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `void smb_break_parent_dir_lease(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `void smb_break_dir_lease_by_dentry(struct dentry *d, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `int smb2_check_durable_oplock(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `			      struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `			      struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `			      struct lease_ctx_info *lctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `			      char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `int ksmbd_oplock_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `void ksmbd_oplock_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `int alloc_lease(struct oplock_info *opinfo, struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `int lease_none_upgrade(struct oplock_info *opinfo, __le32 new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `			struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `void grant_read_oplock(struct oplock_info *opinfo_new,`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `		       struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `void grant_none_oplock(struct oplock_info *opinfo_new,`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		       struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `int compare_guid_key(struct oplock_info *opinfo,`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		     const char *guid1, const char *key1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `struct oplock_info *same_client_has_lease(struct ksmbd_inode *ci,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `					  char *client_guid,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `					  struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `int oplock_break_pending(struct oplock_info *opinfo, int req_op_level);`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `int oplock_break(struct oplock_info *brk_opinfo, int req_op_level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `		 struct ksmbd_work *in_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `void set_oplock_level(struct oplock_info *opinfo, int level,`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `		      struct lease_ctx_info *lctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `void copy_lease(struct oplock_info *op1, struct oplock_info *op2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `int add_lease_global_list(struct oplock_info *opinfo);`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `#endif /* CONFIG_KUNIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `#endif /* __KSMBD_OPLOCK_H */`
  Review: Low-risk line; verify in surrounding control flow.
