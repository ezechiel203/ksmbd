# Line-by-line Review: src/include/fs/vfs_cache.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2019 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __VFS_CACHE_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __VFS_CACHE_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/file.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/rwsem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/idr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/refcount.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/timer.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/workqueue.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "vfs.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `/* Windows style file permissions for extended response */`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define	FILE_GENERIC_ALL	0x1F01FF`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define	FILE_GENERIC_READ	0x120089`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define	FILE_GENERIC_WRITE	0x120116`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define	FILE_GENERIC_EXECUTE	0x001200a0`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define KSMBD_START_FID		0`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define KSMBD_NO_FID		(INT_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [PROTO_GATE|] `#define SMB2_NO_FID		(0xFFFFFFFFFFFFFFFFULL)`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `struct ksmbd_session;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `struct ksmbd_notify_watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `struct ksmbd_lock {`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	struct file_lock *fl;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	struct list_head clist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	struct list_head flist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	struct list_head llist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	unsigned int flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	int cmd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	int zero_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	unsigned long long start;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	unsigned long long end;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `struct stream {`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	char *name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	ssize_t size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	loff_t pos;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `struct ksmbd_inode {`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	struct rw_semaphore		m_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [LIFETIME|] `	atomic_t			m_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00056 [LIFETIME|] `	atomic_t			op_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00057 [NONE] `	/* opinfo count for streams */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [LIFETIME|] `	atomic_t			sop_count;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00059 [NONE] `	struct dentry			*m_de;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	unsigned int			m_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	struct hlist_node		m_hash;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	struct list_head		m_fp_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	struct list_head		m_op_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	struct oplock_info		*m_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	__le32				m_fattr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	 * Cached AllocationSize set via SET_INFO.  -1 means "not`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	 * explicitly set -- derive from stat.blocks".  This exists`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	 * because stat.blocks on ext4 includes external xattr blocks`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	 * which inflates AllocationSize for empty files.`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	loff_t				m_cached_alloc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	FP_NEW = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	FP_INITED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	FP_CLOSED`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `struct ksmbd_file {`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `	struct file			*filp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	u64				persistent_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	u64				volatile_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	spinlock_t			f_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	struct ksmbd_inode		*f_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	struct ksmbd_inode		*f_parent_ci;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	struct oplock_info __rcu	*f_opinfo;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	struct ksmbd_conn		*conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	struct ksmbd_tree_connect	*tcon;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [LIFETIME|] `	refcount_t			refcount;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00095 [NONE] `	__le32				daccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	__le32				saccess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	__le32				coption;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	__le32				cdoption;`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	__u64				create_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	__u64				itime;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	bool				is_nt_open;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	bool				attrib_only;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	char				client_guid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	char				create_guid[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	char				app_instance_id[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	bool				has_app_instance_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	bool				has_app_instance_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	u64				app_instance_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	u64				app_instance_version_low;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	struct stream			stream;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	struct list_head		node;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	struct list_head		blocked_works;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	struct list_head		lock_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	/* Per-handle change-notify watch (persists across requests) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	struct ksmbd_notify_watch	*notify_watch;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	unsigned int			durable_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	unsigned int			durable_scavenger_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	 * C.5: Per-handle expiry timer for durable/persistent handles.`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	 * Armed at disconnect time; fires after durable_timeout ms.`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	 * The timer callback wakes the durable scavenger to reclaim`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	 * expired handles.  MS-SMB2 §3.3.5.9.7 requires the server`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	 * to apply a reconnect timeout to durable handles.`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	struct timer_list		durable_expire_timer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	/* for SMB1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	int				pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	/* conflict lock fail count for SMB1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	unsigned int			cflock_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	/* last lock failure start offset for SMB1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	unsigned long long		llock_fstart;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	int				dirent_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	/* for find_first/find_next */`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	char				*filename;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	/* if ls is happening on directory, below is valid*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	struct ksmbd_readdir_data	readdir_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	int				dot_dotdot[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	unsigned int			f_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	bool				reserve_lease_break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	bool				is_durable;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	bool				is_persistent;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	bool				is_resilient;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	unsigned int			resilient_timeout;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	bool				is_scavenger_claimed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	/* Saved create_action for DHv2 replay (MS-SMB2 3.3.5.9.10) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	int				create_action;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	/* Cached stat for DHv2 replay -- avoids timestamp drift */`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `		__u64			last_access;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		__u64			last_write;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `		__u64			change;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		__u64			alloc_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `		__u64			end_of_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `		__le32			file_attrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `		bool			valid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	} replay_cache;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	bool                            is_posix_ctxt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	bool				is_delete_on_close;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	 * Tracks whether any directory entries have been returned for this`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [PROTO_GATE|] `	 * handle.  The first call with no results returns STATUS_NO_SUCH_FILE`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00178 [PROTO_GATE|] `	 * (pattern never matched); subsequent calls return STATUS_NO_MORE_FILES`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00179 [NONE] `	 * (enumeration exhausted).  MS-SMB2 §3.3.5.17.`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	bool				readdir_started;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	/* Lock sequence validation for resilient/durable handles (MS-SMB2 3.3.5.14)`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	 * Valid indices: 1-64 (index 0 reserved), 0xFF = entry not valid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	__u8				lock_seq[65];`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	spinlock_t			lock_seq_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `	 * MS-SMB2 §3.3.5.2.10: ChannelSequence per open handle.`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	 * State-modifying requests (WRITE, LOCK, IOCTL, SET_INFO, FLUSH)`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	 * must not have a ChannelSequence older than the one already seen.`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	__u16				channel_sequence;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `static inline void set_ctx_actor(struct dir_context *ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `				 filldir_t actor)`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	ctx->actor = actor;`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `#define KSMBD_NR_OPEN_DEFAULT BITS_PER_LONG`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `struct ksmbd_file_table {`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	rwlock_t		lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	struct idr		*idr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `static inline bool has_file_id(u64 id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	return id < KSMBD_NO_FID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `static inline bool ksmbd_stream_fd(struct ksmbd_file *fp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	return fp->stream.name != NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ` * ksmbd_alloc_size() - Compute data-only AllocationSize for a file.`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ` * @fp:   ksmbd file pointer (for cached allocation size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ` * @stat: kstat filled by vfs_getattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * On ext4, stat.blocks can include external xattr blocks (e.g., for`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * security.NTACL).  This inflates AllocationSize for empty files.`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` * If set_file_allocation_info() has cached an explicit allocation`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` * size, use that instead of stat.blocks.`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ` * Return: AllocationSize in bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `static inline u64 ksmbd_alloc_size(struct ksmbd_file *fp, struct kstat *stat)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	if (fp && fp->f_ci && fp->f_ci->m_cached_alloc >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		return (u64)fp->f_ci->m_cached_alloc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	return stat->blocks << 9;`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `int ksmbd_init_file_table(struct ksmbd_file_table *ft);`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `void ksmbd_destroy_file_table(struct ksmbd_file_table *ft);`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `int ksmbd_close_fd(struct ksmbd_work *work, u64 id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_fast(struct ksmbd_work *work, u64 id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `struct ksmbd_file *ksmbd_lookup_foreign_fd(struct ksmbd_work *work, u64 id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_slow(struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `					u64 pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `void ksmbd_fd_put(struct ksmbd_work *work, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `struct ksmbd_inode *ksmbd_inode_lookup_lock(struct dentry *d);`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `void ksmbd_inode_put(struct ksmbd_inode *ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `struct ksmbd_file *ksmbd_lookup_global_fd(unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `struct ksmbd_file *ksmbd_lookup_durable_fd(unsigned long long id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `void ksmbd_put_durable_fd(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_cguid(char *cguid);`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_filename(struct ksmbd_work *work, char *filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_inode(struct dentry *dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `struct ksmbd_file *ksmbd_lookup_fd_inode_sess(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `					      u64 ino);`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `unsigned int ksmbd_open_durable_fd(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `struct ksmbd_file *ksmbd_open_fd(struct ksmbd_work *work, struct file *filp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `void ksmbd_launch_ksmbd_durable_scavenger(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `void ksmbd_stop_durable_scavenger(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `void ksmbd_close_tree_conn_fds(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `void ksmbd_close_session_fds(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `int ksmbd_close_inode_fds(struct ksmbd_work *work, struct inode *inode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `int ksmbd_init_global_file_table(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `void ksmbd_free_global_file_table(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `int ksmbd_file_table_flush(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `void ksmbd_set_fd_limit(unsigned long limit);`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `void ksmbd_update_fstate(struct ksmbd_file_table *ft, struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `			 unsigned int state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ` * INODE hash`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `int __init ksmbd_inode_hash_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `void ksmbd_release_inode_hash(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `enum KSMBD_INODE_STATUS {`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [PROTO_GATE|] `	KSMBD_INODE_STATUS_OK,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00280 [PROTO_GATE|] `	KSMBD_INODE_STATUS_UNKNOWN,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00281 [PROTO_GATE|] `	KSMBD_INODE_STATUS_PENDING_DELETE,`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00282 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `int ksmbd_query_inode_status(struct dentry *dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `bool ksmbd_inode_pending_delete(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `bool ksmbd_inode_clear_pending_delete_if_only(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `void ksmbd_set_inode_pending_delete(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `void ksmbd_clear_inode_pending_delete(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `void ksmbd_fd_set_delete_on_close(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `				  int file_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `void ksmbd_inode_set_posix(struct ksmbd_inode *ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `int ksmbd_reopen_durable_fd(struct ksmbd_work *work, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `int ksmbd_validate_name_reconnect(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `				  struct ksmbd_file *fp, char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `int ksmbd_init_file_cache(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `void ksmbd_exit_file_cache(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `bool fd_limit_depleted(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `unsigned long inode_hash(struct super_block *sb, unsigned long hashval);`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `int ksmbd_inode_init(struct ksmbd_inode *ci, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `bool __sanity_check(struct ksmbd_tree_connect *tcon, struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `#endif /* CONFIG_KUNIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `#endif /* __VFS_CACHE_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
