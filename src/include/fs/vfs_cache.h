/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#ifndef __VFS_CACHE_H__
#define __VFS_CACHE_H__

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/refcount.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#include "vfs.h"
#include "mgmt/share_config.h"

/* Windows style file permissions for extended response */
#define	FILE_GENERIC_ALL	0x1F01FF
#define	FILE_GENERIC_READ	0x120089
#define	FILE_GENERIC_WRITE	0x120116
#define	FILE_GENERIC_EXECUTE	0x001200a0

#define KSMBD_START_FID		0
#define KSMBD_NO_FID		(INT_MAX)
#define SMB2_NO_FID		(0xFFFFFFFFFFFFFFFFULL)

struct ksmbd_conn;
struct ksmbd_session;
struct ksmbd_notify_watch;

struct ksmbd_lock {
	struct file_lock *fl;
	struct list_head clist;
	struct list_head flist;
	struct list_head llist;
	unsigned int flags;
	int cmd;
	int zero_len;
	unsigned long long start;
	unsigned long long end;
};

struct stream {
	char *name;
	ssize_t size;
	loff_t pos;
};

struct ksmbd_inode {
	struct rw_semaphore		m_lock;
	atomic_t			m_count;
	atomic_t			op_count;
	/* opinfo count for streams */
	atomic_t			sop_count;
	struct dentry			*m_de;
	unsigned int			m_flags;
	struct hlist_node		m_hash;
	struct list_head		m_fp_list;
	struct list_head		m_op_list;
	struct oplock_info		*m_opinfo;
	__le32				m_fattr;
	/*
	 * Cached AllocationSize set via SET_INFO.  -1 means "not
	 * explicitly set -- derive from stat.blocks".  This exists
	 * because stat.blocks on ext4 includes external xattr blocks
	 * which inflates AllocationSize for empty files.
	 */
	loff_t				m_cached_alloc;

	/*
	 * Parent lease key of the handle that set delete-on-close.
	 * Used at deletion time to determine directory lease break
	 * exemption: if the closer's parent key matches the DOC-setter's
	 * key, that directory lease is exempted; if they differ, all
	 * directory leases are broken.
	 */
	__u8				m_doc_parent_key[16];
	bool				m_doc_parent_key_valid;
};

enum {
	FP_NEW = 0,
	FP_INITED,
	FP_CLOSED
};

struct ksmbd_file {
	struct file			*filp;
	u64				persistent_id;
	u64				volatile_id;

	spinlock_t			f_lock;

	struct ksmbd_inode		*f_ci;
	struct ksmbd_inode		*f_parent_ci;
	struct oplock_info __rcu	*f_opinfo;
	struct ksmbd_conn		*conn;
	struct ksmbd_tree_connect	*tcon;
	struct ksmbd_file_table		*ft;

	refcount_t			refcount;
	__le32				daccess;
	__le32				saccess;
	__le32				coption;
	__le32				cdoption;
	__u64				create_time;
	__u64				itime;

	bool				is_nt_open;
	bool				attrib_only;

	char				client_guid[16];
	char				create_guid[16];
	char				app_instance_id[16];
	bool				has_app_instance_id;
	bool				has_app_instance_version;
	u64				app_instance_version;
	u64				app_instance_version_low;

	struct stream			stream;
	struct list_head		node;
	struct list_head		blocked_works;
	struct list_head		lock_list;

	/* Per-handle change-notify watch (persists across requests) */
	struct ksmbd_notify_watch	*notify_watch;

	unsigned int			durable_timeout;
	unsigned long			durable_scavenger_timeout;

	/*
	 * C.5: Per-handle expiry timer for durable/persistent handles.
	 * Armed at disconnect time; fires after durable_timeout ms.
	 * The timer callback wakes the durable scavenger to reclaim
	 * expired handles.  MS-SMB2 §3.3.5.9.7 requires the server
	 * to apply a reconnect timeout to durable handles.
	 */
	struct timer_list		durable_expire_timer;

#ifdef CONFIG_SMB_INSECURE_SERVER
	/* for SMB1 */
	int				pid;

	/* conflict lock fail count for SMB1 */
	unsigned int			cflock_cnt;
	/* last lock failure start offset for SMB1 */
	unsigned long long		llock_fstart;

	int				dirent_offset;

	/* for find_first/find_next */
	char				*filename;
#endif
	/* if ls is happening on directory, below is valid*/
	struct ksmbd_readdir_data	readdir_data;
	int				dot_dotdot[2];
	/* QD-01: last search pattern for QUERY_DIRECTORY reuse */
	char				*search_pattern;
	unsigned int			f_state;
	bool				reserve_lease_break;
	bool				is_durable;
	bool				is_persistent;
	bool				persistent_restore_pending;
	bool				is_resilient;
	unsigned int			resilient_timeout;
	bool				is_scavenger_claimed;

	/* Saved create_action for DHv2 replay (MS-SMB2 3.3.5.9.10) */
	int				create_action;

	/* Cached stat for DHv2 replay -- avoids timestamp drift */
	struct {
		__u64			last_access;
		__u64			last_write;
		__u64			change;
		__u64			alloc_size;
		__u64			end_of_file;
		__le32			file_attrs;
		bool			valid;
	} replay_cache;

	bool                            is_posix_ctxt;
	bool				is_delete_on_close;

	/*
	 * Tracks whether any directory entries have been returned for this
	 * handle.  The first call with no results returns STATUS_NO_SUCH_FILE
	 * (pattern never matched); subsequent calls return STATUS_NO_MORE_FILES
	 * (enumeration exhausted).  MS-SMB2 §3.3.5.17.
	 */
	bool				readdir_started;

	/* Lock sequence validation for resilient/durable handles (MS-SMB2 3.3.5.14)
	 * Valid indices: 1-64 (index 0 reserved), 0xFF = entry not valid */
	__u8				lock_seq[65];
	spinlock_t			lock_seq_lock;

	/*
	 * MS-SMB2 §3.3.5.2.10: ChannelSequence per open handle.
	 * State-modifying requests (WRITE, LOCK, IOCTL, SET_INFO, FLUSH)
	 * must not have a ChannelSequence older than the one already seen.
	 */
	__u16				channel_sequence;
};

static inline void set_ctx_actor(struct dir_context *ctx,
				 filldir_t actor)
{
	ctx->actor = actor;
}

#define KSMBD_NR_OPEN_DEFAULT BITS_PER_LONG

struct ksmbd_file_table {
	rwlock_t		lock;
	struct idr		*idr;
};

static inline bool has_file_id(u64 id)
{
	return id < KSMBD_NO_FID;
}

static inline bool ksmbd_stream_fd(struct ksmbd_file *fp)
{
	return fp->stream.name != NULL;
}

/**
 * ksmbd_alloc_size() - Compute data-only AllocationSize for a file.
 * @fp:   ksmbd file pointer (for cached allocation size)
 * @stat: kstat filled by vfs_getattr
 *
 * On ext4, stat.blocks can include external xattr blocks (e.g., for
 * security.NTACL).  This inflates AllocationSize for empty files.
 * If set_file_allocation_info() has cached an explicit allocation
 * size, use that instead of stat.blocks.
 *
 * Return: AllocationSize in bytes
 */
static inline u64 ksmbd_alloc_size(struct ksmbd_file *fp, struct kstat *stat)
{
	if (fp && fp->f_ci && fp->f_ci->m_cached_alloc >= 0)
		return (u64)fp->f_ci->m_cached_alloc;
	return stat->blocks << 9;
}

int ksmbd_init_file_table(struct ksmbd_file_table *ft);
void ksmbd_destroy_file_table(struct ksmbd_file_table *ft);
int ksmbd_close_fd(struct ksmbd_work *work, u64 id);
struct ksmbd_file *ksmbd_lookup_fd_fast(struct ksmbd_work *work, u64 id);
struct ksmbd_file *ksmbd_lookup_foreign_fd(struct ksmbd_work *work, u64 id);
struct ksmbd_file *ksmbd_lookup_fd_slow(struct ksmbd_work *work, u64 id,
					u64 pid);
void ksmbd_fd_put(struct ksmbd_work *work, struct ksmbd_file *fp);
struct ksmbd_inode *ksmbd_inode_lookup_lock(struct dentry *d);
bool ksmbd_inode_is_smb_delete(struct dentry *d);
void ksmbd_inode_put(struct ksmbd_inode *ci);
struct ksmbd_file *ksmbd_lookup_global_fd(unsigned long long id);
struct ksmbd_file *ksmbd_lookup_durable_fd(unsigned long long id);
void ksmbd_put_durable_fd(struct ksmbd_file *fp);
void ksmbd_purge_disconnected_fp(struct ksmbd_inode *ci);
struct ksmbd_file *ksmbd_lookup_fd_cguid(char *cguid);
#ifdef CONFIG_SMB_INSECURE_SERVER
struct ksmbd_file *ksmbd_lookup_fd_filename(struct ksmbd_work *work, char *filename);
#endif
struct ksmbd_file *ksmbd_lookup_fd_inode(struct dentry *dentry);
struct ksmbd_file *ksmbd_lookup_fd_inode_sess(struct ksmbd_work *work,
					      u64 ino);
unsigned int ksmbd_open_durable_fd(struct ksmbd_file *fp);
int ksmbd_open_durable_fd_id(struct ksmbd_file *fp, u64 id);
struct ksmbd_file *ksmbd_open_fd(struct ksmbd_work *work, struct file *filp);
void ksmbd_launch_ksmbd_durable_scavenger(void);
void ksmbd_request_durable_scavenger_stop(void);
void ksmbd_stop_durable_scavenger(void);
void ksmbd_close_tree_conn_fds(struct ksmbd_work *work);
void ksmbd_close_session_fds(struct ksmbd_work *work);
int ksmbd_close_inode_fds(struct ksmbd_work *work, struct inode *inode);
int ksmbd_init_global_file_table(void);
bool ksmbd_global_file_table_inited(void);
void ksmbd_free_global_file_table(void);
int ksmbd_file_table_flush(struct ksmbd_work *work);
void ksmbd_set_fd_limit(unsigned long limit);
void ksmbd_update_fstate(struct ksmbd_file_table *ft, struct ksmbd_file *fp,
			 unsigned int state);

/*
 * INODE hash
 */
int __init ksmbd_inode_hash_init(void);
void ksmbd_release_inode_hash(void);

enum KSMBD_INODE_STATUS {
	KSMBD_INODE_STATUS_OK,
	KSMBD_INODE_STATUS_UNKNOWN,
	KSMBD_INODE_STATUS_PENDING_DELETE,
};

int ksmbd_query_inode_status(struct dentry *dentry);
bool ksmbd_inode_pending_delete(struct ksmbd_file *fp);
bool ksmbd_inode_clear_pending_delete_if_only(struct ksmbd_file *fp);
void ksmbd_set_inode_pending_delete(struct ksmbd_file *fp);
void ksmbd_clear_inode_pending_delete(struct ksmbd_file *fp);
void ksmbd_fd_set_delete_on_close(struct ksmbd_file *fp,
				  int file_info);
bool ksmbd_inode_will_delete_on_close(struct ksmbd_file *fp);
void ksmbd_inode_set_posix(struct ksmbd_inode *ci);
int ksmbd_reopen_durable_fd(struct ksmbd_work *work, struct ksmbd_file *fp);
void ksmbd_force_close_fd(struct ksmbd_file_table *ft, u64 id);
int ksmbd_validate_name_reconnect(struct ksmbd_share_config *share,
				  struct ksmbd_file *fp, char *name);
void ksmbd_durable_unbind_opinfo_conn(struct ksmbd_file *fp,
				      struct ksmbd_conn *conn);
void ksmbd_durable_rebind_opinfo_conn(struct ksmbd_file *fp,
				      struct ksmbd_conn *conn);
int ksmbd_init_file_cache(void);
void ksmbd_exit_file_cache(void);
#if IS_ENABLED(CONFIG_KUNIT)
bool fd_limit_depleted(void);
unsigned long inode_hash(struct super_block *sb, unsigned long hashval);
int ksmbd_inode_init(struct ksmbd_inode *ci, struct ksmbd_file *fp);
bool __sanity_check(struct ksmbd_tree_connect *tcon, struct ksmbd_file *fp);
#endif /* CONFIG_KUNIT */

#endif /* __VFS_CACHE_H__ */
