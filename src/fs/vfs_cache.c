// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 * Copyright (C) 2019 Samsung Electronics Co., Ltd.
 */

#include <kunit/visibility.h>
#include <linux/fs.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "glob.h"
#include "vfs_cache.h"
#include "oplock.h"
#include "vfs.h"
#include "connection.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "smb2pdu.h"
#include "smb_common.h"
#include "server.h"
#include "ksmbd_notify.h"

#define S_DEL_PENDING			1
#define S_DEL_ON_CLS			2
/* S_SMB_DELETE: deletion was initiated via SMB (not external VFS).
 * Used by change notification to emit FILE_ACTION_REMOVED_BY_DELETE (0x9)
 * instead of FILE_ACTION_REMOVED (0x2) per MS-FSCC §2.4.42.
 */
#define S_SMB_DELETE			4
#define S_DEL_ON_CLS_STREAM		8
#define S_POSIX_OPENED			16

static unsigned int inode_hash_mask __read_mostly;
static unsigned int inode_hash_shift __read_mostly;

/**
 * struct ksmbd_inode_hash_bucket - per-bucket inode hash entry
 * @head:	hash chain list head
 * @lock:	per-bucket rwlock for reduced contention
 */
struct ksmbd_inode_hash_bucket {
	struct hlist_head	head;
	rwlock_t		lock;
};

static struct ksmbd_inode_hash_bucket *inode_hashtable __read_mostly;

static struct ksmbd_file_table global_ft;
static atomic_long_t fd_limit;
static struct kmem_cache *filp_cache;

static atomic_t durable_scavenger_wake_seq = ATOMIC_INIT(0);
static bool durable_scavenger_running;
static DEFINE_MUTEX(durable_scavenger_lock);
static wait_queue_head_t dh_wq;

void ksmbd_set_fd_limit(unsigned long limit)
{
	limit = min(limit, get_max_files());
	atomic_long_set(&fd_limit, limit);
}

static bool fd_limit_depleted(void)
{
	long v = atomic_long_dec_return(&fd_limit);

	if (v >= 0)
		return false;
	atomic_long_inc(&fd_limit);
	return true;
}

static void fd_limit_close(void)
{
	atomic_long_inc(&fd_limit);
}

/*
 * INODE hash
 */

static unsigned long inode_hash(struct super_block *sb, unsigned long hashval)
{
	unsigned long tmp;

	tmp = (hashval * (unsigned long)sb) ^ (GOLDEN_RATIO_PRIME + hashval) /
		L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> inode_hash_shift);
	return tmp & inode_hash_mask;
}

static struct ksmbd_inode *__ksmbd_inode_lookup(struct dentry *de)
{
	unsigned long bucket =
		inode_hash(d_inode(de)->i_sb, (unsigned long)de);
	struct ksmbd_inode *ci = NULL, *ret_ci = NULL;

	hlist_for_each_entry(ci, &inode_hashtable[bucket].head, m_hash) {
		if (ci->m_de == de) {
			if (atomic_inc_not_zero(&ci->m_count))
				ret_ci = ci;
			break;
		}
	}
	return ret_ci;
}

static struct ksmbd_inode *ksmbd_inode_lookup(struct ksmbd_file *fp)
{
	return __ksmbd_inode_lookup(fp->filp->f_path.dentry);
}

struct ksmbd_inode *ksmbd_inode_lookup_lock(struct dentry *d)
{
	struct ksmbd_inode *ci;
	unsigned long bucket =
		inode_hash(d_inode(d)->i_sb, (unsigned long)d);

	read_lock(&inode_hashtable[bucket].lock);
	ci = __ksmbd_inode_lookup(d);
	read_unlock(&inode_hashtable[bucket].lock);

	return ci;
}

/**
 * ksmbd_inode_is_smb_delete() - check if deletion was initiated via SMB.
 * @d: dentry of the file being deleted
 *
 * Returns true if at least one SMB handle requested deletion of this inode
 * (via FILE_DELETE_ON_CLOSE or FileDispositionInformation).  Used by change
 * notification to emit FILE_ACTION_REMOVED_BY_DELETE (0x9) per MS-FSCC §2.4.42.
 *
 * Caller must hold a reference that keeps @d valid (which fsnotify guarantees).
 */
bool ksmbd_inode_is_smb_delete(struct dentry *d)
{
	struct ksmbd_inode *ci;
	bool result = false;
	unsigned long bucket =
		inode_hash(d_inode(d)->i_sb, (unsigned long)d);

	read_lock(&inode_hashtable[bucket].lock);
	ci = __ksmbd_inode_lookup(d);
	read_unlock(&inode_hashtable[bucket].lock);

	if (ci) {
		down_read(&ci->m_lock);
		result = !!(ci->m_flags & S_SMB_DELETE);
		up_read(&ci->m_lock);
		ksmbd_inode_put(ci);
	}

	return result;
}

int ksmbd_query_inode_status(struct dentry *dentry)
{
	struct ksmbd_inode *ci;
	int ret = KSMBD_INODE_STATUS_UNKNOWN;
	unsigned long bucket =
		inode_hash(d_inode(dentry)->i_sb, (unsigned long)dentry);

	read_lock(&inode_hashtable[bucket].lock);
	ci = __ksmbd_inode_lookup(dentry);
	read_unlock(&inode_hashtable[bucket].lock);
	if (!ci)
		return ret;

	down_read(&ci->m_lock);
	if (ci->m_flags & (S_DEL_PENDING | S_DEL_ON_CLS))
		ret = KSMBD_INODE_STATUS_PENDING_DELETE;
	else
		ret = KSMBD_INODE_STATUS_OK;
	up_read(&ci->m_lock);

	ksmbd_inode_put(ci);
	return ret;
}

bool ksmbd_inode_pending_delete(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci = fp->f_ci;
	int ret;

	down_read(&ci->m_lock);
	/*
	 * Only S_DEL_PENDING (set via FileDispositionInformation) blocks new
	 * opens with STATUS_DELETE_PENDING.  S_DEL_ON_CLS is a per-handle
	 * property (FILE_DELETE_ON_CLOSE in CreateOptions); the file is simply
	 * deleted when the last handle closes, but new opens are permitted in
	 * the meantime -- matching Windows Server behaviour per MS-SMB2
	 * §3.3.5.9.6.
	 */
	ret = (ci->m_flags & S_DEL_PENDING);
	up_read(&ci->m_lock);

	return ret;
}

bool ksmbd_inode_clear_pending_delete_if_only(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci = fp->f_ci;
	bool cleared = false;

	down_write(&ci->m_lock);
	if ((ci->m_flags & (S_DEL_PENDING | S_DEL_ON_CLS)) &&
	    list_is_singular(&ci->m_fp_list)) {
		ci->m_flags &= ~(S_DEL_PENDING | S_DEL_ON_CLS);
		cleared = true;
	}
	up_write(&ci->m_lock);

	return cleared;
}

void ksmbd_set_inode_pending_delete(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci = fp->f_ci;

	down_write(&ci->m_lock);
	ci->m_flags |= S_DEL_PENDING | S_SMB_DELETE;
	up_write(&ci->m_lock);

	/* Store DOC-setter's parent lease key for dir lease break exemption */
	ksmbd_inode_store_doc_parent_key(fp);
}

void ksmbd_clear_inode_pending_delete(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci = fp->f_ci;

	down_write(&ci->m_lock);
	ci->m_flags &= ~S_DEL_PENDING;
	up_write(&ci->m_lock);
}

/**
 * ksmbd_inode_will_delete_on_close() - check if closing @fp will delete the file
 * @fp:		file pointer being closed
 *
 * Returns true if the inode has delete-on-close/pending-delete set and
 * this is the last open handle (m_count == 1 before decrement).
 */
bool ksmbd_inode_will_delete_on_close(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci = fp->f_ci;
	bool will_delete;

	down_read(&ci->m_lock);
	will_delete = (ci->m_flags & (S_DEL_PENDING | S_DEL_ON_CLS)) &&
		      atomic_read(&ci->m_count) == 1;
	up_read(&ci->m_lock);
	return will_delete;
}

void ksmbd_fd_set_delete_on_close(struct ksmbd_file *fp,
				  int file_info)
{
	struct ksmbd_inode *ci = fp->f_ci;

	fp->is_delete_on_close = true;
	down_write(&ci->m_lock);
	if (ksmbd_stream_fd(fp))
		ci->m_flags |= S_DEL_ON_CLS_STREAM;
	else
		ci->m_flags |= S_DEL_ON_CLS;
	/* Mark SMB-initiated delete for FILE_ACTION_REMOVED_BY_DELETE */
	ci->m_flags |= S_SMB_DELETE;
	up_write(&ci->m_lock);

	/* Store DOC-setter's parent lease key for dir lease break exemption */
	ksmbd_inode_store_doc_parent_key(fp);
}

/**
 * ksmbd_inode_set_posix() - mark inode as having a POSIX context handle
 * @ci:	ksmbd inode
 *
 * Must be called with ci->m_lock held for writing.
 */
void ksmbd_inode_set_posix(struct ksmbd_inode *ci)
{
	ci->m_flags |= S_POSIX_OPENED;
}

static void ksmbd_inode_hash(struct ksmbd_inode *ci)
{
	unsigned long bucket =
		inode_hash(d_inode(ci->m_de)->i_sb,
			   (unsigned long)ci->m_de);

	hlist_add_head(&ci->m_hash, &inode_hashtable[bucket].head);
}

static void ksmbd_inode_unhash(struct ksmbd_inode *ci)
{
	unsigned long bucket =
		inode_hash(d_inode(ci->m_de)->i_sb,
			   (unsigned long)ci->m_de);

	write_lock(&inode_hashtable[bucket].lock);
	hlist_del_init(&ci->m_hash);
	write_unlock(&inode_hashtable[bucket].lock);
}

static int ksmbd_inode_init(struct ksmbd_inode *ci, struct ksmbd_file *fp)
{
	atomic_set(&ci->m_count, 1);
	atomic_set(&ci->op_count, 0);
	atomic_set(&ci->sop_count, 0);
	ci->m_flags = 0;
	ci->m_fattr = 0;
	ci->m_cached_alloc = -1;
	INIT_LIST_HEAD(&ci->m_fp_list);
	INIT_LIST_HEAD(&ci->m_op_list);
	init_rwsem(&ci->m_lock);
	ci->m_de = dget(fp->filp->f_path.dentry);
	return 0;
}

static struct ksmbd_inode *ksmbd_inode_get(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci, *tmpci;
	struct dentry *de = fp->filp->f_path.dentry;
	unsigned long bucket =
		inode_hash(d_inode(de)->i_sb, (unsigned long)de);
	int rc;

	read_lock(&inode_hashtable[bucket].lock);
	ci = ksmbd_inode_lookup(fp);
	read_unlock(&inode_hashtable[bucket].lock);
	if (ci)
		return ci;

	ci = kmalloc(sizeof(struct ksmbd_inode), KSMBD_DEFAULT_GFP);
	if (!ci)
		return NULL;

	rc = ksmbd_inode_init(ci, fp);
	if (rc) {
		pr_err("inode initialized failed\n");
		kfree(ci);
		return NULL;
	}

	write_lock(&inode_hashtable[bucket].lock);
	tmpci = ksmbd_inode_lookup(fp);
	if (!tmpci) {
		ksmbd_inode_hash(ci);
	} else {
		dput(ci->m_de);
		kfree(ci);
		ci = tmpci;
	}
	write_unlock(&inode_hashtable[bucket].lock);
	return ci;
}

static void ksmbd_inode_free(struct ksmbd_inode *ci)
{
	ksmbd_inode_unhash(ci);
	dput(ci->m_de);
	kfree(ci);
}

void ksmbd_inode_put(struct ksmbd_inode *ci)
{
	if (atomic_dec_and_test(&ci->m_count))
		ksmbd_inode_free(ci);
}

int __init ksmbd_inode_hash_init(void)
{
	unsigned int loop;
	unsigned long numentries = 16384;
	unsigned long bucketsize = sizeof(struct ksmbd_inode_hash_bucket);
	unsigned long size;

	inode_hash_shift = ilog2(numentries);
	inode_hash_mask = (1 << inode_hash_shift) - 1;

	size = bucketsize << inode_hash_shift;

	/* init master fp hash table with per-bucket locks */
	inode_hashtable = vmalloc(size);
	if (!inode_hashtable)
		return -ENOMEM;

	for (loop = 0; loop < (1U << inode_hash_shift); loop++) {
		INIT_HLIST_HEAD(&inode_hashtable[loop].head);
		rwlock_init(&inode_hashtable[loop].lock);
	}
	return 0;
}

void ksmbd_release_inode_hash(void)
{
	vfree(inode_hashtable);
	inode_hashtable = NULL;
}

static void __ksmbd_inode_close(struct ksmbd_file *fp)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	struct dentry *dir, *dentry;
#endif
	struct ksmbd_inode *ci = fp->f_ci;
	int err;
	struct file *filp;

	filp = fp->filp;

	if (ksmbd_stream_fd(fp)) {
		bool remove_stream_xattr = false;

		down_write(&ci->m_lock);
		if (ci->m_flags & S_DEL_ON_CLS_STREAM) {
			ci->m_flags &= ~S_DEL_ON_CLS_STREAM;
			remove_stream_xattr = true;
		}
		up_write(&ci->m_lock);

		if (remove_stream_xattr) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
			err = ksmbd_vfs_remove_xattr(file_mnt_idmap(filp),
#else
			err = ksmbd_vfs_remove_xattr(file_mnt_user_ns(filp),
#endif
						     &filp->f_path,
						     fp->stream.name,
						     true);
			if (err)
				pr_err("remove xattr failed : %s\n",
				       fp->stream.name);
		}
	}

	/*
	 * Delete-on-close / delete-pending semantics per MS-SMB2 §3.3.5.9.6
	 * and Windows NTFS semantics:
	 *
	 * FILE_DELETE_ON_CLOSE (S_DEL_ON_CLS): when the handle that set this
	 * flag closes, the file is unlinked from the namespace immediately,
	 * even if other handles remain open -- matching Windows behaviour
	 * (similar to POSIX unlink).  The remaining handles retain access to
	 * the file data via their open file descriptor until they close, but
	 * the name is freed immediately so new creates on the same path
	 * succeed.
	 *
	 * If the immediate unlink fails (e.g., ENOTEMPTY for a non-empty
	 * directory), we fall back to deferred deletion at last-handle close.
	 *
	 * S_DEL_PENDING (set via FileDispositionInformation) is a file-level
	 * attribute that is NOT cleared here; it persists until the client
	 * explicitly clears it or the file is deleted on last close.
	 *
	 * ksmbd_inode_pending_delete() only checks S_DEL_PENDING, so new
	 * opens are not blocked by S_DEL_ON_CLS alone -- callers may open a
	 * file that has an outstanding delete-on-close handle.
	 */
	if (!atomic_dec_and_test(&ci->m_count)) {
		/*
		 * Other handles still open.  If the closing handle had
		 * FILE_DELETE_ON_CLOSE set, defer the actual unlink to the
		 * last-handle close and mark DELETE_PENDING now.
		 */
		if (fp->is_delete_on_close && !ksmbd_stream_fd(fp)) {
			bool notify_pending = false;

			/*
			 * Other handles are still open.  Defer the actual unlink
			 * to the last-handle close; mark the file DELETE_PENDING so
			 * new name-based opens return STATUS_DELETE_PENDING per
			 * MS-SMB2 §3.3.5.9 / Windows NTFS semantics.
			 */
			down_write(&ci->m_lock);
			if (ci->m_flags & S_DEL_ON_CLS) {
				ci->m_flags &= ~S_DEL_ON_CLS;
				ci->m_flags |= S_DEL_PENDING | S_SMB_DELETE;
				notify_pending = true;
			}
			up_write(&ci->m_lock);

			/*
			 * MS-SMB2 §3.3.5.9.6: immediately complete any pending
			 * CHANGE_NOTIFY watches with STATUS_DELETE_PENDING when
			 * delete-on-close is transitioned to delete-pending.
			 * This covers CREATE+DELETE_ON_CLOSE+CLOSE paths where
			 * no SET_INFO is used (e.g. smb2_util_rmdir).
			 */
			if (notify_pending)
				ksmbd_notify_complete_delete_pending(ci);
		}
	} else {
		bool do_unlink = false;

		down_write(&ci->m_lock);
		if (ci->m_flags & (S_DEL_ON_CLS | S_DEL_PENDING)) {
			ci->m_flags &= ~(S_DEL_ON_CLS | S_DEL_PENDING);
			do_unlink = true;
		}
		up_write(&ci->m_lock);

		if (do_unlink) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
			dentry = filp->f_path.dentry;
			dir = dentry->d_parent;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
			ksmbd_vfs_unlink(filp);
#else
			ksmbd_vfs_unlink(file_mnt_idmap(filp), dir, dentry);
#endif
#else
			ksmbd_vfs_unlink(file_mnt_user_ns(filp), dir, dentry);
#endif
		}

		ksmbd_inode_free(ci);
	}
}

static void __ksmbd_remove_durable_fd(struct ksmbd_file *fp)
{
	if (!has_file_id(fp->persistent_id))
		return;

	idr_remove(global_ft.idr, fp->persistent_id);
}

static void ksmbd_remove_durable_fd(struct ksmbd_file *fp)
{
	write_lock(&global_ft.lock);
	__ksmbd_remove_durable_fd(fp);
	write_unlock(&global_ft.lock);
	if (waitqueue_active(&dh_wq))
		wake_up(&dh_wq);
}

static void __ksmbd_remove_fd(struct ksmbd_file_table *ft, struct ksmbd_file *fp)
{
	if (!has_file_id(fp->volatile_id))
		return;

	down_write(&fp->f_ci->m_lock);
	list_del_init(&fp->node);
	up_write(&fp->f_ci->m_lock);

	write_lock(&ft->lock);
	idr_remove(ft->idr, fp->volatile_id);
	write_unlock(&ft->lock);
}

static void __ksmbd_close_fd(struct ksmbd_file_table *ft, struct ksmbd_file *fp)
{
	struct file *filp;
	struct ksmbd_lock *smb_lock, *tmp_lock;

	if (fp->is_persistent && !fp->persistent_restore_pending)
		ksmbd_ph_delete(fp);

	/* C.5: cancel the durable expiry timer before freeing the fp */
	timer_delete_sync(&fp->durable_expire_timer);

	fd_limit_close();
	ksmbd_remove_durable_fd(fp);
	if (ft)
		__ksmbd_remove_fd(ft, fp);

	close_id_del_oplock(fp);
	filp = fp->filp;

	__ksmbd_inode_close(fp);

	/*
	 * Remove POSIX locks synchronously before fput().
	 * fput() defers __fput() via task_work in kthreads, so
	 * POSIX locks may remain visible to concurrent lock
	 * requests if we rely on deferred cleanup.  This fixes
	 * the "NT byte range lock bug" where closing a handle
	 * didn't immediately release its POSIX locks.
	 */
	if (!IS_ERR_OR_NULL(filp))
		locks_remove_posix(filp, filp);

	if (!IS_ERR_OR_NULL(filp))
		fput(filp);

	/* because the reference count of fp is 0, it is guaranteed that
	 * there are not accesses to fp->lock_list.
	 */
	list_for_each_entry_safe(smb_lock, tmp_lock, &fp->lock_list, flist) {
		if (fp->conn) {
			spin_lock(&fp->conn->llist_lock);
			list_del(&smb_lock->clist);
			spin_unlock(&fp->conn->llist_lock);
		} else {
			/* Disconnected durable: clist already detached */
			list_del_init(&smb_lock->clist);
		}

		list_del(&smb_lock->flist);
		locks_free_lock(smb_lock->fl);
		kfree(smb_lock);
	}
#ifdef CONFIG_SMB_INSECURE_SERVER
	kfree(fp->filename);
#endif
	kfree(fp->search_pattern);
	if (ksmbd_stream_fd(fp))
		kfree(fp->stream.name);
	kmem_cache_free(filp_cache, fp);
}

static struct ksmbd_file *ksmbd_fp_get(struct ksmbd_file *fp)
{
	if (fp->f_state != FP_INITED)
		return NULL;

	if (!refcount_inc_not_zero(&fp->refcount))
		return NULL;
	return fp;
}

static struct ksmbd_file *__ksmbd_lookup_fd(struct ksmbd_file_table *ft,
					    u64 id)
{
	struct ksmbd_file *fp;

	if (!has_file_id(id))
		return NULL;

	read_lock(&ft->lock);
	fp = idr_find(ft->idr, id);
	if (fp)
		fp = ksmbd_fp_get(fp);
	read_unlock(&ft->lock);
	return fp;
}

static void __put_fd_final(struct ksmbd_work *work, struct ksmbd_file *fp)
{
	__ksmbd_close_fd(&work->sess->file_table, fp);
}

static void set_close_state_blocked_works(struct ksmbd_file *fp)
{
	struct ksmbd_work *cancel_work;

	spin_lock(&fp->f_lock);
	list_for_each_entry(cancel_work, &fp->blocked_works,
				 fp_entry) {
		struct smb2_hdr *hdr;

		/*
		 * Skip CHANGE_NOTIFY entries — they are handled
		 * by ksmbd_notify_cleanup_file() which safely
		 * drops the lock before doing I/O and freeing.
		 */
		hdr = smb2_get_msg(cancel_work->request_buf);
		if (hdr->Command == SMB2_CHANGE_NOTIFY ||
		    cancel_work->cancel_fn == ksmbd_notify_cancel)
			continue;

		cancel_work->state = KSMBD_WORK_CLOSED;
		if (cancel_work->cancel_fn)
			cancel_work->cancel_fn(cancel_work->cancel_argv);
	}
	spin_unlock(&fp->f_lock);
}

static void ksmbd_cleanup_file_closing_state(struct ksmbd_file *fp)
{
	set_close_state_blocked_works(fp);
	ksmbd_notify_cleanup_file(fp);
}

int ksmbd_close_fd(struct ksmbd_work *work, u64 id)
{
	struct ksmbd_file	*fp;
	struct ksmbd_file_table	*ft;
	bool last = false;

	if (!has_file_id(id))
		return 0;

	ft = &work->sess->file_table;
	write_lock(&ft->lock);
	fp = idr_find(ft->idr, id);
	if (fp) {
		set_close_state_blocked_works(fp);

		if (fp->f_state != FP_INITED)
			fp = NULL;
		else {
			fp->f_state = FP_CLOSED;
			idr_remove(ft->idr, id);
			last = refcount_dec_and_test(&fp->refcount);
		}
	}
	write_unlock(&ft->lock);

	if (!fp)
		return -EINVAL;

	atomic_dec(&work->conn->stats.open_files_count);
	if (!last)
		return 0;

	/*
	 * Notify cleanup sends STATUS_NOTIFY_CLEANUP responses over
	 * TCP (sleepable) and takes mutexes, so it MUST be called
	 * outside write_lock(&ft->lock).  fp is safe here because the
	 * table's open-handle reference was the last remaining ref and
	 * the IDR entry is already gone, preventing new lookups.
	 */
	ksmbd_notify_cleanup_file(fp);
	__put_fd_final(work, fp);
	return 0;
}

/**
 * ksmbd_force_close_fd() - Close a file handle using an explicit file table.
 *
 * Used by APP_INSTANCE_ID logic to force-close a previous open that belongs
 * to a different session's file_table than the current work's session.
 * Uses fp->conn for open-file-count accounting instead of work->conn.
 */
void ksmbd_force_close_fd(struct ksmbd_file_table *ft, u64 id)
{
	struct ksmbd_file *fp;
	struct ksmbd_conn *conn;
	bool last = false;

	if (!has_file_id(id) || !ft)
		return;

	write_lock(&ft->lock);
	if (!ft->idr) {
		write_unlock(&ft->lock);
		return;
	}
	fp = idr_find(ft->idr, id);
	if (fp) {
		set_close_state_blocked_works(fp);
		if (fp->f_state != FP_INITED)
			fp = NULL;
		else {
			fp->f_state = FP_CLOSED;
			idr_remove(ft->idr, id);
			last = refcount_dec_and_test(&fp->refcount);
		}
	}
	write_unlock(&ft->lock);

	if (!fp)
		return;

	conn = fp->conn;
	if (conn)
		atomic_dec(&conn->stats.open_files_count);
	if (!last)
		return;

	ksmbd_notify_cleanup_file(fp);
	__ksmbd_close_fd(ft, fp);
}

void ksmbd_fd_put(struct ksmbd_work *work, struct ksmbd_file *fp)
{
	if (!fp)
		return;

	if (!refcount_dec_and_test(&fp->refcount))
		return;
	__put_fd_final(work, fp);
}

static bool __sanity_check(struct ksmbd_tree_connect *tcon, struct ksmbd_file *fp)
{
	if (!fp)
		return false;
	if (fp->tcon != tcon)
		return false;
	return true;
}

struct ksmbd_file *ksmbd_lookup_foreign_fd(struct ksmbd_work *work, u64 id)
{
	return __ksmbd_lookup_fd(&work->sess->file_table, id);
}

struct ksmbd_file *ksmbd_lookup_fd_fast(struct ksmbd_work *work, u64 id)
{
	struct ksmbd_file *fp = __ksmbd_lookup_fd(&work->sess->file_table, id);

	if (__sanity_check(work->tcon, fp))
		return fp;

	ksmbd_fd_put(work, fp);
	return NULL;
}

struct ksmbd_file *ksmbd_lookup_fd_slow(struct ksmbd_work *work, u64 id,
					u64 pid)
{
	struct ksmbd_file *fp;

	if (!has_file_id(id)) {
		id = work->compound_fid;
		pid = work->compound_pfid;
	}

	fp = __ksmbd_lookup_fd(&work->sess->file_table, id);
	if (!__sanity_check(work->tcon, fp)) {
		ksmbd_fd_put(work, fp);
		return NULL;
	}
	if (fp->persistent_id != pid) {
		ksmbd_fd_put(work, fp);
		return NULL;
	}
	return fp;
}

struct ksmbd_file *ksmbd_lookup_global_fd(unsigned long long id)
{
	return __ksmbd_lookup_fd(&global_ft, id);
}

struct ksmbd_file *ksmbd_lookup_durable_fd(unsigned long long id)
{
	struct ksmbd_file *fp;
	struct ksmbd_conn *fconn;

	fp = __ksmbd_lookup_fd(&global_ft, id);
	fconn = fp ? READ_ONCE(fp->conn) : NULL;
	if (fp && (fp->is_scavenger_claimed ||
		   (fconn && !ksmbd_conn_releasing(fconn) &&
		    !ksmbd_conn_exiting(fconn)) ||
		   (fp->durable_scavenger_timeout &&
		    time_after(jiffies,
			       fp->durable_scavenger_timeout)))) {
		ksmbd_put_durable_fd(fp);
		fp = NULL;
	}

	return fp;
}

void ksmbd_put_durable_fd(struct ksmbd_file *fp)
{
	if (!refcount_dec_and_test(&fp->refcount))
		return;

	ksmbd_cleanup_file_closing_state(fp);
	__ksmbd_close_fd(NULL, fp);
}

/**
 * ksmbd_purge_disconnected_fp() - close disconnected durable handles
 *	for a given inode.
 * @ci:		ksmbd inode whose m_fp_list to scan
 *
 * Per MS-SMB2 §3.3.5.9.6: when a new open arrives and there are
 * disconnected durable handles on the same file, the server must
 * close (purge) them to allow the new open to proceed.
 *
 * Called from smb2_open() before the share mode check.
 */
void ksmbd_purge_disconnected_fp(struct ksmbd_inode *ci)
{
#define PURGE_BATCH 8
	struct ksmbd_file *fp, *purge_list[PURGE_BATCH];
	int i, cnt;

restart:
	cnt = 0;
	down_read(&ci->m_lock);
	list_for_each_entry(fp, &ci->m_fp_list, node) {
		struct ksmbd_conn *fconn;

		if (!fp->is_durable)
			continue;
		if (fp->is_scavenger_claimed)
			continue;

		/*
		 * A durable FP is "disconnected" when its connection is
		 * NULL (fully torn down) or when the connection is in a
		 * dying state (RELEASING/EXITING).  The latter catches
		 * the race where the TCP connection has dropped but the
		 * session teardown hasn't NULLed fp->conn yet.
		 */
		fconn = READ_ONCE(fp->conn);
		if (fconn && !ksmbd_conn_releasing(fconn) &&
		    !ksmbd_conn_exiting(fconn))
			continue;

		if (!refcount_inc_not_zero(&fp->refcount))
			continue;
		purge_list[cnt++] = fp;
		if (cnt >= PURGE_BATCH)
			break;
	}
	up_read(&ci->m_lock);

	for (i = 0; i < cnt; i++) {
		struct ksmbd_conn *fconn;

		fp = purge_list[i];

		/*
		 * Claim under global IDR lock.  Re-verify nobody
		 * reconnected or the scavenger didn't grab it first.
		 */
		write_lock(&global_ft.lock);
		fconn = READ_ONCE(fp->conn);
		if (fp->is_scavenger_claimed ||
		    (fconn && !ksmbd_conn_releasing(fconn) &&
		     !ksmbd_conn_exiting(fconn))) {
			write_unlock(&global_ft.lock);
			refcount_dec(&fp->refcount);
			continue;
		}
		fp->is_scavenger_claimed = true;
		__ksmbd_remove_durable_fd(fp);
		write_unlock(&global_ft.lock);

		/*
		 * If session teardown hasn't run yet (fp->conn still
		 * set), do the disconnect cleanup here: detach locks
		 * and opinfo conn references.  The order matters:
		 * detach locks FIRST (uses fconn->llist_lock), then
		 * drop opinfo conn refs (which may free fconn).
		 */
		fconn = xchg(&fp->conn, NULL);
		if (fconn) {
			/* Detach locks from the dying connection */
			if (!list_empty(&fp->lock_list)) {
				struct ksmbd_lock *lk;

				spin_lock(&fconn->llist_lock);
				list_for_each_entry(lk, &fp->lock_list,
						    flist)
					list_del_init(&lk->clist);
				spin_unlock(&fconn->llist_lock);
			}

			/* Drop only this durable fp's opinfo connection ref. */
			ksmbd_durable_unbind_opinfo_conn(fp, fconn);
			fp->tcon = NULL;
			fp->volatile_id = KSMBD_NO_FID;
		}

		/* Remove from inode's FP list */
		down_write(&ci->m_lock);
		list_del_init(&fp->node);
		up_write(&ci->m_lock);

		ksmbd_debug(VFS, "purging disconnected durable fd %llu\n",
			    fp->persistent_id);

		/*
		 * The FP is now unreachable (removed from global IDR
		 * and m_fp_list).  Drop our guard ref (acquired by
		 * refcount_inc_not_zero above), then drop the orphaned
		 * base ref (session_fd_check never decrements refcount
		 * for durable FPs) to reach zero and trigger close.
		 *
		 * VFS-07: use refcount_dec_and_test for both drops so
		 * that any unexpected undercount is caught (WARN_ONCE)
		 * rather than silently walking through a zero refcount.
		 */
		if (!refcount_dec_and_test(&fp->refcount)) {
			/* Guard ref dropped; base ref still held — drop it */
			if (refcount_dec_and_test(&fp->refcount)) {
				ksmbd_cleanup_file_closing_state(fp);
				__ksmbd_close_fd(NULL, fp);
			} else {
				fp->is_scavenger_claimed = false;
			}
		} else {
			/* Guard ref drop reached zero — close immediately */
			ksmbd_cleanup_file_closing_state(fp);
			__ksmbd_close_fd(NULL, fp);
		}
	}

	if (cnt >= PURGE_BATCH)
		goto restart;
#undef PURGE_BATCH
}

struct ksmbd_file *ksmbd_lookup_fd_cguid(char *cguid)
{
	struct ksmbd_file	*fp = NULL;
	unsigned int		id;

	read_lock(&global_ft.lock);
	idr_for_each_entry(global_ft.idr, fp, id) {
		if (!memcmp(fp->create_guid,
			    cguid,
			    SMB2_CREATE_GUID_SIZE)) {
			fp = ksmbd_fp_get(fp);
			break;
		}
	}
	read_unlock(&global_ft.lock);

	return fp;
}

#ifdef CONFIG_SMB_INSECURE_SERVER
struct ksmbd_file *ksmbd_lookup_fd_filename(struct ksmbd_work *work, char *filename)
{
	struct ksmbd_file	*fp = NULL;
	unsigned int		id;
	char			*pathname;

	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!pathname)
		return NULL;

	read_lock(&work->sess->file_table.lock);
	idr_for_each_entry(work->sess->file_table.idr, fp, id) {
		char *path = d_path(&fp->filp->f_path, pathname, PATH_MAX);

		if (IS_ERR(path))
			break;

		if (!strcmp(path, filename)) {
			fp = ksmbd_fp_get(fp);
			break;
		}
	}
	read_unlock(&work->sess->file_table.lock);

	kfree(pathname);
	return fp;
}
#endif

struct ksmbd_file *ksmbd_lookup_fd_inode(struct dentry *dentry)
{
	struct ksmbd_file	*lfp;
	struct ksmbd_inode	*ci;
	struct inode		*inode = d_inode(dentry);
	unsigned long		bucket =
		inode_hash(inode->i_sb, (unsigned long)dentry);

	read_lock(&inode_hashtable[bucket].lock);
	ci = __ksmbd_inode_lookup(dentry);
	read_unlock(&inode_hashtable[bucket].lock);
	if (!ci)
		return NULL;

	down_read(&ci->m_lock);
	list_for_each_entry(lfp, &ci->m_fp_list, node) {
		if (inode == file_inode(lfp->filp)) {
			lfp = ksmbd_fp_get(lfp);
			up_read(&ci->m_lock);
			ksmbd_inode_put(ci);
			return lfp;
		}
	}
	up_read(&ci->m_lock);
	ksmbd_inode_put(ci);
	return NULL;
}

/**
 * ksmbd_lookup_fd_inode_sess() - Find an open file by inode number
 *                                in the session's file table
 * @work:  smb work containing the session reference
 * @ino:   inode number to search for
 *
 * Iterates the session's file table under the read lock, looking for
 * an open file handle whose backing inode number matches @ino.
 * Returns a reference-counted ksmbd_file on success, NULL if not found.
 *
 * The caller must call ksmbd_fd_put() when done with the returned file.
 */
struct ksmbd_file *ksmbd_lookup_fd_inode_sess(struct ksmbd_work *work,
					      u64 ino)
{
	struct ksmbd_file *fp = NULL;
	unsigned int entry_id;

	if (!work->sess)
		return NULL;

	read_lock(&work->sess->file_table.lock);
	idr_for_each_entry(work->sess->file_table.idr, fp, entry_id) {
		struct inode *inode;

		if (!fp->filp)
			continue;

		if (fp->f_state != FP_INITED)
			continue;

		inode = file_inode(fp->filp);
		if (inode->i_ino == ino) {
			fp = ksmbd_fp_get(fp);
			break;
		}
	}
	read_unlock(&work->sess->file_table.lock);

	return fp;
}

#define OPEN_ID_TYPE_VOLATILE_ID	(0)
#define OPEN_ID_TYPE_PERSISTENT_ID	(1)

static void __open_id_set(struct ksmbd_file *fp, u64 id, int type)
{
	if (type == OPEN_ID_TYPE_VOLATILE_ID)
		fp->volatile_id = id;
	if (type == OPEN_ID_TYPE_PERSISTENT_ID)
		fp->persistent_id = id;
}

static int __open_id(struct ksmbd_file_table *ft, struct ksmbd_file *fp,
		     int type)
{
	u64			id = 0;
	int			ret;

	if (type == OPEN_ID_TYPE_VOLATILE_ID && fd_limit_depleted()) {
		__open_id_set(fp, KSMBD_NO_FID, type);
		return -EMFILE;
	}

	idr_preload(KSMBD_DEFAULT_GFP);
	write_lock(&ft->lock);
#ifdef CONFIG_SMB_INSECURE_SERVER
	ret = idr_alloc_cyclic(ft->idr, fp, 0,
			       IS_SMB2(fp->conn) ? INT_MAX - 1 : 0xFFFF,
			       GFP_NOWAIT);
#else
	ret = idr_alloc_cyclic(ft->idr, fp, 0, INT_MAX - 1, GFP_NOWAIT);
#endif
	if (ret >= 0) {
		id = ret;
		ret = 0;
	} else {
		id = KSMBD_NO_FID;
		fd_limit_close();
	}

	__open_id_set(fp, id, type);
	write_unlock(&ft->lock);
	idr_preload_end();
	return ret;
}

unsigned int ksmbd_open_durable_fd(struct ksmbd_file *fp)
{
	__open_id(&global_ft, fp, OPEN_ID_TYPE_PERSISTENT_ID);
	return fp->persistent_id;
}

int ksmbd_open_durable_fd_id(struct ksmbd_file *fp, u64 id)
{
	int ret;

	if (id == KSMBD_NO_FID || id >= INT_MAX) {
		fp->persistent_id = KSMBD_NO_FID;
		return -EINVAL;
	}

	idr_preload(KSMBD_DEFAULT_GFP);
	write_lock(&global_ft.lock);
	ret = idr_alloc(global_ft.idr, fp, id, id + 1, GFP_NOWAIT);
	if (ret >= 0) {
		fp->persistent_id = id;
		ret = 0;
	} else {
		fp->persistent_id = KSMBD_NO_FID;
	}
	write_unlock(&global_ft.lock);
	idr_preload_end();

	if (!ret && waitqueue_active(&dh_wq))
		wake_up(&dh_wq);

	return ret;
}

/* Forward declaration for C.5 durable expiry timer callback */
static void ksmbd_durable_expire_cb(struct timer_list *t);

struct ksmbd_file *ksmbd_open_fd(struct ksmbd_work *work, struct file *filp)
{
	struct ksmbd_file *fp;
	int ret;

	fp = kmem_cache_zalloc(filp_cache, KSMBD_DEFAULT_GFP);
	if (!fp) {
		pr_err("Failed to allocate memory\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&fp->blocked_works);
	INIT_LIST_HEAD(&fp->node);
	INIT_LIST_HEAD(&fp->lock_list);
	spin_lock_init(&fp->f_lock);
	spin_lock_init(&fp->lock_seq_lock);
	memset(fp->lock_seq, 0xFF, sizeof(fp->lock_seq));
	refcount_set(&fp->refcount, 1);
	/* C.5: initialize durable handle expiry timer */
	timer_setup(&fp->durable_expire_timer, ksmbd_durable_expire_cb, 0);

	fp->filp		= filp;
	fp->conn		= work->conn;
	fp->tcon		= work->tcon;
	fp->ft			= &work->sess->file_table;
	fp->volatile_id		= KSMBD_NO_FID;
	fp->persistent_id	= KSMBD_NO_FID;
	fp->f_state		= FP_NEW;
	fp->f_ci		= ksmbd_inode_get(fp);

	if (!fp->f_ci) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = __open_id(&work->sess->file_table, fp, OPEN_ID_TYPE_VOLATILE_ID);
	if (ret) {
		ksmbd_inode_put(fp->f_ci);
		goto err_out;
	}

	atomic_inc(&work->conn->stats.open_files_count);
	return fp;

err_out:
	kmem_cache_free(filp_cache, fp);
	return ERR_PTR(ret);
}

void ksmbd_update_fstate(struct ksmbd_file_table *ft, struct ksmbd_file *fp,
			 unsigned int state)
{
	if (!fp)
		return;

	write_lock(&ft->lock);
	fp->f_state = state;
	write_unlock(&ft->lock);
}

static int
__close_file_table_ids(struct ksmbd_file_table *ft,
		       struct ksmbd_tree_connect *tcon,
		       bool (*skip)(struct ksmbd_tree_connect *tcon,
				    struct ksmbd_file *fp))
{
	struct ksmbd_file *fp;
	unsigned int id = 0;
	int num = 0;

	while (1) {
		unsigned int cur_id;
		bool close_now = false;

		write_lock(&ft->lock);
		fp = idr_get_next(ft->idr, &id);
		if (!fp) {
			write_unlock(&ft->lock);
			break;
		}

		cur_id = id;
		id++;

		/*
		 * Pin the fp before releasing the spinlock so it survives
		 * while we call skip() outside the lock.
		 *
		 * skip() (= session_fd_check) acquires ci->m_lock via
		 * down_write(), which is a sleepable rw_semaphore.  Calling
		 * it with ft->lock (spinlock) held creates a lock-class
		 * inversion against __ksmbd_remove_fd (ci->m_lock first,
		 * ft->lock second) and can deadlock on a contested ci->m_lock.
		 *
		 * Additionally, ksmbd_purge_disconnected_fp() can free a
		 * durable fp that session_fd_check() preserved, leaving the
		 * session IDR with a dangling pointer (UAF -> list corruption).
		 * We fix both problems by pinning the fp here, releasing the
		 * lock, calling skip() safely, then re-acquiring to do IDR
		 * removals before dropping the pin.
		 */
		if (!refcount_inc_not_zero(&fp->refcount)) {
			/*
			 * Refcount already zero: another thread is already
			 * freeing this fp; the IDR entry will be gone soon.
			 */
			write_unlock(&ft->lock);
			continue;
		}
		write_unlock(&ft->lock);

		/* skip() may call down_write(&ci->m_lock) -- safe here */
		if (skip(tcon, fp)) {
			/*
			 * Only remove the IDR entry when session_fd_check()
			 * preserved the fp as a disconnected durable handle
			 * (it sets volatile_id = KSMBD_NO_FID to mark this).
			 *
			 * For tree_conn_fd_check() returning true, the fp
			 * belongs to a DIFFERENT tree and must be left intact:
			 * removing it here would make the handle invisible to
			 * subsequent lookups (NT_STATUS_FILE_CLOSED on a still-
			 * open handle).
			 *
			 * When volatile_id was set to KSMBD_NO_FID by
			 * session_fd_check(), remove the IDR entry now to
			 * close the UAF window (ksmbd_purge_disconnected_fp()
			 * or the durable scavenger might free the fp while the
			 * IDR still maps cur_id -> freed memory).
			 *
			 * Use cur_id (the actual IDR key), NOT fp->volatile_id
			 * which session_fd_check() already set to KSMBD_NO_FID.
			 */
			if (fp->volatile_id == KSMBD_NO_FID) {
				write_lock(&ft->lock);
				if (idr_find(ft->idr, cur_id) == fp)
					idr_remove(ft->idr, cur_id);
				write_unlock(&ft->lock);
			}
			refcount_dec(&fp->refcount);  /* drop pin */
			continue;
		}

		/*
		 * Not reconnectable: try to win the close race.
		 * Re-acquire the lock and verify the fp is still at cur_id
		 * (a concurrent ksmbd_close_fd may have already removed it).
		 * Then drop the pin and atomically attempt dec-and-test on the
		 * base ref.  Both refcount_dec() calls are inside ft->lock,
		 * preventing any new caller from pinning the fp between them.
		 */
		write_lock(&ft->lock);
		if (idr_find(ft->idr, cur_id) != fp) {
			write_unlock(&ft->lock);
			refcount_dec(&fp->refcount);
			continue;
		}

		if (fp->f_state != FP_INITED) {
			idr_remove(ft->idr, cur_id);
			write_unlock(&ft->lock);
			refcount_dec(&fp->refcount);
			continue;
		}

		set_close_state_blocked_works(fp);
		fp->f_state = FP_CLOSED;
		idr_remove(ft->idr, cur_id);
		write_unlock(&ft->lock);

		num++;

		/*
		 * Drop the iterator pin first, then the file-table's
		 * open-handle reference.  Once the IDR entry is gone the
		 * handle is unreachable, so any remaining refs are internal
		 * users that will run final close through ksmbd_fd_put().
		 */
		if (!refcount_dec_and_test(&fp->refcount))
			close_now = refcount_dec_and_test(&fp->refcount);
		else
			close_now = true;

		if (!close_now)
			continue;

		/*
		 * Notify cleanup sends TCP responses (sleepable),
		 * so must be called outside write_lock(&ft->lock).
		 */
		ksmbd_notify_cleanup_file(fp);
		__ksmbd_close_fd(ft, fp);
	}

	return num;
}

static inline bool is_reconnectable(struct ksmbd_file *fp)
{
	struct oplock_info *opinfo = opinfo_get(fp);
	bool reconn = false;

	if (!opinfo)
		return false;

	if (opinfo->op_state != OPLOCK_STATE_NONE) {
		opinfo_put(opinfo);
		return false;
	}

	/*
	 * MS-SMB2 §3.3.5.9.7: a durable handle with FILE_DELETE_ON_CLOSE
	 * set MUST NOT be preserved across disconnect — the file should be
	 * deleted as if the handle were closed normally.
	 */
	if (fp->is_delete_on_close) {
		opinfo_put(opinfo);
		return false;
	}

	if (fp->is_resilient || fp->is_persistent)
		reconn = true;
	else if (fp->is_durable && opinfo->is_lease &&
		 opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE)
		reconn = true;

	else if (fp->is_durable && opinfo->level == SMB2_OPLOCK_LEVEL_BATCH)
		reconn = true;

	opinfo_put(opinfo);
	return reconn;
}

static bool tree_conn_fd_check(struct ksmbd_tree_connect *tcon,
			       struct ksmbd_file *fp)
{
	return fp->tcon != tcon;
}

static bool ksmbd_durable_scavenger_alive(void)
{
	if (!READ_ONCE(durable_scavenger_running))
		return false;

	if (kthread_should_stop())
		return false;

	read_lock(&global_ft.lock);
	if (!global_ft.idr || idr_is_empty(global_ft.idr)) {
		read_unlock(&global_ft.lock);
		return false;
	}
	read_unlock(&global_ft.lock);

	return true;
}

static bool ksmbd_durable_scavenger_stop_requested(void)
{
	return !READ_ONCE(durable_scavenger_running) || kthread_should_stop();
}

static void ksmbd_wake_durable_scavenger(void)
{
	atomic_inc(&durable_scavenger_wake_seq);
	wake_up(&dh_wq);
}

static int ksmbd_durable_scavenger(void *dummy)
{
	struct ksmbd_file *fp = NULL;
	unsigned int id;
	unsigned int min_timeout = 1;
	bool found_fp_timeout;
	unsigned long remaining_jiffies;
	int wake_seq;

	__module_get(THIS_MODULE);

	set_freezable();
	while (ksmbd_durable_scavenger_alive()) {
		if (try_to_freeze())
			continue;

		found_fp_timeout = false;
rescan:
		if (!ksmbd_durable_scavenger_alive())
			break;

		wake_seq = atomic_read(&durable_scavenger_wake_seq);
		remaining_jiffies = wait_event_timeout(dh_wq,
				   !ksmbd_durable_scavenger_alive() ||
				   atomic_read(&durable_scavenger_wake_seq) != wake_seq,
				   __msecs_to_jiffies(min_timeout));
		if (!ksmbd_durable_scavenger_alive())
			break;
		if (remaining_jiffies)
			min_timeout = jiffies_to_msecs(remaining_jiffies);
		else
			min_timeout = DURABLE_HANDLE_MAX_TIMEOUT;

		write_lock(&global_ft.lock);
		idr_for_each_entry(global_ft.idr, fp, id) {
			if (ksmbd_durable_scavenger_stop_requested())
				break;

			if (!fp->durable_timeout &&
			    !(fp->is_resilient && fp->resilient_timeout))
				continue;

			if (fp->conn)
				continue;

			found_fp_timeout = true;
			if (time_after_eq(jiffies,
				      fp->durable_scavenger_timeout)) {
				/*
				 * Take a reference before claiming. If
				 * someone else already holds a reference
				 * (e.g. a reconnecting client), skip.
				 */
				if (!refcount_inc_not_zero(&fp->refcount))
					continue;

				if (refcount_read(&fp->refcount) != 2) {
					/*
					 * Another thread acquired a ref
					 * between our check and inc.
					 * Drop our ref and skip.
					 */
						refcount_dec(&fp->refcount);
						continue;
					}

					if (ksmbd_durable_scavenger_stop_requested()) {
						refcount_dec(&fp->refcount);
						break;
					}

					fp->is_scavenger_claimed = true;
					__ksmbd_remove_durable_fd(fp);
					write_unlock(&global_ft.lock);

				/*
				 * fp->node is still linked in the
				 * inode's m_fp_list.  Properly remove
				 * it under m_lock before disposing
				 * (m_lock is a semaphore, so must be
				 * taken outside the spinlock).
				 */
				if (fp->f_ci) {
					down_write(&fp->f_ci->m_lock);
					list_del_init(&fp->node);
					up_write(&fp->f_ci->m_lock);
				}

				if (!refcount_dec_and_test(&fp->refcount)) {
					fp->is_scavenger_claimed = false;
				} else {
					ksmbd_cleanup_file_closing_state(fp);
					__ksmbd_close_fd(NULL, fp);
				}

				/*
				 * Restart the IDR scan — the lock was
				 * dropped so entries may have changed.
				 */
				goto rescan;
			} else {
				unsigned long remaining;

				remaining =
					fp->durable_scavenger_timeout -
						jiffies;

				if (min_timeout > remaining)
					min_timeout = remaining;
			}
		}
		write_unlock(&global_ft.lock);

		if (found_fp_timeout == false)
			break;
	}

	/* M-06: pair with READ_ONCE in ksmbd_durable_scavenger_alive() */
	WRITE_ONCE(durable_scavenger_running, false);
	mutex_lock(&durable_scavenger_lock);
	if (server_conf.dh_task == current)
		server_conf.dh_task = NULL;
	mutex_unlock(&durable_scavenger_lock);

	module_put(THIS_MODULE);

	return 0;
}

void ksmbd_launch_ksmbd_durable_scavenger(void)
{
	if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE))
		return;

	mutex_lock(&durable_scavenger_lock);
	if (durable_scavenger_running == true) {
		mutex_unlock(&durable_scavenger_lock);
		return;
	}

	WRITE_ONCE(durable_scavenger_running, true);

	server_conf.dh_task = kthread_run(ksmbd_durable_scavenger,
				     (void *)NULL, "ksmbd-durable-scavenger");
	if (IS_ERR(server_conf.dh_task))
		pr_err("cannot start conn thread, err : %ld\n",
		       PTR_ERR(server_conf.dh_task));
	mutex_unlock(&durable_scavenger_lock);
}

void ksmbd_request_durable_scavenger_stop(void)
{
	if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE))
		return;

	mutex_lock(&durable_scavenger_lock);
	if (!durable_scavenger_running) {
		mutex_unlock(&durable_scavenger_lock);
		return;
	}

	WRITE_ONCE(durable_scavenger_running, false);
	ksmbd_wake_durable_scavenger();
	mutex_unlock(&durable_scavenger_lock);
}

void ksmbd_stop_durable_scavenger(void)
{
	struct task_struct *task;

	if (!(server_conf.flags & KSMBD_GLOBAL_FLAG_DURABLE_HANDLE))
		return;

	mutex_lock(&durable_scavenger_lock);
	task = server_conf.dh_task;
	server_conf.dh_task = NULL;
	if (durable_scavenger_running)
		WRITE_ONCE(durable_scavenger_running, false);
	ksmbd_wake_durable_scavenger();
	mutex_unlock(&durable_scavenger_lock);

	if (task)
		kthread_stop(task);
}

/*
 * C.5: Timer callback for durable handle expiry.
 * Fired when a disconnected durable handle's reconnect window expires.
 * Simply wakes the durable scavenger thread, which will find the handle
 * with an expired durable_scavenger_timeout and close it.
 * This avoids complex locking in timer context — the scavenger already
 * handles all the heavy lifting safely.
 */
static void ksmbd_durable_expire_cb(struct timer_list *t)
{
	ksmbd_wake_durable_scavenger();
}

void ksmbd_durable_unbind_opinfo_conn(struct ksmbd_file *fp,
				      struct ksmbd_conn *conn)
{
	struct oplock_info *opinfo;

	if (!fp || !fp->f_ci || !conn)
		return;

	opinfo = opinfo_get(fp);
	if (!opinfo)
		return;

	down_write(&fp->f_ci->m_lock);
	if (opinfo->conn == conn) {
		/*
		 * Only the opinfo owned by this fp carries the durable
		 * handle's extra connection reference.  Touching other
		 * inode opinfos corrupts unrelated lease state.
		 */
		ksmbd_conn_free(opinfo->conn);
		opinfo->conn = NULL;
	}
	up_write(&fp->f_ci->m_lock);
	opinfo_put(opinfo);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_durable_unbind_opinfo_conn);

void ksmbd_durable_rebind_opinfo_conn(struct ksmbd_file *fp,
				      struct ksmbd_conn *conn)
{
	struct oplock_info *opinfo;

	if (!fp || !fp->f_ci || !conn)
		return;

	opinfo = opinfo_get(fp);
	if (!opinfo)
		return;

	down_write(&fp->f_ci->m_lock);
	if (!opinfo->conn) {
		/*
		 * Reconnect only restores the durable handle's own opinfo.
		 * Rebinding every detached inode opinfo cross-wires lease
		 * ownership between unrelated opens on the same inode.
		 */
		opinfo->conn = conn;
		refcount_inc(&conn->refcnt);
	}
	up_write(&fp->f_ci->m_lock);
	opinfo_put(opinfo);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_durable_rebind_opinfo_conn);

static bool session_fd_check(struct ksmbd_tree_connect *tcon,
			     struct ksmbd_file *fp)
{
	struct ksmbd_conn *conn;

	if (!is_reconnectable(fp))
		return false;

	conn = fp->conn;
	ksmbd_durable_unbind_opinfo_conn(fp, conn);

	/*
	 * Detach locks from the old connection's lock_list before
	 * clearing fp->conn.  The connection is about to be destroyed;
	 * leaving clist linked would cause use-after-free.
	 * The locks remain on fp->lock_list (via flist) and will be
	 * re-linked to the new connection during ksmbd_reopen_durable_fd.
	 */
	if (!list_empty(&fp->lock_list) && conn) {
		struct ksmbd_lock *lk;

		spin_lock(&conn->llist_lock);
		list_for_each_entry(lk, &fp->lock_list, flist) {
			list_del_init(&lk->clist);
		}
		spin_unlock(&conn->llist_lock);
	}

	fp->conn = NULL;
	fp->tcon = NULL;
	fp->volatile_id = KSMBD_NO_FID;

	if (fp->durable_timeout) {
		fp->durable_scavenger_timeout =
			jiffies + msecs_to_jiffies(fp->durable_timeout);
		mod_timer(&fp->durable_expire_timer,
			  fp->durable_scavenger_timeout);
	} else if (fp->is_resilient && fp->resilient_timeout) {
		fp->durable_scavenger_timeout =
			jiffies + msecs_to_jiffies(fp->resilient_timeout);
		mod_timer(&fp->durable_expire_timer,
			  fp->durable_scavenger_timeout);
	}

	return true;
}

void ksmbd_close_tree_conn_fds(struct ksmbd_work *work)
{
	int num = __close_file_table_ids(&work->sess->file_table,
					 work->tcon,
					 tree_conn_fd_check);

	atomic_sub(num, &work->conn->stats.open_files_count);
}

void ksmbd_close_session_fds(struct ksmbd_work *work)
{
	int num = __close_file_table_ids(&work->sess->file_table,
					 work->tcon,
					 session_fd_check);

	atomic_sub(num, &work->conn->stats.open_files_count);
}

int ksmbd_init_global_file_table(void)
{
	return ksmbd_init_file_table(&global_ft);
}

bool ksmbd_global_file_table_inited(void)
{
	return global_ft.idr != NULL;
}

void ksmbd_free_global_file_table(void)
{
	struct ksmbd_file	*fp = NULL;
	unsigned int		id = 0;

	if (!global_ft.idr)
		return;

	while (1) {
		write_lock(&global_ft.lock);
		fp = idr_get_next(global_ft.idr, &id);
		if (!fp) {
			write_unlock(&global_ft.lock);
			break;
		}
		__ksmbd_remove_durable_fd(fp);
		fp->persistent_id = KSMBD_NO_FID;
		write_unlock(&global_ft.lock);
		if (fp->f_ci) {
			down_write(&fp->f_ci->m_lock);
			list_del_init(&fp->node);
			up_write(&fp->f_ci->m_lock);
		}
		ksmbd_cleanup_file_closing_state(fp);
		__ksmbd_close_fd(NULL, fp);
		id = 0;
	}

	idr_destroy(global_ft.idr);
	kfree(global_ft.idr);
	global_ft.idr = NULL;
}

int ksmbd_file_table_flush(struct ksmbd_work *work)
{
	struct ksmbd_file	*fp = NULL;
	unsigned int		id;
	int			ret = 0;

	read_lock(&work->sess->file_table.lock);
	idr_for_each_entry(work->sess->file_table.idr, fp, id) {
		ret = ksmbd_vfs_fsync(work, fp->volatile_id, KSMBD_NO_FID, false);
		if (ret)
			break;
	}
	read_unlock(&work->sess->file_table.lock);
	return ret;
}

int ksmbd_validate_name_reconnect(struct ksmbd_share_config *share,
				  struct ksmbd_file *fp, char *name)
{
	char *pathname, *ab_pathname;
	int ret = 0;

	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!pathname)
		return -EACCES;

	ab_pathname = d_path(&fp->filp->f_path, pathname, PATH_MAX);
	if (IS_ERR(ab_pathname)) {
		kfree(pathname);
		return -EACCES;
	}

	if (name && strcmp(&ab_pathname[share->path_sz + 1], name)) {
		ksmbd_debug(SMB, "invalid name reconnect %s\n", name);
		ret = -EINVAL;
	}

	kfree(pathname);

	return ret;
}

int ksmbd_reopen_durable_fd(struct ksmbd_work *work, struct ksmbd_file *fp)
{
	struct ksmbd_conn *stale_conn;

	stale_conn = READ_ONCE(fp->conn);
	if (!fp->is_durable || fp->conn || fp->tcon) {
		if (fp->is_durable && stale_conn &&
		    ksmbd_conn_releasing(stale_conn)) {
			/*
			 * Reconnect raced with session teardown. The old
			 * transport is already dying, so finish the minimal
			 * durable detach locally and let reconnect claim it.
			 */
			if (!list_empty(&fp->lock_list)) {
				struct ksmbd_lock *lk;

				spin_lock(&stale_conn->llist_lock);
				list_for_each_entry(lk, &fp->lock_list, flist)
					list_del_init(&lk->clist);
				spin_unlock(&stale_conn->llist_lock);
			}
			ksmbd_durable_unbind_opinfo_conn(fp, stale_conn);
			fp->conn = NULL;
			fp->tcon = NULL;
			fp->volatile_id = KSMBD_NO_FID;
		} else if (fp->is_durable && stale_conn &&
			   ksmbd_conn_exiting(stale_conn)) {
			if (!list_empty(&fp->lock_list)) {
				struct ksmbd_lock *lk;

				spin_lock(&stale_conn->llist_lock);
				list_for_each_entry(lk, &fp->lock_list, flist)
					list_del_init(&lk->clist);
				spin_unlock(&stale_conn->llist_lock);
			}
			ksmbd_durable_unbind_opinfo_conn(fp, stale_conn);
			fp->conn = NULL;
			fp->tcon = NULL;
			fp->volatile_id = KSMBD_NO_FID;
		}
	}

	if (!fp->is_durable || fp->conn || fp->tcon) {
		pr_err("Invalid durable fd [%pK:%pK]\n", fp->conn, fp->tcon);
		return -EBADF;
	}

	if (has_file_id(fp->volatile_id)) {
		pr_err("Still in use durable fd: %llu\n", fp->volatile_id);
		return -EBADF;
	}

	/*
	 * Clear scavenger timeout so the scavenger thread will not
	 * attempt to expire this handle while it is being reclaimed.
	 */
	fp->durable_scavenger_timeout = 0;

	fp->conn = work->conn;
	fp->tcon = work->tcon;
	ksmbd_durable_rebind_opinfo_conn(fp, fp->conn);

	/*
	 * Migrate locks from the dead connection's lock_list to the
	 * new connection's lock_list.  During disconnect, the locks
	 * remain on fp->lock_list (via flist) but their clist linkage
	 * to the old connection was removed in session_fd_check().
	 * Re-link them to the new connection so that unlock operations
	 * can find them.
	 */
	if (!list_empty(&fp->lock_list)) {
		struct ksmbd_lock *lk;

		spin_lock(&work->conn->llist_lock);
		list_for_each_entry(lk, &fp->lock_list, flist) {
			list_del_init(&lk->clist);
			list_add_tail(&lk->clist, &work->conn->lock_list);
		}
		spin_unlock(&work->conn->llist_lock);
	}

	fp->f_state = FP_NEW;
	__open_id(&work->sess->file_table, fp, OPEN_ID_TYPE_VOLATILE_ID);
	if (!has_file_id(fp->volatile_id)) {
		fp->conn = NULL;
		fp->tcon = NULL;
		return -EBADF;
	}
	fp->persistent_restore_pending = false;
	return 0;
}

int ksmbd_init_file_table(struct ksmbd_file_table *ft)
{
	ft->idr = kzalloc(sizeof(struct idr), KSMBD_DEFAULT_GFP);
	if (!ft->idr)
		return -ENOMEM;

	idr_init(ft->idr);
	rwlock_init(&ft->lock);
	return 0;
}

void ksmbd_destroy_file_table(struct ksmbd_file_table *ft)
{
	if (!ft->idr)
		return;

	__close_file_table_ids(ft, NULL, session_fd_check);
	idr_destroy(ft->idr);
	kfree(ft->idr);
	ft->idr = NULL;
}

int ksmbd_init_file_cache(void)
{
	filp_cache = kmem_cache_create("ksmbd_file_cache",
				       sizeof(struct ksmbd_file), 0,
				       SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,
				       NULL);
	if (!filp_cache)
		goto out;

	init_waitqueue_head(&dh_wq);

	return 0;

out:
	pr_err("failed to allocate file cache\n");
	return -ENOMEM;
}

void ksmbd_exit_file_cache(void)
{
	kmem_cache_destroy(filp_cache);
	filp_cache = NULL;
}
