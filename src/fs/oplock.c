// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/moduleparam.h>
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT static
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

#include <linux/filelock.h>
#include "glob.h"
#include "oplock.h"
#include "vfs_cache.h"

#include "smb_common.h"
#ifdef CONFIG_SMB_INSECURE_SERVER
#include "smb1pdu.h"
#endif
#include "smbstatus.h"
#include "connection.h"
#include "server.h"
#include "smb2fruit.h"
#include "smb2pdu_internal.h"
#include "mgmt/user_session.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"

static LIST_HEAD(lease_table_list);
static DEFINE_RWLOCK(lease_list_lock);
static struct kmem_cache *opinfo_cache;
static LIST_HEAD(ksmbd_lease_breaker_tasks);
static DEFINE_SPINLOCK(ksmbd_lease_breaker_lock);

__u8 smb2_map_lease_to_oplock(__le32 lease_state);

/*
 * Kernel VFS lease integration for coordination with local openers.
 *
 * KSMBD-LEASE-02:
 * - track ksmbd's own dentry_open() callers so the VFS does not treat them as
 *   foreign lease breakers
 * - hold a dedicated opinfo reference for the lifetime of the registered VFS
 *   lease so flc_owner never points at freed memory
 */
struct ksmbd_lease_breaker_task {
	struct list_head	entry;
	struct task_struct	*task;
	unsigned int		depth;
};

static struct ksmbd_lease_breaker_task *
ksmbd_find_lease_breaker_task(struct task_struct *task)
{
	struct ksmbd_lease_breaker_task *entry;

	list_for_each_entry(entry, &ksmbd_lease_breaker_tasks, entry) {
		if (entry->task == task)
			return entry;
	}

	return NULL;
}

void ksmbd_lease_breaker_enter(void)
{
	struct ksmbd_lease_breaker_task *entry, *new_entry = NULL;
	unsigned long flags;

	spin_lock_irqsave(&ksmbd_lease_breaker_lock, flags);
	entry = ksmbd_find_lease_breaker_task(current);
	if (entry) {
		entry->depth++;
		spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);

	new_entry = kmalloc(sizeof(*new_entry), KSMBD_DEFAULT_GFP);
	if (!new_entry)
		return;

	new_entry->task = current;
	new_entry->depth = 1;
	INIT_LIST_HEAD(&new_entry->entry);

	spin_lock_irqsave(&ksmbd_lease_breaker_lock, flags);
	entry = ksmbd_find_lease_breaker_task(current);
	if (entry) {
		entry->depth++;
		spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);
		kfree(new_entry);
		return;
	}
	list_add(&new_entry->entry, &ksmbd_lease_breaker_tasks);
	spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);
}

void ksmbd_lease_breaker_exit(void)
{
	struct ksmbd_lease_breaker_task *entry;
	unsigned long flags;

	spin_lock_irqsave(&ksmbd_lease_breaker_lock, flags);
	entry = ksmbd_find_lease_breaker_task(current);
	if (!entry) {
		spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);
		return;
	}

	if (--entry->depth) {
		spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);
		return;
	}

	list_del(&entry->entry);
	spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);
	kfree(entry);
}

static bool ksmbd_lm_break(struct file_lease *fl);

static bool ksmbd_lm_breaker_owns_lease(struct file_lease *fl)
{
	struct ksmbd_lease_breaker_task *entry;
	unsigned long flags;
	bool owns = false;

	spin_lock_irqsave(&ksmbd_lease_breaker_lock, flags);
	entry = ksmbd_find_lease_breaker_task(current);
	if (entry && entry->depth)
		owns = true;
	spin_unlock_irqrestore(&ksmbd_lease_breaker_lock, flags);

	return owns;
}

static const struct lease_manager_operations ksmbd_lease_lm_ops = {
	.lm_break		= ksmbd_lm_break,
	.lm_change		= lease_modify,
	.lm_breaker_owns_lease	= ksmbd_lm_breaker_owns_lease,
};

static bool ksmbd_lm_break(struct file_lease *fl)
{
	struct oplock_info *opinfo;

	opinfo = READ_ONCE(fl->c.flc_owner);
	if (!opinfo)
		return true;

	if (!refcount_inc_not_zero(&opinfo->refcount))
		return true;

	if (opinfo->op_state != OPLOCK_ACK_WAIT) {
		opinfo->op_state = OPLOCK_ACK_WAIT;
		wake_up_interruptible_all(&opinfo->oplock_q);
	}

	opinfo_put(opinfo);
	return false;
}

static void ksmbd_set_kernel_lease(struct oplock_info *opinfo)
{
	struct file *filp;
	struct file_lease *fl;
	int lease_type;
	int ret;

	if (!opinfo->o_fp || !opinfo->o_fp->filp)
		return;

	filp = opinfo->o_fp->filp;
	if (S_ISDIR(file_inode(filp)->i_mode))
		return;

	switch (opinfo->level) {
	case SMB2_OPLOCK_LEVEL_BATCH:
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		lease_type = F_WRLCK;
		break;
	case SMB2_OPLOCK_LEVEL_II:
		lease_type = F_RDLCK;
		break;
	default:
		return;
	}

	fl = locks_alloc_lease();
	if (!fl) {
		pr_warn_ratelimited("ksmbd: failed to allocate kernel lease\n");
		return;
	}

	fl->fl_lmops = &ksmbd_lease_lm_ops;
	fl->c.flc_file = filp;
	fl->c.flc_flags = FL_LEASE;
	fl->c.flc_type = lease_type;
	fl->c.flc_pid = current->tgid;
	refcount_inc(&opinfo->refcount);
	fl->c.flc_owner = (fl_owner_t)opinfo;

	ret = vfs_setlease(filp, lease_type, &fl, NULL);
	if (ret) {
		WRITE_ONCE(fl->c.flc_owner, NULL);
		opinfo_put(opinfo);
		ksmbd_debug(OPLOCK,
			    "vfs_setlease failed: %d (level=%d)\n",
			    ret, opinfo->level);
		return;
	}

	opinfo->fl_lease = fl;
}

/**
 * ksmbd_release_kernel_lease() - release the kernel VFS lease for an oplock
 * @opinfo:	oplock info
 */
static void ksmbd_release_kernel_lease(struct oplock_info *opinfo)
{
	struct file *filp;
	struct file_lease *fl;
	void *owner;
	int ret = -ENOENT;

	fl = xchg(&opinfo->fl_lease, NULL);
	if (!fl)
		return;

	if (!opinfo->o_fp || !opinfo->o_fp->filp)
		goto restore;

	filp = opinfo->o_fp->filp;
	owner = opinfo;
	ret = vfs_setlease(filp, F_UNLCK, NULL, &owner);
	if (ret)
		goto restore;

	opinfo_put(opinfo);
	return;

restore:
	if (cmpxchg(&opinfo->fl_lease, NULL, fl) == NULL) {
		ksmbd_debug(OPLOCK,
			    "vfs_setlease F_UNLCK failed: %d\n", ret);
		return;
	}
	ksmbd_debug(OPLOCK,
		    "lease release raced with another teardown path\n");
}

/**
 * ksmbd_downgrade_kernel_lease() - downgrade kernel VFS lease from write to read
 * @opinfo:	oplock info being downgraded
 *
 * Called when an exclusive/batch oplock is downgraded to Level II.
 */
static void ksmbd_downgrade_kernel_lease(struct oplock_info *opinfo)
{
	struct file *filp;
	struct file_lease *fl;
	int ret;

	fl = READ_ONCE(opinfo->fl_lease);
	if (!fl)
		return;

	if (!opinfo->o_fp || !opinfo->o_fp->filp)
		return;

	filp = opinfo->o_fp->filp;
	fl->c.flc_type = F_RDLCK;
	ret = vfs_setlease(filp, F_RDLCK, &fl, NULL);
	if (ret) {
		ksmbd_debug(OPLOCK,
			    "vfs_setlease F_RDLCK downgrade failed: %d\n",
			    ret);
		ksmbd_release_kernel_lease(opinfo);
	}
}

/**
 * alloc_opinfo() - allocate a new opinfo object for oplock info
 * @work:	smb work
 * @id:		fid of open file
 * @Tid:	tree id of connection
 *
 * Return:      allocated opinfo object on success, otherwise NULL
 */
static struct oplock_info *alloc_opinfo(struct ksmbd_work *work,
					u64 id, __u16 Tid)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_session *sess = work->sess;
	struct oplock_info *opinfo;

	opinfo = kmem_cache_zalloc(opinfo_cache, KSMBD_DEFAULT_GFP);
	if (!opinfo)
		return NULL;

	opinfo->sess = sess;
	opinfo->conn = conn;
	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	opinfo->op_state = OPLOCK_STATE_NONE;
	opinfo->pending_break = 0;
	opinfo->fid = id;
	opinfo->Tid = Tid;
#ifdef CONFIG_SMB_INSECURE_SERVER
	opinfo->is_smb2 = IS_SMB2(conn);
#endif
	INIT_LIST_HEAD(&opinfo->op_entry);
	init_waitqueue_head(&opinfo->oplock_q);
	init_waitqueue_head(&opinfo->oplock_brk);
	refcount_set(&opinfo->refcount, 1);
	atomic_set(&opinfo->breaking_cnt, 0);
	/*
	 * Use refcount_inc_not_zero() to guard against a race where the
	 * connection is torn down concurrently and its refcnt has already
	 * reached 0.  An unconditional refcount_inc() on a freed object
	 * would saturate the refcount and corrupt connection state.
	 */
	if (!refcount_inc_not_zero(&opinfo->conn->refcnt)) {
		kmem_cache_free(opinfo_cache, opinfo);
		return NULL;
	}

	return opinfo;
}

static struct ksmbd_conn *opinfo_get_live_conn(struct oplock_info *opinfo)
{
	struct ksmbd_conn *conn;

	conn = READ_ONCE(opinfo->conn);
	if (!conn)
		return NULL;
	if (!refcount_inc_not_zero(&conn->refcnt))
		return NULL;
	if (READ_ONCE(opinfo->conn) != conn || ksmbd_conn_releasing(conn)) {
		ksmbd_conn_free(conn);
		return NULL;
	}
	return conn;
}

/**
 * lease_get_break_conn() - find the best connection for a lease break
 * @opinfo:	oplock_info whose lease needs a break notification
 *
 * MS-SMB2 §3.3.4.7: Lease break notifications are per-client, not
 * per-handle.  Windows/Samba send the break on the first available
 * transport association for the client.
 *
 * Strategy: scan the lease table (per-ClientGUID) for the oldest
 * opinfo entry that has a live connection.  list_add_rcu() adds new
 * entries at the head, so the tail of the list is the oldest.
 * We iterate the whole list and keep updating 'best' so that 'best'
 * ends up pointing to the last (oldest) live entry.
 *
 * Falls back to opinfo's own connection if no other is found.
 *
 * Return:	connection with refcount incremented, or NULL
 */
static struct ksmbd_conn *lease_get_break_conn(struct oplock_info *opinfo,
					       struct ksmbd_session **sess)
{
	struct lease_table *lb;
	struct oplock_info *iter;
	struct ksmbd_conn *best = NULL;
	struct ksmbd_session *best_sess = NULL;

	if (!opinfo->is_lease || !opinfo->o_lease ||
	    !opinfo->o_lease->l_lb)
		goto fallback;

	lb = opinfo->o_lease->l_lb;

	rcu_read_lock();
	list_for_each_entry_rcu(iter, &lb->lease_list, lease_entry) {
		struct ksmbd_conn *c = READ_ONCE(iter->conn);

		if (!c)
			continue;
		/*
		 * Keep iterating — the last live conn we find is the
		 * oldest (tail of list_add_rcu list = first inserted).
		 */
		if (!refcount_inc_not_zero(&c->refcnt))
			continue;
		if (ksmbd_conn_releasing(c) || ksmbd_conn_exiting(c)) {
			ksmbd_conn_free(c);
			continue;
		}
		/* Drop previous candidate */
		if (best)
			ksmbd_conn_free(best);
		best = c;
		best_sess = iter->sess;
	}
	rcu_read_unlock();

fallback:
	if (!best) {
		best = opinfo_get_live_conn(opinfo);
		best_sess = opinfo->sess;
	}

	if (sess)
		*sess = best_sess;

	return best;
}

static void lease_add_list(struct oplock_info *opinfo)
{
	struct lease_table *lb = opinfo->o_lease->l_lb;

	spin_lock(&lb->lb_lock);
	list_add_rcu(&opinfo->lease_entry, &lb->lease_list);
	spin_unlock(&lb->lb_lock);
}

static void lease_del_list(struct oplock_info *opinfo)
{
	struct lease_table *lb = opinfo->o_lease->l_lb;

	if (!lb)
		return;

	spin_lock(&lb->lb_lock);
	if (list_empty(&opinfo->lease_entry)) {
		spin_unlock(&lb->lb_lock);
		return;
	}

	list_del_init(&opinfo->lease_entry);
	opinfo->o_lease->l_lb = NULL;
	spin_unlock(&lb->lb_lock);
}


VISIBLE_IF_KUNIT
int alloc_lease(struct oplock_info *opinfo, struct lease_ctx_info *lctx)
{
	struct lease *lease;

	lease = kmalloc(sizeof(struct lease), KSMBD_DEFAULT_GFP);
	if (!lease)
		return -ENOMEM;

	memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);
	lease->state = lctx->req_state;
	lease->new_state = 0;
	/*
	 * SMB2_LEASE_FLAG_BREAK_IN_PROGRESS is a server-only flag
	 * (MS-SMB2 §2.2.13.2.8).  Strip it from the client's request
	 * so it is not echoed back in the response.
	 */
	lease->flags = lctx->flags & ~SMB2_LEASE_FLAG_BREAK_IN_PROGRESS_LE;
	lease->duration = lctx->duration;
	lease->is_dir = lctx->is_dir;
	memcpy(lease->parent_lease_key, lctx->parent_lease_key, SMB2_LEASE_KEY_SIZE);
	lease->version = lctx->version;
	lease->epoch = le16_to_cpu(lctx->epoch);
	lease->l_lb = NULL;
	INIT_LIST_HEAD(&opinfo->lease_entry);
	opinfo->o_lease = lease;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(alloc_lease);

static void free_lease(struct oplock_info *opinfo)
{
	struct lease *lease;

	lease = opinfo->o_lease;
	kfree(lease);
}

static void free_opinfo(struct oplock_info *opinfo)
{
	if (opinfo->is_lease)
		free_lease(opinfo);
	if (opinfo->conn)
		ksmbd_conn_free(opinfo->conn);
	opinfo->conn = NULL;
	kmem_cache_free(opinfo_cache, opinfo);
}

struct oplock_info *opinfo_get(struct ksmbd_file *fp)
{
	struct oplock_info *opinfo;

	rcu_read_lock();
	opinfo = rcu_dereference(fp->f_opinfo);
	if (opinfo && !refcount_inc_not_zero(&opinfo->refcount))
		opinfo = NULL;
	rcu_read_unlock();

	return opinfo;
}

VISIBLE_IF_KUNIT
struct oplock_info *opinfo_get_list(struct ksmbd_inode *ci)
{
	struct oplock_info *opinfo, *found = NULL;

	down_read(&ci->m_lock);
	list_for_each_entry(opinfo, &ci->m_op_list, op_entry) {
		if (opinfo->conn == NULL)
			continue;
		if (!refcount_inc_not_zero(&opinfo->refcount))
			continue;
		if (ksmbd_conn_releasing(opinfo->conn)) {
			opinfo_put(opinfo);
			continue;
		}
		found = opinfo;
		break;
	}
	up_read(&ci->m_lock);

	return found;
}
EXPORT_SYMBOL_IF_KUNIT(opinfo_get_list);

void opinfo_put(struct oplock_info *opinfo)
{
	if (!opinfo)
		return;

	if (!refcount_dec_and_test(&opinfo->refcount))
		return;

	free_opinfo(opinfo);
}

static void opinfo_add(struct oplock_info *opinfo)
{
	struct ksmbd_inode *ci = opinfo->o_fp->f_ci;

	down_write(&ci->m_lock);
	list_add(&opinfo->op_entry, &ci->m_op_list);
	up_write(&ci->m_lock);
}

static void opinfo_del(struct oplock_info *opinfo)
{
	struct ksmbd_inode *ci = opinfo->o_fp->f_ci;

	if (opinfo->is_lease)
		lease_del_list(opinfo);

	down_write(&ci->m_lock);
	list_del(&opinfo->op_entry);
	up_write(&ci->m_lock);
}

static unsigned long opinfo_count(struct ksmbd_file *fp)
{
	if (ksmbd_stream_fd(fp))
		return atomic_read(&fp->f_ci->sop_count);
	else
		return atomic_read(&fp->f_ci->op_count);
}

static void opinfo_count_inc(struct ksmbd_file *fp)
{
	if (ksmbd_stream_fd(fp))
		return atomic_inc(&fp->f_ci->sop_count);
	else
		return atomic_inc(&fp->f_ci->op_count);
}

static void opinfo_count_dec(struct ksmbd_file *fp)
{
	if (ksmbd_stream_fd(fp))
		return atomic_dec(&fp->f_ci->sop_count);
	else
		return atomic_dec(&fp->f_ci->op_count);
}

/**
 * opinfo_write_to_read() - convert a write oplock to read oplock
 * @opinfo:		current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
/* L-02: all opinfo state transition functions require ci->m_lock write-held */
int opinfo_write_to_read(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (opinfo->is_smb2) {
		if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
		      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
			pr_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				pr_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_II;

		if (opinfo->is_lease)
			lease->state = lease->new_state;
	} else {
		if (!(opinfo->level == OPLOCK_EXCLUSIVE ||
		      opinfo->level == OPLOCK_BATCH)) {
			pr_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_READ;
	}
#else
	if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
	      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
		pr_err("bad oplock(0x%x)\n", opinfo->level);
		if (opinfo->is_lease)
			pr_err("lease state(0x%x)\n", lease->state);
		return -EINVAL;
	}
	opinfo->level = SMB2_OPLOCK_LEVEL_II;

	if (opinfo->is_lease)
		lease->state = lease->new_state;
#endif
	/* Downgrade kernel VFS lease from write to read */
	ksmbd_downgrade_kernel_lease(opinfo);

	return 0;
}

/**
 * opinfo_read_handle_to_read() - convert a read/handle oplock to read oplock
 * @opinfo:		current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_handle_to_read(struct oplock_info *opinfo)
{
	struct lease *lease;

	if (!opinfo->is_lease)
		return -EINVAL;

	lease = opinfo->o_lease;
	lease->state = lease->new_state;
	opinfo->level = SMB2_OPLOCK_LEVEL_II;
	return 0;
}

/**
 * opinfo_write_handle_to_write() - drop handle caching from a write+handle lease
 * @opinfo:		current oplock info
 *
 * Transitions a lease from RWH to RW by dropping Handle caching.
 * The opinfo level stays at BATCH/EXCLUSIVE since Write caching is retained.
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_handle_to_write(struct oplock_info *opinfo)
{
	struct lease *lease;

	if (!opinfo->is_lease)
		return -EINVAL;

	lease = opinfo->o_lease;
	if (!(lease->state & SMB2_LEASE_WRITE_CACHING_LE) ||
	    !(lease->state & SMB2_LEASE_HANDLE_CACHING_LE)) {
		pr_err("bad lease state(0x%x) for write_handle_to_write\n",
		       le32_to_cpu(lease->state));
		return -EINVAL;
	}

	/* Drop Handle caching, keep Read+Write */
	lease->state = lease->new_state;
	/* Keep opinfo->level at BATCH/EXCLUSIVE since Write is retained */
	return 0;
}

/**
 * opinfo_write_to_none() - convert a write oplock to none
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_write_to_none(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (opinfo->is_smb2) {
		if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
		      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
			pr_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				pr_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->is_lease)
			lease->state = lease->new_state;
	} else {
		if (!(opinfo->level == OPLOCK_EXCLUSIVE ||
		      opinfo->level == OPLOCK_BATCH)) {
			pr_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_NONE;
	}
#else
	if (!(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
	      opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)) {
		pr_err("bad oplock(0x%x)\n", opinfo->level);
		if (opinfo->is_lease)
			pr_err("lease state(0x%x)\n", lease->state);
		return -EINVAL;
	}
	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	if (opinfo->is_lease)
		lease->state = lease->new_state;
#endif
	/* Release kernel VFS lease entirely */
	ksmbd_release_kernel_lease(opinfo);

	return 0;
}

/**
 * opinfo_read_to_none() - convert a write read to none
 * @opinfo:	current oplock info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int opinfo_read_to_none(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (opinfo->is_smb2) {
		if (opinfo->level != SMB2_OPLOCK_LEVEL_II) {
			pr_err("bad oplock(0x%x)\n", opinfo->level);
			if (opinfo->is_lease)
				pr_err("lease state(0x%x)\n", lease->state);
			return -EINVAL;
		}
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		if (opinfo->is_lease)
			lease->state = lease->new_state;
	} else {
		if (opinfo->level != OPLOCK_READ) {
			pr_err("bad oplock(0x%x)\n", opinfo->level);
			return -EINVAL;
		}
		opinfo->level = OPLOCK_NONE;
	}
#else
	if (opinfo->level != SMB2_OPLOCK_LEVEL_II) {
		pr_err("bad oplock(0x%x)\n", opinfo->level);
		if (opinfo->is_lease)
			pr_err("lease state(0x%x)\n", lease->state);
		return -EINVAL;
	}
	opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	if (opinfo->is_lease)
		lease->state = lease->new_state;
#endif
	/* Release kernel VFS lease entirely */
	ksmbd_release_kernel_lease(opinfo);

	return 0;
}

static void oplock_complete_local_break(struct oplock_info *opinfo,
					int req_op_level)
{
	if (opinfo->is_lease) {
		opinfo->o_lease->state = opinfo->o_lease->new_state;
		opinfo->level = smb2_map_lease_to_oplock(opinfo->o_lease->state);
		if (!opinfo->level)
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		atomic_set(&opinfo->breaking_cnt, 0);
	} else {
#ifdef CONFIG_SMB_INSECURE_SERVER
		if (!opinfo->is_smb2) {
			if (opinfo->level == OPLOCK_EXCLUSIVE ||
			    opinfo->level == OPLOCK_BATCH) {
				opinfo->level = (req_op_level == SMB2_OPLOCK_LEVEL_NONE ||
						 opinfo->open_trunc) ?
						OPLOCK_NONE : OPLOCK_READ;
			} else {
				opinfo->level = OPLOCK_NONE;
			}
		} else
#endif
		if (opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
		    opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
			opinfo->level = (req_op_level == SMB2_OPLOCK_LEVEL_NONE ||
					 opinfo->open_trunc) ?
					SMB2_OPLOCK_LEVEL_NONE :
					SMB2_OPLOCK_LEVEL_II;
		} else {
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		}
	}

	opinfo->op_state = OPLOCK_STATE_NONE;
}

/**
 * lease_read_to_write() - upgrade lease state from read to write
 * @opinfo:	current lease info
 *
 * Return:      0 on success, otherwise -EINVAL
 */
int lease_read_to_write(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;

	if (!(lease->state & SMB2_LEASE_READ_CACHING_LE)) {
		ksmbd_debug(OPLOCK, "bad lease state(0x%x)\n", lease->state);
		return -EINVAL;
	}

	lease->new_state = SMB2_LEASE_NONE_LE;
	lease->state |= SMB2_LEASE_WRITE_CACHING_LE;
	if (lease->state & SMB2_LEASE_HANDLE_CACHING_LE)
		opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
	else
		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;

	/*
	 * Upgrade kernel VFS lease: release the old read lease and
	 * set a new write lease.
	 */
	ksmbd_release_kernel_lease(opinfo);
	ksmbd_set_kernel_lease(opinfo);

	return 0;
}

/**
 * lease_none_upgrade() - upgrade lease state from none
 * @opinfo:	current lease info
 * @new_state:	new lease state
 *
 * Return:	0 on success, otherwise -EINVAL
 */
VISIBLE_IF_KUNIT
int lease_none_upgrade(struct oplock_info *opinfo, __le32 new_state)
{
	struct lease *lease = opinfo->o_lease;

	if (!(lease->state == SMB2_LEASE_NONE_LE)) {
		ksmbd_debug(OPLOCK, "bad lease state(0x%x)\n", lease->state);
		return -EINVAL;
	}

	lease->new_state = SMB2_LEASE_NONE_LE;
	lease->state = new_state;
	if (lease->state & SMB2_LEASE_HANDLE_CACHING_LE)
		if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)
			opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
		else
			opinfo->level = SMB2_OPLOCK_LEVEL_II;
	else if (lease->state & SMB2_LEASE_WRITE_CACHING_LE)
		opinfo->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	else if (lease->state & SMB2_LEASE_READ_CACHING_LE)
		opinfo->level = SMB2_OPLOCK_LEVEL_II;

	if (new_state != SMB2_LEASE_NONE_LE)
		lease->epoch++;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(lease_none_upgrade);

/**
 * close_id_del_oplock() - release oplock object at file close time
 * @fp:		ksmbd file pointer
 */
void close_id_del_oplock(struct ksmbd_file *fp)
{
	struct oplock_info *opinfo;

	if (fp->reserve_lease_break)
		smb_lazy_parent_lease_break_close(fp);

	/*
	 * If this close will delete the file (last handle with DOC/
	 * DEL_PENDING), break parent directory leases before removing
	 * the opinfo — we need the opinfo's parent lease key to
	 * determine which directory leases to exempt.
	 */
	if (!S_ISDIR(file_inode(fp->filp)->i_mode) &&
	    ksmbd_inode_will_delete_on_close(fp))
		smb_dirlease_break_on_delete(fp);

	opinfo = opinfo_get(fp);
	if (!opinfo)
		return;

	/* Release the kernel VFS lease before removing the oplock */
	ksmbd_release_kernel_lease(opinfo);

	opinfo_del(opinfo);

	rcu_assign_pointer(fp->f_opinfo, NULL);
	if (opinfo->op_state == OPLOCK_ACK_WAIT) {
		opinfo->op_state = OPLOCK_CLOSING;
		wake_up_interruptible_all(&opinfo->oplock_q);
		if (opinfo->is_lease) {
			atomic_set(&opinfo->breaking_cnt, 0);
			wake_up_interruptible_all(&opinfo->oplock_brk);
		}
	}

	opinfo_count_dec(fp);
	opinfo_put(opinfo);  /* release the "created" reference */
	opinfo_put(opinfo);  /* release the opinfo_get() reference */
}

/**
 * grant_write_oplock() - grant exclusive/batch oplock or write lease
 * @opinfo_new:	new oplock info object
 * @req_oplock: request oplock
 * @lctx:	lease context information
 *
 * Return:      0
 */
VISIBLE_IF_KUNIT
void grant_write_oplock(struct oplock_info *opinfo_new, int req_oplock,
			       struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (opinfo_new->is_smb2) {
		if (req_oplock == SMB2_OPLOCK_LEVEL_BATCH)
			opinfo_new->level = SMB2_OPLOCK_LEVEL_BATCH;
		else
			opinfo_new->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else {
		if (req_oplock == REQ_BATCHOPLOCK)
			opinfo_new->level = OPLOCK_BATCH;
		else
			opinfo_new->level = OPLOCK_EXCLUSIVE;
	}
#else
	if (req_oplock == SMB2_OPLOCK_LEVEL_BATCH)
		opinfo_new->level = SMB2_OPLOCK_LEVEL_BATCH;
	else
		opinfo_new->level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
#endif

	if (lctx) {
		lease->state = lctx->req_state;
		memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);
		lease->epoch++;
	}
}
EXPORT_SYMBOL_IF_KUNIT(grant_write_oplock);

/**
 * grant_read_oplock() - grant level2 oplock or read lease
 * @opinfo_new:	new oplock info object
 * @lctx:	lease context information
 *
 * Return:      0
 */
VISIBLE_IF_KUNIT
void grant_read_oplock(struct oplock_info *opinfo_new,
			      struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (opinfo_new->is_smb2)
		opinfo_new->level = SMB2_OPLOCK_LEVEL_II;
	else
		opinfo_new->level = OPLOCK_READ;
#else
	opinfo_new->level = SMB2_OPLOCK_LEVEL_II;
#endif

	if (lctx) {
		lease->state = SMB2_LEASE_READ_CACHING_LE;
		if (lctx->req_state & SMB2_LEASE_HANDLE_CACHING_LE)
			lease->state |= SMB2_LEASE_HANDLE_CACHING_LE;
		memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);
		lease->epoch++;
	}
}
EXPORT_SYMBOL_IF_KUNIT(grant_read_oplock);

/**
 * grant_none_oplock() - grant none oplock or none lease
 * @opinfo_new:	new oplock info object
 * @lctx:	lease context information
 *
 * Return:      0
 */
VISIBLE_IF_KUNIT
void grant_none_oplock(struct oplock_info *opinfo_new,
			      struct lease_ctx_info *lctx)
{
	struct lease *lease = opinfo_new->o_lease;

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (opinfo_new->is_smb2)
		opinfo_new->level = SMB2_OPLOCK_LEVEL_NONE;
	else
		opinfo_new->level = OPLOCK_NONE;
#else
	opinfo_new->level = SMB2_OPLOCK_LEVEL_NONE;
#endif

	if (lctx) {
		lease->state = 0;
		memcpy(lease->lease_key, lctx->lease_key, SMB2_LEASE_KEY_SIZE);
	}
}
EXPORT_SYMBOL_IF_KUNIT(grant_none_oplock);

VISIBLE_IF_KUNIT
int compare_guid_key(struct oplock_info *opinfo,
				   const char *guid1, const char *key1)
{
	const char *guid2 = NULL, *key2;

	if (opinfo->conn &&
	    memchr_inv(opinfo->conn->ClientGUID, 0, SMB2_CLIENT_GUID_SIZE))
		guid2 = opinfo->conn->ClientGUID;
	else if (opinfo->sess &&
		 memchr_inv(opinfo->sess->ClientGUID, 0,
			    SMB2_CLIENT_GUID_SIZE))
		guid2 = opinfo->sess->ClientGUID;
	else if (opinfo->o_lease && opinfo->o_lease->l_lb &&
		 memchr_inv(opinfo->o_lease->l_lb->client_guid, 0,
			    SMB2_CLIENT_GUID_SIZE))
		guid2 = opinfo->o_lease->l_lb->client_guid;

	if (!guid2)
		return 0;

	key2 = opinfo->o_lease->lease_key;
	if (!memcmp(guid1, guid2, SMB2_CLIENT_GUID_SIZE) &&
	    !memcmp(key1, key2, SMB2_LEASE_KEY_SIZE))
		return 1;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(compare_guid_key);

/**
 * same_client_has_lease() - check whether current lease request is
 *		from lease owner of file
 * @ci:		master file pointer
 * @client_guid:	Client GUID
 * @lctx:		lease context information
 *
 * Return:      oplock(lease) object on success, otherwise NULL
 */
VISIBLE_IF_KUNIT
struct oplock_info *same_client_has_lease(struct ksmbd_inode *ci,
						 char *client_guid,
						 struct lease_ctx_info *lctx)
{
	int ret;
	struct lease *lease;
	struct oplock_info *opinfo;
	struct oplock_info *m_opinfo = NULL;

	if (!lctx)
		return NULL;

	/*
	 * Compare lease key and client_guid to know request from same owner
	 * of same client
	 */
	down_read(&ci->m_lock);
	list_for_each_entry(opinfo, &ci->m_op_list, op_entry) {
		if (!opinfo->is_lease || !opinfo->conn)
			continue;
		lease = opinfo->o_lease;

		ret = compare_guid_key(opinfo, client_guid, lctx->lease_key);
		if (ret) {
			m_opinfo = opinfo;
			/* skip upgrading lease about breaking lease */
			if (atomic_read(&opinfo->breaking_cnt))
				continue;

			/* upgrading lease */
			if ((atomic_read(&ci->op_count) +
			     atomic_read(&ci->sop_count)) == 1) {
				if (lease->state != SMB2_LEASE_NONE_LE &&
				    lease->state == (lctx->req_state & lease->state)) {
					/*
					 * Only bump epoch if the lease state
					 * is actually changing (upgrade).
					 * When requested state equals current
					 * state, this is a second open with
					 * the same lease — no epoch change.
					 */
					if (lctx->req_state != lease->state)
						lease->epoch++;
					lease->state |= lctx->req_state;
					if (lctx->req_state &
						SMB2_LEASE_WRITE_CACHING_LE)
						lease_read_to_write(opinfo);

				}
			} else if ((atomic_read(&ci->op_count) +
				    atomic_read(&ci->sop_count)) > 1) {
				if (lctx->req_state ==
				    (SMB2_LEASE_READ_CACHING_LE |
				     SMB2_LEASE_HANDLE_CACHING_LE)) {
					/*
					 * Only bump epoch if the state is
					 * actually changing.  A re-open
					 * with the same state should not
					 * increment the epoch.
					 */
					if (lease->state != lctx->req_state)
						lease->epoch++;
					lease->state = lctx->req_state;
				}
			}

			if (lctx->req_state && lease->state ==
			    SMB2_LEASE_NONE_LE) {
				/* lease_none_upgrade() already bumps epoch */
				lease_none_upgrade(opinfo, lctx->req_state);
			}
		}
	}
	up_read(&ci->m_lock);

	return m_opinfo;
}
EXPORT_SYMBOL_IF_KUNIT(same_client_has_lease);

static void wait_for_break_ack(struct oplock_info *opinfo)
{
	int rc = 0;

	/*
	 * Must use interruptible wait: the wake-up path on connection close
	 * calls wake_up_interruptible_all(&opinfo->oplock_q), which only
	 * wakes TASK_INTERRUPTIBLE waiters.  Using wait_event_timeout
	 * (TASK_UNINTERRUPTIBLE) would cause a full OPLOCK_WAIT_TIME (35s)
	 * stall whenever a client disconnects while a break is pending.
	 * Kernel worker threads do not receive user signals, so -ERESTARTSYS
	 * is not a concern in practice; treat any non-zero rc as "woken".
	 */
	rc = wait_event_interruptible_timeout(opinfo->oplock_q,
				opinfo->op_state == OPLOCK_STATE_NONE ||
				opinfo->op_state == OPLOCK_CLOSING,
				OPLOCK_WAIT_TIME);

	/* is this a timeout ? */
	if (!rc) {
		struct ksmbd_conn *conn;

		if (opinfo->is_lease)
			opinfo->o_lease->state = SMB2_LEASE_NONE_LE;
		opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
		opinfo->op_state = OPLOCK_STATE_NONE;

		/*
		 * On oplock break ACK timeout: clear oplock state so new opens
		 * are not blocked.  Do NOT force-close the file here — calling
		 * ksmbd_force_close_fd() leads to ksmbd_remove_durable_fd()
		 * trying to take write_lock(&global_ft.lock) which deadlocks
		 * with ksmbd_durable_scavenger holding that same lock.
		 * The file will be cleaned up when the client disconnects.
		 */
		pr_warn_ratelimited("ksmbd: oplock break ACK timeout on fid %llu\n",
				    opinfo->fid);

		/*
		 * MS-SMB2 3.3.4.7: if the client does not acknowledge the
		 * oplock break within the timeout, the server MUST disconnect
		 * the client's connection.
		 */
		conn = READ_ONCE(opinfo->conn);
		if (conn)
			ksmbd_conn_set_exiting(conn);
	}
}

static void wake_up_oplock_break(struct oplock_info *opinfo)
{
	clear_bit_unlock(0, &opinfo->pending_break);
	/* memory barrier is needed for wake_up_bit() */
	smp_mb__after_atomic();
	wake_up_bit(&opinfo->pending_break, 0);
}

/**
 * oplock_break_pending() - wait for and serialize concurrent breaks
 * @opinfo:	oplock/lease info
 * @req_op_level:	requested break level
 *
 * Return:	0 = proceed with break (first in sequence),
 *		2 = proceed with break (follow-up after waiting),
 *		1 = skip (already broken to target),
 *		< 0 = error
 */
VISIBLE_IF_KUNIT
int oplock_break_pending(struct oplock_info *opinfo, int req_op_level)
{
	int ret;
	bool waited = false;

	while  (test_and_set_bit(0, &opinfo->pending_break)) {
		waited = true;
		ret = wait_on_bit_timeout(&opinfo->pending_break, 0,
					  TASK_UNINTERRUPTIBLE,
					  OPLOCK_WAIT_TIME);
		if (ret) {
			if (ret == -EAGAIN)
				return -ETIMEDOUT;
			return ret;
		}

		/* Not immediately break to none. */
		opinfo->open_trunc = 0;

		if (opinfo->op_state == OPLOCK_CLOSING)
			return -ENOENT;

		if (opinfo->is_lease) {
			/*
			 * For Handle-caching breaks, skip only when the
			 * lease has no Handle caching left.  For other
			 * break types, skip when the lease has already
			 * been broken down to RH (no Write caching).
			 */
			if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING ||
			    req_op_level == OPLOCK_BREAK_HANDLE_CACHING_WAIT) {
				if (!(opinfo->o_lease->state &
				      SMB2_LEASE_HANDLE_CACHING_LE))
					return 1;
			} else if (opinfo->level <= req_op_level &&
				   opinfo->o_lease->state !=
				   (SMB2_LEASE_HANDLE_CACHING_LE |
				    SMB2_LEASE_READ_CACHING_LE)) {
				return 1;
			}
		} else if (opinfo->level <= req_op_level) {
			return 1;
		}
	}

	if (opinfo->is_lease) {
		if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING ||
		    req_op_level == OPLOCK_BREAK_HANDLE_CACHING_WAIT) {
			if (!(opinfo->o_lease->state &
			      SMB2_LEASE_HANDLE_CACHING_LE)) {
				wake_up_oplock_break(opinfo);
				return 1;
			}
		} else if (opinfo->level <= req_op_level &&
			   opinfo->o_lease->state !=
			   (SMB2_LEASE_HANDLE_CACHING_LE |
			    SMB2_LEASE_READ_CACHING_LE)) {
			wake_up_oplock_break(opinfo);
			return 1;
		}
	} else if (opinfo->level <= req_op_level) {
		wake_up_oplock_break(opinfo);
		return 1;
	}
	return waited ? 2 : 0;
}
EXPORT_SYMBOL_IF_KUNIT(oplock_break_pending);

#ifdef CONFIG_SMB_INSECURE_SERVER
/**
 * smb1_oplock_break_noti() - send smb1 oplock break cmd from conn
 * to client
 * @work:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * work->request_buf contains oplock_info.
 */
static void __smb1_oplock_break_noti(struct work_struct *wk)
{
	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);
	struct ksmbd_conn *conn = work->conn;
	struct smb_hdr *rsp_hdr;
	struct smb_com_lock_req *req;
	struct oplock_info *opinfo = work->request_buf;

	if (allocate_interim_rsp_buf(work)) {
		pr_err("smb_allocate_rsp_buf failed! ");
		goto out;
	}

	/* Init response header */
	rsp_hdr = work->response_buf;
	/* wct is 8 for locking andx(18) */
	memset(rsp_hdr, 0, sizeof(struct smb_hdr) + 18);
	rsp_hdr->smb_buf_length =
		cpu_to_be32(conn->vals->header_size - 4 + 18);
	rsp_hdr->Protocol[0] = 0xFF;
	rsp_hdr->Protocol[1] = 'S';
	rsp_hdr->Protocol[2] = 'M';
	rsp_hdr->Protocol[3] = 'B';

	rsp_hdr->Command = SMB_COM_LOCKING_ANDX;
	/* we know unicode, long file name and use nt error codes */
	rsp_hdr->Flags2 = SMBFLG2_UNICODE | SMBFLG2_KNOWS_LONG_NAMES |
		SMBFLG2_ERR_STATUS;
	rsp_hdr->Uid = cpu_to_le16(work->sess->id);
	rsp_hdr->Pid = cpu_to_le16(0xFFFF);
	rsp_hdr->Mid = cpu_to_le16(0xFFFF);
	rsp_hdr->Tid = cpu_to_le16(opinfo->Tid);
	rsp_hdr->WordCount = 8;

	/* Init locking request */
	req = work->response_buf;

	req->AndXCommand = 0xFF;
	req->AndXReserved = 0;
	req->AndXOffset = 0;
	req->Fid = opinfo->fid;
	req->LockType = LOCKING_ANDX_OPLOCK_RELEASE;
	if (!opinfo->open_trunc &&
	    (opinfo->level == OPLOCK_BATCH ||
	     opinfo->level == OPLOCK_EXCLUSIVE))
		req->OplockLevel = 1;
	else
		req->OplockLevel = 0;
	req->Timeout = 0;
	req->NumberOfUnlocks = 0;
	req->ByteCount = 0;
	ksmbd_debug(OPLOCK, "sending oplock break for fid %d lock level = %d\n",
		    req->Fid, req->OplockLevel);

	ksmbd_conn_write(work);
out:
	ksmbd_free_work_struct(work);
	ksmbd_conn_r_count_dec(conn);
	ksmbd_conn_free(conn);
}

/**
 * smb1_oplock_break() - send smb1 exclusive/batch to level2 oplock
 *		break command from server to client
 * @opinfo:		oplock info object
 * @ack_required	if requiring ack
 *
 * Return:      0 on success, otherwise error
 */
static int smb1_oplock_break_noti(struct oplock_info *opinfo)
{
	struct ksmbd_conn *conn = opinfo_get_live_conn(opinfo);
	struct ksmbd_work *work = ksmbd_alloc_work_struct();

	if (!conn)
		return -ENOENT;
	if (!work) {
		ksmbd_conn_free(conn);
		return -ENOMEM;
	}

	work->request_buf = (char *)opinfo;
	work->conn = conn;

	ksmbd_conn_r_count_inc(conn);
	if (opinfo->op_state == OPLOCK_ACK_WAIT) {
		INIT_WORK(&work->work, __smb1_oplock_break_noti);
		ksmbd_queue_work(work);

		wait_for_break_ack(opinfo);
	} else {
		__smb1_oplock_break_noti(&work->work);
		if (opinfo->level == OPLOCK_READ)
			opinfo->level = OPLOCK_NONE;
	}
	return 0;
}
#endif

/**
 * __smb2_oplock_break_noti() - send smb2 oplock break cmd from conn
 * to client
 * @wk:     smb work object
 *
 * There are two ways this function can be called. 1- while file open we break
 * from exclusive/batch lock to levelII oplock and 2- while file write/truncate
 * we break from levelII oplock no oplock.
 * work->request_buf contains oplock_info.
 */
static void __smb2_oplock_break_noti(struct work_struct *wk)
{
	struct smb2_oplock_break *rsp = NULL;
	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);
	struct ksmbd_conn *conn = work->conn;
	struct oplock_break_info *br_info = work->request_buf;
	struct smb2_hdr *rsp_hdr;
	struct ksmbd_file *fp;

	fp = ksmbd_lookup_global_fd(br_info->fid);
	if (!fp)
		goto out;

	if (allocate_interim_rsp_buf(work)) {
		pr_err("smb2_allocate_rsp_buf failed! ");
		ksmbd_fd_put(work, fp);
		goto out;
	}

	rsp_hdr = smb2_get_msg(work->response_buf);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(0);
	rsp_hdr->Command = SMB2_OPLOCK_BREAK;
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = cpu_to_le64(-1);
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = work->sess ? cpu_to_le64(work->sess->id) : 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = smb2_get_msg(work->response_buf);

	rsp->StructureSize = cpu_to_le16(24);
	if (!br_info->open_trunc &&
	    (br_info->level == SMB2_OPLOCK_LEVEL_BATCH ||
	     br_info->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_II;
	else
		rsp->OplockLevel = SMB2_OPLOCK_LEVEL_NONE;
	rsp->Reserved = 0;
	rsp->Reserved2 = 0;
	rsp->PersistentFid = cpu_to_le64(fp->persistent_id);
	rsp->VolatileFid = cpu_to_le64(fp->volatile_id);

	ksmbd_fd_put(work, fp);
	if (ksmbd_iov_pin_rsp(work, (void *)rsp,
			      sizeof(struct smb2_oplock_break)))
		goto out;

	ksmbd_debug(OPLOCK,
		    "sending oplock break v_id %llu p_id = %llu lock level = %d\n",
		    rsp->VolatileFid, rsp->PersistentFid, rsp->OplockLevel);

	ksmbd_smb2_finalize_async_rsp(work);
	ksmbd_conn_write(work);

out:
	ksmbd_free_work_struct(work);
	ksmbd_conn_r_count_dec(conn);
	ksmbd_conn_free(conn);
}

/**
 * smb2_oplock_break_noti() - send smb2 exclusive/batch to level2 oplock
 *		break command from server to client
 * @opinfo:		oplock info object
 *
 * Return:      0 on success, otherwise error
 */
static int smb2_oplock_break_noti(struct oplock_info *opinfo)
{
	struct ksmbd_conn *conn = opinfo_get_live_conn(opinfo);
	struct oplock_break_info *br_info;
	int ret = 0;
	struct ksmbd_work *work = ksmbd_alloc_work_struct();

	if (!conn)
		return -ENOENT;
	if (!work) {
		ksmbd_conn_free(conn);
		return -ENOMEM;
	}

	br_info = kmalloc(sizeof(struct oplock_break_info), KSMBD_DEFAULT_GFP);
	if (!br_info) {
		ksmbd_free_work_struct(work);
		ksmbd_conn_free(conn);
		return -ENOMEM;
	}

	br_info->level = opinfo->level;
	br_info->fid = opinfo->fid;
	br_info->open_trunc = opinfo->open_trunc;

	work->request_buf = (char *)br_info;
	work->conn = conn;
	work->sess = opinfo->sess;

	ksmbd_conn_r_count_inc(conn);
	if (opinfo->op_state == OPLOCK_ACK_WAIT) {
		INIT_WORK(&work->work, __smb2_oplock_break_noti);
		ksmbd_queue_work(work);

		wait_for_break_ack(opinfo);
	} else {
		__smb2_oplock_break_noti(&work->work);
		if (opinfo->level == SMB2_OPLOCK_LEVEL_II)
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
	}
	return ret;
}

/**
 * __smb2_lease_break_noti() - send lease break command from server
 * to client
 * @wk:     smb work object
 */
static void __smb2_lease_break_noti(struct work_struct *wk)
{
	struct smb2_lease_break *rsp = NULL;
	struct ksmbd_work *work = container_of(wk, struct ksmbd_work, work);
	struct ksmbd_conn *conn = work->conn;
	struct lease_break_info *br_info = work->request_buf;
	struct smb2_hdr *rsp_hdr;

	if (allocate_interim_rsp_buf(work)) {
		ksmbd_debug(OPLOCK, "smb2_allocate_rsp_buf failed! ");
		goto out;
	}

	rsp_hdr = smb2_get_msg(work->response_buf);
	memset(rsp_hdr, 0, sizeof(struct smb2_hdr) + 2);
	rsp_hdr->ProtocolId = SMB2_PROTO_NUMBER;
	rsp_hdr->StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
	rsp_hdr->CreditRequest = cpu_to_le16(0);
	rsp_hdr->Command = SMB2_OPLOCK_BREAK;
	rsp_hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR);
	rsp_hdr->NextCommand = 0;
	rsp_hdr->MessageId = cpu_to_le64(-1);
	rsp_hdr->Id.SyncId.ProcessId = 0;
	rsp_hdr->Id.SyncId.TreeId = 0;
	rsp_hdr->SessionId = work->sess ? cpu_to_le64(work->sess->id) : 0;
	memset(rsp_hdr->Signature, 0, 16);

	rsp = smb2_get_msg(work->response_buf);
	rsp->StructureSize = cpu_to_le16(44);
	rsp->Epoch = br_info->epoch;
	rsp->Flags = 0;

	if (br_info->curr_state & (SMB2_LEASE_WRITE_CACHING_LE |
			SMB2_LEASE_HANDLE_CACHING_LE))
		rsp->Flags = SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED;

	memcpy(rsp->LeaseKey, br_info->lease_key, SMB2_LEASE_KEY_SIZE);
	rsp->CurrentLeaseState = br_info->curr_state;
	rsp->NewLeaseState = br_info->new_state;
	/* M-12: set BreakReason (e.g. PARENT_LEASE_KEY_CHANGED on parent rename) */
	rsp->BreakReason = br_info->break_reason;
	rsp->AccessMaskHint = 0;
	rsp->ShareMaskHint = 0;

	if (ksmbd_iov_pin_rsp(work, (void *)rsp,
			      sizeof(struct smb2_lease_break)))
		goto out;

	ksmbd_smb2_finalize_async_rsp(work);
	ksmbd_conn_write(work);

out:
	ksmbd_free_work_struct(work);
	ksmbd_conn_r_count_dec(conn);
	ksmbd_conn_free(conn);
}

/**
 * lease_propagate_epoch() - propagate epoch to all sibling opinfos
 *     sharing the same lease key in the same lease table.
 * @opinfo:	opinfo whose epoch was just updated
 *
 * Per MS-SMB2 §3.3.4.7, a lease is identified by (ClientGuid, LeaseKey).
 * All opens sharing the same lease key share the same epoch counter.
 * After bumping epoch on one opinfo, propagate to siblings so that
 * subsequent break notifications for the same event carry the same epoch.
 */
static void lease_propagate_epoch(struct oplock_info *opinfo)
{
	struct lease *lease = opinfo->o_lease;
	struct lease_table *lb = lease->l_lb;
	struct oplock_info *sibling;

	if (!lb)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(sibling, &lb->lease_list, lease_entry) {
		if (sibling == opinfo)
			continue;
		if (!memcmp(sibling->o_lease->lease_key, lease->lease_key,
			    SMB2_LEASE_KEY_SIZE))
			sibling->o_lease->epoch = lease->epoch;
	}
	rcu_read_unlock();
}

/**
 * smb2_lease_break_noti() - break lease when a new client request
 *			write lease
 * @opinfo:		contains lease state information
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_lease_break_noti(struct oplock_info *opinfo)
{
	struct ksmbd_session *sess = NULL;
	struct ksmbd_conn *conn = lease_get_break_conn(opinfo, &sess);
	struct ksmbd_work *work;
	struct lease_break_info *br_info;
	struct lease *lease = opinfo->o_lease;

	if (!conn)
		return -ENOENT;
	work = ksmbd_alloc_work_struct();
	if (!work) {
		ksmbd_conn_free(conn);
		return -ENOMEM;
	}

	br_info = kmalloc(sizeof(struct lease_break_info), KSMBD_DEFAULT_GFP);
	if (!br_info) {
		ksmbd_free_work_struct(work);
		ksmbd_conn_free(conn);
		return -ENOMEM;
	}

	br_info->curr_state = lease->state;
	br_info->new_state = lease->new_state;
	/*
	 * Epoch was already bumped (if needed) in oplock_break()
	 * before calling us.  Just report the current value.
	 */
	if (lease->version == 2)
		br_info->epoch = cpu_to_le16(lease->epoch);
	else
		br_info->epoch = 0;
	/* M-12: propagate break reason set by the caller (e.g. parent rename) */
	br_info->break_reason = opinfo->break_reason;
	memcpy(br_info->lease_key, lease->lease_key, SMB2_LEASE_KEY_SIZE);

	work->request_buf = (char *)br_info;
	work->conn = conn;
	work->sess = sess ?: opinfo->sess;

	ksmbd_conn_r_count_inc(conn);
	if (opinfo->op_state == OPLOCK_ACK_WAIT) {
		INIT_WORK(&work->work, __smb2_lease_break_noti);
		ksmbd_queue_work(work);
		if (!opinfo->nowait_ack)
			wait_for_break_ack(opinfo);
	} else {
		__smb2_lease_break_noti(&work->work);
		if (opinfo->o_lease->new_state == SMB2_LEASE_NONE_LE) {
			opinfo->level = SMB2_OPLOCK_LEVEL_NONE;
			opinfo->o_lease->state = SMB2_LEASE_NONE_LE;
		}
	}
	return 0;
}

static void wait_lease_breaking(struct oplock_info *opinfo)
{
	if (!opinfo->is_lease)
		return;

	wake_up_interruptible_all(&opinfo->oplock_brk);
	if (atomic_read(&opinfo->breaking_cnt)) {
		int ret = 0;

		/*
		 * Handle-only breaks (no Write caching) are non-blocking
		 * per MS-SMB2 §3.3.4.7: the conflicting open proceeds
		 * immediately without waiting for the client's ACK.
		 * The ACK will be processed asynchronously when it arrives.
		 */
		if (opinfo->nowait_ack)
			return;

		/*
		 * Must use interruptible wait: the wake-up path calls
		 * wake_up_interruptible_all(&opinfo->oplock_brk).  Using
		 * wait_event_timeout (TASK_UNINTERRUPTIBLE) would not be
		 * woken by that call.
		 */
		ret = wait_event_interruptible_timeout(opinfo->oplock_brk,
					 atomic_read(&opinfo->breaking_cnt) == 0,
					 OPLOCK_WAIT_TIME);
		if (!ret)
			atomic_set(&opinfo->breaking_cnt, 0);
	}
}

VISIBLE_IF_KUNIT
int oplock_break(struct oplock_info *brk_opinfo, int req_op_level,
				struct ksmbd_work *in_work)
{
	int err = 0;
	bool break_in_progress;

	/* Need to break exclusive/batch oplock, write lease or overwrite_if */
	ksmbd_debug(OPLOCK,
		    "request to send oplock(level : 0x%x) break notification\n",
		    brk_opinfo->level);

	if (brk_opinfo->is_lease) {
		struct lease *lease = brk_opinfo->o_lease;
		int pending_ret;
		/*
		 * Save open_trunc before oplock_break_pending() clears
		 * it.  We need to know if truncation is pending so that
		 * Handle-only breaks block for the ACK instead of using
		 * nowait — otherwise smb_break_all_levII_oplock() would
		 * fire the next break before the client ACKs this one,
		 * causing duplicate break notifications (breaking3).
		 */
		int caller_is_trunc = brk_opinfo->open_trunc;

		break_in_progress = atomic_read(&brk_opinfo->breaking_cnt) > 0;
		brk_opinfo->nowait_ack = false;
		atomic_inc(&brk_opinfo->breaking_cnt);

		/*
		 * A later conflicting open that arrives while another lease
		 * break is already outstanding must become cancellable
		 * immediately, even if this invocation ends up being only the
		 * follow-up step in the same serialized downgrade sequence.
		 */
		if (break_in_progress && in_work && !in_work->asynchronous) {
			err = setup_async_work(in_work, NULL, NULL);
			if (!err)
				smb2_send_interim_resp(in_work, STATUS_PENDING);
		}

		pending_ret = oplock_break_pending(brk_opinfo, req_op_level);
		if (pending_ret < 0 || pending_ret == 1) {
			atomic_dec(&brk_opinfo->breaking_cnt);
			return pending_ret < 0 ? pending_ret : 0;
		}

		/*
		 * Bump epoch for v2 leases only on a FRESH break
		 * (pending_ret == 0).  Follow-up breaks within the
		 * same break sequence (pending_ret == 2, meaning we
		 * waited for a prior break) reuse the epoch that was
		 * already bumped by the first break — matching Windows
		 * and Samba behaviour (v2_breaking3).
		 */
		if (lease->version == 2 && pending_ret == 0 &&
		    !(in_work && in_work->asynchronous)) {
			lease->epoch++;
			lease_propagate_epoch(brk_opinfo);
		}

		if (brk_opinfo->open_trunc) {
			/*
			 * Create overwrite break trigger the lease break to
			 * none.
			 */
			lease->new_state = SMB2_LEASE_NONE_LE;
		} else if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING ||
			   req_op_level == OPLOCK_BREAK_HANDLE_CACHING_WAIT) {
			/* Handle break: strip H bit. RWH->RW, RH->R, H->NONE */
			lease->new_state = lease->state &
					   ~SMB2_LEASE_HANDLE_CACHING_LE;
			if (!lease->new_state)
				lease->new_state = SMB2_LEASE_NONE_LE;
		} else if (req_op_level == SMB2_OPLOCK_LEVEL_NONE) {
			lease->new_state = SMB2_LEASE_NONE_LE;
		} else {
			/*
			 * One-level-at-a-time break per MS-SMB2 3.3.4.7:
			 * Strip Write first, then Handle.
			 * RWH->RH, RW->R, RH->R, R->NONE, H->NONE
			 */
			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE) {
				lease->new_state = lease->state &
					~SMB2_LEASE_WRITE_CACHING_LE;
			} else if (lease->state &
				   SMB2_LEASE_HANDLE_CACHING_LE) {
				lease->new_state =
					SMB2_LEASE_READ_CACHING_LE;
			} else {
				lease->new_state = SMB2_LEASE_NONE_LE;
			}
		}

		if (lease->state & (SMB2_LEASE_WRITE_CACHING_LE |
				SMB2_LEASE_HANDLE_CACHING_LE)) {
			if (lease->state & SMB2_LEASE_WRITE_CACHING_LE) {
				/*
				 * Write caching present: the conflicting
				 * open must block until the client ACKs
				 * (MS-SMB2 §3.3.4.7).
				 */
				if (in_work && !in_work->asynchronous) {
					setup_async_work(in_work, NULL, NULL);
					smb2_send_interim_resp(in_work,
							       STATUS_PENDING);
				}
			}

			brk_opinfo->op_state = OPLOCK_ACK_WAIT;
			/*
			 * Handle-only lease breaks (no Write caching):
			 * Send the break notification async but do NOT
			 * wait for the ACK.  Per MS-SMB2 §3.3.4.7,
			 * Handle-only breaks are non-blocking — the
			 * conflicting open can proceed immediately.
			 *
			 * Exception 1: OPLOCK_BREAK_HANDLE_CACHING_WAIT
			 * is used for rename-into-directory where the
			 * server must wait for the Handle break ACK
			 * before proceeding.
			 *
			 * Exception 2: When the caller originally set
			 * open_trunc (OVERWRITE/SUPERSEDE open),
			 * smb_break_all_levII_oplock() will run right
			 * after us.  We must wait for the ACK so the
			 * state is updated before the next break fires.
			 */
			if (req_op_level == OPLOCK_BREAK_HANDLE_CACHING_WAIT)
				brk_opinfo->nowait_ack = false;
			else if (caller_is_trunc)
				brk_opinfo->nowait_ack = false;
			else if (!(lease->state & SMB2_LEASE_WRITE_CACHING_LE) ||
				 (!in_work &&
				  req_op_level == OPLOCK_BREAK_HANDLE_CACHING))
				brk_opinfo->nowait_ack = true;
		} else
			atomic_dec(&brk_opinfo->breaking_cnt);
	} else {
		err = oplock_break_pending(brk_opinfo, req_op_level);
		if (err)
			return err < 0 ? err : 0;

		if (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
		    brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE)
			brk_opinfo->op_state = OPLOCK_ACK_WAIT;
	}

	if (!READ_ONCE(brk_opinfo->conn) ||
	    ksmbd_conn_releasing(READ_ONCE(brk_opinfo->conn))) {
		oplock_complete_local_break(brk_opinfo, req_op_level);
		goto complete;
	}

#ifdef CONFIG_SMB_INSECURE_SERVER
	if (brk_opinfo->is_smb2)
		if (brk_opinfo->is_lease)
			err = smb2_lease_break_noti(brk_opinfo);
		else
			err = smb2_oplock_break_noti(brk_opinfo);
	else
		err = smb1_oplock_break_noti(brk_opinfo);
#else
		if (brk_opinfo->is_lease)
			err = smb2_lease_break_noti(brk_opinfo);
		else {
			/* OB-01: record the oplock level we are notifying client to downgrade to */
			if (!brk_opinfo->open_trunc &&
			    (brk_opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
			     brk_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE))
				brk_opinfo->notified_level = SMB2_OPLOCK_LEVEL_II;
			else
				brk_opinfo->notified_level = SMB2_OPLOCK_LEVEL_NONE;
			err = smb2_oplock_break_noti(brk_opinfo);
		}
	#endif
	if (err == -ENOENT) {
		oplock_complete_local_break(brk_opinfo, req_op_level);
		err = 0;
	}

complete:
	ksmbd_debug(OPLOCK, "oplock granted = %d\n", brk_opinfo->level);
	if (brk_opinfo->op_state == OPLOCK_CLOSING)
		err = -ENOENT;
	wake_up_oplock_break(brk_opinfo);

	wait_lease_breaking(brk_opinfo);

	return err;
}
EXPORT_SYMBOL_IF_KUNIT(oplock_break);

void destroy_lease_table(struct ksmbd_conn *conn)
{
	struct lease_table *lb, *lbtmp;
	struct oplock_info *opinfo;

	/*
	 * Teardown ordering: this is called after all sessions for the
	 * connection have been destroyed and all oplock references have
	 * been dropped.  The rcu_read_lock/list_for_each_entry_rcu here
	 * is safe because we hold write_lock(&lease_list_lock) which
	 * serialises against add_lease_global_list(), and all in-flight
	 * oplock breaks that could call lease_del_list() have completed
	 * before we get here (connection tear-down ensures this).
	 */
	write_lock(&lease_list_lock);
	if (list_empty(&lease_table_list)) {
		write_unlock(&lease_list_lock);
		return;
	}

	list_for_each_entry_safe(lb, lbtmp, &lease_table_list, l_entry) {
		if (conn && memcmp(lb->client_guid, conn->ClientGUID,
				   SMB2_CLIENT_GUID_SIZE))
			continue;
again:
		rcu_read_lock();
		list_for_each_entry_rcu(opinfo, &lb->lease_list,
					lease_entry) {
			rcu_read_unlock();
			lease_del_list(opinfo);
			goto again;
		}
		rcu_read_unlock();
		list_del_rcu(&lb->l_entry);
		kfree_rcu(lb, rcu_head);
	}
	write_unlock(&lease_list_lock);
}

int find_same_lease_key(struct ksmbd_session *sess, struct inode *inode,
			struct lease_ctx_info *lctx)
{
	struct oplock_info *opinfo;
	int err = 0;
	struct lease_table *lb;

	if (!lctx)
		return err;

	rcu_read_lock();
	if (list_empty(&lease_table_list)) {
		rcu_read_unlock();
		return 0;
	}

	list_for_each_entry_rcu(lb, &lease_table_list, l_entry) {
		if (!memcmp(lb->client_guid, sess->ClientGUID,
			    SMB2_CLIENT_GUID_SIZE))
			goto found;
	}
	rcu_read_unlock();

	return 0;

found:
	list_for_each_entry_rcu(opinfo, &lb->lease_list, lease_entry) {
		if (!refcount_inc_not_zero(&opinfo->refcount))
			continue;
		rcu_read_unlock();
		if (inode && opinfo->o_fp && opinfo->o_fp->filp &&
		    file_inode(opinfo->o_fp->filp) == inode)
			goto op_next;
		err = compare_guid_key(opinfo, sess->ClientGUID,
				       lctx->lease_key);
		if (err) {
			err = -EINVAL;
			ksmbd_debug(OPLOCK,
				    "found same lease key is already used in other files\n");
			opinfo_put(opinfo);
			return err;
		}
op_next:
		opinfo_put(opinfo);
		rcu_read_lock();
	}
	rcu_read_unlock();

	return err;
}

VISIBLE_IF_KUNIT
void copy_lease(struct oplock_info *op1, struct oplock_info *op2)
{
	struct lease *lease1 = op1->o_lease;
	struct lease *lease2 = op2->o_lease;

	op2->level = op1->level;
	lease2->state = lease1->state;
	memcpy(lease2->lease_key, lease1->lease_key,
	       SMB2_LEASE_KEY_SIZE);
	lease2->duration = lease1->duration;
	lease2->flags = lease1->flags;
	lease2->epoch = lease1->epoch;
	lease2->version = lease1->version;
	lease2->is_dir = lease1->is_dir;
}
EXPORT_SYMBOL_IF_KUNIT(copy_lease);

VISIBLE_IF_KUNIT
int add_lease_global_list(struct oplock_info *opinfo)
{
	struct lease_table *lb;

	/*
	 * Hold write_lock for the entire search-and-insert to prevent
	 * two concurrent callers for the same ClientGUID from both
	 * missing the lookup and creating duplicate lease_table entries.
	 */
	write_lock(&lease_list_lock);
	list_for_each_entry(lb, &lease_table_list, l_entry) {
		if (!memcmp(lb->client_guid, opinfo->conn->ClientGUID,
			    SMB2_CLIENT_GUID_SIZE)) {
			opinfo->o_lease->l_lb = lb;
			lease_add_list(opinfo);
			write_unlock(&lease_list_lock);
			return 0;
		}
	}

	/*
	 * Not found — must allocate under GFP_ATOMIC since we hold a
	 * write_lock (spinlock context, cannot sleep).
	 */
	lb = kmalloc(sizeof(struct lease_table), GFP_ATOMIC);
	if (!lb) {
		write_unlock(&lease_list_lock);
		return -ENOMEM;
	}

	memcpy(lb->client_guid, opinfo->conn->ClientGUID,
	       SMB2_CLIENT_GUID_SIZE);
	INIT_LIST_HEAD(&lb->lease_list);
	spin_lock_init(&lb->lb_lock);
	opinfo->o_lease->l_lb = lb;
	lease_add_list(opinfo);
	list_add_rcu(&lb->l_entry, &lease_table_list);
	write_unlock(&lease_list_lock);
	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(add_lease_global_list);

VISIBLE_IF_KUNIT
void set_oplock_level(struct oplock_info *opinfo, int level,
			     struct lease_ctx_info *lctx)
{
	switch (level) {
#ifdef CONFIG_SMB_INSECURE_SERVER
	case REQ_OPLOCK:
	case REQ_BATCHOPLOCK:
#endif
	case SMB2_OPLOCK_LEVEL_BATCH:
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		grant_write_oplock(opinfo, level, lctx);
		break;
	case SMB2_OPLOCK_LEVEL_II:
		grant_read_oplock(opinfo, lctx);
		break;
	default:
		grant_none_oplock(opinfo, lctx);
		break;
	}
}
EXPORT_SYMBOL_IF_KUNIT(set_oplock_level);

void smb_send_parent_lease_break_noti(struct ksmbd_file *fp,
				      struct lease_ctx_info *lctx)
{
#define PARENT_NOTI_BRK_BATCH	16
	struct oplock_info *opinfo;
	struct oplock_info *brk_batch[PARENT_NOTI_BRK_BATCH];
	struct ksmbd_inode *p_ci = NULL;
	int brk_cnt = 0, i;

	if (lctx->version != 2)
		return;

	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);
	if (!p_ci)
		return;

	/*
	 * Collect opinfos under the read lock, then send break notifications
	 * after releasing the lock.  oplock_break() may block up to 35 s
	 * waiting for a client ACK — holding m_lock that long would deadlock
	 * against the durable scavenger and any writer that needs m_lock.
	 */
	down_read(&p_ci->m_lock);
	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {
		struct ksmbd_conn *op_conn = opinfo->conn;

		if (op_conn == NULL || !opinfo->is_lease)
			continue;

		/* LB-04: compare lease state (__le32) with SMB2_LEASE_NONE_LE, not OPLOCK_LEVEL_NONE (__u8) */
		if (opinfo->o_lease->state != SMB2_LEASE_NONE_LE &&
		    (!(lctx->flags & SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE) ||
		     memcmp(opinfo->o_lease->lease_key,
			    lctx->parent_lease_key,
			    SMB2_LEASE_KEY_SIZE))) {
			if (!refcount_inc_not_zero(&opinfo->refcount))
				continue;

			if (ksmbd_conn_releasing(op_conn)) {
				opinfo_put(opinfo);
				continue;
			}

			if (brk_cnt < PARENT_NOTI_BRK_BATCH)
				brk_batch[brk_cnt++] = opinfo;
			else
				opinfo_put(opinfo);
		}
	}
	up_read(&p_ci->m_lock);

	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i], SMB2_OPLOCK_LEVEL_NONE, NULL);
		opinfo_put(brk_batch[i]);
	}
#undef PARENT_NOTI_BRK_BATCH

	ksmbd_inode_put(p_ci);
}

void smb_lazy_parent_lease_break_close(struct ksmbd_file *fp)
{
#define LAZY_BRK_BATCH	16
	struct oplock_info *child_opinfo;
	struct oplock_info *opinfo;
	struct oplock_info *brk_batch[LAZY_BRK_BATCH];
	struct ksmbd_inode *p_ci = NULL;
	bool has_parent_key = false;
	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];
	int brk_cnt = 0, i;

	child_opinfo = opinfo_get(fp);
	if (!child_opinfo)
		return;

	if (!child_opinfo->is_lease || child_opinfo->o_lease->version != 2) {
		opinfo_put(child_opinfo);
		return;
	}

	/*
	 * If the child has a parent lease key set, directory leases
	 * held by the same client with a matching key are exempt from
	 * the break — the client already knows the change happened.
	 */
	if (child_opinfo->o_lease->flags &
	    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE) {
		has_parent_key = true;
		memcpy(parent_lease_key,
		       child_opinfo->o_lease->parent_lease_key,
		       SMB2_LEASE_KEY_SIZE);
	}

	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);
	if (!p_ci) {
		opinfo_put(child_opinfo);
		return;
	}

	opinfo_put(child_opinfo);

	/*
	 * Collect opinfos under the read lock, then break outside it.
	 * oplock_break() may wait up to 35 s for a client ACK; holding
	 * m_lock that long deadlocks against the durable scavenger.
	 */
	down_read(&p_ci->m_lock);
	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {
		struct ksmbd_conn *op_conn = opinfo->conn;

		if (op_conn == NULL || !opinfo->is_lease)
			continue;

		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)
			continue;

		/*
		 * Skip if the child's parent lease key matches
		 * this directory lease's key.
		 */
		if (has_parent_key &&
		    !memcmp(opinfo->o_lease->lease_key,
			    parent_lease_key,
			    SMB2_LEASE_KEY_SIZE))
			continue;

		if (!refcount_inc_not_zero(&opinfo->refcount))
			continue;

		if (ksmbd_conn_releasing(op_conn)) {
			opinfo_put(opinfo);
			continue;
		}

		if (brk_cnt < LAZY_BRK_BATCH)
			brk_batch[brk_cnt++] = opinfo;
		else
			opinfo_put(opinfo);
	}
	up_read(&p_ci->m_lock);

	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i], SMB2_OPLOCK_LEVEL_NONE, NULL);
		opinfo_put(brk_batch[i]);
	}
#undef LAZY_BRK_BATCH

	ksmbd_inode_put(p_ci);
}

/**
 * ksmbd_inode_store_doc_parent_key() - record the parent lease key of the
 *     handle that set delete-on-close.
 * @fp:		ksmbd file pointer that is setting DOC
 *
 * Called when delete-on-close is set (via CREATE options or SET_INFO
 * disposition).  At deletion time, the closer's parent key is compared
 * with this stored key to determine directory lease break exemption.
 */
void ksmbd_inode_store_doc_parent_key(struct ksmbd_file *fp)
{
	struct ksmbd_inode *ci = fp->f_ci;
	struct oplock_info *opinfo;

	opinfo = opinfo_get(fp);
	if (!opinfo)
		return;

	if (opinfo->is_lease && opinfo->o_lease->version == 2 &&
	    (opinfo->o_lease->flags &
	     SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)) {
		memcpy(ci->m_doc_parent_key,
		       opinfo->o_lease->parent_lease_key,
		       SMB2_LEASE_KEY_SIZE);
		ci->m_doc_parent_key_valid = true;
	}

	opinfo_put(opinfo);
}

/**
 * smb_dirlease_break_on_delete() - break parent directory leases when a
 *     file is deleted via delete-on-close at last-handle close time.
 * @fp:		ksmbd file pointer for the file being deleted
 *
 * Per MS-SMB2, when a file is deleted and the handle that set
 * delete-on-close has the same parent lease key as the handle that
 * closes last (triggering deletion), that parent key's directory lease
 * is exempted.  When the keys differ, ALL directory leases are broken.
 */
void smb_dirlease_break_on_delete(struct ksmbd_file *fp)
{
#define DEL_BRK_BATCH	16
	struct oplock_info *child_opinfo;
	struct oplock_info *opinfo;
	struct oplock_info *brk_batch[DEL_BRK_BATCH];
	struct ksmbd_inode *ci = fp->f_ci;
	struct ksmbd_inode *p_ci = NULL;
	bool has_parent_key = false;
	bool exempt = true;
	__u8 closer_parent_key[SMB2_LEASE_KEY_SIZE];
	int brk_cnt = 0, i;

	child_opinfo = opinfo_get(fp);
	if (!child_opinfo)
		goto no_opinfo;

	if (!child_opinfo->is_lease || child_opinfo->o_lease->version != 2) {
		opinfo_put(child_opinfo);
		goto no_opinfo;
	}

	if (child_opinfo->o_lease->flags &
	    SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE) {
		has_parent_key = true;
		memcpy(closer_parent_key,
		       child_opinfo->o_lease->parent_lease_key,
		       SMB2_LEASE_KEY_SIZE);
	}

	opinfo_put(child_opinfo);

	/*
	 * Compare the closer's parent key with the DOC-setter's key.
	 * If they differ, break all directory leases (no exemption).
	 */
	if (has_parent_key && ci->m_doc_parent_key_valid) {
		if (memcmp(closer_parent_key, ci->m_doc_parent_key,
			   SMB2_LEASE_KEY_SIZE))
			exempt = false;
	} else if (!has_parent_key) {
		/* No parent key on closer → break all */
		exempt = false;
	}

	goto do_break;

no_opinfo:
	/* No lease on closer → break all directory leases */
	exempt = false;

do_break:
	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);
	if (!p_ci)
		return;

	down_read(&p_ci->m_lock);
	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {
		struct ksmbd_conn *op_conn = opinfo->conn;

		if (op_conn == NULL || !opinfo->is_lease)
			continue;

		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)
			continue;

		/*
		 * Exempt directory lease whose key matches the closer's
		 * parent key — but only when the DOC-setter's key also
		 * matches (same-key case).
		 */
		if (exempt && has_parent_key &&
		    !memcmp(opinfo->o_lease->lease_key,
			    closer_parent_key,
			    SMB2_LEASE_KEY_SIZE))
			continue;

		if (!refcount_inc_not_zero(&opinfo->refcount))
			continue;

		if (ksmbd_conn_releasing(op_conn)) {
			opinfo_put(opinfo);
			continue;
		}

		if (brk_cnt < DEL_BRK_BATCH)
			brk_batch[brk_cnt++] = opinfo;
		else
			opinfo_put(opinfo);
	}
	up_read(&p_ci->m_lock);

	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i], SMB2_OPLOCK_LEVEL_NONE, NULL);
		opinfo_put(brk_batch[i]);
	}
#undef DEL_BRK_BATCH

	ksmbd_inode_put(p_ci);
}

/**
 * smb_break_parent_dir_lease() - break directory leases on parent dir
 * @fp:		ksmbd file pointer for the child file
 *
 * Per MS-SMB2 3.3.4.7, when a child file is created, modified, renamed,
 * or deleted inside a directory, any directory lease held on that parent
 * must be broken to NONE.  Clients that supplied a matching parent lease
 * key (SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET) are exempt because they
 * already know the directory contents are changing.
 */
void smb_break_parent_dir_lease_level(struct ksmbd_file *fp, int break_level)
{
#define PARENT_DIR_BRK_BATCH	16
	struct oplock_info *child_opinfo;
	struct oplock_info *opinfo;
	struct oplock_info *brk_batch[PARENT_DIR_BRK_BATCH];
	struct ksmbd_inode *p_ci;
	bool has_parent_key = false;
	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];
	int brk_cnt = 0, i;

	if (!fp->filp || !fp->filp->f_path.dentry->d_parent)
		return;

	/*
	 * Check if the child file has a v2 lease with parent lease key set.
	 * If so, the parent directory lease held by the same client+key is
	 * exempt from the break notification.
	 */
	child_opinfo = opinfo_get(fp);
	if (child_opinfo) {
		if (child_opinfo->is_lease &&
		    child_opinfo->o_lease->version == 2 &&
		    (child_opinfo->o_lease->flags &
		     SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)) {
			has_parent_key = true;
			memcpy(parent_lease_key,
			       child_opinfo->o_lease->parent_lease_key,
			       SMB2_LEASE_KEY_SIZE);
		}
		opinfo_put(child_opinfo);
	}

	p_ci = ksmbd_inode_lookup_lock(fp->filp->f_path.dentry->d_parent);
	if (!p_ci)
		return;

	/*
	 * Collect opinfos under the read lock, then break outside it.
	 * oplock_break() may wait up to 35 s for a client ACK; holding
	 * m_lock that long deadlocks against the durable scavenger.
	 */
	down_read(&p_ci->m_lock);
	list_for_each_entry(opinfo, &p_ci->m_op_list, op_entry) {
		if (!opinfo->conn || !opinfo->is_lease)
			continue;

		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)
			continue;

		/*
		 * Per MS-SMB2 3.3.4.7, if the child's parent lease key
		 * matches this directory lease's key, skip the break.
		 * The parent key identifies the directory lease that the
		 * opener is coordinated with, regardless of which client
		 * the opener belongs to.
		 */
		if (has_parent_key &&
		    !memcmp(opinfo->o_lease->lease_key,
			    parent_lease_key,
			    SMB2_LEASE_KEY_SIZE))
			continue;

		if (!refcount_inc_not_zero(&opinfo->refcount))
			continue;

		if (ksmbd_conn_releasing(opinfo->conn)) {
			opinfo_put(opinfo);
			continue;
		}

		if (brk_cnt < PARENT_DIR_BRK_BATCH)
			brk_batch[brk_cnt++] = opinfo;
		else
			opinfo_put(opinfo);
	}
	up_read(&p_ci->m_lock);

	for (i = 0; i < brk_cnt; i++) {
		brk_batch[i]->break_reason =
			SMB2_LEASE_BREAK_REASON_PARENT_LEASE_KEY_CHANGED;
		oplock_break(brk_batch[i], break_level, NULL);
		brk_batch[i]->break_reason = SMB2_LEASE_BREAK_REASON_NONE;
		opinfo_put(brk_batch[i]);
	}
#undef PARENT_DIR_BRK_BATCH

	ksmbd_inode_put(p_ci);
}

void smb_break_parent_dir_lease(struct ksmbd_file *fp)
{
	smb_break_parent_dir_lease_level(fp, SMB2_OPLOCK_LEVEL_NONE);
}

/**
 * smb_break_dir_lease_by_dentry() - break all leases on a directory
 * @d:		dentry of the directory to break leases on
 * @fp:		ksmbd file pointer of the child (may be NULL)
 *
 * Break directory leases on the given directory.  Used for rename
 * operations to break the destination parent directory's lease.
 * If @fp has a v2 lease with a parent lease key set, directory leases
 * matching that key are exempt from the break.
 */
void smb_break_dir_lease_by_dentry_level(struct dentry *d,
					 struct ksmbd_file *fp,
					 int break_level)
{
#define DIR_DENTRY_BRK_BATCH	16
	struct oplock_info *child_opinfo;
	struct oplock_info *opinfo;
	struct oplock_info *brk_batch[DIR_DENTRY_BRK_BATCH];
	struct ksmbd_inode *ci;
	bool has_parent_key = false;
	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];
	int brk_cnt = 0, i;

	if (!d || !d_inode(d))
		return;

	if (fp) {
		child_opinfo = opinfo_get(fp);
		if (child_opinfo) {
			if (child_opinfo->is_lease &&
			    child_opinfo->o_lease->version == 2 &&
			    (child_opinfo->o_lease->flags &
			     SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)) {
				has_parent_key = true;
				memcpy(parent_lease_key,
				       child_opinfo->o_lease->parent_lease_key,
				       SMB2_LEASE_KEY_SIZE);
			}
			opinfo_put(child_opinfo);
		}
	}

	ci = ksmbd_inode_lookup_lock(d);
	if (!ci)
		return;

	down_read(&ci->m_lock);
	list_for_each_entry(opinfo, &ci->m_op_list, op_entry) {
		if (!opinfo->conn || !opinfo->is_lease)
			continue;

		if (opinfo->o_lease->state == SMB2_LEASE_NONE_LE)
			continue;

		if (has_parent_key &&
		    !memcmp(opinfo->o_lease->lease_key,
			    parent_lease_key,
			    SMB2_LEASE_KEY_SIZE))
			continue;

		if (!refcount_inc_not_zero(&opinfo->refcount))
			continue;

		if (ksmbd_conn_releasing(opinfo->conn)) {
			opinfo_put(opinfo);
			continue;
		}

		if (brk_cnt < DIR_DENTRY_BRK_BATCH)
			brk_batch[brk_cnt++] = opinfo;
		else
			opinfo_put(opinfo);
	}
	up_read(&ci->m_lock);

	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i], break_level, NULL);
		opinfo_put(brk_batch[i]);
	}
#undef DIR_DENTRY_BRK_BATCH

	ksmbd_inode_put(ci);
}

void smb_break_dir_lease_by_dentry(struct dentry *d, struct ksmbd_file *fp)
{
	smb_break_dir_lease_by_dentry_level(d, fp, SMB2_OPLOCK_LEVEL_NONE);
}

/**
 * disconnected_have_write() - check if any disconnected opinfo holds Write.
 * @ci: ksmbd inode whose opinfo list is searched
 *
 * Walk the per-inode oplock list under m_lock and return true if any entry
 * is disconnected (conn==NULL or conn releasing) AND holds Write caching
 * (lease Write bit, or a BATCH/EXCLUSIVE oplock level).
 *
 * Used by smb_grant_oplock() to decide whether to purge disconnected handles
 * before granting a new lease, or merely strip Write from the new grant.
 */
static bool disconnected_have_write(struct ksmbd_inode *ci)
{
	struct oplock_info *opinfo;
	bool found = false;

	down_read(&ci->m_lock);
	list_for_each_entry(opinfo, &ci->m_op_list, op_entry) {
		struct ksmbd_conn *conn = READ_ONCE(opinfo->conn);

		/* Skip still-connected (non-releasing) opinfos */
		if (conn && !ksmbd_conn_releasing(conn) &&
		    !ksmbd_conn_exiting(conn))
			continue;

		if (opinfo->is_lease) {
			if (opinfo->o_lease &&
			    (opinfo->o_lease->state &
			     SMB2_LEASE_WRITE_CACHING_LE)) {
				found = true;
				break;
			}
		} else {
			if (opinfo->level == SMB2_OPLOCK_LEVEL_BATCH ||
			    opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
				found = true;
				break;
			}
		}
	}
	up_read(&ci->m_lock);
	return found;
}

VISIBLE_IF_KUNIT
void ksmbd_apply_disconnected_only_lease_policy(int *req_op_level,
						struct lease_ctx_info *lctx)
{
	if (!req_op_level)
		return;

	if (!lctx) {
		if (*req_op_level != SMB2_OPLOCK_LEVEL_NONE)
			*req_op_level = SMB2_OPLOCK_LEVEL_II;
		return;
	}

	lctx->req_state &= ~SMB2_LEASE_WRITE_CACHING_LE;
	if (!(lctx->req_state & (SMB2_LEASE_READ_CACHING_LE |
				 SMB2_LEASE_HANDLE_CACHING_LE)))
		*req_op_level = SMB2_OPLOCK_LEVEL_NONE;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_apply_disconnected_only_lease_policy);

VISIBLE_IF_KUNIT
void ksmbd_apply_read_handle_lease_policy(int *req_op_level,
					  struct lease_ctx_info *lctx)
{
	if (!req_op_level || !lctx)
		return;

	lctx->req_state &= SMB2_LEASE_READ_CACHING_LE |
			   SMB2_LEASE_HANDLE_CACHING_LE;
	if (!lctx->req_state) {
		*req_op_level = SMB2_OPLOCK_LEVEL_NONE;
		return;
	}

	*req_op_level = SMB2_OPLOCK_LEVEL_II;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_apply_read_handle_lease_policy);

VISIBLE_IF_KUNIT
bool ksmbd_is_strict_stat_open(const struct ksmbd_file *fp)
{
	return fp && fp->attrib_only &&
	       !(fp->daccess & FILE_READ_CONTROL_LE);
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_is_strict_stat_open);

/**
 * smb_grant_oplock() - handle oplock/lease request on file open
 * @work:		smb work
 * @req_op_level:	oplock level
 * @pid:		id of open file
 * @fp:			ksmbd file pointer
 * @tid:		Tree id of connection
 * @lctx:		lease context information on file open
 * @share_ret:		share mode
 *
 * Return:      0 on success, otherwise error
 */
int smb_grant_oplock(struct ksmbd_work *work, int req_op_level, u64 pid,
		     struct ksmbd_file *fp, __u16 tid,
		     struct lease_ctx_info *lctx, int share_ret)
{
	struct ksmbd_session *sess = work->sess;
	int err = 0;
	struct oplock_info *opinfo = NULL, *prev_opinfo = NULL;
	struct ksmbd_inode *ci = fp->f_ci;
	bool prev_op_has_lease = false;
	bool disconnected_only = false;
	__le32 prev_op_state = 0;

	/* Only v2 leases handle the directory */
	if (S_ISDIR(file_inode(fp->filp)->i_mode)) {
		if (!lctx || lctx->version != 2)
			return 0;
	}

	opinfo = alloc_opinfo(work, pid, tid);
	if (!opinfo)
		return -ENOMEM;

	if (lctx) {
		err = alloc_lease(opinfo, lctx);
		if (err)
			goto err_out;
		opinfo->is_lease = 1;
	}

	/* ci does not have any oplock */
	if (!opinfo_count(fp)) {
		if (share_ret < 0) {
			err = share_ret;
			goto err_out;
		}
		goto set_lev;
	}

	/*
	 * Stat-only opens (attrib_only) without a lease context must not
	 * trigger oplock breaks: they do not perform data I/O and the client
	 * never holds a competing cache.  Force NONE level so the open goes
	 * directly to set_lev without disturbing any existing oplock holder.
	 *
	 * However, for plain oplocks (no lease), READ_CONTROL access must
	 * still break the oplock — oplock.statopen1 expects this per
	 * MS-SMB2 §3.3.5.9 (READ_CONTROL is not in the strict stat-open
	 * set for oplock purposes).  Leases are more permissive and treat
	 * READ_CONTROL as a stat open (lease.statopen4).
	 *
	 * Stat opens WITH a lease context (lctx != NULL) skip this early
	 * return and participate in the lease table so they can join an
	 * existing same-client lease (MS-SMB2 §3.3.5.9.8).
	 */
	if (ksmbd_is_strict_stat_open(fp) && !lctx &&
	    fp->cdoption != FILE_OVERWRITE_IF_LE &&
	    fp->cdoption != FILE_OVERWRITE_LE &&
	    fp->cdoption != FILE_SUPERSEDE_LE) {
		req_op_level = SMB2_OPLOCK_LEVEL_NONE;
		goto set_lev;
	}

	if (lctx) {
		struct oplock_info *m_opinfo;

		/* is lease already granted ? */
		m_opinfo = same_client_has_lease(ci, sess->ClientGUID,
						 lctx);
		if (m_opinfo) {
			copy_lease(m_opinfo, opinfo);
			/*
			 * same_client_has_lease() has already performed the
			 * correct upgrade/downgrade logic: it upgrades the
			 * shared lease state when req_state is a strict
			 * superset, and leaves it unchanged otherwise (no
			 * downgrade).  copy_lease() then copies the result.
			 * Do NOT apply &= req_state here: that would
			 * incorrectly strip bits from the existing grant
			 * (e.g. RH & RW = R, losing Handle caching).
			 */
			if (atomic_read(&m_opinfo->breaking_cnt))
				opinfo->o_lease->flags =
					SMB2_LEASE_FLAG_BREAK_IN_PROGRESS_LE;
			goto out;
		}
	}
	prev_opinfo = opinfo_get_list(ci);
	if (!prev_opinfo) {
		/*
		 * opinfo_get_list() skips disconnected opinfos (conn==NULL or
		 * conn releasing).  If opinfo_count > 0, all remaining opinfos
		 * are disconnected durable handles.
		 *
		 * Decision table:
		 *
		 * A. Sharing conflict (share_ret < 0):
		 *    A disconnected handle is blocking the new open due to
		 *    incompatible share mode.  Purge all disconnected handles
		 *    (they can't ack a break or reduce their access), then
		 *    re-evaluate sharing.  After a successful purge the new
		 *    open can proceed as if no other handles exist.
		 *
		 * B. Disconnected handle holds Write caching (W):
		 *    The disconnected holder cannot ack a Write-break, so its
		 *    Write lease is stale.  Purge it; the new opener then gets
		 *    the full requested lease without interference.
		 *
		 * C. Disconnected handle holds only Read+Handle (RH, no W):
		 *    The handle is still valid for reconnect — the reconnecting
		 *    client will re-establish its caching state.  Keep it, but
		 *    strip Write from the new grant so we never have two
		 *    independent writers on the same file.
		 */
		if (opinfo_count(fp) > 0) {
			bool disconnected_write = disconnected_have_write(ci);
			/*
			 * Purge disconnected handles when:
			 *  - sharing conflict (share_ret < 0), OR
			 *  - disconnected Write caching (batch/exclusive
			 *    oplock or Write lease).  A disconnected client
			 *    cannot ACK a break, so its Write caching is
			 *    stale regardless of whether the new opener uses
			 *    leases or oplocks.
			 */
			bool do_purge = (share_ret < 0) || disconnected_write;

			if (do_purge) {
				ksmbd_purge_disconnected_fp(ci);
				/* Re-check sharing after purge */
				if (share_ret < 0) {
					share_ret = ksmbd_smb_check_shared_mode(
							fp->filp, fp);
					if (share_ret < 0) {
						err = share_ret;
						goto err_out;
					}
				}
				/* If all disconnected handles were purged,
				 * grant the full requested level freely. */
				if (!opinfo_count(fp))
					goto set_lev;
			}
			/*
			 * Case C: keep disconnected RH handles. The new open
			 * must not gain independent Write caching, but Handle
			 * caching remains valid for coordinated reconnect.
			 */
			disconnected_only = true;
			ksmbd_apply_disconnected_only_lease_policy(&req_op_level,
								 lctx);
			goto op_break_not_needed;
		}
		goto set_lev;
	}

	/*
	 * Existing oplock at NONE level + new lease request:
	 *
	 * Non-lease NONE opens:
	 *   - Stat-only opens (attrib_only) don't conflict with caching
	 *     at all — grant the full requested lease.
	 *   - Other non-lease opens at NONE: strip Write caching (another
	 *     handle is doing data I/O) but allow Read+Handle.
	 *
	 * Lease NONE opens (lease downgraded to NONE after a break, or
	 * opened with NONE state from the start):
	 *   - same_client_has_lease() above already handled the same-key
	 *     case.  Here we have a DIFFERENT-key opener.  A different-key
	 *     open — even with NONE state — still represents an uncoordinated
	 *     file handle.  Write caching must be stripped (fall through to
	 *     op_break_not_needed which sets req_op_level = LEVEL_II and
	 *     grant_read_oplock() grants at most RH).
	 */
	if (prev_opinfo->level == SMB2_OPLOCK_LEVEL_NONE &&
	    !prev_opinfo->is_lease && lctx) {
		if (ksmbd_is_strict_stat_open(prev_opinfo->o_fp)) {
			opinfo_put(prev_opinfo);
			goto set_lev;
		}
		/*
		 * Existing non-lease NONE open (not stat-only) still blocks
		 * Write caching, but Read+Handle caching remain valid.  This
		 * is the durable-open "nonstat-and-lease" case from Samba:
		 * a plain opener forces RWH -> RH, not lease NONE.
		 */
		opinfo_put(prev_opinfo);
		ksmbd_apply_read_handle_lease_policy(&req_op_level, lctx);
		goto set_lev;
	}
	prev_op_has_lease = prev_opinfo->is_lease;
	if (prev_op_has_lease)
		prev_op_state = prev_opinfo->o_lease->state;

	/*
	 * Stat-open (attrib_only) against an existing lease holder:
	 * READ_CONTROL opens are stat opens for lease purposes (see
	 * lease.statopen4) but NOT for oplock purposes (oplock.statopen1).
	 * The early shortcut above excludes READ_CONTROL from the oplock
	 * fast path, so READ_CONTROL opens reach here.  If the existing
	 * holder is a lease, grant NONE without breaking — it's still a
	 * stat open from the lease perspective.
	 */
	if (fp->attrib_only && !lctx && prev_op_has_lease &&
	    share_ret >= 0) {
		opinfo_put(prev_opinfo);
		req_op_level = SMB2_OPLOCK_LEVEL_NONE;
		goto set_lev;
	}

	if (share_ret < 0 &&
	    prev_opinfo->level == SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
		err = share_ret;
		opinfo_put(prev_opinfo);
		goto err_out;
	}

	if (prev_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH &&
	    prev_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
		/*
		 * Directory leases with Handle caching (RH) need a
		 * Handle break (RH -> R) when there is a sharing
		 * violation.  The oplock level is LEVEL_II but the
		 * lease state still holds Handle caching that must
		 * be broken.
		 */
		if (share_ret < 0 && prev_op_has_lease &&
		    (prev_op_state & SMB2_LEASE_HANDLE_CACHING_LE)) {
			/*
			 * MS-SMB2 §3.3.5.9: sharing violation with Handle
			 * lease — send STATUS_PENDING, break Handle, and
			 * block until the holder closes or ACKs.  The
			 * normal Handle-break path is non-blocking, but
			 * sharing violations require waiting so the
			 * conflict can be re-evaluated after the break.
			 */
				if (work && !work->asynchronous) {
					setup_async_work(work, NULL, NULL);
					smb2_send_interim_resp(work,
							       STATUS_PENDING);
				}
			err = oplock_break(prev_opinfo,
					   OPLOCK_BREAK_HANDLE_CACHING,
					   work);
			/*
			 * oplock_break() returns immediately for Handle-
			 * only breaks (nowait_ack).  Wait here for the
			 * client to ACK or close — up to 35 seconds.
			 */
			if (!err)
				wait_for_break_ack(prev_opinfo);
			opinfo_put(prev_opinfo);
			if (err == -ENOENT)
				goto set_lev;
			else if (err < 0)
				goto err_out;
			goto op_break_not_needed;
		}
		opinfo_put(prev_opinfo);
		goto op_break_not_needed;
	}

	if (prev_opinfo->is_lease && lctx) {
		if (share_ret < 0) {
			/*
			 * Sharing violation with lease: break Handle
			 * caching (RWH->RW) and block until the holder
			 * ACKs or closes.  Per MS-SMB2 §3.3.5.9, the
			 * server must wait before returning the sharing
			 * violation or re-evaluating.
			 */
				if (work &&
				    !(prev_op_state & SMB2_LEASE_WRITE_CACHING_LE) &&
				    !work->asynchronous) {
					setup_async_work(work, NULL, NULL);
					smb2_send_interim_resp(work,
							       STATUS_PENDING);
				}
			err = oplock_break(prev_opinfo,
					   OPLOCK_BREAK_HANDLE_CACHING, work);
			if (!err && !(prev_op_state &
				      SMB2_LEASE_WRITE_CACHING_LE))
				wait_for_break_ack(prev_opinfo);
			opinfo_put(prev_opinfo);
			if (err == -ENOENT)
				goto set_lev;
			else if (err < 0)
				goto err_out;
			goto op_break_not_needed;
		}
		/*
		 * Successful open: break Write caching only (RWH->RH,
		 * RW->R).  Handle caching is NOT broken on open; it
		 * is only broken by rename or delete operations.
		 * MS-SMB2 3.3.5.9.8
		 */
		err = oplock_break(prev_opinfo,
				   SMB2_OPLOCK_LEVEL_II, work);
		opinfo_put(prev_opinfo);
		if (err == -ENOENT)
			goto set_lev;
		else if (err < 0)
			goto err_out;
	} else {
		/*
		 * Non-lease new opener (or non-lease existing holder):
		 * For sharing violations with an existing lease holder,
		 * break Handle caching only (RWH->RW, 0x7->0x5) per
		 * MS-SMB2 §3.3.5.9.8.  Without a violation, strip Write
		 * only (RWH->RH) via LEVEL_II.
		 */
		int break_level = (share_ret < 0 && prev_op_has_lease) ?
			OPLOCK_BREAK_HANDLE_CACHING : SMB2_OPLOCK_LEVEL_II;
			if (share_ret < 0 && prev_op_has_lease &&
			    !(prev_op_state & SMB2_LEASE_WRITE_CACHING_LE) &&
			    work && !work->asynchronous) {
				setup_async_work(work, NULL, NULL);
				smb2_send_interim_resp(work, STATUS_PENDING);
			}
		err = oplock_break(prev_opinfo, break_level, work);
		if (!err && share_ret < 0 && prev_op_has_lease &&
		    !(prev_op_state & SMB2_LEASE_WRITE_CACHING_LE))
			wait_for_break_ack(prev_opinfo);
		opinfo_put(prev_opinfo);
		if (err == -ENOENT)
			goto set_lev;
		else if (err < 0)
			goto err_out;
	}

op_break_not_needed:
	if (share_ret < 0) {
		/*
		 * Re-evaluate sharing after the lease break.  The holder
		 * may have closed its handle in response to the Handle
		 * break, resolving the conflict (MS-SMB2 §3.3.5.9).
		 */
		share_ret = ksmbd_smb_check_shared_mode(fp->filp, fp);
		if (share_ret < 0) {
			err = share_ret;
			goto err_out;
		}
	}

	if (req_op_level != SMB2_OPLOCK_LEVEL_NONE)
		req_op_level = SMB2_OPLOCK_LEVEL_II;

	/* grant fixed oplock on stacked locking between lease and oplock */
	if (prev_op_has_lease && !lctx)
		if (prev_op_state & SMB2_LEASE_HANDLE_CACHING_LE)
			req_op_level = SMB2_OPLOCK_LEVEL_NONE;

	if (!prev_op_has_lease && lctx && !disconnected_only) {
		/*
		 * Existing non-lease open (oplock holder): strip both
		 * Write and Handle caching.  The existing oplock holder
		 * doesn't participate in the Handle break protocol, so
		 * Handle caching can't be coordinated.  Write caching
		 * is unsafe because the other handle may do data I/O.
		 * Only Read caching is safe to grant.
		 */
		req_op_level = SMB2_OPLOCK_LEVEL_II;
		lctx->req_state &= SMB2_LEASE_READ_CACHING_LE;
		if (!lctx->req_state)
			req_op_level = SMB2_OPLOCK_LEVEL_NONE;
	}

set_lev:
	set_oplock_level(opinfo, req_op_level, lctx);

out:
	rcu_assign_pointer(fp->f_opinfo, opinfo);
	opinfo->o_fp = fp;

	opinfo_count_inc(fp);
	opinfo_add(opinfo);
	if (opinfo->is_lease) {
		err = add_lease_global_list(opinfo);
		if (err)
			goto err_out_registered;
	}

	/* Register a kernel VFS lease for local process coordination */
	ksmbd_set_kernel_lease(opinfo);

	return 0;
err_out_registered:
	/*
	 * Undo the registration that happened above: remove from the
	 * per-inode oplock list, clear the fp back-pointer, and
	 * decrement the opinfo count.  Without this, free_opinfo()
	 * would leave dangling references that later cause a
	 * refcount_t underflow ("decrement hit 0; leaking memory")
	 * when close_id_del_oplock() runs.
	 */
	opinfo_del(opinfo);
	rcu_assign_pointer(fp->f_opinfo, NULL);
	opinfo_count_dec(fp);
err_out:
	free_opinfo(opinfo);
	return err;
}

/**
 * smb_break_all_write_oplock() - break batch/exclusive oplock to level2
 * @work:	smb work
 * @fp:		ksmbd file pointer
 * @is_trunc:	truncate on open
 */
static void smb_break_all_write_oplock(struct ksmbd_work *work,
				       struct ksmbd_file *fp, int is_trunc)
{
	struct oplock_info *brk_opinfo;

	brk_opinfo = opinfo_get_list(fp->f_ci);
	if (!brk_opinfo)
		return;
	if (brk_opinfo->level != SMB2_OPLOCK_LEVEL_BATCH &&
	    brk_opinfo->level != SMB2_OPLOCK_LEVEL_EXCLUSIVE) {
		opinfo_put(brk_opinfo);
		return;
	}

	brk_opinfo->open_trunc = is_trunc;
	oplock_break(brk_opinfo, SMB2_OPLOCK_LEVEL_II, work);
	opinfo_put(brk_opinfo);
}

/**
 * smb_break_all_levII_oplock() - send level2 oplock or read lease break command
 *	from server to client
 * @work:	smb work
 * @fp:		ksmbd file pointer
 * @is_trunc:	truncate on open
 */
void smb_break_all_levII_oplock(struct ksmbd_work *work, struct ksmbd_file *fp,
				int is_trunc)
{
#define LEVII_BRK_BATCH	64
	struct oplock_info *op, *brk_op;
	struct oplock_info *brk_batch[LEVII_BRK_BATCH];
	struct ksmbd_inode *ci;
	struct ksmbd_conn *conn = work->conn;
	int i, brk_cnt;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_OPLOCKS))
		return;

	ci = fp->f_ci;
	op = opinfo_get(fp);

	/*
	 * Collect oplocks to break while holding the lock, then release
	 * the lock before sending break notifications to avoid deadlock.
	 * Each collected entry holds a reference from refcount_inc_not_zero.
	 */
	brk_cnt = 0;
	down_read(&ci->m_lock);
	list_for_each_entry(brk_op, &ci->m_op_list, op_entry) {
		if (brk_op->conn == NULL)
			continue;

		if (!refcount_inc_not_zero(&brk_op->refcount))
			continue;

		if (ksmbd_conn_releasing(brk_op->conn)) {
			opinfo_put(brk_op);
			continue;
		}

#ifdef CONFIG_SMB_INSECURE_SERVER
		if (brk_op->is_smb2) {
			/*
			 * C.8: Use LEASE_RH_MASK to check for unexpected
			 * caching bits (Write caching etc.) in the lease
			 * state, avoiding false positives from extra flags.
			 */
			if (brk_op->is_lease &&
			    (brk_op->o_lease->state & ~LEASE_RH_MASK)) {
				ksmbd_debug(OPLOCK,
					    "unexpected lease state(0x%x)\n",
					    brk_op->o_lease->state);
				goto next;
			} else if (brk_op->level !=
					SMB2_OPLOCK_LEVEL_II) {
				ksmbd_debug(OPLOCK, "unexpected oplock(0x%x)\n",
					    brk_op->level);
				goto next;
			}

			/* Skip oplock being break to none */
			if (brk_op->is_lease &&
			    brk_op->o_lease->new_state == SMB2_LEASE_NONE_LE &&
			    atomic_read(&brk_op->breaking_cnt))
				goto next;
		} else {
			if (brk_op->level != OPLOCK_READ) {
				ksmbd_debug(OPLOCK, "unexpected oplock(0x%x)\n",
					    brk_op->level);
				goto next;
			}
		}
#else
		/*
		 * C.8: Use LEASE_RH_MASK to check for unexpected caching bits
		 * in the lease state.  The mask covers Read and Handle caching;
		 * any other bits (e.g. Write caching) indicate an unexpected
		 * state for a level-II break candidate.
		 */
		if (brk_op->is_lease &&
		    (brk_op->o_lease->state & ~LEASE_RH_MASK)) {
			ksmbd_debug(OPLOCK, "unexpected lease state(0x%x)\n",
				    brk_op->o_lease->state);
			goto next;
		} else if (brk_op->level != SMB2_OPLOCK_LEVEL_II) {
			ksmbd_debug(OPLOCK, "unexpected oplock(0x%x)\n",
				    brk_op->level);
			goto next;
		}

		/* Skip oplock being break to none */
		if (brk_op->is_lease &&
		    brk_op->o_lease->new_state == SMB2_LEASE_NONE_LE &&
		    atomic_read(&brk_op->breaking_cnt))
			goto next;
#endif

		if (op && op->is_lease && brk_op->is_lease &&
		    !memcmp(conn->ClientGUID, brk_op->conn->ClientGUID,
			    SMB2_CLIENT_GUID_SIZE) &&
		    !memcmp(op->o_lease->lease_key, brk_op->o_lease->lease_key,
			    SMB2_LEASE_KEY_SIZE))
			goto next;

		/*
		 * MS-SMB2 §3.3.4.7: a lease is identified by
		 * (ClientGuid, LeaseKey).  Only send one break
		 * notification per logical lease — skip opinfos
		 * that share a lease key with one already collected.
		 */
		if (brk_op->is_lease) {
			int dup = 0, j;

			for (j = 0; j < brk_cnt; j++) {
				if (!brk_batch[j]->is_lease)
					continue;
				if (!memcmp(brk_op->conn->ClientGUID,
					    brk_batch[j]->conn->ClientGUID,
					    SMB2_CLIENT_GUID_SIZE) &&
				    !memcmp(brk_op->o_lease->lease_key,
					    brk_batch[j]->o_lease->lease_key,
					    SMB2_LEASE_KEY_SIZE)) {
					dup = 1;
					break;
				}
			}
			if (dup)
				goto next;
		}

		brk_op->open_trunc = is_trunc;
		if (brk_cnt < LEVII_BRK_BATCH) {
			brk_batch[brk_cnt++] = brk_op;
			/* keep the reference for use after lock release */
			continue;
		}
		/* Overflow: drop this one; will be handled on next call */
		opinfo_put(brk_op);
		continue;
next:
		opinfo_put(brk_op);
	}
	up_read(&ci->m_lock);

	/* Send break notifications without holding ci->m_lock */
	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i], SMB2_OPLOCK_LEVEL_NONE, work);
		opinfo_put(brk_batch[i]);
	}

	/*
	 * Purge any disconnected durable handles on this inode.
	 *
	 * A disconnected durable handle can't receive or acknowledge a
	 * lease break (its conn is NULL).  Per MS-SMB2 §3.3.4.6, if a
	 * break cannot be delivered, the server must revoke the lease
	 * and close the handle so future reconnect attempts fail.
	 *
	 * This is called after the break loop (no locks held) once the
	 * session teardown for the disconnected client has had time to
	 * complete (e.g. the triggering write arrived after a full SMB2
	 * round-trip on another transport).
	 */
	ksmbd_purge_disconnected_fp(ci);

	if (op)
		opinfo_put(op);
#undef LEVII_BRK_BATCH
}

/**
 * smb_break_all_oplock() - break both batch/exclusive and level2 oplock
 * @work:	smb work
 * @fp:		ksmbd file pointer
 */
void smb_break_all_oplock(struct ksmbd_work *work, struct ksmbd_file *fp)
{
	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_OPLOCKS))
		return;

	smb_break_all_write_oplock(work, fp, 1);
	smb_break_all_levII_oplock(work, fp, 1);
}

/**
 * smb_break_all_handle_lease() - break Handle caching on all leases for an inode
 * @work:	smb work
 * @fp:		ksmbd file pointer (caller's own handle)
 * @wait:	if true, block until each client ACKs or times out
 */
void smb_break_all_handle_lease(struct ksmbd_work *work, struct ksmbd_file *fp,
				bool wait)
{
#define HANDLE_BRK_BATCH	64
	struct oplock_info *brk_op;
	struct oplock_info *brk_batch[HANDLE_BRK_BATCH];
	struct ksmbd_inode *ci;
	int i, brk_cnt;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_OPLOCKS))
		return;

	ci = fp->f_ci;

	ksmbd_debug(OPLOCK,
		    "handle lease break: scanning inode %p op_list\n", ci);
	brk_cnt = 0;
	down_read(&ci->m_lock);
	list_for_each_entry(brk_op, &ci->m_op_list, op_entry) {
		ksmbd_debug(OPLOCK,
			    "  op_entry: conn=%p is_lease=%d state=0x%x\n",
			    brk_op->conn, brk_op->is_lease,
			    brk_op->is_lease ?
			    le32_to_cpu(brk_op->o_lease->state) : 0);
		if (!brk_op->conn || !brk_op->is_lease)
			continue;
		if (!(brk_op->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE))
			continue;
		if (!refcount_inc_not_zero(&brk_op->refcount))
			continue;
		if (ksmbd_conn_releasing(brk_op->conn)) {
			opinfo_put(brk_op);
			continue;
		}
		/*
		 * MS-SMB2 §3.3.5.21.1: Skip the caller's own open.
		 * The initiating handle already knows about the rename
		 * or delete, so it does not need a break notification.
		 * Only OTHER opens on the same file need the Handle
		 * caching break.
		 */
		if (brk_op->o_fp == fp) {
			opinfo_put(brk_op);
			continue;
		}

		/*
		 * Deduplicate by lease key: only one break notification
		 * per (ClientGuid, LeaseKey) per MS-SMB2 §3.3.4.7.
		 */
		{
			int dup = 0, j;

			for (j = 0; j < brk_cnt; j++) {
				if (!memcmp(brk_op->conn->ClientGUID,
					    brk_batch[j]->conn->ClientGUID,
					    SMB2_CLIENT_GUID_SIZE) &&
				    !memcmp(brk_op->o_lease->lease_key,
					    brk_batch[j]->o_lease->lease_key,
					    SMB2_LEASE_KEY_SIZE)) {
					dup = 1;
					break;
				}
			}
			if (dup) {
				opinfo_put(brk_op);
				continue;
			}
		}

		if (brk_cnt < HANDLE_BRK_BATCH) {
			brk_batch[brk_cnt++] = brk_op;
			continue;
		}
		opinfo_put(brk_op);
	}
	up_read(&ci->m_lock);

	ksmbd_debug(OPLOCK,
		    "handle lease break: found %d leases to break\n", brk_cnt);
	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i],
			     wait ? OPLOCK_BREAK_HANDLE_CACHING_WAIT
				  : OPLOCK_BREAK_HANDLE_CACHING,
			     NULL);
		opinfo_put(brk_batch[i]);
	}

	/*
	 * Purge disconnected durable handles that hold Handle caching leases.
	 * A disconnected durable can't receive or acknowledge a Handle caching
	 * break (its conn is NULL), so per MS-SMB2 §3.3.4.6 the server must
	 * revoke the lease and close the handle.  Rename and delete operations
	 * trigger Handle breaks, so this is the right place to clean them up.
	 */
	ksmbd_purge_disconnected_fp(ci);
#undef HANDLE_BRK_BATCH
}

/**
 * smb_break_target_handle_lease() - break Handle caching on ALL leases for
 *     an inode (used for rename/delete targets where we don't skip any handle).
 * @work:	smb work
 * @ci:		ksmbd_inode of the target file
 */
void smb_break_target_handle_lease(struct ksmbd_work *work,
				   struct ksmbd_inode *ci)
{
#define TARGET_BRK_BATCH 64
	struct oplock_info *brk_op;
	struct oplock_info *brk_batch[TARGET_BRK_BATCH];
	int i, brk_cnt = 0;

	if (!test_share_config_flag(work->tcon->share_conf,
				    KSMBD_SHARE_FLAG_OPLOCKS))
		return;

	down_read(&ci->m_lock);
	list_for_each_entry(brk_op, &ci->m_op_list, op_entry) {
		if (!brk_op->conn || !brk_op->is_lease)
			continue;
		if (!(brk_op->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE))
			continue;
		if (!refcount_inc_not_zero(&brk_op->refcount))
			continue;
		if (ksmbd_conn_releasing(brk_op->conn)) {
			opinfo_put(brk_op);
			continue;
		}
		/* No skip — break ALL handles, including the target's own */

		/*
		 * Deduplicate by lease key: only one break per
		 * (ClientGuid, LeaseKey) per MS-SMB2 §3.3.4.7.
		 */
		{
			int dup = 0, j;

			for (j = 0; j < brk_cnt; j++) {
				if (!memcmp(brk_op->conn->ClientGUID,
					    brk_batch[j]->conn->ClientGUID,
					    SMB2_CLIENT_GUID_SIZE) &&
				    !memcmp(brk_op->o_lease->lease_key,
					    brk_batch[j]->o_lease->lease_key,
					    SMB2_LEASE_KEY_SIZE)) {
					dup = 1;
					break;
				}
			}
			if (dup) {
				opinfo_put(brk_op);
				continue;
			}
		}

		if (brk_cnt < TARGET_BRK_BATCH)
			brk_batch[brk_cnt++] = brk_op;
		else
			opinfo_put(brk_op);
	}
	up_read(&ci->m_lock);

	for (i = 0; i < brk_cnt; i++) {
		oplock_break(brk_batch[i], OPLOCK_BREAK_HANDLE_CACHING_WAIT,
			     NULL);
		opinfo_put(brk_batch[i]);
	}

	ksmbd_purge_disconnected_fp(ci);
#undef TARGET_BRK_BATCH
}

/**
 * smb2_map_lease_to_oplock() - map lease state to corresponding oplock type
 * @lease_state:     lease type
 *
 * Return:      0 if no mapping, otherwise corresponding oplock type
 */
__u8 smb2_map_lease_to_oplock(__le32 lease_state)
{
	if (lease_state == (SMB2_LEASE_HANDLE_CACHING_LE |
			    SMB2_LEASE_READ_CACHING_LE |
			    SMB2_LEASE_WRITE_CACHING_LE)) {
		return SMB2_OPLOCK_LEVEL_BATCH;
	} else if (lease_state != SMB2_LEASE_WRITE_CACHING_LE &&
		 lease_state & SMB2_LEASE_WRITE_CACHING_LE) {
		if (!(lease_state & SMB2_LEASE_HANDLE_CACHING_LE))
			return SMB2_OPLOCK_LEVEL_EXCLUSIVE;
	} else if (lease_state & SMB2_LEASE_READ_CACHING_LE) {
		return SMB2_OPLOCK_LEVEL_II;
	}
	return 0;
}

/**
 * create_lease_buf() - create lease context for open cmd response
 * @rbuf:	buffer to create lease context response
 * @lease:	buffer to stored parsed lease state information
 */
void create_lease_buf(u8 *rbuf, struct lease *lease)
{
	if (lease->version == 2) {
		struct create_lease_v2 *buf = (struct create_lease_v2 *)rbuf;

		memset(buf, 0, sizeof(struct create_lease_v2));
		memcpy(buf->lcontext.LeaseKey, lease->lease_key,
		       SMB2_LEASE_KEY_SIZE);
		buf->lcontext.LeaseFlags = lease->flags;
		buf->lcontext.Epoch = cpu_to_le16(lease->epoch);
		buf->lcontext.LeaseState = lease->state;
		if (lease->flags == SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)
			memcpy(buf->lcontext.ParentLeaseKey, lease->parent_lease_key,
			       SMB2_LEASE_KEY_SIZE);
		buf->ccontext.DataOffset = cpu_to_le16(offsetof
				(struct create_lease_v2, lcontext));
		buf->ccontext.DataLength = cpu_to_le32(sizeof(struct lease_context_v2));
		buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_lease_v2, Name));
		buf->ccontext.NameLength = cpu_to_le16(4);
		buf->Name[0] = 'R';
		buf->Name[1] = 'q';
		buf->Name[2] = 'L';
		buf->Name[3] = 's';
	} else {
		struct create_lease *buf = (struct create_lease *)rbuf;

		memset(buf, 0, sizeof(struct create_lease));
		memcpy(buf->lcontext.LeaseKey, lease->lease_key, SMB2_LEASE_KEY_SIZE);
		buf->lcontext.LeaseFlags = lease->flags;
		buf->lcontext.LeaseState = lease->state;
		buf->ccontext.DataOffset = cpu_to_le16(offsetof
				(struct create_lease, lcontext));
		buf->ccontext.DataLength = cpu_to_le32(sizeof(struct lease_context));
		buf->ccontext.NameOffset = cpu_to_le16(offsetof
				(struct create_lease, Name));
		buf->ccontext.NameLength = cpu_to_le16(4);
		buf->Name[0] = 'R';
		buf->Name[1] = 'q';
		buf->Name[2] = 'L';
		buf->Name[3] = 's';
	}
}

/**
 * parse_lease_state() - parse lease context contained in file open request
 * @open_req:	buffer containing smb2 file open(create) request
 * @is_dir:	whether leasing file is directory
 *
 * Return: allocated lease context object on success, otherwise NULL
 */
struct lease_ctx_info *parse_lease_state(void *open_req)
{
	struct create_context *cc;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;
	struct lease_ctx_info *lreq;

	cc = smb2_find_context_vals(req, SMB2_CREATE_REQUEST_LEASE, 4);
	if (IS_ERR_OR_NULL(cc))
		return NULL;

	lreq = kzalloc(sizeof(struct lease_ctx_info), KSMBD_DEFAULT_GFP);
	if (!lreq)
		return NULL;

	if (sizeof(struct lease_context_v2) == le32_to_cpu(cc->DataLength)) {
		struct create_lease_v2 *lc = (struct create_lease_v2 *)cc;

		if (le16_to_cpu(cc->DataOffset) + le32_to_cpu(cc->DataLength) <
		    sizeof(struct create_lease_v2) - 4)
			goto err_out;

		memcpy(lreq->lease_key, lc->lcontext.LeaseKey, SMB2_LEASE_KEY_SIZE);
		lreq->req_state = lc->lcontext.LeaseState;
		lreq->flags = lc->lcontext.LeaseFlags;
		lreq->epoch = lc->lcontext.Epoch;
		lreq->duration = lc->lcontext.LeaseDuration;
		if (lreq->flags == SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET_LE)
			memcpy(lreq->parent_lease_key, lc->lcontext.ParentLeaseKey,
			       SMB2_LEASE_KEY_SIZE);
		lreq->version = 2;
	} else {
		struct create_lease *lc = (struct create_lease *)cc;

		if (le16_to_cpu(cc->DataOffset) + le32_to_cpu(cc->DataLength) <
		    sizeof(struct create_lease))
			goto err_out;

		memcpy(lreq->lease_key, lc->lcontext.LeaseKey, SMB2_LEASE_KEY_SIZE);
		lreq->req_state = lc->lcontext.LeaseState;
		lreq->flags = lc->lcontext.LeaseFlags;
		lreq->duration = lc->lcontext.LeaseDuration;
		lreq->version = 1;
	}
	return lreq;
err_out:
	kfree(lreq);
	return NULL;
}

/**
 * smb2_find_context_vals() - find a particular context info in open request
 * @open_req:	buffer containing smb2 file open(create) request
 * @tag:	context name to search for
 * @tag_len:	the length of tag
 *
 * Return:	pointer to requested context, NULL if @str context not found
 *		or error pointer if name length is invalid.
 */
struct create_context *smb2_find_context_vals(void *open_req, const char *tag, int tag_len)
{
	struct create_context *cc;
	unsigned int next = 0;
	char *name;
	struct smb2_create_req *req = (struct smb2_create_req *)open_req;
	unsigned int remain_len, name_off, name_len, value_off, value_len,
		     cc_len;

	/*
	 * CreateContextsOffset and CreateContextsLength are guaranteed to
	 * be valid because of ksmbd_smb2_check_message().
	 */
	cc = (struct create_context *)((char *)req +
				       le32_to_cpu(req->CreateContextsOffset));
	remain_len = le32_to_cpu(req->CreateContextsLength);
	do {
		cc = (struct create_context *)((char *)cc + next);
		if (remain_len < offsetof(struct create_context, Buffer))
			return ERR_PTR(-EINVAL);

		next = le32_to_cpu(cc->Next);
		name_off = le16_to_cpu(cc->NameOffset);
		name_len = le16_to_cpu(cc->NameLength);
		value_off = le16_to_cpu(cc->DataOffset);
		value_len = le32_to_cpu(cc->DataLength);
		cc_len = next ? next : remain_len;

		if ((next & 0x7) != 0 ||
		    next > remain_len ||
		    name_off != offsetof(struct create_context, Buffer) ||
		    name_len < 4 ||
		    name_off + name_len > cc_len ||
		    (value_off & 0x7) != 0 ||
		    (value_len && value_off < name_off + (name_len < 8 ? 8 : name_len)) ||
		    ((u64)value_off + value_len > cc_len))
			return ERR_PTR(-EINVAL);

		name = (char *)cc + name_off;
		if (name_len == tag_len && !memcmp(name, tag, name_len))
			return cc;

		remain_len -= next;
	} while (next != 0);

	return NULL;
}

/**
 * create_durable_rsp_buf() - create durable handle context
 * @cc:	buffer to create durable context response
 */
void create_durable_rsp_buf(char *cc)
{
	struct create_durable_rsp *buf;

	buf = (struct create_durable_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Data));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE is "DHnQ" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = 'n';
	buf->Name[3] = 'Q';
}

/**
 * create_durable_v2_rsp_buf() - create durable handle v2 context
 * @cc:	buffer to create durable context response
 * @fp: ksmbd file pointer
 */
void create_durable_v2_rsp_buf(char *cc, struct ksmbd_file *fp)
{
	struct create_durable_v2_rsp *buf;

	buf = (struct create_durable_v2_rsp *)cc;
	memset(buf, 0, sizeof(struct create_durable_v2_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_durable_v2_rsp, Timeout));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_durable_v2_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 is "DH2Q" */
	buf->Name[0] = 'D';
	buf->Name[1] = 'H';
	buf->Name[2] = '2';
	buf->Name[3] = 'Q';

	buf->Timeout = cpu_to_le32(fp->durable_timeout);
	if (fp->is_persistent)
		buf->Flags = cpu_to_le32(SMB2_DHANDLE_FLAG_PERSISTENT);
}

/**
 * create_mxac_rsp_buf() - create query maximal access context
 * @cc:			buffer to create maximal access context response
 * @maximal_access:	maximal access
 */
void create_mxac_rsp_buf(char *cc, int maximal_access)
{
	struct create_mxac_rsp *buf;

	buf = (struct create_mxac_rsp *)cc;
	memset(buf, 0, sizeof(struct create_mxac_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, QueryStatus));
	buf->ccontext.DataLength = cpu_to_le32(8);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE is "MxAc" */
	buf->Name[0] = 'M';
	buf->Name[1] = 'x';
	buf->Name[2] = 'A';
	buf->Name[3] = 'c';

	buf->QueryStatus = STATUS_SUCCESS;
	buf->MaximalAccess = cpu_to_le32(maximal_access);
}

void create_disk_id_rsp_buf(char *cc, __u64 file_id, __u64 vol_id)
{
	struct create_disk_id_rsp *buf;

	buf = (struct create_disk_id_rsp *)cc;
	memset(buf, 0, sizeof(struct create_disk_id_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_disk_id_rsp, DiskFileId));
	buf->ccontext.DataLength = cpu_to_le32(32);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_mxac_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* SMB2_CREATE_QUERY_ON_DISK_ID_RESPONSE is "QFid" */
	buf->Name[0] = 'Q';
	buf->Name[1] = 'F';
	buf->Name[2] = 'i';
	buf->Name[3] = 'd';

	buf->DiskFileId = cpu_to_le64(file_id);
	buf->VolumeId = cpu_to_le64(vol_id);
}

/**
 * create_posix_rsp_buf() - create posix extension context
 * @cc:	buffer to create posix on posix response
 * @fp: ksmbd file pointer
 */
void create_posix_rsp_buf(char *cc, struct ksmbd_file *fp)
{
	struct create_posix_rsp *buf;
	struct inode *inode = file_inode(fp->filp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap *idmap = file_mnt_idmap(fp->filp);
	vfsuid_t vfsuid = i_uid_into_vfsuid(idmap, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(idmap, inode);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	struct user_namespace *user_ns = file_mnt_user_ns(fp->filp);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	vfsuid_t vfsuid = i_uid_into_vfsuid(user_ns, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(user_ns, inode);
#endif
#endif

	buf = (struct create_posix_rsp *)cc;
	memset(buf, 0, sizeof(struct create_posix_rsp));
	buf->ccontext.DataOffset = cpu_to_le16(offsetof
			(struct create_posix_rsp, nlink));
	/*
	 * DataLength = nlink(4) + reparse_tag(4) + mode(4) +
	 * domain sid(28) + unix group sid(16).
	 */
	buf->ccontext.DataLength = cpu_to_le32(56);
	buf->ccontext.NameOffset = cpu_to_le16(offsetof
			(struct create_posix_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(POSIX_CTXT_DATA_LEN);
	/* SMB2_CREATE_TAG_POSIX is "0x93AD25509CB411E7B42383DE968BCD7C" */
	buf->Name[0] = 0x93;
	buf->Name[1] = 0xAD;
	buf->Name[2] = 0x25;
	buf->Name[3] = 0x50;
	buf->Name[4] = 0x9C;
	buf->Name[5] = 0xB4;
	buf->Name[6] = 0x11;
	buf->Name[7] = 0xE7;
	buf->Name[8] = 0xB4;
	buf->Name[9] = 0x23;
	buf->Name[10] = 0x83;
	buf->Name[11] = 0xDE;
	buf->Name[12] = 0x96;
	buf->Name[13] = 0x8B;
	buf->Name[14] = 0xCD;
	buf->Name[15] = 0x7C;

	buf->nlink = cpu_to_le32(inode->i_nlink);
	buf->reparse_tag = cpu_to_le32(fp->volatile_id);
	buf->mode = cpu_to_le32(inode->i_mode & 0777);
	/*
	 * SidBuffer(44) contain two sids(Domain sid(28), UNIX group sid(16)).
	 * Domain sid(28) = revision(1) + num_subauth(1) + authority(6) +
	 * 		    sub_auth(4 * 4(num_subauth)) + RID(4).
	 * UNIX group id(16) = revision(1) + num_subauth(1) + authority(6) +
	 * 		       sub_auth(4 * 1(num_subauth)) + RID(4).
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	id_to_sid(from_kuid_munged(&init_user_ns, vfsuid_into_kuid(vfsuid)),
#else
	id_to_sid(from_kuid_munged(&init_user_ns,
				   i_uid_into_mnt(user_ns, inode)),
#endif
#else
	id_to_sid(from_kuid_munged(&init_user_ns, inode->i_uid),
#endif
		  SIDOWNER, (struct smb_sid *)&buf->SidBuffer[0]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
	id_to_sid(from_kgid_munged(&init_user_ns, vfsgid_into_kgid(vfsgid)),
#else
	id_to_sid(from_kgid_munged(&init_user_ns,
				   i_gid_into_mnt(user_ns, inode)),
#endif
#else
	id_to_sid(from_kgid_munged(&init_user_ns, inode->i_gid),
#endif
		  SIDUNIX_GROUP, (struct smb_sid *)&buf->SidBuffer[28]);
}

#ifdef CONFIG_KSMBD_FRUIT
/*
 * Compute the total byte size of a Fruit AAPL response
 * including the variable-length model string.
 */
static inline size_t fruit_rsp_size(size_t model_utf16_bytes)
{
	return offsetof(struct create_fruit_rsp, model) +
	       model_utf16_bytes;
}

/*
 * Build the AAPL create context response with all three sections:
 *   - server_caps  (computed from global config flags)
 *   - volume_caps  (case sensitivity + fullsync support)
 *   - model_info   (server model string as UTF-16LE)
 *
 * Returns 0 on success and sets *out_size to the total response size.
 */
int create_fruit_rsp_buf(char *cc, struct ksmbd_conn *conn, size_t *out_size)
{
	struct create_fruit_rsp *buf = (struct create_fruit_rsp *)cc;
	const char *model = server_conf.fruit_model;
	size_t model_ascii_len, model_utf16_bytes, total;
	u64 caps, vcaps;
	int i;

	/* Default model if none configured */
	if (!model[0])
		model = "MacSamba";

	model_ascii_len = strlen(model);
	model_utf16_bytes = model_ascii_len * 2;
	total = fruit_rsp_size(model_utf16_bytes);

	memset(buf, 0, total);

	/* create_context header */
	buf->ccontext.DataOffset = cpu_to_le16(offsetof(
			struct create_fruit_rsp, command_code));
	buf->ccontext.DataLength = cpu_to_le32(total -
			offsetof(struct create_fruit_rsp, command_code));
	buf->ccontext.NameOffset = cpu_to_le16(offsetof(
			struct create_fruit_rsp, Name));
	buf->ccontext.NameLength = cpu_to_le16(4);
	/* Wire protocol name must be "AAPL" */
	buf->Name[0] = 'A';
	buf->Name[1] = 'A';
	buf->Name[2] = 'P';
	buf->Name[3] = 'L';

	buf->command_code = cpu_to_le32(1); /* kAAPL_SERVER_QUERY */
	buf->reply_bitmap = cpu_to_le64(0x07); /* caps + volcaps + model */

	/* server_caps: computed from global config flags */
	caps = kAAPL_UNIX_BASED; /* always: Linux is UNIX-based */
	if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)
		caps |= kAAPL_SUPPORTS_OSX_COPYFILE;
	/* AAPL-02: kAAPL_SUPPORTS_READ_DIR_ATTR removed — wire packing not
	 * implemented; advertising causes macOS to read garbage directory data. */
	buf->server_caps = cpu_to_le64(caps);

	/* volume_caps: use ksmbd_fruit_get_volume_caps() for resolve_fileid */
	vcaps = ksmbd_fruit_get_volume_caps(NULL);
	buf->volume_caps = cpu_to_le64(vcaps);

	/* model string: ASCII → UTF-16LE */
	buf->model_string_len = cpu_to_le32(model_utf16_bytes);
	for (i = 0; i < (int)model_ascii_len; i++)
		buf->model[i] = cpu_to_le16((u16)model[i]);

	*out_size = total;
	return 0;
}
#endif /* CONFIG_KSMBD_FRUIT */

/*
 * Find lease object(opinfo) for given lease key/fid from lease
 * break/file close path.
 */
/**
 * lookup_lease_in_table() - find a matching lease info object
 * @conn:	connection instance
 * @lease_key:	lease key to be searched for
 *
 * Return:      opinfo if found matching opinfo, otherwise NULL
 */
struct oplock_info *lookup_lease_in_table(const char *client_guid,
					  char *lease_key)
{
	struct oplock_info *opinfo = NULL, *ret_op = NULL;
	struct lease_table *lt;
	bool guid_valid;
	int ret;

	guid_valid = client_guid &&
		     memchr_inv(client_guid, 0, SMB2_CLIENT_GUID_SIZE);

	rcu_read_lock();
	if (guid_valid) {
		list_for_each_entry_rcu(lt, &lease_table_list, l_entry) {
			if (!memcmp(lt->client_guid, client_guid,
				    SMB2_CLIENT_GUID_SIZE))
				goto found;
		}
	}

	/*
	 * Fall back to scanning every lease table when the caller does not
	 * have a usable ClientGUID copy. This keeps lease-break ACK lookup
	 * working on rebound/migrated channels where the session still owns
	 * the lease key but the current connection GUID is not populated.
	 */
	list_for_each_entry_rcu(lt, &lease_table_list, l_entry) {
found:
		list_for_each_entry_rcu(opinfo, &lt->lease_list, lease_entry) {
			if (!refcount_inc_not_zero(&opinfo->refcount))
				continue;
			rcu_read_unlock();
			if (!opinfo->op_state || opinfo->op_state == OPLOCK_CLOSING)
				goto op_next;
			if (!(opinfo->o_lease->state &
			      (SMB2_LEASE_HANDLE_CACHING_LE |
			       SMB2_LEASE_WRITE_CACHING_LE)))
				goto op_next;
			if (guid_valid)
				ret = compare_guid_key(opinfo, client_guid,
						       lease_key);
			else
				ret = !memcmp(opinfo->o_lease->lease_key, lease_key,
					      SMB2_LEASE_KEY_SIZE);
			if (ret) {
				ksmbd_debug(OPLOCK, "found opinfo\n");
				ret_op = opinfo;
				return ret_op;
			}
op_next:
			opinfo_put(opinfo);
			rcu_read_lock();
		}
		if (guid_valid)
			break;
	}

	rcu_read_unlock();
	return NULL;
}

int smb2_check_durable_oplock(struct ksmbd_conn *conn,
			      struct ksmbd_share_config *share,
			      struct ksmbd_file *fp,
			      struct lease_ctx_info *lctx,
			      char *name)
{
	struct oplock_info *opinfo = opinfo_get(fp);
	int ret = 0;

	if (!opinfo) {
		/*
		 * C.9: If there is no opinfo (lease expired / oplock revoked)
		 * and this handle was durable, the reconnect MUST fail because
		 * there is no oplock/lease state to restore.
		 * MS-SMB2 §3.3.5.9.10 / §3.3.5.9.13: durable reconnect
		 * requires the handle to still hold the oplock/lease.
		 */
		if (fp->is_durable || fp->is_persistent)
			return -EBADF;
		return 0;
	}

	/*
	 * MS-SMB2 §3.3.5.9.7 step 4: if the handle has byte-range locks AND
	 * the oplock/lease does not include write caching, the reconnect MUST
	 * fail with STATUS_OBJECT_NAME_NOT_FOUND.  For a BATCH oplock, write
	 * caching is implied.  For a lease, WRITE_CACHING must be explicitly
	 * present in the lease state.
	 */
	if (!list_empty(&fp->lock_list)) {
		bool has_write_cache;

		if (opinfo->is_lease)
			has_write_cache = !!(opinfo->o_lease->state &
					     SMB2_LEASE_WRITE_CACHING_LE);
		else
			has_write_cache =
				(opinfo->level == SMB2_OPLOCK_LEVEL_BATCH);

		if (!has_write_cache) {
			ksmbd_debug(SMB,
				    "durable reconnect: locks present but no write caching\n");
			ret = -EBADF;
			goto out;
		}
	}

	if (opinfo->is_lease == false) {
		if (lctx) {
			pr_err("create context include lease\n");
			ret = -EBADF;
			goto out;
		}

		if (opinfo->level != SMB2_OPLOCK_LEVEL_BATCH) {
			pr_err("oplock level is not equal to SMB2_OPLOCK_LEVEL_BATCH\n");
			ret = -EBADF;
		}

		goto out;
	}

	if (memcmp(conn->ClientGUID, fp->client_guid,
				SMB2_CLIENT_GUID_SIZE)) {
		ksmbd_debug(SMB, "Client guid of fp is not equal to the one of connection\n");
		ret = -EBADF;
		goto out;
	}

	if (!lctx) {
		ksmbd_debug(SMB, "create context does not include lease\n");
		ret = -EBADF;
		goto out;
	}

	if (memcmp(opinfo->o_lease->lease_key, lctx->lease_key,
				SMB2_LEASE_KEY_SIZE)) {
		ksmbd_debug(SMB,
			    "lease key of fp does not match lease key in create context\n");
		ret = -EBADF;
		goto out;
	}

	if (!(opinfo->o_lease->state & SMB2_LEASE_HANDLE_CACHING_LE)) {
		ksmbd_debug(SMB, "lease state does not contain SMB2_LEASE_HANDLE_CACHING\n");
		ret = -EBADF;
		goto out;
	}

	if (opinfo->o_lease->version != lctx->version) {
		ksmbd_debug(SMB,
			    "lease version of fp does not match the one in create context\n");
		ret = -EBADF;
		goto out;
	}

	if (!ksmbd_inode_pending_delete(fp))
		ret = ksmbd_validate_name_reconnect(share, fp, name);
out:
	opinfo_put(opinfo);
	return ret;
}

int ksmbd_restore_oplock(struct ksmbd_work *work, struct ksmbd_file *fp,
			 int level, struct lease_ctx_info *lctx)
{
	struct oplock_info *opinfo;
	int err = 0;

	opinfo = alloc_opinfo(work, fp->persistent_id,
			      work->tcon ? work->tcon->id : 0);
	if (!opinfo)
		return -ENOMEM;

	if (lctx) {
		lctx->is_dir = S_ISDIR(file_inode(fp->filp)->i_mode);
		err = alloc_lease(opinfo, lctx);
		if (err)
			goto err_out;
		opinfo->is_lease = true;
	}

	set_oplock_level(opinfo, level, lctx);

	rcu_assign_pointer(fp->f_opinfo, opinfo);
	opinfo->o_fp = fp;
	opinfo_count_inc(fp);
	opinfo_add(opinfo);
	if (opinfo->is_lease) {
		err = add_lease_global_list(opinfo);
		if (err)
			goto err_out_registered;
	}

	/*
	 * A restored persistent handle is initially disconnected; the live
	 * connection/tcon attachment happens later in ksmbd_reopen_durable_fd().
	 */
	if (opinfo->conn) {
		ksmbd_conn_free(opinfo->conn);
		opinfo->conn = NULL;
	}

	return 0;

err_out_registered:
	opinfo_del(opinfo);
	rcu_assign_pointer(fp->f_opinfo, NULL);
	opinfo_count_dec(fp);
err_out:
	free_opinfo(opinfo);
	return err;
}

/**
 * ksmbd_oplock_init() - initialize opinfo slab cache
 *
 * Return:	0 on success, negative errno on failure
 */
int ksmbd_oplock_init(void)
{
	opinfo_cache = kmem_cache_create("ksmbd_opinfo_cache",
					 sizeof(struct oplock_info), 0,
					 SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT,
					 NULL);
	if (!opinfo_cache)
		return -ENOMEM;
	return 0;
}

/**
 * ksmbd_oplock_exit() - destroy opinfo slab cache
 */
void ksmbd_oplock_exit(void)
{
	kmem_cache_destroy(opinfo_cache);
	opinfo_cache = NULL;
}
