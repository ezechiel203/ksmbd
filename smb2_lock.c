// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_lock.c - SMB2_LOCK + SMB2_CANCEL handlers
 */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/ethtool.h>
#include <linux/falloc.h>
#include <linux/crc32.h>
#include <linux/mount.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif

#include <crypto/algapi.h>

#include "compat.h"
#include "glob.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "smbacl.h"

#include "auth.h"
#include "asn1.h"
#include "connection.h"
#include "transport_ipc.h"
#include "transport_rdma.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "misc.h"

#include "server.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/ksmbd_ida.h"
#include "ndr.h"
#include "transport_tcp.h"
#include "smb2fruit.h"
#include "ksmbd_fsctl.h"
#include "ksmbd_create_ctx.h"
#include "ksmbd_vss.h"
#include "ksmbd_notify.h"
#include "ksmbd_info.h"
#include "ksmbd_buffer.h"
#include "smb2pdu_internal.h"

/**
 * smb2_cancel() - handler for smb2 cancel command
 * @work:	smb work containing cancel command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_cancel(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_hdr *hdr = smb2_get_msg(work->request_buf);
	struct smb2_hdr *chdr;
	struct ksmbd_work *iter;
	struct list_head *command_list;

	if (work->next_smb2_rcv_hdr_off)
		hdr = ksmbd_resp_buf_next(work);

	ksmbd_debug(SMB, "smb2 cancel called on mid %llu, async flags 0x%x\n",
		    hdr->MessageId, hdr->Flags);

	if (hdr->Flags & SMB2_FLAGS_ASYNC_COMMAND) {
		command_list = &conn->async_requests;

		spin_lock(&conn->request_lock);
		list_for_each_entry(iter, command_list,
				    async_request_entry) {
			chdr = smb2_get_msg(iter->request_buf);

			if (iter->async_id !=
			    le64_to_cpu(hdr->Id.AsyncId))
				continue;

			ksmbd_debug(SMB,
				    "smb2 with AsyncId %llu cancelled command = 0x%x\n",
				    le64_to_cpu(hdr->Id.AsyncId),
				    le16_to_cpu(chdr->Command));
			iter->state = KSMBD_WORK_CANCELLED;
			if (iter->cancel_fn)
				iter->cancel_fn(iter->cancel_argv);
			break;
		}
		spin_unlock(&conn->request_lock);
	} else {
		command_list = &conn->requests;

		spin_lock(&conn->request_lock);
		list_for_each_entry(iter, command_list, request_entry) {
			chdr = smb2_get_msg(iter->request_buf);

			if (chdr->MessageId != hdr->MessageId ||
			    iter == work)
				continue;

			ksmbd_debug(SMB,
				    "smb2 with mid %llu cancelled command = 0x%x\n",
				    le64_to_cpu(hdr->MessageId),
				    le16_to_cpu(chdr->Command));
			iter->state = KSMBD_WORK_CANCELLED;
			break;
		}
		spin_unlock(&conn->request_lock);
	}

	/* For SMB2_CANCEL command itself send no response*/
	work->send_no_response = 1;
	return 0;
}

struct file_lock *smb_flock_init(struct file *f)
{
	struct file_lock *fl;

	fl = locks_alloc_lock();
	if (!fl)
		goto out;

	locks_init_lock(fl);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	fl->c.flc_owner = f;
	fl->c.flc_pid = current->tgid;
	fl->c.flc_file = f;
	fl->c.flc_flags = FL_POSIX;
#else
	fl->fl_owner = f;
	fl->fl_pid = current->tgid;
	fl->fl_file = f;
	fl->fl_flags = FL_POSIX;
#endif
	fl->fl_ops = NULL;
	fl->fl_lmops = NULL;

out:
	return fl;
}

static int smb2_set_flock_flags(struct file_lock *flock, int flags)
{
	int cmd = -EINVAL;

	/* Checking for wrong flag combination during lock request*/
	switch (flags) {
	case SMB2_LOCKFLAG_SHARED:
		ksmbd_debug(SMB, "received shared request\n");
		cmd = F_SETLKW;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		flock->c.flc_type = F_RDLCK;
		flock->c.flc_flags |= FL_SLEEP;
#else
		flock->fl_type = F_RDLCK;
		flock->fl_flags |= FL_SLEEP;
#endif
		break;
	case SMB2_LOCKFLAG_EXCLUSIVE:
		ksmbd_debug(SMB, "received exclusive request\n");
		cmd = F_SETLKW;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		flock->c.flc_type = F_WRLCK;
		flock->c.flc_flags |= FL_SLEEP;
#else
		flock->fl_type = F_WRLCK;
		flock->fl_flags |= FL_SLEEP;
#endif
		break;
	case SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		ksmbd_debug(SMB,
			    "received shared & fail immediately request\n");
		cmd = F_SETLK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		flock->c.flc_type = F_RDLCK;
#else
		flock->fl_type = F_RDLCK;
#endif
		break;
	case SMB2_LOCKFLAG_EXCLUSIVE | SMB2_LOCKFLAG_FAIL_IMMEDIATELY:
		ksmbd_debug(SMB,
			    "received exclusive & fail immediately request\n");
		cmd = F_SETLK;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		flock->c.flc_type = F_WRLCK;
#else
		flock->fl_type = F_WRLCK;
#endif
		break;
	case SMB2_LOCKFLAG_UNLOCK:
		ksmbd_debug(SMB, "received unlock request\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		flock->c.flc_type = F_UNLCK;
#else
		flock->fl_type = F_UNLCK;
#endif
		cmd = F_SETLK;
		break;
	}

	return cmd;
}

static struct ksmbd_lock *smb2_lock_init(struct file_lock *flock,
					 unsigned int cmd, int flags,
					 struct list_head *lock_list)
{
	struct ksmbd_lock *lock;

	lock = kzalloc(sizeof(struct ksmbd_lock), KSMBD_DEFAULT_GFP);
	if (!lock)
		return NULL;

	lock->cmd = cmd;
	lock->fl = flock;
	lock->start = flock->fl_start;
	lock->end = flock->fl_end;
	lock->flags = flags;
	if (lock->start == lock->end)
		lock->zero_len = 1;
	INIT_LIST_HEAD(&lock->clist);
	INIT_LIST_HEAD(&lock->flist);
	INIT_LIST_HEAD(&lock->llist);
	list_add_tail(&lock->llist, lock_list);

	return lock;
}

static void smb2_remove_blocked_lock(void **argv)
{
	struct file_lock *flock = (struct file_lock *)argv[0];

	ksmbd_vfs_posix_lock_unblock(flock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	locks_wake_up(flock);
#else
	wake_up(&flock->fl_wait);
#endif
}

static inline bool lock_defer_pending(struct file_lock *fl)
{
	/* check pending lock waiters */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
	return waitqueue_active(&fl->c.flc_wait);
#else
	return waitqueue_active(&fl->fl_wait);
#endif
}

/**
 * check_lock_sequence() - validate lock sequence for resilient/durable handles
 * @fp:			ksmbd file pointer
 * @lock_seq_val:	lock sequence value from SMB2 LOCK request
 *
 * Per MS-SMB2 3.3.5.14, the server validates that the lock sequence number
 * hasn't been used before for the given index. This prevents stale lock
 * requests from being processed after client reconnection.
 *
 * Return:	0 on success (proceed with lock), -EAGAIN if duplicate sequence
 */
static int check_lock_sequence(struct ksmbd_file *fp,
			       __le32 lock_seq_val)
{
	u32 val = le32_to_cpu(lock_seq_val);
	u8 seq_num = (val >> 28) & 0xF;  /* High 4 bits */
	u8 seq_idx = (val >> 24) & 0xF;  /* Next 4 bits */
	int ret = 0;

	/* Index 0 means no lock sequence validation */
	if (seq_idx == 0)
		return 0;

	/* Only validate for resilient/durable handles */
	if (!fp->is_resilient && !fp->is_durable)
		return 0;

	spin_lock(&fp->lock_seq_lock);
	if (fp->lock_seq[seq_idx] == seq_num) {
		/* Duplicate - reject with STATUS_FILE_NOT_AVAILABLE */
		ret = -EAGAIN;
	} else {
		fp->lock_seq[seq_idx] = seq_num;
	}
	spin_unlock(&fp->lock_seq_lock);
	return ret;
}

/**
 * smb2_lock() - handler for smb2 file lock command
 * @work:	smb work containing lock command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_lock(struct ksmbd_work *work)
{
	struct smb2_lock_req *req;
	struct smb2_lock_rsp *rsp;
	struct smb2_lock_element *lock_ele;
	struct ksmbd_file *fp = NULL;
	struct file_lock *flock = NULL;
	struct file *filp = NULL;
	int lock_count;
	int flags = 0;
	int cmd = 0;
	int err = -EIO, i, rc = 0;
	u64 lock_start, lock_length;
	struct ksmbd_lock *smb_lock = NULL, *cmp_lock, *tmp, *tmp2;
	struct ksmbd_conn *conn;
	int nolock = 0;
	LIST_HEAD(lock_list);
	LIST_HEAD(rollback_list);
	int prior_lock = 0, bkt = 0;

	WORK_BUFFERS(work, req, rsp);

	ksmbd_debug(SMB, "Received smb2 lock request\n");
	fp = ksmbd_lookup_fd_slow(work, req->VolatileFileId, req->PersistentFileId);
	if (!fp) {
		ksmbd_debug(SMB, "Invalid file id for lock : %llu\n", req->VolatileFileId);
		err = -ENOENT;
		goto out2;
	}

	/* Validate lock sequence for resilient/durable handles */
	rc = check_lock_sequence(fp, req->LockSequenceNumber);
	if (rc) {
		rsp->hdr.Status = STATUS_FILE_NOT_AVAILABLE;
		err = rc;
		goto out2;
	}

	filp = fp->filp;
	lock_count = le16_to_cpu(req->LockCount);
	lock_ele = req->locks;

	ksmbd_debug(SMB, "lock count is %d\n", lock_count);
	if (!lock_count || lock_count > KSMBD_MAX_LOCK_COUNT) {
		pr_err_ratelimited("Invalid lock count: %d\n", lock_count);
		err = -EINVAL;
		goto out2;
	}

	for (i = 0; i < lock_count; i++) {
		flags = le32_to_cpu(lock_ele[i].Flags);

		flock = smb_flock_init(filp);
		if (!flock)
			goto out;

		cmd = smb2_set_flock_flags(flock, flags);

		lock_start = le64_to_cpu(lock_ele[i].Offset);
		lock_length = le64_to_cpu(lock_ele[i].Length);
		if (lock_start > U64_MAX - lock_length) {
			pr_err_ratelimited("Invalid lock range requested\n");
			rsp->hdr.Status = STATUS_INVALID_LOCK_RANGE;
			locks_free_lock(flock);
			goto out;
		}

		if (lock_start > OFFSET_MAX)
			flock->fl_start = OFFSET_MAX;
		else
			flock->fl_start = lock_start;

		lock_length = le64_to_cpu(lock_ele[i].Length);
		if (lock_length > OFFSET_MAX - flock->fl_start)
			lock_length = OFFSET_MAX - flock->fl_start;

		flock->fl_end = flock->fl_start + lock_length;

		if (flock->fl_end < flock->fl_start) {
			ksmbd_debug(SMB,
				    "the end offset(%llx) is smaller than the start offset(%llx)\n",
				    flock->fl_end, flock->fl_start);
			rsp->hdr.Status = STATUS_INVALID_LOCK_RANGE;
			locks_free_lock(flock);
			goto out;
		}

		/* Check conflict locks in one request */
		list_for_each_entry(cmp_lock, &lock_list, llist) {
			if (cmp_lock->fl->fl_start <= flock->fl_start &&
			    cmp_lock->fl->fl_end >= flock->fl_end) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
				if (cmp_lock->fl->c.flc_type != F_UNLCK &&
				    flock->c.flc_type != F_UNLCK) {
#else
				if (cmp_lock->fl->fl_type != F_UNLCK &&
				    flock->fl_type != F_UNLCK) {
#endif
					pr_err_ratelimited("conflict two locks in one request\n");
					err = -EINVAL;
					locks_free_lock(flock);
					goto out;
				}
			}
		}

		smb_lock = smb2_lock_init(flock, cmd, flags, &lock_list);
		if (!smb_lock) {
			err = -EINVAL;
			locks_free_lock(flock);
			goto out;
		}
	}

	list_for_each_entry_safe(smb_lock, tmp, &lock_list, llist) {
		if (smb_lock->cmd < 0) {
			err = -EINVAL;
			goto out;
		}

		if (!(smb_lock->flags & SMB2_LOCKFLAG_MASK)) {
			err = -EINVAL;
			goto out;
		}

		if ((prior_lock & (SMB2_LOCKFLAG_EXCLUSIVE | SMB2_LOCKFLAG_SHARED) &&
		     smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) ||
		    (prior_lock == SMB2_LOCKFLAG_UNLOCK &&
		     !(smb_lock->flags & SMB2_LOCKFLAG_UNLOCK))) {
			err = -EINVAL;
			goto out;
		}

		prior_lock = smb_lock->flags;

		if (!(smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) &&
		    !(smb_lock->flags & SMB2_LOCKFLAG_FAIL_IMMEDIATELY))
			goto no_check_cl;

		nolock = 1;
		/* check locks in connection list */
		for (bkt = 0; bkt < CONN_HASH_SIZE; bkt++) {
		spin_lock(&conn_hash[bkt].lock);
		hlist_for_each_entry(conn, &conn_hash[bkt].head,
				     hlist) {
			spin_lock(&conn->llist_lock);
			list_for_each_entry_safe(cmp_lock, tmp2, &conn->lock_list, clist) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
				if (file_inode(cmp_lock->fl->c.flc_file) !=
				    file_inode(smb_lock->fl->c.flc_file))
#else
				if (file_inode(cmp_lock->fl->fl_file) !=
				    file_inode(smb_lock->fl->fl_file))
#endif
					continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
				if (lock_is_unlock(smb_lock->fl)) {
#else
				if (smb_lock->fl->fl_type == F_UNLCK) {
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
					if (cmp_lock->fl->c.flc_file == smb_lock->fl->c.flc_file &&
#else
					if (cmp_lock->fl->fl_file == smb_lock->fl->fl_file &&
#endif
					    cmp_lock->start == smb_lock->start &&
					    cmp_lock->end == smb_lock->end &&
					    !lock_defer_pending(cmp_lock->fl)) {
						nolock = 0;
						list_del(&cmp_lock->flist);
						list_del(&cmp_lock->clist);
						spin_unlock(&conn->llist_lock);
						spin_unlock(&conn_hash[bkt].lock);

						locks_free_lock(cmp_lock->fl);
						kfree(cmp_lock);
						goto out_check_cl;
					}
					continue;
				}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
				if (cmp_lock->fl->c.flc_file == smb_lock->fl->c.flc_file) {
#else
				if (cmp_lock->fl->fl_file == smb_lock->fl->fl_file) {
#endif
					if (smb_lock->flags & SMB2_LOCKFLAG_SHARED)
						continue;
				} else {
					if (cmp_lock->flags & SMB2_LOCKFLAG_SHARED)
						continue;
				}

				/* check zero byte lock range */
				if (cmp_lock->zero_len && !smb_lock->zero_len &&
				    cmp_lock->start > smb_lock->start &&
				    cmp_lock->start < smb_lock->end) {
					spin_unlock(&conn->llist_lock);
					spin_unlock(&conn_hash[bkt].lock);
					pr_err_ratelimited("previous lock conflict with zero byte lock range\n");
					goto out;
				}

				if (smb_lock->zero_len && !cmp_lock->zero_len &&
				    smb_lock->start > cmp_lock->start &&
				    smb_lock->start < cmp_lock->end) {
					spin_unlock(&conn->llist_lock);
					spin_unlock(&conn_hash[bkt].lock);
					pr_err_ratelimited("current lock conflict with zero byte lock range\n");
					goto out;
				}

				if (((cmp_lock->start <= smb_lock->start &&
				      cmp_lock->end > smb_lock->start) ||
				     (cmp_lock->start < smb_lock->end &&
				      cmp_lock->end >= smb_lock->end)) &&
				    !cmp_lock->zero_len && !smb_lock->zero_len) {
					spin_unlock(&conn->llist_lock);
					spin_unlock(&conn_hash[bkt].lock);
					pr_err_ratelimited("Not allow lock operation on exclusive lock range\n");
					goto out;
				}
			}
			spin_unlock(&conn->llist_lock);
		}
		spin_unlock(&conn_hash[bkt].lock);
		}
out_check_cl:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		if (lock_is_unlock(smb_lock->fl) && nolock) {
#else
		if (smb_lock->fl->fl_type == F_UNLCK && nolock) {
#endif
			pr_err_ratelimited("Try to unlock nolocked range\n");
			rsp->hdr.Status = STATUS_RANGE_NOT_LOCKED;
			goto out;
		}

no_check_cl:
		flock = smb_lock->fl;
		list_del(&smb_lock->llist);

		if (smb_lock->zero_len) {
			err = 0;
			goto skip;
		}
retry:
		rc = vfs_lock_file(filp, smb_lock->cmd, flock, NULL);
skip:
		if (smb_lock->flags & SMB2_LOCKFLAG_UNLOCK) {
			if (!rc) {
				ksmbd_debug(SMB, "File unlocked\n");
			} else if (rc == -ENOENT) {
				rsp->hdr.Status = STATUS_NOT_LOCKED;
				goto out;
			}
			locks_free_lock(flock);
			kfree(smb_lock);
		} else {
			if (rc == FILE_LOCK_DEFERRED) {
				void **argv;

				ksmbd_debug(SMB,
					    "would have to wait for getting lock\n");
				list_add(&smb_lock->llist, &rollback_list);

				argv = kmalloc(sizeof(void *), KSMBD_DEFAULT_GFP);
				if (!argv) {
					err = -ENOMEM;
					goto out;
				}
				argv[0] = flock;

				rc = setup_async_work(work,
						      smb2_remove_blocked_lock,
						      argv);
				if (rc) {
					kfree(argv);
					err = -ENOMEM;
					goto out;
				}
				spin_lock(&fp->f_lock);
				list_add(&work->fp_entry, &fp->blocked_works);
				spin_unlock(&fp->f_lock);

				smb2_send_interim_resp(work, STATUS_PENDING);

				ksmbd_vfs_posix_lock_wait(flock);

				spin_lock(&fp->f_lock);
				list_del(&work->fp_entry);
				spin_unlock(&fp->f_lock);

				if (work->state != KSMBD_WORK_ACTIVE) {
					list_del(&smb_lock->llist);
					locks_free_lock(flock);

					if (work->state == KSMBD_WORK_CANCELLED) {
						rsp->hdr.Status =
							STATUS_CANCELLED;
						kfree(smb_lock);
						smb2_send_interim_resp(work,
								       STATUS_CANCELLED);
						work->send_no_response = 1;
						goto out;
					}

					rsp->hdr.Status =
						STATUS_RANGE_NOT_LOCKED;
					kfree(smb_lock);
					goto out2;
				}

				list_del(&smb_lock->llist);
				release_async_work(work);
				goto retry;
			} else if (!rc) {
				list_add(&smb_lock->llist, &rollback_list);
				spin_lock(&work->conn->llist_lock);
				list_add_tail(&smb_lock->clist,
					      &work->conn->lock_list);
				list_add_tail(&smb_lock->flist,
					      &fp->lock_list);
				spin_unlock(&work->conn->llist_lock);
				ksmbd_debug(SMB, "successful in taking lock\n");
			} else {
				goto out;
			}
		}
	}

	if (atomic_read(&fp->f_ci->op_count) > 1)
		smb_break_all_oplock(work, fp);

	rsp->StructureSize = cpu_to_le16(4);
	ksmbd_debug(SMB, "successful in taking lock\n");
	rsp->hdr.Status = STATUS_SUCCESS;
	rsp->Reserved = 0;
	err = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_lock_rsp));
	if (err)
		goto out;

	ksmbd_fd_put(work, fp);
	return 0;

out:
	list_for_each_entry_safe(smb_lock, tmp, &lock_list, llist) {
		locks_free_lock(smb_lock->fl);
		list_del(&smb_lock->llist);
		kfree(smb_lock);
	}

	list_for_each_entry_safe(smb_lock, tmp, &rollback_list, llist) {
		struct file_lock *rlock = NULL;

		rlock = smb_lock->fl;
		/* Convert to unlock */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		rlock->c.flc_type = F_UNLCK;
#else
		rlock->fl_type = F_UNLCK;
#endif
		/* Apply the unlock to VFS */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
		rc = vfs_lock_file(rlock->c.flc_file,
				   F_SETLK, rlock, NULL);
#else
		rc = vfs_lock_file(rlock->fl_file,
				   F_SETLK, rlock, NULL);
#endif
		if (rc)
			pr_err("rollback unlock fail : %d\n", rc);

		/* Remove from all lists under proper locking */
		spin_lock(&work->conn->llist_lock);
		list_del(&smb_lock->clist);
		spin_unlock(&work->conn->llist_lock);

		list_del(&smb_lock->flist);
		list_del(&smb_lock->llist);

		locks_free_lock(smb_lock->fl);
		kfree(smb_lock);
	}
out2:
	ksmbd_debug(SMB, "failed in taking lock(flags : %x), err : %d\n", flags, err);

	if (!rsp->hdr.Status) {
		if (err == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (err == -ENOMEM)
			rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;
		else if (err == -ENOENT)
			rsp->hdr.Status = STATUS_FILE_CLOSED;
		else
			rsp->hdr.Status = STATUS_LOCK_NOT_GRANTED;
	}

	smb2_set_err_rsp(work);
	ksmbd_fd_put(work, fp);
	return err;
}
