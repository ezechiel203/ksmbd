// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   SMB2 CHANGE_NOTIFY implementation using Linux fsnotify.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/fsnotify_backend.h>
#include <linux/version.h>

#include "glob.h"
#include "smb2pdu.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "vfs_cache.h"
#include "connection.h"
#include "ksmbd_notify.h"

/*
 * fsnotify group flags differ across kernel versions.
 * Use the strongest supported flag set available at build time.
 */
#ifdef FSNOTIFY_GROUP_NOFS
#define KSMBD_FSNOTIFY_GROUP_FLAGS FSNOTIFY_GROUP_NOFS
#else
#define KSMBD_FSNOTIFY_GROUP_FLAGS FSNOTIFY_GROUP_USER
#endif

/* Global fsnotify group for all ksmbd watches */
static struct fsnotify_group *ksmbd_notify_group;

/*
 * Mask of all fsnotify events we care about — directory entry
 * changes, attribute changes, modifications, and accesses.
 */
#define KSMBD_FSNOTIFY_MASK	(FS_CREATE | FS_DELETE | FS_MODIFY |	\
				 FS_MOVED_FROM | FS_MOVED_TO |		\
				 FS_ATTRIB | FS_ACCESS |		\
				 FS_EVENT_ON_CHILD)

/*
 * FILE_NOTIFY_INFORMATION on-wire structure (MS-FSCC 2.4.42).
 * Variable-length: FileName[] follows immediately after the header.
 */
struct file_notify_information {
	__le32 NextEntryOffset;
	__le32 Action;
	__le32 FileNameLength;
	__le16 FileName[];
} __packed;

/* ------------------------------------------------------------------ */
/*  fsnotify event  ->  SMB2 completion-filter mapping                 */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_fsnotify_to_smb2_filter() - map fsnotify mask to SMB2 flags
 * @mask: fsnotify event mask
 *
 * Return: SMB2 FILE_NOTIFY_CHANGE_* bitmask
 */
static u32 ksmbd_fsnotify_to_smb2_filter(u32 mask)
{
	u32 filter = 0;

	if (mask & FS_CREATE)
		filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
	if (mask & FS_DELETE)
		filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
	if (mask & FS_MODIFY)
		filter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	if (mask & FS_ATTRIB)
		filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	if (mask & FS_MOVED_FROM)
		filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
	if (mask & FS_MOVED_TO)
		filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
	if (mask & FS_ACCESS)
		filter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	if (mask & FS_ISDIR) {
		/* Directory operations map to DIR_NAME */
		if (filter & FILE_NOTIFY_CHANGE_FILE_NAME) {
			filter &= ~FILE_NOTIFY_CHANGE_FILE_NAME;
			filter |= FILE_NOTIFY_CHANGE_DIR_NAME;
		}
	}

	return filter;
}

/**
 * ksmbd_fsnotify_to_action() - map fsnotify mask to SMB2 action
 * @mask: fsnotify event mask
 *
 * Return: FILE_ACTION_* constant
 */
static u32 ksmbd_fsnotify_to_action(u32 mask)
{
	if (mask & FS_CREATE)
		return FILE_ACTION_ADDED;
	if (mask & FS_DELETE)
		return FILE_ACTION_REMOVED;
	if (mask & FS_MOVED_FROM)
		return FILE_ACTION_RENAMED_OLD_NAME;
	if (mask & FS_MOVED_TO)
		return FILE_ACTION_RENAMED_NEW_NAME;
	/* FS_MODIFY, FS_ATTRIB, FS_ACCESS -> generic modified */
	return FILE_ACTION_MODIFIED;
}

/* ------------------------------------------------------------------ */
/*  Build FILE_NOTIFY_INFORMATION buffer and complete async work       */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_notify_build_response() - fill the SMB2 notify response
 * @watch:     watch that received the event
 * @action:    FILE_ACTION_* constant
 * @file_name: filename (kernel UTF-8 qstr)
 *
 * Constructs the FILE_NOTIFY_INFORMATION buffer, pins it on the
 * pending work's response, and sends it to the client.
 */
static void ksmbd_notify_build_response(
		struct ksmbd_notify_watch *watch,
		u32 action,
		const struct qstr *file_name)
{
	struct ksmbd_work *work;
	struct smb2_notify_rsp *rsp;
	struct file_notify_information *info;
	int name_bytes;
	int info_len;
	int total_rsp_len;
	int uni_len;
	u8 *out;
	int i;

	spin_lock(&watch->lock);
	work = watch->pending_work;
	if (!work || watch->completed) {
		spin_unlock(&watch->lock);
		return;
	}
	watch->completed = true;
	spin_unlock(&watch->lock);

	rsp = smb2_get_msg(work->response_buf);

	/* Convert filename to UTF-16LE for the response */
	name_bytes = file_name->len * 2;  /* worst case */
	info_len = sizeof(struct file_notify_information) +
		   name_bytes;

	if (info_len > (int)watch->output_buf_len) {
		/*
		 * Buffer overflow -- return STATUS_NOTIFY_ENUM_DIR
		 * which tells the client to re-enumerate.
		 */
		rsp->hdr.Status = STATUS_NOTIFY_ENUM_DIR;
		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(0);
		rsp->OutputBufferLength = cpu_to_le32(0);
		total_rsp_len =
			sizeof(struct smb2_notify_rsp) - 1;
		goto send;
	}

	out = (u8 *)rsp + sizeof(struct smb2_notify_rsp) - 1;
	info = (struct file_notify_information *)out;

	/*
	 * Convert the filename from UTF-8 to UTF-16LE.
	 * Simple byte-by-byte expansion for ASCII.
	 */
	uni_len = 0;
	for (i = 0; i < (int)file_name->len &&
	     uni_len < name_bytes; i++) {
		info->FileName[uni_len / 2] =
			cpu_to_le16((u16)file_name->name[i]);
		uni_len += 2;
	}

	info->NextEntryOffset = cpu_to_le32(0);
	info->Action = cpu_to_le32(action);
	info->FileNameLength = cpu_to_le32(uni_len);

	info_len =
		sizeof(struct file_notify_information) + uni_len;

	rsp->hdr.Status = STATUS_SUCCESS;
	rsp->StructureSize = cpu_to_le16(9);
	rsp->OutputBufferOffset = cpu_to_le16(
		sizeof(struct smb2_hdr) +
		sizeof(rsp->StructureSize) +
		sizeof(rsp->OutputBufferOffset) +
		sizeof(rsp->OutputBufferLength));
	rsp->OutputBufferLength = cpu_to_le32(info_len);

	total_rsp_len =
		sizeof(struct smb2_notify_rsp) - 1 + info_len;

send:
	if (ksmbd_iov_pin_rsp(work, rsp, total_rsp_len))
		rsp->hdr.Status = STATUS_INSUFFICIENT_RESOURCES;

	ksmbd_conn_write(work);

	/* Detach from fp->blocked_works before freeing */
	if (watch->fp) {
		spin_lock(&watch->fp->f_lock);
		list_del_init(&work->fp_entry);
		spin_unlock(&watch->fp->f_lock);
	}

	/*
	 * ksmbd_conn_try_dequeue_request() decrements conn->req_running
	 * (which was incremented in ksmbd_conn_enqueue_request but never
	 * decremented because handle_ksmbd_work skipped it for
	 * pending_async works) and calls release_async_work() internally.
	 */
	ksmbd_conn_try_dequeue_request(work);
	ksmbd_free_work_struct(work);

	spin_lock(&watch->lock);
	watch->pending_work = NULL;
	spin_unlock(&watch->lock);

	/* Destroy the fsnotify mark so it does not accumulate */
	fsnotify_destroy_mark(&watch->mark, ksmbd_notify_group);
}

/* ------------------------------------------------------------------ */
/*  fsnotify callbacks                                                 */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_notify_handle_event() - fsnotify event callback
 * @group:     the fsnotify group
 * @mask:      event mask
 * @data:      event data (inode or path)
 * @data_type: type of data
 * @dir:       directory inode
 * @file_name: name of the affected entry
 * @cookie:    rename cookie
 * @iter_info: iterator with marks
 *
 * Called by the fsnotify subsystem when a watched inode has an
 * event.  Matches the event against the watch's completion filter
 * and, if it passes, builds the response and completes the
 * pending async work.
 *
 * Return: 0 always
 */
static int ksmbd_notify_handle_event(
		struct fsnotify_group *group,
		u32 mask,
		const void *data,
		int data_type,
		struct inode *dir,
		const struct qstr *file_name,
		u32 cookie,
		struct fsnotify_iter_info *iter_info)
{
	struct fsnotify_mark *inode_mark = NULL;
	struct ksmbd_notify_watch *watch;
	u32 smb2_filter;
	u32 action;
	int type;

	/* Walk the iterator to find our inode mark */
	for (type = 0; type < FSNOTIFY_ITER_TYPE_COUNT; type++) {
		struct fsnotify_mark *m;

		m = fsnotify_iter_mark(iter_info, type);
		if (m && m->group == group) {
			inode_mark = m;
			break;
		}
	}

	if (!inode_mark)
		return 0;

	watch = container_of(inode_mark,
			     struct ksmbd_notify_watch, mark);

	/* Map fsnotify mask to SMB2 filter and check overlap */
	smb2_filter = ksmbd_fsnotify_to_smb2_filter(mask);
	if (!(smb2_filter & watch->completion_filter))
		return 0;

	if (!file_name)
		return 0;

	action = ksmbd_fsnotify_to_action(mask);
	ksmbd_notify_build_response(watch, action, file_name);

	return 0;
}

/**
 * ksmbd_notify_free_mark() - free callback for fsnotify_mark
 * @mark: the mark to free
 *
 * Called after all references to the mark are dropped.
 * Frees the containing ksmbd_notify_watch structure.
 */
static void ksmbd_notify_free_mark(struct fsnotify_mark *mark)
{
	struct ksmbd_notify_watch *watch;

	watch = container_of(mark,
			     struct ksmbd_notify_watch, mark);
	kfree(watch);
}

static const struct fsnotify_ops ksmbd_notify_ops = {
	.handle_event	= ksmbd_notify_handle_event,
	.free_mark	= ksmbd_notify_free_mark,
};

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_notify_add_watch() - install an fsnotify watch
 * @fp:                ksmbd file pointer (must be a directory)
 * @work:              async work to complete when an event arrives
 * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* flags
 * @watch_tree:        true to watch recursively
 * @output_buf_len:    client-requested output buffer size
 * @cancel_argv:       cancel args; argv[0] set to watch on success
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_notify_add_watch(struct ksmbd_file *fp,
			   struct ksmbd_work *work,
			   u32 completion_filter,
			   bool watch_tree,
			   u32 output_buf_len,
			   void **cancel_argv)
{
	struct ksmbd_notify_watch *watch;
	struct inode *inode;
	u32 fs_mask;
	int ret;

	if (!fp || !fp->filp)
		return -EINVAL;

	inode = file_inode(fp->filp);
	if (!S_ISDIR(inode->i_mode))
		return -ENOTDIR;

	if (!ksmbd_notify_group)
		return -ENODEV;

	watch = kzalloc(sizeof(*watch), KSMBD_DEFAULT_GFP);
	if (!watch)
		return -ENOMEM;

	watch->fp = fp;
	watch->pending_work = work;
	watch->completion_filter = completion_filter;
	watch->watch_tree = watch_tree;
	watch->output_buf_len = output_buf_len;
	watch->completed = false;
	spin_lock_init(&watch->lock);
	INIT_LIST_HEAD(&watch->list);

	fsnotify_init_mark(&watch->mark, ksmbd_notify_group);

	/*
	 * Build the fsnotify mask from the SMB2 completion
	 * filter.  Always include FS_EVENT_ON_CHILD so the
	 * mark fires for directory entry changes.
	 */
	fs_mask = FS_EVENT_ON_CHILD;
	if (completion_filter &
	    (FILE_NOTIFY_CHANGE_FILE_NAME |
	     FILE_NOTIFY_CHANGE_DIR_NAME |
	     FILE_NOTIFY_CHANGE_NAME))
		fs_mask |= FS_CREATE | FS_DELETE |
			   FS_MOVED_FROM | FS_MOVED_TO;
	if (completion_filter & FILE_NOTIFY_CHANGE_ATTRIBUTES)
		fs_mask |= FS_ATTRIB;
	if (completion_filter &
	    (FILE_NOTIFY_CHANGE_SIZE |
	     FILE_NOTIFY_CHANGE_LAST_WRITE))
		fs_mask |= FS_MODIFY;
	if (completion_filter & FILE_NOTIFY_CHANGE_LAST_ACCESS)
		fs_mask |= FS_ACCESS;
	if (completion_filter & FILE_NOTIFY_CHANGE_CREATION)
		fs_mask |= FS_CREATE;
	if (completion_filter & FILE_NOTIFY_CHANGE_SECURITY)
		fs_mask |= FS_ATTRIB;
	if (completion_filter & FILE_NOTIFY_CHANGE_EA)
		fs_mask |= FS_ATTRIB;
	if (completion_filter &
	    (FILE_NOTIFY_CHANGE_STREAM_NAME |
	     FILE_NOTIFY_CHANGE_STREAM_SIZE |
	     FILE_NOTIFY_CHANGE_STREAM_WRITE))
		fs_mask |= FS_MODIFY;

	watch->mark.mask = fs_mask;

	ret = fsnotify_add_inode_mark(&watch->mark, inode, 0);
	if (ret) {
		pr_err_ratelimited(
			"ksmbd: failed to add fsnotify mark: %d\n",
			ret);
		fsnotify_put_mark(&watch->mark);
		return ret;
	}

	/* Store watch in cancel_argv for the cancel callback */
	if (cancel_argv)
		cancel_argv[0] = watch;

	/* Link the watch into fp->blocked_works for cleanup */
	spin_lock(&fp->f_lock);
	list_add(&work->fp_entry, &fp->blocked_works);
	spin_unlock(&fp->f_lock);

	return 0;
}

/**
 * ksmbd_notify_cancel() - cancel a pending async notify
 * @argv: cancel_argv array (argv[0] = ksmbd_notify_watch *)
 *
 * Invoked from the SMB2_CANCEL handler via work->cancel_fn.
 * Sends STATUS_CANCELLED and detaches the fsnotify mark.
 */
void ksmbd_notify_cancel(void **argv)
{
	struct ksmbd_notify_watch *watch;
	struct ksmbd_work *work;
	struct smb2_notify_rsp *rsp;

	if (!argv || !argv[0])
		return;

	watch = argv[0];

	spin_lock(&watch->lock);
	work = watch->pending_work;
	if (!work || watch->completed) {
		spin_unlock(&watch->lock);
		return;
	}
	watch->completed = true;
	watch->pending_work = NULL;
	spin_unlock(&watch->lock);

	rsp = smb2_get_msg(work->response_buf);
	rsp->hdr.Status = STATUS_CANCELLED;
	rsp->StructureSize = cpu_to_le16(9);
	rsp->OutputBufferOffset = cpu_to_le16(0);
	rsp->OutputBufferLength = cpu_to_le32(0);

	smb2_send_interim_resp(work, STATUS_CANCELLED);
	work->send_no_response = 1;

	/* Detach from fp->blocked_works before freeing */
	if (watch->fp) {
		spin_lock(&watch->fp->f_lock);
		list_del_init(&work->fp_entry);
		spin_unlock(&watch->fp->f_lock);
	}

	ksmbd_conn_try_dequeue_request(work);
	ksmbd_free_work_struct(work);

	/* Remove the fsnotify mark (exported API for modules) */
	fsnotify_destroy_mark(&watch->mark, ksmbd_notify_group);
}

/**
 * ksmbd_notify_cleanup_file() - remove all watches for a file
 * @fp: ksmbd file pointer being closed
 *
 * Iterates blocked_works on this file and cleans up any notify
 * watches.  Called when a file handle is closed.
 */
void ksmbd_notify_cleanup_file(struct ksmbd_file *fp)
{
	struct ksmbd_work *work, *tmp;
	struct smb2_hdr *hdr;
	LIST_HEAD(cleanup_list);

	if (!fp || !ksmbd_notify_group)
		return;

	/*
	 * Collect CHANGE_NOTIFY works into a local list so we
	 * can drop fp->f_lock before doing I/O and freeing.
	 */
	spin_lock(&fp->f_lock);
	list_for_each_entry_safe(work, tmp,
				 &fp->blocked_works, fp_entry) {
		hdr = smb2_get_msg(work->request_buf);
		if (hdr->Command != SMB2_CHANGE_NOTIFY)
			continue;

		list_del_init(&work->fp_entry);
		list_add(&work->fp_entry, &cleanup_list);
	}
	spin_unlock(&fp->f_lock);

	/* Process collected entries without holding any spinlock */
	list_for_each_entry_safe(work, tmp, &cleanup_list, fp_entry) {
		list_del_init(&work->fp_entry);

		if (!work->cancel_argv)
			continue;

		{
			struct ksmbd_notify_watch *watch;
			struct smb2_notify_rsp *rsp;

			watch = work->cancel_argv[0];
			spin_lock(&watch->lock);
			if (!watch->completed) {
				watch->completed = true;
				watch->pending_work = NULL;
				spin_unlock(&watch->lock);

				rsp = smb2_get_msg(
					work->response_buf);
				rsp->hdr.Status =
					STATUS_NOTIFY_CLEANUP;
				rsp->StructureSize =
					cpu_to_le16(9);
				rsp->OutputBufferOffset =
					cpu_to_le16(0);
				rsp->OutputBufferLength =
					cpu_to_le32(0);

				if (!ksmbd_iov_pin_rsp(work,
				    rsp,
				    sizeof(struct smb2_notify_rsp)
				    - 1))
					ksmbd_conn_write(work);

				ksmbd_conn_try_dequeue_request(work);
				ksmbd_free_work_struct(work);
			} else {
				spin_unlock(&watch->lock);
			}

			fsnotify_destroy_mark(&watch->mark,
					      ksmbd_notify_group);
		}
	}
}

/* ------------------------------------------------------------------ */
/*  Module lifecycle                                                   */
/* ------------------------------------------------------------------ */

/**
 * ksmbd_notify_init() - initialise the change-notify subsystem
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_notify_init(void)
{
	ksmbd_notify_group = fsnotify_alloc_group(
		&ksmbd_notify_ops, KSMBD_FSNOTIFY_GROUP_FLAGS);
	if (IS_ERR(ksmbd_notify_group)) {
		int ret = PTR_ERR(ksmbd_notify_group);

		pr_err("ksmbd: failed to allocate fsnotify group: %d\n", ret);
		ksmbd_notify_group = NULL;
		return ret;
	}

	pr_info("ksmbd: CHANGE_NOTIFY subsystem initialised\n");
	return 0;
}

/**
 * ksmbd_notify_exit() - tear down the change-notify subsystem
 */
void ksmbd_notify_exit(void)
{
	if (ksmbd_notify_group) {
		fsnotify_put_group(ksmbd_notify_group);
		ksmbd_notify_group = NULL;
	}
}
