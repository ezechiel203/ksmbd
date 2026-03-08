// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   SMB2 CHANGE_NOTIFY implementation using Linux fsnotify.
 *
 *   Design: one fsnotify_mark per (group, inode).  Multiple
 *   CHANGE_NOTIFY requests on the same directory are tracked
 *   via fp->blocked_works.  When fsnotify fires, the handler
 *   walks blocked_works and completes all matching entries.
 *   Only the first watch per inode gets a real fsnotify mark;
 *   subsequent watches on the same inode piggyback on it.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/fsnotify_backend.h>
#include <linux/version.h>
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define VISIBLE_IF_KUNIT static
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

#include "glob.h"
#include "smb2pdu.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "vfs_cache.h"
#include "connection.h"
#include "server.h"
#include "ksmbd_notify.h"
#include "misc.h"
#include "mgmt/user_session.h"
#include "smb_common.h"
#include "smb1pdu.h"

/* Forward declarations (defined later in this file) */
static void ksmbd_notify_send_delete_pending(struct ksmbd_work *work);
static void ksmbd_notify_batch_work_fn(struct work_struct *w);
static void ksmbd_notify_build_response_from_buffer(
		struct ksmbd_notify_watch *watch);
static bool ksmbd_notify_watch_get(struct ksmbd_notify_watch *watch);
static void ksmbd_notify_watch_put(struct ksmbd_notify_watch *watch);
static void ksmbd_notify_schedule_batch_work(struct ksmbd_notify_watch *watch);

static struct ksmbd_conn *ksmbd_notify_detach_work_conn_ref(
		struct ksmbd_work *work)
{
	if (!work || !work->notify_conn_ref || !work->conn)
		return NULL;

	work->notify_conn_ref = false;
	return work->conn;
}

/* Batching delay: wait this many ms after first event to accumulate
 * rapid sequential changes (e.g. unlink + create + write) so they
 * are all returned in one CHANGE_NOTIFY response. */
#define KSMBD_NOTIFY_BATCH_MS 10
#define KSMBD_NOTIFY_TREE_BATCH_MS 100

/*
 * fsnotify group flags differ across kernel versions.
 */
#ifdef FSNOTIFY_GROUP_NOFS
#define KSMBD_FSNOTIFY_GROUP_FLAGS FSNOTIFY_GROUP_NOFS
#else
#define KSMBD_FSNOTIFY_GROUP_FLAGS FSNOTIFY_GROUP_USER
#endif

/* Global fsnotify group for all ksmbd watches */
static struct fsnotify_group *ksmbd_notify_group;

/* Limit total concurrent notify watches server-wide */
#define KSMBD_MAX_NOTIFY_WATCHES	4096

/* Limit per-connection to prevent memory DoS */
#define KSMBD_MAX_NOTIFY_WATCHES_PER_CONN	1024

/*
 * M-13: MS-SMB2 §3.3.5.19 — per-handle CHANGE_NOTIFY limit.
 * A single authenticated client must not exhaust server resources by
 * issuing unlimited concurrent NOTIFY requests on one file handle.
 */
#define KSMBD_MAX_NOTIFY_PER_HANDLE	4
#define KSMBD_NOTIFY_UTF16_TMP_UNITS	((NAME_MAX * 2) + 2)
#define KSMBD_NOTIFY_ALL_FILTERS	0xFFF
#define KSMBD_NOTIFY_SMB1_PARAM_OFFSET	(offsetof(struct smb_com_nt_transact_rsp, Pad) - 4)

enum ksmbd_notify_proto {
	KSMBD_NOTIFY_PROTO_NONE = 0,
	KSMBD_NOTIFY_PROTO_SMB1,
	KSMBD_NOTIFY_PROTO_SMB2,
};

static enum ksmbd_notify_proto
ksmbd_notify_work_proto(struct ksmbd_work *work);
static bool ksmbd_notify_is_change_notify_work(struct ksmbd_work *work);

/*
 * ksmbd_notify_count_handle_works() - count pending NOTIFY works on @fp.
 * Called under fp->f_lock.
 */
static int ksmbd_notify_count_handle_works(struct ksmbd_file *fp)
{
	struct ksmbd_work *w;
	int cnt = 0;

	list_for_each_entry(w, &fp->blocked_works, fp_entry) {
		if (ksmbd_notify_is_change_notify_work(w))
			cnt++;
	}
	return cnt;
}

/*
 * ksmbd_notify_has_queued_waiter() - true if @fp has another queued
 * CHANGE_NOTIFY work beyond @pending_work.
 * Called without watch->lock held.
 */
static bool ksmbd_notify_has_queued_waiter(struct ksmbd_file *fp,
					   struct ksmbd_work *pending_work)
{
	struct ksmbd_work *w;
	bool queued = false;

	if (!fp)
		return false;

	spin_lock(&fp->f_lock);
	list_for_each_entry(w, &fp->blocked_works, fp_entry) {
		if (w == pending_work)
			continue;
		if (!ksmbd_notify_is_change_notify_work(w))
			continue;
		queued = true;
		break;
	}
	spin_unlock(&fp->f_lock);

	return queued;
}

static void ksmbd_notify_apply_work_params(struct ksmbd_notify_watch *watch,
					   struct ksmbd_work *work)
{
	struct smb_com_ntransact_req *smb1_req;
	struct smb2_notify_req *smb2_req;
	u32 param_off;
	char *params;

	if (!watch || !work || !work->request_buf)
		return;

	switch (ksmbd_notify_work_proto(work)) {
	case KSMBD_NOTIFY_PROTO_SMB1:
		smb1_req = work->request_buf;
		param_off = le32_to_cpu(smb1_req->ParameterOffset);
		if (le32_to_cpu(smb1_req->ParameterCount) < 8 ||
		    param_off + 8 > get_rfc1002_len(work->request_buf) +
				    RFC1002_HEADER_LEN)
			return;

		params = (char *)smb1_req + param_off;
		watch->watch_tree = params[6] != 0;
		watch->buffer_tree |= watch->watch_tree;
		watch->output_buf_len = le32_to_cpu(smb1_req->MaxDataCount);
		return;
	case KSMBD_NOTIFY_PROTO_SMB2:
		smb2_req = smb2_get_msg(work->request_buf);
		watch->watch_tree = le16_to_cpu(smb2_req->Flags) & SMB2_WATCH_TREE;
		watch->buffer_tree |= watch->watch_tree;
		watch->output_buf_len = le32_to_cpu(smb2_req->OutputBufferLength);
		return;
	default:
		return;
	}
}

static void ksmbd_notify_purge_tree_rename_duplicate(
		struct ksmbd_notify_watch *watch)
{
	struct ksmbd_notify_change *chg, *tmp;

	if (!watch || !watch->tree_rename_suppress_len)
		return;

	list_for_each_entry_safe(chg, tmp, &watch->buffered_changes, entry) {
		if (chg->name_len != (size_t)watch->tree_rename_suppress_len)
			continue;
		if (memcmp(chg->name, watch->tree_rename_suppress_name,
			   chg->name_len))
			continue;
		list_del(&chg->entry);
		kfree(chg->name);
		kfree(chg);
		watch->buffered_count--;
	}
}

static atomic_t notify_watch_count = ATOMIC_INIT(0);

static enum ksmbd_notify_proto
ksmbd_notify_work_proto(struct ksmbd_work *work)
{
	struct smb_com_ntransact_req *smb1_req;

	if (!work || !work->request_buf || !work->conn || !work->conn->ops)
		return KSMBD_NOTIFY_PROTO_NONE;

	switch (work->conn->ops->get_cmd_val(work)) {
	case SMB2_CHANGE_NOTIFY_HE:
		return KSMBD_NOTIFY_PROTO_SMB2;
	case SMB_COM_NT_TRANSACT:
		smb1_req = work->request_buf;
		if (le16_to_cpu(smb1_req->Function) == NT_TRANSACT_NOTIFY_CHANGE)
			return KSMBD_NOTIFY_PROTO_SMB1;
		break;
	}

	return KSMBD_NOTIFY_PROTO_NONE;
}

static bool ksmbd_notify_is_change_notify_work(struct ksmbd_work *work)
{
	return ksmbd_notify_work_proto(work) != KSMBD_NOTIFY_PROTO_NONE;
}

static unsigned int ksmbd_notify_sign_command(struct ksmbd_work *work)
{
	switch (ksmbd_notify_work_proto(work)) {
	case KSMBD_NOTIFY_PROTO_SMB1:
		return SMB_COM_NT_TRANSACT;
	case KSMBD_NOTIFY_PROTO_SMB2:
		return SMB2_CHANGE_NOTIFY_HE;
	default:
		return 0;
	}
}

static bool ksmbd_notify_should_sign(struct ksmbd_work *work)
{
	unsigned int command;

	if (!work || !work->sess || !work->conn || !work->conn->ops)
		return false;

	if (work->sess->sign)
		return true;

	if (!work->request_buf)
		return false;

	command = ksmbd_notify_sign_command(work);
	if (!command)
		return false;

	return work->conn->ops->is_sign_req(work, command);
}

static size_t ksmbd_notify_rsp_overhead(struct ksmbd_work *work)
{
	switch (ksmbd_notify_work_proto(work)) {
	case KSMBD_NOTIFY_PROTO_SMB1:
		return RFC1002_HEADER_LEN + ALIGN(KSMBD_NOTIFY_SMB1_PARAM_OFFSET, 4);
	case KSMBD_NOTIFY_PROTO_SMB2:
		return RFC1002_HEADER_LEN + __SMB2_HEADER_STRUCTURE_SIZE +
			sizeof(((struct smb2_notify_rsp *)0)->StructureSize) +
			sizeof(((struct smb2_notify_rsp *)0)->OutputBufferOffset) +
			sizeof(((struct smb2_notify_rsp *)0)->OutputBufferLength);
	default:
		return 0;
	}
}

static u8 *ksmbd_notify_rsp_data(struct ksmbd_work *work)
{
	return (u8 *)work->response_buf + ksmbd_notify_rsp_overhead(work);
}

static int ksmbd_notify_finalize_success_rsp(struct ksmbd_work *work,
					     size_t data_len)
{
	struct smb2_notify_rsp *smb2_rsp;

	switch (ksmbd_notify_work_proto(work)) {
	case KSMBD_NOTIFY_PROTO_SMB1:
		smb_build_ntransact_rsp(work, 0, data_len);
		return get_rfc1002_len(work->response_buf) + RFC1002_HEADER_LEN;
	case KSMBD_NOTIFY_PROTO_SMB2:
		smb2_rsp = smb2_get_msg(work->response_buf);
		smb2_rsp->hdr.Status = STATUS_SUCCESS;
		smb2_rsp->StructureSize = cpu_to_le16(9);
		smb2_rsp->OutputBufferOffset = cpu_to_le16(
			sizeof(struct smb2_hdr) +
			sizeof(smb2_rsp->StructureSize) +
			sizeof(smb2_rsp->OutputBufferOffset) +
			sizeof(smb2_rsp->OutputBufferLength));
		smb2_rsp->OutputBufferLength = cpu_to_le32(data_len);
		return __SMB2_HEADER_STRUCTURE_SIZE +
			sizeof(smb2_rsp->StructureSize) +
			sizeof(smb2_rsp->OutputBufferOffset) +
			sizeof(smb2_rsp->OutputBufferLength) + data_len;
	default:
		return -EINVAL;
	}
}

static int ksmbd_notify_build_status_rsp(struct ksmbd_work *work, __le32 status)
{
	struct smb2_notify_rsp *smb2_rsp;
	struct smb_com_ntransact_rsp *smb1_rsp;

	switch (ksmbd_notify_work_proto(work)) {
	case KSMBD_NOTIFY_PROTO_SMB1:
		smb1_rsp = work->response_buf;
		smb_build_ntransact_rsp(work, 0, 0);
		smb1_rsp->hdr.Status.CifsError = status;
		return get_rfc1002_len(work->response_buf) + RFC1002_HEADER_LEN;
	case KSMBD_NOTIFY_PROTO_SMB2:
		smb2_rsp = smb2_get_msg(work->response_buf);
		smb2_rsp->hdr.Status = status;
		smb2_rsp->StructureSize = cpu_to_le16(9);
		smb2_rsp->OutputBufferOffset = cpu_to_le16(0);
		smb2_rsp->OutputBufferLength = cpu_to_le32(0);
		return __SMB2_HEADER_STRUCTURE_SIZE + SMB2_ERROR_STRUCTURE_SIZE2;
	default:
		return -EINVAL;
	}
}

static void ksmbd_notify_prepare_async_rsp(struct ksmbd_work *work)
{
	struct smb2_notify_rsp *rsp;

	if (ksmbd_notify_work_proto(work) != KSMBD_NOTIFY_PROTO_SMB2)
		return;

	rsp = smb2_get_msg(work->response_buf);
	rsp->hdr.Flags |= SMB2_FLAGS_ASYNC_COMMAND;
	rsp->hdr.Id.AsyncId = cpu_to_le64(work->async_id);
}

/*
 * Mask of all fsnotify events we care about.
 */
#define KSMBD_FSNOTIFY_MASK	(FS_CREATE | FS_DELETE | FS_MODIFY |	\
				 FS_MOVED_FROM | FS_MOVED_TO |		\
				 FS_ATTRIB | FS_ACCESS |		\
				 FS_EVENT_ON_CHILD)

/*
 * FILE_NOTIFY_INFORMATION on-wire structure (MS-FSCC 2.4.42).
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

static u32 ksmbd_fsnotify_to_smb2_filter(u32 mask)
{
	u32 filter = 0;

	/*
	 * Windows maps FS_CREATE/FS_DELETE to only FILE_NAME or DIR_NAME
	 * depending on whether the event is on a directory (FS_ISDIR set)
	 * or a regular file.  Unlike rename/move, creation and deletion do
	 * NOT trigger ATTRIBUTES, LAST_WRITE, SIZE, etc. watchers.  The
	 * MS-SMB2 mask-change test confirms: a file created (FS_CREATE)
	 * while filter=ATTRIBUTES is pending must NOT trigger that watcher;
	 * only a subsequent explicit attribute-change (FS_ATTRIB) fires it.
	 *
	 * FS_MOVED_FROM/TO still map to ALL_FILTERS because renames affect
	 * the directory entry (name), attribute timestamps, size bookkeeping,
	 * etc. on both source and destination.
	 */
	if (mask & FS_CREATE) {
		if (mask & FS_ISDIR)
			filter |= FILE_NOTIFY_CHANGE_DIR_NAME;
		else
			filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
	}
	if (mask & FS_DELETE) {
		if (mask & FS_ISDIR)
			filter |= FILE_NOTIFY_CHANGE_DIR_NAME;
		else
			filter |= FILE_NOTIFY_CHANGE_FILE_NAME;
	}
	/*
	 * FS_CREATE/FS_DELETE frequently arrive with side-band fsnotify bits
	 * from ksmbd's own xattr and inode timestamp updates.  Windows still
	 * treats those operations as name-only notifications, so do not let a
	 * create/delete satisfy ATTRIBUTES/LAST_WRITE/SIZE/STREAM watches.
	 */
	if (!(mask & (FS_CREATE | FS_DELETE))) {
		if (mask & FS_MODIFY)
			filter |= FILE_NOTIFY_CHANGE_LAST_WRITE |
				  FILE_NOTIFY_CHANGE_SIZE;
		if (mask & FS_ATTRIB)
			filter |= FILE_NOTIFY_CHANGE_ATTRIBUTES |
				  FILE_NOTIFY_CHANGE_SECURITY |
				  FILE_NOTIFY_CHANGE_EA;
		/* CN-03: MS-FSCC §2.4.42 — stream change bits (0x200/0x400/0x800).
		 * FS_ATTRIB fires when named stream attributes change; FS_MODIFY
		 * fires when stream content or size changes.  Map both to the
		 * stream filter bits so clients watching for stream events get
		 * completions.
		 */
		if (mask & FS_ATTRIB)
			filter |= FILE_NOTIFY_CHANGE_STREAM_NAME;
		if (mask & FS_MODIFY)
			filter |= FILE_NOTIFY_CHANGE_STREAM_SIZE |
				  FILE_NOTIFY_CHANGE_STREAM_WRITE;
	}
	if (mask & FS_MOVED_FROM)
		filter |= KSMBD_NOTIFY_ALL_FILTERS;
	if (mask & FS_MOVED_TO)
		filter |= KSMBD_NOTIFY_ALL_FILTERS;
	if (!(mask & (FS_CREATE | FS_DELETE)) && (mask & FS_ACCESS))
		filter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;

	return filter;
}

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
	return FILE_ACTION_MODIFIED;
}

static u32 ksmbd_notify_calc_fs_mask(void)
{
	return KSMBD_FSNOTIFY_MASK | FS_DELETE_SELF;
}

VISIBLE_IF_KUNIT
bool ksmbd_notify_take_work(struct ksmbd_work *work, int state)
{
	return cmpxchg(&work->state, KSMBD_WORK_ACTIVE, state) ==
	       KSMBD_WORK_ACTIVE;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_notify_take_work);

struct ksmbd_notify_tree_flush {
	struct list_head		entry;
	struct ksmbd_notify_watch	*watch;
};

VISIBLE_IF_KUNIT
bool ksmbd_notify_claim_cancel_work(struct ksmbd_work *work)
{
	int prev;

	prev = cmpxchg(&work->state, KSMBD_WORK_ACTIVE,
		       KSMBD_WORK_CANCELLED);
	return prev == KSMBD_WORK_ACTIVE || prev == KSMBD_WORK_CANCELLED;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_notify_claim_cancel_work);

static void ksmbd_notify_release_changes(struct ksmbd_notify_watch *watch)
{
	struct ksmbd_notify_change *chg, *tmp;

	list_for_each_entry_safe(chg, tmp, &watch->buffered_changes, entry) {
		list_del(&chg->entry);
		kfree(chg->name);
		kfree(chg);
	}
	watch->buffered_count = 0;
	kfree(watch->rename_old_name);
	watch->rename_old_name = NULL;
	watch->rename_cookie = 0;
	watch->rename_old_len = 0;
}

static struct ksmbd_notify_watch *
ksmbd_notify_get_file_watch(struct ksmbd_file *fp)
{
	struct ksmbd_notify_watch *watch;

	if (!fp)
		return NULL;

	spin_lock(&fp->f_lock);
	watch = fp->notify_watch;
	if (watch && !ksmbd_notify_watch_get(watch))
		watch = NULL;
	spin_unlock(&fp->f_lock);

	return watch;
}

static void ksmbd_notify_set_file_watch(struct ksmbd_file *fp,
					struct ksmbd_notify_watch *watch)
{
	if (!fp)
		return;

	spin_lock(&fp->f_lock);
	fp->notify_watch = watch;
	spin_unlock(&fp->f_lock);
}

static struct ksmbd_notify_watch *
ksmbd_notify_detach_file_watch(struct ksmbd_file *fp)
{
	struct ksmbd_notify_watch *watch = NULL;

	if (!fp)
		return NULL;

	spin_lock(&fp->f_lock);
	watch = fp->notify_watch;
	fp->notify_watch = NULL;
	spin_unlock(&fp->f_lock);

	return watch;
}

static char *ksmbd_notify_relative_name(struct ksmbd_share_config *share,
					const struct path *watch_path,
					const char *full_name)
{
	char *watch_name;
	const char *relative;
	size_t watch_len;

	if (!share || !watch_path || !full_name)
		return ERR_PTR(-EINVAL);

	watch_name = convert_to_nt_pathname(share, watch_path);
	if (IS_ERR(watch_name))
		return watch_name;

	watch_len = strlen(watch_name);
	if (!strcmp(watch_name, "\\")) {
		relative = (*full_name == '\\') ? full_name + 1 : full_name;
	} else if (!strncmp(full_name, watch_name, watch_len) &&
		   full_name[watch_len] == '\\') {
		relative = full_name + watch_len + 1;
	} else {
		kfree(watch_name);
		return ERR_PTR(-EINVAL);
	}

	if (!*relative) {
		kfree(watch_name);
		return ERR_PTR(-EINVAL);
	}

	watch_len = strlen(relative);
	kfree(watch_name);
	return kstrndup(relative, watch_len, KSMBD_DEFAULT_GFP);
}

static void ksmbd_notify_tree_queue_one(struct ksmbd_notify_watch *watch,
					u32 smb2_filter,
					u32 action,
					const char *name,
					struct list_head *flush_list)
{
	struct ksmbd_notify_change *chg = NULL;
	char *copy_name = NULL;
	size_t name_len;
	u32 effective_action = action;
	bool queued = false;
	bool flush_pending = false;
	bool nested_name;

	if (!watch || !name)
		return;

	name_len = strlen(name);
	if (!name_len)
		return;
	nested_name = strchr(name, '\\') != NULL;

	copy_name = kstrndup(name, name_len, GFP_ATOMIC);
	if (!copy_name)
		return;

	chg = kzalloc(sizeof(*chg), GFP_ATOMIC);
	if (!chg) {
		kfree(copy_name);
		return;
	}

	spin_lock(&watch->lock);
	if (watch->detached || !watch->fp || !watch->buffer_tree)
		goto out_unlock;

	if (!(watch->completion_filter &
	      (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME))) {
		bool rename_drop =
			effective_action == FILE_ACTION_RENAMED_OLD_NAME ||
			(smb2_filter == KSMBD_NOTIFY_ALL_FILTERS &&
			 effective_action == FILE_ACTION_REMOVED);
		bool rename_add =
			effective_action == FILE_ACTION_RENAMED_NEW_NAME ||
			(smb2_filter == KSMBD_NOTIFY_ALL_FILTERS &&
			 effective_action == FILE_ACTION_ADDED);

		if (rename_add && !nested_name)
			goto out_unlock;
		if (nested_name && (rename_drop || rename_add))
			goto out_unlock;
		if (rename_drop)
			goto out_unlock;
		if (rename_add) {
			effective_action = FILE_ACTION_MODIFIED;
			if (!nested_name) {
				size_t slen = min_t(size_t, name_len, NAME_MAX);

				memcpy(watch->tree_rename_suppress_name,
				       name, slen);
				watch->tree_rename_suppress_len = (u8)slen;
				memcpy(watch->rename_suppress_name, name, slen);
				watch->rename_suppress_len = (u8)slen;
			}
		}
	}

	if (!(smb2_filter & watch->completion_filter))
		goto out_unlock;

	if (watch->buffered_count >= 256)
		goto maybe_flush;

	chg->action = effective_action;
	chg->name = copy_name;
	chg->name_len = name_len;
	list_add_tail(&chg->entry, &watch->buffered_changes);
	watch->buffered_count++;
	queued = true;
	copy_name = NULL;
	chg = NULL;

maybe_flush:
	if (queued && watch->pending_work && !watch->completed) {
		if (watch->watch_tree &&
		    !ksmbd_notify_has_queued_waiter(watch->fp,
						    watch->pending_work)) {
			ksmbd_notify_schedule_batch_work(watch);
		} else if (flush_list && ksmbd_notify_watch_get(watch)) {
			struct ksmbd_notify_tree_flush *flush;
			bool already = false;
			struct ksmbd_notify_tree_flush *iter;

			list_for_each_entry(iter, flush_list, entry) {
				if (iter->watch == watch) {
					already = true;
					break;
				}
			}
			if (already) {
				ksmbd_notify_watch_put(watch);
			} else {
				flush = kzalloc(sizeof(*flush), GFP_ATOMIC);
				if (flush) {
					flush->watch = watch;
					list_add_tail(&flush->entry, flush_list);
					flush_pending = true;
				} else {
					ksmbd_notify_watch_put(watch);
				}
			}
		}
		if (!flush_pending && flush_list) {
			/* nothing to do */
		}
	}

out_unlock:
	spin_unlock(&watch->lock);
	kfree(copy_name);
	kfree(chg);
}

static void ksmbd_notify_tree_flush_pending(struct list_head *flush_list)
{
	struct ksmbd_notify_tree_flush *flush, *tmp;

	list_for_each_entry_safe(flush, tmp, flush_list, entry) {
		list_del(&flush->entry);
		ksmbd_notify_build_response_from_buffer(flush->watch);
		ksmbd_notify_watch_put(flush->watch);
		kfree(flush);
	}
}

static void ksmbd_notify_tree_collect(
				      const struct ksmbd_share_config *share_conf,
				      const struct path *parent_path,
				      const char *full_name,
				      bool include_self,
				      u32 smb2_filter,
				      u32 action,
				      struct list_head *flush_list)
{
	struct dentry *ancestor, *next;
	struct dentry *share_root;

	if (!share_conf || !parent_path ||
	    !parent_path->dentry || !full_name)
		return;

	share_root = share_conf->vfs_path.dentry;
	if (!include_self && parent_path->dentry == share_root)
		return;

	ancestor = include_self ? dget(parent_path->dentry) :
				  dget_parent(parent_path->dentry);
	while (ancestor) {
		struct ksmbd_inode *ci;
		struct ksmbd_file *fp;
		struct path watch_path = {
			.mnt = parent_path->mnt,
			.dentry = ancestor,
		};
		char *relative_name;

		relative_name = ksmbd_notify_relative_name(
			(struct ksmbd_share_config *)share_conf,
			&watch_path, full_name);
		if (!IS_ERR(relative_name)) {
			ci = ksmbd_inode_lookup_lock(ancestor);
			if (ci) {
				down_read(&ci->m_lock);
				list_for_each_entry(fp, &ci->m_fp_list, node) {
					struct ksmbd_notify_watch *watch;

					watch = ksmbd_notify_get_file_watch(fp);
					if (!watch)
						continue;

					ksmbd_notify_tree_queue_one(watch,
								    smb2_filter,
								    action,
								    relative_name,
								    flush_list);
					ksmbd_notify_watch_put(watch);
				}
				up_read(&ci->m_lock);
				ksmbd_inode_put(ci);
			}
			kfree(relative_name);
		}

		if (ancestor == share_root) {
			dput(ancestor);
			break;
		}

		next = dget_parent(ancestor);
		if (next == ancestor) {
			dput(next);
			dput(ancestor);
			break;
		}
		dput(ancestor);
		ancestor = next;
	}
}

static void ksmbd_notify_free_watch(struct ksmbd_notify_watch *watch)
{
	cancel_delayed_work(&watch->batch_work);
	ksmbd_notify_release_changes(watch);
	atomic_dec(&notify_watch_count);
	if (watch->conn)
		atomic_dec(&watch->conn->notify_watch_count);
	kfree(watch);
}

static bool ksmbd_notify_watch_get(struct ksmbd_notify_watch *watch)
{
	return refcount_inc_not_zero(&watch->refs);
}

static void ksmbd_notify_watch_put(struct ksmbd_notify_watch *watch)
{
	if (refcount_dec_and_test(&watch->refs))
		ksmbd_notify_free_watch(watch);
}

VISIBLE_IF_KUNIT
size_t ksmbd_notify_max_data(struct ksmbd_work *work, u32 output_buf_len)
{
	size_t rsp_overhead;
	size_t max_data;

	if (!work)
		return 0;

	rsp_overhead = ksmbd_notify_rsp_overhead(work);
	if (work->response_sz <= rsp_overhead)
		return 0;

	max_data = work->response_sz - rsp_overhead;
	if (max_data > output_buf_len)
		max_data = output_buf_len;
	return max_data;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_notify_max_data);

static int ksmbd_notify_ensure_rsp_capacity(struct ksmbd_work *work,
					    u32 output_buf_len)
{
	size_t rsp_overhead;
	size_t needed;
	void *new_buf;

	if (!work || !work->response_buf)
		return -EINVAL;

	rsp_overhead = ksmbd_notify_rsp_overhead(work);
	needed = rsp_overhead + output_buf_len;
	if (work->response_sz >= needed)
		return 0;

	new_buf = kvzalloc(needed, KSMBD_DEFAULT_GFP);
	if (!new_buf)
		return -ENOMEM;

	memcpy(new_buf, work->response_buf, work->response_sz);
	kvfree(work->response_buf);
	work->response_buf = new_buf;
	work->response_sz = needed;
	return 0;
}

static int ksmbd_notify_encode_name(__le16 *target, size_t target_units,
				    const char *source, size_t source_len,
				    const struct nls_table *nls)
{
	size_t max_src;
	int units;

	if (!target || target_units < 2)
		return -ENOSPC;

	max_src = min_t(size_t, source_len, (target_units - 2) / 2);
	units = smbConvertToUTF16(target, source, max_src, nls, 0);
	if (units < 0)
		return units;
	if ((size_t)units > target_units)
		return -ENOSPC;
	return units * sizeof(__le16);
}

VISIBLE_IF_KUNIT
bool ksmbd_notify_mark_can_destroy(struct ksmbd_notify_watch *watch,
				   struct fsnotify_group *group)
{
	bool attached, alive, same_group;
	struct fsnotify_mark_connector *connector;

	if (!watch || !watch->has_mark || !group)
		return false;

	spin_lock(&watch->mark.lock);
	same_group = watch->mark.group == group;
	alive = watch->mark.flags & FSNOTIFY_MARK_FLAG_ALIVE;
	attached = watch->mark.flags & FSNOTIFY_MARK_FLAG_ATTACHED;
	connector = watch->mark.connector;
	spin_unlock(&watch->mark.lock);

	return same_group && alive && attached && connector;
}
EXPORT_SYMBOL_IF_KUNIT(ksmbd_notify_mark_can_destroy);

static bool ksmbd_notify_begin_primary_mark_cleanup(
		struct ksmbd_notify_watch *watch)
{
	if (!watch->has_mark || watch->mark_cleanup_started)
		return false;

	watch->detached = true;
	watch->mark_cleanup_started = true;
	return true;
}

static void ksmbd_notify_cancel_batch_work(struct ksmbd_notify_watch *watch)
{
	if (current_work() == &watch->batch_work.work)
		cancel_delayed_work(&watch->batch_work);
	else
		cancel_delayed_work_sync(&watch->batch_work);
}

static void ksmbd_notify_schedule_batch_work(struct ksmbd_notify_watch *watch)
{
	mod_delayed_work(system_wq, &watch->batch_work,
			 msecs_to_jiffies(watch->watch_tree ?
					  KSMBD_NOTIFY_TREE_BATCH_MS :
					  KSMBD_NOTIFY_BATCH_MS));
}

static void ksmbd_notify_unlink_async_request(struct ksmbd_work *work)
{
	if (!work || !work->conn)
		return;

	spin_lock(&work->conn->request_lock);
	if (!list_empty(&work->async_request_entry))
		list_del_init(&work->async_request_entry);
	spin_unlock(&work->conn->request_lock);
}


/* ------------------------------------------------------------------ */
/*  Build FILE_NOTIFY_INFORMATION buffer and complete async work       */
/* ------------------------------------------------------------------ */

/*
 * Build a multi-record CHANGE_NOTIFY response from all events currently
 * buffered in watch->buffered_changes.  Called by the batching timer so
 * that rapid sequential events (e.g. unlink + create + write) are all
 * delivered in one response rather than one per event.
 */
static void ksmbd_notify_build_response_from_buffer(
		struct ksmbd_notify_watch *watch)
{
	struct ksmbd_work *work;
	LIST_HEAD(flush_list);
	struct ksmbd_notify_change *chg, *chg_tmp;
	u8 *buf_start, *cur;
	size_t max_data, total_written = 0;
	struct file_notify_information *prev_info = NULL;
	int total_rsp_len;
	bool overflow = false;

	spin_lock(&watch->lock);
	work = watch->pending_work;
	if (!work || watch->completed) {
		spin_unlock(&watch->lock);
		return;
	}
	watch->completed = true;
	/*
	 * Clear pending_work immediately — before releasing the lock — so
	 * that a concurrent ksmbd_notify_cleanup_file() sees NULL and does
	 * NOT try to call ksmbd_notify_send_cleanup() on the same work,
	 * which would cause a double-free of the work struct and a double
	 * ksmbd_user_session_put() leading to refcount underflow.
	 */
	watch->pending_work = NULL;
	if (work->conn)
		refcount_inc(&work->conn->refcnt);

	/* Steal all buffered events atomically */
	list_splice_init(&watch->buffered_changes, &flush_list);
	watch->buffered_count = 0;
	spin_unlock(&watch->lock);

	if (list_empty(&flush_list)) {
		/*
		 * Timer fired but no events were buffered — revert.
		 * Restore pending_work so the watch is still armed for
		 * the next event.
		 */
		spin_lock(&watch->lock);
		watch->pending_work = work;
		watch->completed = false;
		spin_unlock(&watch->lock);
		if (work->conn)
			ksmbd_conn_free(work->conn);
		return;
	}

	/* Reset IOV state (same as ksmbd_notify_build_response) */
	kfree(work->tr_buf);
	work->tr_buf = NULL;
	work->iov_idx = 0;
	work->iov_cnt = 0;

	ksmbd_notify_ensure_rsp_capacity(work, watch->output_buf_len);
	ksmbd_notify_prepare_async_rsp(work);

	max_data = ksmbd_notify_max_data(work, watch->output_buf_len);
	buf_start = ksmbd_notify_rsp_data(work);
	cur = buf_start;

	list_for_each_entry_safe(chg, chg_tmp, &flush_list, entry) {
		struct file_notify_information *info;
		int name_len_bytes;
		size_t max_rem, rec_sz, rec_sz_al;
		__le16 tmp_name[KSMBD_NOTIFY_UTF16_TMP_UNITS];

		max_rem = (total_written < max_data) ?
			  max_data - total_written : 0;
		if (max_rem < sizeof(*info)) {
			overflow = true;
			break;
		}

		info = (struct file_notify_information *)cur;
		name_len_bytes = ksmbd_notify_encode_name(tmp_name,
							  ARRAY_SIZE(tmp_name),
							  chg->name,
							  chg->name_len,
							  work->conn->local_nls);
		if (name_len_bytes < 0)
			name_len_bytes = 0;

		rec_sz = sizeof(*info) + name_len_bytes;
		rec_sz_al = ALIGN(rec_sz, 4);

		if (rec_sz_al > max_rem) {
			overflow = true;
			break;
		}

		memcpy(info->FileName, tmp_name, name_len_bytes);
		info->Action = cpu_to_le32(chg->action);
		info->FileNameLength = cpu_to_le32(name_len_bytes);
		info->NextEntryOffset = cpu_to_le32(rec_sz_al);
		prev_info = info;
		cur += rec_sz_al;
		total_written += rec_sz_al;

		list_del(&chg->entry);
		kfree(chg->name);
		kfree(chg);
	}

	/* Free any events that didn't fit in the buffer */
	list_for_each_entry_safe(chg, chg_tmp, &flush_list, entry) {
		list_del(&chg->entry);
		kfree(chg->name);
		kfree(chg);
	}

	if (total_written == 0)
		overflow = true;

	if (overflow) {
		if (watch->output_buf_len) {
			spin_lock(&watch->lock);
			watch->enum_dir_sticky = true;
			spin_unlock(&watch->lock);
		}
		total_rsp_len = ksmbd_notify_build_status_rsp(work,
							      STATUS_NOTIFY_ENUM_DIR);
	} else {
		if (prev_info)
			prev_info->NextEntryOffset = 0;
		total_rsp_len = ksmbd_notify_finalize_success_rsp(work,
								  total_written);
	}

	if (ksmbd_iov_pin_rsp(work, work->response_buf, total_rsp_len))
		ksmbd_notify_build_status_rsp(work, STATUS_INSUFFICIENT_RESOURCES);

	if (ksmbd_notify_should_sign(work))
		work->conn->ops->set_sign_rsp(work);

	if (work->sess && work->conn && work->conn->ops &&
	    work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		int rc = work->conn->ops->encrypt_resp(work);

		if (rc < 0)
			pr_err_ratelimited(
				"ksmbd: notify batch encrypt failed: %d\n",
				rc);
	}

	work->send_no_response = 0;
	ksmbd_conn_write(work);

	if (watch->fp) {
		struct ksmbd_work *next_work = NULL;

		spin_lock(&watch->fp->f_lock);
		list_del_init(&work->fp_entry);
		/*
		 * Promote the next waiting CHANGE_NOTIFY work from
		 * fp->blocked_works to watch->pending_work so it will be
		 * completed by the next matching fsnotify event.  This
		 * implements sequential delivery: N requests on the same
		 * handle are served one at a time, oldest first.
		 */
		if (!list_empty(&watch->fp->blocked_works))
			next_work = list_first_entry(&watch->fp->blocked_works,
						     struct ksmbd_work,
						     fp_entry);
		spin_unlock(&watch->fp->f_lock);

		if (next_work) {
			/* fp->f_lock and watch->lock must not be held together */
			spin_lock(&watch->lock);
			if (!watch->pending_work) {
				watch->pending_work = next_work;
				ksmbd_notify_apply_work_params(watch, next_work);
				ksmbd_notify_purge_tree_rename_duplicate(watch);
			}
			spin_unlock(&watch->lock);
		}
	}

	ksmbd_notify_unlink_async_request(work);

	if (work->request_buf)
		ksmbd_conn_try_dequeue_request(work);

	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	/* pending_work was already cleared at the top of this function. */
	spin_lock(&watch->lock);
	watch->completed = false;
	spin_unlock(&watch->lock);

	if (work->sess)
		ksmbd_user_session_put(work->sess);

	{
		struct ksmbd_conn *conn = work->conn;
		struct ksmbd_conn *notify_conn;

		notify_conn = ksmbd_notify_detach_work_conn_ref(work);

		ksmbd_free_work_struct(work);
		/* Release the refcnt pin taken at the top of this function. */
		if (conn)
			ksmbd_conn_free(conn);
		if (notify_conn)
			ksmbd_conn_free(notify_conn);
	}
}

static void ksmbd_notify_batch_work_fn(struct work_struct *w)
{
	struct ksmbd_notify_watch *watch =
		container_of(to_delayed_work(w),
			     struct ksmbd_notify_watch, batch_work);

	ksmbd_notify_build_response_from_buffer(watch);
}

/*
 * CN-02: Build a paired rename response with OLD_NAME + NEW_NAME records
 * contiguous in the same CHANGE_NOTIFY response buffer (MS-FSCC §2.4.42).
 * @watch:    the notify watch (pending_work must be set)
 * @old_name: old (moved-from) filename string
 * @old_len:  length of old_name in chars (not bytes)
 * @new_name: new (moved-to) filename qstr
 */
static void ksmbd_notify_build_rename_response(
		struct ksmbd_notify_watch *watch,
		const char *old_name, size_t old_len,
		const struct qstr *new_name)
{
	struct ksmbd_work *work;
	struct file_notify_information *info_old, *info_new;
	int old_uni_len, new_uni_len;
	int old_info_len, new_info_len, total_info_len;
	int total_rsp_len;
	u8 *out;

	spin_lock(&watch->lock);
	work = watch->pending_work;
	if (!work || watch->completed) {
		spin_unlock(&watch->lock);
		return;
	}
	watch->completed = true;
	/* Clear pending_work immediately to prevent double-free race with cleanup. */
	watch->pending_work = NULL;
	/* Hold conn ref across the race window (same as build_response_from_buffer). */
	if (work->conn)
		refcount_inc(&work->conn->refcnt);
	spin_unlock(&watch->lock);

	kfree(work->tr_buf);
	work->tr_buf = NULL;
	work->iov_idx = 0;
	work->iov_cnt = 0;

	ksmbd_notify_ensure_rsp_capacity(work, watch->output_buf_len);
	ksmbd_notify_prepare_async_rsp(work);

	/*
	 * NOTIFY-07/09: compute max_data against the actual response buffer
	 * allocation to prevent heap overflow when client-supplied
	 * output_buf_len is large.  We need space for two FILE_NOTIFY_INFORMATION
	 * records (old name + new name).
	 */
	{
		size_t max_data = ksmbd_notify_max_data(work,
							watch->output_buf_len);
		__le16 tmp_name[KSMBD_NOTIFY_UTF16_TMP_UNITS];

		out = ksmbd_notify_rsp_data(work);

		/* Check if even the minimum (two empty records) fits */
		if (2 * sizeof(struct file_notify_information) > max_data ||
		    2 * sizeof(struct file_notify_information) > watch->output_buf_len) {
			total_rsp_len = ksmbd_notify_build_status_rsp(work,
							      STATUS_NOTIFY_ENUM_DIR);
			goto send;
		}

		info_old = (struct file_notify_information *)out;

		/*
		 * Encode old name into a temporary buffer first to determine
		 * its length before writing to the response buffer.
		 */
		old_uni_len = ksmbd_notify_encode_name(tmp_name,
						       ARRAY_SIZE(tmp_name),
						       old_name, old_len,
						       work->conn->local_nls);
		if (old_uni_len < 0)
			old_uni_len = 0;
		old_info_len = sizeof(struct file_notify_information) + old_uni_len;
		old_info_len = ALIGN(old_info_len, 4);

		/* Rough pre-check: at least one new record must fit after old */
		new_info_len = sizeof(struct file_notify_information) +
			       new_name->len * 2;
		total_info_len = old_info_len + new_info_len;

		if ((int)total_info_len > (int)watch->output_buf_len ||
		    (int)total_info_len > (int)max_data) {
			total_rsp_len = ksmbd_notify_build_status_rsp(work,
							      STATUS_NOTIFY_ENUM_DIR);
			goto send;
		}

		/* Safe to write old name now — bounds verified above */
		memcpy(info_old->FileName, tmp_name, old_uni_len);
		info_old->NextEntryOffset = cpu_to_le32(old_info_len);
		info_old->Action = cpu_to_le32(FILE_ACTION_RENAMED_OLD_NAME);
		info_old->FileNameLength = cpu_to_le32(old_uni_len);

		info_new = (struct file_notify_information *)(out + old_info_len);
		new_uni_len = ksmbd_notify_encode_name(tmp_name,
						       ARRAY_SIZE(tmp_name),
						       new_name->name,
						       new_name->len,
						       work->conn->local_nls);
		if (new_uni_len < 0)
			new_uni_len = 0;
		new_info_len = sizeof(struct file_notify_information) + new_uni_len;

		if ((int)(old_info_len + new_info_len) > (int)watch->output_buf_len ||
		    (int)(old_info_len + new_info_len) > (int)max_data) {
			total_rsp_len = ksmbd_notify_build_status_rsp(work,
							      STATUS_NOTIFY_ENUM_DIR);
			goto send;
		}

		/* Safe to write new name now */
		memcpy(info_new->FileName, tmp_name, new_uni_len);
		info_new->NextEntryOffset = cpu_to_le32(0);
		info_new->Action = cpu_to_le32(FILE_ACTION_RENAMED_NEW_NAME);
		info_new->FileNameLength = cpu_to_le32(new_uni_len);
	}

	total_info_len = old_info_len + new_info_len;
	total_rsp_len = ksmbd_notify_finalize_success_rsp(work, total_info_len);

send:
	if (ksmbd_iov_pin_rsp(work, work->response_buf, total_rsp_len))
		ksmbd_notify_build_status_rsp(work, STATUS_INSUFFICIENT_RESOURCES);

	if (ksmbd_notify_should_sign(work))
		work->conn->ops->set_sign_rsp(work);

	if (work->sess && work->conn && work->conn->ops &&
	    work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		int rc = work->conn->ops->encrypt_resp(work);

		if (rc < 0) {
			pr_err_ratelimited("ksmbd: notify rename encrypt failed: %d\n", rc);
			ksmbd_notify_build_status_rsp(work, STATUS_DATA_ERROR);
		}
	}

	work->send_no_response = 0;
	ksmbd_conn_write(work);

	if (watch->fp) {
		spin_lock(&watch->fp->f_lock);
		list_del_init(&work->fp_entry);
		spin_unlock(&watch->fp->f_lock);
	}

	ksmbd_notify_unlink_async_request(work);

	if (work->request_buf)
		ksmbd_conn_try_dequeue_request(work);

	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	/* pending_work was already cleared at the top of this function. */
	spin_lock(&watch->lock);
	watch->completed = false;
	spin_unlock(&watch->lock);

	if (work->sess)
		ksmbd_user_session_put(work->sess);

	{
		struct ksmbd_conn *conn = work->conn;
		struct ksmbd_conn *notify_conn;

		notify_conn = ksmbd_notify_detach_work_conn_ref(work);

		ksmbd_free_work_struct(work);
		/* Release the conn reference taken at the top of this function. */
		if (conn)
			ksmbd_conn_free(conn);
		if (notify_conn)
			ksmbd_conn_free(notify_conn);
	}
}

/**
 * ksmbd_notify_complete_piggyback() - complete a piggyback notify work
 * @work: the async work item from fp->blocked_works
 * @action: FILE_ACTION_* constant
 * @file_name: event filename
 *
 * Completes a CHANGE_NOTIFY work that does NOT own an fsnotify mark
 * (a "piggyback" watch).  These works get completed when the real
 * mark's event fires.
 */
static void ksmbd_notify_complete_piggyback(
		struct ksmbd_work *work,
		u32 action,
		const struct qstr *file_name)
{
	struct smb_com_ntransact_req *smb1_req;
	struct file_notify_information *info;
	int info_len;
	int total_rsp_len;
	int uni_len;
	u8 *out;
	size_t max_data;
	u32 output_buf_len;
	__le16 tmp_name[KSMBD_NOTIFY_UTF16_TMP_UNITS];

	if (!ksmbd_notify_take_work(work, KSMBD_WORK_CLOSED))
		return;

	switch (ksmbd_notify_work_proto(work)) {
	case KSMBD_NOTIFY_PROTO_SMB1:
		smb1_req = work->request_buf;
		output_buf_len = le32_to_cpu(smb1_req->MaxDataCount);
		break;
	case KSMBD_NOTIFY_PROTO_SMB2:
		output_buf_len = le32_to_cpu(
			((struct smb2_notify_req *)smb2_get_msg(work->request_buf))->OutputBufferLength);
		break;
	default:
		return;
	}

	max_data = ksmbd_notify_max_data(work, output_buf_len);
	ksmbd_notify_prepare_async_rsp(work);

	if (max_data < sizeof(struct file_notify_information)) {
		total_rsp_len = ksmbd_notify_build_status_rsp(work,
							      STATUS_NOTIFY_ENUM_DIR);
		goto send;
	}

	out = ksmbd_notify_rsp_data(work);
	info = (struct file_notify_information *)out;

	uni_len = ksmbd_notify_encode_name(tmp_name, ARRAY_SIZE(tmp_name),
					   file_name->name, file_name->len,
					   work->conn->local_nls);
	if (uni_len < 0)
		uni_len = 0;

	info_len = sizeof(struct file_notify_information) + uni_len;
	if (info_len > (int)max_data) {
		total_rsp_len = ksmbd_notify_build_status_rsp(work,
							      STATUS_NOTIFY_ENUM_DIR);
		goto send;
	}

	memcpy(info->FileName, tmp_name, uni_len);
	info->NextEntryOffset = cpu_to_le32(0);
	info->Action = cpu_to_le32(action);
	info->FileNameLength = cpu_to_le32(uni_len);

	total_rsp_len = ksmbd_notify_finalize_success_rsp(work, info_len);

send:
	if (ksmbd_iov_pin_rsp(work, work->response_buf, total_rsp_len))
		ksmbd_notify_build_status_rsp(work, STATUS_INSUFFICIENT_RESOURCES);

	/* Sign if required (before encryption) */
	if (ksmbd_notify_should_sign(work))
		work->conn->ops->set_sign_rsp(work);

	if (work->sess && work->conn && work->conn->ops &&
	    work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		int rc = work->conn->ops->encrypt_resp(work);

		if (rc < 0)
			ksmbd_notify_build_status_rsp(work, STATUS_DATA_ERROR);
	}

	/* Clear send_no_response so ksmbd_conn_write transmits */
	work->send_no_response = 0;
	ksmbd_conn_write(work);

	/* Remove from async_requests list before freeing */
	ksmbd_notify_unlink_async_request(work);

	/*
	 * Only dequeue from the request list if this work was
	 * a real request (has a request_buf).  Compound-spawned
	 * async work structs were never queued or counted.
	 */
	if (work->request_buf)
		ksmbd_conn_try_dequeue_request(work);

	/* Decrement outstanding async count */
	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	/* Drop the extra session reference taken in smb2_notify */
	if (work->sess)
		ksmbd_user_session_put(work->sess);

	{
		struct ksmbd_conn *notify_conn;

		notify_conn = ksmbd_notify_detach_work_conn_ref(work);
		ksmbd_free_work_struct(work);
		if (notify_conn)
			ksmbd_conn_free(notify_conn);
	}
}

/* ------------------------------------------------------------------ */
/*  fsnotify callbacks                                                 */
/* ------------------------------------------------------------------ */

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
	struct ksmbd_file *fp;
	struct ksmbd_work *work, *tmp;
	struct ksmbd_notify_watch *sec;
	u32 smb2_filter;
	u32 action;
	int type;
	bool primary_fired = false;
	bool primary_active;
	LIST_HEAD(complete_list);

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

	/*
	 * FS_DELETE_SELF: the watched directory itself was deleted.
	 * Complete any pending NOTIFY with STATUS_DELETE_PENDING.
	 */
	if (mask & FS_DELETE_SELF) {
		struct ksmbd_work *del_work;

		spin_lock(&watch->lock);
		del_work = watch->pending_work;
		if (!del_work || watch->completed) {
			spin_unlock(&watch->lock);
			return 0;
		}
		watch->completed = true;
		watch->pending_work = NULL;
		/*
		 * NOTIFY-UAF: hold a conn reference while the lock is still
		 * held so the conn cannot be freed before we call
		 * ksmbd_notify_send_delete_pending() below.  We drop this
		 * refcnt reference ourselves after the call returns (the
		 * function only releases r_count, not refcnt).
		 */
		if (del_work->conn)
			refcount_inc(&del_work->conn->refcnt);
		spin_unlock(&watch->lock);

		if (watch->fp) {
			spin_lock(&watch->fp->f_lock);
			list_del_init(&del_work->fp_entry);
			spin_unlock(&watch->fp->f_lock);
		}

		{
			struct ksmbd_conn *del_conn = del_work->conn;

			ksmbd_notify_send_delete_pending(del_work);
			/* del_work is freed; release the refcnt pin we took */
			if (del_conn)
				ksmbd_conn_free(del_conn);
		}
		return 0;
	}

	spin_lock(&watch->lock);
	if (watch->completed) {
		spin_unlock(&watch->lock);
		return 0;
	}
	fp = watch->fp;
	primary_active = fp != NULL;
	if (!primary_active && list_empty(&watch->secondary_watches)) {
		spin_unlock(&watch->lock);
		return 0;
	}

	/*
	 * Filter out self-events on the watched directory.
	 * FS_EVENT_ON_CHILD fires for both the child AND the parent
	 * directory inode.  We only want child events.
	 */
	{
		struct inode *event_inode;

		event_inode = fsnotify_data_inode(data, data_type);
		if (event_inode && fp->filp &&
		    event_inode == file_inode(fp->filp)) {
			spin_unlock(&watch->lock);
			return 0;
		}
	}

	smb2_filter = ksmbd_fsnotify_to_smb2_filter(mask);
	if (!file_name) {
		spin_unlock(&watch->lock);
		return 0;
	}

	action = ksmbd_fsnotify_to_action(mask);
	if (!primary_active) {
		spin_unlock(&watch->lock);
		goto handle_piggybacks;
	}

	/*
	 * MS-FSCC §2.4.42: if the file was removed via an explicit SMB
	 * delete operation (DELETE_ON_CLOSE or FileDispositionInformation),
	 * emit FILE_ACTION_REMOVED_BY_DELETE (0x9) instead of
	 * FILE_ACTION_REMOVED (0x2).
	 */
	if (action == FILE_ACTION_REMOVED) {
		struct dentry *event_de =
			fsnotify_data_dentry(data, data_type);

		if (event_de && ksmbd_inode_is_smb_delete(event_de))
			action = FILE_ACTION_REMOVED_BY_DELETE;
	}

	/*
	 * CN-RENAME-ATTR: When the completion_filter lacks FILE_NAME (0x1)
	 * and DIR_NAME (0x2), Windows delivers rename events as
	 * FILE_ACTION_MODIFIED rather than paired OLD_NAME/NEW_NAME records.
	 * With an ATTRS-only filter the client cares about attribute changes
	 * on the destination entry, not name-change semantics.
	 *
	 * - FS_MOVED_FROM: Drop entirely.  The source disappearance is
	 *   invisible to an ATTRS-only watcher.
	 * - FS_MOVED_TO: Convert to FILE_ACTION_MODIFIED so the new name
	 *   appears as an attribute change (MS-FSCC §2.4.42 note).
	 *
	 * FS_MOVED_FROM/TO both map to smb2_filter=ALL_FILTERS (0xFFF) so
	 * they would pass the completion_filter check.  We must convert
	 * BEFORE CN-02 to prevent saving a useless rename cookie.
	 */
	if (!(watch->completion_filter &
	      (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME))) {
		if ((action == FILE_ACTION_RENAMED_NEW_NAME ||
		     action == FILE_ACTION_ADDED) &&
		    watch->tree_rename_suppress_len > 0 &&
		    file_name->len ==
		    (size_t)watch->tree_rename_suppress_len &&
		    !memcmp(file_name->name,
			    watch->tree_rename_suppress_name,
			    file_name->len)) {
			watch->tree_rename_suppress_len = 0;
			spin_unlock(&watch->lock);
			return 0;
		}
		if (action == FILE_ACTION_RENAMED_OLD_NAME) {
			spin_unlock(&watch->lock);
			return 0;
		}
		if (action == FILE_ACTION_RENAMED_NEW_NAME) {
			action = FILE_ACTION_MODIFIED;
			/*
			 * CN-RENAME-ATTR-SUPPRESS: record the new name so we
			 * can suppress the spurious FS_ATTRIB that fires
			 * immediately after the rename (ctime update, close
			 * flush) — it is NOT a real attribute change and would
			 * prematurely complete the next pending NOTIFY work.
			 */
			{
				size_t slen = min_t(size_t, file_name->len,
						    NAME_MAX);

				memcpy(watch->rename_suppress_name,
				       file_name->name, slen);
				watch->rename_suppress_len = (u8)slen;
			}
		}
	}

	/*
	 * CN-02: Pair FS_MOVED_FROM (OLD_NAME) with FS_MOVED_TO (NEW_NAME)
	 * using the fsnotify cookie so both records are contiguous in the
	 * same CHANGE_NOTIFY response buffer (MS-FSCC §2.4.42).
	 *
	 * When MOVED_FROM arrives: save cookie + old filename.  Do NOT
	 * complete the pending work yet — wait for the matching MOVED_TO.
	 * When MOVED_TO arrives with matching cookie: emit a paired response.
	 * Unmatched MOVED_TO (different/no cookie): fall through to normal
	 * single-record response.
	 */
	if (action == FILE_ACTION_RENAMED_OLD_NAME && cookie &&
	    (smb2_filter & watch->completion_filter)) {
		/* Save old name, defer until MOVED_TO with matching cookie */
		kfree(watch->rename_old_name);
		watch->rename_old_name = kstrndup(file_name->name,
						  file_name->len, GFP_ATOMIC);
		watch->rename_old_len = file_name->len;
		watch->rename_cookie = cookie;
		spin_unlock(&watch->lock);
		return 0;
	}

	if (action == FILE_ACTION_RENAMED_NEW_NAME && cookie &&
	    watch->rename_cookie == cookie && watch->rename_old_name &&
	    (smb2_filter & watch->completion_filter)) {
		char *saved_old = watch->rename_old_name;
		size_t saved_len = watch->rename_old_len;
		bool batch_recursive = watch->pending_work && watch->watch_tree;
		size_t slen = min_t(size_t, file_name->len, NAME_MAX);

		watch->rename_old_name = NULL;
		watch->rename_cookie = 0;
		memcpy(watch->rename_suppress_name, file_name->name, slen);
		watch->rename_suppress_len = (u8)slen;

		if (watch->pending_work && !batch_recursive) {
			spin_unlock(&watch->lock);
			ksmbd_notify_build_rename_response(watch,
							   saved_old, saved_len,
							   file_name);
			kfree(saved_old);
			goto handle_piggybacks;
		}

		/*
		 * pw=NULL: buffer OLD_NAME + NEW_NAME so the next
		 * CHANGE_NOTIFY request drains them instead of losing the pair.
		 */
		if (watch->buffered_count + 2 <= 256) {
			struct ksmbd_notify_change *old_chg, *new_chg;

			old_chg = kzalloc(sizeof(*old_chg), GFP_ATOMIC);
			new_chg = kzalloc(sizeof(*new_chg), GFP_ATOMIC);
			if (old_chg && new_chg) {
				new_chg->name = kstrndup(file_name->name,
							 file_name->len,
							 GFP_ATOMIC);
				if (new_chg->name) {
					/* OLD_NAME entry takes ownership of saved_old */
					old_chg->action   = FILE_ACTION_RENAMED_OLD_NAME;
					old_chg->name     = saved_old;
					old_chg->name_len = saved_len;
					saved_old = NULL;

					new_chg->action   = FILE_ACTION_RENAMED_NEW_NAME;
					new_chg->name_len = file_name->len;

					list_add_tail(&old_chg->entry,
						      &watch->buffered_changes);
					list_add_tail(&new_chg->entry,
						      &watch->buffered_changes);
					watch->buffered_count += 2;
					if (batch_recursive && watch->pending_work &&
					    !watch->completed)
						ksmbd_notify_schedule_batch_work(watch);
				} else {
					kfree(old_chg);
					kfree(new_chg);
				}
			} else {
				kfree(old_chg);
				kfree(new_chg);
			}
		}
		spin_unlock(&watch->lock);
		kfree(saved_old); /* NULL if ownership transferred above */
		return 0;
	}

	/* Clear any stale pending rename if cookies don't match */
	if (action == FILE_ACTION_RENAMED_NEW_NAME &&
	    watch->rename_old_name) {
		kfree(watch->rename_old_name);
		watch->rename_old_name = NULL;
		watch->rename_cookie = 0;
	}

	if (action == FILE_ACTION_RENAMED_NEW_NAME && cookie &&
	    !watch->rename_old_name && watch->buffer_tree) {
		size_t slen = min_t(size_t, file_name->len, NAME_MAX);

		memcpy(watch->rename_suppress_name, file_name->name, slen);
		watch->rename_suppress_len = (u8)slen;
		spin_unlock(&watch->lock);
		return 0;
	}

	if (action == FILE_ACTION_RENAMED_NEW_NAME) {
		size_t slen = min_t(size_t, file_name->len, NAME_MAX);

		memcpy(watch->rename_suppress_name, file_name->name, slen);
		watch->rename_suppress_len = (u8)slen;
	}

	/*
	 * CN-RENAME-ATTR-SUPPRESS: suppress the first FS_ATTRIB that fires
	 * after a FS_MOVED_TO (rename) for the same filename.  This FS_ATTRIB
	 * is a side-effect of the rename — the VFS updates the inode's ctime
	 * and any pending timestamp flush on close.  It is NOT a real
	 * attribute change initiated by the client and must NOT prematurely
	 * complete the next pending CHANGE_NOTIFY work.
	 * One-shot: clear after first suppression so legitimate subsequent
	 * attribute changes (from a separate SET_INFO request) are delivered.
	 */
	if ((mask & FS_ATTRIB) && !(mask & FS_CREATE) &&
	    watch->rename_suppress_len > 0 &&
	    file_name->len == (size_t)watch->rename_suppress_len &&
	    !memcmp(file_name->name, watch->rename_suppress_name,
		    file_name->len)) {
		watch->rename_suppress_len = 0;
		spin_unlock(&watch->lock);
		return 0;
	}

	/*
	 * Suppress the spurious FS_ATTRIB that fires immediately after
	 * FS_CREATE (caused by smb2_new_xattrs() writing the DOS attribute
	 * xattr).  We record the FS_CREATE filename in create_suppress_name
	 * and suppress the first FS_ATTRIB for the same name.
	 * This prevents an unwanted FILE_ACTION_MODIFIED event from appearing
	 * before the client sees FILE_ACTION_ADDED (mask test CN-SUPPRESS).
	 */
	/*
	 * Suppress spurious FS_ATTRIB events that fire from the SAME ksmbd
	 * worker thread that processed the SMB2_CREATE (i.e. smb2_new_xattrs
	 * and posix-ACL initialisation).  Legitimate attribute changes from a
	 * subsequent SMB2_SET_INFO request always arrive from a DIFFERENT
	 * worker thread and are therefore never suppressed here.
	 *
	 * We do NOT clear create_suppress_len on suppression so that all
	 * spurious FS_ATTRIB events (DOS-attr xattr + POSIX ACL) are filtered,
	 * not just the first one.  The suppress window is bound to the worker
	 * PID; any FS_ATTRIB from a different PID passes through.
	 */
	/*
	 * CN-SUPPRESS: drop spurious FS_ATTRIB events generated by
	 * ksmbd's own xattr init writes (POSIX ACL, NT SD, DOS attrs)
	 * during SMB2_CREATE processing.
	 *
	 * Detection: the ksmbd worker that created the file sets
	 * work->notify_suppress=true before writing init xattrs and
	 * clears it afterwards.  We read this flag via current_work()
	 * to determine whether the current fsnotify callchain is
	 * an internal init write.  This is robust against work-thread
	 * reuse (unlike PID tracking) because the flag is per-work-item,
	 * not per-thread.
	 *
	 * We must return 0 (not goto handle_piggybacks) to prevent the
	 * legacy blocked_works path from delivering the event either.
	 */
	if ((mask & FS_ATTRIB) && !(mask & FS_CREATE) &&
	    watch->create_suppress_len > 0 &&
	    file_name->len == (size_t)watch->create_suppress_len &&
	    !memcmp(file_name->name, watch->create_suppress_name,
		    file_name->len)) {
		struct work_struct *cur_work = current_work();

		if (cur_work) {
			struct ksmbd_work *kwork =
				container_of(cur_work,
					     struct ksmbd_work, work);
			if (kwork->notify_suppress) {
				spin_unlock(&watch->lock);
				return 0;
			}
		}
	}

	/*
	 * Record the filename on FS_CREATE so the spurious FS_ATTRIB
	 * that immediately follows (from xattr init) can be suppressed.
	 * This must be done BEFORE the completion_filter check so that
	 * even when the filter doesn't include DIR/FILE_NAME, the suppress
	 * is still armed for the ATTRIB filter case.
	 * Store the current PID so we can limit suppression to this worker.
	 */
	if (action == FILE_ACTION_ADDED) {
		size_t slen = min_t(size_t, file_name->len, NAME_MAX);

		memcpy(watch->create_suppress_name, file_name->name, slen);
		watch->create_suppress_len = (u8)slen;
	} else if (action == FILE_ACTION_REMOVED &&
		   watch->create_suppress_len > 0 &&
		   file_name->len == (size_t)watch->create_suppress_len &&
		   !memcmp(file_name->name, watch->create_suppress_name,
			   file_name->len)) {
		/* Entry removed before the suppress was consumed; clear it. */
		watch->create_suppress_len = 0;
	}

	/*
	 * If the event matches the filter and there's a pending
	 * work, complete it.  Otherwise, buffer the change so it
	 * can be delivered on the next NOTIFY request.
	 */
	if (smb2_filter & watch->completion_filter) {
		/*
		 * Buffer this event unconditionally regardless of
		 * whether a pending NOTIFY is waiting or not.
		 * When pending_work is set, schedule the batching
		 * timer instead of firing immediately — this lets
		 * rapid sequential events (e.g. unlink+create+write)
		 * accumulate so they are all returned in ONE response.
		 * Do NOT coalesce: mkdir/rmdir/mkdir/rmdir on the same
		 * name must deliver all four events in order.
		 */
		if (watch->buffered_count < 256) {
			struct ksmbd_notify_change *chg;

			chg = kzalloc(sizeof(*chg), GFP_ATOMIC);
			if (chg) {
				chg->name = kstrndup(file_name->name,
						     file_name->len,
						     GFP_ATOMIC);
				if (chg->name) {
					chg->name_len = file_name->len;
					chg->action = action;
					list_add_tail(&chg->entry,
						      &watch->buffered_changes);
					watch->buffered_count++;
				} else {
					kfree(chg);
				}
			}
		}

		if (watch->pending_work) {
			struct ksmbd_work *pending_work = watch->pending_work;
			bool batch_recursive = watch->watch_tree;

			spin_unlock(&watch->lock);
			if (batch_recursive &&
			    !ksmbd_notify_has_queued_waiter(watch->fp,
							    pending_work)) {
				ksmbd_notify_schedule_batch_work(watch);
			} else {
				/*
				 * Complete the pending NOTIFY synchronously with the
				 * buffered event(s).  The former 10 ms debounce timer
				 * was batching rapid mkdir+rmdir sequences into a single
				 * response, causing tests to see changes[0]=ADDED when
				 * they expected changes[0]=REMOVED.  Windows fires the
				 * pending NOTIFY immediately on the first matching event;
				 * any events that arrive before the client re-issues
				 * CHANGE_NOTIFY are buffered and returned by add_watch's
				 * buffered-changes drain path.
				 *
				 * Also avoid recursive batching when another CHANGE_NOTIFY
				 * is already queued on the same handle: sequential delivery
				 * must let the next waiter observe the next matching event
				 * instead of draining multiple descendant changes into the
				 * first request.
				 */
				ksmbd_notify_build_response_from_buffer(watch);
			}
			/*
			 * Mark that the primary watch fired so that the legacy
			 * blocked_works loop (below) is skipped.  Multiple
			 * CHANGE_NOTIFY requests on the same handle must be
			 * served sequentially — one event per request — which
			 * matches Windows behaviour (the next waiting work is
			 * promoted to pending_work inside
			 * ksmbd_notify_build_response_from_buffer).
			 */
			primary_fired = true;
		} else {
			spin_unlock(&watch->lock);
		}
	} else {
		spin_unlock(&watch->lock);
	}

handle_piggybacks:
	/*
	 * Dispatch event to secondary watches (persistent per-handle watches
	 * that share the primary's mark) and legacy blocked_works piggybacks.
	 *
	 * Secondary watches have their own independent event buffers so each
	 * handle accumulates events between NOTIFY requests (Windows behaviour).
	 * For each matching secondary:
	 *   1. Buffer the event in secondary->buffered_changes.
	 *   2. If secondary->pending_work is set, complete it now.
	 */
	{
		/* Fixed stack array for secondaries needing completion */
		struct ksmbd_notify_watch *complete_secs[32];
		int n_secs = 0, i;

		spin_lock(&watch->lock);
		list_for_each_entry(sec, &watch->secondary_watches, list) {
			bool buffered_only = true;

			if (!ksmbd_notify_watch_get(sec))
				continue;
			if (sec->detached || !sec->fp) {
				ksmbd_notify_watch_put(sec);
				continue;
			}
			if (!(smb2_filter & sec->completion_filter))
				goto put_secondary;
			spin_lock(&sec->lock);
			if (sec->detached || !sec->fp) {
				spin_unlock(&sec->lock);
				goto put_secondary;
			}
			/* Buffer the event in the secondary's own buffer */
			if (sec->buffered_count < 256) {
				struct ksmbd_notify_change *chg;

				chg = kzalloc(sizeof(*chg), GFP_ATOMIC);
				if (chg) {
					chg->name = kstrndup(file_name->name,
							     file_name->len,
							     GFP_ATOMIC);
					if (chg->name) {
						chg->name_len = file_name->len;
						chg->action = action;
						list_add_tail(&chg->entry,
							      &sec->buffered_changes);
						sec->buffered_count++;
					} else {
						kfree(chg);
					}
				}
			}
			/* Collect for completion if there is a pending work */
			if (sec->pending_work && !sec->completed) {
				if (sec->watch_tree) {
					ksmbd_notify_schedule_batch_work(sec);
				} else if (n_secs < (int)ARRAY_SIZE(complete_secs)) {
					complete_secs[n_secs++] = sec;
					buffered_only = false;
				}
			}
			spin_unlock(&sec->lock);
			if (buffered_only)
				ksmbd_notify_watch_put(sec);
			continue;
put_secondary:
			ksmbd_notify_watch_put(sec);
		}
		spin_unlock(&watch->lock);

		/* Complete secondaries outside the primary lock */
		for (i = 0; i < n_secs; i++) {
			ksmbd_notify_build_response_from_buffer(complete_secs[i]);
			ksmbd_notify_watch_put(complete_secs[i]);
		}
	}

	/*
	 * Legacy blocked_works piggyback dispatch.
	 * NOTIFY-01: get a fp reference while holding watch->lock.
	 *
	 * Skip if the primary watch already fired for this event.
	 * Multiple CHANGE_NOTIFY requests on the same handle must be served
	 * sequentially (one event → one completion).  The next waiting work
	 * was promoted to pending_work inside build_response_from_buffer and
	 * will be triggered by the next matching event.
	 */
	if (primary_fired)
		return 0;

	spin_lock(&watch->lock);
	fp = watch->fp;
	if (fp && (fp->f_state != FP_INITED ||
		   !refcount_inc_not_zero(&fp->refcount)))
		fp = NULL;
	spin_unlock(&watch->lock);

	if (!fp)
		return 0;

	spin_lock(&fp->f_lock);
	list_for_each_entry_safe(work, tmp,
				 &fp->blocked_works, fp_entry) {
		if (!ksmbd_notify_is_change_notify_work(work))
			continue;

		/*
		 * Use the WATCH's locked completion_filter, not the request's
		 * CompletionFilter.  The first CHANGE_NOTIFY on a handle fixes
		 * the filter for the lifetime of the handle; subsequent requests
		 * with a different filter are silently ignored (filter locking).
		 * Using the request's cf would bypass this locking.
		 */
		if (!(smb2_filter & watch->completion_filter))
			continue;

		list_del_init(&work->fp_entry);
		list_add(&work->fp_entry, &complete_list);
	}
	spin_unlock(&fp->f_lock);

	list_for_each_entry_safe(work, tmp, &complete_list, fp_entry) {
		list_del_init(&work->fp_entry);
		atomic_dec(&notify_watch_count);
		if (work->conn)
			atomic_dec(&work->conn->notify_watch_count);
		ksmbd_notify_complete_piggyback(work, action, file_name);
	}

	if (refcount_dec_and_test(&fp->refcount))
		pr_warn_ratelimited("ksmbd: notify: unexpected last fp reference in handle_event\n");

	return 0;
}

static void ksmbd_notify_free_mark(struct fsnotify_mark *mark)
{
	struct ksmbd_notify_watch *watch;

	watch = container_of(mark,
			     struct ksmbd_notify_watch, mark);

	/* Cancel any pending (queued but not running) batch work */
	cancel_delayed_work(&watch->batch_work);
	WARN_ON_ONCE(!list_empty(&watch->secondary_watches));
	watch->has_mark = false;
	ksmbd_notify_watch_put(watch);
}

static const struct fsnotify_ops ksmbd_notify_ops = {
	.handle_event	= ksmbd_notify_handle_event,
	.free_mark	= ksmbd_notify_free_mark,
};

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/*
 * ksmbd_notify_add_secondary() - create a secondary watch for @fp on an inode
 * that already has a primary watch.
 *
 * Each directory file handle gets its own persistent ksmbd_notify_watch with
 * an independent event buffer so it accumulates events between NOTIFY requests
 * independently (matching Windows behaviour).  Only the first handle installs
 * a fsnotify mark (primary, has_mark=true); all subsequent handles get
 * secondary watches (has_mark=false) driven by the primary's mark.
 *
 * @fp:             the file handle issuing CHANGE_NOTIFY
 * @work:           the async work to complete on the first event
 * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* bitmask
 * @watch_tree:     true to watch recursively
 * @output_buf_len: client-requested output buffer size
 * @existing_mark:  the primary's fsnotify mark (caller holds a ref)
 * @cancel_argv:    cancel_argv array; argv[0] is set to the secondary watch
 *
 * On failure: watch counts are decremented (caller already incremented them).
 */
static int ksmbd_notify_add_secondary(struct ksmbd_file *fp,
				      struct ksmbd_work *work,
				      u32 completion_filter,
				      bool watch_tree,
				      u32 output_buf_len,
				      struct fsnotify_mark *existing_mark,
				      void **cancel_argv)
{
	struct ksmbd_notify_watch *primary, *secondary;

	primary = container_of(existing_mark,
			       struct ksmbd_notify_watch, mark);

	secondary = kzalloc(sizeof(*secondary), KSMBD_DEFAULT_GFP);
	if (!secondary) {
		atomic_dec(&notify_watch_count);
		if (work->conn)
			atomic_dec(&work->conn->notify_watch_count);
		return -ENOMEM;
	}

	secondary->fp			= fp;
	secondary->pending_work		= work;
	secondary->conn			= work->conn;
	secondary->completion_filter	= completion_filter;
	secondary->watch_tree		= watch_tree;
	secondary->buffer_tree		= watch_tree;
	secondary->output_buf_len	= output_buf_len;
	secondary->has_mark		= false;
	secondary->detached		= false;
	secondary->mark_cleanup_started	= false;
	secondary->enum_dir_sticky	= false;
	secondary->primary		= primary;
	spin_lock_init(&secondary->lock);
	refcount_set(&secondary->refs, 1);
	INIT_LIST_HEAD(&secondary->secondary_watches); /* unused on secondary */
	INIT_LIST_HEAD(&secondary->list);
	INIT_LIST_HEAD(&secondary->buffered_changes);
	INIT_DELAYED_WORK(&secondary->batch_work, ksmbd_notify_batch_work_fn);

	/* Link into the primary's secondary_watches list */
	spin_lock(&primary->lock);
	if (primary->detached) {
		spin_unlock(&primary->lock);
		kfree(secondary);
		atomic_dec(&notify_watch_count);
		if (work->conn)
			atomic_dec(&work->conn->notify_watch_count);
		return -ENOENT;
	}
	list_add(&secondary->list, &primary->secondary_watches);
	spin_unlock(&primary->lock);

	/* Attach the secondary watch to the fp so re-NOTIFY reuses it */
	ksmbd_notify_set_file_watch(fp, secondary);

	if (cancel_argv)
		cancel_argv[0] = secondary;

	return 0;
}

int ksmbd_notify_add_watch(struct ksmbd_file *fp,
			   struct ksmbd_work *work,
			   u32 completion_filter,
			   bool watch_tree,
			   u32 output_buf_len,
			   void **cancel_argv)
{
	struct ksmbd_notify_watch *watch;
	struct inode *inode;
	int ret;
	int retries = 0;

	if (!fp || !fp->filp)
		return -EINVAL;

	inode = file_inode(fp->filp);
	if (!S_ISDIR(inode->i_mode))
		return -ENOTDIR;

	if (!ksmbd_notify_group)
		return -ENODEV;

	/*
	 * Reuse the existing per-handle watch if present.
	 * This persists across NOTIFY/CANCEL cycles so that
	 * events occurring between cancel and the next NOTIFY
	 * are buffered and can be delivered immediately.
	 */
	spin_lock(&fp->f_lock);
	watch = fp->notify_watch;
	spin_unlock(&fp->f_lock);
	if (watch) {
		spin_lock(&watch->lock);

		/*
		 * Update per-request parameters.  The completion_filter
		 * (mask) is intentionally NOT updated here: Windows fixes the
		 * filter for the lifetime of the file handle (the first
		 * CHANGE_NOTIFY that creates the watch establishes the mask).
		 * Subsequent requests on the same handle with a different
		 * filter are silently ignored per Windows behaviour (as
		 * tested by smbtorture smb2.notify.mask-change).
		 */
		if (!watch->pending_work) {
			watch->watch_tree = watch_tree;
			watch->output_buf_len = output_buf_len;
		}
		watch->buffer_tree |= watch_tree;
		watch->completed = false;

		if (watch->enum_dir_sticky) {
			spin_unlock(&watch->lock);
			ksmbd_notify_build_status_rsp(work, STATUS_NOTIFY_ENUM_DIR);
			ksmbd_iov_pin_rsp(work, work->response_buf,
					  get_rfc1002_len(work->response_buf) +
					  RFC1002_HEADER_LEN);
			if (cancel_argv)
				cancel_argv[0] = NULL;
			return -EIOCBQUEUED;
		}

		if (!list_empty(&watch->buffered_changes)) {
			/*
			 * Buffered events are available — respond
			 * synchronously with ALL of them in one
			 * multi-record FILE_NOTIFY_INFORMATION buffer.
			 * Return -EIOCBQUEUED so the caller skips the
			 * async path.
			 */
			LIST_HEAD(flush_list);
			struct ksmbd_notify_change *chg, *chg_tmp;
			u8 *buf_start, *cur;
			size_t max_data, total_written = 0;
			struct file_notify_information *prev_info = NULL;
			int total_rsp_len;
			bool overflow = false;

			/* Steal all buffered events under the lock */
			list_splice_init(&watch->buffered_changes,
					 &flush_list);
			watch->buffered_count = 0;
			spin_unlock(&watch->lock);

			ksmbd_notify_ensure_rsp_capacity(work, output_buf_len);

			max_data = ksmbd_notify_max_data(work, output_buf_len);
			buf_start = ksmbd_notify_rsp_data(work);
			cur = buf_start;

			list_for_each_entry_safe(chg, chg_tmp,
						 &flush_list, entry) {
				struct file_notify_information *info;
				int name_len_bytes;
				size_t max_rem, rec_sz, rec_sz_al;
				__le16 tmp_name[KSMBD_NOTIFY_UTF16_TMP_UNITS];

				max_rem = (total_written < max_data) ?
					  max_data - total_written : 0;
				if (max_rem < sizeof(*info)) {
					overflow = true;
					break;
				}

				info = (struct file_notify_information *)cur;
				name_len_bytes = ksmbd_notify_encode_name(
					tmp_name, ARRAY_SIZE(tmp_name),
					chg->name, chg->name_len,
					work->conn->local_nls);
				if (name_len_bytes < 0)
					name_len_bytes = 0;

				rec_sz = sizeof(*info) + name_len_bytes;
				rec_sz_al = ALIGN(rec_sz, 4);

				if (rec_sz_al > max_rem) {
					overflow = true;
					break;
				}

				memcpy(info->FileName, tmp_name, name_len_bytes);
				info->Action = cpu_to_le32(chg->action);
				info->FileNameLength = cpu_to_le32(name_len_bytes);
				/* Will be zeroed for the last record */
				info->NextEntryOffset =
					cpu_to_le32(rec_sz_al);

				prev_info = info;
				cur += rec_sz_al;
				total_written += rec_sz_al;

				list_del(&chg->entry);
				kfree(chg->name);
				kfree(chg);
			}

			/* Free any events that didn't fit */
			list_for_each_entry_safe(chg, chg_tmp,
						 &flush_list, entry) {
				list_del(&chg->entry);
				kfree(chg->name);
				kfree(chg);
			}

			if (total_written == 0)
				overflow = true;

			if (overflow) {
				if (output_buf_len) {
					spin_lock(&watch->lock);
					watch->enum_dir_sticky = true;
					spin_unlock(&watch->lock);
				}
				total_rsp_len = ksmbd_notify_build_status_rsp(
					work, STATUS_NOTIFY_ENUM_DIR);
			} else {
				/* Zero the last record's NextEntryOffset */
				if (prev_info)
					prev_info->NextEntryOffset = 0;
				total_rsp_len = ksmbd_notify_finalize_success_rsp(
					work, total_written);
			}

			ksmbd_iov_pin_rsp(work, work->response_buf, total_rsp_len);

			if (cancel_argv)
				cancel_argv[0] = NULL;
			return -EIOCBQUEUED;
		}
		/* No buffered changes -- go async as usual.
		 * Set pending_work INSIDE the lock to prevent a race where an
		 * fsnotify event fires between the unlock and the assignment,
		 * sees pending_work=NULL, buffers the event, and never fires
		 * a completion (leaving the NOTIFY pending forever).
		 *
		 * If a pending_work is already set (earlier CHANGE_NOTIFY on
		 * this handle that has not yet been completed), keep the older
		 * one as the active pending_work.  Multiple CHANGE_NOTIFY
		 * requests on the same handle are served sequentially (Windows
		 * behaviour): the first event completes the oldest request, the
		 * second event completes the next one, etc.  The new work is
		 * added to fp->blocked_works and will be promoted to
		 * pending_work by ksmbd_notify_build_response_from_buffer when
		 * the current pending_work completes.
		 */
		{
			bool set_pending = !watch->pending_work;

			if (set_pending)
				watch->pending_work = work;
			spin_unlock(&watch->lock);

			if (cancel_argv)
				cancel_argv[0] = watch;

			/*
			 * For secondary watches (has_mark=false), the work is
			 * tracked exclusively via watch->pending_work.  Do NOT
			 * add it to fp->blocked_works (that list is for legacy
			 * piggyback mode and primary-watch compound work only).
			 * For primary watches, add to fp->blocked_works so the
			 * next-work promotion and old handle_piggybacks path can
			 * find it (M-13 limit applies).
			 */
			if (watch->has_mark) {
				spin_lock(&fp->f_lock);
				/* M-13: enforce per-handle NOTIFY limit */
				if (ksmbd_notify_count_handle_works(fp) >=
				    KSMBD_MAX_NOTIFY_PER_HANDLE) {
					spin_unlock(&fp->f_lock);
					if (set_pending)
						watch->pending_work = NULL;
					if (cancel_argv)
						cancel_argv[0] = NULL;
					return -ENOSPC;
				}
				list_add(&work->fp_entry, &fp->blocked_works);
				spin_unlock(&fp->f_lock);
			}
		}

		return 0;
	}

retry_new_watch:
	/* No existing watch -- create a new one */
	if (atomic_inc_return(&notify_watch_count) >
	    KSMBD_MAX_NOTIFY_WATCHES) {
		atomic_dec(&notify_watch_count);
		return -ENOSPC;
	}

	if (work->conn &&
	    atomic_inc_return(&work->conn->notify_watch_count) >
	    KSMBD_MAX_NOTIFY_WATCHES_PER_CONN) {
		atomic_dec(&work->conn->notify_watch_count);
		atomic_dec(&notify_watch_count);
		return -ENOSPC;
	}

	watch = kzalloc(sizeof(*watch), KSMBD_DEFAULT_GFP);
	if (!watch) {
		if (work->conn)
			atomic_dec(&work->conn->notify_watch_count);
		atomic_dec(&notify_watch_count);
		return -ENOMEM;
	}

	watch->fp = fp;
	watch->pending_work = work;
	watch->conn = work->conn;
	watch->completion_filter = completion_filter;
	watch->watch_tree = watch_tree;
	watch->buffer_tree = watch_tree;
	watch->output_buf_len = output_buf_len;
	watch->completed = false;
	watch->has_mark = true;
	watch->detached = false;
	watch->mark_cleanup_started = false;
	watch->enum_dir_sticky = false;
	watch->primary = NULL;
	spin_lock_init(&watch->lock);
	refcount_set(&watch->refs, 1);
	INIT_DELAYED_WORK(&watch->batch_work, ksmbd_notify_batch_work_fn);
	INIT_LIST_HEAD(&watch->list);
	INIT_LIST_HEAD(&watch->secondary_watches);
	INIT_LIST_HEAD(&watch->buffered_changes);
	watch->buffered_count = 0;

	fsnotify_init_mark(&watch->mark, ksmbd_notify_group);

	watch->mark.mask = ksmbd_notify_calc_fs_mask();

	/* M-13: check per-handle limit before registering the mark */
	spin_lock(&fp->f_lock);
	if (ksmbd_notify_count_handle_works(fp) >= KSMBD_MAX_NOTIFY_PER_HANDLE) {
		spin_unlock(&fp->f_lock);
		fsnotify_put_mark(&watch->mark);
		return -ENOSPC;
	}
	spin_unlock(&fp->f_lock);

	/*
	 * Piggyback detection (kernel 6.x compatible):
	 *
	 * In kernel 6.x, fsnotify_add_mark_locked() CONSUMES our mark's
	 * reference when it returns -EEXIST (it calls fsnotify_put_mark
	 * internally on the mark we're adding).  This triggers
	 * ksmbd_notify_free_mark() → kfree(watch) before we return.
	 * Calling fsnotify_put_mark() or kfree(watch) ourselves afterwards
	 * is a double-free that crashes the kernel.
	 *
	 * Solution: check for an existing mark BEFORE calling add_inode_mark.
	 * If found, free our temporary watch cleanly, re-bump the watch
	 * counts (ksmbd_notify_free_mark decremented them), and register the
	 * work as a piggyback directly.  fsnotify_add_inode_mark is only
	 * called when we're certain no mark exists (avoiding -EEXIST entirely
	 * except in the unlikely TOCTOU race window).
	 */
	ret = 0;
	{
		struct fsnotify_mark *pre_existing;

		pre_existing = fsnotify_find_inode_mark(inode,
							ksmbd_notify_group);
		if (pre_existing) {
			/*
			 * An existing primary mark found.  Free our temporary
			 * watch via fsnotify_put_mark: drops refcount to 0,
			 * ksmbd_notify_free_mark runs synchronously:
			 *   - kfree(watch) → 'watch' is now dangling
			 *   - atomic_dec(notify_watch_count)
			 *   - atomic_dec(conn->notify_watch_count)
			 * Do NOT access 'watch' after this point.
			 */
			fsnotify_put_mark(&watch->mark);
			ret = -EEXIST;
			/* 'existing' from find above — use pre_existing */
			if (cancel_argv)
				cancel_argv[0] = NULL;
			/*
			 * Re-bump counts: the piggyback work is an active
			 * NOTIFY consumer and will decrement on
			 * completion/cancel — balance the decrement done by
			 * ksmbd_notify_free_mark.
			 */
			atomic_inc(&notify_watch_count);
			if (work->conn)
				atomic_inc(&work->conn->notify_watch_count);
			ret = ksmbd_notify_add_secondary(fp, work,
							 completion_filter,
							 watch_tree,
							 output_buf_len,
							 pre_existing,
							 cancel_argv);
			fsnotify_put_mark(pre_existing);
			if (ret == -ENOENT && retries++ < 2)
				goto retry_new_watch;
			return ret;
		}
	}

	ret = fsnotify_add_inode_mark(&watch->mark, inode, 0);
	if (ret == -EEXIST) {
		/*
		 * TOCTOU race: a mark was added between our pre-check and
		 * our fsnotify_add_inode_mark call.
		 *
		 * In kernel 6.x, fsnotify_add_mark_locked() has already
		 * called fsnotify_put_mark() on our mark, triggering
		 * ksmbd_notify_free_mark() → kfree(watch) + count decrements.
		 * 'watch' is a dangling pointer — do NOT dereference it.
		 */
		struct fsnotify_mark *existing;

		if (cancel_argv)
			cancel_argv[0] = NULL;

		/* Re-bump counts for the piggyback we're about to register. */
		atomic_inc(&notify_watch_count);
		if (work->conn)
			atomic_inc(&work->conn->notify_watch_count);

		existing = fsnotify_find_inode_mark(inode, ksmbd_notify_group);
		if (!existing) {
			atomic_dec(&notify_watch_count);
			if (work->conn)
				atomic_dec(&work->conn->notify_watch_count);
			return -ENODEV;
		}
		ret = ksmbd_notify_add_secondary(fp, work,
						 completion_filter,
						 watch_tree,
						 output_buf_len,
						 existing,
						 cancel_argv);
		fsnotify_put_mark(existing);
		if (ret == -ENOENT && retries++ < 2)
			goto retry_new_watch;
		return ret;
	} else if (ret) {
		pr_err_ratelimited(
			"ksmbd: failed to add fsnotify mark: %d\n",
			ret);
		/*
		 * For non-EEXIST errors, the kernel did NOT consume our mark
		 * reference.  Drop our reference to trigger free_mark cleanup.
		 */
		fsnotify_put_mark(&watch->mark);
		return ret;
	}

	/* Attach watch to the file handle for persistence */
	ksmbd_notify_set_file_watch(fp, watch);

	if (cancel_argv)
		cancel_argv[0] = watch;

	spin_lock(&fp->f_lock);
	list_add(&work->fp_entry, &fp->blocked_works);
	spin_unlock(&fp->f_lock);

	return 0;
}

void ksmbd_notify_cancel(void **argv)
{
	struct ksmbd_notify_watch *watch;
	struct ksmbd_work *work;
	bool put_watch = false;

	if (!argv)
		return;

	watch = argv[0];
	if (watch && !watch->has_mark) {
		if (!ksmbd_notify_watch_get(watch))
			return;
		put_watch = true;
	}
	if (!watch) {
		/*
		 * Piggyback watch (no fsnotify mark of its own).
		 * argv[1] = work, argv[2] = fp.
		 * Remove from fp->blocked_works and send STATUS_CANCELLED.
		 */
		struct ksmbd_file *fp;

		work = argv[1];
		fp = argv[2];
		if (!work)
			return;
		if (!ksmbd_notify_claim_cancel_work(work))
			return;

		/* Remove from fp->blocked_works if still linked */
		if (fp) {
			spin_lock(&fp->f_lock);
			if (!list_empty(&work->fp_entry))
				list_del_init(&work->fp_entry);
			spin_unlock(&fp->f_lock);
		}

		/* Build STATUS_CANCELLED response */
		kfree(work->tr_buf);
		work->tr_buf = NULL;
		work->iov_idx = 0;
		work->iov_cnt = 0;
		work->send_no_response = 0;
		ksmbd_notify_prepare_async_rsp(work);
		ksmbd_notify_build_status_rsp(work, STATUS_CANCELLED);

		/* Sign if required (before encryption) */
		if (ksmbd_notify_should_sign(work))
			work->conn->ops->set_sign_rsp(work);

		if (work->sess && work->conn && work->conn->ops &&
		    work->sess->enc && work->encrypted &&
		    work->conn->ops->encrypt_resp) {
			int rc = work->conn->ops->encrypt_resp(work);

			if (rc < 0)
				pr_err_ratelimited(
					"ksmbd: piggyback cancel encrypt failed: %d\n",
					rc);
		}

		ksmbd_conn_write(work);

		/* Remove from async_requests list before freeing */
		ksmbd_notify_unlink_async_request(work);

		/*
		 * Only dequeue from the request list if this work was
		 * a real request (has a request_buf).  Compound-spawned
		 * async work structs were never queued or counted.
		 */
		if (work->request_buf)
			ksmbd_conn_try_dequeue_request(work);

		atomic_dec(&notify_watch_count);
		if (work->conn)
			atomic_dec(&work->conn->notify_watch_count);

		/* Decrement outstanding async count */
		if (READ_ONCE(server_conf.max_async_credits))
			atomic_dec(&work->conn->outstanding_async);

		/* Drop the extra session reference taken in smb2_notify */
		if (work->sess)
			ksmbd_user_session_put(work->sess);

		{
			struct ksmbd_conn *notify_conn;

			notify_conn = ksmbd_notify_detach_work_conn_ref(work);
			ksmbd_free_work_struct(work);
			if (notify_conn)
				ksmbd_conn_free(notify_conn);
		}
		if (put_watch)
			ksmbd_notify_watch_put(watch);
		return;
	}

	spin_lock(&watch->lock);
	work = watch->pending_work;
	if (!work || watch->completed) {
		spin_unlock(&watch->lock);
		if (put_watch)
			ksmbd_notify_watch_put(watch);
		return;
	}
	/*
	 * Do NOT set completed = true.  The watch persists for the
	 * lifetime of the file handle.  Clear pending_work so the
	 * event handler knows no request is waiting, and reset
	 * completed so the watch can accept a new NOTIFY request.
	 */
	watch->pending_work = NULL;
	watch->completed = false;
	spin_unlock(&watch->lock);
	if (!ksmbd_notify_claim_cancel_work(work))
		goto out_put_watch;

	/* Cancel any pending batch timer — the request is being cancelled. */
	cancel_delayed_work_sync(&watch->batch_work);

	kfree(work->tr_buf);
	work->tr_buf = NULL;
	work->iov_idx = 0;
	work->iov_cnt = 0;
	work->send_no_response = 0;
	ksmbd_notify_prepare_async_rsp(work);
	ksmbd_notify_build_status_rsp(work, STATUS_CANCELLED);

	/*
	 * Sign the response if the session requires signing.
	 * Per MS-SMB2 3.3.4.4, the final async response SHOULD
	 * be signed.  Signing must happen before encryption.
	 */
	if (ksmbd_notify_should_sign(work))
		work->conn->ops->set_sign_rsp(work);

	/* Encrypt if the session requires it */
	if (work->sess && work->conn && work->conn->ops &&
	    work->sess->enc && work->encrypted &&
	    work->conn->ops->encrypt_resp) {
		int rc = work->conn->ops->encrypt_resp(work);

		if (rc < 0)
			pr_err_ratelimited(
				"ksmbd: notify cancel encrypt failed: %d\n",
				rc);
	}

	ksmbd_conn_write(work);

	if (watch->fp) {
		spin_lock(&watch->fp->f_lock);
		list_del_init(&work->fp_entry);
		spin_unlock(&watch->fp->f_lock);
	}

	/* Remove from async_requests list before freeing */
	ksmbd_notify_unlink_async_request(work);

	/*
	 * Only dequeue from the request list if this work was
	 * a real request (has a request_buf).  Compound-spawned
	 * async work structs were never queued or counted.
	 */
	if (work->request_buf)
		ksmbd_conn_try_dequeue_request(work);

	/* Decrement outstanding async count */
	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	/* Drop the extra session reference taken in smb2_notify */
	if (work->sess)
		ksmbd_user_session_put(work->sess);

	{
		struct ksmbd_conn *notify_conn;

		notify_conn = ksmbd_notify_detach_work_conn_ref(work);
		ksmbd_free_work_struct(work);
		if (notify_conn)
			ksmbd_conn_free(notify_conn);
	}

	/*
	 * Do NOT destroy the mark or NULL out fp.  The watch
	 * persists for the lifetime of the file handle so that
	 * events occurring after this cancel (and before the next
	 * NOTIFY request) are buffered and can be delivered
	 * immediately (MS-SMB2 3.3.1.6).
	 */
out_put_watch:
	if (put_watch)
		ksmbd_notify_watch_put(watch);
}

/*
 * Helper: send STATUS_NOTIFY_CLEANUP for a single async work item
 * and free it.  Used during file close to terminate any outstanding
 * async CHANGE_NOTIFY requests.
 */
static void ksmbd_notify_send_cleanup(struct ksmbd_work *work)
{
	int ret = 0;

	if (!ksmbd_notify_take_work(work, KSMBD_WORK_CLOSED))
		return;

	work->send_no_response = 0;
	kfree(work->tr_buf);
	work->tr_buf = NULL;
	work->iov_idx = 0;
	work->iov_cnt = 0;
	ksmbd_notify_prepare_async_rsp(work);
	ksmbd_notify_build_status_rsp(work, STATUS_NOTIFY_CLEANUP);

	/* Sign if required (before encryption) */
	if (ksmbd_notify_should_sign(work))
		work->conn->ops->set_sign_rsp(work);

	if (work->sess && work->conn && work->conn->ops &&
	    work->sess->enc &&
	    work->encrypted && work->conn->ops->encrypt_resp)
		work->conn->ops->encrypt_resp(work);

	/*
	 * Do NOT write to the socket if the connection is already in the
	 * releasing state (ksmbd_conn_handler_loop has set RELEASING and is
	 * waiting for r_count == 0).  The TCP send buffer may be full because
	 * the client disconnected without draining it; writev() would then
	 * block forever, preventing r_count from ever reaching 0 — a
	 * permanent deadlock.  Skipping the write is safe: the client is
	 * already gone and will never receive the STATUS_NOTIFY_CLEANUP.
	 */
	if (work->conn && !ksmbd_conn_releasing(work->conn))
		ret = ksmbd_conn_try_write(work);

	/*
	 * A live connection still owes the client the async completion.
	 * Falling back to a blocking write preserves protocol delivery while
	 * still avoiding teardown deadlocks for already-releasing sessions.
	 */
	if (ret == -EAGAIN && work->conn && !ksmbd_conn_releasing(work->conn))
		ret = ksmbd_conn_write(work);

	if (ret == -EAGAIN)
		ksmbd_debug(CONN,
			    "skip STATUS_NOTIFY_CLEANUP on busy connection during teardown\n");

	ksmbd_notify_unlink_async_request(work);

	/*
	 * Only dequeue if this work was counted in req_running.
	 * Compound-spawned async_work has no request_buf and was
	 * never enqueued, so dequeuing would underflow req_running.
	 */
	if (work->request_buf)
		ksmbd_conn_try_dequeue_request(work);

	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	if (work->sess)
		ksmbd_user_session_put(work->sess);

	{
		struct ksmbd_conn *notify_conn;

		notify_conn = ksmbd_notify_detach_work_conn_ref(work);
		ksmbd_free_work_struct(work);
		if (notify_conn)
			ksmbd_conn_free(notify_conn);
	}
}

void ksmbd_notify_cleanup_file(struct ksmbd_file *fp)
{
	struct fsnotify_group *notify_group;
	struct ksmbd_notify_watch *watch;
	struct ksmbd_notify_watch *primary = NULL;
	struct ksmbd_work *work, *tmp;
	bool destroy_primary = false;
	LIST_HEAD(cleanup_list);

	notify_group = READ_ONCE(ksmbd_notify_group);
	if (!fp || !notify_group)
		return;

	/*
	 * Handle the persistent per-handle watch first.
	 * If there is a pending async work on the watch, complete
	 * it with STATUS_NOTIFY_CLEANUP.  Then destroy the mark.
	 */
	watch = ksmbd_notify_detach_file_watch(fp);
	if (watch) {
		work = NULL;

		/*
		 * Flush any in-flight batch work before we destroy the primary
		 * mark. When cleanup runs from that work item itself, we must use
		 * the non-sync variant or we deadlock waiting on ourselves.
		 */
		if (watch->has_mark) {
			spin_lock(&watch->lock);
			work = watch->pending_work;
			watch->pending_work = NULL;
			watch->completed = true;
			watch->fp = NULL;
			spin_unlock(&watch->lock);
			ksmbd_notify_cancel_batch_work(watch);

			if (work) {
				spin_lock(&fp->f_lock);
				if (!list_empty(&work->fp_entry))
					list_del_init(&work->fp_entry);
				spin_unlock(&fp->f_lock);

				ksmbd_notify_send_cleanup(work);
			}

			spin_lock(&watch->lock);
			if (list_empty(&watch->secondary_watches))
				destroy_primary =
					ksmbd_notify_begin_primary_mark_cleanup(
						watch);
			spin_unlock(&watch->lock);
		} else {
			primary = watch->primary;
			if (primary) {
				spin_lock(&primary->lock);
				watch->detached = true;
				if (!list_empty(&watch->list))
					list_del_init(&watch->list);
				watch->primary = NULL;
				spin_lock(&watch->lock);
				work = watch->pending_work;
				watch->pending_work = NULL;
				watch->completed = true;
				watch->fp = NULL;
				spin_unlock(&watch->lock);

				if (!primary->fp &&
				    list_empty(&primary->secondary_watches)) {
					destroy_primary =
						ksmbd_notify_begin_primary_mark_cleanup(
							primary);
				}
				spin_unlock(&primary->lock);
			} else {
				spin_lock(&watch->lock);
				work = watch->pending_work;
				watch->pending_work = NULL;
				watch->completed = true;
				watch->fp = NULL;
				spin_unlock(&watch->lock);
			}
			ksmbd_notify_cancel_batch_work(watch);

			if (work) {
				spin_lock(&fp->f_lock);
				if (!list_empty(&work->fp_entry))
					list_del_init(&work->fp_entry);
				spin_unlock(&fp->f_lock);

				ksmbd_notify_send_cleanup(work);
			}

		ksmbd_notify_watch_put(watch);
	}
	}

	if (destroy_primary) {
		struct ksmbd_notify_watch *mark_owner = primary ?: watch;

		ksmbd_notify_cancel_batch_work(mark_owner);
		if (ksmbd_notify_mark_can_destroy(mark_owner, notify_group))
			fsnotify_destroy_mark(&mark_owner->mark,
					      notify_group);
	}

	/*
	 * Clean up any piggyback watches (works on fp->blocked_works
	 * that piggybacked on another handle's fsnotify mark).
	 */
	spin_lock(&fp->f_lock);
	list_for_each_entry_safe(work, tmp,
				 &fp->blocked_works, fp_entry) {
		if (!ksmbd_notify_is_change_notify_work(work))
			continue;

		list_del_init(&work->fp_entry);
		list_add(&work->fp_entry, &cleanup_list);
	}
	spin_unlock(&fp->f_lock);

	list_for_each_entry_safe(work, tmp, &cleanup_list, fp_entry) {
		list_del_init(&work->fp_entry);
		atomic_dec(&notify_watch_count);
		if (work->conn)
			atomic_dec(&work->conn->notify_watch_count);
		ksmbd_notify_send_cleanup(work);
	}
}

/* ------------------------------------------------------------------ */
/*  Delete-pending notification                                        */
/* ------------------------------------------------------------------ */

/*
 * Helper: send STATUS_DELETE_PENDING for a single async NOTIFY work
 * item and free it.  Very similar to ksmbd_notify_send_cleanup but
 * uses STATUS_DELETE_PENDING instead of STATUS_NOTIFY_CLEANUP.
 */
static void ksmbd_notify_send_delete_pending(struct ksmbd_work *work)
{
	int ret = 0;

	if (!ksmbd_notify_take_work(work, KSMBD_WORK_CLOSED))
		return;

	work->send_no_response = 0;
	kfree(work->tr_buf);
	work->tr_buf = NULL;
	work->iov_idx = 0;
	work->iov_cnt = 0;
	ksmbd_notify_prepare_async_rsp(work);
	ksmbd_notify_build_status_rsp(work, STATUS_DELETE_PENDING);

	/* Sign if required (before encryption) */
	if (ksmbd_notify_should_sign(work))
		work->conn->ops->set_sign_rsp(work);

	if (work->sess && work->conn && work->conn->ops &&
	    work->sess->enc &&
	    work->encrypted && work->conn->ops->encrypt_resp)
		work->conn->ops->encrypt_resp(work);

	if (work->conn && !ksmbd_conn_releasing(work->conn))
		ret = ksmbd_conn_try_write(work);

	/*
	 * STATUS_DELETE_PENDING is observable protocol state, not optional
	 * cleanup.  Retry with the regular serialized write path unless the
	 * connection is already draining.
	 */
	if (ret == -EAGAIN && work->conn && !ksmbd_conn_releasing(work->conn))
		ret = ksmbd_conn_write(work);

	if (ret == -EAGAIN)
		ksmbd_debug(CONN,
			    "skip STATUS_DELETE_PENDING on busy connection during teardown\n");

	ksmbd_notify_unlink_async_request(work);

	/*
	 * Only dequeue if this work was counted in req_running.
	 * Compound-spawned async_work has no request_buf and was
	 * never enqueued, so dequeuing would underflow req_running.
	 */
	if (work->request_buf)
		ksmbd_conn_try_dequeue_request(work);

	if (READ_ONCE(server_conf.max_async_credits))
		atomic_dec(&work->conn->outstanding_async);

	if (work->sess)
		ksmbd_user_session_put(work->sess);

	{
		struct ksmbd_conn *notify_conn;

		notify_conn = ksmbd_notify_detach_work_conn_ref(work);
		ksmbd_free_work_struct(work);
		/*
		 * Note: the FS_DELETE_SELF caller (fsnotify handler) also does
		 * a refcount_inc(&conn->refcnt) before invoking this function;
		 * that extra refcnt reference is released by the caller after
		 * we return via ksmbd_conn_free().
		 */
		if (notify_conn)
			ksmbd_conn_free(notify_conn);
	}
}

/**
 * ksmbd_notify_complete_delete_pending() - complete pending NOTIFY
 *   watches on an inode that has become delete-pending.
 * @ci: ksmbd_inode whose directory is being deleted
 *
 * Called from __ksmbd_inode_close() when a handle with DELETE_ON_CLOSE
 * is closed and the inode has S_DEL_ON_CLS or S_DEL_PENDING set.
 * Iterates over all file pointers on the inode and completes any
 * pending CHANGE_NOTIFY requests with STATUS_DELETE_PENDING.
 *
 * This implements the Windows behavior where CHANGE_NOTIFY completes
 * with STATUS_DELETE_PENDING as soon as the directory becomes
 * delete-pending (not when it is actually deleted).
 */
void ksmbd_notify_complete_delete_pending(struct ksmbd_inode *ci)
{
	struct ksmbd_file *fp;
	struct ksmbd_notify_watch *watch;
	struct ksmbd_work *work;
	struct ksmbd_conn *conn;

	if (!ksmbd_notify_group)
		return;

	/*
	 * Walk all file pointers on this inode.  For each one that
	 * has a notify watch with a pending work, complete it.
	 *
	 * We take m_lock for reading.  The caller (__ksmbd_inode_close)
	 * has already released m_lock before calling us, and we are
	 * safe to re-acquire it.
	 */
	down_read(&ci->m_lock);
	list_for_each_entry(fp, &ci->m_fp_list, node) {
		watch = ksmbd_notify_get_file_watch(fp);
		if (!watch)
			continue;

		spin_lock(&watch->lock);
		work = watch->pending_work;
		if (!work || watch->completed) {
			spin_unlock(&watch->lock);
			ksmbd_notify_watch_put(watch);
			continue;
		}
		/*
		 * Mark as completed and clear pending_work.
		 * The watch persists (for cleanup_file later).
		 */
		watch->completed = true;
		watch->pending_work = NULL;
		conn = work->conn;
		if (conn)
			refcount_inc(&conn->refcnt);
		spin_unlock(&watch->lock);

		/* Remove from blocked_works */
		spin_lock(&fp->f_lock);
		if (!list_empty(&work->fp_entry))
			list_del_init(&work->fp_entry);
		spin_unlock(&fp->f_lock);

		ksmbd_notify_send_delete_pending(work);
		if (conn)
			ksmbd_conn_free(conn);
		ksmbd_notify_watch_put(watch);
	}
	up_read(&ci->m_lock);
}

void ksmbd_notify_tree_change(struct ksmbd_work *work,
			      const struct path *parent_path,
			      const char *full_name,
			      u32 action,
			      bool is_dir)
{
	LIST_HEAD(flush_list);
	u32 smb2_filter;

	smb2_filter = is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME :
			       FILE_NOTIFY_CHANGE_FILE_NAME;
	ksmbd_notify_tree_collect(work->tcon->share_conf, parent_path,
				  full_name, false, smb2_filter,
				  action, &flush_list);
	ksmbd_notify_tree_flush_pending(&flush_list);
}

void ksmbd_notify_tree_rename(struct ksmbd_work *work,
			      const struct path *old_parent_path,
			      const char *old_full_name,
			      const struct path *new_parent_path,
			      const char *new_full_name,
			      bool is_dir)
{
	LIST_HEAD(flush_list);
	u32 smb2_filter = KSMBD_NOTIFY_ALL_FILTERS;
	bool same_parent;

	(void)is_dir;
	same_parent = old_parent_path->dentry == new_parent_path->dentry;

	ksmbd_notify_tree_collect(work->tcon->share_conf,
				  old_parent_path, old_full_name, false,
				  smb2_filter,
				  same_parent ? FILE_ACTION_RENAMED_OLD_NAME :
						FILE_ACTION_REMOVED,
				  &flush_list);
	ksmbd_notify_tree_collect(work->tcon->share_conf,
				  new_parent_path, new_full_name,
				  !same_parent,
				  smb2_filter,
				  same_parent ? FILE_ACTION_RENAMED_NEW_NAME :
						FILE_ACTION_ADDED,
				  &flush_list);
	ksmbd_notify_tree_flush_pending(&flush_list);
}

void ksmbd_notify_tree_remove_on_close(struct ksmbd_file *fp)
{
	LIST_HEAD(flush_list);
	struct path parent_path;
	char *full_name;
	u32 action;
	bool is_dir;

	if (!fp || !fp->filp || !fp->tcon)
		return;

	parent_path.mnt = fp->filp->f_path.mnt;
	parent_path.dentry = fp->filp->f_path.dentry->d_parent;
	full_name = convert_to_nt_pathname(fp->tcon->share_conf,
					   &fp->filp->f_path);
	if (IS_ERR(full_name))
		return;

	action = ksmbd_inode_is_smb_delete(fp->filp->f_path.dentry) ?
		 FILE_ACTION_REMOVED_BY_DELETE : FILE_ACTION_REMOVED;
	is_dir = S_ISDIR(file_inode(fp->filp)->i_mode);
	ksmbd_notify_tree_collect(fp->tcon->share_conf, &parent_path,
				  full_name, false,
				  is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME :
					   FILE_NOTIFY_CHANGE_FILE_NAME,
				  action, &flush_list);
	ksmbd_notify_tree_flush_pending(&flush_list);
	kfree(full_name);
}

/* ------------------------------------------------------------------ */
/*  Module lifecycle                                                   */
/* ------------------------------------------------------------------ */

bool ksmbd_notify_enabled(void)
{
	return ksmbd_notify_group != NULL;
}

int ksmbd_notify_init(void)
{
	ksmbd_notify_group = fsnotify_alloc_group(&ksmbd_notify_ops,
						  KSMBD_FSNOTIFY_GROUP_FLAGS);
	if (IS_ERR(ksmbd_notify_group)) {
		int err = PTR_ERR(ksmbd_notify_group);

		ksmbd_notify_group = NULL;
		pr_err("ksmbd: failed to create fsnotify group: %d\n", err);
		return err;
	}
	pr_info("ksmbd: CHANGE_NOTIFY subsystem initialised\n");
	return 0;
}

void ksmbd_notify_exit(void)
{
	if (ksmbd_notify_group) {
		/*
		 * Drop the group reference.  fsnotify_put_group will
		 * internally call fsnotify_clear_marks_by_group to
		 * detach all marks.  Then wait for pending mark
		 * destruction to complete before returning to the
		 * caller (module unload), preventing use-after-free
		 * in fsnotify event delivery paths on kernel 6.18+.
		 */
		fsnotify_put_group(ksmbd_notify_group);
		fsnotify_wait_marks_destroyed();
		ksmbd_notify_group = NULL;
	}
}
