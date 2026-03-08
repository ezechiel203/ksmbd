/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   SMB2 CHANGE_NOTIFY subsystem — fsnotify-based directory watching.
 */

#ifndef __KSMBD_NOTIFY_H__
#define __KSMBD_NOTIFY_H__

#include <linux/limits.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/fsnotify_backend.h>

struct ksmbd_conn;
struct ksmbd_file;
struct ksmbd_inode;
struct ksmbd_work;

/**
 * struct ksmbd_notify_change - buffered change notification
 * @entry:  linkage on ksmbd_notify_watch.buffered_changes
 * @action: FILE_ACTION_* constant
 * @name:   filename (allocated, NUL-terminated)
 * @name_len: length of name in bytes (excluding NUL)
 */
struct ksmbd_notify_change {
	struct list_head	entry;
	u32			action;
	char			*name;
	size_t			name_len;
};

/**
 * struct ksmbd_notify_watch - per-directory change-notify watch
 * @fp:              file pointer for the watched directory
 * @pending_work:    async work waiting for an event (first watch only)
 * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* bitmask
 * @watch_tree:      true if watching the entire subtree
 * @output_buf_len:  max response buffer from client request
 * @conn:            connection that owns this watch (for per-conn accounting)
 * @lock:            protects pending_work, completed, and buffered_changes
 * @completed:       true once an event has been delivered
 * @list:            linkage on the per-file watch list
 * @mark:            fsnotify inode mark
 * @buffered_changes: list of ksmbd_notify_change entries
 *                   for events that arrived with no pending NOTIFY
 * @buffered_count:  number of entries in buffered_changes
 * @enum_dir_sticky: once a handle overflows its notify buffer and returns
 *                   STATUS_NOTIFY_ENUM_DIR, subsequent CHANGE_NOTIFY requests
 *                   on the same handle continue to return ENUM_DIR until the
 *                   handle is closed, matching Windows behaviour.
 * @create_suppress_len: length of create_suppress_name; 0 = none pending
 * @create_suppress_name: filename from the last FS_CREATE event; the
 *                   immediately-following FS_ATTRIB for the same name is
 *                   suppressed because it is a spurious side-effect of
 *                   smb2_new_xattrs() initialising the DOS attribute xattr
 *                   and does not represent a real attribute change.
 * @has_mark:        true if this watch owns an fsnotify mark on the inode.
 *                   false for secondary watches (additional handles on the
 *                   same directory inode) which share the primary's mark
 *                   but maintain independent pending_work and buffered_changes.
 * @rename_cookie:   fsnotify cookie for a pending FS_MOVED_FROM event.
 *                   When non-zero, a RENAMED_OLD_NAME record is held
 *                   waiting for the matching FS_MOVED_TO (CN-02).
 * @rename_old_name: name from the FS_MOVED_FROM event (allocated).
 * @rename_old_len:  length of rename_old_name in chars (not bytes).
 */
struct ksmbd_notify_watch {
	struct ksmbd_file	*fp;
	struct ksmbd_work	*pending_work;
	u32			completion_filter;
	bool			watch_tree;
	bool			buffer_tree;
	u32			output_buf_len;
	struct ksmbd_conn	*conn;
	spinlock_t		lock;
	refcount_t		refs;
	bool			completed;
	bool			has_mark;
	bool			detached;
	bool			mark_cleanup_started;
	struct list_head	list;
	struct fsnotify_mark	mark;
	struct list_head	buffered_changes;
	unsigned int		buffered_count;
	bool			enum_dir_sticky;
	u8			create_suppress_len;
	char			create_suppress_name[NAME_MAX + 1];
	/*
	 * Filename of the last FS_CREATE event.  FS_ATTRIB events for this
	 * name are suppressed only when the current ksmbd_work has
	 * notify_suppress=true (set by smb2_open during xattr init).
	 * See CN-SUPPRESS in ksmbd_notify.c.
	 */
	/* CN-02: deferred rename pairing */
	u32			rename_cookie;
	char			*rename_old_name;
	size_t			rename_old_len;
	/*
	 * CN-RENAME-ATTR-SUPPRESS: filename from the last FS_MOVED_TO event
	 * that was converted to FILE_ACTION_MODIFIED (ATTRS-only filter).
	 * The immediately-following FS_ATTRIB for the same name is suppressed
	 * as a spurious side-effect of the rename (ctime update, close flush).
	 * Cleared unconditionally after the first suppression (one-shot).
	 */
	u8			rename_suppress_len;
	char			rename_suppress_name[NAME_MAX + 1];
	u8			tree_rename_suppress_len;
	char			tree_rename_suppress_name[NAME_MAX + 1];
	/* Batching: delay response to accumulate rapid sequential events */
	struct delayed_work	batch_work;
	/*
	 * Secondary watch support (CN-sec):
	 * Each directory file handle that has issued at least one CHANGE_NOTIFY
	 * gets its own persistent watch so it can independently buffer events
	 * between NOTIFY requests (matching Windows behaviour).
	 *
	 * The first fp to install a watch owns the fsnotify mark (has_mark=true)
	 * and is the "primary".  Subsequent fps on the same inode get "secondary"
	 * watches (has_mark=false) that share the mark but have their own
	 * pending_work and buffered_changes.
	 *
	 * @secondary_watches: on the primary, the HEAD of all secondary watches;
	 *                     on a secondary, the LINK in primary->secondary_watches.
	 *                     Protected by primary->lock.
	 * @primary: NULL on the primary watch; back-pointer to the primary on
	 *           secondary watches.
	 */
	struct list_head	secondary_watches;
	struct ksmbd_notify_watch *primary;
};

/**
 * ksmbd_notify_init() - initialise the change-notify subsystem
 *
 * Creates the fsnotify group used for all SMB2 watches.
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_notify_init(void);

/**
 * ksmbd_notify_enabled() - check if change-notify is available
 *
 * Return: true if the subsystem was initialised, false otherwise.
 */
bool ksmbd_notify_enabled(void);

/**
 * ksmbd_notify_exit() - tear down the change-notify subsystem
 *
 * Destroys the global fsnotify group and frees resources.
 */
void ksmbd_notify_exit(void);

/**
 * ksmbd_notify_add_watch() - install an fsnotify watch on a directory
 * @fp:                ksmbd file pointer (must be a directory)
 * @work:              async work to complete when an event arrives
 * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* flags
 * @watch_tree:        true to watch recursively
 * @output_buf_len:    client-requested output buffer size
 * @cancel_argv:       cancel arguments array; argv[0] will be set
 *                     to the allocated watch pointer on success
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_notify_add_watch(struct ksmbd_file *fp,
			   struct ksmbd_work *work,
			   u32 completion_filter,
			   bool watch_tree,
			   u32 output_buf_len,
			   void **cancel_argv);

/**
 * ksmbd_notify_cancel() - cancel a pending async notify
 * @argv: cancel_argv array (argv[0] is the ksmbd_notify_watch *)
 *
 * Called from the SMB2 CANCEL path via work->cancel_fn.
 */
void ksmbd_notify_cancel(void **argv);

/**
 * ksmbd_notify_cleanup_file() - remove all watches for a file
 * @fp: ksmbd file pointer being closed
 *
 * Called when a file handle is closed to tear down any
 * outstanding change-notify watches.
 */
void ksmbd_notify_cleanup_file(struct ksmbd_file *fp);

/**
 * ksmbd_notify_complete_delete_pending() - complete pending NOTIFY
 *   watches on an inode that has become delete-pending.
 * @ci: ksmbd_inode whose directory is being deleted
 *
 * Called from __ksmbd_inode_close() when a handle with DELETE_ON_CLOSE
 * is closed and the inode has S_DEL_ON_CLS or S_DEL_PENDING set.
 * Completes any pending CHANGE_NOTIFY with STATUS_DELETE_PENDING.
 */
void ksmbd_notify_complete_delete_pending(struct ksmbd_inode *ci);

void ksmbd_notify_tree_change(struct ksmbd_work *work,
			      const struct path *parent_path,
			      const char *full_name,
			      u32 action,
			      bool is_dir);

void ksmbd_notify_tree_rename(struct ksmbd_work *work,
			      const struct path *old_parent_path,
			      const char *old_full_name,
			      const struct path *new_parent_path,
			      const char *new_full_name,
			      bool is_dir);

void ksmbd_notify_tree_remove_on_close(struct ksmbd_file *fp);

#endif /* __KSMBD_NOTIFY_H__ */
