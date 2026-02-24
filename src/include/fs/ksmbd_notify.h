/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   SMB2 CHANGE_NOTIFY subsystem — fsnotify-based directory watching.
 */

#ifndef __KSMBD_NOTIFY_H__
#define __KSMBD_NOTIFY_H__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/fsnotify_backend.h>

struct ksmbd_file;
struct ksmbd_work;

/**
 * struct ksmbd_notify_watch - per-directory change-notify watch
 * @fp:              file pointer for the watched directory
 * @pending_work:    async work waiting for an event
 * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* bitmask
 * @watch_tree:      true if watching the entire subtree
 * @output_buf_len:  max response buffer from client request
 * @lock:            protects pending_work and completed flag
 * @completed:       true once an event has been delivered
 * @list:            linkage on the per-file watch list
 * @mark:            fsnotify inode mark
 */
struct ksmbd_notify_watch {
	struct ksmbd_file	*fp;
	struct ksmbd_work	*pending_work;
	u32			completion_filter;
	bool			watch_tree;
	u32			output_buf_len;
	spinlock_t		lock;
	bool			completed;
	struct list_head	list;
	struct fsnotify_mark	mark;
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

#endif /* __KSMBD_NOTIFY_H__ */
