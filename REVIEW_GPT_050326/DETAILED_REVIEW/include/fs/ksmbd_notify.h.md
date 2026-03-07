# Line-by-line Review: src/include/fs/ksmbd_notify.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2024 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   SMB2 CHANGE_NOTIFY subsystem — fsnotify-based directory watching.`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#ifndef __KSMBD_NOTIFY_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#define __KSMBD_NOTIFY_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/limits.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/fsnotify_backend.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `struct ksmbd_inode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * struct ksmbd_notify_change - buffered change notification`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * @entry:  linkage on ksmbd_notify_watch.buffered_changes`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * @action: FILE_ACTION_* constant`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * @name:   filename (allocated, NUL-terminated)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * @name_len: length of name in bytes (excluding NUL)`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `struct ksmbd_notify_change {`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	struct list_head	entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	u32			action;`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	char			*name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	size_t			name_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` * struct ksmbd_notify_watch - per-directory change-notify watch`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * @fp:              file pointer for the watched directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * @pending_work:    async work waiting for an event (first watch only)`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* bitmask`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * @watch_tree:      true if watching the entire subtree`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` * @output_buf_len:  max response buffer from client request`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * @conn:            connection that owns this watch (for per-conn accounting)`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * @lock:            protects pending_work, completed, and buffered_changes`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * @completed:       true once an event has been delivered`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * @list:            linkage on the per-file watch list`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * @mark:            fsnotify inode mark`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * @buffered_changes: list of ksmbd_notify_change entries`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` *                   for events that arrived with no pending NOTIFY`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * @buffered_count:  number of entries in buffered_changes`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` * @create_suppress_len: length of create_suppress_name; 0 = none pending`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` * @create_suppress_name: filename from the last FS_CREATE event; the`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` *                   immediately-following FS_ATTRIB for the same name is`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` *                   suppressed because it is a spurious side-effect of`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` *                   smb2_new_xattrs() initialising the DOS attribute xattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` *                   and does not represent a real attribute change.`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * @has_mark:        true if this watch owns an fsnotify mark on the inode.`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` *                   false for secondary watches (additional handles on the`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ` *                   same directory inode) which share the primary's mark`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` *                   but maintain independent pending_work and buffered_changes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `struct ksmbd_notify_watch {`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	struct ksmbd_file	*fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	struct ksmbd_work	*pending_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	u32			completion_filter;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	bool			watch_tree;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	u32			output_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	struct ksmbd_conn	*conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	spinlock_t		lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	bool			completed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	bool			has_mark;`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	struct fsnotify_mark	mark;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	struct list_head	buffered_changes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	unsigned int		buffered_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	u8			create_suppress_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	char			create_suppress_name[NAME_MAX + 1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` * ksmbd_notify_init() - initialise the change-notify subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * Creates the fsnotify group used for all SMB2 watches.`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `int ksmbd_notify_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * ksmbd_notify_enabled() - check if change-notify is available`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * Return: true if the subsystem was initialised, false otherwise.`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `bool ksmbd_notify_enabled(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * ksmbd_notify_exit() - tear down the change-notify subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` * Destroys the global fsnotify group and frees resources.`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `void ksmbd_notify_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` * ksmbd_notify_add_watch() - install an fsnotify watch on a directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * @fp:                ksmbd file pointer (must be a directory)`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` * @work:              async work to complete when an event arrives`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` * @completion_filter: SMB2 FILE_NOTIFY_CHANGE_* flags`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` * @watch_tree:        true to watch recursively`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * @output_buf_len:    client-requested output buffer size`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` * @cancel_argv:       cancel arguments array; argv[0] will be set`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` *                     to the allocated watch pointer on success`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `int ksmbd_notify_add_watch(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `			   struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `			   u32 completion_filter,`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `			   bool watch_tree,`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `			   u32 output_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `			   void **cancel_argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * ksmbd_notify_cancel() - cancel a pending async notify`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` * @argv: cancel_argv array (argv[0] is the ksmbd_notify_watch *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` * Called from the SMB2 CANCEL path via work->cancel_fn.`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `void ksmbd_notify_cancel(void **argv);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ` * ksmbd_notify_cleanup_file() - remove all watches for a file`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` * @fp: ksmbd file pointer being closed`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ` * Called when a file handle is closed to tear down any`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` * outstanding change-notify watches.`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `void ksmbd_notify_cleanup_file(struct ksmbd_file *fp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * ksmbd_notify_complete_delete_pending() - complete pending NOTIFY`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` *   watches on an inode that has become delete-pending.`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * @ci: ksmbd_inode whose directory is being deleted`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * Called from __ksmbd_inode_close() when a handle with DELETE_ON_CLOSE`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` * is closed and the inode has S_DEL_ON_CLS or S_DEL_PENDING set.`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [PROTO_GATE|] ` * Completes any pending CHANGE_NOTIFY with STATUS_DELETE_PENDING.`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00146 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `void ksmbd_notify_complete_delete_pending(struct ksmbd_inode *ci);`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `#endif /* __KSMBD_NOTIFY_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
