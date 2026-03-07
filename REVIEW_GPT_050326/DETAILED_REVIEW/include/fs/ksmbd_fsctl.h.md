# Line-by-line Review: src/include/fs/ksmbd_fsctl.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   FSCTL handler registration API for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#ifndef __KSMBD_FSCTL_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define __KSMBD_FSCTL_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/module.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/rcupdate.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `struct smb2_ioctl_rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * struct ksmbd_fsctl_handler - FSCTL dispatch entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * @ctl_code:	FSCTL control code (host byte order)`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * @handler:	callback function invoked on matching FSCTL`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` * @owner:	module owning this handler (for reference counting)`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * @node:	hash table linkage`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [LIFETIME|] ` * @rcu:	RCU callback head for safe removal`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00027 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [LIFETIME|] ` * Each registered handler is hashed by ctl_code into an RCU-protected`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00029 [LIFETIME|] ` * hash table.  The dispatch path looks up handlers under rcu_read_lock`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00030 [NONE] ` * and invokes the callback.`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` * Handler return values:`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` *   0         - success, @out_len contains response bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` *   negative  - errno (e.g. -EINVAL, -ENOENT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `struct ksmbd_fsctl_handler {`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	u32 ctl_code;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	int (*handler)(struct ksmbd_work *work, u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `		       void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `		       unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `		       struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `		       unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `	struct module *owner;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	struct hlist_node node;`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [LIFETIME|] `	struct rcu_head rcu;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00046 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ` * ksmbd_register_fsctl() - Register an FSCTL handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ` * @h: handler descriptor (caller must keep alive until unregistered)`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [LIFETIME|] ` * Adds the handler to the RCU-protected dispatch table.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00053 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` * Return: 0 on success, -EEXIST if ctl_code already registered`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` * ksmbd_unregister_fsctl() - Unregister an FSCTL handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` * @h: handler descriptor previously passed to ksmbd_register_fsctl()`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [LIFETIME|] ` * Removes the handler and waits for an RCU grace period so that`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00063 [NONE] ` * in-flight lookups complete safely.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h);`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * ksmbd_dispatch_fsctl() - Look up and invoke a registered FSCTL handler`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * @work:	    smb work for this request`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * @ctl_code:	    FSCTL control code (host byte order)`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` * @id:		    volatile file id`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * @in_buf:	    pointer to input buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * @in_buf_len:    input buffer length`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * @max_out_len:   maximum output length allowed`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` * @rsp:	    pointer to ioctl response structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * @out_len:	    [out] number of output bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` *         handler is registered for the given ctl_code.`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `int ksmbd_dispatch_fsctl(struct ksmbd_work *work, u32 ctl_code,`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `			 u64 id, void *in_buf, unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `			 unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `			 struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `			 unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ` * ksmbd_fsctl_init() - Initialize the FSCTL dispatch table`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * Registers all built-in FSCTL handlers.  Must be called during`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * module initialization.`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `int ksmbd_fsctl_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` * ksmbd_fsctl_exit() - Tear down the FSCTL dispatch table`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ` * Unregisters all handlers and cleans up.  Must be called during`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ` * module exit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `void ksmbd_fsctl_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `#if IS_ENABLED(CONFIG_KUNIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `struct copychunk_ioctl_req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `struct in_device;`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `struct ksmbd_odx_token;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `/* FSCTL functions exported for KUnit testing (ksmbd_fsctl.c) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `void ksmbd_fsctl_build_fallback_object_id(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `					  u8 *object_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `int ksmbd_fsctl_fill_object_id_rsp(struct ksmbd_file *fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `				   bool create_if_missing,`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `				   unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `				   struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `				   unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `int fsctl_is_pathname_valid_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `				    u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `				    unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `				    unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `				    struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `				    unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `__be32 fsctl_idev_ipv4_address(struct in_device *idev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `int fsctl_copychunk_common(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `			   struct copychunk_ioctl_req *ci_req,`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `			   unsigned int cnt_code,`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `			   unsigned int input_count,`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `			   u64 id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `			   struct smb2_ioctl_rsp *rsp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `u32 odx_nonce_hash(const u8 *nonce);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `bool odx_token_validate(const struct ksmbd_odx_token *token);`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `int fsctl_validate_negotiate_info_handler(struct ksmbd_work *work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `					  u64 id, void *in_buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `					  unsigned int in_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `					  unsigned int max_out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `					  struct smb2_ioctl_rsp *rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `					  unsigned int *out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `#endif /* CONFIG_KUNIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `#endif /* __KSMBD_FSCTL_H */`
  Review: Low-risk line; verify in surrounding control flow.
