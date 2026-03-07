# Line-by-line Review: src/include/transport/transport_ipc.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __KSMBD_TRANSPORT_IPC_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __KSMBD_TRANSPORT_IPC_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/wait.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#define KSMBD_IPC_MAX_PAYLOAD	4096`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `struct ksmbd_login_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `ksmbd_ipc_login_request(const char *account);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `struct ksmbd_login_response_ext *`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `ksmbd_ipc_login_request_ext(const char *account);`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `struct ksmbd_session;`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `struct ksmbd_share_config;`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `struct ksmbd_tree_connect;`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `struct sockaddr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `struct ksmbd_tree_connect_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `ksmbd_ipc_tree_connect_request(struct ksmbd_session *sess,`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `			       struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `			       struct ksmbd_tree_connect *tree_conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `			       struct sockaddr *peer_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `int ksmbd_ipc_tree_disconnect_request(unsigned long long session_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `				      unsigned long long connect_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `int ksmbd_ipc_logout_request(const char *account, int flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct ksmbd_share_config_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `ksmbd_ipc_share_config_request(const char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `struct ksmbd_spnego_authen_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `ksmbd_ipc_spnego_authen_request(const char *spnego_blob, int blob_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `int ksmbd_ipc_id_alloc(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `void ksmbd_rpc_id_free(int handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_open(struct ksmbd_session *sess, int handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_close(struct ksmbd_session *sess, int handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_write(struct ksmbd_session *sess, int handle,`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `					  void *payload, size_t payload_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_read(struct ksmbd_session *sess, int handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_ioctl(struct ksmbd_session *sess, int handle,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `					  void *payload, size_t payload_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `struct ksmbd_rpc_command *ksmbd_rpc_rap(struct ksmbd_session *sess, void *payload,`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `					size_t payload_sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `void ksmbd_ipc_release(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `void ksmbd_ipc_soft_reset(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `int ksmbd_ipc_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `/* Witness Protocol (MS-SWN) IPC functions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `int ksmbd_ipc_witness_notify(u32 reg_id, const char *resource_name,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `			     int new_state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `struct ksmbd_witness_iface_list_response *`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `ksmbd_ipc_witness_iface_list_request(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#endif /* __KSMBD_TRANSPORT_IPC_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
