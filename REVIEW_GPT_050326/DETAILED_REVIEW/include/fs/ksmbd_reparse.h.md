# Line-by-line Review: src/include/fs/ksmbd_reparse.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Reparse point FSCTL handlers for ksmbd`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#ifndef __KSMBD_REPARSE_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define __KSMBD_REPARSE_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` * ksmbd_reparse_init() - Initialize reparse point subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * Registers FSCTL handlers for FSCTL_SET_REPARSE_POINT,`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * FSCTL_GET_REPARSE_POINT, and FSCTL_DELETE_REPARSE_POINT.`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * Must be called during module initialization after`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * ksmbd_fsctl_init().`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `int ksmbd_reparse_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * ksmbd_reparse_exit() - Tear down reparse point subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` * Unregisters FSCTL handlers and releases resources.`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` * Must be called during module exit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `void ksmbd_reparse_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#endif /* __KSMBD_REPARSE_H */`
  Review: Low-risk line; verify in surrounding control flow.
