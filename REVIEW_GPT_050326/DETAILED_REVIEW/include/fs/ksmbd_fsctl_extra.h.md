# Line-by-line Review: src/include/fs/ksmbd_fsctl_extra.h

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
- L00006 [NONE] ` *   Extra FSCTL handlers for ksmbd (TRIM, ALLOCATED_RANGES,`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *   SET_ZERO_DATA, PIPE_WAIT)`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#ifndef __KSMBD_FSCTL_EXTRA_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#define __KSMBD_FSCTL_EXTRA_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * ksmbd_fsctl_extra_init() - Initialize extra FSCTL handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * Registers FSCTL handlers for FSCTL_FILE_LEVEL_TRIM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_ZERO_DATA, and`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * FSCTL_PIPE_WAIT.  Must be called during module initialization`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * after ksmbd_fsctl_init().`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `int ksmbd_fsctl_extra_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * ksmbd_fsctl_extra_exit() - Tear down extra FSCTL handlers`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` * Unregisters all extra FSCTL handlers and releases resources.`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * Must be called during module exit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `void ksmbd_fsctl_extra_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#endif /* __KSMBD_FSCTL_EXTRA_H */`
  Review: Low-risk line; verify in surrounding control flow.
