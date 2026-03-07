# Line-by-line Review: src/mgmt/ksmbd_ida.h

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
- L00006 [NONE] `#ifndef __KSMBD_IDA_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __KSMBD_IDA_MANAGEMENT_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/idr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` * 2.2.1.6.7 TID Generation`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *    The value 0xFFFF MUST NOT be used as a valid TID. All other`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *    possible values for TID, including zero (0x0000), are valid.`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *    The value 0xFFFF is used to specify all TIDs or no TID,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *    depending upon the context in which it is used.`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `int ksmbd_acquire_smb1_tid(struct ida *ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `int ksmbd_acquire_smb2_tid(struct ida *ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * 2.2.1.6.8 UID Generation`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` *    The value 0xFFFE was declared reserved in the LAN Manager 1.0`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` *    documentation, so a value of 0xFFFE SHOULD NOT be used as a`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *    valid UID.<21> All other possible values for a UID, excluding`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` *    zero (0x0000), are valid.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#ifdef CONFIG_SMB_INSECURE_SERVER`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `int ksmbd_acquire_smb1_uid(struct ida *ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `int ksmbd_acquire_smb2_uid(struct ida *ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `int ksmbd_acquire_async_msg_id(struct ida *ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `int ksmbd_acquire_id(struct ida *ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `void ksmbd_release_id(struct ida *ida, int id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#endif /* __KSMBD_IDA_MANAGEMENT_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
