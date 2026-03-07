# Line-by-line Review: src/include/core/ksmbd_buffer.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef __KSMBD_BUFFER_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_BUFFER_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` * Buffer ownership semantics:`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` * Buffers obtained via ksmbd_buffer_pool_get() follow a strict single-owner`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * model.  At any point in time, exactly one entity (connection, work struct,`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * etc.) owns each buffer and is responsible for releasing it.`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * Ownership transfer protocol:`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *   1. The new owner receives the buffer pointer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` *   2. The old owner's pointer is immediately set to NULL.`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` *   3. The new owner is now responsible for calling ksmbd_buffer_pool_put()`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` *      or kvfree() as appropriate.`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * Example (conn -> work transfer in queue_ksmbd_work()):`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` *   work->request_buf = conn->request_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` *   conn->request_buf = NULL;   // conn no longer owns the buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` * Callers MUST NOT access a buffer after transferring ownership.`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` * Use WARN_ON_ONCE() to assert the source pointer is non-NULL before`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` * transfer, catching double-free or use-after-transfer bugs early.`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` * ksmbd_buffer_pool_init() - Initialize the buffer pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * Pre-allocates buffers in two tiers (small 64KB and large 1MB) to`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * reduce allocation overhead on the SMB read/write hot path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `int ksmbd_buffer_pool_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * ksmbd_buffer_pool_exit() - Destroy the buffer pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` * Frees all pre-allocated buffers and tears down the pool.`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `void ksmbd_buffer_pool_exit(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ` * ksmbd_buffer_pool_get() - Get a buffer from the pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` * @size: requested buffer size`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` * Returns a buffer of at least @size bytes. If the pool has a`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * suitable pre-allocated buffer, it is returned immediately.`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [MEM_BOUNDS|] ` * Otherwise falls back to kvzalloc().`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00058 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ` * Return: pointer to buffer or NULL on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `void *ksmbd_buffer_pool_get(size_t size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * ksmbd_buffer_pool_put() - Return a buffer to the pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * @buf: buffer previously obtained from ksmbd_buffer_pool_get()`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ` * Returns the buffer to the appropriate freelist if the pool is not`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ` * full. Otherwise frees the buffer via kvfree().`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `void ksmbd_buffer_pool_put(void *buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#endif /* __KSMBD_BUFFER_H */`
  Review: Low-risk line; verify in surrounding control flow.
