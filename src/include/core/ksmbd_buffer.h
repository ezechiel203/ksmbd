/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 */

#ifndef __KSMBD_BUFFER_H
#define __KSMBD_BUFFER_H

#include <linux/types.h>

/*
 * Buffer ownership semantics:
 *
 * Buffers obtained via ksmbd_buffer_pool_get() follow a strict single-owner
 * model.  At any point in time, exactly one entity (connection, work struct,
 * etc.) owns each buffer and is responsible for releasing it.
 *
 * Ownership transfer protocol:
 *   1. The new owner receives the buffer pointer.
 *   2. The old owner's pointer is immediately set to NULL.
 *   3. The new owner is now responsible for calling ksmbd_buffer_pool_put()
 *      or kvfree() as appropriate.
 *
 * Example (conn -> work transfer in queue_ksmbd_work()):
 *   work->request_buf = conn->request_buf;
 *   conn->request_buf = NULL;   // conn no longer owns the buffer
 *
 * Callers MUST NOT access a buffer after transferring ownership.
 * Use WARN_ON_ONCE() to assert the source pointer is non-NULL before
 * transfer, catching double-free or use-after-transfer bugs early.
 */

/**
 * ksmbd_buffer_pool_init() - Initialize the buffer pool
 *
 * Pre-allocates buffers in two tiers (small 64KB and large 1MB) to
 * reduce allocation overhead on the SMB read/write hot path.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_buffer_pool_init(void);

/**
 * ksmbd_buffer_pool_exit() - Destroy the buffer pool
 *
 * Frees all pre-allocated buffers and tears down the pool.
 */
void ksmbd_buffer_pool_exit(void);

/**
 * ksmbd_buffer_pool_get() - Get a buffer from the pool
 * @size: requested buffer size
 *
 * Returns a buffer of at least @size bytes. If the pool has a
 * suitable pre-allocated buffer, it is returned immediately.
 * Otherwise falls back to kvzalloc().
 *
 * Return: pointer to buffer or NULL on failure
 */
void *ksmbd_buffer_pool_get(size_t size);

/**
 * ksmbd_buffer_pool_put() - Return a buffer to the pool
 * @buf: buffer previously obtained from ksmbd_buffer_pool_get()
 *
 * Returns the buffer to the appropriate freelist if the pool is not
 * full. Otherwise frees the buffer via kvfree().
 */
void ksmbd_buffer_pool_put(void *buf);

#endif /* __KSMBD_BUFFER_H */
