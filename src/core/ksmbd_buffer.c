// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Buffer pool for SMB read/write operations.
 *   Pre-allocates buffers in two tiers to reduce kvzalloc() overhead
 *   on the hot path.
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/mm.h>

#include "glob.h"
#include "ksmbd_buffer.h"

#define KSMBD_BUF_SMALL_SIZE	(64 * 1024)	/* 64 KB */
#define KSMBD_BUF_LARGE_SIZE	(1024 * 1024)	/* 1 MB */
#define KSMBD_BUF_SMALL_COUNT	8
#define KSMBD_BUF_LARGE_COUNT	4

struct ksmbd_buf_entry {
	struct list_head	list;
	size_t			size;
	/* Buffer data follows immediately after this struct */
};

struct ksmbd_buf_pool {
	struct list_head	free_list;
	spinlock_t		lock;
	unsigned int		buf_size;
	unsigned int		total;
	unsigned int		free;
	unsigned int		max_free;
};

static struct ksmbd_buf_pool small_pool;
static struct ksmbd_buf_pool large_pool;

static inline void *entry_to_buf(struct ksmbd_buf_entry *entry)
{
	return (char *)entry + sizeof(*entry);
}

static inline struct ksmbd_buf_entry *buf_to_entry(void *buf)
{
	return (struct ksmbd_buf_entry *)((char *)buf - sizeof(struct ksmbd_buf_entry));
}

static int ksmbd_buf_pool_alloc(struct ksmbd_buf_pool *pool,
				unsigned int buf_size,
				unsigned int count)
{
	unsigned int i;

	INIT_LIST_HEAD(&pool->free_list);
	spin_lock_init(&pool->lock);
	pool->buf_size = buf_size;
	pool->total = 0;
	pool->free = 0;
	pool->max_free = count;

	for (i = 0; i < count; i++) {
		struct ksmbd_buf_entry *entry;

		entry = kvzalloc(sizeof(*entry) + buf_size,
				 KSMBD_DEFAULT_GFP);
		if (!entry) {
			struct ksmbd_buf_entry *tmp;

			list_for_each_entry_safe(entry, tmp,
						 &pool->free_list, list) {
				list_del(&entry->list);
				kvfree(entry);
			}
			pool->total = 0;
			pool->free = 0;
			return -ENOMEM;
		}

		entry->size = buf_size;
		list_add_tail(&entry->list, &pool->free_list);
		pool->total++;
		pool->free++;
	}

	return 0;
}

static void ksmbd_buf_pool_free(struct ksmbd_buf_pool *pool)
{
	struct ksmbd_buf_entry *entry, *tmp;
	LIST_HEAD(to_free);

	spin_lock(&pool->lock);
	list_splice_init(&pool->free_list, &to_free);
	pool->total -= pool->free;
	pool->free = 0;
	spin_unlock(&pool->lock);

	list_for_each_entry_safe(entry, tmp, &to_free, list) {
		list_del(&entry->list);
		kvfree(entry);
	}
}

static struct ksmbd_buf_pool *ksmbd_buf_select_pool(size_t size)
{
	if (size <= KSMBD_BUF_SMALL_SIZE)
		return &small_pool;
	if (size <= KSMBD_BUF_LARGE_SIZE)
		return &large_pool;
	return NULL;
}

/**
 * ksmbd_buffer_pool_init() - Initialize the buffer pool
 *
 * Pre-allocates buffers in two tiers (small 64KB and large 1MB) to
 * reduce allocation overhead on the SMB read/write hot path.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_buffer_pool_init(void)
{
	int ret;

	ret = ksmbd_buf_pool_alloc(&small_pool, KSMBD_BUF_SMALL_SIZE,
				   KSMBD_BUF_SMALL_COUNT);
	if (ret)
		goto err_small;

	ret = ksmbd_buf_pool_alloc(&large_pool, KSMBD_BUF_LARGE_SIZE,
				   KSMBD_BUF_LARGE_COUNT);
	if (ret)
		goto err_large;

	return 0;

err_large:
	ksmbd_buf_pool_free(&small_pool);
err_small:
	return ret;
}

/**
 * ksmbd_buffer_pool_exit() - Destroy the buffer pool
 *
 * Frees all pre-allocated buffers and tears down the pool.
 */
void ksmbd_buffer_pool_exit(void)
{
	ksmbd_buf_pool_free(&large_pool);
	ksmbd_buf_pool_free(&small_pool);
}

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
void *ksmbd_buffer_pool_get(size_t size)
{
	struct ksmbd_buf_pool *pool;
	struct ksmbd_buf_entry *entry;

	pool = ksmbd_buf_select_pool(size);
	if (pool) {
		spin_lock(&pool->lock);
		if (!list_empty(&pool->free_list)) {
			entry = list_first_entry(&pool->free_list,
						 struct ksmbd_buf_entry,
						 list);
			list_del(&entry->list);
			pool->free--;
			spin_unlock(&pool->lock);
			memset(entry_to_buf(entry), 0, pool->buf_size);
			return entry_to_buf(entry);
		}
		spin_unlock(&pool->lock);

		/* Pool exhausted, allocate with pool->buf_size */
		entry = kvzalloc(sizeof(*entry) + pool->buf_size,
				 KSMBD_DEFAULT_GFP);
		if (!entry)
			return NULL;
		entry->size = pool->buf_size;
		return entry_to_buf(entry);
	}

	/* Size exceeds largest pool tier, fall back to kvzalloc */
	entry = kvzalloc(sizeof(*entry) + size, KSMBD_DEFAULT_GFP);
	if (!entry)
		return NULL;
	entry->size = size;
	return entry_to_buf(entry);
}

/**
 * ksmbd_buffer_pool_put() - Return a buffer to the pool
 * @buf: buffer previously obtained from ksmbd_buffer_pool_get()
 *
 * Returns the buffer to the appropriate freelist if the pool is not
 * full. Otherwise frees the buffer via kvfree().
 */
void ksmbd_buffer_pool_put(void *buf)
{
	struct ksmbd_buf_entry *entry;
	struct ksmbd_buf_pool *pool;

	if (!buf)
		return;

	entry = buf_to_entry(buf);
	pool = ksmbd_buf_select_pool(entry->size);

	if (pool) {
		spin_lock(&pool->lock);
		if (pool->free < pool->max_free) {
			list_add_tail(&entry->list, &pool->free_list);
			pool->free++;
			spin_unlock(&pool->lock);
			return;
		}
		spin_unlock(&pool->lock);
	}

	kvfree(entry);
}
