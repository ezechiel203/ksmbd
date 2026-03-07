# Line-by-line Review: src/core/ksmbd_buffer.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Buffer pool for SMB read/write operations.`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [MEM_BOUNDS|] ` *   Pre-allocates buffers in two tiers to reduce kvzalloc() overhead`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00008 [NONE] ` *   on the hot path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/vmalloc.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/mm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include "ksmbd_buffer.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define KSMBD_BUF_SMALL_SIZE	(64 * 1024)	/* 64 KB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define KSMBD_BUF_LARGE_SIZE	(1024 * 1024)	/* 1 MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define KSMBD_BUF_SMALL_COUNT	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define KSMBD_BUF_LARGE_COUNT	4`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `struct ksmbd_buf_entry {`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	size_t			size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	/* Buffer data follows immediately after this struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct ksmbd_buf_pool {`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	struct list_head	free_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	spinlock_t		lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	unsigned int		buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	unsigned int		total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	unsigned int		free;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	unsigned int		max_free;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `static struct ksmbd_buf_pool small_pool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `static struct ksmbd_buf_pool large_pool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `static inline void *entry_to_buf(struct ksmbd_buf_entry *entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	return (char *)entry + sizeof(*entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `static inline struct ksmbd_buf_entry *buf_to_entry(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	return (struct ksmbd_buf_entry *)((char *)buf - sizeof(struct ksmbd_buf_entry));`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `static int ksmbd_buf_pool_alloc(struct ksmbd_buf_pool *pool,`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `				unsigned int buf_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `				unsigned int count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	INIT_LIST_HEAD(&pool->free_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `	spin_lock_init(&pool->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	pool->buf_size = buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `	pool->total = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `	pool->free = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	pool->max_free = count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	for (i = 0; i < count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `		struct ksmbd_buf_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [MEM_BOUNDS|] `		entry = kvzalloc(sizeof(*entry) + buf_size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00070 [NONE] `				 KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `		if (!entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `			struct ksmbd_buf_entry *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `			list_for_each_entry_safe(entry, tmp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `						 &pool->free_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `				list_del(&entry->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `				kvfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `			pool->total = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `			pool->free = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00082 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `		entry->size = buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		list_add_tail(&entry->list, &pool->free_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `		pool->total++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `		pool->free++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `static void ksmbd_buf_pool_free(struct ksmbd_buf_pool *pool)`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	struct ksmbd_buf_entry *entry, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	LIST_HEAD(to_free);`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [LOCK|] `	spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00099 [NONE] `	list_splice_init(&pool->free_list, &to_free);`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	pool->total -= pool->free;`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	pool->free = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [LOCK|] `	spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	list_for_each_entry_safe(entry, tmp, &to_free, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `		list_del(&entry->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `		kvfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `static struct ksmbd_buf_pool *ksmbd_buf_select_pool(size_t size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	if (size <= KSMBD_BUF_SMALL_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `		return &small_pool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	if (size <= KSMBD_BUF_LARGE_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `		return &large_pool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * ksmbd_buffer_pool_init() - Initialize the buffer pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` * Pre-allocates buffers in two tiers (small 64KB and large 1MB) to`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` * reduce allocation overhead on the SMB read/write hot path.`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ` * Return: 0 on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `int ksmbd_buffer_pool_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	ret = ksmbd_buf_pool_alloc(&small_pool, KSMBD_BUF_SMALL_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `				   KSMBD_BUF_SMALL_COUNT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [ERROR_PATH|] `		goto err_small;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	ret = ksmbd_buf_pool_alloc(&large_pool, KSMBD_BUF_LARGE_SIZE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `				   KSMBD_BUF_LARGE_COUNT);`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [ERROR_PATH|] `		goto err_large;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `err_large:`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	ksmbd_buf_pool_free(&small_pool);`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `err_small:`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` * ksmbd_buffer_pool_exit() - Destroy the buffer pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` * Frees all pre-allocated buffers and tears down the pool.`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `void ksmbd_buffer_pool_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	ksmbd_buf_pool_free(&large_pool);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	ksmbd_buf_pool_free(&small_pool);`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] ` * ksmbd_buffer_pool_get() - Get a buffer from the pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ` * @size: requested buffer size`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] ` * Returns a buffer of at least @size bytes. If the pool has a`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ` * suitable pre-allocated buffer, it is returned immediately.`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [MEM_BOUNDS|] ` * Otherwise falls back to kvzalloc().`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00167 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * Return: pointer to buffer or NULL on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `void *ksmbd_buffer_pool_get(size_t size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	struct ksmbd_buf_pool *pool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	struct ksmbd_buf_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	pool = ksmbd_buf_select_pool(size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	if (pool) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [LOCK|] `		spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00178 [NONE] `		if (!list_empty(&pool->free_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `			entry = list_first_entry(&pool->free_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `						 struct ksmbd_buf_entry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `						 list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `			list_del(&entry->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `			pool->free--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [LOCK|] `			spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00185 [NONE] `			memset(entry_to_buf(entry), 0, pool->buf_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `			return entry_to_buf(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [LOCK|] `		spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `		/* Pool exhausted, allocate with pool->buf_size */`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [MEM_BOUNDS|] `		entry = kvzalloc(sizeof(*entry) + pool->buf_size,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00192 [NONE] `				 KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		if (!entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `			return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `		entry->size = pool->buf_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		return entry_to_buf(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `	/* Size exceeds largest pool tier, fall back to kvzalloc */`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [MEM_BOUNDS|] `	entry = kvzalloc(sizeof(*entry) + size, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00201 [NONE] `	if (!entry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	entry->size = size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	return entry_to_buf(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * ksmbd_buffer_pool_put() - Return a buffer to the pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` * @buf: buffer previously obtained from ksmbd_buffer_pool_get()`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] ` * Returns the buffer to the appropriate freelist if the pool is not`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] ` * full. Otherwise frees the buffer via kvfree().`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `void ksmbd_buffer_pool_put(void *buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `	struct ksmbd_buf_entry *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	struct ksmbd_buf_pool *pool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	if (!buf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	entry = buf_to_entry(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	pool = ksmbd_buf_select_pool(entry->size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	if (pool) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [LOCK|] `		spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00227 [NONE] `		if (pool->free < pool->max_free) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `			list_add_tail(&entry->list, &pool->free_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `			pool->free++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [LOCK|] `			spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00231 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [LOCK|] `		spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00234 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	kvfree(entry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
