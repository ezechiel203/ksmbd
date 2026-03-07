/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Userspace compatibility header for ksmbd fuzz targets.
 *
 * Provides definitions for kernel types, endian conversion macros,
 * and kernel API stubs so that ksmbd parsing code can be compiled
 * and fuzzed in userspace with ASAN/MSAN/UBSAN sanitizers.
 */

#ifndef _KSMBD_COMPAT_H
#define _KSMBD_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <endian.h>

/* --- Fixed-width kernel types --- */

typedef uint8_t   __u8;
typedef uint16_t  __u16;
typedef uint32_t  __u32;
typedef uint64_t  __u64;
typedef int8_t    __s8;
typedef int16_t   __s16;
typedef int32_t   __s32;
typedef int64_t   __s64;

typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef uint64_t  u64;
typedef int8_t    s8;
typedef int16_t   s16;
typedef int32_t   s32;
typedef int64_t   s64;

typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef s64 ssize_t;

/* --- Endian conversion macros --- */

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define cpu_to_le16(x) ((__le16)(__u16)(x))
#define cpu_to_le32(x) ((__le32)(__u32)(x))
#define cpu_to_le64(x) ((__le64)(__u64)(x))
#define le16_to_cpu(x) ((__u16)(__le16)(x))
#define le32_to_cpu(x) ((__u32)(__le32)(x))
#define le64_to_cpu(x) ((__u64)(__le64)(x))

#define cpu_to_be16(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define cpu_to_be32(x) ((__be32)__builtin_bswap32((__u32)(x)))
#define cpu_to_be64(x) ((__be64)__builtin_bswap64((__u64)(x)))
#define be16_to_cpu(x) ((__u16)__builtin_bswap16((__be16)(x)))
#define be32_to_cpu(x) ((__u32)__builtin_bswap32((__be32)(x)))
#define be64_to_cpu(x) ((__u64)__builtin_bswap64((__be64)(x)))

#else /* big endian */

#define cpu_to_le16(x) ((__le16)__builtin_bswap16((__u16)(x)))
#define cpu_to_le32(x) ((__le32)__builtin_bswap32((__u32)(x)))
#define cpu_to_le64(x) ((__le64)__builtin_bswap64((__u64)(x)))
#define le16_to_cpu(x) ((__u16)__builtin_bswap16((__le16)(x)))
#define le32_to_cpu(x) ((__u32)__builtin_bswap32((__le32)(x)))
#define le64_to_cpu(x) ((__u64)__builtin_bswap64((__le64)(x)))

#define cpu_to_be16(x) ((__be16)(__u16)(x))
#define cpu_to_be32(x) ((__be32)(__u32)(x))
#define cpu_to_be64(x) ((__be64)(__u64)(x))
#define be16_to_cpu(x) ((__u16)(__be16)(x))
#define be32_to_cpu(x) ((__u32)(__be32)(x))
#define be64_to_cpu(x) ((__u64)(__be64)(x))

#endif

/* --- Compiler attributes --- */

#define __packed   __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))

/* --- Basic kernel macros --- */

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef min
#define min(a, b) ({        \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b;  \
})
#endif

#ifndef max
#define max(a, b) ({        \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b;  \
})
#endif

#ifndef min_t
#define min_t(type, a, b) ({    \
	type _a = (type)(a);    \
	type _b = (type)(b);    \
	_a < _b ? _a : _b;      \
})
#endif

#ifndef max_t
#define max_t(type, a, b) ({    \
	type _a = (type)(a);    \
	type _b = (type)(b);    \
	_a > _b ? _a : _b;      \
})
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({               \
	const typeof(((type *)0)->member) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type, member)); \
})
#endif

#ifndef UINT_MAX
#define UINT_MAX (~0U)
#endif

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif

/* --- Kernel error codes --- */

#ifndef EINVAL
#define EINVAL 22
#endif

#ifndef ENOMEM
#define ENOMEM 12
#endif

#ifndef ENOSPC
#define ENOSPC 28
#endif

#ifndef EACCES
#define EACCES 13
#endif

#ifndef ENOENT
#define ENOENT 2
#endif

#ifndef EBADF
#define EBADF 9
#endif

#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif

/* --- Memory allocation stubs --- */

#define GFP_KERNEL 0

static inline void *kzalloc(size_t size, unsigned int flags)
{
	(void)flags;
	return calloc(1, size);
}

static inline void *kmalloc(size_t size, unsigned int flags)
{
	(void)flags;
	return malloc(size);
}

static inline void kfree(const void *ptr)
{
	free((void *)ptr);
}

/* --- Logging stubs (no-ops for fuzzing) --- */

#define pr_err(fmt, ...)    do { } while (0)
#define pr_warn(fmt, ...)   do { } while (0)
#define pr_info(fmt, ...)   do { } while (0)
#define pr_debug(fmt, ...)  do { } while (0)
#define pr_warn_ratelimited(fmt, ...) do { } while (0)

#define ksmbd_debug(type, fmt, ...) do { } while (0)

/* --- ERR_PTR / PTR_ERR / IS_ERR (kernel error pointer encoding) --- */

#define MAX_ERRNO 4095

static inline void *ERR_PTR(long error)
{
	return (void *)(intptr_t)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)(intptr_t)ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return (unsigned long)(intptr_t)ptr >= (unsigned long)-MAX_ERRNO;
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR(ptr);
}

#endif /* _KSMBD_COMPAT_H */
