/* Stub for userspace testing */
#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H
#include <stdlib.h>
#define GFP_KERNEL 0
#define KSMBD_DEFAULT_GFP 0
static inline void *kzalloc(size_t size, int flags)
{
	(void)flags;
	return calloc(1, size);
}
#define kfree(ptr) free(ptr)
#endif
