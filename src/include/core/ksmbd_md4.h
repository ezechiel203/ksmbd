/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Self-contained MD4 hash for ksmbd.
 *
 * Registers a crypto_shash algorithm named "md4" so that
 * crypto_alloc_shash("md4", 0, 0) succeeds even on kernels
 * that removed the in-tree md4 module (>= 6.6).
 */
#ifndef __KSMBD_MD4_H__
#define __KSMBD_MD4_H__

int ksmbd_md4_register(void);
void ksmbd_md4_unregister(void);

#endif /* __KSMBD_MD4_H__ */
