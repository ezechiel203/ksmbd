/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Reparse point FSCTL handlers for ksmbd
 */

#ifndef __KSMBD_REPARSE_H
#define __KSMBD_REPARSE_H

/**
 * ksmbd_reparse_init() - Initialize reparse point subsystem
 *
 * Registers FSCTL handlers for FSCTL_SET_REPARSE_POINT,
 * FSCTL_GET_REPARSE_POINT, and FSCTL_DELETE_REPARSE_POINT.
 * Must be called during module initialization after
 * ksmbd_fsctl_init().
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_reparse_init(void);

/**
 * ksmbd_reparse_exit() - Tear down reparse point subsystem
 *
 * Unregisters FSCTL handlers and releases resources.
 * Must be called during module exit.
 */
void ksmbd_reparse_exit(void);

#endif /* __KSMBD_REPARSE_H */
