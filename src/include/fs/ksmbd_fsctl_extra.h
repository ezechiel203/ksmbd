/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Extra FSCTL handlers for ksmbd (TRIM, ALLOCATED_RANGES,
 *   SET_ZERO_DATA, PIPE_WAIT)
 */

#ifndef __KSMBD_FSCTL_EXTRA_H
#define __KSMBD_FSCTL_EXTRA_H

/**
 * ksmbd_fsctl_extra_init() - Initialize extra FSCTL handlers
 *
 * Registers FSCTL handlers for FSCTL_FILE_LEVEL_TRIM,
 * FSCTL_QUERY_ALLOCATED_RANGES, FSCTL_SET_ZERO_DATA, and
 * FSCTL_PIPE_WAIT.  Must be called during module initialization
 * after ksmbd_fsctl_init().
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_fsctl_extra_init(void);

/**
 * ksmbd_fsctl_extra_exit() - Tear down extra FSCTL handlers
 *
 * Unregisters all extra FSCTL handlers and releases resources.
 * Must be called during module exit.
 */
void ksmbd_fsctl_extra_exit(void);

#endif /* __KSMBD_FSCTL_EXTRA_H */
