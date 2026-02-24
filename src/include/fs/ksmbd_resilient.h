/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   Resilient handle support for ksmbd
 */

#ifndef __KSMBD_RESILIENT_H
#define __KSMBD_RESILIENT_H

/**
 * ksmbd_resilient_init() - Initialize resilient handle subsystem
 *
 * Registers the FSCTL handler for FSCTL_LMR_REQUEST_RESILIENCY
 * (0x001401D4).  Must be called during module initialization
 * after ksmbd_fsctl_init().
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_resilient_init(void);

/**
 * ksmbd_resilient_exit() - Tear down resilient handle subsystem
 *
 * Unregisters the FSCTL handler and releases resources.
 * Must be called during module exit.
 */
void ksmbd_resilient_exit(void);

#endif /* __KSMBD_RESILIENT_H */
