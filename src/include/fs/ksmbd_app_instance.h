/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   APP_INSTANCE_ID / APP_INSTANCE_VERSION create context support
 */

#ifndef __KSMBD_APP_INSTANCE_H
#define __KSMBD_APP_INSTANCE_H

/**
 * ksmbd_app_instance_init() - Initialize app instance create contexts
 *
 * Registers the SMB2_CREATE_APP_INSTANCE_ID and
 * SMB2_CREATE_APP_INSTANCE_VERSION create context handlers.
 * Must be called during module initialization after
 * ksmbd_create_ctx_init().
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_app_instance_init(void);

/**
 * ksmbd_app_instance_exit() - Tear down app instance create contexts
 *
 * Unregisters the create context handlers and releases resources.
 * Must be called during module exit.
 */
void ksmbd_app_instance_exit(void);

#endif /* __KSMBD_APP_INSTANCE_H */
