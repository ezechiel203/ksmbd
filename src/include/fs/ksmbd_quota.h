/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   SMB2 quota query support for ksmbd
 */

#ifndef __KSMBD_QUOTA_H
#define __KSMBD_QUOTA_H

/**
 * ksmbd_quota_init() - Initialize quota query handlers
 *
 * Registers the SMB2_O_INFO_QUOTA info-level handler in the
 * dispatch table so that quota queries from clients are handled.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_quota_init(void);

/**
 * ksmbd_quota_exit() - Tear down quota query handlers
 *
 * Unregisters the quota info-level handler.
 */
void ksmbd_quota_exit(void);

#endif /* __KSMBD_QUOTA_H */
