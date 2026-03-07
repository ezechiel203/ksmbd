/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#ifndef __KSMBD_CONFIG_H__
#define __KSMBD_CONFIG_H__

#include <linux/types.h>

enum ksmbd_config_param {
	KSMBD_CFG_MAX_READ_SIZE,
	KSMBD_CFG_MAX_WRITE_SIZE,
	KSMBD_CFG_MAX_TRANS_SIZE,
	KSMBD_CFG_MAX_CREDITS,
	KSMBD_CFG_MAX_CONNECTIONS,
	KSMBD_CFG_MAX_CONNECTIONS_PER_IP,
	KSMBD_CFG_DEADTIME,
	KSMBD_CFG_COPY_CHUNK_MAX_COUNT,
	KSMBD_CFG_COPY_CHUNK_MAX_SIZE,
	KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE,
	KSMBD_CFG_SMB_ECHO_INTERVAL,
	KSMBD_CFG_IPC_TIMEOUT,
	__KSMBD_CFG_MAX,
};

/**
 * struct ksmbd_config_desc - descriptor for one configuration parameter
 * @name:	human-readable name (for debugfs/logging)
 * @def_val:	default value
 * @min_val:	minimum allowed value (0 = no minimum)
 * @max_val:	maximum allowed value (0 = no maximum)
 * @runtime:	can be changed at runtime (during SIGHUP reload)
 */
struct ksmbd_config_desc {
	const char	*name;
	u32		def_val;
	u32		min_val;
	u32		max_val;
	bool		runtime;
};

/**
 * ksmbd_config_init() - initialize all configuration parameters to defaults
 *
 * Return:	0 on success, negative errno on failure
 */
int ksmbd_config_init(void);

/**
 * ksmbd_config_exit() - clean up configuration subsystem
 */
void ksmbd_config_exit(void);

/**
 * ksmbd_config_set_u32() - set a configuration parameter with validation
 * @param:	configuration parameter enum
 * @val:	value to set
 *
 * Values outside [min_val, max_val] are clamped and a warning is emitted.
 *
 * Return:	0 on success, -EINVAL for invalid param
 */
int ksmbd_config_set_u32(enum ksmbd_config_param param, u32 val);

/**
 * ksmbd_config_get_u32() - read a configuration parameter
 * @param:	configuration parameter enum
 *
 * Return:	current value of the parameter, or 0 for invalid param
 */
u32 ksmbd_config_get_u32(enum ksmbd_config_param param);

/**
 * ksmbd_config_param_name() - get the human-readable name of a parameter
 * @param:	configuration parameter enum
 *
 * Return:	name string, or "(invalid)" for invalid param
 */
const char *ksmbd_config_param_name(enum ksmbd_config_param param);

#endif /* __KSMBD_CONFIG_H__ */
