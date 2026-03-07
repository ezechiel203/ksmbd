// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/spinlock.h>

#include "ksmbd_config.h"
#include "glob.h"

static u32 config_values[__KSMBD_CFG_MAX];
static DEFINE_RWLOCK(config_lock);

static const struct ksmbd_config_desc config_descs[__KSMBD_CFG_MAX] = {
	[KSMBD_CFG_MAX_READ_SIZE] = {
		.name		= "max read size",
		.def_val	= 65536,
		.min_val	= 4096,
		.max_val	= 8388608,	/* 8MB */
		.runtime	= false,
	},
	[KSMBD_CFG_MAX_WRITE_SIZE] = {
		.name		= "max write size",
		.def_val	= 65536,
		.min_val	= 4096,
		.max_val	= 8388608,
		.runtime	= false,
	},
	[KSMBD_CFG_MAX_TRANS_SIZE] = {
		.name		= "max transact size",
		.def_val	= 65536,
		.min_val	= 4096,
		.max_val	= 8388608,
		.runtime	= false,
	},
	[KSMBD_CFG_MAX_CREDITS] = {
		.name		= "max credits",
		.def_val	= 8192,
		.min_val	= 1,
		.max_val	= 65535,
		.runtime	= false,
	},
	[KSMBD_CFG_MAX_CONNECTIONS] = {
		.name		= "max connections",
		.def_val	= 1024,
		.min_val	= 0,
		.max_val	= 65535,
		.runtime	= true,
	},
	[KSMBD_CFG_MAX_CONNECTIONS_PER_IP] = {
		.name		= "max connections per IP",
		.def_val	= 64,
		.min_val	= 0,
		.max_val	= 65535,
		.runtime	= true,
	},
	[KSMBD_CFG_DEADTIME] = {
		.name		= "deadtime",
		.def_val	= 0,
		.min_val	= 0,
		.max_val	= 86400,	/* 24h */
		.runtime	= true,
	},
	[KSMBD_CFG_COPY_CHUNK_MAX_COUNT] = {
		.name		= "copy chunk max count",
		.def_val	= 256,
		.min_val	= 1,
		.max_val	= 65535,
		.runtime	= false,
	},
	[KSMBD_CFG_COPY_CHUNK_MAX_SIZE] = {
		.name		= "copy chunk max size",
		.def_val	= 1048576,	/* 1MB */
		.min_val	= 4096,
		.max_val	= 16777216,	/* 16MB */
		.runtime	= false,
	},
	[KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE] = {
		.name		= "copy chunk total size",
		.def_val	= 16777216,	/* 16MB */
		.min_val	= 4096,
		.max_val	= 268435456,	/* 256MB */
		.runtime	= false,
	},
	[KSMBD_CFG_SMB_ECHO_INTERVAL] = {
		.name		= "smb echo interval",
		.def_val	= 0,
		.min_val	= 0,
		.max_val	= 3600,
		.runtime	= true,
	},
	[KSMBD_CFG_IPC_TIMEOUT] = {
		.name		= "ipc timeout",
		.def_val	= 10,
		.min_val	= 1,
		.max_val	= 300,
		.runtime	= false,
	},
};

/**
 * ksmbd_config_init() - initialize all configuration parameters to defaults
 *
 * Return:	0 on success
 */
int ksmbd_config_init(void)
{
	int i;

	write_lock(&config_lock);
	for (i = 0; i < __KSMBD_CFG_MAX; i++)
		config_values[i] = config_descs[i].def_val;
	write_unlock(&config_lock);

	pr_info("Configuration subsystem initialized with %d parameters\n",
		__KSMBD_CFG_MAX);
	return 0;
}

/**
 * ksmbd_config_exit() - clean up configuration subsystem
 */
void ksmbd_config_exit(void)
{
	/* Nothing to free; static arrays only */
}

/**
 * ksmbd_config_set_u32() - set a configuration parameter with validation
 * @param:	configuration parameter enum
 * @val:	value to set
 *
 * Values outside [min_val, max_val] are clamped and a warning is emitted.
 *
 * Return:	0 on success, -EINVAL for invalid param
 */
int ksmbd_config_set_u32(enum ksmbd_config_param param, u32 val)
{
	const struct ksmbd_config_desc *desc;

	if (param < 0 || param >= __KSMBD_CFG_MAX)
		return -EINVAL;

	desc = &config_descs[param];

	if (desc->max_val && val > desc->max_val) {
		pr_warn("Config '%s': value %u exceeds max %u, clamping\n",
			desc->name, val, desc->max_val);
		val = desc->max_val;
	}

	if (val < desc->min_val) {
		pr_warn("Config '%s': value %u below min %u, clamping\n",
			desc->name, val, desc->min_val);
		val = desc->min_val;
	}

	write_lock(&config_lock);
	config_values[param] = val;
	write_unlock(&config_lock);

	return 0;
}

/**
 * ksmbd_config_get_u32() - read a configuration parameter
 * @param:	configuration parameter enum
 *
 * Return:	current value of the parameter, or 0 for invalid param
 */
u32 ksmbd_config_get_u32(enum ksmbd_config_param param)
{
	u32 val;

	if (param < 0 || param >= __KSMBD_CFG_MAX)
		return 0;

	read_lock(&config_lock);
	val = config_values[param];
	read_unlock(&config_lock);

	return val;
}

/**
 * ksmbd_config_param_name() - get the human-readable name of a parameter
 * @param:	configuration parameter enum
 *
 * Return:	name string, or "(invalid)" for invalid param
 */
const char *ksmbd_config_param_name(enum ksmbd_config_param param)
{
	if (param < 0 || param >= __KSMBD_CFG_MAX)
		return "(invalid)";

	return config_descs[param].name;
}
