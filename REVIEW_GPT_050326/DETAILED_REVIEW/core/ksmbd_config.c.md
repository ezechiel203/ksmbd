# Line-by-line Review: src/core/ksmbd_config.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include "ksmbd_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `static u32 config_values[__KSMBD_CFG_MAX];`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `static DEFINE_RWLOCK(config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `static const struct ksmbd_config_desc config_descs[__KSMBD_CFG_MAX] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `	[KSMBD_CFG_MAX_READ_SIZE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `		.name		= "max read size",`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `		.def_val	= 65536,`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `		.min_val	= 4096,`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `		.max_val	= 8388608,	/* 8MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	[KSMBD_CFG_MAX_WRITE_SIZE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `		.name		= "max write size",`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `		.def_val	= 65536,`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `		.min_val	= 4096,`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `		.max_val	= 8388608,`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `	[KSMBD_CFG_MAX_TRANS_SIZE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `		.name		= "max transact size",`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `		.def_val	= 65536,`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `		.min_val	= 4096,`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `		.max_val	= 8388608,`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	[KSMBD_CFG_MAX_CREDITS] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `		.name		= "max credits",`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `		.def_val	= 8192,`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `		.min_val	= 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `		.max_val	= 65535,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	[KSMBD_CFG_MAX_CONNECTIONS] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `		.name		= "max connections",`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `		.def_val	= 1024,`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `		.min_val	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `		.max_val	= 65535,`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `		.runtime	= true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	[KSMBD_CFG_MAX_CONNECTIONS_PER_IP] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `		.name		= "max connections per IP",`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `		.def_val	= 64,`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `		.min_val	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `		.max_val	= 65535,`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `		.runtime	= true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	[KSMBD_CFG_DEADTIME] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `		.name		= "deadtime",`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `		.def_val	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `		.min_val	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `		.max_val	= 86400,	/* 24h */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `		.runtime	= true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `	[KSMBD_CFG_COPY_CHUNK_MAX_COUNT] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `		.name		= "copy chunk max count",`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `		.def_val	= 256,`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `		.min_val	= 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `		.max_val	= 65535,`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	[KSMBD_CFG_COPY_CHUNK_MAX_SIZE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `		.name		= "copy chunk max size",`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `		.def_val	= 1048576,	/* 1MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `		.min_val	= 4096,`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `		.max_val	= 16777216,	/* 16MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	[KSMBD_CFG_COPY_CHUNK_TOTAL_SIZE] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `		.name		= "copy chunk total size",`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `		.def_val	= 16777216,	/* 16MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `		.min_val	= 4096,`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `		.max_val	= 268435456,	/* 256MB */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	[KSMBD_CFG_SMB_ECHO_INTERVAL] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `		.name		= "smb echo interval",`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `		.def_val	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `		.min_val	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `		.max_val	= 3600,`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `		.runtime	= true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	[KSMBD_CFG_IPC_TIMEOUT] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `		.name		= "ipc timeout",`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `		.def_val	= 10,`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		.min_val	= 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `		.max_val	= 300,`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		.runtime	= false,`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * ksmbd_config_init() - initialize all configuration parameters to defaults`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ` * Return:	0 on success`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `int ksmbd_config_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	write_lock(&config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	for (i = 0; i < __KSMBD_CFG_MAX; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `		config_values[i] = config_descs[i].def_val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	write_unlock(&config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	pr_info("Configuration subsystem initialized with %d parameters\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		__KSMBD_CFG_MAX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] ` * ksmbd_config_exit() - clean up configuration subsystem`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `void ksmbd_config_exit(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	/* Nothing to free; static arrays only */`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] ` * ksmbd_config_set_u32() - set a configuration parameter with validation`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ` * @param:	configuration parameter enum`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ` * @val:	value to set`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` * Values outside [min_val, max_val] are clamped and a warning is emitted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * Return:	0 on success, -EINVAL for invalid param`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `int ksmbd_config_set_u32(enum ksmbd_config_param param, u32 val)`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	const struct ksmbd_config_desc *desc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	if (param < 0 || param >= __KSMBD_CFG_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	desc = &config_descs[param];`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	if (desc->max_val && val > desc->max_val) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [ERROR_PATH|] `		pr_warn("Config '%s': value %u exceeds max %u, clamping\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00150 [NONE] `			desc->name, val, desc->max_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `		val = desc->max_val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	if (val < desc->min_val) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [ERROR_PATH|] `		pr_warn("Config '%s': value %u below min %u, clamping\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00156 [NONE] `			desc->name, val, desc->min_val);`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `		val = desc->min_val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	write_lock(&config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	config_values[param] = val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	write_unlock(&config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * ksmbd_config_get_u32() - read a configuration parameter`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` * @param:	configuration parameter enum`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ` * Return:	current value of the parameter, or 0 for invalid param`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `u32 ksmbd_config_get_u32(enum ksmbd_config_param param)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	u32 val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	if (param < 0 || param >= __KSMBD_CFG_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	read_lock(&config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	val = config_values[param];`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	read_unlock(&config_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	return val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] ` * ksmbd_config_param_name() - get the human-readable name of a parameter`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ` * @param:	configuration parameter enum`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ` * Return:	name string, or "(invalid)" for invalid param`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `const char *ksmbd_config_param_name(enum ksmbd_config_param param)`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	if (param < 0 || param >= __KSMBD_CFG_MAX)`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `		return "(invalid)";`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `	return config_descs[param].name;`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
