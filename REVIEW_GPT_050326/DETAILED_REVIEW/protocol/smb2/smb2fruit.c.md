# Line-by-line Review: src/protocol/smb2/smb2fruit.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2025 Alexandre BETRY`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *   Fruit SMB extensions for KSMBD`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/kernel.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/string.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/errno.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/stat.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/statfs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/timekeeping.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <linux/xattr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <linux/fs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include "smb2fruit.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#include "smb2pdu_internal.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "ksmbd_netlink.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "mgmt/share_config.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "oplock.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "vfs_cache.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `/* Wire protocol signature - must remain "AAPL" for compatibility */`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `static const __u8 fruit_smb_signature[4] = {'A', 'A', 'P', 'L'};`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/* Wire xattr name - must remain unchanged for compatibility */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define LOOKERINFO_XATTR_NAME "com.apple.FinderInfo"`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` * Maximum allowed DataLength for an AAPL create context.  This caps the`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` * amount of data the server will accept from the client, preventing`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` * excessive memory allocation from a crafted request.  4 KiB is far`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` * larger than any legitimate AAPL context payload.`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `#define FRUIT_CREATE_CTX_MAX_DATA_LEN	4096`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `bool fruit_is_client_request(const void *buffer, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	const struct create_context *context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	if (len < sizeof(struct smb2_create_req))`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	context = smb2_find_context_vals((void *)buffer,`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [PROTO_GATE|] `					 SMB2_CREATE_AAPL, 4);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00053 [NONE] `	if (!context || IS_ERR(context))`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	if (le16_to_cpu(context->NameLength) != 4 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	    le32_to_cpu(context->DataLength) < sizeof(struct fruit_client_info) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	    le32_to_cpu(context->DataLength) > FRUIT_CREATE_CTX_MAX_DATA_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `int fruit_parse_client_info(const void *context_data, size_t data_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `			    struct fruit_conn_state *state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	const struct fruit_client_info *client_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `	if (!context_data || !state || data_len < sizeof(struct fruit_client_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00071 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	client_info = context_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	if (memcmp(client_info->signature, fruit_smb_signature, 4) != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	state->client_version = le32_to_cpu(client_info->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	state->client_type = le32_to_cpu(client_info->client_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	state->client_capabilities = le64_to_cpu(client_info->capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [MEM_BOUNDS|] `	memcpy(state->client_build, &client_info->build_number,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00082 [NONE] `	       min_t(size_t, sizeof(state->client_build),`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `		     sizeof(client_info->build_number)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * Compute kAAPL server_caps from global config flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * These bits are sent on the wire in the AAPL create context response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `static u64 fruit_compute_server_caps(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	u64 caps = kAAPL_UNIX_BASED; /* always: Linux is UNIX-based */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `		caps |= kAAPL_SUPPORTS_OSX_COPYFILE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES)`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `		caps |= kAAPL_SUPPORTS_NFS_ACE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	/* ReadDirAttr is gated per-share, but advertised globally */`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	caps |= kAAPL_SUPPORTS_READ_DIR_ATTR;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	return caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `int fruit_negotiate_capabilities(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `				 const struct fruit_client_info *client_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	struct fruit_conn_state *state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	u64 server_caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	if (!conn || !client_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	if (!conn->fruit_state) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [MEM_BOUNDS|] `		conn->fruit_state = kzalloc(sizeof(struct fruit_conn_state),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00117 [NONE] `					    GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `		if (!conn->fruit_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [ERROR_PATH|] `			return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00120 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	state = conn->fruit_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	server_caps = fruit_compute_server_caps();`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	state->client_version = le32_to_cpu(client_info->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	state->client_type = le32_to_cpu(client_info->client_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	state->client_capabilities = le64_to_cpu(client_info->capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	state->supported_features = server_caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	state->negotiated_capabilities = server_caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	state->enabled_features = server_caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	state->extensions_enabled = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `bool fruit_supports_capability(struct fruit_conn_state *state, u64 capability)`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	if (!state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	return !!(state->negotiated_capabilities & capability);`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `int fruit_detect_client_version(const void *data, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	const struct fruit_client_info *client_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	if (!data || len < sizeof(struct fruit_client_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	client_info = data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	if (memcmp(client_info->signature, fruit_smb_signature, 4) != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	return le32_to_cpu(client_info->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `const char *fruit_get_client_name(__le32 client_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	switch (le32_to_cpu(client_type)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	case FRUIT_CLIENT_MACOS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `		return "macOS";`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	case FRUIT_CLIENT_IOS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `		return "iOS";`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	case FRUIT_CLIENT_IPADOS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `		return "iPadOS";`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	case FRUIT_CLIENT_TVOS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `		return "tvOS";`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	case FRUIT_CLIENT_WATCHOS:`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `		return "watchOS";`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `		return "Unknown";`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `const char *fruit_get_version_string(__le32 version)`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	switch (le32_to_cpu(version)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	case FRUIT_VERSION_1_0:`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `		return "1.0";`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	case FRUIT_VERSION_1_1:`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `		return "1.1";`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	case FRUIT_VERSION_2_0:`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `		return "2.0";`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `		return "Unknown";`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `bool fruit_valid_signature(const __u8 *signature)`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	if (!signature)`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	return memcmp(signature, fruit_smb_signature, 4) == 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `int fruit_validate_create_context(const struct create_context *context)`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `	if (!context)`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00202 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	if (le16_to_cpu(context->NameLength) != 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00205 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `	if (le32_to_cpu(context->DataLength) < sizeof(struct fruit_client_info))`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	if (le32_to_cpu(context->DataLength) > FRUIT_CREATE_CTX_MAX_DATA_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00211 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `int fruit_init_connection_state(struct fruit_conn_state *state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `	u64 caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	if (!state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	memset(state, 0, sizeof(*state));`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	caps = fruit_compute_server_caps();`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	state->supported_features = caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	state->enabled_features = caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	state->negotiated_capabilities = caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `void fruit_cleanup_connection_state(struct fruit_conn_state *state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	if (!state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	memset(state, 0, sizeof(*state));`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `int fruit_update_connection_state(struct fruit_conn_state *state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `				  const struct fruit_client_info *client_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	if (!state || !client_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00244 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	if (memcmp(client_info->signature, fruit_smb_signature, 4) != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00247 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `	state->client_version = le32_to_cpu(client_info->version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	state->client_type = le32_to_cpu(client_info->client_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	state->client_capabilities = le64_to_cpu(client_info->capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [MEM_BOUNDS|] `	memcpy(state->client_build, &client_info->build_number,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00253 [NONE] `	       min_t(size_t, sizeof(state->client_build),`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] `		     sizeof(client_info->build_number)));`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `	state->negotiated_capabilities =`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `		state->client_capabilities & state->supported_features;`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `	state->enabled_features = state->negotiated_capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `void fruit_debug_client_info(const struct fruit_client_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	if (!info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	ksmbd_debug(SMB, "Fruit client: sig=%.4s ver=%s(0x%08x) type=%s(0x%08x) caps=0x%016llx\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `		    info->signature,`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `		    fruit_get_version_string(info->version),`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		    le32_to_cpu(info->version),`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `		    fruit_get_client_name(info->client_type),`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `		    le32_to_cpu(info->client_type),`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `		    le64_to_cpu(info->capabilities));`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `size_t fruit_get_context_size(const char *context_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	if (!context_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	if (strcmp(context_name, FRUIT_SERVER_QUERY_CONTEXT) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `		return sizeof(struct fruit_server_query);`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	if (strcmp(context_name, FRUIT_VOLUME_CAPABILITIES_CONTEXT) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `		return sizeof(struct fruit_volume_capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	if (strcmp(context_name, FRUIT_FILE_MODE_CONTEXT) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `		return sizeof(struct fruit_file_mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	if (strcmp(context_name, FRUIT_DIR_HARDLINKS_CONTEXT) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `		return sizeof(struct fruit_dir_hardlinks);`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	if (strcmp(context_name, FRUIT_LOOKERINFO_CONTEXT) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `		return sizeof(struct fruit_looker_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (strcmp(context_name, FRUIT_SAVEBOX_CONTEXT) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `		return sizeof(struct fruit_savebox_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `int fruit_build_server_response(void **response_data, size_t *response_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `				__le64 capabilities, __le32 query_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `	struct fruit_server_query *query;`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `	size_t size = sizeof(struct fruit_server_query);`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `	if (!response_data || !response_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00306 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [MEM_BOUNDS|] `	*response_data = kzalloc(size, GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00308 [NONE] `	if (!*response_data)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00310 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `	query = *response_data;`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `	query->type = query_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	query->flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	query->max_response_size = cpu_to_le32(size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	query->reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	*response_len = size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `int fruit_process_looker_info(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `			      const struct fruit_looker_info *looker_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `	if (!conn || !looker_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] `	ksmbd_debug(SMB, "Fruit LookerInfo: creator=%.4s type=%.4s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `		    looker_info->creator, looker_info->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `int fruit_process_savebox_info(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `			       const struct fruit_savebox_info *sb_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `	if (!conn || !sb_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `	ksmbd_debug(SMB, "Fruit Save box: version=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `		    le32_to_cpu(sb_info->version));`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `int fruit_handle_savebox_bundle(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `				const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `				const struct fruit_savebox_info *sb_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] `	if (!conn || !path || !sb_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00352 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `	ksmbd_debug(SMB, "Fruit Save box bundle\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] ` * fruit_synthesize_afpinfo - Build a 60-byte AFP_AfpInfo structure`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] ` * from the com.apple.FinderInfo xattr (netatalk migration path).`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] ` * When a macOS client reads the AFP_AfpInfo stream and the DosStream`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] ` * xattr doesn't exist, we try to synthesize it from the native`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] ` * com.apple.FinderInfo xattr that netatalk/AFP servers create.`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] ` * Returns AFP_AFPINFO_SIZE (60) on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `int fruit_synthesize_afpinfo(struct mnt_idmap *idmap, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `			     char *buf, size_t bufsize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	ssize_t fi_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `	__be32 val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `	if (!idmap || !dentry || !buf || bufsize < AFP_AFPINFO_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00376 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	 * Try to read the native com.apple.FinderInfo xattr.`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `	 * This is what netatalk stores (32 bytes of FinderInfo data).`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] `	fi_len = vfs_getxattr(idmap, dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `			      APPLE_FINDER_INFO_XATTR_USER,`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `			      buf + 16, AFP_FINDER_INFO_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	if (fi_len < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		return fi_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	 * Build the 60-byte AfpInfo header around the FinderInfo.`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `	 * All multi-byte fields are big-endian (Apple convention).`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `	 * Offset  Size  Field`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `	 * 0       4     Magic ("AFP\0" = 0x41465000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	 * 4       4     Version (0x00010000 = 1.0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	 * 8       4     FileID (0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	 * 12      4     BackupDate (0x80000000 = invalid)`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `	 * 16      32    FinderInfo (already placed by vfs_getxattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	 * 48      6     ProDOS info (0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `	 * 54      6     Padding (0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `	memset(buf, 0, 16);    /* clear header area */`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `	memset(buf + 48, 0, 12); /* clear ProDOS + padding */`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	val = cpu_to_be32(AFP_MAGIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [MEM_BOUNDS|] `	memcpy(buf, &val, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `	val = cpu_to_be32(AFP_VERSION);`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [MEM_BOUNDS|] `	memcpy(buf + 4, &val, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	/* FileID = 0 (bytes 8-11 already zeroed) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `	val = cpu_to_be32(AFP_BACKUP_DATE_INVALID);`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [MEM_BOUNDS|] `	memcpy(buf + 12, &val, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00413 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `	/* FinderInfo at offset 16 was already written by vfs_getxattr */`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `	/* Pad remaining bytes if FinderInfo was short */`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] `	if (fi_len < AFP_FINDER_INFO_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `		memset(buf + 16 + fi_len, 0, AFP_FINDER_INFO_SIZE - fi_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	return AFP_AFPINFO_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `/* ── Step 1: AFP_AfpInfo Stream Interception ───────────────────── */`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ` * ksmbd_fruit_is_afpinfo_stream() - Check if path is an AFP_AfpInfo stream`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] ` * @stream_name:	stream name portion of the path (after the colon)`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ` * When a macOS client opens "filename:AFP_AfpInfo:$DATA", ksmbd should`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] ` * intercept this and serve AFP metadata from extended attributes rather`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] ` * than requiring a real alternate data stream.`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] ` * Return:	true if the stream name matches AFP_AfpInfo (case-insensitive)`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `bool ksmbd_fruit_is_afpinfo_stream(const char *stream_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	if (!stream_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] `	return !strncasecmp(stream_name, AFP_AFPINFO_STREAM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `			    sizeof(AFP_AFPINFO_STREAM) - 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ` * ksmbd_fruit_read_afpinfo() - Read AFP_AfpInfo from xattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ` * @path:	path to the file whose AFP_AfpInfo is requested`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] ` * @buf:	output buffer (must be at least AFP_AFPINFO_SIZE bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ` * @len:	size of output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ` * Reads the AFP_AfpInfo data for a file. First tries the DosStream xattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ` * (user.DosStream.AFP_AfpInfo:$DATA), then falls back to synthesizing`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ` * from com.apple.FinderInfo xattr via fruit_synthesize_afpinfo().`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ` * Return:	AFP_AFPINFO_SIZE (60) on success, negative errno on failure`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `int ksmbd_fruit_read_afpinfo(struct path *path, void *buf, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] `	struct mnt_idmap *idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	ssize_t ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `	if (!path || !buf || len < AFP_AFPINFO_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	dentry = path->dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	if (!dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00468 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	idmap = mnt_idmap(path->mnt);`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] `	 * First, try reading from the DosStream xattr which stores`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	 * the complete 60-byte AFP_AfpInfo structure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	ret = vfs_getxattr(idmap, dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `			   XATTR_NAME_AFP_AFPINFO,`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `			   buf, AFP_AFPINFO_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	if (ret == AFP_AFPINFO_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `		return AFP_AFPINFO_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	 * Fall back to synthesizing from com.apple.FinderInfo xattr`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	 * (netatalk migration path).`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] `	memset(buf, 0, AFP_AFPINFO_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	ret = fruit_synthesize_afpinfo(idmap, dentry, buf, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	if (ret > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [NONE] `	 * No AFP metadata available at all. Return a blank AfpInfo`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `	 * structure with valid magic/version so macOS does not error out.`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	memset(buf, 0, AFP_AFPINFO_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `		__be32 val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `		val = cpu_to_be32(AFP_MAGIC);`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [MEM_BOUNDS|] `		memcpy(buf, &val, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `		val = cpu_to_be32(AFP_VERSION);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [MEM_BOUNDS|] `		memcpy(buf + 4, &val, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00503 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `		val = cpu_to_be32(AFP_BACKUP_DATE_INVALID);`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [MEM_BOUNDS|] `		memcpy(buf + 12, &val, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00506 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	return AFP_AFPINFO_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `/* ── Step 2: Time Machine Quota Enforcement ────────────────────── */`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] ` * ksmbd_fruit_check_tm_quota() - Check Time Machine backup size limit`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] ` * @share:	share configuration to check`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ` * @share_path:	VFS path to the share root`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] ` * For shares with "fruit time machine = yes" and a configured max size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] ` * this checks whether the current usage exceeds the Time Machine quota.`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] ` * The used space is computed as (total_blocks - free_blocks) * block_size.`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ` * Return:	0 if within quota or quota not configured,`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` *		-ENOSPC if the quota has been exceeded,`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` *		negative errno on other errors`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] `int ksmbd_fruit_check_tm_quota(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `			       struct path *share_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] `	struct kstatfs stfs;`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	unsigned long long used_bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] `	if (!share || !share_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00535 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] `	/* No TM flag or no max size configured — no quota to enforce */`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	if (!test_share_config_flag(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `				    KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	if (share->time_machine_max_size == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	rc = vfs_statfs(share_path, &stfs);`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	if (rc) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [ERROR_PATH|] `		pr_err("ksmbd: fruit TM quota: vfs_statfs failed: %d\n", rc);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00547 [NONE] `		return rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `	if (stfs.f_bfree > stfs.f_blocks)`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		stfs.f_bfree = stfs.f_blocks;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `	used_bytes = (u64)(stfs.f_blocks - stfs.f_bfree) * stfs.f_bsize;`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `	if (used_bytes >= share->time_machine_max_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `		ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `			    "Fruit TM quota exceeded: used=%llu max=%llu\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `			    used_bytes, share->time_machine_max_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [ERROR_PATH|] `		return -ENOSPC;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00559 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `/* ── Step 3: ReadDirAttr Enrichment ────────────────────────────── */`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `/* xattr name for the resource fork DosStream */`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `#define XATTR_NAME_AFP_RESOURCE \`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	"user.DosStream." AFP_RESOURCE_STREAM ":$DATA"`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] ` * ksmbd_fruit_fill_readdir_attr() - Enrich directory entry with fruit metadata`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] ` * @dir_fp:	file pointer for the directory being listed`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] ` * @ksmbd_kstat:	kstat wrapper for the directory entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ` * @entry_path:	VFS path to the directory entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] ` * When fruit extensions are negotiated, macOS Finder expects enriched`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ` * directory listing entries.  This function adds:`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] ` *   - Resource fork size (from the AFP_Resource DosStream xattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ` *   - FinderInfo (from com.apple.FinderInfo xattr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ` * These enrichments are gated per-share via FRUIT_RFORK_SIZE and`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] ` * FRUIT_FINDER_INFO flags so admins can enable them selectively.`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] ` * Return:	0 on success, negative errno on failure (non-fatal)`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `int ksmbd_fruit_fill_readdir_attr(struct ksmbd_file *dir_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `				  struct ksmbd_kstat *ksmbd_kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `				  struct path *entry_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	struct ksmbd_share_config *share;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	struct dentry *dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	ssize_t rfork_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `	if (!dir_fp || !ksmbd_kstat || !entry_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00596 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `	if (!dir_fp->tcon || !dir_fp->tcon->share_conf)`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] `	share = dir_fp->tcon->share_conf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	dentry = entry_path->dentry;`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	if (!dentry)`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `	 * Resource fork size: read the length of the AFP_Resource`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	 * DosStream xattr.  A negative return means no resource fork.`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	if (test_share_config_flag(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `				   KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `		rfork_len = vfs_getxattr(mnt_idmap(entry_path->mnt), dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `					 XATTR_NAME_AFP_RESOURCE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `					 NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `		if (rfork_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `				    "Fruit readdir: rfork size=%zd for %pd\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `				    rfork_len, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		 * We report the resource fork size through the EaSize`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] `		 * field override (handled in smb2_read_dir_attr_fill).`
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		 * The size itself is informational for debug here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `/* ── Step 4: Volume Capabilities — Resolve File ID support ─────── */`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ` * ksmbd_fruit_get_volume_caps() - Compute AAPL volume capabilities`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] ` * @share:	share configuration (may be NULL for defaults)`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ` * Returns the volume_caps bitfield for the AAPL create context response.`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] ` * This includes file ID resolution support (kAAPL_SUPPORT_RESOLVE_ID),`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] ` * case sensitivity, and full sync support.`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ` * Return:	volume capabilities bitmask`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `u64 ksmbd_fruit_get_volume_caps(struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `	u64 vcaps = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `	 * Linux filesystems are generally case-sensitive and support`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `	 * full fsync semantics.`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `	vcaps |= kAAPL_CASE_SENSITIVE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `	vcaps |= kAAPL_SUPPORTS_FULL_SYNC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `	 * Advertise file ID resolution support.  The actual resolution`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `	 * is implemented in ksmbd_vfs_resolve_fileid() (vfs.c).`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	vcaps |= kAAPL_SUPPORT_RESOLVE_ID;`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	return vcaps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `int fruit_init_module(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `	pr_info("ksmbd: Fruit SMB extensions loaded\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `void fruit_cleanup_module(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `	pr_info("ksmbd: Fruit SMB extensions unloaded\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ` * fruit_process_server_query - Process a kAAPL server query request`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] ` * Validates the query, updates the connection's fruit state with the`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] ` * query type and timestamp, and marks the connection as queried.`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] ` * The actual query response (server_caps, volume_caps) is built by`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] ` * the create-context response path using fruit_build_server_response().`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `int fruit_process_server_query(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] `			       const struct fruit_server_query *query)`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `	struct fruit_conn_state *state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] `	u32 type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] `	if (!conn || !query)`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] `	state = conn->fruit_state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] `	if (!state) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `		ksmbd_debug(SMB, "Fruit server query without negotiated state\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [ERROR_PATH|] `		return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00693 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] `	type = le32_to_cpu(query->type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] `	ksmbd_debug(SMB, "Fruit server query: type=%u flags=%u max_rsp=%u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `		    type, le32_to_cpu(query->flags),`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `		    le32_to_cpu(query->max_response_size));`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] `	state->server_queried = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] `	state->last_query_type = type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] `	state->last_query_time = ktime_get_real_seconds();`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `void fruit_debug_capabilities(u64 capabilities)`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	ksmbd_debug(SMB, "Fruit kAAPL server_caps: 0x%016llx\n", capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	ksmbd_debug(SMB, "  read_dir_attr=%d osx_copyfile=%d unix_based=%d nfs_ace=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		    !!(capabilities & kAAPL_SUPPORTS_READ_DIR_ATTR),`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `		    !!(capabilities & kAAPL_SUPPORTS_OSX_COPYFILE),`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		    !!(capabilities & kAAPL_UNIX_BASED),`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `		    !!(capabilities & kAAPL_SUPPORTS_NFS_ACE));`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] ` * smb2_read_dir_attr - Batch-level hook for Fruit directory attribute reading`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] ` * Called once per QUERY_DIRECTORY batch to validate fruit state.`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] ` * Per-entry enrichment (UNIX mode packing into EaSize, resource fork`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] ` * size reporting, FinderInfo) is done in smb2_read_dir_attr_fill().`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [NONE] `int smb2_read_dir_attr(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	if (!work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00731 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	conn = work->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	if (!conn || !conn->is_fruit)`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00736 [NONE] `	ksmbd_debug(SMB, "Fruit ReadDirAttr batch for conn %p\n", conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00740 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] ` * smb2_read_dir_attr_fill - Enrich a directory entry with UNIX metadata.`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] ` * Called from smb2_populate_readdir_entry() for Fruit connections.`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] ` * Apple ReadDirAttr convention:`
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] ` *   EaSize[4] = UNIX mode (S_IFMT | permission bits)`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] ` * Additional enrichment (per-share flags):`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ` *   FRUIT_RFORK_SIZE   → reads resource fork size from AFP_Resource stream`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] ` *   FRUIT_MAX_ACCESS   → computes maximum access rights for current user`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ` * Resource fork size and max_access are logged at debug level for`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ` * diagnostic purposes.  The SMB2 readdir wire format does not have`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ` * dedicated fields for these values; they are available to clients`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] ` * through FILE_STREAM_INFORMATION and CREATE response respectively.`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] ` * Note: Enrichment reads xattrs and checks permissions per directory`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] ` * entry, so they have performance implications on large directories.`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] ` * These are gated behind per-share flags so admins can enable selectively.`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `void smb2_read_dir_attr_fill(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] `			     struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `			     struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `			     struct kstat *stat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `			     struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `			     __le32 *ea_size_field)`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	if (!conn->is_fruit || !stat || !ea_size_field)`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `	 * Apple ReadDirAttr convention: overwrite the EaSize field with`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `	 * the UNIX mode (S_IFMT | permission bits) so that macOS Finder`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	 * can display file-type icons without extra round-trips.`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	 * This intentionally repurposes the EaSize field, which normally`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	 * holds the extended-attribute size.  It is ONLY done when the`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	 * connection has negotiated Apple/Fruit UNIX extensions`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `	 * (conn->is_fruit == true), so standard Windows clients are`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	 * never affected.`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `	 * For special files (symlinks, char/block devices, fifos, sockets)`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	 * the reparse tag is already set by the caller, so we must not`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] `	 * overwrite it here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `	if (!smb2_get_reparse_tag_special_file(stat->mode))`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `		*ea_size_field = cpu_to_le32(stat->mode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	 * Optional enrichments gated by per-share flags.`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `	 * These read xattrs per directory entry, so they have`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `	 * performance implications on large directories.`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `	if (!share || !dentry || !idmap)`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	/* Resource fork size: read AFP_Resource stream length */`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `	if (test_share_config_flag(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `				   KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `		ssize_t rfork_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `		rfork_len = vfs_getxattr(idmap, dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `					 XATTR_NAME_AFP_RESOURCE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `					 NULL, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `		if (rfork_len > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `			ksmbd_debug(SMB,`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `				    "Fruit readdir: rfork_size=%zd for %pd\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `				    rfork_len, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `	/* Max access: compute rwx permission mask for current user */`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `	if (test_share_config_flag(share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `				   KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `		struct inode *inode = d_inode(dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `		unsigned int access = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] `		if (inode) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] `			if (!inode_permission(idmap, inode, MAY_READ))`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `				access |= MAY_READ;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `			if (!inode_permission(idmap, inode, MAY_WRITE))`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `				access |= MAY_WRITE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `			if (!inode_permission(idmap, inode, MAY_EXEC))`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `				access |= MAY_EXEC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] `		ksmbd_debug(SMB, "Fruit readdir: max_access=0x%x for %pd\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] `			    access, dentry);`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `#endif /* CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
