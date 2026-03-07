# Line-by-line Review: src/include/protocol/smb2fruit.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
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
- L00008 [PROTO_GATE|] `#ifndef _SMB2_FRUIT_H`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00009 [PROTO_GATE|] `#define _SMB2_FRUIT_H`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00010 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `struct create_context;`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `struct ksmbd_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `struct ksmbd_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `struct mnt_idmap;`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `struct path;`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `/* Wire protocol context name - must remain "AAPL" for compatibility */`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#define FRUIT_CONTEXT_NAME			"AAPL"`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `#define FRUIT_SERVER_QUERY_CONTEXT		"ServerQuery"`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#define FRUIT_VOLUME_CAPABILITIES_CONTEXT	"VolumeCapabilities"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#define FRUIT_FILE_MODE_CONTEXT			"FileMode"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define FRUIT_DIR_HARDLINKS_CONTEXT		"DirHardLinks"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define FRUIT_LOOKERINFO_CONTEXT		"FinderInfo"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#define FRUIT_SAVEBOX_CONTEXT			"TimeMachine"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `/* Fruit SMB protocol versions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define FRUIT_VERSION_MIN			0x00010000`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define FRUIT_VERSION_1_0			0x00010000`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define FRUIT_VERSION_1_1			0x00010001`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `#define FRUIT_VERSION_2_0			0x00020000`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define FRUIT_VERSION_CURRENT			FRUIT_VERSION_2_0`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `/* Fruit client types */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define FRUIT_CLIENT_MACOS			0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#define FRUIT_CLIENT_IOS			0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define FRUIT_CLIENT_IPADOS			0x03`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define FRUIT_CLIENT_TVOS			0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define FRUIT_CLIENT_WATCHOS			0x05`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * Apple kAAPL server capabilities — MUST match Apple wire protocol.`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * These are the bits sent in the server_caps field of the AAPL`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` * create context response (command_code=kAAPL_SERVER_QUERY=1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` * reply_bitmap bit 0).`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define kAAPL_SUPPORTS_READ_DIR_ATTR		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define kAAPL_SUPPORTS_OSX_COPYFILE		0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#define kAAPL_UNIX_BASED			0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#define kAAPL_SUPPORTS_NFS_ACE			0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#define kAAPL_SUPPORTS_TM_LOCK_STEAL		0x40`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` * Apple kAAPL volume capabilities — sent in volume_caps field`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * (reply_bitmap bit 1).`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define kAAPL_SUPPORT_RESOLVE_ID		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#define kAAPL_CASE_SENSITIVE			0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define kAAPL_SUPPORTS_FULL_SYNC		0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * Apple ReadDirAttr enrichment — packed into EaSize field of`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * directory entries when kAAPL_SUPPORTS_READ_DIR_ATTR is negotiated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` * EaSize[4] = UNIX mode (S_IFMT | permission bits).`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#define READDIR_ATTR_FINDER_INFO_SIZE		32`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `/* AFP stream names for FinderInfo / Resource Fork interception */`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#define AFP_AFPINFO_STREAM			"AFP_AfpInfo"`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#define AFP_RESOURCE_STREAM			"AFP_Resource"`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#define APPLE_FINDER_INFO_XATTR			"com.apple.FinderInfo"`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#define APPLE_FINDER_INFO_XATTR_USER		"user." APPLE_FINDER_INFO_XATTR`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#define AFP_AFPINFO_SIZE			60`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#define AFP_FINDER_INFO_SIZE			32`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` * AFP_AfpInfo on-disk structure (60 bytes, big-endian fields).`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` * This is what macOS expects when reading the AFP_AfpInfo named stream.`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#define AFP_MAGIC				0x41465000 /* "AFP\0" */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `#define AFP_VERSION				0x00010000 /* 1.0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#define AFP_BACKUP_DATE_INVALID			0x80000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `/* The xattr name that ksmbd uses for the AFP_AfpInfo DosStream */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define XATTR_NAME_AFP_AFPINFO \`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `	"user.DosStream." AFP_AFPINFO_STREAM ":$DATA"`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `#define FRUIT_SERVER_QUERY_SIZE			256`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `#define FRUIT_VOLUME_CAPS_SIZE			128`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define FRUIT_FILE_MODE_SIZE			16`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `#define FRUIT_CLIENT_INFO_SIZE			64`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `#define FRUIT_NEGOTIATE_SIZE			32`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `/* Fruit-specific constants for SMB query directory */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `#define KSMBD_DIR_INFO_REQ_XATTR_BATCH		0x00000001`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [PROTO_GATE|] `#define SMB2_REOPEN_ORIGINAL			0x00000020`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00098 [PROTO_GATE|] `#define SMB2_REOPEN_POSITION			0x00000040`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `struct fruit_server_query {`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	__le32			type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	__le32			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	__le32			max_response_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	__le32			reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	__u8			query_data[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `struct fruit_volume_capabilities {`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	__le64			capability_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	__le32			max_path_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	__le32			max_filename_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	__le32			compression_types;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	__u8			case_sensitive;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	__u8			file_ids_supported;`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	__u8			reserved[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `struct fruit_file_mode {`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	__le32			mode;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	__le32			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	__u8			creator[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	__u8			type[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `struct fruit_client_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	__u8			signature[4];	/* "AAPL" on wire */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	__le32			version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	__le32			client_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	__le64			capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	__le32			build_number;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	__u8			reserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `struct fruit_negotiate_context {`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	struct fruit_client_info client_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	__le64			server_capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	__le64			requested_features;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	__u8			reserved[40];`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `struct fruit_dir_hardlinks {`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	__le32			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	__le32			max_links_per_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `	__u8			case_sensitive;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `	__u8			reserved[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `struct fruit_looker_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	__u8			creator[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	__u8			type[4];`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	__le16			flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	__le16			location_x;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	__le16			location_y;`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	__le16			extended_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	__u8			reserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `struct fruit_savebox_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	__le32			version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	__le32			sparse_caps;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	__le64			bundle_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	__le64			validation_seq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	__le64			durable_handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	__u8			reserved[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `/* Internal state, not a wire format */`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `struct fruit_conn_state {`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	u32			client_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	u32			client_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	u64			client_capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	__u8			client_build[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	u64			negotiated_capabilities;`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	u64			supported_features;`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	u64			enabled_features;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	__u8			extensions_enabled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	__u8			compression_supported;`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	__u8			resilient_handles_enabled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	__u8			posix_locks_enabled;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	__u8			server_queried;`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	u32			last_query_type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	u64			last_query_time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `struct ksmbd_share_config;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `struct ksmbd_kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `#ifdef CONFIG_KSMBD_FRUIT`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `/* ── Real declarations (feature enabled) ───────────────────── */`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `bool fruit_is_client_request(const void *buffer, size_t len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `int fruit_parse_client_info(const void *context_data, size_t data_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `			    struct fruit_conn_state *state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `int fruit_validate_create_context(const struct create_context *context);`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `int fruit_negotiate_capabilities(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `				 const struct fruit_client_info *client_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `bool fruit_supports_capability(struct fruit_conn_state *state, u64 capability);`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `int fruit_detect_client_version(const void *data, size_t len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `const char *fruit_get_client_name(__le32 client_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `const char *fruit_get_version_string(__le32 version);`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `bool fruit_valid_signature(const __u8 *signature);`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `size_t fruit_get_context_size(const char *context_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `int fruit_build_server_response(void **response_data, size_t *response_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `				__le64 capabilities, __le32 query_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `int fruit_init_connection_state(struct fruit_conn_state *state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `void fruit_cleanup_connection_state(struct fruit_conn_state *state);`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `int fruit_update_connection_state(struct fruit_conn_state *state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `				  const struct fruit_client_info *client_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `void fruit_debug_client_info(const struct fruit_client_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `int fruit_process_looker_info(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `			      const struct fruit_looker_info *looker_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `int fruit_process_savebox_info(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `			       const struct fruit_savebox_info *sb_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `int fruit_handle_savebox_bundle(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `				const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `				const struct fruit_savebox_info *sb_info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `int fruit_process_server_query(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `			       const struct fruit_server_query *query);`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `void fruit_debug_capabilities(u64 capabilities);`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `int smb2_read_dir_attr(struct ksmbd_work *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `void smb2_read_dir_attr_fill(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `			     struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `			     struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `			     struct kstat *stat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `			     struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `			     __le32 *ea_size_field);`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `int fruit_synthesize_afpinfo(struct mnt_idmap *idmap, struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `			     char *buf, size_t bufsize);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `/* Step 1: AFP_AfpInfo stream interception */`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `bool ksmbd_fruit_is_afpinfo_stream(const char *stream_name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `int ksmbd_fruit_read_afpinfo(struct path *path, void *buf, size_t len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `/* Step 2: Time Machine quota enforcement */`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `int ksmbd_fruit_check_tm_quota(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `			       struct path *share_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `/* Step 3: ReadDirAttr enrichment */`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `int ksmbd_fruit_fill_readdir_attr(struct ksmbd_file *dir_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `				  struct ksmbd_kstat *ksmbd_kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `				  struct path *entry_path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `/* Step 4: Volume capabilities with resolve_fileid */`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `u64 ksmbd_fruit_get_volume_caps(struct ksmbd_share_config *share);`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `int fruit_init_module(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `void fruit_cleanup_module(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `#else /* !CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `/* ── Stubs (feature disabled — all compile to nothing) ─────── */`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `static inline bool fruit_is_client_request(const void *buffer, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `{ return false; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `static inline int fruit_parse_client_info(const void *context_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `			size_t data_len, struct fruit_conn_state *state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00270 [NONE] `static inline int fruit_validate_create_context(`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `			const struct create_context *context)`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00273 [NONE] `static inline int fruit_negotiate_capabilities(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `			const struct fruit_client_info *client_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00276 [NONE] `static inline bool fruit_supports_capability(struct fruit_conn_state *state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `			u64 capability)`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `{ return false; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `static inline int fruit_detect_client_version(const void *data, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00281 [NONE] `static inline const char *fruit_get_client_name(__le32 client_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `{ return "unknown"; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `static inline const char *fruit_get_version_string(__le32 version)`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `{ return "unknown"; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `static inline bool fruit_valid_signature(const __u8 *signature)`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `{ return false; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `static inline size_t fruit_get_context_size(const char *context_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `static inline int fruit_build_server_response(void **response_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `			size_t *response_len, __le64 capabilities,`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `			__le32 query_type)`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00293 [NONE] `static inline int fruit_init_connection_state(struct fruit_conn_state *state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `static inline void fruit_cleanup_connection_state(`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `			struct fruit_conn_state *state) {}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `static inline int fruit_update_connection_state(`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `			struct fruit_conn_state *state,`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `			const struct fruit_client_info *client_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00301 [NONE] `static inline void fruit_debug_client_info(`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] `			const struct fruit_client_info *info) {}`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] `static inline int fruit_process_looker_info(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `			const struct fruit_looker_info *looker_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00306 [NONE] `static inline int fruit_process_savebox_info(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `			const struct fruit_savebox_info *sb_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00309 [NONE] `static inline int fruit_handle_savebox_bundle(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `			const struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `			const struct fruit_savebox_info *sb_info)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00313 [NONE] `static inline int fruit_process_server_query(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `			const struct fruit_server_query *query)`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00316 [NONE] `static inline void fruit_debug_capabilities(u64 capabilities) {}`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `static inline int smb2_read_dir_attr(struct ksmbd_work *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `static inline void smb2_read_dir_attr_fill(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `			struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `			struct dentry *dentry, struct kstat *stat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `			struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `			__le32 *ea_size_field) {}`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `static inline int fruit_synthesize_afpinfo(struct mnt_idmap *idmap,`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `			struct dentry *dentry,`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `			char *buf, size_t bufsize)`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] `static inline bool ksmbd_fruit_is_afpinfo_stream(const char *stream_name)`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `{ return false; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `static inline int ksmbd_fruit_read_afpinfo(struct path *path,`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `			void *buf, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [ERROR_PATH|] `{ return -EOPNOTSUPP; }`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00334 [NONE] `static inline int ksmbd_fruit_check_tm_quota(`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `			struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `			struct path *share_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `static inline int ksmbd_fruit_fill_readdir_attr(struct ksmbd_file *dir_fp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `			struct ksmbd_kstat *ksmbd_kstat,`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `			struct path *entry_path)`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `static inline u64 ksmbd_fruit_get_volume_caps(`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `			struct ksmbd_share_config *share)`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `{ return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `static inline int fruit_init_module(void) { return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `static inline void fruit_cleanup_module(void) {}`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] `#endif /* CONFIG_KSMBD_FRUIT */`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [PROTO_GATE|] `#endif /* _SMB2_FRUIT_H */`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
