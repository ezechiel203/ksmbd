/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2025 Alexandre BETRY
 *
 *   Fruit SMB extensions for KSMBD
 */

#ifndef _SMB2_FRUIT_H
#define _SMB2_FRUIT_H

#include <linux/types.h>

struct create_context;
struct ksmbd_conn;
struct ksmbd_work;
struct path;

/* Wire protocol context name - must remain "AAPL" for compatibility */
#define FRUIT_CONTEXT_NAME			"AAPL"
#define FRUIT_SERVER_QUERY_CONTEXT		"ServerQuery"
#define FRUIT_VOLUME_CAPABILITIES_CONTEXT	"VolumeCapabilities"
#define FRUIT_FILE_MODE_CONTEXT			"FileMode"
#define FRUIT_DIR_HARDLINKS_CONTEXT		"DirHardLinks"
#define FRUIT_LOOKERINFO_CONTEXT		"FinderInfo"
#define FRUIT_SAVEBOX_CONTEXT			"TimeMachine"

/* Fruit SMB protocol versions */
#define FRUIT_VERSION_MIN			0x00010000
#define FRUIT_VERSION_1_0			0x00010000
#define FRUIT_VERSION_1_1			0x00010001
#define FRUIT_VERSION_2_0			0x00020000
#define FRUIT_VERSION_CURRENT			FRUIT_VERSION_2_0

/* Fruit client types */
#define FRUIT_CLIENT_MACOS			0x01
#define FRUIT_CLIENT_IOS			0x02
#define FRUIT_CLIENT_IPADOS			0x03
#define FRUIT_CLIENT_TVOS			0x04
#define FRUIT_CLIENT_WATCHOS			0x05

/*
 * Apple kAAPL server capabilities — MUST match Apple wire protocol.
 * These are the bits sent in the server_caps field of the AAPL
 * create context response (command_code=kAAPL_SERVER_QUERY=1,
 * reply_bitmap bit 0).
 */
#define kAAPL_SUPPORTS_READ_DIR_ATTR		0x01
#define kAAPL_SUPPORTS_OSX_COPYFILE		0x02
#define kAAPL_UNIX_BASED			0x04
#define kAAPL_SUPPORTS_NFS_ACE			0x08
#define kAAPL_SUPPORTS_TM_LOCK_STEAL		0x40

/*
 * Apple kAAPL volume capabilities — sent in volume_caps field
 * (reply_bitmap bit 1).
 */
#define kAAPL_SUPPORT_RESOLVE_ID		0x01
#define kAAPL_CASE_SENSITIVE			0x02
#define kAAPL_SUPPORTS_FULL_SYNC		0x04

/*
 * Apple ReadDirAttr enrichment — packed into EaSize field of
 * directory entries when kAAPL_SUPPORTS_READ_DIR_ATTR is negotiated.
 * EaSize[4] = UNIX mode (S_IFMT | permission bits).
 */
#define READDIR_ATTR_FINDER_INFO_SIZE		32

/* AFP stream names for FinderInfo / Resource Fork interception */
#define AFP_AFPINFO_STREAM			"AFP_AfpInfo"
#define AFP_RESOURCE_STREAM			"AFP_Resource"
#define APPLE_FINDER_INFO_XATTR			"com.apple.FinderInfo"
#define APPLE_FINDER_INFO_XATTR_USER		"user." APPLE_FINDER_INFO_XATTR
#define AFP_AFPINFO_SIZE			60
#define AFP_FINDER_INFO_SIZE			32

/*
 * AFP_AfpInfo on-disk structure (60 bytes, big-endian fields).
 * This is what macOS expects when reading the AFP_AfpInfo named stream.
 */
#define AFP_MAGIC				0x41465000 /* "AFP\0" */
#define AFP_VERSION				0x00010000 /* 1.0 */
#define AFP_BACKUP_DATE_INVALID			0x80000000

/* The xattr name that ksmbd uses for the AFP_AfpInfo DosStream */
#define XATTR_NAME_AFP_AFPINFO \
	"user.DosStream." AFP_AFPINFO_STREAM ":$DATA"

#define FRUIT_SERVER_QUERY_SIZE			256
#define FRUIT_VOLUME_CAPS_SIZE			128
#define FRUIT_FILE_MODE_SIZE			16
#define FRUIT_CLIENT_INFO_SIZE			64
#define FRUIT_NEGOTIATE_SIZE			32

/* Fruit-specific constants for SMB query directory */
#define KSMBD_DIR_INFO_REQ_XATTR_BATCH		0x00000001
#define SMB2_REOPEN_ORIGINAL			0x00000020
#define SMB2_REOPEN_POSITION			0x00000040

struct fruit_server_query {
	__le32			type;
	__le32			flags;
	__le32			max_response_size;
	__le32			reserved;
	__u8			query_data[];
} __packed;

struct fruit_volume_capabilities {
	__le64			capability_flags;
	__le32			max_path_length;
	__le32			max_filename_length;
	__le32			compression_types;
	__u8			case_sensitive;
	__u8			file_ids_supported;
	__u8			reserved[2];
} __packed;

struct fruit_file_mode {
	__le32			mode;
	__le32			flags;
	__u8			creator[4];
	__u8			type[4];
} __packed;

struct fruit_client_info {
	__u8			signature[4];	/* "AAPL" on wire */
	__le32			version;
	__le32			client_type;
	__le64			capabilities;
	__le32			build_number;
	__u8			reserved[16];
} __packed;

struct fruit_negotiate_context {
	struct fruit_client_info client_info;
	__le64			server_capabilities;
	__le64			requested_features;
	__u8			reserved[40];
} __packed;

struct fruit_dir_hardlinks {
	__le32			flags;
	__le32			max_links_per_file;
	__u8			case_sensitive;
	__u8			reserved[3];
} __packed;

struct fruit_looker_info {
	__u8			creator[4];
	__u8			type[4];
	__le16			flags;
	__le16			location_x;
	__le16			location_y;
	__le16			extended_flags;
	__u8			reserved[16];
} __packed;

struct fruit_savebox_info {
	__le32			version;
	__le32			sparse_caps;
	__le64			bundle_id;
	__le64			validation_seq;
	__le64			durable_handle;
	__u8			reserved[16];
} __packed;

/* Internal state, not a wire format */
struct fruit_conn_state {
	u32			client_version;
	u32			client_type;
	u64			client_capabilities;
	__u8			client_build[16];

	u64			negotiated_capabilities;
	u64			supported_features;
	u64			enabled_features;

	__u8			extensions_enabled;
	__u8			compression_supported;
	__u8			resilient_handles_enabled;
	__u8			posix_locks_enabled;

	__u8			server_queried;
	u32			last_query_type;
	u64			last_query_time;
};

struct ksmbd_share_config;

#ifdef CONFIG_KSMBD_FRUIT

/* ── Real declarations (feature enabled) ───────────────────── */

bool fruit_is_client_request(const void *buffer, size_t len);
int fruit_parse_client_info(const void *context_data, size_t data_len,
			    struct fruit_conn_state *state);
int fruit_validate_create_context(const struct create_context *context);

int fruit_negotiate_capabilities(struct ksmbd_conn *conn,
				 const struct fruit_client_info *client_info);
bool fruit_supports_capability(struct fruit_conn_state *state, u64 capability);

int fruit_detect_client_version(const void *data, size_t len);
const char *fruit_get_client_name(__le32 client_type);
const char *fruit_get_version_string(__le32 version);

bool fruit_valid_signature(const __u8 *signature);
size_t fruit_get_context_size(const char *context_name);
int fruit_build_server_response(void **response_data, size_t *response_len,
				__le64 capabilities, __le32 query_type);

int fruit_init_connection_state(struct fruit_conn_state *state);
void fruit_cleanup_connection_state(struct fruit_conn_state *state);
int fruit_update_connection_state(struct fruit_conn_state *state,
				  const struct fruit_client_info *client_info);
void fruit_debug_client_info(const struct fruit_client_info *info);

int fruit_process_looker_info(struct ksmbd_conn *conn,
			      const struct fruit_looker_info *looker_info);
int fruit_process_savebox_info(struct ksmbd_conn *conn,
			       const struct fruit_savebox_info *sb_info);
int fruit_handle_savebox_bundle(struct ksmbd_conn *conn,
				const struct path *path,
				const struct fruit_savebox_info *sb_info);
int fruit_process_server_query(struct ksmbd_conn *conn,
			       const struct fruit_server_query *query);
void fruit_debug_capabilities(u64 capabilities);

int smb2_read_dir_attr(struct ksmbd_work *work);
void smb2_read_dir_attr_fill(struct ksmbd_conn *conn,
			     struct dentry *dentry,
			     struct kstat *stat,
			     struct ksmbd_share_config *share,
			     __le32 *ea_size_field);

int fruit_synthesize_afpinfo(struct dentry *dentry, char *buf, size_t bufsize);

int fruit_init_module(void);
void fruit_cleanup_module(void);

#else /* !CONFIG_KSMBD_FRUIT */

/* ── Stubs (feature disabled — all compile to nothing) ─────── */

static inline bool fruit_is_client_request(const void *buffer, size_t len)
{ return false; }
static inline int fruit_parse_client_info(const void *context_data,
			size_t data_len, struct fruit_conn_state *state)
{ return -EOPNOTSUPP; }
static inline int fruit_validate_create_context(
			const struct create_context *context)
{ return -EOPNOTSUPP; }
static inline int fruit_negotiate_capabilities(struct ksmbd_conn *conn,
			const struct fruit_client_info *client_info)
{ return -EOPNOTSUPP; }
static inline bool fruit_supports_capability(struct fruit_conn_state *state,
			u64 capability)
{ return false; }
static inline int fruit_detect_client_version(const void *data, size_t len)
{ return -EOPNOTSUPP; }
static inline const char *fruit_get_client_name(__le32 client_type)
{ return "unknown"; }
static inline const char *fruit_get_version_string(__le32 version)
{ return "unknown"; }
static inline bool fruit_valid_signature(const __u8 *signature)
{ return false; }
static inline size_t fruit_get_context_size(const char *context_name)
{ return 0; }
static inline int fruit_build_server_response(void **response_data,
			size_t *response_len, __le64 capabilities,
			__le32 query_type)
{ return -EOPNOTSUPP; }
static inline int fruit_init_connection_state(struct fruit_conn_state *state)
{ return 0; }
static inline void fruit_cleanup_connection_state(
			struct fruit_conn_state *state) {}
static inline int fruit_update_connection_state(
			struct fruit_conn_state *state,
			const struct fruit_client_info *client_info)
{ return -EOPNOTSUPP; }
static inline void fruit_debug_client_info(
			const struct fruit_client_info *info) {}
static inline int fruit_process_looker_info(struct ksmbd_conn *conn,
			const struct fruit_looker_info *looker_info)
{ return -EOPNOTSUPP; }
static inline int fruit_process_savebox_info(struct ksmbd_conn *conn,
			const struct fruit_savebox_info *sb_info)
{ return -EOPNOTSUPP; }
static inline int fruit_handle_savebox_bundle(struct ksmbd_conn *conn,
			const struct path *path,
			const struct fruit_savebox_info *sb_info)
{ return -EOPNOTSUPP; }
static inline int fruit_process_server_query(struct ksmbd_conn *conn,
			const struct fruit_server_query *query)
{ return -EOPNOTSUPP; }
static inline void fruit_debug_capabilities(u64 capabilities) {}
static inline int smb2_read_dir_attr(struct ksmbd_work *work)
{ return 0; }
static inline void smb2_read_dir_attr_fill(struct ksmbd_conn *conn,
			struct dentry *dentry, struct kstat *stat,
			struct ksmbd_share_config *share,
			__le32 *ea_size_field) {}
static inline int fruit_synthesize_afpinfo(struct dentry *dentry,
			char *buf, size_t bufsize)
{ return -EOPNOTSUPP; }
static inline int fruit_init_module(void) { return 0; }
static inline void fruit_cleanup_module(void) {}

#endif /* CONFIG_KSMBD_FRUIT */

#endif /* _SMB2_FRUIT_H */
