/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2024 KSMBD Contributors
 *
 *   Apple SMB/CIFS protocol extensions for KSMBD
 *
 *   This header contains Apple-specific data structures, constants, and
 *   function prototypes required for supporting Apple SMB extensions
 *   including AAPL create contexts, macOS-specific capabilities,
 *   and Apple client version detection.
 */

#ifndef _SMB2_AAPL_H
#define _SMB2_AAPL_H

#include <linux/types.h>
#include <linux/kernel.h>

/* Apple SMB Extension Constants */
#define AAPL_CONTEXT_NAME			"AAPL"
#define AAPL_SERVER_QUERY_CONTEXT		"ServerQuery"
#define AAPL_VOLUME_CAPABILITIES_CONTEXT	"VolumeCapabilities"
#define AAPL_FILE_MODE_CONTEXT			"FileMode"
#define AAPL_DIR_HARDLINKS_CONTEXT		"DirHardLinks"
#define AAPL_FINDERINFO_CONTEXT			"FinderInfo"
#define AAPL_TIMEMACHINE_CONTEXT		"TimeMachine"

/* Apple SMB Protocol Versions */
#define AAPL_VERSION_MIN			0x00010000
#define AAPL_VERSION_1_0			0x00010000
#define AAPL_VERSION_1_1			0x00010001
#define AAPL_VERSION_2_0			0x00020000
#define AAPL_VERSION_CURRENT			AAPL_VERSION_2_0

/* Apple Client Types */
#define AAPL_CLIENT_MACOS			0x01
#define AAPL_CLIENT_IOS			0x02
#define AAPL_CLIENT_IPADOS			0x03
#define AAPL_CLIENT_TVOS			0x04
#define AAPL_CLIENT_WATCHOS			0x05

/* Apple Capabilities */
#define AAPL_CAP_UNIX_EXTENSIONS		0x00000001
#define AAPL_CAP_EXTENDED_ATTRIBUTES		0x00000002
#define AAPL_CAP_CASE_SENSITIVE			0x00000004
#define AAPL_CAP_POSIX_LOCKS			0x00000008
#define AAPL_CAP_RESILIENT_HANDLES		0x00000010
#define AAPL_COMPRESSION_ZLIB			0x00000020
#define AAPL_COMPRESSION_LZFS			0x00000040
#define AAPL_CAP_READDIR_ATTRS			0x00000080
#define AAPL_CAP_FILE_IDS			0x00000100
#define AAPL_CAP_DEDUPlication			0x00000200
#define AAPL_CAP_SERVER_QUERY			0x00000400
#define AAPL_CAP_VOLUME_CAPABILITIES		0x00000800
#define AAPL_CAP_FILE_MODE			0x00001000
#define AAPL_CAP_DIR_HARDLINKS			0x00002000
#define AAPL_CAP_FINDERINFO			0x00004000
#define AAPL_CAP_TIMEMACHINE			0x00008000
#define AAPL_CAP_F_FULLFSYNC			0x00010000
#define AAPL_CAP_SPARSE_BUNDLES			0x00020000

/* Default Apple capabilities */
#define AAPL_DEFAULT_CAPABILITIES		(AAPL_CAP_UNIX_EXTENSIONS | \
						 AAPL_CAP_EXTENDED_ATTRIBUTES | \
						 AAPL_CAP_CASE_SENSITIVE | \
						 AAPL_CAP_POSIX_LOCKS | \
						 AAPL_CAP_RESILIENT_HANDLES | \
						 AAPL_CAP_READDIR_ATTRS | \
						 AAPL_CAP_FILE_IDS | \
						 AAPL_CAP_SERVER_QUERY | \
						 AAPL_CAP_VOLUME_CAPABILITIES | \
						 AAPL_CAP_FILE_MODE | \
						 AAPL_CAP_FINDERINFO | \
						 AAPL_CAP_F_FULLFSYNC | \
						 AAPL_CAP_SPARSE_BUNDLES)

/* Maximum Apple-specific data sizes */
#define AAPL_SERVER_QUERY_SIZE			256
#define AAPL_VOLUME_CAPS_SIZE			128
#define AAPL_FILE_MODE_SIZE			16
#define AAPL_CLIENT_INFO_SIZE			64
#define AAPL_NEGOTIATE_SIZE			32

/* Apple-specific SMB2 Create Context Structures */

/**
 * struct aapl_server_query - Apple Server Query context
 * @type: Query type (0=capabilities, 1=extensions, 2=compression)
 * @flags: Query flags (bitfield)
 * @max_response_size: Maximum response size in bytes
 * @reserved: Reserved for future use
 * @query_data: Query-specific data (variable length)
 *
 * This structure represents the Apple Server Query SMB2 create context.
 * It is used by Apple clients to query server capabilities and negotiate
 * specific features. The context allows clients to dynamically discover
 * which Apple SMB extensions are available on the server.
 *
 * Query types:
 * - 0: Capabilities query - basic server capabilities
 * - 1: Extensions query - extended attribute support
 * - 2: Compression query - compression algorithm support
 * - 3: Reserved for future use
 *
 * The query_data field contains type-specific information and may be
 * variable length depending on the query type.
 */
struct aapl_server_query {
	__le32			type;
	__le32			flags;
	__le32			max_response_size;
	__le32			reserved;
	__u8			query_data[0];
} __packed;

/**
 * struct aapl_volume_capabilities - Apple Volume Capabilities context
 * @capability_flags: Bitmask of supported capabilities
 * @max_path_length: Maximum path length supported
 * @max_filename_length: Maximum filename length supported
 * @compression_types: Supported compression algorithms
 * @case_sensitive: Whether volume is case sensitive
 * @file_ids_supported: Whether file IDs are supported
 * @reserved: Reserved for future use
 *
 * This structure represents Apple Volume Capabilities SMB2 create context.
 * It describes</think> capabilities and features of an SMB share from Apple's
 * perspective. This context is used to inform Apple clients about what
 * features are available on specific shares and volumes.
 *
 * Capabilities flags correspond to AAPL_CAP_* constants and include:
 * - UNIX Extensions, Extended Attributes, Case Sensitivity
 * - POSIX Locks, Resilient Handles, Compression Support
 * - ReadDir Attributes, File IDs, Query and Volume Capabilities
 * - File Mode, FinderInfo, TimeMachine, F_FULLFSYNC, Sparse Bundles
 *
 * The compression_types field indicates which compression algorithms
 * are supported (bit 0 = ZLIB, bit 1 = LZFS, etc.).
 */
struct aapl_volume_capabilities {
	__le64			capability_flags;
	__le32			max_path_length;
	__le32			max_filename_length;
	__le32			compression_types;
	__u8			case_sensitive;
	__u8			file_ids_supported;
	__u8			reserved[2];
} __packed;

/**
 * struct aapl_file_mode - Apple File Mode context
 * @mode: POSIX-style file mode bits
 * @flags: File mode flags
 * @creator: macOS creator code (4 bytes)
 * @type: macOS file type code (4 bytes)
 */
struct aapl_file_mode {
	__le32			mode;
	__le32			flags;
	__u8			creator[4];
	__u8			type[4];
} __packed;

/**
 * struct aapl_client_info - Apple Client Information
 * @signature: Apple signature "AAPL"
 * @version: Apple SMB extension version
 * @client_type: Type of Apple client (macOS, iOS, etc.)
 * @build_number: Build number of the client
 * @capabilities: Client capabilities bitmask
 * @reserved: Reserved for future use
 */
struct aapl_client_info {
	__u8			signature[4];	/* "AAPL" */
	__le32			version;
	__le32			client_type;
	__le32			build_number;
	__le64			capabilities;
	__u8			reserved[16];
} __packed;

/**
 * struct aapl_negotiate_context - Apple Negotiation Context
 * @client_info: Client information structure
 * @server_capabilities: Server capabilities to advertise
 * @requested_features: Features client wants to use
 * @reserved: Reserved for future use
 */
struct aapl_negotiate_context {
	struct aapl_client_info	client_info;
	__le64			server_capabilities;
	__le64			requested_features;
	__u8			reserved[32];
} __packed;

/**
 * struct aapl_dir_hardlinks - Apple Directory Hard Links context
 * @flags: Flags for hard link behavior
 * @max_links_per_file: Maximum hard links per file
 * @case_sensitive: Whether directory is case sensitive
 * @reserved: Reserved for future use
 */
struct aapl_dir_hardlinks {
	__le32			flags;
	__le32			max_links_per_file;
	__u8			case_sensitive;
	__u8			reserved[3];
} __packed;

/**
 * struct aapl_finder_info - Apple FinderInfo context
 * @creator: macOS creator code (4 bytes, e.g., 'TEXT')
 * @type: macOS file type code (4 bytes, e.g., 'TEXT')
 * @flags: Finder flags for file attributes
 * @location: File location in window (X, Y coordinates)
 * @extended_flags: Extended Finder flags
 * @reserved: Reserved for future use
 */
struct aapl_finder_info {
	__u8			creator[4];
	__u8			type[4];
	__le16			flags;
	__le16			location_x;
	__le16			location_y;
	__le16			extended_flags;
	__u8			reserved[10];
} __packed;

/**
 * struct aapl_timemachine_info - Apple Time Machine context
 * @version: Time Machine protocol version
 * @bundle_id: Time Machine bundle identifier
 * @sparse_caps: Sparse bundle capabilities
 * @validation_seq: Validation sequence number
 * @durable_handle: Durable handle for Time Machine operations
 * @reserved: Reserved for future use
 */
struct aapl_timemachine_info {
	__le32			version;
	__le64			bundle_id;
	__le32			sparse_caps;
	__le64			validation_seq;
	__le64			durable_handle;
	__u8			reserved[20];
} __packed;

/* Apple Connection State Structure */
struct aapl_conn_state {
	/* Client Information */
	__le32			client_version;
	__le32			client_type;
	__le64			client_capabilities;
	__u8			client_build[16];

	/* Negotiated Capabilities */
	__le64			negotiated_capabilities;
	__le64			supported_features;
	__le64			enabled_features;

	/* State Flags */
	bool			extensions_enabled;
	bool			compression_supported;
	bool			resilient_handles_enabled;
	bool			posix_locks_enabled;

	/* Query State */
	bool			server_queried;
	__le32			last_query_type;
	__le64			last_query_time;

	/* Reserved for future expansion */
	__u8			reserved[64];
};

/* Function Prototypes for Apple SMB Extensions */

/* Apple context detection and parsing */
bool aapl_is_client_request(const void *buffer, size_t len);
int aapl_parse_client_info(const void *context_data, size_t data_len,
			   struct aapl_conn_state *state);
int aapl_validate_create_context(const struct create_context *context);

/* Apple capability negotiation */
int aapl_negotiate_capabilities(struct ksmbd_conn *conn,
				const struct aapl_client_info *client_info);
bool aapl_supports_capability(struct aapl_conn_state *state, __le64 capability);
int aapl_enable_capability(struct aapl_conn_state *state, __le64 capability);

/* Apple version detection */
int aapl_detect_client_version(const void *data, size_t len);
const char *aapl_get_client_name(__le32 client_type);
const char *aapl_get_version_string(__le32 version);

/* Apple context handling */
int aapl_process_server_query(struct ksmbd_conn *conn,
			      const struct aapl_server_query *query);
int aapl_process_volume_caps(struct ksmbd_conn *conn,
			      const struct aapl_volume_capabilities *caps);
int aapl_process_file_mode(struct ksmbd_conn *conn,
			    const struct aapl_file_mode *file_mode);
int aapl_process_dir_hardlinks(struct ksmbd_conn *conn,
				const struct aapl_dir_hardlinks *hardlinks);
int aapl_process_finder_info(struct ksmbd_conn *conn,
			     const struct aapl_finder_info *finder_info);
int aapl_process_timemachine_info(struct ksmbd_conn *conn,
				  const struct aapl_timemachine_info *tm_info);

/* Apple-specific file operations */
int aapl_set_finder_info(struct ksmbd_conn *conn, const struct path *path,
			  const struct aapl_finder_info *finder_info);
int aapl_get_finder_info(struct ksmbd_conn *conn, const struct path *path,
			  struct aapl_finder_info *finder_info);
int aapl_handle_timemachine_bundle(struct ksmbd_conn *conn,
				    const struct path *path,
				    const struct aapl_timemachine_info *tm_info);
int aapl_validate_timemachine_sequence(struct ksmbd_conn *conn,
				       const struct aapl_timemachine_info *tm_info);

/* Apple file synchronization support */
int aapl_fullfsync(struct ksmbd_conn *conn, const struct path *path);

/* Apple connection state management */
int aapl_init_connection_state(struct aapl_conn_state *state);
void aapl_cleanup_connection_state(struct aapl_conn_state *state);
int aapl_update_connection_state(struct aapl_conn_state *state,
				 const struct aapl_client_info *client_info);

/* Debug and logging helpers */
void aapl_debug_client_info(const struct aapl_client_info *info);
void aapl_debug_capabilities(__le64 capabilities);
void aapl_debug_negotiation(struct aapl_conn_state *state);

/* Utility functions */
bool aapl_valid_signature(const __u8 *signature);
size_t aapl_get_context_size(const char *context_name);
int aapl_build_server_response(void **response_data, size_t *response_len,
			       __le64 capabilities, __le32 query_type);

#endif /* _SMB2_AAPL_H */