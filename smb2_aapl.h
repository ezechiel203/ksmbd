/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Alexandre BETRY
 *
 * Apple SMB/CIFS protocol extensions for KSMBD
 *
 * This header contains Apple-specific data structures, constants, and
 * function prototypes required for supporting Apple SMB extensions
 * for interoperability with Apple operating systems.
 *
 * Apple, macOS, iOS, Time Machine, and Finder are trademarks of Apple Inc.,
 * registered in the U.S. and other countries. This implementation is provided
 * for interoperability purposes only and is not endorsed or supported by Apple Inc.
 */

#ifndef _SMB2_AAPL_H
#define _SMB2_AAPL_H

#include <linux/types.h>
#include <linux/kernel.h>

/* Forward declaration to avoid include dependencies */
struct create_context;

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
 * It describes capabilities and features of an SMB share from Apple's
 * perspective. This context is used to inform Apple clients about what
 * features are available on specific shares and volumes.
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
 * @mode: POSIX-style file mode bits (permissions)
 * @flags: Apple-specific file flags (hidden, locked, etc.)
 * @creator: macOS 4-byte creator code (e.g., 'TEXT' for TextEdit)
 * @type: macOS 4-byte file type code (e.g., 'TEXT' for text files)
 *
 * This structure represents the Apple File Mode SMB2 create context. It contains
 * both POSIX-style file permissions and Apple-specific metadata including creator
 * and type codes. These codes are used by macOS applications to identify file
 * types and maintain compatibility with classic Mac OS applications.
 */
struct aapl_file_mode {
	__le32			mode;
	__le32			flags;
	__u8			creator[4];
	__u8			type[4];
} __packed;

/**
 * struct aapl_client_info - Apple Client Information
 * @signature: Apple signature "AAPL" (4 bytes, must be "AAPL")
 * @version: Apple SMB extension version (e.g., AAPL_VERSION_2_0)
 * @client_type: Type of Apple client (AAPL_CLIENT_MACOS, etc.)
 * @capabilities: Bitmask of requested capabilities (AAPL_CAP_* flags)
 * @build_number: Build number of the client software
 * @reserved: Reserved for future use (must be zero)
 *
 * This structure contains information about the Apple client connecting to the SMB
 * server. It is used for client identification, capability negotiation, and
 * feature enablement.
 */
struct aapl_client_info {
	__u8			signature[4];	/* "AAPL" */
	__le32			version;
	__le32			client_type;
	__le64			capabilities;
	__le32			build_number;
	__u8			reserved[16];
} __packed;

/**
 * struct aapl_negotiate_context - Apple Negotiation Context
 * @client_info: Client information structure with identification details
 * @server_capabilities: Server capabilities bitmask to advertise to client
 * @requested_features: Specific features client wants to enable
 * @reserved: Reserved for future use (must be zero)
 * @reserved2: Additional padding to maintain structure size compatibility
 *
 * This structure is used during the initial negotiation phase between Apple
 * clients and the KSMBD server. It combines client identification with
 * capability negotiation to establish which Apple SMB extensions will be
 * available for the connection.
 */
struct aapl_negotiate_context {
	struct aapl_client_info	client_info;
	__le64			server_capabilities;
	__le64			requested_features;
	__u8			reserved[40];
} __packed;

/**
 * struct aapl_dir_hardlinks - Apple Directory Hard Links context
 * @flags: Bitmask of flags controlling hard link behavior (0-3)
 * @max_links_per_file: Maximum number of hard links allowed per file
 * @case_sensitive: Boolean indicating if directory is case sensitive
 * @reserved: Reserved for future use (must be zero)
 *
 * This structure configures directory hard link behavior for Apple clients.
 */
struct aapl_dir_hardlinks {
	__le32			flags;
	__le32			max_links_per_file;
	__u8			case_sensitive;
	__u8			reserved[3];
} __packed;

/**
 * struct aapl_finder_info - Apple FinderInfo context
 * @creator: macOS 4-byte creator code (e.g., 'TEXT' for TextEdit)
 * @type: macOS 4-byte file type code (e.g., 'TEXT' for text files)
 * @flags: Finder flags (bitmask of file attributes like hidden, locked)
 * @location: File location coordinates (X, Y) in Finder window
 * @extended_flags: Additional extended Finder flags
 * @reserved: Reserved for future use (must be zero)
 * @reserved2: Additional padding to maintain structure size compatibility
 *
 * This structure contains macOS Finder metadata including creator and type codes
 * that are essential for Mac application compatibility.
 */
struct aapl_finder_info {
	__u8			creator[4];
	__u8			type[4];
	__le16			flags;
	__le16			location_x;
	__le16			location_y;
	__le16			extended_flags;
	__u8			reserved[16];
} __packed;

/**
 * struct aapl_timemachine_info - Apple Time Machine context
 * @version: Time Machine protocol version (must be >= 1)
 * @bundle_id: Unique identifier for Time Machine sparse bundle
 * @sparse_caps: Bitmask of sparse bundle capability flags
 * @validation_seq: Anti-replay protection sequence number
 * @durable_handle: Persistent handle for Time Machine session
 * @reserved: Reserved for future use (must be zero)
 *
 * This structure configures Apple Time Machine backup operations over SMB.
 */
struct aapl_timemachine_info {
	__le32			version;
	__le32			sparse_caps;
	__le64			bundle_id;
	__le64			validation_seq;
	__le64			durable_handle;
	__u8			reserved[16];
} __packed;

/**
 * struct aapl_conn_state - Apple Connection State
 * @client_version: Apple SMB extension version from client
 * @client_type: Type of Apple client (macOS, iOS, etc.)
 * @client_capabilities: Full bitmask of client-requested capabilities
 * @client_build: Build number string from client (16 bytes)
 * @negotiated_capabilities: Final negotiated capability set (client ∩ server)
 * @supported_features: Server-supported capability bitmask
 * @enabled_features: Currently enabled features for this connection
 * @extensions_enabled: Boolean flag for extended attributes support
 * @compression_supported: Boolean flag for compression support
 * @resilient_handles_enabled: Boolean flag for resilient handle support
 * @posix_locks_enabled: Boolean flag for POSIX lock support
 * @server_queried: Boolean flag indicating if server has been queried
 * @last_query_type: Last server query type processed
 * @last_query_time: Timestamp of last query operation (jiffies or sequence)
 * @reserved: Reserved for future use (must be zero)
 *
 * This structure maintains the state of an Apple client connection throughout
 * its lifetime.
 */
struct aapl_conn_state {
	__le32			client_version;
	__le32			client_type;
	__le64			client_capabilities;
	__u8			client_build[16];

	__le64			negotiated_capabilities;
	__le64			supported_features;
	__le64			enabled_features;

	__u8			extensions_enabled;
	__u8			compression_supported;
	__u8			resilient_handles_enabled;
	__u8			posix_locks_enabled;

	__u8			server_queried;
	__le32			last_query_type;
	__le64			last_query_time;

	__u8			reserved[47];
} __packed;

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

/* Apple version detection */
int aapl_detect_client_version(const void *data, size_t len);
const char *aapl_get_client_name(__le32 client_type);
const char *aapl_get_version_string(__le32 version);

/* Utility functions */
bool aapl_valid_signature(const __u8 *signature);
size_t aapl_get_context_size(const char *context_name);
int aapl_build_server_response(void **response_data, size_t *response_len,
			       __le64 capabilities, __le32 query_type);

/* Apple connection state management */
int aapl_init_connection_state(struct aapl_conn_state *state);
void aapl_cleanup_connection_state(struct aapl_conn_state *state);
int aapl_update_connection_state(struct aapl_conn_state *state,
				 const struct aapl_client_info *client_info);

/* Debug and logging helpers */
void aapl_debug_client_info(const struct aapl_client_info *info);

/* Apple context processing functions */
int aapl_process_finder_info(struct ksmbd_conn *conn,
			    const struct aapl_finder_info *finder_info);
int aapl_process_timemachine_info(struct ksmbd_conn *conn,
			       const struct aapl_timemachine_info *tm_info);
int aapl_handle_timemachine_bundle(struct ksmbd_conn *conn,
				const struct path *path,
				const struct aapl_timemachine_info *tm_info);

/* Module initialization and cleanup */
int aapl_init_module(void);
void aapl_cleanup_module(void);

/* Structure size verification for cross-platform compatibility */
#ifdef __KERNEL__
/* Ensure consistent structure sizes across architectures */
static_assert(sizeof(struct aapl_client_info) == 40,
              "Apple client info structure size must be 40 bytes");
static_assert(sizeof(struct aapl_server_query) == 16,
              "Apple server query structure size must be 16 bytes");
static_assert(sizeof(struct aapl_volume_capabilities) == 24,
              "Apple volume capabilities structure size must be 24 bytes");
static_assert(sizeof(struct aapl_file_mode) == 16,
              "Apple file mode structure size must be 16 bytes");
static_assert(sizeof(struct aapl_finder_info) == 32,
              "Apple finder info structure size must be 32 bytes");
static_assert(sizeof(struct aapl_timemachine_info) == 48,
              "Apple timemachine info structure size must be 48 bytes");
static_assert(sizeof(struct aapl_negotiate_context) == 96,
              "Apple negotiate context structure size must be 96 bytes");
static_assert(sizeof(struct aapl_dir_hardlinks) == 12,
              "Apple dir hardlinks structure size must be 12 bytes");
static_assert(sizeof(struct aapl_conn_state) == 120,
              "Apple connection state structure size must be 120 bytes");

/* SMB2 Protocol Compliance: Verify create_context size matches specification */
static_assert(sizeof(struct create_context) == 24,
              "SMB2 create_context structure size must be 24 bytes per MS-SMB2");

/* Verify packing and alignment compliance */
static_assert(offsetof(struct aapl_client_info, signature) == 0,
              "Apple client info signature must be at offset 0");
static_assert(offsetof(struct aapl_client_info, version) == 4,
              "Apple client info version must be at offset 4");
static_assert(offsetof(struct aapl_client_info, capabilities) == 12,
              "Apple client info capabilities must be at offset 12");
#endif

#endif /* _SMB2_AAPL_H */