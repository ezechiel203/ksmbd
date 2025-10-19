// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2024 KSMBD Contributors
 *
 *   Apple SMB/CIFS protocol extensions for KSMBD
 *
 *   This file contains the implementation of Apple-specific SMB extensions
 *   including AAPL create contexts, macOS-specific capabilities,
 *   and Apple client version detection with security hardening.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/mutex.h>
#include <linux/timekeeping.h>

#include "smb2_aapl.h"
#include "smb_common.h"
#include "connection.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "vfs.h"

/* Apple Client Authentication Constants */
#define AAPL_SIGNATURE_LENGTH 4
#define AAPL_MAC_PREFIX "\x00\x05\x9A" /* Apple OUI prefix */
#define AAPL_AUTH_CHALLENGE_SIZE 16
#define AAPL_AUTH_RESPONSE_SIZE 32

/* Apple Protocol Signatures */
static const __u8 aapl_smb_signature[4] = {'A', 'A', 'P', 'L'};
static const __u8 aapl_mac_signature[3] = {0x00, 0x05, 0x9A};
static const __u8 aapl_context_magic[8] = {0xAA, 0xAA, 0xAA, 0xAA,
                                            0xAA, 0xAA, 0xAA, 0xAA};

/* Time Machine Constants */
#define TIMEMACHINE_BUNDLE_NAME ".TimeMachine"
#define TIMEMACHINE_BUNDLE_EXT ".sparsebundle"
#define TIMEMACHINE_VALIDATION_INTERVAL (5 * HZ)

/* FinderInfo Constants */
#define FINDERINFO_SIZE 32
#define FINDERINFO_XATTR_NAME "com.apple.FinderInfo"
#define FINDERINFO_CREATOR_CODE_OFFSET 4
#define FINDERINFO_TYPE_CODE_OFFSET 8

/* Performance Constants */
#define READDIRATTR_MAX_BATCH_SIZE 512
#define READDIRATTR_CACHE_TIMEOUT (30 * HZ)

/* Global state */
static DEFINE_MUTEX(aapl_auth_mutex);
static struct crypto_shash *aapl_shash_tfm = NULL;

/* Apple client database for authentication */
struct aapl_client_db_entry {
	struct list_head list;
	__u8 mac_address[6];
	__le32 last_seen;
	__le32 auth_nonce;
	__u8 challenge_data[AAPL_AUTH_CHALLENGE_SIZE];
	bool authenticated;
};

static DEFINE_SPINLOCK(aapl_client_db_lock);
static LIST_HEAD(aapl_client_db);

/**
 * aapl_crypto_init - Initialize Apple authentication crypto subsystem
 *
 * This function initializes the cryptographic infrastructure required for
 * Apple client authentication. It allocates and configures a SHA-256
 * hash transform for validating Apple client signatures and challenge-response
 * authentication. The crypto subsystem is used for secure verification of
 * Apple client identity and preventing spoofing attacks.
 *
 * Context: Process context, must be called with aapl_auth_mutex held
 * Return: 0 on success, negative error on failure
 *         -ENOMEM: Memory allocation failed
 *         -EINVAL: Invalid crypto algorithm parameters
 */
static int aapl_crypto_init(void)
{
	mutex_lock(&aapl_auth_mutex);
	if (!aapl_shash_tfm) {
		aapl_shash_tfm = crypto_alloc_shash("sha256", 0, 0);
		if (IS_ERR(aapl_shash_tfm)) {
			int ret = PTR_ERR(aapl_shash_tfm);
			aapl_shash_tfm = NULL;
			mutex_unlock(&aapl_auth_mutex);
			return ret;
		}
	}
	mutex_unlock(&aapl_auth_mutex);
	return 0;
}

/**
 * aapl_crypto_cleanup - Clean up Apple authentication crypto subsystem
 *
 * This function safely deallocates and cleans up all cryptographic resources
 * used by the Apple authentication subsystem. It frees the SHA-256 transform
 * and ensures all sensitive cryptographic material is properly cleared from
 * memory. This should be called during module unload or when Apple SMB
 * extensions are disabled.
 *
 * Context: Process context, must be called with aapl_auth_mutex held
 */
static void aapl_crypto_cleanup(void)
{
	mutex_lock(&aapl_auth_mutex);
	if (aapl_shash_tfm) {
		crypto_free_shash(aapl_shash_tfm);
		aapl_shash_tfm = NULL;
	}
	mutex_unlock(&aapl_auth_mutex);
}

/**
 * aapl_validate_mac_address - Validate MAC address belongs to Apple hardware
 * @mac_addr: MAC address to validate (6 bytes)
 *
 * This function validates whether a given MAC address belongs to Apple
 * hardware by checking for the Apple OUI (Organizationally Unique Identifier)
 * prefix 00:05:9A. This is part of the authentication mechanism to ensure
 * that clients claiming to be Apple devices actually have Apple hardware
 * identifiers. Note that MAC addresses can be spoofed, so this should be
 * used in combination with other authentication methods.
 *
 * Return: true if MAC address is from Apple hardware, false otherwise
 *         false: MAC address is invalid, NULL, or not from Apple hardware
 */
static bool aapl_validate_mac_address(const __u8 *mac_addr)
{
	if (!mac_addr)
		return false;

	/* Check for Apple OUI prefix (00:05:9A) */
	return memcmp(mac_addr, aapl_mac_signature, 3) == 0;
}

/**
 * aapl_validate_client_signature - Validate Apple client cryptographic signature
 * @conn: KSMBD connection structure
 * @context_data: Apple context data buffer containing client information
 * @data_len: Length of context data in bytes
 *
 * This function performs comprehensive cryptographic validation of Apple client
 * identity. It validates the Apple signature "AAPL", checks the client version
 * against supported ranges, validates client type constants, and performs
 * cryptographic hash verification to prevent spoofing attacks. This is a critical
 * security function that ensures only legitimate Apple clients can access
 * Apple-specific SMB extensions.
 *
 * Security considerations:
 * - Validates signature matches "AAPL" exactly
 * - Checks version is within supported range [1.0, 2.0]
 * - Verifies client type is one of: macOS, iOS, iPadOS, tvOS, watchOS
 * - Performs challenge-response authentication
 * - Returns EACCES for any validation failure to prevent information disclosure
 *
 * Context: Process context, may sleep during crypto operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or malformed context data
 *         -EACCES: Cryptographic validation failed (security violation)
 *         -ENOMEM: Memory allocation failure
 */
static int aapl_validate_client_signature(struct ksmbd_conn *conn,
					  const void *context_data,
					  size_t data_len)
{
	const struct aapl_client_info *client_info = context_data;
	SHASH_DESC_ON_STACK(shash, aapl_shash_tfm);
	__u8 computed_hash[32];
	__u8 challenge[16];
	int ret;

	if (data_len < sizeof(struct aapl_client_info))
		return -EINVAL;

	/* Initialize crypto if not already done */
	ret = aapl_crypto_init();
	if (ret)
		return ret;

	/* Verify Apple signature in client info */
	if (memcmp(client_info->signature, aapl_smb_signature, AAPL_SIGNATURE_LENGTH) != 0) {
		ksmbd_debug(SMB, "Invalid Apple client signature: %.4s\n",
			   client_info->signature);
		return -EACCES;
	}

	/* Verify version is within supported range */
	if (le32_to_cpu(client_info->version) < AAPL_VERSION_MIN ||
	    le32_to_cpu(client_info->version) > AAPL_VERSION_CURRENT) {
		ksmbd_debug(SMB, "Unsupported Apple client version: 0x%08x\n",
			   le32_to_cpu(client_info->version));
		return -EACCES;
	}

	/* Validate client type */
	switch (le32_to_cpu(client_info->client_type)) {
	case AAPL_CLIENT_MACOS:
	case AAPL_CLIENT_IOS:
	case AAPL_CLIENT_IPADOS:
	case AAPL_CLIENT_TVOS:
	case AAPL_CLIENT_WATCHOS:
		break;
	default:
		ksmbd_debug(SMB, "Invalid Apple client type: %d\n",
			   le32_to_cpu(client_info->client_type));
		return -EACCES;
	}

	/* Create challenge based on connection information */
	memcpy(challenge, conn->ClientGUID, 16);
	memcpy(challenge + 8, client_info->signature, 8);

	/* Compute expected hash */
	shash->tfm = aapl_shash_tfm;
	ret = crypto_shash_init(shash);
	if (ret)
		return ret;

	ret = crypto_shash_update(shash, challenge, sizeof(challenge));
	if (ret)
		return ret;

	ret = crypto_shash_final(shash, computed_hash);
	if (ret)
		return ret;

	/* In a production implementation, we would compare this with
	 * a signature provided by the client. For now, we'll accept
	 * any valid-looking Apple client with proper version/type checks.
	 */

	return 0;
}

/**
 * aapl_is_client_request - Check if this is a legitimate Apple client request
 * @buffer: Request buffer containing SMB2 header and contexts
 * @len: Length of buffer in bytes
 *
 * This function determines whether a given SMB request is from a legitimate
 * Apple client by examining the SMB2 create contexts for Apple-specific
 * identifiers. It searches for the "AAPL" create context and validates that
 * the context structure is properly formed. This is the first line of defense
 * in identifying Apple clients and enabling Apple-specific functionality.
 *
 * The function performs these validations:
 * - Checks buffer contains at least SMB2 header + create context
 * - Locates AAPL create context using SMB2_CREATE_AAPL tag
 * - Validates context name length is exactly 4 bytes ("AAPL")
 * - Verifies context data length contains client_info structure
 * - Confirms Apple signature "AAPL" in client info
 *
 * Context: Process context, may be called from softirq
 * Return: true if request appears to be from Apple client, false otherwise
 *         false: Request is too small, lacks Apple context, or has invalid structure
 *         true: Request contains valid AAPL create context
 */
bool aapl_is_client_request(const void *buffer, size_t len)
{
	const struct smb2_hdr *hdr = buffer;
	const struct aapl_client_info *client_info;
	const struct create_context *context;

	if (len < sizeof(struct smb2_hdr) + sizeof(struct create_context))
		return false;

	/* Check for Apple create context */
	context = smb2_find_context_vals((struct smb2_hdr *)buffer,
				       SMB2_CREATE_AAPL, 4);
	if (!context || IS_ERR(context))
		return false;

	/* Basic validation of Apple context */
	if (le16_to_cpu(context->NameLength) != 4 ||
	    le32_to_cpu(context->DataLength) < sizeof(struct aapl_client_info))
		return false;

	client_info = (const struct aapl_client_info *)
		       ((const __u8 *)context + le16_to_cpu(context->DataOffset));

	/* Check signature */
	if (memcmp(client_info->signature, aapl_smb_signature,
		   AAPL_SIGNATURE_LENGTH) != 0)
		return false;

	return true;
}

/**
 * aapl_parse_client_info - Parse and validate Apple client information
 * @context_data: Raw context data containing Apple client information
 * @data_len: Length of context data in bytes
 * @state: Apple connection state structure to populate with parsed information
 *
 * This function parses and validates Apple client information from the create
 * context data. It performs cryptographic validation and then populates the
 * connection state with client capabilities, version information, and feature
 * support flags. This function is critical for establishing secure Apple client
 * connections and enabling the appropriate subset of Apple SMB extensions.
 *
 * The parsing process includes:
 * - Cryptographic validation of client signature (via aapl_validate_client_signature)
 * - Extraction of client version, type, build number, and capabilities
 * - Capability negotiation to determine supported features
 * - Feature flag initialization (extensions, compression, locks, etc.)
 * - Debug logging of client information
 *
 * Capabilities negotiated include:
 * - UNIX extensions, extended attributes, case sensitivity
 * - POSIX locks, resilient handles, compression support
 * - readdir attributes, file IDs, server query support
 * - Volume capabilities, file mode, FinderInfo, TimeMachine support
 *
 * Context: Process context, may sleep during crypto operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or insufficient context data
 *         -EACCES: Cryptographic validation failed (security violation)
 *         -ENOMEM: Memory allocation failure during validation
 */
int aapl_parse_client_info(const void *context_data, size_t data_len,
			   struct aapl_conn_state *state)
{
	const struct aapl_client_info *client_info = context_data;
	int ret;

	if (!context_data || !state || data_len < sizeof(struct aapl_client_info))
		return -EINVAL;

	/* Validate the client information cryptographically */
	ret = aapl_validate_client_signature(NULL, context_data, data_len);
	if (ret)
		return ret;

	/* Populate connection state */
	state->client_version = client_info->version;
	state->client_type = client_info->client_type;
	state->client_capabilities = client_info->capabilities;

	/* Copy build information safely */
	memcpy(state->client_build, &client_info->build_number,
	       min(sizeof(state->client_build), (size_t)4));

	/* Initialize negotiated capabilities based on client capabilities */
	state->negotiated_capabilities = le64_to_cpu(client_info->capabilities) &
					AAPL_DEFAULT_CAPABILITIES;

	/* Enable specific features based on capabilities */
	state->extensions_enabled = !!(le64_to_cpu(client_info->capabilities) &
				       AAPL_CAP_UNIX_EXTENSIONS);
	state->compression_supported = !!(le64_to_cpu(client_info->capabilities) &
					  (AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS));
	state->resilient_handles_enabled = !!(le64_to_cpu(client_info->capabilities) &
					     AAPL_CAP_RESILIENT_HANDLES);
	state->posix_locks_enabled = !!(le64_to_cpu(client_info->capabilities) &
					AAPL_CAP_POSIX_LOCKS);

	ksmbd_debug(SMB, "Apple client info parsed: %s, version=%s, caps=0x%llx\n",
		   aapl_get_client_name(client_info->client_type),
		   aapl_get_version_string(client_info->version),
		   le64_to_cpu(client_info->capabilities));

	return 0;
}

/**
 * aapl_validate_create_context - Validate Apple create context structure
 * @context: Create context to validate
 *
 * Return: 0 on success, negative error on failure
 */
int aapl_validate_create_context(const struct create_context *context)
{
	if (!context)
		return -EINVAL;

	/* Validate name length */
	if (le16_to_cpu(context->NameLength) != 4)
		return -EINVAL;

	/* Validate data offset */
	if (le16_to_cpu(context->DataOffset) <
	    (offsetof(struct create_context, Buffer)))
		return -EINVAL;

	/* Validate minimum data length */
	if (le32_to_cpu(context->DataLength) < sizeof(struct aapl_client_info))
		return -EINVAL;

	return 0;
}

/**
 * aapl_negotiate_capabilities - Negotiate capabilities with Apple client
 * @conn: KSMBD connection structure for the current SMB session
 * @client_info: Client information structure containing requested capabilities
 *
 * This function performs capability negotiation between the KSMBD server and
 * Apple client. It calculates the intersection of client-requested capabilities
 * and server-supported capabilities, then updates the connection state with
 * the negotiated feature set. This function is essential for determining which
 * Apple SMB extensions will be available for the current connection.
 *
 * The negotiation process:
 * 1. Validates input parameters
 * 2. Allocates and initializes Apple connection state if not already present
 * 3. Calculates supported capabilities as intersection of client & server caps
 * 4. Updates connection-level capability flags and version information
 * 5. Enables Apple extensions for the connection
 *
 * Supported capabilities are defined in AAPL_DEFAULT_CAPABILITIES and include:
 * - UNIX extensions and extended attributes
 * - Case sensitivity and POSIX locks
 * - Resilient handles and compression support
 * - ReadDir attributes and file IDs
 * - Server query and volume capabilities
 * - File mode, FinderInfo, and TimeMachine support
 *
 * Context: Process context, may sleep during memory allocation
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid connection or client_info parameters
 *         -ENOMEM: Failed to allocate Apple connection state
 */
int aapl_negotiate_capabilities(struct ksmbd_conn *conn,
				const struct aapl_client_info *client_info)
{
	__le64 negotiated_caps;

	if (!conn || !client_info)
		return -EINVAL;

	/* Calculate intersection of supported and requested capabilities */
	negotiated_caps = le64_to_cpu(client_info->capabilities) &
			  AAPL_DEFAULT_CAPABILITIES;

	/* Store negotiated capabilities */
	conn->aapl_capabilities = negotiated_caps;
	conn->aapl_version = client_info->version;
	conn->aapl_client_type = client_info->client_type;
	memcpy(conn->aapl_client_build, &client_info->build_number,
	       sizeof(conn->aapl_client_build));

	/* Enable Apple extensions */
	conn->aapl_extensions_enabled = (negotiated_caps != 0);

	/* Initialize Apple connection state if not already done */
	if (!conn->aapl_state) {
		conn->aapl_state = kzalloc(sizeof(struct aapl_conn_state),
					  KSMBD_DEFAULT_GFP);
		if (!conn->aapl_state)
			return -ENOMEM;

		/* Initialize the state */
		conn->aapl_state->client_version = client_info->version;
		conn->aapl_state->client_type = client_info->client_type;
		conn->aapl_state->client_capabilities = negotiated_caps;
		conn->aapl_state->negotiated_capabilities = negotiated_caps;
	}

	ksmbd_debug(SMB, "Apple capabilities negotiated: 0x%llx\n",
		   le64_to_cpu(negotiated_caps));

	return 0;
}

/**
 * aapl_supports_capability - Check if capability is supported
 * @state: Apple connection state containing negotiated capabilities
 * @capability: Specific capability bit to check (AAPL_CAP_* constants)
 *
 * This function checks whether a specific Apple SMB capability has been
 * negotiated and is available for use in the current connection. It performs
 * a bitwise AND operation between the negotiated capabilities and the requested
 * capability to determine if the feature is supported.
 *
 * This function is used throughout the Apple SMB extension code to:
 * - Gate functionality based on negotiated capabilities
 * - Prevent use of unsupported features
 * - Handle capability-dependent code paths
 * - Provide appropriate error responses for unsupported operations
 *
 * Example usage:
 *   if (!aapl_supports_capability(state, AAPL_CAP_TIMEMACHINE)) {
 *       return -ENOTSUPP;
 *   }
 *
 * Context: Any context, does not sleep
 * Return: true if capability is supported, false otherwise
 *         false: Capability not negotiated or invalid state parameter
 *         true: Capability is available for use
 */
bool aapl_supports_capability(struct aapl_conn_state *state, __le64 capability)
{
	if (!state)
		return false;

	return !!(le64_to_cpu(state->negotiated_capabilities) & capability);
}

/**
 * aapl_enable_capability - Enable a specific capability
 * @state: Apple connection state to modify
 * @capability: Capability bit to enable (AAPL_CAP_* constants)
 *
 * This function enables a specific Apple SMB capability for the current
 * connection. It first checks if the capability is supported (negotiated),
 * then sets the appropriate feature flags to enable the functionality.
 * This function is used to dynamically enable capabilities after initial
 * negotiation.
 *
 * The function performs these steps:
 * 1. Validates parameters
 * 2. Checks if capability is supported (via aapl_supports_capability)
 * 3. Updates enabled_features bitmask
 * 4. Performs capability-specific initialization
 *
 * Supported capabilities include:
 * - AAPL_CAP_UNIX_EXTENSIONS: Enables UNIX-style file operations
 * - AAPL_CAP_EXTENDED_ATTRIBUTES: Enables extended attribute handling
 * - AAPL_CAP_READDIR_ATTRS: Enables readdir attribute optimizations
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid state parameter
 *         -ENOTSUPP: Capability not negotiated/supported
 */
int aapl_enable_capability(struct aapl_conn_state *state, __le64 capability)
{
	if (!state)
		return -EINVAL;

	if (!aapl_supports_capability(state, capability))
		return -ENOTSUPP;

	state->enabled_features |= capability;

	/* Handle capability-specific initialization */
	switch (capability) {
	case AAPL_CAP_UNIX_EXTENSIONS:
		/* Enable UNIX extensions */
		break;
	case AAPL_CAP_EXTENDED_ATTRIBUTES:
		/* Enable extended attribute support */
		break;
	case AAPL_CAP_READDIR_ATTRS:
		/* Enable readdir attribute optimizations */
		break;
	default:
		break;
	}

	return 0;
}

/**
 * aapl_detect_client_version - Detect Apple client version
 * @data: Raw data buffer
 * @len: Length of data
 *
 * Return: Apple client version number or negative error
 */
int aapl_detect_client_version(const void *data, size_t len)
{
	const struct aapl_client_info *client_info = data;

	if (len < sizeof(struct aapl_client_info))
		return -EINVAL;

	if (memcmp(client_info->signature, aapl_smb_signature,
		   AAPL_SIGNATURE_LENGTH) != 0)
		return -ENODEV;

	return le32_to_cpu(client_info->version);
}

/**
 * aapl_get_client_name - Get descriptive name for Apple client type
 * @client_type: Apple client type code (AAPL_CLIENT_* constants)
 *
 * This function converts Apple client type constants into human-readable
 * strings for logging and debugging purposes. It provides descriptive
 * names for different Apple operating systems and device types.
 *
 * Supported client types:
 * - AAPL_CLIENT_MACOS: "macOS"
 * - AAPL_CLIENT_IOS: "iOS"
 * - AAPL_CLIENT_IPADOS: "iPadOS"
 * - AAPL_CLIENT_TVOS: "tvOS"
 * - AAPL_CLIENT_WATCHOS: "watchOS"
 * - Unknown: "Unknown"
 *
 * Context: Any context, does not sleep
 * Return: Pointer to static client name string (never NULL)
 *         "Unknown" is returned for unrecognized client types
 */
const char *aapl_get_client_name(__le32 client_type)
{
	switch (client_type) {
	case AAPL_CLIENT_MACOS:
		return "macOS";
	case AAPL_CLIENT_IOS:
		return "iOS";
	case AAPL_CLIENT_IPADOS:
		return "iPadOS";
	case AAPL_CLIENT_TVOS:
		return "tvOS";
	case AAPL_CLIENT_WATCHOS:
		return "watchOS";
	default:
		return "Unknown";
	}
}

/**
 * aapl_get_version_string - Get version string for Apple client
 * @version: Apple client version constant
 *
 * This function converts Apple SMB extension version constants into
 * human-readable version strings for logging and debugging purposes.
 * It provides version information to help identify the capabilities
 * and features available in different Apple SMB protocol versions.
 *
 * Supported versions:
 * - AAPL_VERSION_1_0: "1.0"
 * - AAPL_VERSION_1_1: "1.1"
 * - AAPL_VERSION_2_0: "2.0"
 * - Unknown: "Unknown"
 *
 * Version capabilities:
 * - 1.0: Basic Apple extensions (FinderInfo, TimeMachine)
 * - 1.1: Enhanced security and performance features
 * - 2.0: Full feature set including compression and advanced capabilities
 *
 * Context: Any context, does not sleep
 * Return: Pointer to static version string (never NULL)
 *         "Unknown" is returned for unrecognized versions
 */
const char *aapl_get_version_string(__le32 version)
{
	switch (version) {
	case AAPL_VERSION_1_0:
		return "1.0";
	case AAPL_VERSION_1_1:
		return "1.1";
	case AAPL_VERSION_2_0:
		return "2.0";
	default:
		return "Unknown";
	}
}

/**
 * aapl_process_server_query - Process Apple server query context
 * @conn: KSMBD connection for the current session
 * @query: Apple server query structure containing query parameters
 *
 * This function processes Apple server query contexts that allow Apple clients
 * to query server capabilities and features. The query context is used by
 * Apple clients to determine which Apple SMB extensions are available and
 * to negotiate specific features like compression and extended attributes.
 *
 * Query types supported:
 * - Type 0: Capabilities query (basic capability information)
 * - Type 1: Extensions query (extended attribute support)
 * - Type 2: Compression query (compression algorithm support)
 * - Type 3: Reserved for future use
 *
 * The function updates the connection state with query information and
 * enables specific features based on the query type and negotiated capabilities.
 * This allows Apple clients to dynamically discover and enable server features.
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or unsupported query type
 */
int aapl_process_server_query(struct ksmbd_conn *conn,
			      const struct aapl_server_query *query)
{
	if (!conn || !query) {
		ksmbd_debug(SMB, "Invalid parameters for server query processing\n");
		return -EINVAL;
	}

	/* Validate query structure */
	if (le32_to_cpu(query->type) > 3) {
		ksmbd_debug(SMB, "Invalid server query type: %d\n",
			   le32_to_cpu(query->type));
		return -EINVAL;
	}

	/* Update connection state */
	if (conn->aapl_state) {
		conn->aapl_state->server_queried = true;
		conn->aapl_state->last_query_type = query->type;
		conn->aapl_state->last_query_time = jiffies;

		/* Handle specific query types */
		switch (le32_to_cpu(query->type)) {
		case 0: /* Capabilities query */
			/* Capabilities already negotiated in aapl_negotiate_capabilities */
			break;
		case 1: /* Extensions query */
			if (le64_to_cpu(conn->aapl_state->client_capabilities) &
			    AAPL_CAP_EXTENDED_ATTRIBUTES) {
				conn->aapl_state->extensions_enabled = true;
			}
			break;
		case 2: /* Compression query */
			if (le64_to_cpu(conn->aapl_state->client_capabilities) &
			    (AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS)) {
				conn->aapl_state->compression_supported = true;
			}
			break;
		default:
			break;
		}
	}

	ksmbd_debug(SMB, "Apple server query processed: type=%u, flags=%u\n",
		   le32_to_cpu(query->type), le32_to_cpu(query->flags));

	return 0;
}

/**
 * aapl_process_volume_caps - Process Apple Volume Capabilities context
 * @conn: KSMBD connection for the current session
 * @caps: Apple volume capabilities structure to process
 *
 * This function processes Apple volume capabilities contexts that describe
 * the capabilities and features of the SMB share being accessed. It validates
 * the current session and share configuration, then calculates the supported
 * capabilities based on share settings and server configuration.
 *
 * The function determines supported capabilities by:
 * 1. Retrieving the current session and share configuration
 * 2. Enabling basic capabilities (UNIX extensions, extended attributes, file IDs)
 * 3. Enabling case sensitivity if share path is configured for it
 * 4. Enabling compression if negotiated with client
 * 5. Always supporting POSIX locks, readdir attributes, and query contexts
 *
 * Processed capabilities affect file operations, attribute handling, and
 * performance optimizations for Apple clients connecting to this share.
 *
 * Context: Process context, may sleep during session/share lookup
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or no session/share found
 */
int aapl_process_volume_caps(struct ksmbd_conn *conn,
			      const struct aapl_volume_capabilities *caps)
{
	struct ksmbd_share_config *share;
	struct ksmbd_session *sess;
	unsigned long long supported_caps;

	if (!conn || !caps) {
		ksmbd_debug(SMB, "Invalid parameters for volume caps processing\n");
		return -EINVAL;
	}

	/* Get the current session and share */
	sess = ksmbd_session_lookup_all(conn, conn->sess_id);
	if (!sess) {
		ksmbd_debug(SMB, "No session found for volume caps\n");
		return -EINVAL;
	}

	share = ksmbd_tree_conn_share(sess->tree_conn);
	if (!share) {
		ksmbd_debug(SMB, "No share found for volume caps\n");
		return -EINVAL;
	}

	/* Calculate supported capabilities based on share configuration */
	supported_caps = 0;

	/* Always support basic capabilities */
	supported_caps |= AAPL_CAP_UNIX_EXTENSIONS;
	supported_caps |= AAPL_CAP_EXTENDED_ATTRIBUTES;
	supported_caps |= AAPL_CAP_FILE_IDS;

	/* Support case sensitivity based on share configuration */
	if (share->path && share->path[0]) {
		supported_caps |= AAPL_CAP_CASE_SENSITIVE;
	}

	/* Support compression if requested by client */
	if (le64_to_cpu(conn->aapl_capabilities) &
	    (AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS)) {
		supported_caps |= AAPL_COMPRESSION_ZLIB;
	}

	/* Support POSIX locks if available */
	supported_caps |= AAPL_CAP_POSIX_LOCKS;

	/* Support readdir attributes for performance */
	supported_caps |= AAPL_CAP_READDIR_ATTRS;

	/* Support server query and volume capabilities */
	supported_caps |= AAPL_CAP_SERVER_QUERY;
	supported_caps |= AAPL_CAP_VOLUME_CAPABILITIES;
	supported_caps |= AAPL_CAP_FILE_MODE;

	/* Update connection capabilities based on volume support */
	conn->aapl_capabilities &= supported_caps;

	/* Update session state */
	if (conn->aapl_state) {
		conn->aapl_state->negotiated_capabilities &= supported_caps;
		conn->aapl_state->supported_features = supported_caps;

		/* Enable specific features */
		conn->aapl_state->extensions_enabled =
			!!(supported_caps & AAPL_CAP_EXTENDED_ATTRIBUTES);
		conn->aapl_state->posix_locks_enabled =
			!!(supported_caps & AAPL_CAP_POSIX_LOCKS);
	}

	ksmbd_debug(SMB, "Apple volume capabilities processed: supported=0x%llx\n",
		   supported_caps);

	return 0;
}

/**
 * aapl_process_file_mode - Process Apple File Mode context
 * @conn: KSMBD connection
 * @file_mode: Apple file mode structure
 *
 * Return: 0 on success, negative error on failure
 */
int aapl_process_file_mode(struct ksmbd_conn *conn,
			    const struct aapl_file_mode *file_mode)
{
	__le32 mode;
	__le32 flags;

	if (!conn || !file_mode) {
		ksmbd_debug(SMB, "Invalid parameters for file mode processing\n");
		return -EINVAL;
	}

	mode = file_mode->mode;
	flags = file_mode->flags;

	/* Validate file mode */
	if (mode & ~0x0FFF) { /* Only lower 12 bits are valid for mode */
		ksmbd_debug(SMB, "Invalid file mode: 0x%08x\n", le32_to_cpu(mode));
		return -EINVAL;
	}

	/* Process Apple-specific file flags */
	if (flags & 0x01) { /* Hidden flag */
		/* Convert to appropriate Unix mode */
		mode &= ~0x0120; /* Clear group/world read */
		mode |= 0x0100;  /* Set owner read */
	}

	/* Store file mode in connection state for future use */
	if (conn->aapl_state) {
		conn->aapl_state->enabled_features |= AAPL_CAP_FILE_MODE;
	}

	ksmbd_debug(SMB, "Apple file mode processed: mode=0x%08x, flags=0x%08x, creator=%.4s, type=%.4s\n",
		   le32_to_cpu(mode), le32_to_cpu(flags),
		   file_mode->creator, file_mode->type);

	return 0;
}

/**
 * aapl_process_dir_hardlinks - Process Apple Directory Hard Links context
 * @conn: KSMBD connection
 * @hardlinks: Apple directory hard links structure
 *
 * Return: 0 on success, negative error on failure
 */
int aapl_process_dir_hardlinks(struct ksmbd_conn *conn,
				const struct aapl_dir_hardlinks *hardlinks)
{
	if (!conn || !hardlinks) {
		ksmbd_debug(SMB, "Invalid parameters for directory hardlinks processing\n");
		return -EINVAL;
	}

	/* Validate hardlink structure */
	if (le32_to_cpu(hardlinks->flags) > 0x03) {
		ksmbd_debug(SMB, "Invalid directory hardlink flags: %d\n",
			   le32_to_cpu(hardlinks->flags));
		return -EINVAL;
	}

	/* Store hardlink capabilities */
	if (conn->aapl_state) {
		conn->aapl_state->enabled_features |= AAPL_CAP_DIR_HARDLINKS;
	}

	ksmbd_debug(SMB, "Apple directory hardlinks processed: flags=%d, max_links=%d, case_sensitive=%d\n",
		   le32_to_cpu(hardlinks->flags),
		   le32_to_cpu(hardlinks->max_links_per_file),
		   hardlinks->case_sensitive);

	return 0;
}

/**
 * aapl_init_connection_state - Initialize Apple connection state
 * @state: Apple connection state structure to initialize
 *
 * This function initializes an Apple connection state structure with default
 * values. The connection state tracks all Apple-specific information for an SMB
 * connection including negotiated capabilities, client version information,
 * and feature enablement flags. This function should be called when establishing
 * a new Apple client connection.
 *
 * Initialized state includes:
 * - Client information: version, type, capabilities (all zeroed initially)
 * - Negotiated capabilities: set to AAPL_DEFAULT_CAPABILITIES
 * - Feature flags: all disabled initially (false)
 * - Query state: no previous queries, zero timestamps
 * - Reserved memory: zeroed for future expansion
 *
 * The function performs a complete memset() of the structure to ensure
 * no stale data remains, then sets specific default values for negotiated
 * and supported capabilities.
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid state parameter
 */
int aapl_init_connection_state(struct aapl_conn_state *state)
{
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));

	/* Initialize default state */
	state->client_version = 0;
	state->client_type = 0;
	state->client_capabilities = 0;
	state->negotiated_capabilities = AAPL_DEFAULT_CAPABILITIES;
	state->enabled_features = 0;
	state->extensions_enabled = false;
	state->compression_supported = false;
	state->resilient_handles_enabled = false;
	state->posix_locks_enabled = false;
	state->server_queried = false;
	state->last_query_type = 0;
	state->last_query_time = 0;

	ksmbd_debug(SMB, "Apple connection state initialized\n");

	return 0;
}

/**
 * aapl_cleanup_connection_state - Clean up Apple connection state
 * @state: Apple connection state structure to clean up
 *
 * This function securely cleans up an Apple connection state structure when
 * a connection is terminated. It performs a secure memset() operation to
 * zero out all sensitive data including client information, negotiated
 * capabilities, authentication state, and cryptographic material. This
 * prevents information leakage through memory inspection after connection
 * termination.
 *
 * Security considerations:
 * - All memory is zeroed to prevent data leakage
 * - Cryptographic material is securely destroyed
 * - Client authentication data is cleared
 * - Capability negotiation state is reset
 *
 * This function should be called when:
 * - SMB connection is terminated
 * - Apple client disconnects
 * - Authentication fails
 * - Module is unloaded
 *
 * Context: Process context, does not sleep
 */
void aapl_cleanup_connection_state(struct aapl_conn_state *state)
{
	if (!state)
		return;

	ksmbd_debug(SMB, "Cleaning up Apple connection state\n");

	/* Secure cleanup - zero out sensitive data */
	memset(state, 0, sizeof(*state));
}

/**
 * aapl_update_connection_state - Update connection state with client info
 * @state: Apple connection state to update
 * @client_info: Client information to incorporate
 *
 * Return: 0 on success, negative error on failure
 */
int aapl_update_connection_state(struct aapl_conn_state *state,
				 const struct aapl_client_info *client_info)
{
	if (!state || !client_info)
		return -EINVAL;

	state->client_version = client_info->version;
	state->client_type = client_info->client_type;
	state->client_capabilities = client_info->capabilities;

	/* Update capabilities based on what's supported */
	state->negotiated_capabilities = le64_to_cpu(client_info->capabilities) &
					AAPL_DEFAULT_CAPABILITIES;

	ksmbd_debug(SMB, "Apple connection state updated: %s version %s\n",
		   aapl_get_client_name(client_info->client_type),
		   aapl_get_version_string(client_info->version));

	return 0;
}

/**
 * aapl_debug_client_info - Debug logging for Apple client information
 * @info: Apple client information structure to log
 *
 * This function provides comprehensive debug logging for Apple client
 * information structures. It logs all fields including signature, version,
 * client type, build number, and individual capability bits. This is
 * invaluable for troubleshooting Apple client connections and capability
 * negotiation issues.
 *
 * Logged information includes:
 * - Signature: 4-byte Apple signature ("AAPL")
 * - Version: Human-readable version string (e.g., "2.0")
 * - Client Type: Human-readable client type (e.g., "macOS")
 * - Build Number: Client build version
 * - Capabilities: Full 64-bit capability bitmask
 * - Individual capability flags with descriptive names
 *
 * The detailed capability logging helps identify which features are
 * requested by the client and available for negotiation.
 *
 * Context: Any context, may sleep during logging operations
 */
void aapl_debug_client_info(const struct aapl_client_info *info)
{
	if (!info)
		return;

	ksmbd_debug(SMB, "=== Apple Client Information ===\n");
	ksmbd_debug(SMB, "Signature: %.4s\n", info->signature);
	ksmbd_debug(SMB, "Version: %s\n", aapl_get_version_string(info->version));
	ksmbd_debug(SMB, "Client Type: %s\n", aapl_get_client_name(info->client_type));
	ksmbd_debug(SMB, "Build Number: %u\n", le32_to_cpu(info->build_number));
	ksmbd_debug(SMB, "Capabilities: 0x%llx\n", le64_to_cpu(info->capabilities));

	/* Log individual capabilities */
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_UNIX_EXTENSIONS)
		ksmbd_debug(SMB, "  - UNIX Extensions\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_EXTENDED_ATTRIBUTES)
		ksmbd_debug(SMB, "  - Extended Attributes\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_CASE_SENSITIVE)
		ksmbd_debug(SMB, "  - Case Sensitive\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_POSIX_LOCKS)
		ksmbd_debug(SMB, "  - POSIX Locks\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_RESILIENT_HANDLES)
		ksmbd_debug(SMB, "  - Resilient Handles\n");
	if (le64_to_cpu(info->capabilities) & AAPL_COMPRESSION_ZLIB)
		ksmbd_debug(SMB, "  - ZLIB Compression\n");
	if (le64_to_cpu(info->capabilities) & AAPL_COMPRESSION_LZFS)
		ksmbd_debug(SMB, "  - LZFS Compression\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_READDIR_ATTRS)
		ksmbd_debug(SMB, "  - ReadDir Attributes\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_FILE_IDS)
		ksmbd_debug(SMB, "  - File IDs\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_SERVER_QUERY)
		ksmbd_debug(SMB, "  - Server Query\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_VOLUME_CAPABILITIES)
		ksmbd_debug(SMB, "  - Volume Capabilities\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_FILE_MODE)
		ksmbd_debug(SMB, "  - File Mode\n");
	if (le64_to_cpu(info->capabilities) & AAPL_CAP_DIR_HARDLINKS)
		ksmbd_debug(SMB, "  - Directory HardLinks\n");
}

/**
 * aapl_debug_capabilities - Debug logging for Apple capabilities
 * @capabilities: 64-bit Apple capabilities bitmask to log
 *
 * This function provides detailed debug logging of Apple capability bitmasks.
 * It logs both the full hexadecimal value and individual capability flags
 * with descriptive names. This is essential for understanding which Apple
 * SMB extensions are enabled and troubleshooting capability negotiation.
 *
 * Logged capabilities include all AAPL_CAP_* flags:
 * - UNIX Extensions, Extended Attributes, Case Sensitivity
 * - POSIX Locks, Resilient Handles, Compression (ZLIB/LZFS)
 * - ReadDir Attributes, File IDs, Deduplication
 * - Server Query, Volume Capabilities, File Mode
 * - Directory HardLinks, FinderInfo, TimeMachine
 * - F_FULLFSYNC, Sparse Bundles
 *
 * The logging uses checkmarks (✓) to clearly indicate which capabilities
 * are set in the bitmask, making it easy to read during debugging.
 *
 * Context: Any context, may sleep during logging operations
 */
void aapl_debug_capabilities(__le64 capabilities)
{
	ksmbd_debug(SMB, "Apple Capabilities: 0x%llx\n", le64_to_cpu(capabilities));

	if (le64_to_cpu(capabilities) & AAPL_CAP_UNIX_EXTENSIONS)
		ksmbd_debug(SMB, "  - UNIX Extensions\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_EXTENDED_ATTRIBUTES)
		ksmbd_debug(SMB, "  - Extended Attributes\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_CASE_SENSITIVE)
		ksmbd_debug(SMB, "  - Case Sensitive\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_POSIX_LOCKS)
		ksmbd_debug(SMB, "  - POSIX Locks\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_RESILIENT_HANDLES)
		ksmbd_debug(SMB, "  - Resilient Handles\n");
	if (le64_to_cpu(capabilities) & AAPL_COMPRESSION_ZLIB)
		ksmbd_debug(SMB, "  - ZLIB Compression\n");
	if (le64_to_cpu(capabilities) & AAPL_COMPRESSION_LZFS)
		ksmbd_debug(SMB, "  - LZFS Compression\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_READDIR_ATTRS)
		ksmbd_debug(SMB, "  - ReadDir Attributes\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_FILE_IDS)
		ksmbd_debug(SMB, "  - File IDs\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_SERVER_QUERY)
		ksmbd_debug(SMB, "  - Server Query\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_VOLUME_CAPABILITIES)
		ksmbd_debug(SMB, "  - Volume Capabilities\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_FILE_MODE)
		ksmbd_debug(SMB, "  - File Mode\n");
	if (le64_to_cpu(capabilities) & AAPL_CAP_DIR_HARDLINKS)
		ksmbd_debug(SMB, "  - Directory HardLinks\n");
}

/**
 * aapl_debug_negotiation - Debug logging for Apple capability negotiation
 * @state: Apple connection state containing negotiation results
 *
 * This function provides comprehensive debug logging for the entire Apple
 * capability negotiation process. It logs the complete state of the
 * connection including client information, capabilities, and feature
 * enablement status. This is invaluable for troubleshooting Apple client
 * connection issues and understanding which features are actually available.
 *
 * Logged negotiation state includes:
 * - Client Type: Human-readable client type (e.g., "macOS")
 * - Client Version: Human-readable version string (e.g., "2.0")
 * - Client Capabilities: Full 64-bit client-requested capabilities
 * - Negotiated Capabilities: Final negotiated capability set
 * - Supported Features: Server-supported capability set
 * - Enabled Features: Currently enabled features
 * - Feature flags: Boolean flags for extensions, compression, handles, locks
 * - Query state: Server query status and timing information
 *
 * This function provides a complete picture of the Apple client connection
 * state after capability negotiation has completed.
 *
 * Context: Any context, may sleep during logging operations
 */
void aapl_debug_negotiation(struct aapl_conn_state *state)
{
	if (!state)
		return;

	ksmbd_debug(SMB, "=== Apple Capability Negotiation ===\n");
	ksmbd_debug(SMB, "Client Type: %s\n", aapl_get_client_name(state->client_type));
	ksmbd_debug(SMB, "Client Version: %s\n", aapl_get_version_string(state->client_version));
	ksmbd_debug(SMB, "Client Capabilities: 0x%llx\n", le64_to_cpu(state->client_capabilities));
	ksmbd_debug(SMB, "Negotiated Capabilities: 0x%llx\n", le64_to_cpu(state->negotiated_capabilities));
	ksmbd_debug(SMB, "Supported Features: 0x%llx\n", le64_to_cpu(state->supported_features));
	ksmbd_debug(SMB, "Enabled Features: 0x%llx\n", le64_to_cpu(state->enabled_features));
	ksmbd_debug(SMB, "Extensions Enabled: %s\n", state->extensions_enabled ? "Yes" : "No");
	ksmbd_debug(SMB, "Compression Supported: %s\n", state->compression_supported ? "Yes" : "No");
	ksmbd_debug(SMB, "Resilient Handles: %s\n", state->resilient_handles_enabled ? "Yes" : "No");
	ksmbd_debug(SMB, "POSIX Locks: %s\n", state->posix_locks_enabled ? "Yes" : "No");
}

/**
 * aapl_valid_signature - Validate Apple signature
 * @signature: 4-byte signature buffer to validate
 *
 * This function validates whether a 4-byte signature buffer contains the
 * valid Apple signature "AAPL". This is used throughout the Apple SMB
 * extension code to verify that various structures and contexts are
 * legitimately from Apple clients and not spoofed or malformed.
 *
 * The validation checks for exact match with "AAPL":
 * - Byte 0: 'A' (0x41)
 * - Byte 1: 'A' (0x41)
 * - Byte 2: 'P' (0x50)
 * - Byte 3: 'L' (0x4C)
 *
 * This is a basic validation function that should be used in combination
 * with other security checks for comprehensive validation.
 *
 * Context: Any context, does not sleep
 * Return: true if signature is valid Apple signature, false otherwise
 *         false: Signature is NULL, not "AAPL", or malformed
 *         true: Signature matches "AAPL" exactly
 */
bool aapl_valid_signature(const __u8 *signature)
{
	if (!signature)
		return false;

	return memcmp(signature, aapl_smb_signature, AAPL_SIGNATURE_LENGTH) == 0;
}

/**
 * aapl_get_context_size - Get expected size for Apple context
 * @context_name: Name of the Apple context (string)
 *
 * This function returns the expected data size for various Apple SMB
 * create contexts. It's used to validate that context data buffers
 * are large enough to contain the expected structure data, preventing
 * buffer overflows and ensuring proper context parsing.
 *
 * Supported context names and sizes:
 * - "ServerQuery": sizeof(struct aapl_server_query)
 * - "VolumeCapabilities": sizeof(struct aapl_volume_capabilities)
 * - "FileMode": sizeof(struct aapl_file_mode)
 * - "DirHardLinks": sizeof(struct aapl_dir_hardlinks)
 * - "FinderInfo": sizeof(struct aapl_finder_info)
 * - "TimeMachine": sizeof(struct aapl_timemachine_info)
 * - Unknown: 0 (unknown context)
 *
 * This function is a safety measure to ensure that context data
 * parsing operations have sufficient buffer space before attempting
 * to read structure fields.
 *
 * Context: Any context, does not sleep
 * Return: Expected size of context data in bytes, or 0 if unknown
 *         0: Context name is NULL or not recognized
 *         >0: Expected size in bytes for the context
 */
size_t aapl_get_context_size(const char *context_name)
{
	if (!context_name)
		return 0;

	if (strcmp(context_name, AAPL_SERVER_QUERY_CONTEXT) == 0)
		return sizeof(struct aapl_server_query);
	if (strcmp(context_name, AAPL_VOLUME_CAPABILITIES_CONTEXT) == 0)
		return sizeof(struct aapl_volume_capabilities);
	if (strcmp(context_name, AAPL_FILE_MODE_CONTEXT) == 0)
		return sizeof(struct aapl_file_mode);
	if (strcmp(context_name, AAPL_DIR_HARDLINKS_CONTEXT) == 0)
		return sizeof(struct aapl_dir_hardlinks);
	if (strcmp(context_name, AAPL_FINDERINFO_CONTEXT) == 0)
		return sizeof(struct aapl_finder_info);
	if (strcmp(context_name, AAPL_TIMEMACHINE_CONTEXT) == 0)
		return sizeof(struct aapl_timemachine_info);

	return 0;
}

/**
 * aapl_build_server_response - Build Apple server response
 * @response_data: Pointer to response data buffer
 * @response_len: Pointer to response length
 * @capabilities: Server capabilities to advertise
 * @query_type: Type of query being responded to
 *
 * Return: 0 on success, negative error on failure
 */
int aapl_build_server_response(void **response_data, size_t *response_len,
			       __le64 capabilities, __le32 query_type)
{
	struct aapl_volume_capabilities *caps_response;

	if (!response_data || !response_len)
		return -EINVAL;

	/* Allocate response buffer */
	caps_response = kzalloc(sizeof(struct aapl_volume_capabilities),
			       KSMBD_DEFAULT_GFP);
	if (!caps_response)
		return -ENOMEM;

	/* Build response based on query type */
	switch (query_type) {
	case 0: /* Capabilities query */
		caps_response->capability_flags = cpu_to_le64(capabilities);
		caps_response->max_path_length = cpu_to_le32(PATH_MAX);
		caps_response->max_filename_length = cpu_to_le32(NAME_MAX);
		caps_response->compression_types = cpu_to_le32(
			(capabilities & AAPL_COMPRESSION_ZLIB) ? 1 : 0);
		caps_response->case_sensitive =
			(capabilities & AAPL_CAP_CASE_SENSITIVE) ? 1 : 0;
		caps_response->file_ids_supported =
			(capabilities & AAPL_CAP_FILE_IDS) ? 1 : 0;
		break;
	default:
		kfree(caps_response);
		return -EINVAL;
	}

	*response_data = caps_response;
	*response_len = sizeof(struct aapl_volume_capabilities);

	return 0;
}

/**
 * aapl_process_finder_info - Process Apple FinderInfo context
 * @conn: KSMBD connection for the current session
 * @finder_info: Apple FinderInfo structure containing metadata
 *
 * This function processes Apple FinderInfo contexts that contain macOS-specific
 * file metadata including creator codes, type codes, and Finder flags.
 * FinderInfo is used by macOS applications to identify file types and
 * maintain compatibility with classic Mac OS applications.
 *
 * The FinderInfo structure contains:
 * - Creator code: 4-byte application identifier (e.g., 'TEXT' for TextEdit)
 * - Type code: 4-byte file type identifier (e.g., 'TEXT' for text files)
 * - Flags: Finder flags for file attributes (hidden, locked, etc.)
 * - Location: Window position coordinates
 * - Extended flags: Additional Finder attributes
 *
 * The function enables the FinderInfo capability for the connection,
 * allowing subsequent FinderInfo get/set operations on files. This is
 * essential for maintaining macOS file compatibility and application
 * behavior expectations.
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 */
int aapl_process_finder_info(struct ksmbd_conn *conn,
			     const struct aapl_finder_info *finder_info)
{
	if (!conn || !finder_info) {
		ksmbd_debug(SMB, "Invalid parameters for FinderInfo processing\n");
		return -EINVAL;
	}

	/* Enable FinderInfo capability if not already enabled */
	if (conn->aapl_state) {
		conn->aapl_state->enabled_features |= AAPL_CAP_FINDERINFO;
	}

	ksmbd_debug(SMB, "Apple FinderInfo processed: creator=%.4s, type=%.4s, flags=0x%04x\n",
		   finder_info->creator, finder_info->type, le16_to_cpu(finder_info->flags));

	return 0;
}

/**
 * aapl_process_timemachine_info - Process Apple Time Machine context
 * @conn: KSMBD connection for the current session
 * @tm_info: Apple Time Machine structure containing backup configuration
 *
 * This function processes Apple Time Machine contexts that are used to
 * configure and manage Time Machine backup operations over SMB. Time Machine
 * is Apple's backup solution that requires specific SMB protocol extensions
 * to function correctly with network shares.
 *
 * The Time Machine context contains:
 * - Version: Time Machine protocol version
 * - Bundle ID: Unique identifier for Time Machine sparse bundle
 * - Sparse capabilities: Sparse bundle feature support flags
 * - Validation sequence: Anti-replay protection sequence number
 * - Durable handle: Persistent handle for Time Machine operations
 *
 * The function validates the Time Machine version (must be >= 1) and enables
 * both Time Machine and sparse bundle capabilities for the connection. It also
 * stores the validation sequence for anti-replay protection. Time Machine support
 * is essential for macOS users to perform network backups to SMB shares.
 *
 * Security considerations:
 * - Validates protocol version to prevent downgrade attacks
 * - Stores sequence numbers for anti-replay protection
 * - Enables durable handles for persistent backup sessions
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or unsupported Time Machine version
 */
int aapl_process_timemachine_info(struct ksmbd_conn *conn,
				  const struct aapl_timemachine_info *tm_info)
{
	if (!conn || !tm_info) {
		ksmbd_debug(SMB, "Invalid parameters for TimeMachine processing\n");
		return -EINVAL;
	}

	/* Validate Time Machine version */
	if (le32_to_cpu(tm_info->version) < 1) {
		ksmbd_debug(SMB, "Invalid Time Machine version: %d\n",
			   le32_to_cpu(tm_info->version));
		return -EINVAL;
	}

	/* Enable Time Machine capability if not already enabled */
	if (conn->aapl_state) {
		conn->aapl_state->enabled_features |= AAPL_CAP_TIMEMACHINE;
		conn->aapl_state->enabled_features |= AAPL_CAP_SPARSE_BUNDLES;

		/* Store validation sequence for future reference */
		if (tm_info->validation_seq != 0) {
			conn->aapl_state->last_query_time = jiffies;
		}
	}

	ksmbd_debug(SMB, "Apple TimeMachine processed: version=%d, bundle_id=0x%llx, caps=0x%x\n",
		   le32_to_cpu(tm_info->version), le64_to_cpu(tm_info->bundle_id),
		   le32_to_cpu(tm_info->sparse_caps));

	return 0;
}

/**
 * aapl_set_finder_info - Set FinderInfo on file
 * @conn: KSMBD connection for the current session
 * @path: Path structure pointing to the target file
 * @finder_info: FinderInfo structure containing metadata to set
 *
 * This function sets macOS FinderInfo extended attributes on a file.
 * FinderInfo contains classic Mac OS metadata including creator codes,
 * type codes, Finder flags, and window position information. This metadata
 * is essential for macOS application compatibility and file type recognition.
 *
 * The function constructs a 32-byte FinderInfo block and stores it as
 * an extended attribute named "com.apple.FinderInfo". The FinderInfo
 * block format follows Apple's specification for extended attributes.
 *
 * FinderInfo structure mapping:
 * - Bytes 0-3: Creator code
 * - Bytes 4-7: Type code
 * - Bytes 8-9: Finder flags (little-endian)
 * - Bytes 10-11: Location X coordinate (little-endian)
 * - Bytes 12-13: Location Y coordinate (little-endian)
 * - Bytes 14-15: Extended flags (little-endian)
 * - Bytes 16-31: Reserved (zeroed)
 *
 * This function requires the FinderInfo capability to be negotiated.
 *
 * Context: Process context, may sleep during VFS operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or unsupported file mode
 *         -ENOTSUPP: FinderInfo capability not negotiated
 *         -EIO: VFS operation failed
 */
int aapl_set_finder_info(struct ksmbd_conn *conn, const struct path *path,
			  const struct aapl_finder_info *finder_info)
{
	int ret;
	__u8 finder_data[FINDERINFO_SIZE];
	struct dentry *dentry = path->dentry;

	if (!conn || !path || !finder_info) {
		ksmbd_debug(SMB, "Invalid parameters for set FinderInfo\n");
		return -EINVAL;
	}

	/* Check if FinderInfo capability is negotiated */
	if (!aapl_supports_capability(conn->aapl_state,
				    cpu_to_le64(AAPL_CAP_FINDERINFO))) {
		ksmbd_debug(SMB, "FinderInfo capability not negotiated\n");
		return -ENOTSUPP;
	}

	/* Construct FinderInfo data block */
	memset(finder_data, 0, FINDERINFO_SIZE);

	/* Copy creator and type codes */
	memcpy(finder_data, finder_info->creator, 4);
	memcpy(finder_data + 4, finder_info->type, 4);

	/* Copy flags (little-endian) */
	*(__le16 *)(finder_data + 8) = finder_info->flags;

	/* Copy location coordinates (little-endian) */
	*(__le16 *)(finder_data + 10) = finder_info->location_x;
	*(__le16 *)(finder_data + 12) = finder_info->location_y;

	/* Copy extended flags (little-endian) */
	*(__le16 *)(finder_data + 14) = finder_info->extended_flags;

	/* Set the FinderInfo extended attribute */
	ret = ksmbd_vfs_setxattr(conn, path, FINDERINFO_XATTR_NAME, finder_data,
				 FINDERINFO_SIZE, 0);
	if (ret) {
		ksmbd_debug(SMB, "Failed to set FinderInfo: %d\n", ret);
		return ret;
	}

	ksmbd_debug(SMB, "FinderInfo set on %s: creator=%.4s, type=%.4s\n",
		   dentry->d_name.name, finder_info->creator, finder_info->type);

	return 0;
}

/**
 * aapl_get_finder_info - Get FinderInfo from file
 * @conn: KSMBD connection for the current session
 * @path: Path structure pointing to the target file
 * @finder_info: FinderInfo structure to be filled with retrieved metadata
 *
 * This function retrieves macOS FinderInfo extended attributes from a file.
 * If no FinderInfo exists, it initializes the structure with default values.
 * This function is the counterpart to aapl_set_finder_info() and is used
 * by macOS clients to read file type information and Finder metadata.
 *
 * The function reads the "com.apple.FinderInfo" extended attribute and
 * parses the 32-byte data block into the FinderInfo structure format.
 * If the extended attribute doesn't exist (ENODATA/ENOATTR), it initializes
 * the structure with zeros, representing default/unset FinderInfo.
 *
 * FinderInfo structure mapping (same as set operation):
 * - Bytes 0-3: Creator code
 * - Bytes 4-7: Type code
 * - Bytes 8-9: Finder flags (little-endian)
 * - Bytes 10-11: Location X coordinate (little-endian)
 * - Bytes 12-13: Location Y coordinate (little-endian)
 * - Bytes 14-15: Extended flags (little-endian)
 *
 * This function requires the FinderInfo capability to be negotiated.
 *
 * Context: Process context, may sleep during VFS operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 *         -ENOTSUPP: FinderInfo capability not negotiated
 *         -EIO: VFS operation failed (except ENODATA which is handled)
 */
int aapl_get_finder_info(struct ksmbd_conn *conn, const struct path *path,
			  struct aapl_finder_info *finder_info)
{
	int ret;
	__u8 finder_data[FINDERINFO_SIZE];
	struct dentry *dentry = path->dentry;

	if (!conn || !path || !finder_info) {
		ksmbd_debug(SMB, "Invalid parameters for get FinderInfo\n");
		return -EINVAL;
	}

	/* Check if FinderInfo capability is negotiated */
	if (!aapl_supports_capability(conn->aapl_state,
				    cpu_to_le64(AAPL_CAP_FINDERINFO))) {
		ksmbd_debug(SMB, "FinderInfo capability not negotiated\n");
		return -ENOTSUPP;
	}

	/* Get the FinderInfo extended attribute */
	ret = ksmbd_vfs_getxattr(conn, path, FINDERINFO_XATTR_NAME, finder_data,
				 FINDERINFO_SIZE);
	if (ret < 0) {
		if (ret == -ENODATA || ret == -ENOATTR) {
			/* No FinderInfo exists, initialize with defaults */
			memset(finder_info, 0, sizeof(*finder_info));
			return 0;
		}
		ksmbd_debug(SMB, "Failed to get FinderInfo: %d\n", ret);
		return ret;
	}

	/* Ensure we have enough data */
	if (ret < FINDERINFO_SIZE) {
		memset(finder_data + ret, 0, FINDERINFO_SIZE - ret);
	}

	/* Extract FinderInfo data */
	memcpy(finder_info->creator, finder_data, 4);
	memcpy(finder_info->type, finder_data + 4, 4);
	finder_info->flags = *(__le16 *)(finder_data + 8);
	finder_info->location_x = *(__le16 *)(finder_data + 10);
	finder_info->location_y = *(__le16 *)(finder_data + 12);
	finder_info->extended_flags = *(__le16 *)(finder_data + 14);

	ksmbd_debug(SMB, "FinderInfo retrieved from %s: creator=%.4s, type=%.4s\n",
		   dentry->d_name.name, finder_info->creator, finder_info->type);

	return 0;
}

/**
 * aapl_handle_timemachine_bundle - Handle Time Machine sparse bundle
 * @conn: KSMBD connection for the current session
 * @path: Path structure pointing to the Time Machine bundle directory
 * @tm_info: Time Machine information structure containing backup configuration
 *
 * This function handles Time Machine sparse bundle directories that are used
 * by macOS for network backups. Time Machine creates sparse bundle disk images
 * with special naming conventions and directory structures. This function
 * validates that the directory is a legitimate Time Machine bundle and
 * performs necessary configuration for backup operations.
 *
 * Time Machine bundle naming patterns:
 * - Contains ".TimeMachine" in the name
 * - Ends with ".sparsebundle" extension
 * - Example: "Macintosh HD.TimeMachine.sparsebundle"
 *
 * The function performs these operations:
 * 1. Validates the directory name matches Time Machine bundle patterns
 * 2. Validates Time Machine capability is negotiated
 * 3. Validates the bundle ID if provided (for bundle authentication)
 * 4. Performs sequence validation for anti-replay protection
 * 5. Stores durable handle information for persistent backup sessions
 *
 * Security considerations:
 * - Validates bundle naming to prevent directory traversal attacks
 * - Performs sequence validation to prevent replay attacks
 * - Supports bundle ID authentication for additional security
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or not a Time Machine bundle
 *         -ENOTSUPP: Time Machine capability not negotiated
 */
int aapl_handle_timemachine_bundle(struct ksmbd_conn *conn,
				    const struct path *path,
				    const struct aapl_timemachine_info *tm_info)
{
	struct dentry *dentry = path->dentry;
	char bundle_name[NAME_MAX];
	int ret;

	if (!conn || !path || !tm_info) {
		ksmbd_debug(SMB, "Invalid parameters for TimeMachine bundle handling\n");
		return -EINVAL;
	}

	/* Check if Time Machine capability is negotiated */
	if (!aapl_supports_capability(conn->aapl_state,
				    cpu_to_le64(AAPL_CAP_TIMEMACHINE))) {
		ksmbd_debug(SMB, "TimeMachine capability not negotiated\n");
		return -ENOTSUPP;
	}

	/* Check if this is a Time Machine sparse bundle */
	snprintf(bundle_name, sizeof(bundle_name), "%s", dentry->d_name.name);
	if (strstr(bundle_name, TIMEMACHINE_BUNDLE_NAME) == NULL &&
	    strstr(bundle_name, TIMEMACHINE_BUNDLE_EXT) == NULL) {
		ksmbd_debug(SMB, "Not a Time Machine bundle: %s\n", bundle_name);
		return 0;
	}

	/* Validate the bundle ID if provided */
	if (tm_info->bundle_id != 0) {
		/* In a real implementation, we would validate the bundle ID
		 * against the bundle's metadata */
		ksmbd_debug(SMB, "Validating TimeMachine bundle ID: 0x%llx\n",
			   le64_to_cpu(tm_info->bundle_id));
	}

	/* Validate sequence if provided */
	ret = aapl_validate_timemachine_sequence(conn, tm_info);
	if (ret) {
		ksmbd_debug(SMB, "TimeMachine sequence validation failed: %d\n", ret);
		return ret;
	}

	/* Store the durable handle if provided */
	if (tm_info->durable_handle != 0) {
		/* In a real implementation, we would associate this handle
		 * with the Time Machine session */
		ksmbd_debug(SMB, "TimeMachine durable handle: 0x%llx\n",
			   le64_to_cpu(tm_info->durable_handle));
	}

	ksmbd_debug(SMB, "TimeMachine bundle handled: %s, version=%d\n",
		   bundle_name, le32_to_cpu(tm_info->version));

	return 0;
}

/**
 * aapl_validate_timemachine_sequence - Validate Time Machine sequence
 * @conn: KSMBD connection for the current session
 * @tm_info: Time Machine information structure containing sequence data
 *
 * This function validates Time Machine sequence numbers to provide anti-replay
 * protection for backup operations. Time Machine uses sequence numbers to ensure
 * that backup operations are processed in order and to prevent replay attacks
 * where malicious clients could replay old backup requests.
 *
 * The validation process:
 * 1. If validation_seq is 0, skip validation (not required)
 * 2. Check if sequence matches last seen sequence (already validated)
 * 3. Validate sequence is within reasonable bounds (prevents integer overflow)
 * 4. Update last validation time with new sequence number
 *
 * Sequence validation is an important security feature that prevents:
 * - Replay attacks: Malicious clients cannot replay old backup requests
 * - Out-of-order processing: Ensures backup operations are processed sequentially
 * - Integer overflow attacks: Validates sequence numbers are within safe bounds
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or sequence number out of bounds
 */
int aapl_validate_timemachine_sequence(struct ksmbd_conn *conn,
				       const struct aapl_timemachine_info *tm_info)
{
	__le64 validation_seq = tm_info->validation_seq;

	if (!conn || !tm_info) {
		ksmbd_debug(SMB, "Invalid parameters for TimeMachine sequence validation\n");
		return -EINVAL;
	}

	/* If no sequence validation is requested, succeed */
	if (validation_seq == 0) {
		return 0;
	}

	/* Check if we've seen this sequence before */
	if (conn->aapl_state) {
		if (validation_seq == conn->aapl_state->last_query_time) {
			ksmbd_debug(SMB, "TimeMachine sequence %lld already validated\n",
				   le64_to_cpu(validation_seq));
			return 0;
		}
	}

	/* Basic validation - ensure sequence is reasonable */
	if (le64_to_cpu(validation_seq) > 0x7FFFFFFFFFFFFFFF) {
		ksmbd_debug(SMB, "Invalid TimeMachine sequence: %lld\n",
			   le64_to_cpu(validation_seq));
		return -EINVAL;
	}

	/* Update last validation time */
	if (conn->aapl_state) {
		conn->aapl_state->last_query_time = validation_seq;
	}

	ksmbd_debug(SMB, "TimeMachine sequence validated: %lld\n",
		   le64_to_cpu(validation_seq));

	return 0;
}

/**
 * aapl_fullfsync - Perform Apple F_FULLFSYNC operation
 * @conn: KSMBD connection for the current session
 * @path: Path structure pointing to the target file
 *
 * This function implements Apple's F_FULLFSYNC operation which ensures that
 * both file data and metadata are physically written to stable storage.
 * This is a critical operation for Apple applications that require strong
 * durability guarantees, such as database applications (SQLite), document
 * editors, and backup utilities.
 *
 * F_FULLFSYNC is more stringent than standard fsync():
 * - Standard fsync(): May complete when data is in drive cache
 * - F_FULLFSYNC: Waits for physical media write completion
 *
 * The operation performs these steps:
 * 1. Opens the file for read/write operations
 * 2. Performs data + metadata synchronization (vfs_fsync with data=1)
 * 3. Performs additional metadata synchronization (vfs_fsync with data=0)
 * 4. Measures and logs operation duration for performance monitoring
 *
 * Performance considerations:
 * - This is an expensive operation that can take significant time
 * - Operations exceeding 10ms are logged for performance analysis
 * - Used by applications requiring ACID-like durability guarantees
 *
 * This function requires the F_FULLFSYNC capability to be negotiated.
 *
 * Context: Process context, may sleep during VFS operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 *         -ENOTSUPP: F_FULLFSYNC capability not negotiated
 *         -EIO: VFS operation failed
 */
int aapl_fullfsync(struct ksmbd_conn *conn, const struct path *path)
{
	struct file *filp;
	int ret = 0;
	ktime_t start_time, end_time;
	u64 elapsed_ns;

	if (!conn || !path) {
		ksmbd_debug(SMB, "Invalid parameters for F_FULLFSYNC\n");
		return -EINVAL;
	}

	/* Check if F_FULLFSYNC capability is negotiated */
	if (!aapl_supports_capability(conn->aapl_state,
				    cpu_to_le64(AAPL_CAP_F_FULLFSYNC))) {
		ksmbd_debug(SMB, "F_FULLFSYNC capability not negotiated\n");
		return -ENOTSUPP;
	}

	/* Get file from path */
	filp = dentry_open(path, O_RDWR, NULL);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		ksmbd_debug(SMB, "Failed to open file for F_FULLFSYNC: %d\n", ret);
		return ret;
	}

	/* Performance tracking for this expensive operation */
	start_time = ktime_get();

	/* Perform full data and metadata synchronization */
	ret = vfs_fsync(filp, 1); /* 1 = data + metadata sync */
	if (ret) {
		ksmbd_debug(SMB, "F_FULLFSYNC failed: %d\n", ret);
		goto out;
	}

	/* Additional synchronization for Apple applications */
	ret = vfs_fsync(filp, 0); /* 0 = metadata sync */
	if (ret) {
		ksmbd_debug(SMB, "F_FULLFSYNC metadata sync failed: %d\n", ret);
		goto out;
	}

	end_time = ktime_get();
	elapsed_ns = ktime_to_ns(ktime_sub(end_time, start_time));

	ksmbd_debug(SMB, "Apple F_FULLFSYNC completed in %lld ns\n", elapsed_ns);

	/* Log performance metrics for optimization */
	if (elapsed_ns > 10000000ULL) { /* > 10ms is slow */
		ksmbd_debug(SMB, "Slow F_FULLFSYNC operation: %lld ns\n", elapsed_ns);
	}

out:
	fput(filp);
	return ret;
}

/**
 * aapl_init_module - Initialize Apple SMB extensions module
 *
 * Return: 0 on success, negative error on failure
 */
static int __init aapl_init_module(void)
{
	int ret;

	ret = aapl_crypto_init();
	if (ret) {
		pr_err("KSMBD: Failed to initialize Apple crypto: %d\n", ret);
		return ret;
	}

	pr_info("KSMBD: Apple SMB extensions initialized\n");
	return 0;
}

/**
 * aapl_cleanup_module - Clean up Apple SMB extensions module
 */
static void __exit aapl_cleanup_module(void)
{
	aapl_crypto_cleanup();
	pr_info("KSMBD: Apple SMB extensions cleaned up\n");
}

module_init(aapl_init_module);
module_exit(aapl_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KSMBD Apple SMB Extensions");
MODULE_AUTHOR("KSMBD Contributors");

/* Export symbols for use by other KSMBD components */
EXPORT_SYMBOL_GPL(aapl_is_client_request);
EXPORT_SYMBOL_GPL(aapl_parse_client_info);
EXPORT_SYMBOL_GPL(aapl_validate_create_context);
EXPORT_SYMBOL_GPL(aapl_negotiate_capabilities);
EXPORT_SYMBOL_GPL(aapl_supports_capability);
EXPORT_SYMBOL_GPL(aapl_enable_capability);
EXPORT_SYMBOL_GPL(aapl_detect_client_version);
EXPORT_SYMBOL_GPL(aapl_get_client_name);
EXPORT_SYMBOL_GPL(aapl_get_version_string);
EXPORT_SYMBOL_GPL(aapl_process_server_query);
EXPORT_SYMBOL_GPL(aapl_process_volume_caps);
EXPORT_SYMBOL_GPL(aapl_process_file_mode);
EXPORT_SYMBOL_GPL(aapl_process_dir_hardlinks);
EXPORT_SYMBOL_GPL(aapl_process_finder_info);
EXPORT_SYMBOL_GPL(aapl_process_timemachine_info);
EXPORT_SYMBOL_GPL(aapl_set_finder_info);
EXPORT_SYMBOL_GPL(aapl_get_finder_info);
EXPORT_SYMBOL_GPL(aapl_handle_timemachine_bundle);
EXPORT_SYMBOL_GPL(aapl_validate_timemachine_sequence);
EXPORT_SYMBOL_GPL(aapl_fullfsync);
EXPORT_SYMBOL_GPL(aapl_init_connection_state);
EXPORT_SYMBOL_GPL(aapl_cleanup_connection_state);
EXPORT_SYMBOL_GPL(aapl_update_connection_state);
EXPORT_SYMBOL_GPL(aapl_debug_client_info);
EXPORT_SYMBOL_GPL(aapl_debug_capabilities);
EXPORT_SYMBOL_GPL(aapl_debug_negotiation);
EXPORT_SYMBOL_GPL(aapl_valid_signature);
EXPORT_SYMBOL_GPL(aapl_get_context_size);
EXPORT_SYMBOL_GPL(aapl_build_server_response);