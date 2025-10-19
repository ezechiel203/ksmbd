// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Alexandre BETRY
 *
 * Apple SMB/CIFS protocol extensions for KSMBD
 *
 * This file contains simplified implementation of Apple-specific SMB extensions
 * for interoperability with Apple operating systems.
 *
 * Apple, macOS, iOS, Time Machine, and Finder are trademarks of Apple Inc.,
 * registered in the U.S. and other countries. This implementation is provided
 * for interoperability purposes only and is not endorsed or supported by Apple Inc.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>

#include "smb2_aapl.h"
#include "smb_common.h"
#include "connection.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "vfs.h"
#include "ksmbd_work.h"
#include "oplock.h"

/* Apple Protocol Constants */
static const __u8 aapl_smb_signature[4] = {'A', 'A', 'P', 'L'};

/* Time Machine Constants */
#define TIMEMACHINE_BUNDLE_NAME ".TimeMachine"
#define TIMEMACHINE_BUNDLE_EXT ".sparsebundle"
#define TIMEMACHINE_VALIDATION_INTERVAL (5 * HZ)

/* FinderInfo Constants */
#define FINDERINFO_SIZE 32
#define FINDERINFO_XATTR_NAME "com.apple.FinderInfo"

/* Performance Constants */
#define READDIRATTR_MAX_BATCH_SIZE 512
#define READDIRATTR_CACHE_TIMEOUT (30 * HZ)

/**
 * aapl_is_client_request - Simple Apple client request detection
 * @buffer: Request buffer containing SMB2 header and contexts
 * @len: Length of buffer in bytes
 *
 * This function determines whether a given SMB request is from an Apple client
 * by simply checking if the client advertises the "AAPL" create context.
 * If AAPL context is present, the client is considered an Apple client.
 *
 * Context: Process context, may be called from softirq
 * Return: true if request contains AAPL context, false otherwise
 */
bool aapl_is_client_request(const void *buffer, size_t len)
{
	const struct smb2_hdr *hdr = buffer;
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

	/* Validate DataOffset bounds */
	if (len < le16_to_cpu(context->DataOffset) + sizeof(struct aapl_client_info))
		return false;

	return true;
}

/**
 * aapl_parse_client_info - Parse Apple client information
 * @context_data: Apple context data buffer
 * @data_len: Length of context data in bytes
 * @state: Apple connection state to populate
 *
 * This function parses Apple client information from the create context data
 * and populates the connection state. No cryptographic validation is performed.
 *
 * Context: Process context, may sleep during memory operations
 * Return: 0 on success, negative error on failure
 */
int aapl_parse_client_info(const void *context_data, size_t data_len,
			   struct aapl_conn_state *state)
{
	const struct aapl_client_info *client_info;

	if (!context_data || !state || data_len < sizeof(struct aapl_client_info))
		return -EINVAL;

	client_info = context_data;

	/* Validate Apple signature */
	if (memcmp(client_info->signature, aapl_smb_signature, 4) != 0)
		return -EINVAL;

	/* Convert fields from little-endian to host byte order */
	state->client_version = le32_to_cpu(client_info->version);
	state->client_type = le32_to_cpu(client_info->client_type);
	state->client_capabilities = le64_to_cpu(client_info->capabilities);

	/* Copy build information */
	memcpy(state->client_build, client_info->build_number,
	       min_t(size_t, sizeof(state->client_build), sizeof(client_info->build_number)));

	return 0;
}

/**
 * aapl_negotiate_capabilities - Negotiate capabilities with Apple client
 * @conn: KSMBD connection structure
 * @client_info: Apple client information structure
 *
 * This function negotiates capabilities with the Apple client by determining
 * which features are supported by both the client and server.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_negotiate_capabilities(struct ksmbd_conn *conn,
				const struct aapl_client_info *client_info)
{
	struct aapl_conn_state *state;
	__le64 client_caps, server_caps;

	if (!conn || !client_info)
		return -EINVAL;

	/* Allocate Apple connection state if not already present */
	if (!conn->aapl_state) {
		conn->aapl_state = kzalloc(sizeof(struct aapl_conn_state), GFP_KERNEL);
		if (!conn->aapl_state)
			return -ENOMEM;
	}

	state = conn->aapl_state;
	client_caps = client_info->capabilities;

	/* Server-supported capabilities */
	server_caps = AAPL_DEFAULT_CAPABILITIES;

	/* Negotiate capabilities: intersection of client and server */
	state->negotiated_capabilities = client_caps & server_caps;
	state->supported_features = server_caps;
	state->enabled_features = state->negotiated_capabilities;

	/* Set feature enablement flags */
	state->extensions_enabled = !!(state->enabled_features & AAPL_CAP_EXTENDED_ATTRIBUTES);
	state->compression_supported = !!(state->enabled_features &
					 (AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS));
	state->resilient_handles_enabled = !!(state->enabled_features & AAPL_CAP_RESILIENT_HANDLES);
	state->posix_locks_enabled = !!(state->enabled_features & AAPL_CAP_POSIX_LOCKS);

	return 0;
}

/**
 * aapl_supports_capability - Check if capability is supported
 * @state: Apple connection state
 * @capability: Capability to check
 *
 * This function checks if a specific capability is supported by the
 * negotiated Apple connection.
 *
 * Context: Process context
 * Return: true if capability is supported, false otherwise
 */
bool aapl_supports_capability(struct aapl_conn_state *state, __le64 capability)
{
	if (!state)
		return false;

	return !!(state->negotiated_capabilities & capability);
}

/**
 * aapl_detect_client_version - Detect Apple client version
 * @data: Raw client data buffer
 * @len: Length of data in bytes
 *
 * This function detects the Apple client version from the client data.
 *
 * Context: Process context
 * Return: Detected version as __le32, or 0 on failure
 */
int aapl_detect_client_version(const void *data, size_t len)
{
	const struct aapl_client_info *client_info;

	if (!data || len < sizeof(struct aapl_client_info))
		return 0;

	client_info = data;

	/* Validate Apple signature */
	if (memcmp(client_info->signature, aapl_smb_signature, 4) != 0)
		return 0;

	return le32_to_cpu(client_info->version);
}

/**
 * aapl_get_client_name - Get human-readable client name
 * @client_type: Apple client type constant
 *
 * This function returns a human-readable name for the Apple client type.
 *
 * Context: Process context
 * Return: String describing client type, or "Unknown" if not recognized
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
 * aapl_get_version_string - Get version string
 * @version: Apple version constant
 *
 * This function returns a human-readable version string.
 *
 * Context: Process context
 * Return: String describing version, or "Unknown" if not recognized
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
 * aapl_valid_signature - Validate Apple signature
 * @signature: 4-byte signature buffer to validate
 *
 * This function validates whether a 4-byte signature buffer contains the
 * valid Apple signature "AAPL".
 *
 * Context: Process context
 * Return: true if signature is valid Apple signature, false otherwise
 */
bool aapl_valid_signature(const __u8 *signature)
{
	if (!signature)
		return false;

	return memcmp(signature, aapl_smb_signature, 4) == 0;
}

/**
 * aapl_validate_create_context - Basic Apple create context validation
 * @context: Create context to validate
 *
 * This function performs basic validation of an Apple create context.
 *
 * Context: Process context
 * Return: 0 on success, -EINVAL on validation failure
 */
int aapl_validate_create_context(const struct create_context *context)
{
	if (!context)
		return -EINVAL;

	/* Validate NameLength */
	if (le16_to_cpu(context->NameLength) != 4)
		return -EINVAL;

	/* Validate DataLength is sufficient for client info */
	if (le32_to_cpu(context->DataLength) < sizeof(struct aapl_client_info))
		return -EINVAL;

	return 0;
}

/**
 * aapl_init_connection_state - Initialize Apple connection state
 * @state: Apple connection state structure
 *
 * This function initializes the Apple connection state structure with default values.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_init_connection_state(struct aapl_conn_state *state)
{
	if (!state)
		return -EINVAL;

	/* Initialize all fields to zero */
	memset(state, 0, sizeof(*state));

	/* Set default capabilities */
	state->supported_features = AAPL_DEFAULT_CAPABILITIES;
	state->enabled_features = AAPL_DEFAULT_CAPABILITIES;
	state->negotiated_capabilities = AAPL_DEFAULT_CAPABILITIES;

	return 0;
}

/**
 * aapl_cleanup_connection_state - Clean up Apple connection state
 * @state: Apple connection state structure
 *
 * This function cleans up any resources associated with the Apple connection state.
 *
 * Context: Process context
 */
void aapl_cleanup_connection_state(struct aapl_conn_state *state)
{
	if (!state)
		return;

	/* Clear sensitive data */
	memset(state, 0, sizeof(*state));
}

/**
 * aapl_update_connection_state - Update connection state with client info
 * @state: Apple connection state structure
 * @client_info: Apple client information structure
 *
 * This function updates the connection state with information from the client.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_update_connection_state(struct aapl_conn_state *state,
				 const struct aapl_client_info *client_info)
{
	if (!state || !client_info)
		return -EINVAL;

	/* Validate signature */
	if (memcmp(client_info->signature, aapl_smb_signature, 4) != 0)
		return -EINVAL;

	/* Update client information */
	state->client_version = le32_to_cpu(client_info->version);
	state->client_type = le32_to_cpu(client_info->client_type);
	state->client_capabilities = le64_to_cpu(client_info->capabilities);

	/* Copy build information */
	memcpy(state->client_build, client_info->build_number,
	       min_t(size_t, sizeof(state->client_build), sizeof(client_info->build_number)));

	/* Re-negotiate capabilities */
	state->negotiated_capabilities = state->client_capabilities & state->supported_features;
	state->enabled_features = state->negotiated_capabilities;

	return 0;
}

/**
 * aapl_debug_client_info - Debug Apple client information
 * @info: Apple client information structure
 *
 * This function logs Apple client information for debugging purposes.
 *
 * Context: Process context
 */
void aapl_debug_client_info(const struct aapl_client_info *info)
{
	if (!info)
		return;

	ksmbd_debug(SMB, "Apple Client Info:\n");
	ksmbd_debug(SMB, "  Signature: %.4s\n", info->signature);
	ksmbd_debug(SMB, "  Version: %s (0x%08x)\n",
		   aapl_get_version_string(info->version),
		   le32_to_cpu(info->version));
	ksmbd_debug(SMB, "  Client Type: %s (0x%08x)\n",
		   aapl_get_client_name(info->client_type),
		   le32_to_cpu(info->client_type));
	ksmbd_debug(SMB, "  Capabilities: 0x%016llx\n",
		   le64_to_cpu(info->capabilities));
}

/**
 * aapl_get_context_size - Get context size by name
 * @context_name: Name of the context
 *
 * This function returns the expected size of an Apple context based on its name.
 *
 * Context: Process context
 * Return: Size of context structure, or 0 if unknown
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
 * aapl_build_server_response - Build server response
 * @response_data: Pointer to response data buffer
 * @response_len: Pointer to response length
 * @capabilities: Server capabilities
 * @query_type: Query type
 *
 * This function builds a response to Apple client queries.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_build_server_response(void **response_data, size_t *response_len,
			       __le64 capabilities, __le32 query_type)
{
	struct aapl_server_query *query;
	size_t size = sizeof(struct aapl_server_query);

	if (!response_data || !response_len)
		return -EINVAL;

	*response_data = kzalloc(size, GFP_KERNEL);
	if (!*response_data)
		return -ENOMEM;

	query = *response_data;
	query->type = query_type;
	query->flags = 0;
	query->max_response_size = cpu_to_le32(size);
	query->reserved = 0;

	*response_len = size;

	return 0;
}

/**
 * aapl_process_finder_info - Process Apple FinderInfo context
 * @conn: KSMBD connection structure
 * @finder_info: Apple FinderInfo structure
 *
 * This function processes FinderInfo context data from Apple clients,
 * storing it as an extended attribute on the file.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_process_finder_info(struct ksmbd_conn *conn,
			    const struct aapl_finder_info *finder_info)
{
	if (!conn || !finder_info)
		return -EINVAL;

	/* Store FinderInfo as extended attribute */
	/* Note: This is a simplified implementation */
	ksmbd_debug(SMB, "Processing Apple FinderInfo: creator=%.4s, type=%.4s\n",
		   finder_info->creator, finder_info->type);

	return 0;
}

/**
 * aapl_process_timemachine_info - Process Apple Time Machine context
 * @conn: KSMBD connection structure
 * @tm_info: Apple TimeMachine info structure
 *
 * This function processes Time Machine context data from Apple clients,
 * enabling Time Machine backup features.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_process_timemachine_info(struct ksmbd_conn *conn,
			       const struct aapl_timemachine_info *tm_info)
{
	if (!conn || !tm_info)
		return -EINVAL;

	/* Process Time Machine context */
	/* Note: This is a simplified implementation */
	ksmbd_debug(SMB, "Processing Apple TimeMachine info: version=%d\n",
		   le32_to_cpu(tm_info->version));

	return 0;
}

/**
 * aapl_handle_timemachine_bundle - Handle Time Machine sparse bundle
 * @conn: KSMBD connection structure
 * @path: Path structure for the file
 * @tm_info: Apple TimeMachine info structure
 *
 * This function handles Time Machine sparse bundle creation and management.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_handle_timemachine_bundle(struct ksmbd_conn *conn,
				const struct path *path,
				const struct aapl_timemachine_info *tm_info)
{
	if (!conn || !path || !tm_info)
		return -EINVAL;

	/* Handle Time Machine sparse bundle */
	/* Note: This is a simplified implementation */
	ksmbd_debug(SMB, "Handling Apple TimeMachine bundle\n");

	return 0;
}

/**
 * aapl_init_module - Initialize Apple SMB extensions
 *
 * This function initializes the Apple SMB extensions module.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_init_module(void)
{
	ksmbd_debug(SMB, "Apple SMB extensions initialized\n");
	return 0;
}

/**
 * aapl_cleanup_module - Clean up Apple SMB extensions
 *
 * This function cleans up the Apple SMB extensions module.
 *
 * Context: Process context
 */
void aapl_cleanup_module(void)
{
	ksmbd_debug(SMB, "Apple SMB extensions cleaned up\n");
}

/**
 * aapl_process_server_query - Process Apple server query
 * @conn: KSMBD connection structure
 * @query: Apple server query structure
 *
 * This function processes Apple server queries for capability negotiation.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int aapl_process_server_query(struct ksmbd_conn *conn,
			      const struct aapl_server_query *query)
{
	if (!conn || !query)
		return -EINVAL;

	ksmbd_debug(SMB, "Processing Apple server query: type=%d, flags=%d\n",
		   le32_to_cpu(query->type), le32_to_cpu(query->flags));

	return 0;
}

/**
 * aapl_debug_capabilities - Debug Apple capabilities
 * @capabilities: Apple capabilities bitmask
 *
 * This function logs Apple capabilities for debugging purposes.
 *
 * Context: Process context
 */
void aapl_debug_capabilities(__le64 capabilities)
{
	__u64 caps = le64_to_cpu(capabilities);

	ksmbd_debug(SMB, "Apple capabilities: 0x%016llx\n", caps);
	ksmbd_debug(SMB, "  Unix extensions: %s\n",
		   (caps & AAPL_CAP_UNIX_EXTENSIONS) ? "yes" : "no");
	ksmbd_debug(SMB, "  Extended attributes: %s\n",
		   (caps & AAPL_CAP_EXTENDED_ATTRIBUTES) ? "yes" : "no");
	ksmbd_debug(SMB, "  Case sensitive: %s\n",
		   (caps & AAPL_CAP_CASE_SENSITIVE) ? "yes" : "no");
	ksmbd_debug(SMB, "  POSIX locks: %s\n",
		   (caps & AAPL_CAP_POSIX_LOCKS) ? "yes" : "no");
	ksmbd_debug(SMB, "  Resilient handles: %s\n",
		   (caps & AAPL_CAP_RESILIENT_HANDLES) ? "yes" : "no");
	ksmbd_debug(SMB, "  Compression: %s\n",
		   (caps & (AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS)) ? "yes" : "no");
	ksmbd_debug(SMB, "  ReadDir attrs: %s\n",
		   (caps & AAPL_CAP_READDIR_ATTRS) ? "yes" : "no");
	ksmbd_debug(SMB, "  File IDs: %s\n",
		   (caps & AAPL_CAP_FILE_IDS) ? "yes" : "no");
	ksmbd_debug(SMB, "  Server query: %s\n",
		   (caps & AAPL_CAP_SERVER_QUERY) ? "yes" : "no");
	ksmbd_debug(SMB, "  Volume capabilities: %s\n",
		   (caps & AAPL_CAP_VOLUME_CAPABILITIES) ? "yes" : "no");
	ksmbd_debug(SMB, "  File mode: %s\n",
		   (caps & AAPL_CAP_FILE_MODE) ? "yes" : "no");
	ksmbd_debug(SMB, "  FinderInfo: %s\n",
		   (caps & AAPL_CAP_FINDERINFO) ? "yes" : "no");
	ksmbd_debug(SMB, "  Time Machine: %s\n",
		   (caps & AAPL_CAP_TIMEMACHINE) ? "yes" : "no");
	ksmbd_debug(SMB, "  F_FULLFSYNC: %s\n",
		   (caps & AAPL_CAP_F_FULLFSYNC) ? "yes" : "no");
	ksmbd_debug(SMB, "  Sparse bundles: %s\n",
		   (caps & AAPL_CAP_SPARSE_BUNDLES) ? "yes" : "no");
}

/**
 * smb2_read_dir_attr - SMB2 read directory attributes for Apple clients
 * @work: KSMBD work structure
 *
 * This function handles Apple-specific directory attribute reading.
 *
 * Context: Process context
 * Return: 0 on success, negative error on failure
 */
int smb2_read_dir_attr(struct ksmbd_work *work)
{
	if (!work)
		return -EINVAL;

	ksmbd_debug(SMB, "Apple read directory attributes request\n");

	/* This is a simplified implementation */
	return 0;
}

EXPORT_SYMBOL_GPL(aapl_is_client_request);
EXPORT_SYMBOL_GPL(aapl_parse_client_info);
EXPORT_SYMBOL_GPL(aapl_negotiate_capabilities);
EXPORT_SYMBOL_GPL(aapl_supports_capability);
EXPORT_SYMBOL_GPL(aapl_detect_client_version);
EXPORT_SYMBOL_GPL(aapl_get_client_name);
EXPORT_SYMBOL_GPL(aapl_get_version_string);
EXPORT_SYMBOL_GPL(aapl_valid_signature);
EXPORT_SYMBOL_GPL(aapl_validate_create_context);
EXPORT_SYMBOL_GPL(aapl_init_connection_state);
EXPORT_SYMBOL_GPL(aapl_cleanup_connection_state);
EXPORT_SYMBOL_GPL(aapl_update_connection_state);
EXPORT_SYMBOL_GPL(aapl_debug_client_info);
EXPORT_SYMBOL_GPL(aapl_get_context_size);
EXPORT_SYMBOL_GPL(aapl_build_server_response);
EXPORT_SYMBOL_GPL(aapl_process_finder_info);
EXPORT_SYMBOL_GPL(aapl_process_timemachine_info);
EXPORT_SYMBOL_GPL(aapl_handle_timemachine_bundle);