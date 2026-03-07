# KSMBD Apple SMB Extensions - API Reference Manual

## Table of Contents

1. [Overview](#overview)
2. [Initialization and Cleanup](#initialization-and-cleanup)
3. [Client Detection and Authentication](#client-detection-and-authentication)
4. [Capability Negotiation](#capability-negotiation)
5. [Context Processing](#context-processing)
6. [File Operations](#file-operations)
7. [Connection Management](#connection-management)
8. [Utility Functions](#utility-functions)
9. [Debug and Logging](#debug-and-logging)
10. [Data Structures](#data-structures)
11. [Constants and Macros](#constants-and-macros)
12. [Error Handling](#error-handling)
13. [Usage Examples](#usage-examples)

## Overview

This API reference manual provides detailed documentation for all functions, data structures, and constants in the KSMBD Apple SMB extensions implementation. The API is designed for kernel module developers integrating Apple SMB support into their SMB server implementations.

### API Organization

The API is organized into several functional areas:

- **Initialization**: Module setup and cleanup functions
- **Authentication**: Client validation and security functions
- **Capability Negotiation**: Feature negotiation between client and server
- **Context Processing**: SMB2 create context handling
- **File Operations**: Apple-specific file operations (FinderInfo, TimeMachine)
- **Connection Management**: State management for Apple connections
- **Utilities**: Helper functions for common operations
- **Debugging**: Logging and diagnostic functions

### Thread Safety

All API functions are thread-safe and may be called from any context unless explicitly noted otherwise. Functions that may sleep are clearly documented.

### Memory Management

Most API functions handle their own memory management. Functions that allocate memory require the caller to free the allocated resources, as documented in individual function descriptions.

## Initialization and Cleanup

### `aapl_init_module`

```c
/**
 * aapl_init_module - Initialize Apple SMB extensions module
 *
 * This function initializes the Apple SMB extensions subsystem,
 * including cryptographic infrastructure, client databases,
 * and global state. Must be called during module initialization.
 *
 * Context: Process context, may sleep
 * Return: 0 on success, negative error on failure
 *         -ENOMEM: Memory allocation failed
 *         -EINVAL: Invalid initialization parameters
 */
static int __init aapl_init_module(void);
```

**Usage:**
```c
static int __init ksmbd_init(void)
{
    int ret;

    ret = aapl_init_module();
    if (ret) {
        pr_err("Failed to initialize Apple SMB extensions: %d\n", ret);
        return ret;
    }

    // Continue with KSMBD initialization
    return 0;
}
```

### `aapl_cleanup_module`

```c
/**
 * aapl_cleanup_module - Clean up Apple SMB extensions module
 *
 * This function safely deallocates all resources used by the
 * Apple SMB extensions subsystem, including cryptographic material,
 * client databases, and connection state. Must be called
 * during module cleanup.
 *
 * Context: Process context, may sleep
 */
static void __exit aapl_cleanup_module(void);
```

**Usage:**
```c
static void __exit ksmbd_exit(void)
{
    aapl_cleanup_module();

    // Continue with KSMBD cleanup
}
```

## Client Detection and Authentication

### `aapl_is_client_request`

```c
/**
 * aapl_is_client_request - Check if request is from Apple client
 * @buffer: Request buffer containing SMB2 header and contexts
 * @len: Length of buffer in bytes
 *
 * This function determines whether a given SMB request contains
 * Apple-specific create contexts and appears to be from a legitimate
 * Apple client. It performs basic structural validation to identify
 * Apple clients.
 *
 * Context: Process context, may be called from softirq
 * Return: true if request appears to be from Apple client, false otherwise
 *         false: Request is too small, lacks Apple context, or malformed
 *         true: Request contains valid AAPL create context
 */
bool aapl_is_client_request(const void *buffer, size_t len);
```

**Usage:**
```c
int smb2_create(struct ksmbd_work *work)
{
    struct smb2_create_req *req = work->request_buf;
    bool is_apple_client;

    // Check if this is an Apple client request
    is_apple_client = aapl_is_client_request(req, work->response_sz);

    if (is_apple_client) {
        // Process Apple-specific contexts
        ret = process_apple_contexts(work);
        if (ret)
            return ret;
    }

    // Continue with standard CREATE processing
    return smb2_create_regular(work);
}
```

### `aapl_validate_client_signature`

```c
/**
 * aapl_validate_client_signature - Validate Apple client signature
 * @conn: KSMBD connection structure
 * @context_data: Apple context data buffer containing client information
 * @data_len: Length of context data in bytes
 *
 * This function performs comprehensive cryptographic validation of Apple
 * client identity. It validates the Apple signature, checks client version
 * against supported ranges, validates client type constants, and performs
 * cryptographic hash verification to prevent spoofing attacks.
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
int aapl_validate_client_signature(struct ksmbd_conn *conn,
                                 const void *context_data,
                                 size_t data_len);
```

**Usage:**
```c
int process_apple_create_context(struct ksmbd_conn *conn,
                              const struct create_context *context)
{
    int ret;
    const struct aapl_client_info *client_info;

    // Validate context structure
    ret = aapl_validate_create_context(context);
    if (ret)
        return ret;

    // Extract client information
    client_info = (const struct aapl_client_info *)
        ((const __u8 *)context + le16_to_cpu(context->DataOffset));

    // Validate cryptographic signature
    ret = aapl_validate_client_signature(conn, client_info,
                                        le32_to_cpu(context->DataLength));
    if (ret) {
        ksmbd_debug(SMB, "Apple client signature validation failed: %d\n", ret);
        return -EACCES;  // Security failure
    }

    // Client is validated, proceed with capability negotiation
    return aapl_negotiate_capabilities(conn, client_info);
}
```

### `aapl_parse_client_info`

```c
/**
 * aapl_parse_client_info - Parse Apple client information
 * @context_data: Raw context data containing Apple client information
 * @data_len: Length of context data in bytes
 * @state: Apple connection state structure to populate with parsed information
 *
 * This function parses and validates Apple client information from the
 * create context data. It performs cryptographic validation and then
 * populates the connection state with client capabilities, version
 * information, and feature support flags.
 *
 * The parsing process includes:
 * - Cryptographic validation of client signature (via aapl_validate_client_signature)
 * - Extraction of client version, type, build number, and capabilities
 * - Capability negotiation to determine supported features
 * - Feature flag initialization (extensions, compression, locks, etc.)
 * - Debug logging of client information
 *
 * Context: Process context, may sleep during crypto operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or insufficient context data
 *         -EACCES: Cryptographic validation failed (security violation)
 *         -ENOMEM: Memory allocation failure during validation
 */
int aapl_parse_client_info(const void *context_data, size_t data_len,
                          struct aapl_conn_state *state);
```

**Usage:**
```c
int handle_apple_client(struct ksmbd_conn *conn,
                      const void *context_data, size_t data_len)
{
    int ret;

    // Allocate Apple connection state if not already present
    if (!conn->aapl_state) {
        conn->aapl_state = kzalloc(sizeof(struct aapl_conn_state),
                                  GFP_KERNEL);
        if (!conn->aapl_state)
            return -ENOMEM;
    }

    // Parse and validate client information
    ret = aapl_parse_client_info(context_data, data_len, conn->aapl_state);
    if (ret) {
        kfree(conn->aapl_state);
        conn->aapl_state = NULL;
        return ret;
    }

    // Client successfully validated and parsed
    conn->is_aapl = true;
    ksmbd_debug(SMB, "Apple client %s connected\n",
               aapl_get_client_name(conn->aapl_state->client_type));

    return 0;
}
```

## Capability Negotiation

### `aapl_negotiate_capabilities`

```c
/**
 * aapl_negotiate_capabilities - Negotiate capabilities with Apple client
 * @conn: KSMBD connection structure for the current SMB session
 * @client_info: Client information structure containing requested capabilities
 *
 * This function performs capability negotiation between the KSMBD server
 * and Apple client. It calculates the intersection of client-requested
 * capabilities and server-supported capabilities, then updates the connection
 * state with the negotiated feature set.
 *
 * The negotiation process:
 * 1. Validates input parameters
 * 2. Allocates and initializes Apple connection state if not already present
 * 3. Calculates supported capabilities as intersection of client & server caps
 * 4. Updates connection-level capability flags and version information
 * 5. Enables Apple extensions for the connection
 *
 * Context: Process context, may sleep during memory allocation
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid connection or client_info parameters
 *         -ENOMEM: Failed to allocate Apple connection state
 */
int aapl_negotiate_capabilities(struct ksmbd_conn *conn,
                               const struct aapl_client_info *client_info);
```

**Usage:**
```c
int setup_apple_connection(struct ksmbd_conn *conn,
                         const struct aapl_client_info *client_info)
{
    int ret;

    // Negotiate capabilities with client
    ret = aapl_negotiate_capabilities(conn, client_info);
    if (ret) {
        ksmbd_debug(SMB, "Apple capability negotiation failed: %d\n", ret);
        return ret;
    }

    // Enable Apple extensions for this connection
    conn->aapl_extensions_enabled = true;

    // Log negotiation results
    aapl_debug_negotiation(conn->aapl_state);

    ksmbd_debug(SMB, "Apple connection established with %s capabilities\n",
               aapl_get_version_string(conn->aapl_state->client_version));

    return 0;
}
```

### `aapl_supports_capability`

```c
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
 * Context: Any context, does not sleep
 * Return: true if capability is supported, false otherwise
 *         false: Capability not negotiated or invalid state parameter
 *         true: Capability is available for use
 */
bool aapl_supports_capability(struct aapl_conn_state *state, __le64 capability);
```

**Usage:**
```c
int handle_apple_readirattr(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;

    // Check if Apple extensions are enabled for this connection
    if (!conn->is_aapl || !conn->aapl_extensions_enabled) {
        ksmbd_debug(SMB, "Apple extensions not enabled for this connection\n");
        work->response->hdr.Status = STATUS_NOT_SUPPORTED;
        return -ENOTSUPP;
    }

    // Check if readdirattr capability is negotiated
    if (!aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_READDIR_ATTRS))) {
        ksmbd_debug(SMB, "ReadDir attributes capability not negotiated\n");
        work->response->hdr.Status = STATUS_NOT_SUPPORTED;
        return -ENOTSUPP;
    }

    // Capability is supported, proceed with readdirattr
    return smb2_read_dir_attr(work);
}
```

### `aapl_enable_capability`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid state parameter
 *         -ENOTSUPP: Capability not negotiated/supported
 */
int aapl_enable_capability(struct aapl_conn_state *state, __le64 capability);
```

**Usage:**
```c
int handle_apple_server_query(struct ksmbd_conn *conn,
                           const struct aapl_server_query *query)
{
    int ret;

    // Process the query
    ret = aapl_process_server_query(conn, query);
    if (ret)
        return ret;

    // Enable specific capabilities based on query type
    switch (le32_to_cpu(query->type)) {
    case 1:  // Extensions query
        ret = aapl_enable_capability(conn->aapl_state,
                                    cpu_to_le64(AAPL_CAP_EXTENDED_ATTRIBUTES));
        break;
    case 2:  // Compression query
        ret = aapl_enable_capability(conn->aapl_state,
                                    cpu_to_le64(AAPL_COMPRESSION_ZLIB));
        break;
    }

    return ret;
}
```

## Context Processing

### `aapl_validate_create_context`

```c
/**
 * aapl_validate_create_context - Validate Apple create context structure
 * @context: Create context to validate
 *
 * This function validates the basic structure of Apple SMB2 create
 * contexts. It checks field sizes, offsets, and ensures the context
 * is properly formed before attempting to parse Apple-specific data.
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid context structure or malformed fields
 */
int aapl_validate_create_context(const struct create_context *context);
```

**Usage:**
```c
int process_apple_context(struct ksmbd_work *work)
{
    struct create_context *context;
    int ret;

    // Find Apple context in the CREATE request
    context = smb2_find_context_vals(work->request_buf, SMB2_CREATE_AAPL, 4);
    if (IS_ERR(context))
        return PTR_ERR(context);

    if (!context) {
        // No Apple context, this is a regular SMB client
        return 0;
    }

    // Validate context structure before parsing
    ret = aapl_validate_create_context(context);
    if (ret) {
        ksmbd_debug(SMB, "Invalid AAPL create context: %d\n", ret);
        return ret;
    }

    // Process the validated Apple context
    return handle_apple_context(work, context);
}
```

### `aapl_process_server_query`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or unsupported query type
 */
int aapl_process_server_query(struct ksmbd_conn *conn,
                            const struct aapl_server_query *query);
```

**Usage:**
```c
int handle_apple_queries(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct create_context *context;

    // Process ServerQuery context
    context = smb2_find_context_vals(work->request_buf,
                                   SMB2_CREATE_SERVER_QUERY, 4);
    if (!IS_ERR(context) && context) {
        const struct aapl_server_query *query =
            (const struct aapl_server_query *)
            ((const __u8 *)context + le16_to_cpu(context->DataOffset));

        if (le32_to_cpu(context->DataLength) >= sizeof(struct aapl_server_query)) {
            aapl_process_server_query(conn, query);
        }
    }

    // Process other contexts...
    return 0;
}
```

### `aapl_process_volume_caps`

```c
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
 * Context: Process context, may sleep during session/share lookup
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or no session/share found
 */
int aapl_process_volume_caps(struct ksmbd_conn *conn,
                            const struct aapl_volume_capabilities *caps);
```

**Usage:**
```c
int handle_volume_capabilities(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct create_context *context;

    // Find VolumeCapabilities context
    context = smb2_find_context_vals(work->request_buf,
                                   SMB2_CREATE_VOLUME_CAPABILITIES, 4);
    if (!IS_ERR(context) && context) {
        const struct aapl_volume_capabilities *caps =
            (const struct aapl_volume_capabilities *)
            ((const __u8 *)context + le16_to_cpu(context->DataOffset));

        if (le32_to_cpu(context->DataLength) >= sizeof(struct aapl_volume_capabilities)) {
            aapl_process_volume_caps(conn, caps);
        }
    }

    return 0;
}
```

### `aapl_process_finder_info`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 */
int aapl_process_finder_info(struct ksmbd_conn *conn,
                             const struct aapl_finder_info *finder_info);
```

**Usage:**
```c
int handle_finder_info_context(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct create_context *context;

    // Find FinderInfo context
    context = smb2_find_context_vals(work->request_buf,
                                   SMB2_CREATE_FINDERINFO, 4);
    if (!IS_ERR(context) && context) {
        const struct aapl_finder_info *finder_info =
            (const struct aapl_finder_info *)
            ((const __u8 *)context + le16_to_cpu(context->DataOffset));

        if (le32_to_cpu(context->DataLength) >= sizeof(struct aapl_finder_info)) {
            aapl_process_finder_info(conn, finder_info);
        }
    }

    return 0;
}
```

### `aapl_process_timemachine_info`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or unsupported Time Machine version
 */
int aapl_process_timemachine_info(struct ksmbd_conn *conn,
                                const struct aapl_timemachine_info *tm_info);
```

**Usage:**
```c
int handle_timemachine_context(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct create_context *context;

    // Find TimeMachine context
    context = smb2_find_context_vals(work->request_buf,
                                   SMB2_CREATE_TIMEMACHINE, 4);
    if (!IS_ERR(context) && context) {
        const struct aapl_timemachine_info *tm_info =
            (const struct aapl_timemachine_info *)
            ((const __u8 *)context + le16_to_cpu(context->DataOffset));

        if (le32_to_cpu(context->DataLength) >= sizeof(struct aapl_timemachine_info)) {
            aapl_process_timemachine_info(conn, tm_info);
        }
    }

    return 0;
}
```

## File Operations

### `aapl_set_finder_info`

```c
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
 * Context: Process context, may sleep during VFS operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or unsupported file mode
 *         -ENOTSUPP: FinderInfo capability not negotiated
 *         -EIO: VFS operation failed
 */
int aapl_set_finder_info(struct ksmbd_conn *conn, const struct path *path,
                        const struct aapl_finder_info *finder_info);
```

**Usage:**
```c
int handle_set_finder_info(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct smb2_set_info_req *req = work->request_buf;
    struct path path;
    struct aapl_finder_info finder_info;
    int ret;

    // Check if FinderInfo capability is negotiated
    if (!aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_FINDERINFO))) {
        return -ENOTSUPP;
    }

    // Get file path
    ret = ksmbd_get_path(work, &path);
    if (ret)
        return ret;

    // Parse FinderInfo from request
    if (le32_to_cpu(req->InputBufferLength) < sizeof(struct aapl_finder_info)) {
        path_put(&path);
        return -EINVAL;
    }

    memcpy(&finder_info, req->Buffer, sizeof(finder_info));

    // Set FinderInfo on the file
    ret = aapl_set_finder_info(conn, &path, &finder_info);
    path_put(&path);

    return ret;
}
```

### `aapl_get_finder_info`

```c
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
 * Context: Process context, may sleep during VFS operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 *         -ENOTSUPP: FinderInfo capability not negotiated
 *         -EIO: VFS operation failed (except ENODATA which is handled)
 */
int aapl_get_finder_info(struct ksmbd_conn *conn, const struct path *path,
                        struct aapl_finder_info *finder_info);
```

**Usage:**
```c
int handle_get_finder_info(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct smb2_query_info_req *req = work->request_buf;
    struct smb2_query_info_rsp *rsp = work->response_buf;
    struct path path;
    struct aapl_finder_info finder_info;
    int ret;

    // Check if FinderInfo capability is negotiated
    if (!aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_FINDERINFO))) {
        rsp->hdr.Status = STATUS_NOT_SUPPORTED;
        return -ENOTSUPP;
    }

    // Get file path
    ret = ksmbd_get_path(work, &path);
    if (ret)
        return ret;

    // Get FinderInfo from the file
    ret = aapl_get_finder_info(conn, &path, &finder_info);
    path_put(&path);

    if (ret) {
        rsp->hdr.Status = STATUS_INVALID_PARAMETER;
        return ret;
    }

    // Copy FinderInfo to response
    memcpy(rsp->Buffer, &finder_info, sizeof(finder_info));
    rsp->OutputBufferLength = cpu_to_le32(sizeof(finder_info));

    return 0;
}
```

### `aapl_fullfsync`

```c
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
 * Context: Process context, may sleep during VFS operations
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 *         -ENOTSUPP: F_FULLFSYNC capability not negotiated
 *         -EIO: VFS operation failed
 */
int aapl_fullfsync(struct ksmbd_conn *conn, const struct path *path);
```

**Usage:**
```c
int handle_ioctl_fullfsync(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct smb2_ioctl_req *req = work->request_buf;
    struct path path;
    int ret;

    // Check if F_FULLFSYNC capability is negotiated
    if (!aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_F_FULLFSYNC))) {
        work->response->hdr.Status = STATUS_NOT_SUPPORTED;
        return -ENOTSUPP;
    }

    // Get file path
    ret = ksmbd_get_path(work, &path);
    if (ret)
        return ret;

    // Perform F_FULLFSYNC operation
    ret = aapl_fullfsync(conn, &path);
    path_put(&path);

    if (ret) {
        work->response->hdr.Status = STATUS_IO_DEVICE_ERROR;
        return ret;
    }

    return 0;
}
```

### `aapl_handle_timemachine_bundle`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or not a Time Machine bundle
 *         -ENOTSUPP: Time Machine capability not negotiated
 */
int aapl_handle_timemachine_bundle(struct ksmbd_conn *conn,
                                 const struct path *path,
                                 const struct aapl_timemachine_info *tm_info);
```

**Usage:**
```c
int handle_create_timemachine_bundle(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct smb2_create_req *req = work->request_buf;
    struct path path;
    struct aapl_timemachine_info tm_info;
    int ret;

    // Check if TimeMachine capability is negotiated
    if (!aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_TIMEMACHINE))) {
        work->response->hdr.Status = STATUS_NOT_SUPPORTED;
        return -ENOTSUPP;
    }

    // Get created directory path
    ret = ksmbd_get_created_path(work, &path);
    if (ret)
        return ret;

    // Check if this is a Time Machine bundle by name
    if (strstr(req->Buffer, ".TimeMachine") ||
        strstr(req->Buffer, ".sparsebundle")) {

        // Get TimeMachine context if present
        struct create_context *context =
            smb2_find_context_vals(req, SMB2_CREATE_TIMEMACHINE, 4);

        if (!IS_ERR(context) && context &&
            le32_to_cpu(context->DataLength) >= sizeof(struct aapl_timemachine_info)) {

            memcpy(&tm_info,
                   (const __u8 *)context + le16_to_cpu(context->DataOffset),
                   sizeof(tm_info));

            // Handle Time Machine bundle
            ret = aapl_handle_timemachine_bundle(conn, &path, &tm_info);
            if (ret) {
                path_put(&path);
                return ret;
            }
        }
    }

    path_put(&path);
    return 0;
}
```

### `aapl_validate_timemachine_sequence`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters or sequence number out of bounds
 */
int aapl_validate_timemachine_sequence(struct ksmbd_conn *conn,
                                     const struct aapl_timemachine_info *tm_info);
```

**Usage:**
```c
int validate_timemachine_request(struct ksmbd_conn *conn,
                             const struct aapl_timemachine_info *tm_info)
{
    int ret;

    // Validate sequence for anti-replay protection
    ret = aapl_validate_timemachine_sequence(conn, tm_info);
    if (ret) {
        ksmbd_debug(SMB, "TimeMachine sequence validation failed: %d\n", ret);
        return ret;
    }

    // Sequence is valid, proceed with request
    return process_timemachine_operation(conn, tm_info);
}
```

## Connection Management

### `aapl_init_connection_state`

```c
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
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid state parameter
 */
int aapl_init_connection_state(struct aapl_conn_state *state);
```

**Usage:**
```c
int create_apple_connection(struct ksmbd_conn *conn)
{
    // Allocate Apple connection state
    conn->aapl_state = kzalloc(sizeof(struct aapl_conn_state), GFP_KERNEL);
    if (!conn->aapl_state) {
        ksmbd_debug(SMB, "Failed to allocate Apple connection state\n");
        return -ENOMEM;
    }

    // Initialize the state
    int ret = aapl_init_connection_state(conn->aapl_state);
    if (ret) {
        kfree(conn->aapl_state);
        conn->aapl_state = NULL;
        return ret;
    }

    // Mark this as an Apple connection
    conn->is_aapl = true;

    ksmbd_debug(SMB, "Apple connection state initialized\n");
    return 0;
}
```

### `aapl_cleanup_connection_state`

```c
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
 * Context: Process context, does not sleep
 */
void aapl_cleanup_connection_state(struct aapl_conn_state *state);
```

**Usage:**
```c
void cleanup_apple_connection(struct ksmbd_conn *conn)
{
    if (conn->aapl_state) {
        // Securely clean up Apple connection state
        aapl_cleanup_connection_state(conn->aapl_state);

        // Free the state structure
        kfree(conn->aapl_state);
        conn->aapl_state = NULL;
    }

    // Reset Apple flags
    conn->is_aapl = false;
    conn->aapl_extensions_enabled = false;

    ksmbd_debug(SMB, "Apple connection cleaned up\n");
}
```

### `aapl_update_connection_state`

```c
/**
 * aapl_update_connection_state - Update connection state with client info
 * @state: Apple connection state to update
 * @client_info: Client information to incorporate
 *
 * This function updates an existing Apple connection state with new client
 * information. It is used during capability renegotiation or when updating
 * connection parameters after initial negotiation.
 *
 * Context: Process context, does not sleep
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 */
int aapl_update_connection_state(struct aapl_conn_state *state,
                                const struct aapl_client_info *client_info);
```

**Usage:**
```c
int renegotiate_apple_capabilities(struct ksmbd_conn *conn,
                                 const struct aapl_client_info *new_info)
{
    int ret;

    if (!conn->aapl_state) {
        ksmbd_debug(SMB, "No Apple connection state for renegotiation\n");
        return -EINVAL;
    }

    // Update connection state with new client information
    ret = aapl_update_connection_state(conn->aapl_state, new_info);
    if (ret) {
        ksmbd_debug(SMB, "Failed to update Apple connection state: %d\n", ret);
        return ret;
    }

    // Update connection-level flags
    conn->aapl_capabilities = conn->aapl_state->negotiated_capabilities;

    ksmbd_debug(SMB, "Apple connection state updated\n");
    return 0;
}
```

## Utility Functions

### `aapl_get_client_name`

```c
/**
 * aapl_get_client_name - Get descriptive name for Apple client type
 * @client_type: Apple client type code (AAPL_CLIENT_* constants)
 *
 * This function converts Apple client type constants into human-readable
 * strings for logging and debugging purposes. It provides descriptive
 * names for different Apple operating systems and device types.
 *
 * Context: Any context, does not sleep
 * Return: Pointer to static client name string (never NULL)
 *         "Unknown" is returned for unrecognized client types
 */
const char *aapl_get_client_name(__le32 client_type);
```

**Usage:**
```c
void log_apple_client_info(struct ksmbd_conn *conn)
{
    if (conn->aapl_state) {
        ksmbd_debug(SMB, "Apple client: %s version %s\n",
                    aapl_get_client_name(conn->aapl_state->client_type),
                    aapl_get_version_string(conn->aapl_state->client_version));
    }
}
```

### `aapl_get_version_string`

```c
/**
 * aapl_get_version_string - Get version string for Apple client
 * @version: Apple client version constant
 *
 * This function converts Apple SMB extension version constants into
 * human-readable version strings for logging and debugging purposes.
 * It provides version information to help identify the capabilities
 * and features available in different Apple SMB protocol versions.
 *
 * Context: Any context, does not sleep
 * Return: Pointer to static version string (never NULL)
 *         "Unknown" is returned for unrecognized versions
 */
const char *aapl_get_version_string(__le32 version);
```

**Usage:**
```c
void log_apple_version(struct aapl_client_info *info)
{
    ksmbd_debug(SMB, "Apple SMB extension version: %s\n",
                aapl_get_version_string(info->version));
}
```

### `aapl_valid_signature`

```c
/**
 * aapl_valid_signature - Validate Apple signature
 * @signature: 4-byte signature buffer to validate
 *
 * This function validates whether a 4-byte signature buffer contains the
 * valid Apple signature "AAPL". This is used throughout the Apple SMB
 * extension code to verify that various structures and contexts are
 * legitimately from Apple clients and not spoofed or malformed.
 *
 * Context: Any context, does not sleep
 * Return: true if signature is valid Apple signature, false otherwise
 *         false: Signature is NULL, not "AAPL", or malformed
 *         true: Signature matches "AAPL" exactly
 */
bool aapl_valid_signature(const __u8 *signature);
```

**Usage:**
```c
int validate_apple_context(const struct create_context *context)
{
    const __u8 *signature;

    if (le16_to_cpu(context->NameLength) != 4) {
        ksmbd_debug(SMB, "Invalid Apple context name length: %u\n",
                    le16_to_cpu(context->NameLength));
        return -EINVAL;
    }

    signature = context->Buffer;

    if (!aapl_valid_signature(signature)) {
        ksmbd_debug(SMB, "Invalid Apple signature: %.4s\n", signature);
        return -EINVAL;
    }

    return 0;  // Valid Apple signature
}
```

### `aapl_get_context_size`

```c
/**
 * aapl_get_context_size - Get expected size for Apple context
 * @context_name: Name of the Apple context (string)
 *
 * This function returns the expected data size for various Apple SMB
 * create contexts. It's used to validate that context data buffers
 * are large enough to contain the expected structure data, preventing
 * buffer overflows and ensuring proper context parsing.
 *
 * Context: Any context, does not sleep
 * Return: Expected size of context data in bytes, or 0 if unknown
 *         0: Context name is NULL or not recognized
 *         >0: Expected size in bytes for the context
 */
size_t aapl_get_context_size(const char *context_name);
```

**Usage:**
```c
int validate_context_data(const struct create_context *context)
{
    const char *context_name;
    size_t expected_size;

    if (le16_to_cpu(context->DataLength) == 0)
        return 0;  // No data is valid

    context_name = (const char *)context->Buffer;
    expected_size = aapl_get_context_size(context_name);

    if (expected_size == 0) {
        ksmbd_debug(SMB, "Unknown Apple context: %s\n", context_name);
        return -EINVAL;  // Unknown context type
    }

    if (le32_to_cpu(context->DataLength) < expected_size) {
        ksmbd_debug(SMB, "Apple context too small: %s, got %u, need %zu\n",
                    context_name, le32_to_cpu(context->DataLength), expected_size);
        return -EINVAL;
    }

    return 0;  // Valid context data size
}
```

### `aapl_build_server_response`

```c
/**
 * aapl_build_server_response - Build Apple server response
 * @response_data: Pointer to response data buffer
 * @response_len: Pointer to response length
 * @capabilities: Server capabilities to advertise
 * @query_type: Type of query being responded to
 *
 * This function builds response data for Apple server queries. It allocates
 * and populates response structures based on the query type and server
 * capabilities. The caller is responsible for freeing the allocated
 * response data.
 *
 * Context: Process context, may sleep during memory allocation
 * Return: 0 on success, negative error on failure
 *         -EINVAL: Invalid parameters
 *         -ENOMEM: Memory allocation failed
 */
int aapl_build_server_response(void **response_data, size_t *response_len,
                               __le64 capabilities, __le32 query_type);
```

**Usage:**
```c
int handle_server_query(struct ksmbd_work *work,
                      const struct aapl_server_query *query)
{
    struct ksmbd_conn *conn = work->conn;
    void *response_data = NULL;
    size_t response_len = 0;
    int ret;

    // Build server response
    ret = aapl_build_server_response(&response_data, &response_len,
                                     conn->aapl_capabilities, query->type);
    if (ret) {
        ksmbd_debug(SMB, "Failed to build server response: %d\n", ret);
        return ret;
    }

    // Copy response to work buffer
    if (response_len > work->response_sz) {
        kfree(response_data);
        return -EMSGSIZE;
    }

    memcpy(work->response_buf, response_data, response_len);
    work->response_sz = response_len;

    kfree(response_data);
    return 0;
}
```

## Debug and Logging

### `aapl_debug_client_info`

```c
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
 * Context: Any context, may sleep during logging operations
 */
void aapl_debug_client_info(const struct aapl_client_info *info);
```

**Usage:**
```c
void log_apple_connection(struct ksmbd_conn *conn)
{
    if (conn->aapl_state) {
        ksmbd_debug(SMB, "=== Apple Client Connection ===\n");
        aapl_debug_client_info(&conn->aapl_state->client_info);
        aapl_debug_capabilities(conn->aapl_capabilities);
    }
}
```

### `aapl_debug_capabilities`

```c
/**
 * aapl_debug_capabilities - Debug logging for Apple capabilities
 * @capabilities: 64-bit Apple capabilities bitmask to log
 *
 * This function provides detailed debug logging of Apple capability bitmasks.
 * It logs both the full hexadecimal value and individual capability flags
 * with descriptive names. This is essential for understanding which Apple
 * SMB extensions are enabled and troubleshooting capability negotiation.
 *
 * Context: Any context, may sleep during logging operations
 */
void aapl_debug_capabilities(__le64 capabilities);
```

**Usage:**
```c
void log_negotiated_capabilities(struct ksmbd_conn *conn)
{
    if (conn->aapl_state) {
        ksmbd_debug(SMB, "Negotiated Apple capabilities:\n");
        aapl_debug_capabilities(conn->aapl_state->negotiated_capabilities);
    }
}
```

### `aapl_debug_negotiation`

```c
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
 * Context: Any context, may sleep during logging operations
 */
void aapl_debug_negotiation(struct aapl_conn_state *state);
```

**Usage:**
```c
void log_apple_negotiation_complete(struct ksmbd_conn *conn)
{
    if (conn->aapl_state) {
        ksmbd_debug(SMB, "=== Apple Capability Negotiation Complete ===\n");
        aapl_debug_negotiation(conn->aapl_state);
    }
}
```

## Data Structures

### `struct aapl_conn_state`

```c
/**
 * struct aapl_conn_state - Apple connection state tracking
 * @client_version: Apple SMB extension version from client
 * @client_type: Type of Apple client (macOS, iOS, etc.)
 * @client_capabilities: Full 64-bit client capabilities bitmask
 * @client_build: Client build number for version tracking
 * @negotiated_capabilities: Intersection of client & server capabilities
 * @supported_features: Server-supported capability mask
 * @enabled_features: Currently enabled feature flags
 * @extensions_enabled: True if Apple extensions are enabled
 * @compression_supported: True if compression is negotiated
 * @resilient_handles_enabled: True if resilient handles are enabled
 * @posix_locks_enabled: True if POSIX locks are enabled
 * @server_queried: True if server query has been processed
 * @last_query_type: Last server query type processed
 * @last_query_time: Timestamp of last query/sequence validation
 * @reserved: Reserved for future expansion
 *
 * This structure tracks the complete state of an Apple SMB connection.
 * It includes client information, negotiated capabilities, feature
 * enablement status, and timing information for security validation.
 * The structure is allocated when an Apple client connects and cleaned
 * up when the connection terminates.
 */
struct aapl_conn_state {
    /* Client Information */
    __le32          client_version;
    __le32          client_type;
    __le64          client_capabilities;
    __u8            client_build[16];

    /* Negotiated Capabilities */
    __le64          negotiated_capabilities;
    __le64          supported_features;
    __le64          enabled_features;

    /* State Flags */
    bool            extensions_enabled;
    bool            compression_supported;
    bool            resilient_handles_enabled;
    bool            posix_locks_enabled;

    /* Query State */
    bool            server_queried;
    __le32          last_query_type;
    __le64          last_query_time;

    /* Reserved for future expansion */
    __u8            reserved[64];
};
```

### `struct aapl_client_info`

```c
/**
 * struct aapl_client_info - Apple Client Information
 * @signature: Apple signature "AAPL" (4 bytes)
 * @version: Apple SMB extension version
 * @client_type: Type of Apple client (macOS, iOS, etc.)
 * @build_number: Build number of the client
 * @capabilities: Client capabilities bitmask
 * @reserved: Reserved for future use
 *
 * This structure contains identifying information about Apple clients
 * connecting to the SMB server. It is used for client validation,
 * capability negotiation, and connection management.
 */
struct aapl_client_info {
    __u8            signature[4];    /* "AAPL" */
    __le32          version;
    __le32          client_type;
    __le32          build_number;
    __le64          capabilities;
    __u8            reserved[16];
};
```

### `struct aapl_server_query`

```c
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
 * specific features.
 */
struct aapl_server_query {
    __le32          type;
    __le32          flags;
    __le32          max_response_size;
    __le32          reserved;
    __u8            query_data[0];
};
```

## Constants and Macros

### Apple SMB Context Names

```c
#define AAPL_CONTEXT_NAME             "AAPL"
#define AAPL_SERVER_QUERY_CONTEXT     "ServerQuery"
#define AAPL_VOLUME_CAPABILITIES_CONTEXT "VolumeCapabilities"
#define AAPL_FILE_MODE_CONTEXT        "FileMode"
#define AAPL_DIR_HARDLINKS_CONTEXT   "DirHardLinks"
#define AAPL_FINDERINFO_CONTEXT      "FinderInfo"
#define AAPL_TIMEMACHINE_CONTEXT     "TimeMachine"
```

### Protocol Versions

```c
#define AAPL_VERSION_MIN             0x00010000
#define AAPL_VERSION_1_0             0x00010000
#define AAPL_VERSION_1_1             0x00010001
#define AAPL_VERSION_2_0             0x00020000
#define AAPL_VERSION_CURRENT         AAPL_VERSION_2_0
```

### Client Types

```c
#define AAPL_CLIENT_MACOS            0x01
#define AAPL_CLIENT_IOS              0x02
#define AAPL_CLIENT_IPADOS           0x03
#define AAPL_CLIENT_TVOS             0x04
#define AAPL_CLIENT_WATCHOS          0x05
```

### Capability Flags

```c
#define AAPL_CAP_UNIX_EXTENSIONS     0x00000001
#define AAPL_CAP_EXTENDED_ATTRIBUTES 0x00000002
#define AAPL_CAP_CASE_SENSITIVE      0x00000004
#define AAPL_CAP_POSIX_LOCKS        0x00000008
#define AAPL_CAP_RESILIENT_HANDLES  0x00000010
#define AAPL_COMPRESSION_ZLIB        0x00000020
#define AAPL_COMPRESSION_LZFS        0x00000040
#define AAPL_CAP_READDIR_ATTRS      0x00000080
#define AAPL_CAP_FILE_IDS            0x00000100
#define AAPL_CAP_DEDUPlication       0x00000200
#define AAPL_CAP_SERVER_QUERY        0x00000400
#define AAPL_CAP_VOLUME_CAPABILITIES 0x00000800
#define AAPL_CAP_FILE_MODE           0x00001000
#define AAPL_CAP_DIR_HARDLINKS       0x00002000
#define AAPL_CAP_FINDERINFO          0x00004000
#define AAPL_CAP_TIMEMACHINE          0x00008000
#define AAPL_CAP_F_FULLFSYNC         0x00010000
#define AAPL_CAP_SPARSE_BUNDLES      0x00020000
```

### Default Capabilities

```c
#define AAPL_DEFAULT_CAPABILITIES (\
    AAPL_CAP_UNIX_EXTENSIONS | \
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
```

## Error Handling

### Common Return Codes

| Return Code | Description | Typical Cause |
|------------|-------------|---------------|
| `0` | Success | Operation completed successfully |
| `-EINVAL` | Invalid argument | Invalid parameters, malformed data |
| `-EACCES` | Permission denied | Authentication/authorization failure |
| `-ENOMEM` | Out of memory | Memory allocation failed |
| `-ENOTSUPP` | Operation not supported | Feature not negotiated |
| `-EIO` | I/O error | Filesystem or device error |
| `-EMSGSIZE` | Message too large | Response buffer too small |
| `-EBADF` | Bad file descriptor | Invalid file handle |

### Error Handling Patterns

#### Capability Check Pattern
```c
// Always check capabilities before Apple-specific operations
if (!aapl_supports_capability(conn->aapl_state,
                             cpu_to_le64(AAPL_CAP_FINDERINFO))) {
    ksmbd_debug(SMB, "FinderInfo not supported\n");
    return -ENOTSUPP;
}
```

#### Resource Cleanup Pattern
```c
// Ensure resources are cleaned up on error paths
int handle_apple_operation(struct ksmbd_conn *conn)
{
    struct resource *res = allocate_resource();
    if (!res)
        return -ENOMEM;

    int ret = perform_operation(res);
    if (ret) {
        free_resource(res);
        return ret;
    }

    // Success case cleanup
    free_resource(res);
    return 0;
}
```

#### Validation Pattern
```c
// Always validate input parameters
int validate_and_process(const void *data, size_t len)
{
    if (!data || len < sizeof(struct expected_structure)) {
        ksmbd_debug(SMB, "Invalid parameters: data=%p, len=%zu\n", data, len);
        return -EINVAL;
    }

    return process_valid_data(data);
}
```

## Usage Examples

### Basic Apple Client Setup

```c
#include "smb2_aapl.h"

int handle_apple_client_connection(struct ksmbd_conn *conn,
                                 const void *context_data, size_t data_len)
{
    int ret;

    // Step 1: Allocate and initialize connection state
    conn->aapl_state = kzalloc(sizeof(struct aapl_conn_state), GFP_KERNEL);
    if (!conn->aapl_state)
        return -ENOMEM;

    ret = aapl_init_connection_state(conn->aapl_state);
    if (ret) {
        kfree(conn->aapl_state);
        return ret;
    }

    // Step 2: Parse and validate client information
    ret = aapl_parse_client_info(context_data, data_len, conn->aapl_state);
    if (ret) {
        aapl_cleanup_connection_state(conn->aapl_state);
        kfree(conn->aapl_state);
        return ret;
    }

    // Step 3: Enable Apple extensions
    conn->is_aapl = true;
    conn->aapl_extensions_enabled = true;

    // Step 4: Log connection information
    ksmbd_debug(SMB, "Apple client %s connected with %s capabilities\n",
                    aapl_get_client_name(conn->aapl_state->client_type),
                    aapl_get_version_string(conn->aapl_state->client_version));

    return 0;
}
```

### Time Machine Share Configuration

```c
int setup_timemachine_share(struct ksmbd_share_config *share)
{
    // Enable Time Machine capabilities for the share
    share->aapl_extensions = true;
    share->aapl_time_machine = true;
    share->aapl_sparse_bundles = true;

    // Configure Time Machine specific settings
    share->fruit_time_machine = true;
    share->fruit_encoding = FRUIT_ENCODING_PRIVATE;
    share->fruit_metadata = FRUIT_METADATA_STREAM;

    // Set appropriate permissions
    share->create_mask = 0660;
    share->directory_mask = 0770;

    ksmbd_debug(SMB, "Time Machine share configured\n");
    return 0;
}
```

### FinderInfo File Operations

```c
int handle_finder_info_request(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct path path;
    struct aapl_finder_info finder_info;
    int ret;

    // Step 1: Check if FinderInfo capability is negotiated
    if (!aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_FINDERINFO))) {
        work->response->hdr.Status = STATUS_NOT_SUPPORTED;
        return -ENOTSUPP;
    }

    // Step 2: Get file path
    ret = ksmbd_get_path(work, &path);
    if (ret)
        return ret;

    // Step 3: Get FinderInfo from file
    ret = aapl_get_finder_info(conn, &path, &finder_info);
    path_put(&path);

    if (ret) {
        work->response->hdr.Status = STATUS_INVALID_PARAMETER;
        return ret;
    }

    // Step 4: Return FinderInfo to client
    struct smb2_query_info_rsp *rsp = work->response_buf;
    memcpy(rsp->Buffer, &finder_info, sizeof(finder_info));
    rsp->OutputBufferLength = cpu_to_le32(sizeof(finder_info));

    return 0;
}
```

### Performance Optimization Example

```c
int optimize_apple_readdir(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    struct ksmbd_dir_info *d_info = work->d_info;

    // Step 1: Check if Apple client with readdirattr capability
    if (!conn->is_aapl ||
        !aapl_supports_capability(conn->aapl_state,
                               cpu_to_le64(AAPL_CAP_READDIR_ATTRS))) {
        // Use standard directory read
        return smb2_read_dir_regular(work);
    }

    // Step 2: Enable Apple-specific optimizations
    d_info->flags |= KSMBD_DIR_INFO_REQ_XATTR_BATCH;

    // Step 3: Configure for Apple Finder optimization
    d_info->out_buf_offset = 0;
    d_info->out_buf_len = min(d_info->out_buf_len, 8192);

    // Step 4: Perform optimized directory read
    int ret = smb2_read_dir_attr_optimized(work);

    // Step 5: Configure compound requests if supported
    if (aapl_supports_capability(conn->aapl_state,
                               cpu_to_le64(AAPL_CAP_RESILIENT_HANDLES))) {
        struct smb2_read_dir_rsp *rsp = work->response_buf;
        rsp->Flags = cpu_to_le16(SMB2_REOPEN_ORIGINAL | SMB2_REOPEN_POSITION);
    }

    return ret;
}
```

### Security Validation Example

```c
int validate_apple_request(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    const struct create_context *context;
    int ret;

    // Step 1: Find Apple context in request
    context = smb2_find_context_vals(work->request_buf, SMB2_CREATE_AAPL, 4);
    if (IS_ERR(context))
        return PTR_ERR(context);

    if (!context) {
        // Not an Apple request, allow standard processing
        return 0;
    }

    // Step 2: Validate context structure
    ret = aapl_validate_create_context(context);
    if (ret) {
        ksmbd_debug(SMB, "Invalid AAPL context structure\n");
        return -EACCES;  // Security failure
    }

    // Step 3: Extract and validate client information
    const struct aapl_client_info *client_info =
        (const struct aapl_client_info *)
        ((const __u8 *)context + le16_to_cpu(context->DataOffset));

    // Step 4: Cryptographic validation
    ret = aapl_validate_client_signature(conn, client_info,
                                        le32_to_cpu(context->DataLength));
    if (ret) {
        ksmbd_debug(SMB, "Apple client signature validation failed\n");
        return -EACCES;  // Security failure
    }

    // Step 5: Verify this is not a replay attack
    if (conn->aapl_state &&
        le32_to_cpu(client_info->build_number) < conn->aapl_state->client_build) {
        ksmbd_debug(SMB, "Potential replay attack detected\n");
        return -EACCES;  // Security failure
    }

    // Step 6: Client is validated, establish Apple connection
    return establish_apple_connection(conn, client_info);
}
```

### Complete Integration Example

```c
/**
 * Example: Complete integration of Apple SMB extensions into KSMBD
 */

#include "smb2_aapl.h"

/* Global Apple extensions state */
static bool apple_extensions_enabled = true;

int ksmbd_init_apple_extensions(void)
{
    int ret;

    // Initialize Apple crypto subsystem
    ret = aapl_crypto_init();
    if (ret) {
        pr_err("Failed to initialize Apple crypto: %d\n", ret);
        return ret;
    }

    pr_info("KSMBD Apple SMB extensions initialized\n");
    return 0;
}

void ksmbd_cleanup_apple_extensions(void)
{
    aapl_crypto_cleanup();
    pr_info("KSMBD Apple SMB extensions cleaned up\n");
}

int handle_smb2_create_apple(struct ksmbd_work *work)
{
    struct ksmbd_conn *conn = work->conn;
    const struct create_context *context;
    int ret;

    // Skip if Apple extensions are disabled
    if (!apple_extensions_enabled)
        return 0;

    // Step 1: Check if this is an Apple client request
    if (!aapl_is_client_request(work->request_buf, work->response_sz)) {
        // Not an Apple client, continue with standard processing
        return 0;
    }

    // Step 2: Process Apple contexts
    context = smb2_find_context_vals(work->request_buf, SMB2_CREATE_AAPL, 4);
    if (!IS_ERR(context) && context) {
        ret = process_apple_client_context(conn, context);
        if (ret) {
            ksmbd_debug(SMB, "Apple context processing failed: %d\n", ret);
            return ret;
        }
    }

    // Step 3: Process other Apple contexts
    ret = process_apple_contexts(work);
    if (ret)
        return ret;

    // Step 4: Enable Apple-specific optimizations for this connection
    if (conn->is_aapl) {
        ret = enable_apple_optimizations(conn);
        if (ret) {
            ksmbd_debug(SMB, "Failed to enable Apple optimizations: %d\n", ret);
            // Non-fatal, continue with connection
        }
    }

    return 0;
}

int process_apple_client_context(struct ksmbd_conn *conn,
                               const struct create_context *context)
{
    const struct aapl_client_info *client_info;
    int ret;

    // Validate context structure
    ret = aapl_validate_create_context(context);
    if (ret)
        return ret;

    // Extract client information
    client_info = (const struct aapl_client_info *)
        ((const __u8 *)context + le16_to_cpu(context->DataOffset));

    // Validate cryptographic signature
    ret = aapl_validate_client_signature(conn, client_info,
                                        le32_to_cpu(context->DataLength));
    if (ret)
        return ret;

    // Initialize connection state if not already done
    if (!conn->aapl_state) {
        conn->aapl_state = kzalloc(sizeof(struct aapl_conn_state), GFP_KERNEL);
        if (!conn->aapl_state)
            return -ENOMEM;

        ret = aapl_init_connection_state(conn->aapl_state);
        if (ret) {
            kfree(conn->aapl_state);
            conn->aapl_state = NULL;
            return ret;
        }
    }

    // Update connection state
    ret = aapl_update_connection_state(conn->aapl_state, client_info);
    if (ret)
        return ret;

    // Mark as Apple connection
    conn->is_aapl = true;
    conn->aapl_extensions_enabled = true;

    // Log successful Apple client connection
    ksmbd_debug(SMB, "Apple client %s version %s connected\n",
                    aapl_get_client_name(client_info->client_type),
                    aapl_get_version_string(client_info->version));

    return 0;
}

int enable_apple_optimizations(struct ksmbd_conn *conn)
{
    int ret;

    // Enable individual capabilities based on negotiation
    if (aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_EXTENDED_ATTRIBUTES))) {
        ret = aapl_enable_capability(conn->aapl_state,
                                    cpu_to_le64(AAPL_CAP_EXTENDED_ATTRIBUTES));
        if (ret)
            ksmbd_debug(SMB, "Failed to enable extended attributes: %d\n", ret);
    }

    if (aapl_supports_capability(conn->aapl_state,
                                 cpu_to_le64(AAPL_CAP_READDIR_ATTRS))) {
        ret = aapl_enable_capability(conn->aapl_state,
                                    cpu_to_le64(AAPL_CAP_READDIR_ATTRS));
        if (ret)
            ksmbd_debug(SMB, "Failed to enable readdir attributes: %d\n", ret);
    }

    // Configure performance optimizations
    conn->aapl_batch_size = 512;
    conn->aapl_cache_timeout = 30;

    ksmbd_debug(SMB, "Apple optimizations enabled for connection\n");
    return 0;
}

void cleanup_apple_connection(struct ksmbd_conn *conn)
{
    if (conn->aapl_state) {
        // Securely clean up Apple connection state
        aapl_cleanup_connection_state(conn->aapl_state);
        kfree(conn->aapl_state);
        conn->aapl_state = NULL;
    }

    // Reset Apple flags
    conn->is_aapl = false;
    conn->aapl_extensions_enabled = false;

    ksmbd_debug(SMB, "Apple connection cleaned up\n");
}
```

## Conclusion

This API reference manual provides comprehensive documentation for all functions, data structures, and constants in the KSMBD Apple SMB extensions implementation. The API is designed to be:

- **Secure**: Comprehensive validation and capability gating
- **Flexible**: Support for multiple Apple client types and versions
- **Performant**: Optimized for Apple client workloads
- **Maintainable**: Clear architecture and documentation
- **Extensible**: Easy to add new Apple features

Following the patterns and best practices in this manual will ensure successful integration of Apple SMB extensions into SMB server implementations while maintaining security, performance, and compatibility with macOS and iOS clients.