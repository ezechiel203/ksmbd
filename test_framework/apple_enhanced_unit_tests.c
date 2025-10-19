// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2024 ksmbd Contributors
 *
 *   Enhanced Unit Test Framework for Apple SMB Extensions
 *   This framework addresses gaps identified in the testing review
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/vmalloc.h>

#include "smb2pdu.h"
#include "connection.h"
#include "smb2aapl.h"
#include "test_framework/test_utils.h"

#define ENHANCED_TEST_MODULE "ksmbd_apple_enhanced"

/* Enhanced test statistics */
struct enhanced_test_stats {
    atomic_t total_tests;
    atomic_t passed_tests;
    atomic_t failed_tests;
    atomic_t skipped_tests;
    atomic_t critical_tests;
    atomic_t critical_passed;
};

static struct enhanced_test_stats enhanced_stats;

/* Enhanced test result structure */
struct enhanced_test_result {
    const char *test_name;
    const char *category;
    bool critical;
    bool passed;
    const char *error_message;
    unsigned long long duration_ns;
    size_t memory_used;
};

/* Malformed AAPL context test data structures */
struct malformed_context_test {
    const char *description;
    void (*create_context)(void *buffer, size_t size);
    size_t buffer_size;
    bool should_pass;
    int expected_error;
};

/* Test data for malformed contexts */
static struct malformed_context_test malformed_tests[] = {
    {
        "Valid AAPL context",
        create_valid_aapl_context,
        sizeof(struct create_context) + sizeof(struct aapl_client_info),
        true, 0
    },
    {
        "Truncated AAPL context",
        create_truncated_aapl_context,
        20, /* Too small */
        false, -EINVAL
    },
    {
        "AAPL context with invalid signature",
        create_invalid_signature_context,
        sizeof(struct create_context) + sizeof(struct aapl_client_info),
        false, -EINVAL
    },
    {
        "AAPL context with oversized data",
        create_oversized_aapl_context,
        sizeof(struct create_context) + 65536, /* Maximum possible */
        false, -EMSGSIZE
    },
    {
        "AAPL context with invalid data alignment",
        create_unaligned_aapl_context,
        sizeof(struct create_context) + sizeof(struct aapl_client_info) + 1,
        false, -EINVAL
    },
    {
        "AAPL context with negative length",
        create_negative_length_context,
        sizeof(struct create_context) + sizeof(struct aapl_client_info),
        false, -EINVAL
    },
    {
        "AAPL context with zero length",
        create_zero_length_context,
        sizeof(struct create_context),
        false, -EINVAL
    },
    {
        "AAPL context with data offset out of bounds",
        create_invalid_offset_context,
        sizeof(struct create_context) + sizeof(struct aapl_client_info),
        false, -EINVAL
    },
    { NULL, NULL, 0, false, 0 }
};

/* Capability negotiation test data */
struct capability_negotiation_test {
    const char *description;
    __le64 client_capabilities;
    __le64 server_capabilities;
    __le64 expected_result;
    bool should_succeed;
};

static struct capability_negotiation_test cap_tests[] = {
    {
        "Standard capability match",
        AAPL_DEFAULT_CAPABILITIES,
        AAPL_DEFAULT_CAPABILITIES,
        AAPL_DEFAULT_CAPABILITIES,
        true
    },
    {
        "Client subset of server capabilities",
        cpu_to_le64(AAPL_CAP_UNIX_EXTENSIONS | AAPL_CAP_CASE_SENSITIVE),
        AAPL_DEFAULT_CAPABILITIES,
        cpu_to_le64(AAPL_CAP_UNIX_EXTENSIONS | AAPL_CAP_CASE_SENSITIVE),
        true
    },
    {
        "Server subset of client capabilities",
        AAPL_DEFAULT_CAPABILITIES,
        cpu_to_le64(AAPL_CAP_UNIX_EXTENSIONS | AAPL_CAP_CASE_SENSITIVE),
        cpu_to_le64(AAPL_CAP_UNIX_EXTENSIONS | AAPL_CAP_CASE_SENSITIVE),
        true
    },
    {
        "No common capabilities",
        cpu_to_le64(AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS),
        cpu_to_le64(AAPL_CAP_UNIX_EXTENSIONS | AAPL_CAP_CASE_SENSITIVE),
        0,
        true
    },
    {
        "All client capabilities zero",
        0,
        AAPL_DEFAULT_CAPABILITIES,
        0,
        true
    },
    {
        "All server capabilities zero",
        AAPL_DEFAULT_CAPABILITIES,
        0,
        0,
        true
    },
    {
        "Unknown capability bits set",
        cpu_to_le64(0xFFFFFFFFFFFFFFFF),
        AAPL_DEFAULT_CAPABILITIES,
        AAPL_DEFAULT_CAPABILITIES,
        true
    },
    {
        "Mutually exclusive compression capabilities",
        cpu_to_le64(AAPL_COMPRESSION_ZLIB | AAPL_COMPRESSION_LZFS),
        cpu_to_le64(AAPL_COMPRESSION_ZLIB),
        cpu_to_le64(AAPL_COMPRESSION_ZLIB),
        true
    },
    { NULL, 0, 0, 0, false }
};

/* Apple client version detection test data */
struct client_detection_test {
    const char *description;
    void (*create_packet)(void *buffer, size_t size);
    size_t packet_size;
    bool should_detect_apple;
    int expected_client_type;
};

static struct client_detection_test detection_tests[] = {
    {
        "Standard Apple macOS client",
        create_macos_packet,
        512,
        true,
        AAPL_CLIENT_MACOS
    },
    {
        "Apple iOS client",
        create_ios_packet,
        512,
        true,
        AAPL_CLIENT_IOS
    },
    {
        "Apple iPadOS client",
        create_ipados_packet,
        512,
        true,
        AAPL_CLIENT_IPADOS
    },
    {
        "Non-Apple Windows client",
        create_windows_packet,
        512,
        false,
        0
    },
    {
        "Non-Apple Linux client",
        create_linux_packet,
        512,
        false,
        0
    },
    {
        "Malformed Apple packet",
        create_malformed_apple_packet,
        512,
        false,
        0
    },
    {
        "Apple packet with large context",
        create_large_apple_packet,
        16384,
        true,
        AAPL_CLIENT_MACOS
    },
    { NULL, NULL, 0, false, 0 }
};

/* Enhanced assertion macros */
#define CRITICAL_TEST_ASSERT(condition, test_name, message) \
    do { \
        atomic_inc(&enhanced_stats.critical_tests); \
        if (!(condition)) { \
            test_fail(test_name, __func__, __LINE__, message); \
            return; \
        } \
        atomic_inc(&enhanced_stats.critical_passed); \
    } while (0)

#define MEMORY_TEST_ASSERT(condition, test_name, message, expected_memory) \
    do { \
        if (!(condition)) { \
            char msg[512]; \
            snprintf(msg, sizeof(msg), "%s (Memory: %zu bytes)", message, expected_memory); \
            test_fail(test_name, __func__, __LINE__, msg); \
            return; \
        } \
    } while (0)

/* Malformed context creation functions */
static void create_valid_aapl_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;
    struct aapl_client_info *info = (struct aapl_client_info *)(ctx->Buffer + 4);

    ctx->NameLength = 4;
    ctx->DataLength = cpu_to_le32(sizeof(struct aapl_client_info));
    ctx->DataOffset = cpu_to_le16(offsetof(struct create_context, Buffer) + 4);

    memcpy(ctx->Buffer, "AAPL", 4);

    info->signature[0] = 'A';
    info->signature[1] = 'A';
    info->signature[2] = 'P';
    info->signature[3] = 'L';
    info->version = cpu_to_le32(AAPL_VERSION_2_0);
    info->client_type = cpu_to_le32(AAPL_CLIENT_MACOS);
    info->capabilities = cpu_to_le64(AAPL_DEFAULT_CAPABILITIES);
}

static void create_truncated_aapl_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;

    ctx->NameLength = 4;
    ctx->DataLength = cpu_to_le32(1000); /* Larger than buffer */
    ctx->DataOffset = cpu_to_le16(offsetof(struct create_context, Buffer) + 4);

    memcpy(ctx->Buffer, "AAPL", 4);
}

static void create_invalid_signature_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;
    struct aapl_client_info *info = (struct aapl_client_info *)(ctx->Buffer + 4);

    ctx->NameLength = 4;
    ctx->DataLength = cpu_to_le32(sizeof(struct aapl_client_info));
    ctx->DataOffset = cpu_to_le16(offsetof(struct create_context, Buffer) + 4);

    memcpy(ctx->Buffer, "AAAX", 4); /* Invalid signature */

    info->signature[0] = 'A';
    info->signature[1] = 'A';
    info->signature[2] = 'X';
    info->signature[3] = 'X';
    info->version = cpu_to_le32(AAPL_VERSION_2_0);
    info->client_type = cpu_to_le32(AAPL_CLIENT_MACOS);
    info->capabilities = cpu_to_le64(AAPL_DEFAULT_CAPABILITIES);
}

static void create_oversized_aapl_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;

    ctx->NameLength = 4;
    ctx->DataLength = cpu_to_le32(65536);
    ctx->DataOffset = cpu_to_le16(offsetof(struct create_context, Buffer) + 4);

    memcpy(ctx->Buffer, "AAPL", 4);
}

static void create_unaligned_aapl_context(void *buffer, size_t size)
{
    /* Create context with unaligned data */
    memset(buffer, 0, size);
    memcpy(buffer + 1, "AAPL", 4); /* Misaligned signature */
}

static void create_negative_length_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;

    ctx->NameLength = 4;
    ctx->DataLength = cpu_to_le32(0xFFFFFFFF); /* Invalid negative length */
    ctx->DataOffset = cpu_to_le16(offsetof(struct create_context, Buffer) + 4);

    memcpy(ctx->Buffer, "AAPL", 4);
}

static void create_zero_length_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;

    ctx->NameLength = 4;
    ctx->DataLength = 0; /* Zero length */
    ctx->DataOffset = cpu_to_le16(offsetof(struct create_context, Buffer) + 4);

    memcpy(ctx->Buffer, "AAPL", 4);
}

static void create_invalid_offset_context(void *buffer, size_t size)
{
    struct create_context *ctx = buffer;

    ctx->NameLength = 4;
    ctx->DataLength = cpu_to_le32(sizeof(struct aapl_client_info));
    ctx->DataOffset = cpu_to_le16(1000); /* Offset beyond buffer */

    memcpy(ctx->Buffer, "AAPL", 4);
}

/* Packet creation functions for client detection tests */
static void create_macos_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;
    struct smb2_create_req *req = buffer;
    struct create_context *ctx = buffer + sizeof(struct smb2_create_req);

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    req->CreateContextsOffset = cpu_to_le32(sizeof(struct smb2_create_req));
    req->CreateContextsLength = cpu_to_le32(sizeof(struct create_context) + 4);

    ctx->NameOffset = offsetof(struct create_context, Buffer);
    ctx->NameLength = 4;
    memcpy(ctx->Buffer, "AAPL", 4);
}

static void create_ios_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;
    struct smb2_create_req *req = buffer;
    struct create_context *ctx = buffer + sizeof(struct smb2_create_req);
    struct aapl_client_info *info = (struct aapl_client_info *)(ctx->Buffer + 4);

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    req->CreateContextsOffset = cpu_to_le32(sizeof(struct smb2_create_req));
    req->CreateContextsLength = cpu_to_le32(sizeof(struct create_context) + sizeof(struct aapl_client_info));

    ctx->NameOffset = offsetof(struct create_context, Buffer);
    ctx->NameLength = 4;
    memcpy(ctx->Buffer, "AAPL", 4);

    info->signature[0] = 'A';
    info->signature[1] = 'A';
    info->signature[2] = 'P';
    info->signature[3] = 'L';
    info->version = cpu_to_le32(AAPL_VERSION_2_0);
    info->client_type = cpu_to_le32(AAPL_CLIENT_IOS);
}

static void create_ipados_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;
    struct smb2_create_req *req = buffer;
    struct create_context *ctx = buffer + sizeof(struct smb2_create_req);
    struct aapl_client_info *info = (struct aapl_client_info *)(ctx->Buffer + 4);

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    req->CreateContextsOffset = cpu_to_le32(sizeof(struct smb2_create_req));
    req->CreateContextsLength = cpu_to_le32(sizeof(struct create_context) + sizeof(struct aapl_client_info));

    ctx->NameOffset = offsetof(struct create_context, Buffer);
    ctx->NameLength = 4;
    memcpy(ctx->Buffer, "AAPL", 4);

    info->signature[0] = 'A';
    info->signature[1] = 'A';
    info->signature[2] = 'P';
    info->signature[3] = 'L';
    info->version = cpu_to_le32(AAPL_VERSION_2_0);
    info->client_type = cpu_to_le32(AAPL_CLIENT_IPADOS);
}

static void create_windows_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;
    struct smb2_create_req *req = buffer;

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    req->CreateContextsOffset = 0; /* No contexts */
    req->CreateContextsLength = 0;
}

static void create_linux_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;
    struct smb2_create_req *req = buffer;
    struct create_context *ctx = buffer + sizeof(struct smb2_create_req);

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    req->CreateContextsOffset = cpu_to_le32(sizeof(struct smb2_create_req));
    req->CreateContextsLength = cpu_to_le32(sizeof(struct create_context) + 4);

    ctx->NameOffset = offsetof(struct create_context, Buffer);
    ctx->NameLength = 4;
    memcpy(ctx->Buffer, "LNX", 3); /* Linux context, not AAPL */
}

static void create_malformed_apple_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    /* Invalid packet structure */
    memset(buffer + sizeof(struct smb2_hdr), 0xFF, size - sizeof(struct smb2_hdr));
}

static void create_large_apple_packet(void *buffer, size_t size)
{
    struct smb2_hdr *hdr = buffer;
    struct smb2_create_req *req = buffer;
    struct create_context *ctx = buffer + sizeof(struct smb2_create_req);

    hdr->ProtocolId = SMB2_PROTO_NUMBER;
    hdr->Command = SMB2_CREATE_HE;

    req->CreateContextsOffset = cpu_to_le32(sizeof(struct smb2_create_req));
    req->CreateContextsLength = cpu_to_le32(sizeof(struct create_context) + 4);

    ctx->NameOffset = offsetof(struct create_context, Buffer);
    ctx->NameLength = 4;
    memcpy(ctx->Buffer, "AAPL", 4);
}

/* Enhanced test functions */
static void test_malformed_aapl_context_validation(void)
{
    const char *test_name = "Malformed AAPL context validation";
    atomic_inc(&enhanced_stats.total_tests);

    for (int i = 0; malformed_tests[i].description != NULL; i++) {
        struct malformed_context_test *test = &malformed_tests[i];
        void *buffer;
        int result;

        buffer = kzalloc(test->buffer_size, GFP_KERNEL);
        if (!buffer) {
            test_fail(test_name, __func__, __LINE__, "Memory allocation failed");
            return;
        }

        test->create_context(buffer, test->buffer_size);

        result = aapl_validate_create_context(buffer);

        if (test->should_pass) {
            CRITICAL_TEST_ASSERT(result == 0, test_name,
                              test->description);
        } else {
            CRITICAL_TEST_ASSERT(result == test->expected_error, test_name,
                              test->description);
        }

        kfree(buffer);
    }

    test_pass(test_name);
}

static void test_capability_negotiation_comprehensive(void)
{
    const char *test_name = "Comprehensive capability negotiation";
    atomic_inc(&enhanced_stats.total_tests);

    for (int i = 0; cap_tests[i].description != NULL; i++) {
        struct capability_negotiation_test *test = &cap_tests[i];
        __le64 negotiated;

        negotiated = cpu_to_le64(
            le64_to_cpu(test->client_capabilities) &
            le64_to_cpu(test->server_capabilities)
        );

        CRITICAL_TEST_ASSERT(negotiated == test->expected_result, test_name,
                          test->description);
    }

    test_pass(test_name);
}

static void test_apple_client_detection_comprehensive(void)
{
    const char *test_name = "Comprehensive Apple client detection";
    atomic_inc(&enhanced_stats.total_tests);

    for (int i = 0; detection_tests[i].description != NULL; i++) {
        struct client_detection_test *test = &detection_tests[i];
        void *buffer;
        bool is_apple;

        buffer = kzalloc(test->packet_size, GFP_KERNEL);
        if (!buffer) {
            test_fail(test_name, __func__, __LINE__, "Memory allocation failed");
            return;
        }

        test->create_packet(buffer, test->packet_size);

        is_apple = aapl_is_client_request(buffer, test->packet_size);

        CRITICAL_TEST_ASSERT(is_apple == test->should_detect_apple, test_name,
                          test->description);

        kfree(buffer);
    }

    test_pass(test_name);
}

static void test_aapl_connection_state_management(void)
{
    const char *test_name = "AAPL connection state management";
    struct aapl_conn_state *state;
    struct aapl_client_info client_info;
    int result;

    atomic_inc(&enhanced_stats.total_tests);
    CRITICAL_TEST_ASSERT(atomic_inc(&enhanced_stats.critical_tests) > 0, test_name, "Critical test");

    state = kzalloc(sizeof(struct aapl_conn_state), GFP_KERNEL);
    if (!state) {
        test_fail(test_name, __func__, __LINE__, "Memory allocation failed");
        return;
    }

    /* Test initialization */
    result = aapl_init_connection_state(state);
    CRITICAL_TEST_ASSERT(result == 0, test_name, "Connection state initialization");

    /* Test default capabilities */
    CRITICAL_TEST_ASSERT(state->negotiated_capabilities == cpu_to_le64(AAPL_DEFAULT_CAPABILITIES),
                      test_name, "Default capabilities set correctly");

    /* Test cleanup */
    aapl_cleanup_connection_state(state);
    CRITICAL_TEST_ASSERT(state->negotiated_capabilities == 0, test_name, "Connection state cleaned up");

    /* Test client info update */
    memset(&client_info, 0, sizeof(client_info));
    client_info.signature[0] = 'A';
    client_info.signature[1] = 'A';
    client_info.signature[2] = 'P';
    client_info.signature[3] = 'L';
    client_info.version = cpu_to_le32(AAPL_VERSION_2_0);
    client_info.client_type = cpu_to_le32(AAPL_CLIENT_MACOS);
    client_info.capabilities = cpu_to_le64(AAPL_DEFAULT_CAPABILITIES);

    result = aapl_update_connection_state(state, &client_info);
    CRITICAL_TEST_ASSERT(result == 0, test_name, "Connection state update");

    /* Test capability support */
    CRITICAL_TEST_ASSERT(aapl_supports_capability(state, AAPL_CAP_UNIX_EXTENSIONS),
                      test_name, "Capability support check");
    CRITICAL_TEST_ASSERT(!aapl_supports_capability(state, cpu_to_le64(0x1000000000000000ULL)),
                      test_name, "Non-existent capability check");

    kfree(state);
    atomic_inc(&enhanced_stats.critical_passed);
    test_pass(test_name);
}

static void test_aapl_memory_management(void)
{
    const char *test_name = "AAPL memory management";
    struct ksmbd_conn *conn;
    int result;
    size_t initial_memory, final_memory;

    atomic_inc(&enhanced_stats.total_tests);

    initial_memory = get_memory_usage();

    conn = create_mock_connection(true);
    if (!conn) {
        test_fail(test_name, __func__, __LINE__, "Mock connection creation failed");
        return;
    }

    /* Test Apple state allocation */
    result = aapl_negotiate_capabilities(conn, NULL);
    CRITICAL_TEST_ASSERT(result == -EINVAL, test_name, "Invalid parameter handling");

    /* Create valid client info */
    {
        struct aapl_client_info client_info = {
            .signature = {'A', 'A', 'P', 'L'},
            .version = cpu_to_le32(AAPL_VERSION_2_0),
            .client_type = cpu_to_le32(AAPL_CLIENT_MACOS),
            .capabilities = cpu_to_le64(AAPL_DEFAULT_CAPABILITIES)
        };

        result = aapl_negotiate_capabilities(conn, &client_info);
        CRITICAL_TEST_ASSERT(result == 0, test_name, "Capability negotiation");
        CRITICAL_TEST_ASSERT(conn->aapl_state != NULL, test_name, "Apple state allocated");
    }

    /* Test connection cleanup */
    ksmbd_conn_free(conn);
    final_memory = get_memory_usage();

    MEMORY_TEST_ASSERT(initial_memory == final_memory, test_name,
                     "Memory leak detected", final_memory - initial_memory);

    test_pass(test_name);
}

static void test_aapl_edge_case_scenarios(void)
{
    const char *test_name = "AAPL edge case scenarios";
    struct aapl_conn_state state;
    int i;

    atomic_inc(&enhanced_stats.total_tests);

    /* Test connection state with null pointers */
    CRITICAL_TEST_ASSERT(aapl_init_connection_state(NULL) == -EINVAL, test_name,
                      "Null state initialization");

    /* Test capability support with null state */
    CRITICAL_TEST_ASSERT(!aapl_supports_capability(NULL, AAPL_CAP_UNIX_EXTENSIONS), test_name,
                      "Null state capability check");

    /* Test client info parsing with invalid data */
    memset(&state, 0, sizeof(state));
    CRITICAL_TEST_ASSERT(aapl_parse_client_info(NULL, 0, &state) == -EINVAL, test_name,
                      "Null context data parsing");

    /* Test client info parsing with insufficient data */
    char small_data[4];
    CRITICAL_TEST_ASSERT(aapl_parse_client_info(small_data, sizeof(small_data), &state) == -EINVAL,
                      test_name, "Insufficient data parsing");

    /* Test various client version detection scenarios */
    struct version_test {
        __le32 version;
        const char *expected_string;
    };

    struct version_test version_tests[] = {
        {cpu_to_le32(AAPL_VERSION_1_0), "1.0"},
        {cpu_to_le32(AAPL_VERSION_1_1), "1.1"},
        {cpu_to_le32(AAPL_VERSION_2_0), "2.0"},
        {cpu_to_le32(0xFFFFFFFF), "Unknown"},
        {cpu_to_le32(0), "Unknown"}
    };

    for (i = 0; i < ARRAY_SIZE(version_tests); i++) {
        const char *result = aapl_get_version_string(version_tests[i].version);
        CRITICAL_TEST_ASSERT(strcmp(result, version_tests[i].expected_string) == 0, test_name,
                          "Version string conversion");
    }

    test_pass(test_name);
}

/* Performance-critical tests */
static void test_aapl_performance_critical_paths(void)
{
    const char *test_name = "AAPL performance critical paths";
    unsigned long long start_time, end_time, total_time = 0;
    int i, iterations = 10000;

    atomic_inc(&enhanced_stats.total_tests);

    /* Test signature validation performance */
    __u8 valid_signature[4] = {'A', 'A', 'P', 'L'};
    __u8 invalid_signature[4] = {'A', 'A', 'P', 'X'};

    start_time = get_time_ns();
    for (i = 0; i < iterations; i++) {
        aapl_valid_signature(valid_signature);
        aapl_valid_signature(invalid_signature);
    }
    end_time = get_time_ns();
    total_time = end_time - start_time;

    CRITICAL_TEST_ASSERT(total_time < (unsigned long long)(iterations * 1000), test_name,
                      "Signature validation performance");

    /* Test capability support check performance */
    struct aapl_conn_state test_state = {
        .negotiated_capabilities = cpu_to_le64(AAPL_DEFAULT_CAPABILITIES)
    };

    start_time = get_time_ns();
    for (i = 0; i < iterations; i++) {
        aapl_supports_capability(&test_state, AAPL_CAP_UNIX_EXTENSIONS);
        aapl_supports_capability(&test_state, AAPL_CAP_CASE_SENSITIVE);
        aapl_supports_capability(&test_state, cpu_to_le64(0));
    }
    end_time = get_time_ns();
    total_time = end_time - start_time;

    CRITICAL_TEST_ASSERT(total_time < (unsigned long long)(iterations * 500), test_name,
                      "Capability support check performance");

    test_pass(test_name);
}

/* Test suite definition */
static struct enhanced_test_case {
    const char *name;
    const char *category;
    bool critical;
    void (*test_func)(void);
} enhanced_test_cases[] = {
    {"malformed_aapl_context_validation", "Security", true, test_malformed_aapl_context_validation},
    {"capability_negotiation_comprehensive", "Core", true, test_capability_negotiation_comprehensive},
    {"apple_client_detection_comprehensive", "Core", true, test_apple_client_detection_comprehensive},
    {"aapl_connection_state_management", "State", true, test_aapl_connection_state_management},
    {"aapl_memory_management", "Memory", true, test_aapl_memory_management},
    {"aapl_edge_case_scenarios", "Edge Cases", false, test_aapl_edge_case_scenarios},
    {"aapl_performance_critical_paths", "Performance", true, test_aapl_performance_critical_paths},
    {NULL, NULL, false, NULL}
};

/* Test failure function */
static void test_fail(const char *test_name, const char *func, int line, const char *message)
{
    atomic_inc(&enhanced_stats.failed_tests);
    pr_err("❌ FAIL: %s (%s:%d): %s\n", test_name, func, line, message);
}

/* Test pass function */
static void test_pass(const char *test_name)
{
    atomic_inc(&enhanced_stats.passed_tests);
    pr_info("✅ PASS: %s\n", test_name);
}

/* Test skip function */
static void test_skip(const char *test_name, const char *reason)
{
    atomic_inc(&enhanced_stats.skipped_tests);
    pr_info("⏭️  SKIP: %s (%s)\n", test_name, reason);
}

/* Enhanced test runner */
static int run_enhanced_tests(void)
{
    int i, failed = 0;
    unsigned long long start_time, end_time, total_time;

    pr_info("🧪 Starting Enhanced Apple SMB Extensions Unit Tests\n");
    pr_info("=========================================================\n");

    memset(&enhanced_stats, 0, sizeof(enhanced_stats));

    start_time = get_time_ns();

    for (i = 0; enhanced_test_cases[i].name != NULL; i++) {
        unsigned long long test_start = get_time_ns();
        struct enhanced_test_case *test = &enhanced_test_cases[i];

        pr_info("Running: %s (%s, %s)\n", test->name, test->category,
                test->critical ? "Critical" : "Standard");

        test->test_func();

        unsigned long long test_duration = get_time_ns() - test_start;
        pr_info("%s completed in %lld ns\n",
                test->passed ? "✅" : "❌", test_duration);
    }

    end_time = get_time_ns();
    total_time = end_time - start_time;

    pr_info("=========================================================\n");
    pr_info("Enhanced Test Results:\n");
    pr_info("  Total tests: %d\n", atomic_read(&enhanced_stats.total_tests));
    pr_info("  Passed tests: %d\n", atomic_read(&enhanced_stats.passed_tests));
    pr_info("  Failed tests: %d\n", atomic_read(&enhanced_stats.failed_tests));
    pr_info("  Skipped tests: %d\n", atomic_read(&enhanced_stats.skipped_tests));
    pr_info("  Critical tests: %d\n", atomic_read(&enhanced_stats.critical_tests));
    pr_info("  Critical passed: %d\n", atomic_read(&enhanced_stats.critical_passed));
    pr_info("  Total time: %lld ns\n", total_time);
    pr_info("  Pass rate: %.2f%%\n",
            atomic_read(&enhanced_stats.total_tests) > 0 ?
            (float)atomic_read(&enhanced_stats.passed_tests) / atomic_read(&enhanced_stats.total_tests) * 100.0 : 0.0);
    pr_info("  Critical pass rate: %.2f%%\n",
            atomic_read(&enhanced_stats.critical_tests) > 0 ?
            (float)atomic_read(&enhanced_stats.critical_passed) / atomic_read(&enhanced_stats.critical_tests) * 100.0 : 0.0);

    return atomic_read(&enhanced_stats.failed_tests) == 0 ? 0 : -1;
}

/* Module initialization */
static int __init apple_enhanced_test_init(void)
{
    int ret;

    pr_info("Loading %s module\n", ENHANCED_TEST_MODULE);

    ret = run_enhanced_tests();
    if (ret != 0) {
        pr_err("Enhanced unit tests failed!\n");
        return ret;
    }

    pr_info("All enhanced unit tests passed!\n");
    return 0;
}

/* Module cleanup */
static void __exit apple_enhanced_test_exit(void)
{
    pr_info("Unloading %s module\n", ENHANCED_TEST_MODULE);
}

module_init(apple_enhanced_test_init);
module_exit(apple_enhanced_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ksmbd Contributors");
MODULE_DESCRIPTION("Enhanced Unit Test Framework for Apple SMB Extensions");
MODULE_VERSION("2.0");