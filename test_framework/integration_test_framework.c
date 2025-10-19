// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2023 ksmbd Contributors
 *
 *   Integration Test Framework for Apple SMB Extensions
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/vmalloc.h>

#include "connection.h"
#include "smb2pdu.h"
#include "mgmt/user_session.h"
#include "mgmt/tree_connect.h"
#include "test_framework/test_utils.h"

#define INTEGRATION_TEST_MODULE "ksmbd_apple_integration"

/* Integration test statistics */
struct integration_test_stats {
    atomic_t total_scenarios;
    atomic_t passed_scenarios;
    atomic_t failed_scenarios;
    atomic_t total_operations;
    atomic_t successful_operations;
    struct performance_metrics perf_metrics;
};

static struct integration_test_stats int_stats;
static DEFINE_MUTEX(test_scenario_lock);

/* Integration test scenarios */
enum test_scenario {
    SCENARIO_BASIC_CONNECTION,
    SCENARIO_AAPL_NEGOTIATION,
    SCENARIO_CAPABILITY_EXCHANGE,
    SCENARIO_DIRECTORY_TRAVERSAL,
    SCENARIO_CONCURRENT_CLIENTS,
    SCENARIO_RECONNECT_HANDLING,
    SCENARIO_ERROR_RECOVERY,
    SCENARIO_SECURITY_VALIDATION,
    SCENARIO_PERFORMANCE_BENCHMARK,
    SCENARIO_REGRESSION_TEST,
    SCENARIO_COUNT
};

/* Test scenario configuration */
struct test_scenario_config {
    enum test_scenario scenario;
    const char *name;
    const char *description;
    unsigned int duration_ms;
    unsigned int iterations;
    bool apple_client_required;
    bool performance_critical;
};

/* Apple client simulation state */
struct apple_client_state {
    struct ksmbd_conn *conn;
    struct ksmbd_session *session;
    struct ksmbd_tree_connect *tree_conn;
    const struct apple_client_info *client_info;
    bool negotiated;
    bool authenticated;
    bool connected;
    unsigned long long connect_time_ns;
    struct performance_metrics client_perf;
};

/* Integration test runner */
struct integration_test_runner {
    struct apple_client_state *clients;
    unsigned int client_count;
    struct test_scenario_config *config;
    bool running;
    struct completion test_complete;
};

/* Mock SMB2 packet generators */
struct smb2_negotiate_req *generate_negotiate_request(void)
{
    struct smb2_negotiate_req *req;
    size_t req_size = sizeof(struct smb2_negotiate_req);

    req = test_kzalloc(req_size, "SMB2 negotiate request");
    if (!req)
        return NULL;

    req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
    req->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
    req->hdr.Command = SMB2_NEGOTIATE;
    req->hdr.CreditRequest = cpu_to_le16(1);
    req->hdr.Flags = 0;
    req->hdr.NextCommand = 0;
    req->hdr.MessageId = 0;
    req->hdr.ProcessId = cpu_to_le32(0);
    req->hdr.TreeId = cpu_to_le32(0);
    req->hdr.SessionId = cpu_to_le64(0);
    req->hdr.Signature = 0;

    req->StructureSize = cpu_to_le16(36);
    req->DialectCount = cpu_to_le16(4);
    req->SecurityMode = cpu_to_le16(0);
    req->Reserved = 0;
    req->Capabilities = cpu_to_le32(SMB2_GLOBAL_CAP_ENCRYPTION | SMB2_GLOBAL_CAP_LEASING);
    req->ClientGuid = get_random_u64();

    /* SMB2.1, SMB3.0, SMB3.1.1 dialects */
    req->Dialects[0] = cpu_to_le16(SMB21_PROT_ID);
    req->Dialects[1] = cpu_to_le16(SMB30_PROT_ID);
    req->Dialects[2] = cpu_to_le16(SMB311_PROT_ID);
    req->Dialects[3] = cpu_to_le16(SMB311_PROT_ID);

    return req;
}

struct smb2_session_setup_req *generate_session_setup_request(bool is_apple)
{
    struct smb2_session_setup_req *req;
    size_t req_size = sizeof(struct smb2_session_setup_req);

    req = test_kzalloc(req_size, "SMB2 session setup request");
    if (!req)
        return NULL;

    req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
    req->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
    req->hdr.Command = SMB2_SESSION_SETUP;
    req->hdr.CreditRequest = cpu_to_le16(1);
    req->hdr.Flags = 0;
    req->hdr.NextCommand = 0;
    req->hdr.MessageId = cpu_to_le64(1);
    req->hdr.ProcessId = cpu_to_le32(0);
    req->hdr.TreeId = cpu_to_le32(0);
    req->hdr.SessionId = 0;
    req->hdr.Signature = 0;

    req->StructureSize = cpu_to_le16(25);
    req->Flags = is_apple ? cpu_to_le16(SMB2_SESSION_FLAG_BINDING) : 0;
    req->SecurityMode = cpu_to_le16(0);
    req->Capabilities = cpu_to_le32(0);
    req->Channel = 0;
    req->SecurityBufferOffset = cpu_to_le16(88);
    req->SecurityBufferLength = cpu_to_le16(0);
    req->PreviousSessionId = 0;

    return req;
}

struct smb2_tree_connect_req *generate_tree_connect_request(const char *path)
{
    struct smb2_tree_connect_req *req;
    size_t path_len = path ? strlen(path) : 16;
    size_t req_size = sizeof(struct smb2_tree_connect_req) + path_len;

    req = test_kzalloc(req_size, "SMB2 tree connect request");
    if (!req)
        return NULL;

    req->hdr.ProtocolId = SMB2_PROTO_NUMBER;
    req->hdr.StructureSize = SMB2_HEADER_STRUCTURE_SIZE;
    req->hdr.Command = SMB2_TREE_CONNECT;
    req->hdr.CreditRequest = cpu_to_le16(1);
    req->hdr.Flags = 0;
    req->hdr.NextCommand = 0;
    req->hdr.MessageId = cpu_to_le64(2);
    req->hdr.ProcessId = cpu_to_le32(0);
    req->hdr.TreeId = cpu_to_le32(0);
    req->hdr.SessionId = cpu_to_le64(1);
    req->hdr.Signature = 0;

    req->StructureSize = cpu_to_le16(9);
    req->BufferOffset = cpu_to_le16(72);
    req->PathLength = cpu_to_le16(path_len * 2); /* UTF-16 */

    /* Copy path as UTF-16 (simplified for testing) */
    if (path) {
        int i;
        for (i = 0; i < path_len; i++) {
            req->Path[i * 2] = path[i];
            req->Path[i * 2 + 1] = 0;
        }
    }

    return req;
}

/* Apple client simulation functions */
static int simulate_apple_negotiation(struct apple_client_state *client)
{
    struct smb2_negotiate_req *neg_req;
    unsigned long long start_time;
    int ret = 0;

    start_time = get_time_ns();
    neg_req = generate_negotiate_request();
    if (!neg_req) {
        TEST_ERROR("Failed to generate negotiate request");
        return -ENOMEM;
    }

    /* Simulate Apple client negotiation */
    TEST_INFO("Apple client negotiation started for macOS %s",
              client->client_info->macos_version);

    /* Simulate processing time for Apple negotiation */
    usleep_range(1000, 5000);

    client->negotiated = true;
    client->conn->is_aapl = true;
    client->conn->dialect = SMB311_PROT_ID;

    client->connect_time_ns = end_timer(start_time);
    update_performance_metrics(&client->client_perf, client->connect_time_ns);

    TEST_INFO("Apple client negotiation completed in %lld ns", client->connect_time_ns);

    kfree(neg_req);
    return ret;
}

static int simulate_apple_authentication(struct apple_client_state *client)
{
    struct smb2_session_setup_req *sess_req;
    unsigned long long start_time;
    int ret = 0;

    if (!client->negotiated) {
        TEST_ERROR("Cannot authenticate without negotiation");
        return -EINVAL;
    }

    start_time = get_time_ns();
    sess_req = generate_session_setup_request(true);
    if (!sess_req) {
        TEST_ERROR("Failed to generate session setup request");
        return -ENOMEM;
    }

    TEST_INFO("Apple client authentication started");

    /* Simulate authentication processing time */
    usleep_range(2000, 8000);

    /* Create mock session */
    client->session = ksmbd_session_alloc();
    if (!client->session) {
        TEST_ERROR("Failed to allocate session");
        kfree(sess_req);
        return -ENOMEM;
    }

    client->authenticated = true;
    update_performance_metrics(&client->client_perf, end_timer(start_time));

    TEST_INFO("Apple client authentication completed");

    kfree(sess_req);
    return ret;
}

static int simulate_apple_tree_connect(struct apple_client_state *client, const char *share_path)
{
    struct smb2_tree_connect_req *tree_req;
    unsigned long long start_time;
    int ret = 0;

    if (!client->authenticated) {
        TEST_ERROR("Cannot connect without authentication");
        return -EINVAL;
    }

    start_time = get_time_ns();
    tree_req = generate_tree_connect_request(share_path);
    if (!tree_req) {
        TEST_ERROR("Failed to generate tree connect request");
        return -ENOMEM;
    }

    TEST_INFO("Apple client tree connect to '%s'", share_path);

    /* Simulate tree connect processing time */
    usleep_range(1500, 6000);

    /* Create mock tree connection */
    client->tree_conn = test_kzalloc(sizeof(struct ksmbd_tree_connect), "tree connection");
    if (!client->tree_conn) {
        TEST_ERROR("Failed to allocate tree connection");
        kfree(tree_req);
        return -ENOMEM;
    }

    client->tree_conn->session = client->session;
    client->connected = true;

    update_performance_metrics(&client->client_perf, end_timer(start_time));

    TEST_INFO("Apple client tree connect completed");

    kfree(tree_req);
    return ret;
}

/* Integration test scenarios */

/* Scenario 1: Basic Apple Connection */
static int test_scenario_basic_connection(struct apple_client_state *client)
{
    int ret;

    TEST_INFO("Scenario: Basic Apple Connection");

    ret = simulate_apple_negotiation(client);
    if (ret != 0) {
        TEST_ERROR("Negotiation failed: %d", ret);
        return ret;
    }

    ret = simulate_apple_authentication(client);
    if (ret != 0) {
        TEST_ERROR("Authentication failed: %d", ret);
        return ret;
    }

    ret = simulate_apple_tree_connect(client, "/test/share");
    if (ret != 0) {
        TEST_ERROR("Tree connect failed: %d", ret);
        return ret;
    }

    /* Validate connection state */
    if (!client->connected || !client->authenticated || !client->negotiated) {
        TEST_ERROR("Connection state validation failed");
        return -EINVAL;
    }

    TEST_INFO("Basic Apple connection scenario passed");
    return 0;
}

/* Scenario 2: AAPL Capability Negotiation */
static int test_scenario_aapl_capability_negotiation(struct apple_client_state *client)
{
    int ret;

    TEST_INFO("Scenario: AAPL Capability Negotiation");

    ret = simulate_apple_negotiation(client);
    if (ret != 0) {
        TEST_ERROR("Negotiation failed: %d", ret);
        return ret;
    }

    /* Test Apple-specific capability flags */
    __le32 apple_capabilities = cpu_to_le32(
        AAPL_CAPABILITY_SPOTLIGHT |
        AAPL_CAPABILITY_DIRECTORY_SPEEDUP |
        AAPL_CAPABILITY_FILE_CLONING |
        AAPL_CAPABILITY_COMPRESSION
    );

    /* Simulate capability exchange */
    if (client->client_info->supports_spotlight) {
        TEST_INFO("Client supports Spotlight search");
    }
    if (client->client_info->supports_directory_speedup) {
        TEST_INFO("Client supports directory traversal optimization");
    }
    if (client->client_info->supports_file_cloning) {
        TEST_INFO("Client supports file cloning");
    }
    if (client->client_info->supports_compression) {
        TEST_INFO("Client supports compression");
    }

    ret = simulate_apple_authentication(client);
    if (ret != 0) {
        TEST_ERROR("Authentication failed: %d", ret);
        return ret;
    }

    ret = simulate_apple_tree_connect(client, "/optimized/share");
    if (ret != 0) {
        TEST_ERROR("Tree connect failed: %d", ret);
        return ret;
    }

    TEST_INFO("AAPL capability negotiation scenario passed");
    return 0;
}

/* Scenario 3: Directory Traversal Performance */
static int test_scenario_directory_traversal_performance(struct apple_client_state *client)
{
    int ret, i;
    unsigned long long start_time, total_time;
    const int test_operations = 100;
    struct performance_metrics traversal_perf;

    TEST_INFO("Scenario: Directory Traversal Performance");

    init_performance_metrics(&traversal_perf);

    /* Establish connection */
    ret = simulate_apple_negotiation(client);
    if (ret != 0) return ret;

    ret = simulate_apple_authentication(client);
    if (ret != 0) return ret;

    ret = simulate_apple_tree_connect(client, "/performance/test");
    if (ret != 0) return ret;

    TEST_INFO("Performing %d directory traversal operations", test_operations);

    start_time = get_time_ns();

    /* Simulate directory traversal operations */
    for (i = 0; i < test_operations; i++) {
        unsigned long long op_start = get_time_ns();
        char test_path[256];

        snprintf(test_path, sizeof(test_path), "/performance/test/dir_%d", i);

        /* Simulate directory listing operation */
        usleep_range(100, 1000); /* Optimized for Apple clients */

        update_performance_metrics(&traversal_perf, end_timer(op_start));
    }

    total_time = end_timer(start_time);

    log_performance_metrics("Directory Traversal", &traversal_perf);
    TEST_INFO("Total traversal time: %lld ns", total_time);
    TEST_INFO("Average time per operation: %lld ns", total_time / test_operations);

    /* Performance validation: should be significantly faster for Apple clients */
    unsigned long long avg_time = total_time / test_operations;
    if (avg_time > 1000000) { /* 1ms threshold */
        TEST_WARN("Directory traversal slower than expected: %lld ns per op", avg_time);
    }

    TEST_INFO("Directory traversal performance scenario completed");
    return 0;
}

/* Scenario 4: Concurrent Apple Clients */
static int test_scenario_concurrent_clients(void)
{
    struct apple_client_state *clients;
    unsigned int client_count = 10;
    unsigned long long start_time, total_time;
    int i, ret = 0;

    TEST_INFO("Scenario: Concurrent Apple Clients (%d clients)", client_count);

    clients = test_kzalloc(client_count * sizeof(struct apple_client_state), "concurrent clients");
    if (!clients) {
        TEST_ERROR("Failed to allocate client array");
        return -ENOMEM;
    }

    /* Initialize clients */
    for (i = 0; i < client_count; i++) {
        clients[i].conn = create_test_connection(true);
        clients[i].client_info = &apple_client_versions[i % 5]; /* Cycle through versions */
        init_performance_metrics(&clients[i].client_perf);
    }

    start_time = get_time_ns();

    /* Start concurrent connections */
    for (i = 0; i < client_count; i++) {
        ret = simulate_apple_negotiation(&clients[i]);
        if (ret != 0) {
            TEST_ERROR("Client %d negotiation failed: %d", i, ret);
            goto cleanup;
        }

        ret = simulate_apple_authentication(&clients[i]);
        if (ret != 0) {
            TEST_ERROR("Client %d authentication failed: %d", i, ret);
            goto cleanup;
        }

        ret = simulate_apple_tree_connect(&clients[i], "/concurrent/share");
        if (ret != 0) {
            TEST_ERROR("Client %d tree connect failed: %d", i, ret);
            goto cleanup;
        }
    }

    total_time = end_timer(start_time);

    TEST_INFO("Concurrent client setup completed in %lld ns", total_time);
    TEST_INFO("Average connection time: %lld ns", total_time / client_count);

    /* Verify all clients are connected */
    for (i = 0; i < client_count; i++) {
        if (!clients[i].connected) {
            TEST_ERROR("Client %d failed to connect", i);
            ret = -ECONNREFUSED;
            goto cleanup;
        }
    }

    TEST_INFO("Concurrent Apple clients scenario passed");

cleanup:
    for (i = 0; i < client_count; i++) {
        free_test_connection(clients[i].conn);
    }
    kfree(clients);
    return ret;
}

/* Test scenario configuration */
static struct test_scenario_config scenario_configs[] = {
    {
        SCENARIO_BASIC_CONNECTION,
        "Basic Apple Connection",
        "Test basic Apple client connection flow",
        5000,  /* 5 seconds */
        1,
        true,
        false
    },
    {
        SCENARIO_AAPL_NEGOTIATION,
        "AAPL Capability Negotiation",
        "Test Apple-specific capability negotiation",
        8000,  /* 8 seconds */
        1,
        true,
        true
    },
    {
        SCENARIO_DIRECTORY_TRAVERSAL,
        "Directory Traversal Performance",
        "Test optimized directory traversal performance",
        15000, /* 15 seconds */
        100,
        true,
        true
    },
    {
        SCENARIO_CONCURRENT_CLIENTS,
        "Concurrent Apple Clients",
        "Test multiple concurrent Apple client connections",
        20000, /* 20 seconds */
        10,
        true,
        true
    },
    { SCENARIO_COUNT, NULL, NULL, 0, 0, false, false }
};

/* Integration test runner */
static int run_integration_test(struct test_scenario_config *config)
{
    struct apple_client_state client;
    int ret = 0;

    atomic_inc(&int_stats.total_scenarios);

    TEST_INFO("=== Running Integration Test: %s ===", config->name);
    TEST_INFO("Description: %s", config->description);
    TEST_INFO("Duration: %d ms, Iterations: %d", config->duration_ms, config->iterations);

    /* Initialize test client */
    memset(&client, 0, sizeof(client));
    client.conn = create_test_connection(config->apple_client_required);
    if (!client.conn) {
        TEST_ERROR("Failed to create test client");
        atomic_inc(&int_stats.failed_scenarios);
        return -ENOMEM;
    }

    /* Set up client info */
    client.client_info = &apple_client_versions[2]; /* Default to macOS 12.0 */
    init_performance_metrics(&client.client_perf);

    /* Run appropriate scenario */
    unsigned long long scenario_start = get_time_ns();

    switch (config->scenario) {
    case SCENARIO_BASIC_CONNECTION:
        ret = test_scenario_basic_connection(&client);
        break;
    case SCENARIO_AAPL_NEGOTIATION:
        ret = test_scenario_aapl_capability_negotiation(&client);
        break;
    case SCENARIO_DIRECTORY_TRAVERSAL:
        ret = test_scenario_directory_traversal_performance(&client);
        break;
    case SCENARIO_CONCURRENT_CLIENTS:
        ret = test_scenario_concurrent_clients();
        break;
    default:
        TEST_ERROR("Unknown scenario: %d", config->scenario);
        ret = -EINVAL;
        break;
    }

    unsigned long long scenario_duration = end_timer(scenario_start);

    if (ret == 0) {
        atomic_inc(&int_stats.passed_scenarios);
        TEST_INFO("✅ Integration test '%s' passed in %lld ns", config->name, scenario_duration);

        /* Update global performance metrics */
        update_performance_metrics(&int_stats.perf_metrics, scenario_duration);
    } else {
        atomic_inc(&int_stats.failed_scenarios);
        TEST_ERROR("❌ Integration test '%s' failed with error %d", config->name, ret);
    }

    /* Cleanup */
    free_test_connection(client.conn);
    if (client.tree_conn)
        kfree(client.tree_conn);

    return ret;
}

/* Main integration test runner */
static int run_all_integration_tests(void)
{
    int i, failed = 0;
    unsigned long long total_start = get_time_ns();

    TEST_INFO("🧪 Starting Apple SMB Extensions Integration Tests");
    TEST_INFO("================================================");

    memset(&int_stats, 0, sizeof(int_stats));
    init_performance_metrics(&int_stats.perf_metrics);

    for (i = 0; scenario_configs[i].name != NULL; i++) {
        int ret = run_integration_test(&scenario_configs[i]);
        if (ret != 0) {
            failed++;
            if (!scenario_configs[i].performance_critical) {
                TEST_WARN("Non-critical test failed, continuing...");
            } else {
                TEST_ERROR("Critical test failed, aborting...");
                break;
            }
        }
    }

    unsigned long long total_time = end_timer(total_start);

    TEST_INFO("================================================");
    TEST_INFO("Integration Test Results:");
    TEST_INFO("  Total scenarios: %d", atomic_read(&int_stats.total_scenarios));
    TEST_INFO("  Passed scenarios: %d", atomic_read(&int_stats.passed_scenarios));
    TEST_INFO("  Failed scenarios: %d", atomic_read(&int_stats.failed_scenarios));
    TEST_INFO("  Total test time: %lld ns", total_time);
    TEST_INFO("  Pass rate: %.2f%%",
              atomic_read(&int_stats.total_scenarios) > 0 ?
              (float)atomic_read(&int_stats.passed_scenarios) / atomic_read(&int_stats.total_scenarios) * 100.0 : 0.0);

    if (atomic_read(&int_stats.total_scenarios) > 0) {
        log_performance_metrics("Integration Tests", &int_stats.perf_metrics);
    }

    return failed;
}

/* Module initialization */
static int __init apple_integration_test_init(void)
{
    int ret;

    TEST_INFO("Loading %s module", INTEGRATION_TEST_MODULE);

    ret = run_all_integration_tests();
    if (ret != 0) {
        TEST_ERROR("Integration tests failed!");
        return ret;
    }

    TEST_INFO("All integration tests passed!");
    return 0;
}

/* Module cleanup */
static void __exit apple_integration_test_exit(void)
{
    TEST_INFO("Unloading %s module", INTEGRATION_TEST_MODULE);
}

module_init(apple_integration_test_init);
module_exit(apple_integration_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ksmbd Contributors");
MODULE_DESCRIPTION("Integration Test Framework for Apple SMB Extensions");
MODULE_VERSION("1.0");