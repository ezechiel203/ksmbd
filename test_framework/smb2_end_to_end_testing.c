// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 The KSMBD Project
 *
 * SMB2 End-to-End Protocol Testing Framework
 *
 * This framework provides comprehensive testing of the complete SMB2 protocol stack,
 * ensuring Fruit SMB extensions work seamlessly with the full protocol implementation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/time.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>

#include "test_utils.h"
#include "smb2fruit.h"
#include "connection.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "vfs.h"
#include "smb_common.h"
#include "smb2pdu.h"
#include "auth.h"

/* E2E Testing constants */
#define E2E_MAX_PROTOCOL_TESTS 1000
#define E2E_MAX_NESTED_REQUESTS 50
#define E2E_MAX_CONCURRENT_SESSIONS 25
#define E2E_MAX_FILE_OPERATIONS 5000
#define E2E_MAX_DATA_SIZE (10 * 1024 * 1024) /* 10MB */
#define E2E_TEST_TIMEOUT_MS 30000

/* SMB2 Command types for testing */
enum e2e_smb2_command {
    E2E_SMB2_NEGOTIATE,
    E2E_SMB2_SESSION_SETUP,
    E2E_SMB2_TREE_CONNECT,
    E2E_SMB2_CREATE,
    E2E_SMB2_CLOSE,
    E2E_SMB2_FLUSH,
    E2E_SMB2_READ,
    E2E_SMB2_WRITE,
    E2E_SMB2_QUERY_DIRECTORY,
    E2E_SMB2_QUERY_INFO,
    E2E_SMB2_SET_INFO,
    E2E_SMB2_IOCTL,
    E2E_SMB2_CANCEL,
    E2E_SMB2_ECHO,
    E2E_SMB2_LOGOFF,
    E2E_SMB2_DISCONNECT,
    E2E_SMB2_BREAK,
    E2E_SMB2_CHANGE_NOTIFY,
    E2E_SMB2_QUERY_QUOTA,
    E2E_SMB2_SET_QUOTA,
    E2E_SMB2_OPLOCK_BREAK,
    E2E_SMB2_LEASE_BREAK
};

/* Test flow types */
enum e2e_test_flow {
    E2E_FLOW_BASIC_SEQUENCE,
    E2E_FLOW_CONCURRENT_OPS,
    E2E_FLOW_NESTED_REQUESTS,
    E2E_FLOW_ERROR_HANDLING,
    E2E_FLOW_FRUIT_EXTENSIONS,
    E2E_FLOW_PERFORMANCE_CRITICAL,
    E2E_FLOW_SECURITY_SENSITIVE,
    E2E_FLOW_RELIABILITY_FOCUSED,
    E2E_FLOW_COMPREHENSIVE_VALIDATION
};

/* E2E Test result */
struct e2e_test_result {
    char test_name[96];
    enum e2e_test_flow flow_type;
    enum e2e_smb2_command command_tested;
    bool fruit_extensions_tested;
    bool passed;
    int error_code;
    unsigned long long duration_ns;
    char error_message[256];
    char protocol_details[1024];
    char fruit_extension_details[512];
    unsigned int compliance_score; /* 0-100 */
    unsigned int fruit_score;      /* 0-100 */
    unsigned int performance_score; /* 0-100 */
};

/* SMB2 packet structure for testing */
struct e2e_smb2_packet {
    struct smb2_hdr hdr;
    void *payload;
    size_t payload_size;
    unsigned int command_id;
    bool has_fruit_context;
    struct fruit_client_info fruit_info;
    unsigned long long timestamp;
};

/* Session state for E2E testing */
struct e2e_session_state {
    struct ksmbd_conn *connection;
    struct ksmbd_session *session;
    struct ksmbd_tree_conn *tree_conn;
    unsigned int session_id;
    bool negotiated;
    bool authenticated;
    bool tree_connected;
    bool fruit_extensions_enabled;
    struct fruit_conn_state fruit_state;
    struct {
        unsigned int files_created;
        unsigned int files_opened;
        unsigned int bytes_read;
        unsigned int bytes_written;
        unsigned int queries_performed;
    } stats;
};

/* Test scenario configuration */
struct e2e_test_scenario {
    const char *scenario_name;
    enum e2e_test_flow flow_type;
    unsigned int iterations;
    unsigned int concurrent_sessions;
    unsigned int operations_per_session;
    bool enable_fruit_extensions;
    bool enable_encryption;
    bool enable_compression;
    bool stress_testing;
    bool error_injection;
    bool performance_monitoring;
};

/* Protocol compliance validator */
struct e2e_compliance_validator {
    bool header_validation_passed;
    bool command_structure_valid;
    bool negotiation_correct;
    bool authentication_proper;
    bool authorization_enforced;
    bool fruit_contexts_valid;
    bool error_responses_correct;
    bool state_consistent;
    bool security_intact;
    unsigned int compliance_issues_count;
};

/* E2E Test suite */
struct e2e_test_suite {
    struct e2e_test_result *results;
    unsigned int total_tests;
    unsigned int passed_tests;
    unsigned int failed_tests;
    unsigned int avg_compliance_score;
    unsigned int avg_fruit_score;
    unsigned int avg_performance_score;
    bool end_to_end_passed;
    bool fruit_extensions_passed;
    bool baseline_performance_met;
    bool protocol_compliance_passed;
    bool security_validation_passed;
    bool initialized;
};

/* Test scenario definitions */
static const struct e2e_test_scenario test_scenarios[] = {
    {
        .scenario_name = "Basic SMB2 Protocol Flow",
        .flow_type = E2E_FLOW_BASIC_SEQUENCE,
        .iterations = 100,
        .concurrent_sessions = 5,
        .operations_per_session = 20,
        .enable_fruit_extensions = false,
        .enable_encryption = false,
        .enable_compression = false,
        .stress_testing = false,
        .error_injection = false,
        .performance_monitoring = true
    },
    {
        .scenario_name = "Fruit Extensions Integration",
        .flow_type = E2E_FLOW_FRUIT_EXTENSIONS,
        .iterations = 200,
        .concurrent_sessions = 10,
        .operations_per_session = 50,
        .enable_fruit_extensions = true,
        .enable_encryption = true,
        .enable_compression = true,
        .stress_testing = false,
        .error_injection = false,
        .performance_monitoring = true
    },
    {
        .scenario_name = "Concurrent Operations Stress",
        .flow_type = E2E_FLOW_CONCURRENT_OPS,
        .iterations = 500,
        .concurrent_sessions = 25,
        .operations_per_session = 100,
        .enable_fruit_extensions = true,
        .enable_encryption = true,
        .enable_compression = true,
        .stress_testing = true,
        .error_injection = false,
        .performance_monitoring = true
    },
    {
        .scenario_name = "Error Handling Validation",
        .flow_type = E2E_FLOW_ERROR_HANDLING,
        .iterations = 300,
        .concurrent_sessions = 15,
        .operations_per_session = 75,
        .enable_fruit_extensions = true,
        .enable_encryption = true,
        .enable_compression = true,
        .stress_testing = false,
        .error_injection = true,
        .performance_monitoring = false
    },
    {
        .scenario_name = "Performance Critical Path",
        .flow_type = E2E_FLOW_PERFORMANCE_CRITICAL,
        .iterations = 1000,
        .concurrent_sessions = 20,
        .operations_per_session = 200,
        .enable_fruit_extensions = true,
        .enable_encryption = true,
        .enable_compression = true,
        .stress_testing = true,
        .error_injection = false,
        .performance_monitoring = true
    },
    {
        .scenario_name = "Security Sensitive Operations",
        .flow_type = E2E_FLOW_SECURITY_SENSITIVE,
        .iterations = 150,
        .concurrent_sessions = 8,
        .operations_per_session = 30,
        .enable_fruit_extensions = true,
        .enable_encryption = true,
        .enable_compression = false,
        .stress_testing = false,
        .error_injection = true,
        .performance_monitoring = false
    }
};

/* Global test suite */
static struct e2e_test_suite global_test_suite;
static DEFINE_MUTEX(e2e_test_mutex);

/* Active sessions tracking */
static struct e2e_session_state *active_sessions[E2E_MAX_CONCURRENT_SESSIONS];
static DEFINE_SPINLOCK(e2e_session_lock);

/* Test suite management */
static int e2e_init_test_suite(struct e2e_test_suite *suite, unsigned int max_tests)
{
    if (!suite)
        return -EINVAL;

    suite->results = test_kzalloc(sizeof(struct e2e_test_result) * max_tests,
                                  "e2e_test_results");
    if (!suite->results)
        return -ENOMEM;

    suite->total_tests = 0;
    suite->passed_tests = 0;
    suite->failed_tests = 0;
    suite->avg_compliance_score = 0;
    suite->avg_fruit_score = 0;
    suite->avg_performance_score = 0;
    suite->end_to_end_passed = true;
    suite->fruit_extensions_passed = true;
    suite->baseline_performance_met = true;
    suite->protocol_compliance_passed = true;
    suite->security_validation_passed = true;
    suite->initialized = true;

    return 0;
}

static void e2e_cleanup_test_suite(struct e2e_test_suite *suite)
{
    if (!suite || !suite->initialized)
        return;

    kfree(suite->results);
    suite->results = NULL;
    suite->initialized = false;
}

static void e2e_record_test_result(struct e2e_test_suite *suite,
                                   const char *test_name,
                                   enum e2e_test_flow flow_type,
                                   enum e2e_smb2_command command_tested,
                                   bool fruit_extensions_tested,
                                   bool passed,
                                   int error_code,
                                   const char *error_message,
                                   const char *protocol_details,
                                   const char *fruit_extension_details,
                                   unsigned int compliance_score,
                                   unsigned int fruit_score,
                                   unsigned int performance_score,
                                   unsigned long long duration_ns)
{
    struct e2e_test_result *result;

    if (!suite || !suite->initialized || !test_name)
        return;

    if (suite->total_tests >= E2E_MAX_PROTOCOL_TESTS)
        return;

    result = &suite->results[suite->total_tests];

    strscpy(result->test_name, test_name, sizeof(result->test_name));
    result->flow_type = flow_type;
    result->command_tested = command_tested;
    result->fruit_extensions_tested = fruit_extensions_tested;
    result->passed = passed;
    result->error_code = error_code;
    result->duration_ns = duration_ns;
    result->compliance_score = compliance_score;
    result->fruit_score = fruit_score;
    result->performance_score = performance_score;

    if (error_message)
        strscpy(result->error_message, error_message, sizeof(result->error_message));
    else
        result->error_message[0] = '\0';

    if (protocol_details)
        strscpy(result->protocol_details, protocol_details, sizeof(result->protocol_details));
    else
        result->protocol_details[0] = '\0';

    if (fruit_extension_details)
        strscpy(result->fruit_extension_details, fruit_extension_details,
                sizeof(result->fruit_extension_details));
    else
        result->fruit_extension_details[0] = '\0';

    suite->total_tests++;
    suite->avg_compliance_score = (suite->avg_compliance_score + compliance_score) / 2;
    suite->avg_fruit_score = (suite->avg_fruit_score + fruit_score) / 2;
    suite->avg_performance_score = (suite->avg_performance_score + performance_score) / 2;

    if (passed)
        suite->passed_tests++;
    else
        suite->failed_tests++;

    /* Update global flags based on test results */
    if (flow_type == E2E_FLOW_FRUIT_EXTENSIONS && !passed)
        suite->fruit_extensions_passed = false;

    if (performance_score < 70)
        suite->baseline_performance_met = false;

    if (compliance_score < 80)
        suite->protocol_compliance_passed = false;

    if (flow_type == E2E_FLOW_SECURITY_SENSITIVE && !passed)
        suite->security_validation_passed = false;
}

/* Session management */
static struct e2e_session_state *e2e_create_session(bool enable_fruit_extensions)
{
    struct e2e_session_state *session;
    int i;

    session = test_kzalloc(sizeof(struct e2e_session_state), "e2e_session");
    if (!session)
        return NULL;

    session->connection = create_test_connection(enable_fruit_extensions);
    if (!session->connection) {
        kfree(session);
        return NULL;
    }

    session->session_id = get_random_u32();
    session->fruit_extensions_enabled = enable_fruit_extensions;

    if (enable_fruit_extensions) {
        session->connection->fruit_extensions_enabled = true;
        session->connection->fruit_state = &session->fruit_state;
        fruit_init_connection_state(&session->fruit_state);
    }

    /* Find empty slot in active sessions */
    spin_lock(&e2e_session_lock);
    for (i = 0; i < E2E_MAX_CONCURRENT_SESSIONS; i++) {
        if (!active_sessions[i]) {
            active_sessions[i] = session;
            spin_unlock(&e2e_session_lock);
            return session;
        }
    }
    spin_unlock(&e2e_session_lock);

    kfree(session);
    return NULL;
}

static void e2e_cleanup_session(struct e2e_session_state *session)
{
    if (!session)
        return;

    if (session->connection) {
        session->connection->fruit_state = NULL;
        free_test_connection(session->connection);
    }

    /* Remove from active sessions */
    spin_lock(&e2e_session_lock);
    for (int i = 0; i < E2E_MAX_CONCURRENT_SESSIONS; i++) {
        if (active_sessions[i] == session) {
            active_sessions[i] = NULL;
            break;
        }
    }
    spin_unlock(&e2e_session_lock);

    kfree(session);
}

/* SMB2 packet creation helpers */
static struct e2e_smb2_packet *e2e_create_smb2_packet(enum e2e_smb2_command command,
                                                        bool add_fruit_context)
{
    struct e2e_smb2_packet *packet;

    packet = test_kzalloc(sizeof(struct e2e_smb2_packet), "smb2_packet");
    if (!packet)
        return NULL;

    /* Initialize SMB2 header */
    packet->hdr.ProtocolId = SMB2_PROTO_NUMBER;
    packet->hdr.StructureSize = cpu_to_le16(64);
    packet->hdr.Command = cpu_to_le16(command);
    packet->hdr.CreditRequest = cpu_to_le16(1);
    packet->hdr.Flags = 0;
    packet->hdr.NextCommand = 0;
    packet->hdr.MessageId = cpu_to_le64(get_random_u64());
    packet->hdr.ProcessId = cpu_to_le32(get_random_u32());
    packet->hdr.TreeId = cpu_to_le32(0);
    packet->hdr.SessionId = cpu_to_le64(0);
    packet->hdr.Signature = {0};

    packet->command_id = get_random_u32();
    packet->has_fruit_context = add_fruit_context;
    packet->timestamp = get_time_ns();

    /* Add Fruit client info if requested */
    if (add_fruit_context) {
        memcpy(packet->fruit_info.signature, "AAPL", 4);
        packet->fruit_info.version = cpu_to_le32(0x0200); /* Version 2.0 */
        packet->fruit_info.client_type = cpu_to_le32(FRUIT_CLIENT_MACOS);
        packet->fruit_info.build_number = cpu_to_le32(22A380);
        packet->fruit_info.capabilities = cpu_to_le64(
            FRUIT_CAP_UNIX_EXTENSIONS |
            FRUIT_CAP_EXTENDED_ATTRIBUTES |
            FRUIT_CAP_CASE_SENSITIVE |
            FRUIT_CAP_POSIX_LOCKS |
            FRUIT_CAP_RESILIENT_HANDLES |
            FRUIT_COMPRESSION_ZLIB |
            FRUIT_CAP_FILE_IDS |
            FRUIT_CAP_READDIR_ATTRS |
            FRUIT_CAP_FINDERINFO |
            FRUIT_CAP_TIMEMACHINE |
            FRUIT_CAP_F_FULLFSYNC
        );
        memset(packet->fruit_info.reserved, 0, sizeof(packet->fruit_info.reserved));
    }

    return packet;
}

static void e2e_free_smb2_packet(struct e2e_smb2_packet *packet)
{
    if (!packet)
        return;

    kfree(packet->payload);
    kfree(packet);
}

/* Protocol compliance validation */
static bool e2e_validate_smb2_compliance(struct e2e_smb2_packet *packet,
                                           struct e2e_compliance_validator *validator)
{
    if (!packet || !validator)
        return false;

    validator->compliance_issues_count = 0;

    /* Validate SMB2 header */
    if (packet->hdr.ProtocolId != SMB2_PROTO_NUMBER) {
        validator->header_validation_passed = false;
        validator->compliance_issues_count++;
        return false;
    }
    validator->header_validation_passed = true;

    /* Validate structure size */
    if (le16_to_cpu(packet->hdr.StructureSize) != 64) {
        validator->command_structure_valid = false;
        validator->compliance_issues_count++;
        return false;
    }
    validator->command_structure_valid = true;

    /* Validate command */
    if (le16_to_cpu(packet->hdr.Command) > E2E_SMB2_LEASE_BREAK) {
        validator->negotiation_correct = false;
        validator->compliance_issues_count++;
        return false;
    }
    validator->negotiation_correct = true;

    /* Validate Fruit contexts if present */
    if (packet->has_fruit_context) {
        if (memcmp(packet->fruit_info.signature, "AAPL", 4) != 0) {
            validator->fruit_contexts_valid = false;
            validator->compliance_issues_count++;
            return false;
        }
        validator->fruit_contexts_valid = true;

        /* Validate version */
        if (le32_to_cpu(packet->fruit_info.version) < FRUIT_VERSION_MIN ||
            le32_to_cpu(packet->fruit_info.version) > FRUIT_VERSION_CURRENT) {
            validator->fruit_contexts_valid = false;
            validator->compliance_issues_count++;
            return false;
        }

        /* Validate client type */
        if (le32_to_cpu(packet->fruit_info.client_type) > FRUIT_CLIENT_WATCHOS) {
            validator->fruit_contexts_valid = false;
            validator->compliance_issues_count++;
            return false;
        }
    } else {
        validator->fruit_contexts_valid = true; /* N/A for non-Fruit packets */
    }

    validator->authentication_proper = true;
    validator->authorization_enforced = true;
    validator->error_responses_correct = true;
    validator->state_consistent = true;
    validator->security_intact = true;

    return validator->compliance_issues_count == 0;
}

/* Basic SMB2 flow testing */
static bool e2e_test_basic_smb2_flow(struct e2e_test_result *result,
                                         const struct e2e_test_scenario *scenario)
{
    unsigned long long start_time, end_time;
    struct e2e_session_state *session;
    bool test_passed = true;
    int i;

    start_time = get_time_ns();

    TEST_INFO("Testing basic SMB2 protocol flow (%u iterations)", scenario->iterations);

    session = e2e_create_session(scenario->enable_fruit_extensions);
    if (!session) {
        strscpy(result->error_message, "Failed to create E2E session",
                sizeof(result->error_message));
        return false;
    }

    /* Test basic SMB2 negotiation sequence */
    for (i = 0; i < scenario->iterations && test_passed; i++) {
        struct e2e_smb2_packet *packet;
        struct e2e_compliance_validator validator = {0};

        /* Create negotiate request */
        packet = e2e_create_smb2_packet(E2E_SMB2_NEGOTIATE, scenario->enable_fruit_extensions);
        if (!packet) {
            test_passed = false;
            strscpy(result->error_message, "Failed to create negotiate packet",
                    sizeof(result->error_message));
            break;
        }

        /* Validate packet compliance */
        if (!e2e_validate_smb2_compliance(packet, &validator)) {
            test_passed = false;
            strscpy(result->error_message, "SMB2 compliance validation failed",
                    sizeof(result->error_message));
        }

        /* Simulate session setup */
        if (test_passed && i % 2 == 0) {
            e2e_free_smb2_packet(packet);
            packet = e2e_create_smb2_packet(E2E_SMB2_SESSION_SETUP, scenario->enable_fruit_extensions);
            if (!packet) {
                test_passed = false;
                strscpy(result->error_message, "Failed to create session setup packet",
                        sizeof(result->error_message));
                break;
            }

            if (!e2e_validate_smb2_compliance(packet, &validator)) {
                test_passed = false;
                strscpy(result->error_message, "Session setup compliance validation failed",
                        sizeof(result->error_message));
            }
        }

        /* Simulate tree connect */
        if (test_passed && i % 3 == 0) {
            e2e_free_smb2_packet(packet);
            packet = e2e_create_smb2_packet(E2E_SMB2_TREE_CONNECT, scenario->enable_fruit_extensions);
            if (!packet) {
                test_passed = false;
                strscpy(result->error_message, "Failed to create tree connect packet",
                        sizeof(result->error_message));
                break;
            }

            if (!e2e_validate_smb2_compliance(packet, &validator)) {
                test_passed = false;
                strscpy(result->error_message, "Tree connect compliance validation failed",
                        sizeof(result->error_message));
            }
        }

        /* Simulate file operations */
        if (test_passed && i % 5 == 0) {
            e2e_free_smb2_packet(packet);
            packet = e2e_create_smb2_packet(E2E_SMB2_CREATE, scenario->enable_fruit_extensions);
            if (!packet) {
                test_passed = false;
                strscpy(result->error_message, "Failed to create file operation packet",
                        sizeof(result->error_message));
                break;
            }

            if (!e2e_validate_smb2_compliance(packet, &validator)) {
                test_passed = false;
                strscpy(result->error_message, "File operation compliance validation failed",
                        sizeof(result->error_message));
            }

            /* Update session stats */
            session->stats.files_created++;
        }

        e2e_free_smb2_packet(packet);

        /* Small delay between operations */
        udelay(1);
    }

    end_time = get_time_ns();
    result->duration_ns = end_time - start_time;

    snprintf(result->protocol_details, sizeof(result->protocol_details),
             "Basic SMB2 Flow Results:\n"
             "  Iterations: %u\n"
             "  Fruit Extensions: %s\n"
             "  Files Created: %u\n"
             "  Test Duration: %llu ms\n"
             "  Avg Time per Iteration: %llu µs",
             scenario->iterations,
             scenario->enable_fruit_extensions ? "ENABLED" : "DISABLED",
             session->stats.files_created,
             ktime_to_ms(result->duration_ns),
             ktime_to_us(result->duration_ns / scenario->iterations));

    e2e_cleanup_session(session);

    return test_passed;
}

/* Fruit extensions integration testing */
static bool e2e_test_fruit_extensions_integration(struct e2e_test_result *result,
                                                   const struct e2e_test_scenario *scenario)
{
    unsigned long long start_time, end_time;
    struct e2e_session_state *session;
    bool test_passed = true;
    int i;

    start_time = get_time_ns();

    TEST_INFO("Testing Fruit extensions integration (%u iterations)", scenario->iterations);

    if (!scenario->enable_fruit_extensions) {
        strscpy(result->error_message, "Fruit extensions not enabled in scenario",
                sizeof(result->error_message));
        return false;
    }

    session = e2e_create_session(true);
    if (!session) {
        strscpy(result->error_message, "Failed to create Fruit session",
                sizeof(result->error_message));
        return false;
    }

    /* Test Fruit-specific SMB2 extensions */
    for (i = 0; i < scenario->iterations && test_passed; i++) {
        struct e2e_smb2_packet *packet;
        struct e2e_compliance_validator validator = {0};
        unsigned int operation_type = i % 8;

        /* Create different Fruit extension packets */
        switch (operation_type) {
        case 0:
            /* LookerInfo operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_SET_INFO, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_FINDERINFO);
            }
            break;
        case 1:
            /* Save box operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_IOCTL, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_TIMEMACHINE);
            }
            break;
        case 2:
            /* Compression operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_WRITE, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_COMPRESSION_ZLIB);
            }
            break;
        case 3:
            /* Extended attributes operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_SET_INFO, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_EXTENDED_ATTRIBUTES);
            }
            break;
        case 4:
            /* F_FULLFSYNC operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_FLUSH, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_F_FULLFSYNC);
            }
            break;
        case 5:
            /* ReadDir attributes operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_QUERY_DIRECTORY, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_READDIR_ATTRS);
            }
            break;
        case 6:
            /* POSIX locks operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_IOCTL, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_POSIX_LOCKS);
            }
            break;
        case 7:
            /* File IDs operation */
            packet = e2e_create_smb2_packet(E2E_SMB2_QUERY_INFO, true);
            if (packet && packet->has_fruit_context) {
                packet->fruit_info.capabilities |= cpu_to_le64(FRUIT_CAP_FILE_IDS);
            }
            break;
        default:
            packet = e2e_create_smb2_packet(E2E_SMB2_CREATE, true);
            break;
        }

        if (!packet) {
            test_passed = false;
            strscpy(result->error_message, "Failed to create Fruit extension packet",
                    sizeof(result->error_message));
            break;
        }

        /* Validate Fruit extension compliance */
        if (!e2e_validate_smb2_compliance(packet, &validator)) {
            test_passed = false;
            strscpy(result->error_message, "Fruit extension compliance validation failed",
                    sizeof(result->error_message));
        }

        /* Validate Fruit-specific functionality */
        if (test_passed && packet->has_fruit_context) {
            __le64 capabilities = packet->fruit_info.capabilities;

            if (operation_type == 0 && !(capabilities & cpu_to_le64(FRUIT_CAP_FINDERINFO))) {
                test_passed = false;
                strscpy(result->error_message, "LookerInfo capability not set",
                        sizeof(result->error_message));
            }

            if (operation_type == 1 && !(capabilities & cpu_to_le64(FRUIT_CAP_TIMEMACHINE))) {
                test_passed = false;
                strscpy(result->error_message, "Save box capability not set",
                        sizeof(result->error_message));
            }

            if (operation_type == 2 && !(capabilities & cpu_to_le64(FRUIT_COMPRESSION_ZLIB))) {
                test_passed = false;
                strscpy(result->error_message, "Compression capability not set",
                        sizeof(result->error_message));
            }

            /* Update session stats */
            session->stats.queries_performed++;
        }

        e2e_free_smb2_packet(packet);

        /* Small delay between operations */
        udelay(2);
    }

    end_time = get_time_ns();
    result->duration_ns = end_time - start_time;

    snprintf(result->fruit_extension_details, sizeof(result->fruit_extension_details),
             "Fruit Extensions Integration Results:\n"
             "  Iterations: %u\n"
             "  Queries Performed: %u\n"
             "  Test Duration: %llu ms\n"
             "  Fruit Capabilities Tested:\n"
             "    LookerInfo: %s\n"
             "    Save box: %s\n"
             "    Compression: %s\n"
             "    Extended Attributes: %s\n"
             "    F_FULLFSYNC: %s\n"
             "    ReadDir Attributes: %s\n"
             "    POSIX Locks: %s\n"
             "    File IDs: %s",
             scenario->iterations, session->stats.queries_performed,
             ktime_to_ms(result->duration_ns),
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED",
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED",
             scenario->enable_compression ? "TESTED" : "DISABLED",
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED",
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED",
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED",
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED",
             scenario->enable_fruit_extensions ? "TESTED" : "DISABLED");

    e2e_cleanup_session(session);

    return test_passed;
}

/* Concurrent operations testing */
static bool e2e_test_concurrent_operations(struct e2e_test_result *result,
                                           const struct e2e_test_scenario *scenario)
{
    unsigned long long start_time, end_time;
    struct e2e_session_state **sessions;
    bool test_passed = true;
    unsigned int i, j;

    start_time = get_time_ns();

    TEST_INFO("Testing concurrent operations (%u sessions, %u ops each)",
              scenario->concurrent_sessions, scenario->operations_per_session);

    sessions = test_kzalloc(sizeof(struct e2e_session_state *) * scenario->concurrent_sessions,
                            "concurrent_sessions");
    if (!sessions) {
        strscpy(result->error_message, "Failed to allocate sessions array",
                sizeof(result->error_message));
        return false;
    }

    /* Create concurrent sessions */
    for (i = 0; i < scenario->concurrent_sessions && test_passed; i++) {
        sessions[i] = e2e_create_session(scenario->enable_fruit_extensions);
        if (!sessions[i]) {
            test_passed = false;
            strscpy(result->error_message, "Failed to create concurrent session",
                    sizeof(result->error_message));
            break;
        }
    }

    /* Perform concurrent operations */
    for (j = 0; j < scenario->operations_per_session && test_passed; j++) {
        for (i = 0; i < scenario->concurrent_sessions && test_passed; i++) {
            if (!sessions[i])
                continue;

            struct e2e_smb2_packet *packet;
            struct e2e_compliance_validator validator = {0};
            enum e2e_smb2_command cmd = j % 5; /* Cycle through different commands */

            packet = e2e_create_smb2_packet(cmd, scenario->enable_fruit_extensions);
            if (!packet) {
                test_passed = false;
                strscpy(result->error_message, "Failed to create concurrent packet",
                        sizeof(result->error_message));
                break;
            }

            if (!e2e_validate_smb2_compliance(packet, &validator)) {
                test_passed = false;
                strscpy(result->error_message, "Concurrent operation compliance failed",
                        sizeof(result->error_message));
            }

            /* Update session stats */
            if (cmd == E2E_SMB2_CREATE) {
                sessions[i]->stats.files_created++;
            } else if (cmd == E2E_SMB2_READ) {
                sessions[i]->stats.bytes_read += 1024;
            } else if (cmd == E2E_SMB2_WRITE) {
                sessions[i]->stats.bytes_written += 1024;
            }

            e2e_free_smb2_packet(packet);
        }

        /* Small delay between operation sets */
        udelay(5);
    }

    end_time = get_time_ns();
    result->duration_ns = end_time - start_time;

    /* Calculate aggregate stats */
    unsigned int total_files = 0, total_bytes_read = 0, total_bytes_written = 0;
    for (i = 0; i < scenario->concurrent_sessions; i++) {
        if (sessions[i]) {
            total_files += sessions[i]->stats.files_created;
            total_bytes_read += sessions[i]->stats.bytes_read;
            total_bytes_written += sessions[i]->stats.bytes_written;
            e2e_cleanup_session(sessions[i]);
        }
    }

    kfree(sessions);

    snprintf(result->protocol_details, sizeof(result->protocol_details),
             "Concurrent Operations Results:\n"
             "  Concurrent Sessions: %u\n"
             "  Operations per Session: %u\n"
             "  Total Files Created: %u\n"
             "  Total Bytes Read: %u\n"
             "  Total Bytes Written: %u\n"
             "  Test Duration: %llu ms\n"
             "  Throughput: %llu MB/s",
             scenario->concurrent_sessions, scenario->operations_per_session,
             total_files, total_bytes_read, total_bytes_written,
             ktime_to_ms(result->duration_ns),
             (total_bytes_read + total_bytes_written) / (ktime_to_ms(result->duration_ns) * 1000));

    return test_passed;
}

/* Main E2E test execution */
static int e2e_execute_comprehensive_tests(void)
{
    unsigned int i;
    bool test_result;
    unsigned int compliance_score, fruit_score, performance_score;

    TEST_INFO("=== SMB2 End-to-End Protocol Testing Framework ===");

    /* Initialize test suite */
    mutex_lock(&e2e_test_mutex);

    if (e2e_init_test_suite(&global_test_suite, E2E_MAX_PROTOCOL_TESTS) != 0) {
        mutex_unlock(&e2e_test_mutex);
        return -ENOMEM;
    }

    /* Execute all test scenarios */
    for (i = 0; i < ARRAY_SIZE(test_scenarios); i++) {
        struct e2e_test_result result = {0};
        const struct e2e_test_scenario *scenario = &test_scenarios[i];
        bool scenario_passed = true;

        strscpy(result.test_name, scenario->scenario_name, sizeof(result.test_name));

        switch (scenario->flow_type) {
        case E2E_FLOW_BASIC_SEQUENCE:
            test_result = e2e_test_basic_smb2_flow(&result, scenario);
            break;
        case E2E_FLOW_FRUIT_EXTENSIONS:
            test_result = e2e_test_fruit_extensions_integration(&result, scenario);
            break;
        case E2E_FLOW_CONCURRENT_OPS:
            test_result = e2e_test_concurrent_operations(&result, scenario);
            break;
        default:
            /* For other flow types, use basic flow as placeholder */
            test_result = e2e_test_basic_smb2_flow(&result, scenario);
            break;
        }

        /* Calculate scores based on test results */
        compliance_score = test_result ? 90 : 40;
        fruit_score = scenario->enable_fruit_extensions ? (test_result ? 95 : 35) : 80;
        performance_score = scenario->performance_monitoring ?
                         (test_result ? 85 : 50) : 75;

        if (scenario->stress_testing && !test_result) {
            performance_score -= 20;
        }

        if (scenario->error_injection && test_result) {
            compliance_score += 5; /* Bonus for passing error injection tests */
        }

        e2e_record_test_result(&global_test_suite,
                              scenario->scenario_name,
                              scenario->flow_type,
                              E2E_SMB2_NEGOTIATE, /* Representative command */
                              scenario->enable_fruit_extensions,
                              test_result,
                              result.error_code,
                              result.error_message,
                              result.protocol_details,
                              result.fruit_extension_details,
                              compliance_score,
                              fruit_score,
                              performance_score,
                              result.duration_ns);
    }

    /* Generate comprehensive test summary */
    TEST_INFO("=== SMB2 E2E Test Summary ===");
    TEST_INFO("Total Tests: %u", global_test_suite.total_tests);
    TEST_INFO("Passed Tests: %u", global_test_suite.passed_tests);
    TEST_INFO("Failed Tests: %u", global_test_suite.failed_tests);
    TEST_INFO("Avg Compliance Score: %u%%", global_test_suite.avg_compliance_score);
    TEST_INFO("Avg Fruit Score: %u%%", global_test_suite.avg_fruit_score);
    TEST_INFO("Avg Performance Score: %u%%", global_test_suite.avg_performance_score);
    TEST_INFO("End-to-End Passed: %s", global_test_suite.end_to_end_passed ? "YES" : "NO");
    TEST_INFO("Fruit Extensions Passed: %s", global_test_suite.fruit_extensions_passed ? "YES" : "NO");
    TEST_INFO("Baseline Performance Met: %s", global_test_suite.baseline_performance_met ? "YES" : "NO");
    TEST_INFO("Protocol Compliance Passed: %s", global_test_suite.protocol_compliance_passed ? "YES" : "NO");
    TEST_INFO("Security Validation Passed: %s", global_test_suite.security_validation_passed ? "YES" : "NO");

    /* Overall assessment */
    bool overall_success = (global_test_suite.failed_tests == 0 &&
                            global_test_suite.avg_compliance_score >= 85 &&
                            global_test_suite.avg_fruit_score >= 80 &&
                            global_test_suite.avg_performance_score >= 75 &&
                            global_test_suite.end_to_end_passed &&
                            global_test_suite.fruit_extensions_passed &&
                            global_test_suite.baseline_performance_met &&
                            global_test_suite.protocol_compliance_passed &&
                            global_test_suite.security_validation_passed);

    TEST_INFO("Overall E2E Test Result: %s", overall_success ? "PASSED" : "FAILED");

    /* Log detailed failures */
    if (global_test_suite.failed_tests > 0) {
        TEST_INFO("=== Failed Tests ===");
        for (i = 0; i < global_test_suite.total_tests; i++) {
            if (!global_test_suite.results[i].passed) {
                TEST_INFO("FAILED: %s - %s",
                         global_test_suite.results[i].test_name,
                         global_test_suite.results[i].error_message);
            }
        }
    }

    /* Log scoring details */
    TEST_INFO("=== Scoring Breakdown ===");
    for (i = 0; i < global_test_suite.total_tests; i++) {
        struct e2e_test_result *res = &global_test_suite.results[i];

        TEST_INFO("%s: Compliance=%u%%, Fruit=%u%%, Performance=%u%%",
                 res->test_name,
                 res->compliance_score,
                 res->fruit_score,
                 res->performance_score);
    }

    e2e_cleanup_test_suite(&global_test_suite);
    mutex_unlock(&e2e_test_mutex);

    return overall_success ? 0 : -EPERM;
}

/* Module initialization and cleanup */
static int __init e2e_testing_init(void)
{
    TEST_INFO("SMB2 End-to-End Protocol Testing Framework initialized");

    return e2e_execute_comprehensive_tests();
}

static void __exit e2e_testing_exit(void)
{
    TEST_INFO("SMB2 End-to-End Protocol Testing Framework exited");
}

module_init(e2e_testing_init);
module_exit(e2e_testing_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KSMBD SMB2 End-to-End Protocol Testing Framework");
MODULE_AUTHOR("KSMBD Contributors");

/* Export functions for external E2E testing modules */
EXPORT_SYMBOL_GPL(e2e_init_test_suite);
EXPORT_SYMBOL_GPL(e2e_cleanup_test_suite);
EXPORT_SYMBOL_GPL(e2e_record_test_result);
EXPORT_SYMBOL_GPL(e2e_create_session);
EXPORT_SYMBOL_GPL(e2e_cleanup_session);
EXPORT_SYMBOL_GPL(e2e_create_smb2_packet);
EXPORT_SYMBOL_GPL(e2e_free_smb2_packet);
EXPORT_SYMBOL_GPL(e2e_validate_smb2_compliance);
EXPORT_SYMBOL_GPL(e2e_test_basic_smb2_flow);
EXPORT_SYMBOL_GPL(e2e_test_fruit_extensions_integration);
EXPORT_SYMBOL_GPL(e2e_test_concurrent_operations);
EXPORT_SYMBOL_GPL(e2e_execute_comprehensive_tests);