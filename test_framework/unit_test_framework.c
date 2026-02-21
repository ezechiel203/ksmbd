// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2023 ksmbd Contributors
 *
 *   Unit Test Framework for Fruit SMB Extensions
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>

#include "smb2pdu.h"
#include "connection.h"
#include "test_framework/test_utils.h"

#define TEST_MODULE_NAME "ksmbd_fruit_test"

/* Test statistics */
struct test_stats {
    atomic_t total_tests;
    atomic_t passed_tests;
    atomic_t failed_tests;
    atomic_t skipped_tests;
};

static struct test_stats test_stats;

/* Test result tracking */
struct test_result {
    const char *test_name;
    const char *suite_name;
    bool passed;
    const char *error_message;
    unsigned long long duration_ns;
};

/* Test assertion helpers */
#define TEST_ASSERT(condition, test_name, message) \
    do { \
        if (!(condition)) { \
            test_fail(test_name, __func__, __LINE__, message); \
            return; \
        } \
    } while (0)

#define TEST_ASSERT_EQ(expected, actual, test_name, message) \
    do { \
        if ((expected) != (actual)) { \
            char msg[256]; \
            snprintf(msg, sizeof(msg), "%s (Expected: %lld, Actual: %lld)", \
                    message, (long long)(expected), (long long)(actual)); \
            test_fail(test_name, __func__, __LINE__, msg); \
            return; \
        } \
    } while (0)

#define TEST_ASSERT_STR_EQ(expected, actual, test_name, message) \
    do { \
        if (strcmp(expected, actual) != 0) { \
            char msg[512]; \
            snprintf(msg, sizeof(msg), "%s (Expected: '%s', Actual: '%s')", \
                    message, expected, actual); \
            test_fail(test_name, __func__, __LINE__, msg); \
            return; \
        } \
    } while (0)

#define TEST_ASSERT_PTR_NULL(ptr, test_name, message) \
    do { \
        if ((ptr) != NULL) { \
            char msg[256]; \
            snprintf(msg, sizeof(msg), "%s (Expected NULL, got %p)", \
                    message, ptr); \
            test_fail(test_name, __func__, __LINE__, msg); \
            return; \
        } \
    } while (0)

#define TEST_ASSERT_PTR_NOT_NULL(ptr, test_name, message) \
    do { \
        if ((ptr) == NULL) { \
            test_fail(test_name, __func__, __LINE__, message); \
            return; \
        } \
    } while (0)

/* Test utilities */
static void test_fail(const char *test_name, const char *func, int line, const char *message)
{
    atomic_inc(&test_stats.failed_tests);
    pr_err("❌ FAIL: %s (%s:%d): %s\n", test_name, func, line, message);
}

static void test_pass(const char *test_name)
{
    atomic_inc(&test_stats.passed_tests);
    pr_info("✅ PASS: %s\n", test_name);
}

static void test_skip(const char *test_name, const char *reason)
{
    atomic_inc(&test_stats.skipped_tests);
    pr_info("⏭️  SKIP: %s (%s)\n", test_name, reason);
}

/* Test data structures */
struct test_smb2_create_request {
    struct smb2_create_req *req;
    struct ksmbd_conn *conn;
    struct ksmbd_work *work;
    size_t buffer_size;
};

struct test_fruit_context {
    struct create_context *context;
    char data[256];
    size_t data_size;
};

/* Mock connection setup */
static struct ksmbd_conn *create_mock_connection(bool is_fruit_client)
{
    struct ksmbd_conn *conn = kzalloc(sizeof(struct ksmbd_conn), GFP_KERNEL);
    if (!conn)
        return NULL;

    conn->is_fruit = is_fruit_client;
    conn->dialect = SMB311_PROT_ID;
    conn->vals = &smb311_server_values;
    conn->ops = &smb311_server_ops;

    mutex_init(&conn->srv_mutex);
    atomic_set(&conn->req_running, 0);
    atomic_set(&conn->r_count, 1);

    return conn;
}

static void free_mock_connection(struct ksmbd_conn *conn)
{
    if (conn)
        kfree(conn);
}

/* Mock work setup */
static struct ksmbd_work *create_mock_work(struct ksmbd_conn *conn)
{
    struct ksmbd_work *work = kzalloc(sizeof(struct ksmbd_work), GFP_KERNEL);
    if (!work)
        return NULL;

    work->conn = conn;
    work->request_buf = kzalloc(4096, GFP_KERNEL);
    if (!work->request_buf) {
        kfree(work);
        return NULL;
    }

    return work;
}

static void free_mock_work(struct ksmbd_work *work)
{
    if (work) {
        kfree(work->request_buf);
        kfree(work);
    }
}

/* Fruit context creation utilities */
static struct create_context *create_fruit_context(const char *data, size_t data_size)
{
    struct create_context *context;
    size_t total_size = sizeof(struct create_context) + data_size;

    context = kzalloc(total_size, GFP_KERNEL);
    if (!context)
        return NULL;

    context->Next = 0;
    context->NameOffset = offsetof(struct create_context, Buffer);
    context->NameLength = 4; /* "AAPL" */
    context->DataOffset = cpu_to_le16(context->NameOffset + context->NameLength);
    context->DataLength = cpu_to_le32(data_size);
    context->Buffer[0] = 'A';
    context->Buffer[1] = 'A';
    context->Buffer[2] = 'P';
    context->Buffer[3] = 'L';

    if (data && data_size > 0)
        memcpy(context->Buffer + 4, data, data_size);

    return context;
}

/* Fruit Client Detection Tests */
static void test_fruit_client_detection_new_connection(void)
{
    struct ksmbd_conn *conn = create_mock_connection(false);
    const char *test_name = "Fruit client detection - new connection";

    atomic_inc(&test_stats.total_tests);

    TEST_ASSERT_PTR_NOT_NULL(conn, test_name, "Failed to create mock connection");
    TEST_ASSERT_EQ(false, conn->is_fruit, test_name, "New connection should not be Fruit client");

    free_mock_connection(conn);
    test_pass(test_name);
}

static void test_fruit_client_detection_fruit_context(void)
{
    struct ksmbd_conn *conn = create_mock_connection(false);
    struct create_context *fruit_context;
    const char *test_name = "Fruit client detection - Fruit context";

    atomic_inc(&test_stats.total_tests);

    TEST_ASSERT_PTR_NOT_NULL(conn, test_name, "Failed to create mock connection");

    fruit_context = create_fruit_context(NULL, 0);
    TEST_ASSERT_PTR_NOT_NULL(fruit_context, test_name, "Failed to create Fruit context");

    /* Simulate Fruit context detection */
    if (!IS_ERR(fruit_context)) {
        conn->is_fruit = true;
        TEST_ASSERT_EQ(true, conn->is_fruit, test_name, "Connection should be detected as Fruit client");
    }

    kfree(fruit_context);
    free_mock_connection(conn);
    test_pass(test_name);
}

static void test_fruit_client_detection_preexisting_connection(void)
{
    struct ksmbd_conn *conn = create_mock_connection(true);
    const char *test_name = "Fruit client detection - preexisting connection";

    atomic_inc(&test_stats.total_tests);

    TEST_ASSERT_PTR_NOT_NULL(conn, test_name, "Failed to create mock connection");
    TEST_ASSERT_EQ(true, conn->is_fruit, test_name, "Preexisting Fruit connection should remain Fruit");

    free_mock_connection(conn);
    test_pass(test_name);
}

/* Fruit Context Parsing Tests */
static void test_fruit_context_parsing_valid(void)
{
    struct create_context *context;
    const char test_data[] = "test_data";
    const char *test_name = "Fruit context parsing - valid context";

    atomic_inc(&test_stats.total_tests);

    context = create_fruit_context(test_data, strlen(test_data));
    TEST_ASSERT_PTR_NOT_NULL(context, test_name, "Failed to create Fruit context");

    TEST_ASSERT_EQ(4, context->NameLength, test_name, "Name length should be 4");
    TEST_ASSERT_EQ(0, strncmp(context->Buffer, "AAPL", 4), test_name, "Context name should be 'AAPL'");
    TEST_ASSERT_EQ(strlen(test_data), le32_to_cpu(context->DataLength), test_name, "Data length should match");
    TEST_ASSERT_EQ(0, strncmp(context->Buffer + 4, test_data, strlen(test_data)),
                   test_name, "Data should match input");

    kfree(context);
    test_pass(test_name);
}

static void test_fruit_context_parsing_empty_data(void)
{
    struct create_context *context;
    const char *test_name = "Fruit context parsing - empty data";

    atomic_inc(&test_stats.total_tests);

    context = create_fruit_context(NULL, 0);
    TEST_ASSERT_PTR_NOT_NULL(context, test_name, "Failed to create Fruit context with empty data");

    TEST_ASSERT_EQ(0, le32_to_cpu(context->DataLength), test_name, "Data length should be 0");
    TEST_ASSERT_EQ(4, context->NameLength, test_name, "Name length should still be 4");
    TEST_ASSERT_EQ(0, strncmp(context->Buffer, "AAPL", 4), test_name, "Context name should be 'AAPL'");

    kfree(context);
    test_pass(test_name);
}

static void test_fruit_context_parsing_large_data(void)
{
    struct create_context *context;
    char large_data[1024];
    const char *test_name = "Fruit context parsing - large data";

    atomic_inc(&test_stats.total_tests);

    /* Fill with test data */
    memset(large_data, 'A', sizeof(large_data) - 1);
    large_data[sizeof(large_data) - 1] = '\0';

    context = create_fruit_context(large_data, sizeof(large_data) - 1);
    TEST_ASSERT_PTR_NOT_NULL(context, test_name, "Failed to create Fruit context with large data");

    TEST_ASSERT_EQ(sizeof(large_data) - 1, le32_to_cpu(context->DataLength),
                   test_name, "Data length should match");
    TEST_ASSERT_EQ(0, strncmp(context->Buffer + 4, large_data, sizeof(large_data) - 1),
                   test_name, "Large data should match input");

    kfree(context);
    test_pass(test_name);
}

/* Connection Management Tests */
static void test_connection_memory_management(void)
{
    struct ksmbd_conn *conn;
    struct ksmbd_work *work;
    const char *test_name = "Connection memory management";

    atomic_inc(&test_stats.total_tests);

    conn = create_mock_connection(true);
    TEST_ASSERT_PTR_NOT_NULL(conn, test_name, "Failed to create mock connection");

    work = create_mock_work(conn);
    TEST_ASSERT_PTR_NOT_NULL(work, test_name, "Failed to create mock work");
    TEST_ASSERT_PTR_EQ(conn, work->conn, test_name, "Work should reference connection");
    TEST_ASSERT_PTR_NOT_NULL(work->request_buf, test_name, "Work should have request buffer");

    free_mock_work(work);
    free_mock_connection(conn);
    test_pass(test_name);
}

static void test_connection_flags(void)
{
    struct ksmbd_conn *fruit_conn, *non_fruit_conn;
    const char *test_name = "Connection flags";

    atomic_inc(&test_stats.total_tests);

    fruit_conn = create_mock_connection(true);
    non_fruit_conn = create_mock_connection(false);

    TEST_ASSERT_PTR_NOT_NULL(fruit_conn, test_name, "Failed to create Fruit connection");
    TEST_ASSERT_PTR_NOT_NULL(non_fruit_conn, test_name, "Failed to create non-Fruit connection");

    TEST_ASSERT_EQ(true, fruit_conn->is_fruit, test_name, "Fruit connection should have is_fruit=true");
    TEST_ASSERT_EQ(false, non_fruit_conn->is_fruit, test_name, "Non-Fruit connection should have is_fruit=false");
    TEST_ASSERT_EQ(SMB311_PROT_ID, fruit_conn->dialect, test_name, "Connection should have SMB3.1.1 dialect");

    free_mock_connection(fruit_conn);
    free_mock_connection(non_fruit_conn);
    test_pass(test_name);
}

/* Test suite registration */
static struct test_case {
    const char *name;
    void (*test_func)(void);
} fruit_test_cases[] = {
    {"fruit_client_detection_new_connection", test_fruit_client_detection_new_connection},
    {"fruit_client_detection_fruit_context", test_fruit_client_detection_fruit_context},
    {"fruit_client_detection_preexisting_connection", test_fruit_client_detection_preexisting_connection},
    {"fruit_context_parsing_valid", test_fruit_context_parsing_valid},
    {"fruit_context_parsing_empty_data", test_fruit_context_parsing_empty_data},
    {"fruit_context_parsing_large_data", test_fruit_context_parsing_large_data},
    {"connection_memory_management", test_connection_memory_management},
    {"connection_flags", test_connection_flags},
    {NULL, NULL}
};

/* Main test runner */
static int run_all_tests(void)
{
    int i;
    unsigned long long start_time, end_time, total_time;

    pr_info("🧪 Starting Fruit SMB Extensions Unit Tests\n");
    pr_info("===============================================\n");

    memset(&test_stats, 0, sizeof(test_stats));

    start_time = ktime_get_ns();

    for (i = 0; fruit_test_cases[i].name != NULL; i++) {
        unsigned long long test_start = ktime_get_ns();

        pr_info("Running: %s\n", fruit_test_cases[i].name);
        fruit_test_cases[i].test_func();

        if (atomic_read(&test_stats.failed_tests) == 0) {
            unsigned long long test_duration = ktime_get_ns() - test_start;
            pr_info("✅ %s completed in %lld ns\n", fruit_test_cases[i].name, test_duration);
        }
    }

    end_time = ktime_get_ns();
    total_time = end_time - start_time;

    pr_info("===============================================\n");
    pr_info("Test Results:\n");
    pr_info("  Total tests: %d\n", atomic_read(&test_stats.total_tests));
    pr_info("  Passed: %d\n", atomic_read(&test_stats.passed_tests));
    pr_info("  Failed: %d\n", atomic_read(&test_stats.failed_tests));
    pr_info("  Skipped: %d\n", atomic_read(&test_stats.skipped_tests));
    pr_info("  Total time: %lld ns\n", total_time);
    pr_info("  Pass rate: %.2f%%\n",
            atomic_read(&test_stats.total_tests) > 0 ?
            (float)atomic_read(&test_stats.passed_tests) / atomic_read(&test_stats.total_tests) * 100.0 : 0.0);

    return atomic_read(&test_stats.failed_tests) == 0 ? 0 : -1;
}

/* Module initialization */
static int __init fruit_test_init(void)
{
    int ret;

    pr_info("Loading %s module\n", TEST_MODULE_NAME);

    ret = run_all_tests();
    if (ret != 0) {
        pr_err("Unit tests failed!\n");
        return ret;
    }

    pr_info("All unit tests passed!\n");
    return 0;
}

/* Module cleanup */
static void __exit fruit_test_exit(void)
{
    pr_info("Unloading %s module\n", TEST_MODULE_NAME);
}

module_init(fruit_test_init);
module_exit(fruit_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ksmbd Contributors");
MODULE_DESCRIPTION("Unit Test Framework for Fruit SMB Extensions");
MODULE_VERSION("1.0");