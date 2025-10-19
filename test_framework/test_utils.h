/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2023 ksmbd Contributors
 *
 *   Test Utilities for Apple SMB Extensions Testing
 */

#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/time.h>
#include "connection.h"
#include "smb2pdu.h"

/* Test logging macros */
#define TEST_LOG(level, msg, ...) \
    printk(KERN_##level "TEST: " msg "\n", ##__VA_ARGS__)

#define TEST_INFO(msg, ...) TEST_LOG(INFO, msg, ##__VA_ARGS__)
#define TEST_WARN(msg, ...) TEST_LOG(WARNING, msg, ##__VA_ARGS__)
#define TEST_ERROR(msg, ...) TEST_LOG(ERR, msg, ##__VA_ARGS__)

/* Test timing utilities */
static inline unsigned long long get_time_ns(void)
{
    return ktime_get_ns();
}

static inline void start_timer(unsigned long long *start)
{
    *start = get_time_ns();
}

static inline unsigned long long end_timer(unsigned long long start)
{
    return get_time_ns() - start;
}

static inline void log_time(const char *test_name, unsigned long long duration_ns)
{
    if (duration_ns < 1000) {
        TEST_INFO("%s: %lld ns", test_name, duration_ns);
    } else if (duration_ns < 1000000) {
        TEST_INFO("%s: %lld µs", test_name, duration_ns / 1000);
    } else if (duration_ns < 1000000000) {
        TEST_INFO("%s: %lld ms", test_name, duration_ns / 1000000);
    } else {
        TEST_INFO("%s: %.2f s", test_name, (double)duration_ns / 1000000000.0);
    }
}

/* Memory allocation utilities */
static inline void *test_kzalloc(size_t size, const char *alloc_name)
{
    void *ptr = kzalloc(size, GFP_KERNEL);
    if (!ptr) {
        TEST_ERROR("Failed to allocate %zu bytes for %s", size, alloc_name);
    }
    return ptr;
}

static inline void *test_kvmalloc(size_t size, const char *alloc_name)
{
    void *ptr = vmalloc(size);
    if (!ptr) {
        TEST_ERROR("Failed to allocate %zu bytes for %s", size, alloc_name);
    } else {
        memset(ptr, 0, size);
    }
    return ptr;
}

/* Test data generation utilities */
static inline void generate_random_string(char *buffer, size_t length)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t i;

    for (i = 0; i < length - 1; i++) {
        buffer[i] = charset[get_random_u32() % (sizeof(charset) - 1)];
    }
    buffer[length - 1] = '\0';
}

static inline void generate_random_data(unsigned char *buffer, size_t length)
{
    get_random_bytes(buffer, length);
}

/* Test assertion helpers */
#define ASSERT_EQ(expected, actual, msg) \
    do { \
        if ((expected) != (actual)) { \
            TEST_ERROR("%s: Expected %lld, got %lld", (msg), \
                      (long long)(expected), (long long)(actual)); \
            return false; \
        } \
    } while (0)

#define ASSERT_NEQ(expected, actual, msg) \
    do { \
        if ((expected) == (actual)) { \
            TEST_ERROR("%s: Expected not equal to %lld, got %lld", (msg), \
                      (long long)(expected), (long long)(actual)); \
            return false; \
        } \
    } while (0)

#define ASSERT_PTR_NULL(ptr, msg) \
    do { \
        if ((ptr) != NULL) { \
            TEST_ERROR("%s: Expected NULL, got %p", (msg), (ptr)); \
            return false; \
        } \
    } while (0)

#define ASSERT_PTR_NOT_NULL(ptr, msg) \
    do { \
        if ((ptr) == NULL) { \
            TEST_ERROR("%s: Expected non-NULL, got NULL", (msg)); \
            return false; \
        } \
    } while (0)

#define ASSERT_STR_EQ(expected, actual, msg) \
    do { \
        if (strcmp((expected), (actual)) != 0) { \
            TEST_ERROR("%s: Expected '%s', got '%s'", (msg), (expected), (actual)); \
            return false; \
        } \
    } while (0)

#define ASSERT_STR_NEQ(expected, actual, msg) \
    do { \
        if (strcmp((expected), (actual)) == 0) { \
            TEST_ERROR("%s: Expected strings to differ, both are '%s'", (msg), (expected)); \
            return false; \
        } \
    } while (0)

/* Mock structure utilities */
struct test_connection {
    struct ksmbd_conn base;
    bool is_mock;
    void *private_data;
};

static inline struct ksmbd_conn *create_test_connection(bool is_apple)
{
    struct test_connection *test_conn = test_kzalloc(sizeof(struct test_connection), "test_connection");
    if (!test_conn)
        return NULL;

    test_conn->is_mock = true;
    test_conn->base.is_aapl = is_apple;
    test_conn->base.dialect = SMB311_PROT_ID;
    test_conn->base.vals = &smb311_server_values;
    test_conn->base.ops = &smb311_server_ops;

    mutex_init(&test_conn->base.srv_mutex);
    atomic_set(&test_conn->base.req_running, 0);
    atomic_set(&test_conn->base.r_count, 1);

    return &test_conn->base;
}

static inline void free_test_connection(struct ksmbd_conn *conn)
{
    if (conn) {
        struct test_connection *test_conn = container_of(conn, struct test_connection, base);
        if (test_conn->is_mock) {
            kfree(test_conn);
        }
    }
}

/* Apple client simulation utilities */
struct apple_client_info {
    const char *macos_version;
    const char *build_number;
    const char *smb_client_version;
    const char *user_agent;
    bool supports_spotlight;
    bool supports_directory_speedup;
    bool supports_file_cloning;
    bool supports_compression;
};

static const struct apple_client_info apple_client_versions[] = {
    {
        .macos_version = "10.14",
        .build_number = "18G6032",
        .smb_client_version = "2.1.0",
        .user_agent = "Mac OS X",
        .supports_spotlight = true,
        .supports_directory_speedup = false,
        .supports_file_cloning = false,
        .supports_compression = false
    },
    {
        .macos_version = "11.0",
        .build_number = "20A2411",
        .smb_client_version = "3.0.0",
        .user_agent = "macOS",
        .supports_spotlight = true,
        .supports_directory_speedup = true,
        .supports_file_cloning = true,
        .supports_compression = false
    },
    {
        .macos_version = "12.0",
        .build_number = "21A558",
        .smb_client_version = "3.0.1",
        .user_agent = "macOS",
        .supports_spotlight = true,
        .supports_directory_speedup = true,
        .supports_file_cloning = true,
        .supports_compression = true
    },
    {
        .macos_version = "13.0",
        .build_number = "22A380",
        .smb_client_version = "3.0.2",
        .user_agent = "macOS",
        .supports_spotlight = true,
        .supports_directory_speedup = true,
        .supports_file_cloning = true,
        .supports_compression = true
    },
    {
        .macos_version = "14.0",
        .build_number = "23A344",
        .smb_client_version = "3.1.0",
        .user_agent = "macOS",
        .supports_spotlight = true,
        .supports_directory_speedup = true,
        .supports_file_cloning = true,
        .supports_compression = true
    },
    { NULL }
};

static inline const struct apple_client_info *get_apple_client_info(const char *version)
{
    int i;

    if (!version)
        return NULL;

    for (i = 0; apple_client_versions[i].macos_version; i++) {
        if (strcmp(apple_client_versions[i].macos_version, version) == 0) {
            return &apple_client_versions[i];
        }
    }

    return &apple_client_versions[0]; /* Default to 10.14 */
}

/* AAPL context creation utilities */
struct aapl_context_data {
    __le32 capabilities;
    __le32 flags;
    __le32 reserved1;
    __le32 reserved2;
    char client_info[128];
    char extended_data[256];
};

static inline struct create_context *create_aapl_context_with_capabilities(__le32 capabilities)
{
    struct create_context *context;
    struct aapl_context_data *aapl_data;
    size_t context_size = sizeof(struct create_context) + sizeof(struct aapl_context_data);

    context = test_kzalloc(context_size, "AAPL context");
    if (!context)
        return NULL;

    context->Next = 0;
    context->NameOffset = offsetof(struct create_context, Buffer);
    context->NameLength = 4;
    context->DataOffset = cpu_to_le16(context->NameOffset + context->NameLength);
    context->DataLength = cpu_to_le32(sizeof(struct aapl_context_data));

    /* Set AAPL name */
    context->Buffer[0] = 'A';
    context->Buffer[1] = 'A';
    context->Buffer[2] = 'P';
    context->Buffer[3] = 'L';

    /* Initialize AAPL data */
    aapl_data = (struct aapl_context_data *)(context->Buffer + 4);
    aapl_data->capabilities = capabilities;
    aapl_data->flags = 0;
    aapl_data->reserved1 = 0;
    aapl_data->reserved2 = 0;

    return context;
}

/* Performance measurement utilities */
struct performance_metrics {
    unsigned long long min_time;
    unsigned long long max_time;
    unsigned long long total_time;
    unsigned long long total_operations;
    unsigned long long memory_peak;
    unsigned long long memory_current;
};

static inline void init_performance_metrics(struct performance_metrics *metrics)
{
    memset(metrics, 0, sizeof(*metrics));
    metrics->min_time = ULLONG_MAX;
}

static inline void update_performance_metrics(struct performance_metrics *metrics,
                                            unsigned long long operation_time)
{
    if (operation_time < metrics->min_time)
        metrics->min_time = operation_time;
    if (operation_time > metrics->max_time)
        metrics->max_time = operation_time;

    metrics->total_time += operation_time;
    metrics->total_operations++;
}

static inline void log_performance_metrics(const char *test_name, struct performance_metrics *metrics)
{
    if (metrics->total_operations == 0) {
        TEST_INFO("%s: No operations measured", test_name);
        return;
    }

    unsigned long long avg_time = metrics->total_time / metrics->total_operations;

    TEST_INFO("%s Performance Metrics:", test_name);
    TEST_INFO("  Operations: %llu", metrics->total_operations);
    TEST_INFO("  Min time: %llu ns", metrics->min_time);
    TEST_INFO("  Max time: %llu ns", metrics->max_time);
    TEST_INFO("  Avg time: %llu ns", avg_time);
    TEST_INFO("  Total time: %llu ns", metrics->total_time);
    TEST_INFO("  Memory peak: %llu bytes", metrics->memory_peak);
    TEST_INFO("  Memory current: %llu bytes", metrics->memory_current);
}

/* Stress testing utilities */
struct stress_test_config {
    unsigned int concurrent_connections;
    unsigned int operations_per_connection;
    unsigned int duration_ms;
    unsigned int memory_limit_mb;
    bool enable_timing;
    bool enable_memory_tracking;
};

static inline bool validate_stress_test_config(struct stress_test_config *config)
{
    if (config->concurrent_connections == 0) {
        TEST_ERROR("Stress test: concurrent_connections must be > 0");
        return false;
    }

    if (config->operations_per_connection == 0) {
        TEST_ERROR("Stress test: operations_per_connection must be > 0");
        return false;
    }

    if (config->duration_ms == 0) {
        TEST_ERROR("Stress test: duration_ms must be > 0");
        return false;
    }

    return true;
}

#endif /* _TEST_UTILS_H */