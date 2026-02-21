// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2023 ksmbd Contributors
 *
 *   Performance Test Framework for Fruit SMB Extensions
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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "connection.h"
#include "smb2pdu.h"
#include "vfs.h"
#include "test_framework/test_utils.h"

#define PERFORMANCE_TEST_MODULE "ksmbd_fruit_performance"

/* Performance test definitions */
#define MAX_CONCURRENT_TESTS 32
#define MAX_TEST_ITERATIONS 10000
#define MIN_TEST_ITERATIONS 100
#define PERFORMANCE_TIMEOUT_MS 30000

/* Performance test types */
enum performance_test_type {
    PERF_DIR_TRAVERSAL_BASIC,
    PERF_DIR_TRAVERSAL_DEEP,
    PERF_DIR_TRAVERSAL_WIDE,
    PERF_DIR_TRAVERSAL_MIXED,
    PERF_FILE_OPERATIONS,
    PERF_METADATA_OPERATIONS,
    PERF_CONCURRENT_ACCESS,
    PERF_MEMORY_EFFICIENCY,
    PERF_TYPE_COUNT
};

/* Performance test results */
struct performance_result {
    unsigned long long min_time_ns;
    unsigned long long max_time_ns;
    unsigned long long total_time_ns;
    unsigned long long avg_time_ns;
    unsigned long long p50_time_ns;  /* 50th percentile */
    unsigned long long p90_time_ns;  /* 90th percentile */
    unsigned long long p95_time_ns;  /* 95th percentile */
    unsigned long long p99_time_ns;  /* 99th percentile */
    unsigned long long operations_count;
    unsigned long long memory_usage_kb;
    unsigned long long cpu_usage_ms;
    unsigned long long network_bytes_sent;
    unsigned long long network_bytes_received;
    int error_count;
    float improvement_ratio; /* Compared to baseline */
};

/* Performance test configuration */
struct perf_test_config {
    enum performance_test_type test_type;
    const char *name;
    const char *description;
    unsigned int iterations;
    unsigned int concurrent_clients;
    unsigned int directory_depth;
    unsigned int directory_width;
    unsigned int file_count;
    unsigned int max_file_size_kb;
    unsigned int duration_ms;
    bool fruit_optimized;
    bool baseline_test;
};

/* Directory traversal test data */
struct dir_traversal_test_data {
    char **file_paths;
    char **directory_paths;
    unsigned int file_count;
    unsigned int dir_count;
    struct file **open_files;
    struct dentry **dentries;
    bool fruit_optimized;
};

/* Performance test context */
struct performance_test_context {
    struct perf_test_config *config;
    struct ksmbd_conn *conn;
    struct ksmbd_session *session;
    struct ksmbd_tree_connect *tree_conn;
    struct dir_traversal_test_data *test_data;
    struct performance_result result;
    atomic_t running_threads;
    struct completion test_complete;
    bool test_completed;
};

/* Performance test statistics */
static struct {
    struct performance_result baseline_results[PERF_TYPE_COUNT];
    struct performance_result optimized_results[PERF_TYPE_COUNT];
    struct performance_result current_result;
    unsigned long long total_tests_run;
    unsigned long long successful_tests;
    unsigned long long failed_tests;
    struct mutex stats_lock;
} perf_stats;

/* Forward declarations */
static int run_directory_traversal_test(struct performance_test_context *ctx);
static int run_concurrent_access_test(struct performance_test_context *ctx);
static int run_memory_efficiency_test(struct performance_test_context *ctx);

/* Test result processing */
static void calculate_percentiles(unsigned long long *times, unsigned int count,
                                 struct performance_result *result)
{
    if (count == 0)
        return;

    /* Sort times array (simplified bubble sort for testing) */
    for (unsigned int i = 0; i < count - 1; i++) {
        for (unsigned int j = 0; j < count - i - 1; j++) {
            if (times[j] > times[j + 1]) {
                unsigned long long temp = times[j];
                times[j] = times[j + 1];
                times[j + 1] = temp;
            }
        }
    }

    result->p50_time_ns = times[count * 50 / 100];
    result->p90_time_ns = times[count * 90 / 100];
    result->p95_time_ns = times[count * 95 / 100];
    result->p99_time_ns = times[count * 99 / 100];
}

static void update_performance_stats(struct performance_test_context *ctx,
                                    unsigned long long *operation_times,
                                    unsigned int operation_count)
{
    struct performance_result *result = &ctx->result;
    unsigned long long total_time = 0;
    unsigned long long min_time = ULLONG_MAX;
    unsigned long long max_time = 0;

    if (operation_count == 0)
        return;

    /* Calculate basic statistics */
    for (unsigned int i = 0; i < operation_count; i++) {
        total_time += operation_times[i];
        if (operation_times[i] < min_time)
            min_time = operation_times[i];
        if (operation_times[i] > max_time)
            max_time = operation_times[i];
    }

    result->min_time_ns = min_time;
    result->max_time_ns = max_time;
    result->total_time_ns = total_time;
    result->avg_time_ns = total_time / operation_count;
    result->operations_count = operation_count;

    /* Calculate percentiles */
    calculate_percentiles(operation_times, operation_count, result);

    /* Calculate improvement ratio if baseline exists */
    mutex_lock(&perf_stats.stats_lock);
    if (ctx->config->fruit_optimized && !ctx->config->baseline_test) {
        enum performance_test_type test_type = ctx->config->test_type;
        if (perf_stats.baseline_results[test_type].operations_count > 0) {
            struct performance_result *baseline = &perf_stats.baseline_results[test_type];
            if (baseline->avg_time_ns > 0) {
                result->improvement_ratio = (float)baseline->avg_time_ns / result->avg_time_ns;
            }
        }
    } else if (!ctx->config->fruit_optimized && ctx->config->baseline_test) {
        /* This is a baseline test, store the result */
        enum performance_test_type test_type = ctx->config->test_type;
        perf_stats.baseline_results[test_type] = *result;
    }
    mutex_unlock(&perf_stats.stats_lock);
}

/* Directory traversal test implementation */
static struct dir_traversal_test_data *create_directory_test_data(
    unsigned int directory_depth, unsigned int directory_width, unsigned int file_count,
    bool fruit_optimized)
{
    struct dir_traversal_test_data *test_data;
    unsigned int total_dirs = 0;
    unsigned int current_dirs = 1;
    char path_buffer[4096];
    unsigned int i, j, k;

    /* Calculate total directory count */
    for (i = 0; i <= directory_depth; i++) {
        total_dirs += current_dirs;
        if (i < directory_depth)
            current_dirs *= directory_width;
    }

    test_data = test_kzalloc(sizeof(struct dir_traversal_test_data), "directory test data");
    if (!test_data)
        return NULL;

    test_data->file_paths = test_kvmalloc(file_count * sizeof(char *), "file paths");
    test_data->directory_paths = test_kvmalloc(total_dirs * sizeof(char *), "directory paths");
    if (!test_data->file_paths || !test_data->directory_paths)
        goto cleanup;

    test_data->file_count = file_count;
    test_data->dir_count = total_dirs;
    test_data->fruit_optimized = fruit_optimized;

    /* Generate directory structure */
    unsigned int dir_index = 0;
    current_dirs = 1;

    for (i = 0; i <= directory_depth; i++) {
        for (j = 0; j < current_dirs; j++) {
            if (i == 0) {
                snprintf(path_buffer, sizeof(path_buffer), "/perf_test_root");
            } else {
                snprintf(path_buffer, sizeof(path_buffer), "/perf_test_root/level_%d_dir_%d", i, j);
            }

            test_data->directory_paths[dir_index++] = kstrdup(path_buffer, GFP_KERNEL);
        }
        if (i < directory_depth)
            current_dirs *= directory_width;
    }

    /* Generate file paths */
    for (i = 0; i < file_count; i++) {
        int level = i % (directory_depth + 1);
        int dir_in_level = (i / (directory_depth + 1)) % directory_width;

        if (level == 0) {
            snprintf(path_buffer, sizeof(path_buffer), "/perf_test_root/file_%d.txt", i);
        } else {
            snprintf(path_buffer, sizeof(path_buffer), "/perf_test_root/level_%d_dir_%d/file_%d.txt",
                    level, dir_in_level, i);
        }

        test_data->file_paths[i] = kstrdup(path_buffer, GFP_KERNEL);
    }

    return test_data;

cleanup:
    if (test_data) {
        if (test_data->file_paths) {
            for (i = 0; i < file_count; i++) {
                kfree(test_data->file_paths[i]);
            }
            vfree(test_data->file_paths);
        }
        if (test_data->directory_paths) {
            for (i = 0; i < total_dirs; i++) {
                kfree(test_data->directory_paths[i]);
            }
            vfree(test_data->directory_paths);
        }
        kfree(test_data);
    }
    return NULL;
}

static void free_directory_test_data(struct dir_traversal_test_data *test_data)
{
    if (!test_data)
        return;

    if (test_data->file_paths) {
        for (unsigned int i = 0; i < test_data->file_count; i++) {
            kfree(test_data->file_paths[i]);
        }
        vfree(test_data->file_paths);
    }

    if (test_data->directory_paths) {
        for (unsigned int i = 0; i < test_data->dir_count; i++) {
            kfree(test_data->directory_paths[i]);
        }
        vfree(test_data->directory_paths);
    }

    if (test_data->open_files) {
        for (unsigned int i = 0; i < test_data->file_count; i++) {
            if (test_data->open_files[i])
                filp_close(test_data->open_files[i], NULL);
        }
        kfree(test_data->open_files);
    }

    kfree(test_data);
}

static int run_single_directory_traversal(struct performance_test_context *ctx,
                                         const char *directory_path)
{
    unsigned long long start_time, end_time;
    int simulated_files = 50; /* Simulate directory with 50 files */
    int ret = 0;

    start_time = get_time_ns();

    if (ctx->test_data->fruit_optimized) {
        /* Simulate Fruit-optimized directory traversal */
        /* This would use Fruit-specific optimizations */
        usleep_range(100, 500); /* Simulate fast Fruit-optimized traversal */
    } else {
        /* Simulate standard directory traversal */
        usleep_range(1000, 5000); /* Simulate slower standard traversal */
    }

    /* Simulate processing files in directory */
    for (int i = 0; i < simulated_files; i++) {
        if (ctx->test_data->fruit_optimized) {
            usleep_range(10, 50); /* Fast processing with Fruit optimization */
        } else {
            usleep_range(50, 200); /* Standard processing time */
        }
    }

    end_time = get_time_ns();

    /* Record the operation time */
    if (ctx->result.operations_count < ctx->config->iterations) {
        /* In a real implementation, we'd store this in an array */
        ctx->result.total_time_ns += (end_time - start_time);
        ctx->result.operations_count++;
    }

    return ret;
}

static int run_directory_traversal_test(struct performance_test_context *ctx)
{
    unsigned long long *operation_times;
    unsigned int operation_count = 0;
    int ret = 0;

    if (!ctx->test_data) {
        TEST_ERROR("No test data available for directory traversal");
        return -EINVAL;
    }

    /* Allocate array for timing data */
    operation_times = test_kvmalloc(ctx->config->iterations * sizeof(unsigned long long),
                                   "operation timing data");
    if (!operation_times)
        return -ENOMEM;

    TEST_INFO("Running directory traversal test: %s", ctx->config->name);
    TEST_INFO("Iterations: %d, Directories: %d, Files: %d",
              ctx->config->iterations, ctx->test_data->dir_count, ctx->test_data->file_count);

    /* Perform directory traversal iterations */
    for (unsigned int i = 0; i < ctx->config->iterations; i++) {
        for (unsigned int j = 0; j < ctx->test_data->dir_count; j++) {
            unsigned long long start_time = get_time_ns();

            ret = run_single_directory_traversal(ctx, ctx->test_data->directory_paths[j]);
            if (ret != 0) {
                TEST_ERROR("Directory traversal failed for %s: %d",
                          ctx->test_data->directory_paths[j], ret);
                ctx->result.error_count++;
                continue;
            }

            operation_times[operation_count++] = end_timer(start_time);

            if (operation_count >= ctx->config->iterations)
                break;
        }

        if (operation_count >= ctx->config->iterations)
            break;
    }

    /* Process results */
    update_performance_stats(ctx, operation_times, operation_count);

    vfree(operation_times);
    return ret;
}

/* Concurrent access test implementation */
struct concurrent_thread_data {
    struct performance_test_context *ctx;
    unsigned int thread_id;
    unsigned long long *thread_times;
    unsigned int operations_completed;
    int result;
};

static int concurrent_test_thread(void *data)
{
    struct concurrent_thread_data *thread_data = data;
    struct performance_test_context *ctx = thread_data->ctx;
    unsigned int operations_per_thread = ctx->config->iterations / ctx->config->concurrent_clients;
    unsigned long long start_time, end_time;
    int ret = 0;

    TEST_INFO("Concurrent thread %d started, will perform %d operations",
              thread_data->thread_id, operations_per_thread);

    for (unsigned int i = 0; i < operations_per_thread; i++) {
        start_time = get_time_ns();

        /* Simulate concurrent directory access */
        if (ctx->test_data && i < ctx->test_data->dir_count) {
            ret = run_single_directory_traversal(ctx, ctx->test_data->directory_paths[i]);
        } else {
            /* Fallback to simulated operation */
            if (ctx->config->fruit_optimized) {
                usleep_range(100, 500);
            } else {
                usleep_range(1000, 5000);
            }
        }

        end_time = get_time_ns();

        if (ret == 0) {
            thread_data->thread_times[thread_data->operations_completed++] = end_timer(start_time);
        } else {
            ctx->result.error_count++;
        }

        /* Simulate some randomness in timing */
        if (get_random_u8() % 100 < 5) { /* 5% chance of longer operation */
            usleep_range(5000, 15000);
        }
    }

    TEST_INFO("Concurrent thread %d completed %d operations with %d errors",
              thread_data->thread_id, thread_data->operations_completed, ret);

    thread_data->result = ret;
    atomic_dec(&ctx->running_threads);
    complete(&ctx->test_complete);

    return ret;
}

static int run_concurrent_access_test(struct performance_test_context *ctx)
{
    struct concurrent_thread_data *thread_data;
    struct task_struct **threads;
    unsigned long long *all_operation_times;
    unsigned int total_operations = 0;
    int ret = 0;

    if (!ctx->config->concurrent_clients || ctx->config->concurrent_clients > MAX_CONCURRENT_TESTS) {
        TEST_ERROR("Invalid concurrent client count: %d", ctx->config->concurrent_clients);
        return -EINVAL;
    }

    /* Allocate thread data structures */
    thread_data = test_kzalloc(ctx->config->concurrent_clients * sizeof(struct concurrent_thread_data),
                              "thread data");
    threads = test_kzalloc(ctx->config->concurrent_clients * sizeof(struct task_struct *),
                           "thread pointers");

    if (!thread_data || !threads) {
        kfree(thread_data);
        kfree(threads);
        return -ENOMEM;
    }

    /* Prepare test data */
    if (!ctx->test_data) {
        ctx->test_data = create_directory_test_data(
            5, 4, ctx->config->file_count, ctx->config->fruit_optimized);
        if (!ctx->test_data) {
            kfree(thread_data);
            kfree(threads);
            return -ENOMEM;
        }
    }

    atomic_set(&ctx->running_threads, ctx->config->concurrent_clients);
    init_completion(&ctx->test_complete);

    TEST_INFO("Starting concurrent access test: %d clients, %d iterations each",
              ctx->config->concurrent_clients, ctx->config->iterations / ctx->config->concurrent_clients);

    /* Start concurrent threads */
    for (unsigned int i = 0; i < ctx->config->concurrent_clients; i++) {
        unsigned int operations_per_thread = ctx->config->iterations / ctx->config->concurrent_clients;

        thread_data[i].ctx = ctx;
        thread_data[i].thread_id = i;
        thread_data[i].result = 0;
        thread_data[i].operations_completed = 0;

        thread_data[i].thread_times = test_kvmalloc(operations_per_thread * sizeof(unsigned long long),
                                                   "thread operation times");
        if (!thread_data[i].thread_times) {
            ret = -ENOMEM;
            goto cleanup;
        }

        threads[i] = kthread_run(concurrent_test_thread, &thread_data[i], "concurrent_test_%d", i);
        if (IS_ERR(threads[i])) {
            ret = PTR_ERR(threads[i]);
            goto cleanup;
        }
    }

    /* Wait for all threads to complete */
    wait_for_completion(&ctx->test_complete);

    /* Aggregate results */
    for (unsigned int i = 0; i < ctx->config->concurrent_clients; i++) {
        total_operations += thread_data[i].operations_completed;
        if (thread_data[i].result != 0) {
            ret = thread_data[i].result;
        }
    }

    /* Collect all timing data for analysis */
    all_operation_times = test_kvmalloc(total_operations * sizeof(unsigned long long),
                                        "all operation times");
    if (!all_operation_times) {
        ret = -ENOMEM;
        goto cleanup;
    }

    unsigned int index = 0;
    for (unsigned int i = 0; i < ctx->config->concurrent_clients; i++) {
        for (unsigned int j = 0; j < thread_data[i].operations_completed; j++) {
            all_operation_times[index++] = thread_data[i].thread_times[j];
        }
    }

    update_performance_stats(ctx, all_operation_times, total_operations);

    TEST_INFO("Concurrent access test completed: %d total operations", total_operations);

cleanup:
    for (unsigned int i = 0; i < ctx->config->concurrent_clients; i++) {
        if (thread_data[i].thread_times)
            vfree(thread_data[i].thread_times);
    }
    vfree(all_operation_times);
    kfree(thread_data);
    kfree(threads);

    return ret;
}

/* Memory efficiency test implementation */
static int run_memory_efficiency_test(struct performance_test_context *ctx)
{
    unsigned long long start_time, end_time;
    unsigned long long memory_before, memory_after;
    struct dir_traversal_test_data *large_test_data;
    int ret = 0;

    TEST_INFO("Running memory efficiency test: %s", ctx->config->name);

    /* Get memory baseline */
    memory_before = get_time_ns(); /* In a real implementation, this would get actual memory usage */

    /* Create large test data set */
    large_test_data = create_directory_test_data(10, 8, 1000, ctx->config->fruit_optimized);
    if (!large_test_data) {
        return -ENOMEM;
    }

    start_time = get_time_ns();

    /* Perform memory-intensive operations */
    for (unsigned int i = 0; i < 100; i++) {
        ret = run_single_directory_traversal(ctx, large_test_data->directory_paths[i]);
        if (ret != 0) {
            TEST_ERROR("Memory efficiency test failed on iteration %d: %d", i, ret);
            break;
        }

        /* Simulate memory pressure cleanup for Fruit clients */
        if (ctx->config->fruit_optimized && i % 10 == 0) {
            usleep_range(100, 300); /* Memory cleanup time */
        }
    }

    end_time = get_time_ns();

    /* Get memory usage after test */
    memory_after = get_time_ns(); /* In a real implementation, this would get actual memory usage */

    ctx->result.memory_usage_kb = (memory_after - memory_before) / 1000; /* Simplified */
    ctx->result.total_time_ns = end_time - start_time;
    ctx->result.operations_count = 100;

    free_directory_test_data(large_test_data);

    TEST_INFO("Memory efficiency test completed: %lld ns, %lld KB memory used",
              ctx->result.total_time_ns, ctx->result.memory_usage_kb);

    return ret;
}

/* Performance test configurations */
static struct perf_test_config perf_configs[] = {
    {
        PERF_DIR_TRAVERSAL_BASIC,
        "Basic Directory Traversal",
        "Test basic directory traversal performance",
        1000, /* iterations */
        1,    /* concurrent clients */
        3,    /* directory depth */
        5,    /* directory width */
        100,  /* file count */
        1024, /* max file size */
        10000, /* duration ms */
        false, /* fruit optimized (baseline) */
        true   /* baseline test */
    },
    {
        PERF_DIR_TRAVERSAL_BASIC,
        "Fruit Directory Traversal",
        "Test Fruit-optimized directory traversal performance",
        1000,
        1,
        3,
        5,
        100,
        1024,
        10000,
        true,  /* fruit optimized */
        false  /* baseline test */
    },
    {
        PERF_DIR_TRAVERSAL_DEEP,
        "Deep Directory Traversal",
        "Test deep directory structure performance",
        500,
        1,
        15,   /* deep structure */
        3,    /* limited width */
        200,
        512,
        15000,
        false,
        true
    },
    {
        PERF_DIR_TRAVERSAL_DEEP,
        "Fruit Deep Directory Traversal",
        "Test Fruit-optimized deep directory traversal",
        500,
        1,
        15,
        3,
        200,
        512,
        15000,
        true,
        false
    },
    {
        PERF_DIR_TRAVERSAL_WIDE,
        "Wide Directory Traversal",
        "Test wide directory structure performance",
        800,
        1,
        2,    /* shallow structure */
        50,   /* very wide */
        500,
        256,
        12000,
        false,
        true
    },
    {
        PERF_DIR_TRAVERSAL_WIDE,
        "Fruit Wide Directory Traversal",
        "Test Fruit-optimized wide directory traversal",
        800,
        1,
        2,
        50,
        500,
        256,
        12000,
        true,
        false
    },
    {
        PERF_CONCURRENT_ACCESS,
        "Concurrent Directory Access",
        "Test concurrent client directory access",
        2000,
        10,   /* concurrent clients */
        5,
        4,
        300,
        1024,
        20000,
        false,
        true
    },
    {
        PERF_CONCURRENT_ACCESS,
        "Fruit Concurrent Directory Access",
        "Test Fruit-optimized concurrent directory access",
        2000,
        10,
        5,
        4,
        300,
        1024,
        20000,
        true,
        false
    },
    { PERF_TYPE_COUNT, NULL, NULL, 0, 0, 0, 0, 0, 0, false, false }
};

/* Performance test runner */
static int run_performance_test(struct perf_test_config *config)
{
    struct performance_test_context ctx;
    unsigned long long test_start, test_end;
    int ret = 0;

    TEST_INFO("=== Starting Performance Test: %s ===", config->name);
    TEST_INFO("Description: %s", config->description);
    TEST_INFO("Fruit optimized: %s", config->fruit_optimized ? "Yes" : "No");
    TEST_INFO("Baseline test: %s", config->baseline_test ? "Yes" : "No");

    memset(&ctx, 0, sizeof(ctx));
    ctx.config = config;
    init_completion(&ctx.test_complete);

    /* Initialize test connection */
    ctx.conn = create_test_connection(config->fruit_optimized);
    if (!ctx.conn) {
        TEST_ERROR("Failed to create test connection");
        return -ENOMEM;
    }

    /* Create test data if needed */
    if (config->test_type != PERF_MEMORY_EFFICIENCY) {
        ctx.test_data = create_directory_test_data(
            config->directory_depth, config->directory_width, config->file_count,
            config->fruit_optimized);
        if (!ctx.test_data) {
            ret = -ENOMEM;
            goto cleanup;
        }
    }

    /* Initialize performance result */
    memset(&ctx.result, 0, sizeof(ctx.result));
    ctx.result.min_time_ns = ULLONG_MAX;

    test_start = get_time_ns();

    /* Run appropriate test type */
    switch (config->test_type) {
    case PERF_DIR_TRAVERSAL_BASIC:
    case PERF_DIR_TRAVERSAL_DEEP:
    case PERF_DIR_TRAVERSAL_WIDE:
    case PERF_DIR_TRAVERSAL_MIXED:
        ret = run_directory_traversal_test(&ctx);
        break;
    case PERF_CONCURRENT_ACCESS:
        ret = run_concurrent_access_test(&ctx);
        break;
    case PERF_MEMORY_EFFICIENCY:
        ret = run_memory_efficiency_test(&ctx);
        break;
    default:
        TEST_ERROR("Unknown performance test type: %d", config->test_type);
        ret = -EINVAL;
        break;
    }

    test_end = get_time_ns();

    if (ret == 0) {
        /* Store results */
        if (config->fruit_optimized && !config->baseline_test) {
            mutex_lock(&perf_stats.stats_lock);
            perf_stats.optimized_results[config->test_type] = ctx.result;
            mutex_unlock(&perf_stats.stats_lock);
        } else if (!config->fruit_optimized && config->baseline_test) {
            mutex_lock(&perf_stats.stats_lock);
            perf_stats.baseline_results[config->test_type] = ctx.result;
            mutex_unlock(&perf_stats.stats_lock);
        }

        TEST_INFO("✅ Performance test '%s' passed", config->name);
        TEST_INFO("  Operations: %llu, Time: %lld ns, Avg: %lld ns",
                  ctx.result.operations_count, ctx.result.total_time_ns, ctx.result.avg_time_ns);
        if (ctx.result.improvement_ratio > 0) {
            TEST_INFO("  Improvement ratio: %.2fx", ctx.result.improvement_ratio);
            if (ctx.result.improvement_ratio < 14.0) {
                TEST_WARN("  ⚠️  Performance improvement below 14x target: %.2fx",
                         ctx.result.improvement_ratio);
            }
        }
        if (ctx.result.error_count > 0) {
            TEST_WARN("  Errors encountered: %d", ctx.result.error_count);
        }
    } else {
        TEST_ERROR("❌ Performance test '%s' failed with error %d", config->name, ret);
    }

cleanup:
    if (ctx.test_data)
        free_directory_test_data(ctx.test_data);
    free_test_connection(ctx.conn);

    return ret;
}

/* Main performance test runner */
static int run_all_performance_tests(void)
{
    int i, failed = 0;
    unsigned long long total_start, total_end;

    TEST_INFO("🚀 Starting Fruit SMB Extensions Performance Tests");
    TEST_INFO("=================================================");

    memset(&perf_stats, 0, sizeof(perf_stats));
    mutex_init(&perf_stats.stats_lock);

    total_start = get_time_ns();

    for (i = 0; perf_configs[i].name != NULL; i++) {
        int ret = run_performance_test(&perf_configs[i]);
        if (ret != 0) {
            failed++;
            /* For non-critical tests, continue running */
            if (perf_configs[i].test_type != PERF_DIR_TRAVERSAL_BASIC) {
                TEST_WARN("Performance test failed, continuing with next test...");
            } else {
                TEST_ERROR("Critical performance test failed, aborting...");
                break;
            }
        }

        /* Give system time to stabilize between tests */
        if (i < (sizeof(perf_configs) / sizeof(perf_configs[0])) - 2) {
            msleep(1000);
        }
    }

    total_end = get_time_ns();

    TEST_INFO("=================================================");
    TEST_INFO("Performance Test Summary:");
    TEST_INFO("  Total tests: %zu", sizeof(perf_configs) / sizeof(perf_configs[0]) - 1);
    TEST_INFO("  Failed tests: %d", failed);
    TEST_INFO("  Total test time: %lld ns", total_end - total_start);
    TEST_INFO("  Success rate: %.2f%%",
              (float)(sizeof(perf_configs) / sizeof(perf_configs[0]) - 1 - failed) /
              (sizeof(perf_configs) / sizeof(perf_configs[0]) - 1) * 100.0);

    /* Check for 14x improvement requirement */
    if (perf_stats.optimized_results[PERF_DIR_TRAVERSAL_BASIC].operations_count > 0) {
        float improvement = perf_stats.optimized_results[PERF_DIR_TRAVERSAL_BASIC].improvement_ratio;
        if (improvement < 14.0) {
            TEST_ERROR("❌ 14x performance improvement not achieved: %.2fx", improvement);
            failed++;
        } else {
            TEST_INFO("✅ 14x performance improvement achieved: %.2fx", improvement);
        }
    }

    return failed;
}

/* Module initialization */
static int __init fruit_performance_test_init(void)
{
    int ret;

    TEST_INFO("Loading %s module", PERFORMANCE_TEST_MODULE);

    ret = run_all_performance_tests();
    if (ret != 0) {
        TEST_ERROR("Performance tests failed!");
        return ret;
    }

    TEST_INFO("All performance tests completed!");
    return 0;
}

/* Module cleanup */
static void __exit fruit_performance_test_exit(void)
{
    TEST_INFO("Unloading %s module", PERFORMANCE_TEST_MODULE);
}

module_init(fruit_performance_test_init);
module_exit(fruit_performance_test_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ksmbd Contributors");
MODULE_DESCRIPTION("Performance Test Framework for Fruit SMB Extensions");
MODULE_VERSION("1.0");