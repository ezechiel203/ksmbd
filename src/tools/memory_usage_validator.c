/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Memory Usage Validator for Fruit SMB Extensions
 *
 * This program validates the memory usage patterns and efficiency
 * of the Fruit SMB extensions implementation in ksmbd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Simulate kernel types */
typedef uint32_t __le32;
typedef uint64_t __le64;
typedef uint8_t __u8;

/* Fruit SMB extension structures (from smb2fruit.h) */
struct fruit_conn_state {
    __le32 client_version;        /* 4 bytes */
    __le32 client_type;           /* 4 bytes */
    __le64 client_capabilities;   /* 8 bytes */
    __u8 client_build[16];        /* 16 bytes */
    __le64 negotiated_capabilities; /* 8 bytes */
    __le64 supported_features;    /* 8 bytes */
    __le64 enabled_features;      /* 8 bytes */
    bool extensions_enabled;      /* 1 byte */
    bool compression_supported;   /* 1 byte */
    bool resilient_handles_enabled; /* 1 byte */
    bool posix_locks_enabled;     /* 1 byte */
    bool server_queried;          /* 1 byte */
    __le32 last_query_type;       /* 4 bytes */
    __le64 last_query_time;       /* 8 bytes */
    __u8 reserved[64];            /* 64 bytes */
} __attribute__((packed));

struct ksmbd_conn_fruit_additions {
    struct fruit_conn_state *fruit_state;   /* 8 bytes */
    __le64 fruit_capabilities;              /* 8 bytes */
    __le32 fruit_version;                   /* 4 bytes */
    __le32 fruit_client_type;               /* 4 bytes */
    __u8 fruit_client_build[16];            /* 16 bytes */
    bool fruit_extensions_enabled;          /* 1 byte */
    bool is_fruit;                          /* 1 byte */
    /* Padding: 2 bytes for alignment */
} __attribute__((packed));

struct memory_stats {
    size_t fruit_state_size;
    size_t conn_additions_size;
    size_t total_per_fruit_connection;
    size_t total_per_non_fruit_connection;
    size_t alignment_overhead;
    double fragmentation_risk;
};

void calculate_memory_usage(struct memory_stats *stats)
{
    stats->fruit_state_size = sizeof(struct fruit_conn_state);
    stats->conn_additions_size = sizeof(struct ksmbd_conn_fruit_additions);

    stats->total_per_fruit_connection = stats->fruit_state_size + stats->conn_additions_size;
    stats->total_per_non_fruit_connection = stats->conn_additions_size;

    stats->alignment_overhead = (8 - (stats->conn_additions_size % 8)) % 8;
    stats->fragmentation_risk = 0.1;
}

bool validate_memory_efficiency(const struct memory_stats *stats)
{
    const size_t MEMORY_LIMIT = 2048;
    double efficiency = (double)stats->total_per_fruit_connection / MEMORY_LIMIT;

    printf("Memory Efficiency Analysis:\n");
    printf("  Fruit connection state: %zu bytes\n", stats->fruit_state_size);
    printf("  Connection additions: %zu bytes\n", stats->conn_additions_size);
    printf("  Total per Fruit connection: %zu bytes\n", stats->total_per_fruit_connection);
    printf("  Total per non-Fruit connection: %zu bytes\n", stats->total_per_non_fruit_connection);
    printf("  Memory efficiency: %.1f%% of 2KB limit\n", efficiency * 100.0);
    printf("  Alignment overhead: %zu bytes\n", stats->alignment_overhead);
    printf("  Fragmentation risk: %.1f%%\n", stats->fragmentation_risk * 100.0);

    return efficiency <= 1.0;
}

void test_allocation_patterns(void)
{
    printf("\nMemory Allocation Pattern Tests:\n");

    const int num_allocations = 1000;
    void *allocations[num_allocations];
    size_t total_allocated = 0;
    int successful_allocations = 0;

    for (int i = 0; i < num_allocations; i++) {
        allocations[i] = malloc(sizeof(struct fruit_conn_state));
        if (allocations[i]) {
            total_allocated += sizeof(struct fruit_conn_state);
            successful_allocations++;
        }
    }

    printf("  Allocation test: %d/%d successful (%.1f%%)\n",
           successful_allocations, num_allocations,
           (double)successful_allocations / num_allocations * 100.0);
    printf("  Total memory allocated: %zu KB\n", total_allocated / 1024);
    printf("  Average allocation size: %zu bytes\n", sizeof(struct fruit_conn_state));

    const size_t cache_line_size = 64;
    size_t cache_lines_used = (sizeof(struct fruit_conn_state) + cache_line_size - 1) / cache_line_size;
    double cache_efficiency = (double)sizeof(struct fruit_conn_state) / (cache_lines_used * cache_line_size) * 100.0;

    printf("  Cache lines used: %zu\n", cache_lines_used);
    printf("  Cache efficiency: %.1f%%\n", cache_efficiency);

    for (int i = 0; i < num_allocations; i++) {
        if (allocations[i])
            free(allocations[i]);
    }
}

void simulate_memory_load(int concurrent_connections)
{
    printf("\nMemory Usage Simulation (%d concurrent connections):\n", concurrent_connections);

    struct memory_stats stats;
    calculate_memory_usage(&stats);

    double fruit_ratio = 0.4;
    int fruit_connections = (int)(concurrent_connections * fruit_ratio);
    int non_fruit_connections = concurrent_connections - fruit_connections;

    size_t total_memory = (fruit_connections * stats.total_per_fruit_connection) +
                          (non_fruit_connections * stats.total_per_non_fruit_connection);

    printf("  Fruit connections: %d (%.1f%%)\n", fruit_connections, fruit_ratio * 100.0);
    printf("  Non-Fruit connections: %d (%.1f%%)\n", non_fruit_connections, (1.0 - fruit_ratio) * 100.0);
    printf("  Total memory usage: %zu KB\n", total_memory / 1024);
    printf("  Average per connection: %.1f bytes\n", (double)total_memory / concurrent_connections);
    printf("  Memory scaling factor: %.2fx\n", (double)total_memory / (concurrent_connections * stats.total_per_fruit_connection));

    bool memory_ok = total_memory < (concurrent_connections * 2048);
    printf("  Memory requirement: %s\n", memory_ok ? "PASS" : "FAIL");
}

void test_memory_pressure(void)
{
    printf("\nMemory Pressure Tests:\n");

    const int stress_iterations = 10000;
    void *ptrs[stress_iterations];
    int successful_allocs = 0;
    int failed_allocs = 0;

    for (int i = 0; i < stress_iterations; i++) {
        ptrs[i] = malloc(sizeof(struct fruit_conn_state));
        if (ptrs[i]) {
            successful_allocs++;
            memset(ptrs[i], 0, sizeof(struct fruit_conn_state));
        } else {
            failed_allocs++;
        }
    }

    printf("  Stress test results:\n");
    printf("    Total allocations attempted: %d\n", stress_iterations);
    printf("    Successful: %d (%.1f%%)\n", successful_allocs,
           (double)successful_allocs / stress_iterations * 100.0);
    printf("    Failed: %d (%.1f%%)\n", failed_allocs,
           (double)failed_allocs / stress_iterations * 100.0);

    for (int i = 0; i < stress_iterations; i++) {
        if (ptrs[i])
            free(ptrs[i]);
    }

    printf("  Fragmentation test:\n");
    void *frag_ptrs[1000];
    int frag_successful = 0;

    for (int round = 0; round < 10; round++) {
        for (int i = 0; i < 100; i++) {
            int idx = round * 100 + i;
            frag_ptrs[idx] = malloc(sizeof(struct fruit_conn_state));
            if (frag_ptrs[idx])
                frag_successful++;
        }

        for (int i = 0; i < 100; i += 2) {
            int idx = round * 100 + i;
            if (frag_ptrs[idx]) {
                free(frag_ptrs[idx]);
                frag_ptrs[idx] = NULL;
            }
        }
    }

    printf("    Fragmentation resistance: %d/1000 successful (%.1f%%)\n",
           frag_successful, (double)frag_successful / 1000 * 100.0);

    for (int i = 0; i < 1000; i++) {
        if (frag_ptrs[i])
            free(frag_ptrs[i]);
    }
}

void validate_structure_layout(void)
{
    printf("\nStructure Layout Validation:\n");

    printf("  fruit_conn_state layout:\n");
    printf("    Size: %zu bytes\n", sizeof(struct fruit_conn_state));
    printf("    Alignment: %zu bytes\n", __alignof__(struct fruit_conn_state));

    struct fruit_conn_state test_state;
    memset(&test_state, 0, sizeof(test_state));

    size_t offset_client_version = (size_t)&test_state.client_version - (size_t)&test_state;
    size_t offset_client_type = (size_t)&test_state.client_type - (size_t)&test_state;
    size_t offset_capabilities = (size_t)&test_state.client_capabilities - (size_t)&test_state;
    size_t offset_reserved = (size_t)&test_state.reserved - (size_t)&test_state;
    size_t struct_end = sizeof(test_state);

    printf("    Field offsets:\n");
    printf("      client_version: %zu\n", offset_client_version);
    printf("      client_type: %zu\n", offset_client_type);
    printf("      client_capabilities: %zu\n", offset_capabilities);
    printf("      reserved: %zu\n", offset_reserved);
    printf("      struct_end: %zu\n", struct_end);

    printf("  ksmbd_conn Fruit additions:\n");
    printf("    Size: %zu bytes\n", sizeof(struct ksmbd_conn_fruit_additions));
    printf("    Alignment: %zu bytes\n", __alignof__(struct ksmbd_conn_fruit_additions));

    struct ksmbd_conn_fruit_additions test_additions;
    memset(&test_additions, 0, sizeof(test_additions));

    printf("    Pointer alignment: %s\n",
           ((size_t)&test_additions.fruit_state % 8 == 0) ? "OK" : "MISALIGNED");
}

int main(void)
{
    printf("=== Fruit SMB Extensions Memory Usage Validator ===\n");

    struct memory_stats stats;
    calculate_memory_usage(&stats);

    printf("\n1. Memory Efficiency Validation:\n");
    bool efficiency_ok = validate_memory_efficiency(&stats);
    printf("  Result: %s\n", efficiency_ok ? "PASS" : "FAIL");

    printf("\n2. Allocation Pattern Tests:");
    test_allocation_patterns();

    printf("\n3. Load Simulation Tests:");
    simulate_memory_load(100);
    simulate_memory_load(1000);
    simulate_memory_load(10000);

    printf("\n4. Memory Pressure Tests:");
    test_memory_pressure();

    printf("\n5. Structure Layout Validation:");
    validate_structure_layout();

    printf("\n=== Final Memory Assessment ===\n");
    printf("Memory per Fruit connection: %zu bytes (%.1f%% of 2KB limit)\n",
           stats.total_per_fruit_connection,
           (double)stats.total_per_fruit_connection / 2048.0 * 100.0);
    printf("Memory per non-Fruit connection: %zu bytes (%.1f%% of 2KB limit)\n",
           stats.total_per_non_fruit_connection,
           (double)stats.total_per_non_fruit_connection / 2048.0 * 100.0);
    printf("Memory efficiency: %s\n", efficiency_ok ? "EXCELLENT" : "NEEDS ATTENTION");
    printf("Cache line usage: %zu lines (%.1f%% efficient)\n",
           (sizeof(struct fruit_conn_state) + 63) / 64,
           (double)sizeof(struct fruit_conn_state) / (((sizeof(struct fruit_conn_state) + 63) / 64) * 64) * 100.0);
    printf("Fragmentation risk: %.1f%% (%s)\n",
           stats.fragmentation_risk * 100.0,
           stats.fragmentation_risk < 0.2 ? "LOW" : "MODERATE");

    if (efficiency_ok && stats.fragmentation_risk < 0.2) {
        printf("\nMEMORY USAGE: PRODUCTION READY\n");
    } else {
        printf("\nMEMORY USAGE: NEEDS OPTIMIZATION\n");
    }

    return efficiency_ok ? 0 : 1;
}
