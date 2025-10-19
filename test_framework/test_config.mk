# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2024 The KSMBD Project
#
# Configuration for KSMBD Apple SMB Testing Framework
#
# This configuration file defines all testing parameters, scenarios,
# and validation criteria for comprehensive Apple SMB testing.

# ====== TEST CONFIGURATION ======

# Test timeout configuration
TEST_TIMEOUT ?= 300000              # 5 minutes in milliseconds
TEST_ITERATIONS ?= 1000               # Number of test iterations
TEST_CONCURRENT_SESSIONS ?= 50       # Maximum concurrent sessions
TEST_MEMORY_LIMIT ?= 8192             # Memory limit in MB
TEST_CPU_LIMIT ?= 80                   # CPU limit in percent

# ====== CLIENT SIMULATION CONFIGURATION ======

# Apple client versions to test
TEST_MACOS_VERSIONS ?= 10.14 11.0 12.0 13.0 14.0
TEST_IOS_VERSIONS ?= 14.0 15.0 16.0 17.0
TEST_IPADOS_VERSIONS ?= 13.0 14.0 15.0 16.0

# Non-Apple clients for compatibility testing
TEST_WINDOWS_VERSIONS ?= 10 11
TEST_LINUX_DISTRIBUTIONS ?= ubuntu centos debian
TEST_ANDROID_VERSIONS ?= 11 12 13 14

# ====== PERFORMANCE TESTING CONFIGURATION ======

# Performance benchmarks
PERF_MIN_OPS_PER_SEC ?= 1000         # Minimum operations per second
PERF_MAX_LATENCY_MS ?= 100            # Maximum latency in milliseconds
PERF_THROUGHPUT_MIN_MBS ?= 100        # Minimum throughput in MB/s
PERF_MEMORY_MAX_MB ?= 2048             # Maximum memory usage in MB
PERF_CPU_MAX_PERCENT ?= 80             # Maximum CPU usage percentage

# Stress testing parameters
STRESS_CONCURRENT_CONNECTIONS ?= 100   # Concurrent connections for stress test
STRESS_TEST_DURATION ?= 300000          # Stress test duration in milliseconds
STRESS_MEMORY_PRESSURE ?= true          # Enable memory pressure simulation
STRESS_CPU_PRESSURE ?= true             # Enable CPU pressure simulation

# ====== PRODUCTION READINESS CONFIGURATION ======

# Production environment simulation
PROD_MAX_CONNECTIONS ?= 1000          # Maximum production connections
PROD_MAX_FILES ?= 100000              # Maximum files per session
PROD_BACKUP_INTERVAL_HOURS ?= 24       # Backup interval in hours
PROD_MONITORING_INTERVAL ?= 30         # Monitoring interval in seconds

# Disaster recovery scenarios
DISASTER_RECOVERY_ENABLED ?= true      # Enable disaster recovery testing
DISASTER_SCENARIOS ?= network disk memory power process security
DISASTER_SEVERITY_LEVELS ?= 1 2 3 4 5 6 7 8 9 10

# ====== SECURITY VALIDATION CONFIGURATION ======

# Security testing parameters
SECURITY_VALIDATION_ENABLED ?= true    # Enable security validation
SECURITY_PENETRATION_TESTING ?= true  # Enable penetration testing
SECURITY_VULNERABILITY_SCANNING ?= true # Enable vulnerability scanning
SECURITY_COMPLIANCE_CHECKING ?= true    # Enable compliance checking

# Authentication and encryption
SECURITY_REQUIRE_ENCRYPTION ?= true    # Require encryption for all connections
SECURITY_REQUIRE_SIGNING ?= true        # Require SMB signing
SECURITY_MIN_KEY_STRENGTH ?= 128        # Minimum encryption key strength

# ====== INTEGRATION TESTING CONFIGURATION ======

# Integration test scenarios
INTEGRATION_MIXED_CLIENTS ?= true       # Test with mixed client types
INTEGRATION_PROTOCOL_VERSIONS ?= smb1 smb2 smb3
INTEGRATION_FEATURE_MATRIX ?= true        # Test feature compatibility matrix

# Compatibility thresholds
COMPATIBILITY_SUCCESS_RATE ?= 95       # Minimum success rate percentage
COMPATIBILITY_PERFORMANCE_DEGRADATION ?= 20  # Maximum performance degradation
COMPATIBILITY_MEMORY_OVERHEAD ?= 15      # Maximum memory overhead percentage

# ====== END-TO-END PROTOCOL TESTING ======

# E2E testing parameters
E2E_PROTOCOL_TESTING_ENABLED ?= true    # Enable E2E protocol testing
E2E_TEST_ALL_COMMANDS ?= true          # Test all SMB2 commands
E2E_ERROR_INJECTION ?= true             # Enable error injection testing
E2E_STATE_TRANSITION_TESTING ?= true   # Test state transitions

# Protocol validation
PROTOCOL_STRICT_VALIDATION ?= true      # Enable strict protocol validation
PROTOCOL_BACKWARDS_COMPATIBILITY ?= true # Test backwards compatibility
PROTOCOL_INTEROPERABILITY ?= true       # Test interoperability

# ====== APPLE-SPECIFIC TESTING ======

# Apple extensions testing
AAPL_EXTENSIONS_TESTING ?= true        # Enable Apple extensions testing
AAPL_FINDERINFO_TESTING ?= true       # Test FinderInfo operations
AAPL_TIMEMACHINE_TESTING ?= true       # Test Time Machine functionality
AAPL_COMPRESSION_TESTING ?= true      # Test compression operations
AAPL_F_FULLFSYNC_TESTING ?= true      # Test F_FULLFSYNC operations

# Apple client capabilities
AAPL_TEST_UNIX_EXTENSIONS ?= true      # Test UNIX extensions
AAPL_TEST_EXTENDED_ATTRIBUTES ?= true   # Test extended attributes
AAPL_TEST_CASE_SENSITIVITY ?= true     # Test case sensitivity
AAPL_TEST_POSIX_LOCKS ?= true         # Test POSIX locks
AAPL_TEST_RESILIENT_HANDLES ?= true    # Test resilient handles
AAPL_TEST_READDIR_ATTRS ?= true        # Test readdir attributes
AAPL_TEST_FILE_IDS ?= true             # Test file IDs

# ====== TESTING FRAMEWORK CONFIGURATION ======

# Debugging and logging
TESTING_DEBUG_VERBOSE ?= false         # Enable verbose debugging
TESTING_MEMORY_TRACING ?= true         # Enable memory usage tracing
TESTING_PERFORMANCE_ANALYSIS ?= true   # Enable performance analysis
TESTING_SECURITY_VALIDATION ?= true    # Enable security validation
TESTING_ERROR_DETAILED ?= true         # Enable detailed error reporting

# Test data management
TEST_DATA_RETENTION_DAYS ?= 7          # Retain test data for N days
TEST_LOG_LEVEL ?= info                  # Test log level (debug, info, warning, error)
TEST_REPORT_FORMAT ?= json               # Test report format (json, xml, html)

# ====== BUILD CONFIGURATION ======

# Compiler and optimization flags
OPTIMIZATION_LEVEL ?= O2               # Optimization level (O0, O1, O2, O3)
DEBUG_SYMBOLS ?= true                  # Include debug symbols
PROFILING_ENABLED ?= true              # Enable profiling support
STATIC_ANALYSIS_ENABLED ?= true        # Enable static analysis

# Architecture-specific configuration
ARCH_X86_64_FLAGS ?= -m64            # x86_64 architecture flags
ARCH_AARCH64_FLAGS ?= -march=armv8-a   # ARM64 architecture flags
ARCH_POWERPC_FLAGS ?= -m64             # PowerPC architecture flags

# ====== NETWORK TESTING CONFIGURATION ======

# Network simulation
NETWORK_SIMULATION_ENABLED ?= true     # Enable network simulation
NETWORK_LATENCY_MS ?= 10               # Network latency in milliseconds
NETWORK_BANDWIDTH_MBPS ?= 1000         # Network bandwidth limit
NETWORK_PACKET_LOSS_PERCENT ?= 1       # Network packet loss percentage
NETWORK_MTU_SIZE ?= 1500               # Network MTU size

# Connection testing
CONNECTION_POOL_SIZE ?= 50             # Connection pool size
CONNECTION_TIMEOUT ?= 30000            # Connection timeout in milliseconds
CONNECTION_RETRY_COUNT ?= 3              # Connection retry count
CONNECTION_RETRY_DELAY ?= 1000          # Connection retry delay in milliseconds

# ====== FILE SYSTEM TESTING CONFIGURATION ======

# File system test parameters
FS_TEST_DIRECTORY ?= /tmp/ksmbd_test   # Test directory path
FS_TEST_FILE_SIZE ?= 1048576          # Test file size (1MB)
FS_TEST_FILE_COUNT ?= 100              # Number of test files
FS_TEST_DIRECTORY_DEPTH ?= 10           # Directory depth for testing

# File system operations
FS_TEST_CREATE_OPERATIONS ?= true       # Test file creation
FS_TEST_READ_OPERATIONS ?= true         # Test file reading
FS_TEST_WRITE_OPERATIONS ?= true        # Test file writing
FS_TEST_DELETE_OPERATIONS ?= true       # Test file deletion
FS_TEST_RENAME_OPERATIONS ?= true       # Test file renaming

# Extended attributes testing
FS_TEST_XATTR_ENABLED ?= true          # Enable extended attributes testing
FS_TEST_XATTR_COUNT ?= 10              # Number of extended attributes per file
FS_TEST_XATTR_SIZE ?= 1024              # Extended attribute size in bytes

# ====== VALIDATION THRESHOLDS ======

# Success rate thresholds
MIN_SUCCESS_RATE_BASIC ?= 98           # Minimum success rate for basic tests
MIN_SUCCESS_RATE_ADVANCED ?= 95       # Minimum success rate for advanced tests
MIN_SUCCESS_RATE_PRODUCTION ?= 90      # Minimum success rate for production tests

# Performance thresholds
MAX_LATENCY_INCREASE ?= 50            # Maximum latency increase percentage
MAX_MEMORY_LEAK_BYTES ?= 1024          # Maximum memory leak in bytes
MAX_HANDLE_LEAK_COUNT ?= 10            # Maximum handle leak count

# Security thresholds
SECURITY_VULNERABILITY_COUNT ?= 0       # Maximum allowed vulnerabilities
SECURITY_WEAKNESS_COUNT ?= 5            # Maximum allowed weaknesses
SECURITY_COMPLIANCE_VIOLATIONS ?= 0     # Maximum compliance violations

# ====== REPORTING AND ANALYSIS ======

# Test reporting
REPORT_DETAILED_RESULTS ?= true         # Generate detailed test reports
REPORT_PERFORMANCE_METRICS ?= true      # Include performance metrics
REPORT_SECURITY_ASSESSMENT ?= true     # Include security assessment
REPORT_RECOMMENDATIONS ?= true         # Include recommendations

# Analysis parameters
ANALYSIS_TREND_COMPARISON ?= true      # Compare with historical trends
ANALYSIS_BASELINE_COMPARISON ?= true    # Compare with baseline performance
ANALYSIS_ROOT_CAUSE ?= true             # Include root cause analysis

# ====== CONTINUOUS INTEGRATION ======

# CI testing parameters
CI_PARALLEL_JOBS ?= 4                 # Number of parallel CI jobs
CI_TIMEOUT_MINUTES ?= 30               # CI timeout in minutes
CI_RETRY_COUNT ?= 3                    # CI retry count for failed tests
CI_EMAIL_NOTIFICATIONS ?= false        # Send email notifications for CI results

# CI test selection
CI_RUN_BASIC_TESTS ?= true             # Run basic tests in CI
CI_RUN_SECURITY_TESTS ?= false          # Run security tests in CI
CI_RUN_PERFORMANCE_TESTS ?= false       # Run performance tests in CI

# ====== SPECIALIZED TESTING ======

# Fuzz testing configuration
FUZZING_ENABLED ?= false               # Enable fuzz testing
FUZZING_ITERATIONS ?= 100000           # Number of fuzzing iterations
FUZZING_MUTATION_RATE ?= 10           # Fuzzing mutation rate percentage
FUZZING_CRASH_REPRODUCTION ?= true     # Enable crash reproduction

# Longevity testing
LONGEVITY_TESTING_ENABLED ?= false      # Enable longevity testing
LONGEVITY_DURATION_HOURS ?= 24          # Longevity test duration in hours
LONGEVITY_OPERATION_COUNT ?= 1000000    # Longevity test operation count

# Memory testing
MEMORY_CORRUPTION_TESTING ?= false      # Enable memory corruption testing
MEMORY_STRESS_TESTING ?= false          # Enable memory stress testing
MEMORY_LEAK_DETECTION ?= true           # Enable memory leak detection

# ====== DEVELOPMENT CONFIGURATION ======

# Development features
DEVELOPER_MODE ?= false                  # Enable developer mode features
EXPERIMENTAL_FEATURES ?= false          # Enable experimental features
DEBUG_ASSERTIONS ?= true                 # Enable debug assertions
TRACE_INSTRUMENTATION ?= true           # Enable trace instrumentation

# Development tools
VALGRIND_ANALYSIS ?= true              # Enable Valgrind analysis
GDB_DEBUGGING_SUPPORT ?= true          # Enable GDB debugging support
PROFILING_TOOLS ?= true                # Enable profiling tools

# ====== PLATFORM-SPECIFIC CONFIGURATION ======

# Platform detection and configuration
PLATFORM ?= $(shell uname -m)
PLATFORM_X86_64 ?= $(filter x86_64,$(PLATFORM))
PLATFORM_AARCH64 ?= $(filter aarch64 arm64,$(PLATFORM))
PLATFORM_POWERPC ?= $(filter ppc64 ppc64le,$(PLATFORM))

# Platform-specific flags
ifeq ($(PLATFORM_X86_64),x86_64)
    ARCH_FLAGS ?= $(ARCH_X86_64_FLAGS)
else ifeq ($(PLATFORM_AARCH64),aarch64)
    ARCH_FLAGS ?= $(ARCH_AARCH64_FLAGS)
else ifeq ($(PLATFORM_POWERPC),ppc64)
    ARCH_FLAGS ?= $(ARCH_POWERPC_FLAGS)
endif

# Kernel version compatibility
KERNEL_VERSION ?= $(shell uname -r)
KERNEL_MAJOR ?= $(word 1,$(subst ., ,$(KERNEL_VERSION)))
KERNEL_MINOR ?= $(word 2,$(subst ., ,$(KERNEL_VERSION)))

# Feature compatibility based on kernel version
ifeq ($(shell expr $(KERNEL_MAJOR) \>= 5),1)
    KERNEL_SUPPORTS_MODERN_FEATURES ?= true
else
    KERNEL_SUPPORTS_MODERN_FEATURES ?= false
endif

# ====== CUSTOMIZATION OVERRIDES ======

# Allow custom configuration files
CUSTOM_CONFIG_FILE ?= $(TEST_CONFIG_CUSTOM)
-include $(CUSTOM_CONFIG_FILE)

# Environment variable overrides
TEST_TIMEOUT := $(or $(TEST_TIMEOUT_OVERRIDE),$(TEST_TIMEOUT))
TEST_ITERATIONS := $(or $(TEST_ITERATIONS_OVERRIDE),$(TEST_ITERATIONS))
TEST_CONCURRENT_SESSIONS := $(or $(TEST_CONCURRENT_SESSIONS_OVERRIDE),$(TEST_CONCURRENT_SESSIONS))

# ====== MAKEFILE COMPATIBILITY ======

# Export configuration variables
export TEST_TIMEOUT TEST_ITERATIONS TEST_CONCURRENT_SESSIONS
export TEST_MEMORY_LIMIT TEST_CPU_LIMIT
export PERF_MIN_OPS_PER_SEC PERF_MAX_LATENCY_MS
export PROD_MAX_CONNECTIONS SECURITY_VALIDATION_ENABLED

# Mark file as imported
TEST_CONFIG_IMPORTED ?= 1