# Apple SMB Extensions Test Framework

A comprehensive testing framework for validating Apple client support in the ksmbd SMB server. This framework provides unit tests, integration tests, performance benchmarks, and security validation specifically designed for Apple SMB protocol extensions.

## 📋 Overview

This test framework ensures that the Apple SMB extensions implementation meets the following objectives:

- **100% Apple client detection accuracy**
- **Robust AAPL create context parsing**
- **Successful capability negotiation**
- **14x performance improvement in directory traversal**
- **Zero regression in existing SMB functionality**
- **Comprehensive security validation**

## 🏗️ Framework Architecture

```
test_framework/
├── README.md                     # This file
├── unit_test_framework.c         # Kernel module unit tests
├── integration_test_framework.c  # Kernel module integration tests
├── performance_test_framework.c # Kernel module performance tests
├── automation_framework.py       # Python automation and CI/CD
├── build_test_modules.sh         # Build script for test modules
├── test_utils.h                 # Common test utilities
└── build/                        # Build artifacts (generated)
```

## 🚀 Quick Start

### Prerequisites

- Linux kernel source with ksmbd
- Build tools (gcc, make, etc.)
- Python 3.6+
- Root privileges for kernel module loading

### Building and Running Tests

1. **Clone and setup the repository:**
   ```bash
   cd /path/to/ksmbd
   chmod +x test_framework/build_test_modules.sh
   chmod +x run_tests.sh
   ```

2. **Run all tests:**
   ```bash
   ./run_tests.sh
   ```

3. **Run specific test suites:**
   ```bash
   ./run_tests.sh unit              # Unit tests only
   ./run_tests.sh integration       # Integration tests only
   ./run_tests.sh performance       # Performance tests only
   ./run_tests.sh security          # Security tests only
   ```

4. **CI/CD mode (strict quality gates):**
   ```bash
   ./run_tests.sh --ci-mode
   ```

## 📊 Test Categories

### 1. Unit Tests (70% coverage)

**Location:** `test_framework/unit_test_framework.c`

**Scope:**
- Apple client detection logic
- AAPL create context parsing
- Connection management
- Memory handling
- Error conditions

**Key Tests:**
- `test_apple_client_detection_new_connection()`
- `test_apple_client_detection_aapl_context()`
- `test_aapl_context_parsing_valid()`
- `test_connection_memory_management()`

### 2. Integration Tests (20% coverage)

**Location:** `test_framework/integration_test_framework.c`

**Scope:**
- End-to-end Apple client workflows
- Capability negotiation
- Directory traversal flows
- Concurrent client handling
- Error recovery scenarios

**Key Tests:**
- `test_scenario_basic_connection()`
- `test_scenario_aapl_capability_negotiation()`
- `test_scenario_directory_traversal_performance()`
- `test_scenario_concurrent_clients()`

### 3. Performance Tests (7% coverage)

**Location:** `test_framework/performance_test_framework.c`

**Scope:**
- Directory traversal benchmarking
- Baseline vs. Apple-optimized performance
- Concurrent access patterns
- Memory efficiency validation

**Key Metrics:**
- 14x performance improvement target
- P50, P90, P95, P99 latencies
- Memory usage patterns
- Throughput measurements

### 4. Security Tests (3% coverage)

**Location:** `automated via automation_framework.py`

**Scope:**
- Input validation fuzzing
- Resource limit testing
- Memory corruption detection
- Authentication validation

## 🧪 Test Execution

### Command Line Options

```bash
./run_tests.sh [OPTIONS] [COMMAND]

Options:
  -h, --help              Show help message
  -v, --verbose           Enable verbose output
  -c, --config FILE       Use specific config file
  -o, --output DIR        Results directory
  --ci-mode              CI/CD mode with strict gates
  --skip-build           Skip building test modules
  --keep-results          Don't clean results directory
  --dry-run              Show what would be done

Commands:
  all                    Run all test suites (default)
  unit                   Run only unit tests
  integration            Run only integration tests
  performance            Run only performance tests
  security               Run only security tests
  build                  Only build test modules
  clean                  Clean build artifacts
```

### Examples

```bash
# Run all tests with verbose output
./run_tests.sh --verbose all

# Run only unit tests in CI mode
./run_tests.sh --ci-mode unit

# Use custom configuration and output directory
./run_tests.sh --config my_config.json --output custom_results performance

# Clean all build artifacts
./run_tests.sh clean

# Show what would be done
./run_tests.sh --dry-run all
```

## 📈 Quality Gates

The test framework enforces strict quality gates:

### Coverage Requirements
- **Overall Coverage:** ≥95%
- **Critical Path Coverage:** 100%
- **Apple-Specific Code:** 98%+

### Performance Requirements
- **Directory Traversal Improvement:** ≥14x
- **Regression Tolerance:** ≤5%
- **Memory Overhead:** ≤10%

### Security Requirements
- **Critical Vulnerabilities:** 0
- **Memory Leaks:** 0
- **Use-After-Free:** 0
- **Buffer Overflows:** 0

## 📊 Test Results and Reporting

### Generated Reports

1. **JSON Report:** `test_results/test_report_YYYYMMDD_HHMMSS.json`
   - Machine-readable format
   - Complete test metrics
   - Performance benchmarks

2. **HTML Report:** `test_results/test_report_YYYYMMDD_HHMMSS.html`
   - Visual test results
   - Performance charts
   - Interactive dashboard

3. **JUnit XML:** `test_results/junit_report_YYYYMMDD_HHMMSS.xml`
   - CI/CD integration
   - Test results format
   - Failure details

4. **Coverage Report:** Generated using gcov/lcov
   - Code coverage analysis
   - Highlighted source code
   - Coverage metrics

### Example Output

```
🧪 Starting Apple SMB Extensions Test Framework
=======================================================
[INFO] Validating test environment...
[INFO] Setting up test environment...
[INFO] Results directory: test_results
[INFO] Log file: test_results/test_run_20231115_143022.log

=== Starting Performance Test: Apple Directory Traversal ===
[INFO] Description: Test Apple-optimized directory traversal performance
[INFO] Apple optimized: Yes
[INFO] Baseline test: No
✅ Performance test 'Apple Directory Traversal' passed
  Operations: 1000, Time: 850000 ns, Avg: 850 ns
  Improvement ratio: 14.71x

=======================================================
Performance Test Summary:
  Total tests: 8
  Failed tests: 0
  Total test time: 42512345 ns
  Success rate: 100%
✅ 14x performance improvement achieved: 14.71x
```

## 🔧 Configuration

### Test Configuration

The framework uses `test_config.json` for configuration:

```json
{
  "quality_gates": {
    "min_coverage": 95.0,
    "max_vulnerabilities": 0,
    "min_performance_improvement": 14.0
  },
  "test_suites": {
    "unit_tests": {
      "enabled": true,
      "timeout": 300,
      "critical": true
    },
    "performance_tests": {
      "enabled": true,
      "timeout": 1200,
      "critical": true
    }
  }
}
```

### Performance Test Configuration

```json
{
  "performance_test_config": {
    "test_types": {
      "apple_traversal": {
        "iterations": 1000,
        "directory_depth": 3,
        "directory_width": 5,
        "apple_optimized": true
      }
    }
  }
}
```

## 🏗️ CI/CD Integration

### GitHub Actions Example

```yaml
name: Apple SMB Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run Tests
      run: ./run_tests.sh --ci-mode
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: test_results/
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    stages {
        stage('Test') {
            steps {
                sh './run_tests.sh --ci-mode'
            }
        }
        stage('Publish Results') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'test_results',
                    reportFiles: '*.html',
                    reportName: 'Test Report'
                ])
            }
        }
    }
}
```

## 🐛 Debugging

### Common Issues

1. **Kernel Module Build Failures**
   ```bash
   # Check kernel source is properly configured
   make defconfig
   make prepare

   # Enable debug symbols
   echo "CONFIG_DEBUG_INFO=y" >> .config
   ```

2. **Module Loading Failures**
   ```bash
   # Check kernel version compatibility
   uname -r

   # Check module dependencies
   lsmod | grep ksmbd

   # View kernel messages
   dmesg | tail -20
   ```

3. **Test Timeouts**
   ```bash
   # Increase timeout in test_config.json
   {
     "test_suites": {
       "performance_tests": {
         "timeout": 1800
       }
     }
   }
   ```

### Debug Mode

```bash
# Run with verbose output
./run_tests.sh --verbose all

# Run individual test module
sudo insmod test_framework/unit_test_framework.ko
dmesg | tail

# Dry run to see what would be executed
./run_tests.sh --dry-run all
```

## 📝 Extending the Framework

### Adding New Unit Tests

```c
// In unit_test_framework.c
static void test_new_feature(void)
{
    struct ksmbd_conn *conn = create_test_connection(true);
    const char *test_name = "New Feature Test";

    atomic_inc(&test_stats.total_tests);

    TEST_ASSERT_PTR_NOT_NULL(conn, test_name, "Failed to create connection");
    TEST_ASSERT_EQ(true, conn->is_aapl, test_name, "Should be Apple client");

    free_test_connection(conn);
    test_pass(test_name);
}

// Add to test_cases array:
static struct test_case apple_test_cases[] = {
    // ... existing tests ...
    {"new_feature_test", test_new_feature},
    {NULL, NULL}
};
```

### Adding New Integration Tests

```c
// In integration_test_framework.c
static int test_scenario_new_workflow(struct apple_client_state *client)
{
    int ret;

    ret = simulate_apple_negotiation(client);
    if (ret != 0) return ret;

    // Implement new workflow test logic
    TEST_INFO("Testing new workflow");

    return 0;
}
```

### Adding New Performance Tests

```c
// In performance_test_framework.c
static int run_new_performance_test(struct performance_test_context *ctx)
{
    // Implement new performance test
    for (unsigned int i = 0; i < ctx->config->iterations; i++) {
        start_time = get_time_ns();
        // Perform operation
        end_time = get_time_ns();
        update_performance_metrics(&ctx->result, end_time - start_time);
    }
    return 0;
}
```

## 📊 Performance Analysis

The framework provides detailed performance analysis:

### Baseline vs. Optimized

```
Test: Directory Traversal
  Baseline: 12,500,000 ns per operation
  Optimized: 850,000 ns per operation
  Improvement: 14.71x
  P95 latency: 950,000 ns
  Memory overhead: 2,048 KB
```

### Performance Validation

- **14x Improvement Target**: Automated validation
- **Regression Detection**: Automatic failure on >5% regression
- **Latency Analysis**: P50, P90, P95, P99 percentiles
- **Memory Monitoring**: Track memory usage patterns

## 🔒 Security Testing

### Automated Security Checks

- **Input Validation**: Fuzz testing of AAPL context parsing
- **Buffer Bounds**: Automatic boundary checking
- **Memory Safety**: Use-after-free detection
- **Resource Limits**: Connection and memory limits

### Security Vulnerability Scanning

```bash
# Static analysis
cppcheck --enable=all --inconclusive smb2pdu.c

# Dynamic analysis (requires special kernel setup)
valgrind --tool=memcheck ./test_binaries

# Fuzz testing
./run_tests.sh security --fuzz-iterations=100000
```

## 🤝 Contributing

1. Follow kernel coding style
2. Add tests for new functionality
3. Update documentation
4. Run full test suite before submission
5. Ensure quality gates are met

### Test Development Guidelines

- **Unit Tests**: Test individual functions in isolation
- **Integration Tests**: Test complete workflows
- **Performance Tests**: Include baseline and optimized versions
- **Security Tests**: Consider edge cases and boundary conditions

## 📄 License

This test framework is part of the ksmbd project and is licensed under GPL-2.0-or-later.

## 🙏 Acknowledgments

- ksmbd project contributors
- Linux kernel development community
- Apple SMB protocol documentation
- Testing and validation frameworks

---

For questions or issues, please refer to the main ksmbd project documentation or submit issues through the project's issue tracker.