#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
#   Copyright (C) 2023 ksmbd Contributors
#
#   Main test execution script for Apple SMB Extensions

set -eo pipefail

# Script information
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}" && pwd)"
TEST_DIR="${ROOT_DIR}/test_framework"

# Configuration
BUILD_SCRIPT="${TEST_DIR}/build_test_modules.sh"
AUTOMATION_SCRIPT="${TEST_DIR}/automation_framework.py"
CONFIG_FILE="${ROOT_DIR}/test_config.json"
RESULTS_DIR="${ROOT_DIR}/test_results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Global variables
VERBOSE=false
BUILD_ONLY=false
TEST_TYPE="all"
CI_MODE=false
SKIP_BUILD=false
KEEP_RESULTS=false
DRY_RUN=false
TEST_LOG=""
EXIT_CODE=0

# Test exit codes
EXIT_SUCCESS=0
EXIT_BUILD_FAILED=1
EXIT_TEST_FAILED=2
EXIT_CONFIG_ERROR=3
EXIT_RUNTIME_ERROR=4

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$TEST_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$TEST_LOG"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$TEST_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$TEST_LOG"
    EXIT_CODE=${EXIT_CODE:-$EXIT_TEST_FAILED}
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1" | tee -a "$TEST_LOG"
    fi
}

log_header() {
    echo -e "${CYAN}${BOLD}$1${NC}" | tee -a "$TEST_LOG"
    echo -e "${CYAN}$(printf '%*s' "${#1}" '' | tr ' ' '=')${NC}" | tee -a "$TEST_LOG"
}

# Print help information
show_help() {
    cat << EOF
${BOLD}Apple SMB Extensions Test Execution Script${NC}

${BOLD}Usage:${NC}
    $SCRIPT_NAME [OPTIONS] [COMMAND]

${BOLD}Commands:${NC}
    all                    Run all test suites (default)
    unit                   Run only unit tests
    integration            Run only integration tests
    performance            Run only performance tests
    security               Run only security tests
    build                  Only build test modules
    clean                  Clean build artifacts and results

${BOLD}Options:${NC}
    -h, --help             Show this help message
    -v, --verbose          Enable verbose output
    -c, --config FILE      Use specific config file (default: test_config.json)
    -o, --output DIR       Results directory (default: test_results)
    -j, --jobs N           Number of parallel jobs (default: auto)
    --ci-mode              CI/CD mode with strict quality gates
    --skip-build           Skip building test modules
    --keep-results         Don't clean results directory before running
    --dry-run              Show what would be done without executing
    --log-file FILE        Custom log file location

${BOLD}Examples:${NC}
    $SCRIPT_NAME                                    # Run all tests
    $SCRIPT_NAME --verbose unit                     # Run unit tests with verbose output
    $SCRIPT_NAME --ci-mode                          # Run in CI mode
    $SCRIPT_NAME --skip-build integration           # Skip build, run integration tests
    $SCRIPT_NAME --config my_config.json            # Use custom config

${BOLD}Quality Gates:${NC}
    • Code Coverage: ≥95%
    • Performance Improvement: ≥14x
    • Security Vulnerabilities: 0
    • Test Success Rate: 100%

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit $EXIT_SUCCESS
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -o|--output)
                RESULTS_DIR="$2"
                shift 2
                ;;
            -j|--jobs)
                # Handle parallel jobs (if needed in future)
                shift 2
                ;;
            --ci-mode)
                CI_MODE=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --keep-results)
                KEEP_RESULTS=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --log-file)
                TEST_LOG="$2"
                shift 2
                ;;
            all|unit|integration|performance|security|build|clean)
                TEST_TYPE="$1"
                shift
                ;;
            *)
                log_error "Unknown argument: $1"
                show_help
                exit $EXIT_CONFIG_ERROR
                ;;
        esac
    done
}

# Validate environment
validate_environment() {
    log_info "Validating test environment..."

    # Check if we're in the right directory
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        return $EXIT_CONFIG_ERROR
    fi

    # Check required scripts
    if [[ ! -f "$BUILD_SCRIPT" ]]; then
        log_error "Build script not found: $BUILD_SCRIPT"
        return $EXIT_CONFIG_ERROR
    fi

    if [[ ! -f "$AUTOMATION_SCRIPT" ]]; then
        log_error "Automation script not found: $AUTOMATION_SCRIPT"
        return $EXIT_CONFIG_ERROR
    fi

    # Check Python availability
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "Python3 is required but not found"
        return $EXIT_CONFIG_ERROR
    fi

    # Check for required modules
    if ! python3 -c "import json, subprocess, sys, time, threading, signal, tempfile, shutil, pathlib, argparse, logging, datetime" >/dev/null 2>&1; then
        log_error "Required Python modules not available"
        return $EXIT_CONFIG_ERROR
    fi

    log_success "Environment validation passed"
    return $EXIT_SUCCESS
}

# Setup test environment
setup_environment() {
    log_info "Setting up test environment..."

    # Create results directory
    if [[ "$KEEP_RESULTS" != "true" && "$TEST_TYPE" != "clean" ]]; then
        if [[ -d "$RESULTS_DIR" ]]; then
            log_info "Cleaning existing results directory..."
            rm -rf "$RESULTS_DIR"
        fi
    fi

    mkdir -p "$RESULTS_DIR"

    # Setup test log file
    if [[ -z "$TEST_LOG" ]]; then
        TEST_LOG="${RESULTS_DIR}/test_run_$(date +%Y%m%d_%H%M%S).log"
    fi

    mkdir -p "$(dirname "$TEST_LOG")"
    touch "$TEST_LOG"

    log_info "Test environment ready"
    log_info "Results directory: $RESULTS_DIR"
    log_info "Log file: $TEST_LOG"
}

# Build test modules
build_test_modules() {
    log_header "Building Test Modules"

    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "Skipping build as requested"
        return $EXIT_SUCCESS
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would build test modules using: $BUILD_SCRIPT"
        return $EXIT_SUCCESS
    fi

    if [[ ! -x "$BUILD_SCRIPT" ]]; then
        chmod +x "$BUILD_SCRIPT"
    fi

    local build_start=$(date +%s)
    log_info "Starting build at $(date)"

    if ! "$BUILD_SCRIPT" 2>&1 | tee -a "$TEST_LOG"; then
        log_error "Build failed"
        return $EXIT_BUILD_FAILED
    fi

    local build_end=$(date +%s)
    local build_duration=$((build_end - build_start))

    log_success "Build completed successfully in ${build_duration}s"
    return $EXIT_SUCCESS
}

# Run specific test suite
run_test_suite() {
    local suite="$1"
    local extra_args=()

    log_header "Running $suite Tests"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run $suite tests using: python3 $AUTOMATION_SCRIPT"
        return $EXIT_SUCCESS
    fi

    # Build automation command
    local cmd=("python3" "$AUTOMATION_SCRIPT" "--config" "$CONFIG_FILE" "--results-dir" "$RESULTS_DIR")

    case "$suite" in
        "unit")
            cmd+=("--unit-only")
            ;;
        "integration")
            cmd+=("--integration-only")
            ;;
        "performance")
            cmd+=("--performance-only")
            ;;
        "security")
            cmd+=("--security-only")
            ;;
        "all")
            # No additional arguments needed
            ;;
        *)
            log_error "Unknown test suite: $suite"
            return $EXIT_CONFIG_ERROR
            ;;
    esac

    if [[ "$VERBOSE" == "true" ]]; then
        cmd+=("--verbose")
    fi

    if [[ "$CI_MODE" == "true" ]]; then
        cmd+=("--ci-mode")
    fi

    log_info "Running: ${cmd[*]}"
    log_info "Suite started at $(date)"

    local test_start=$(date +%s)
    local test_output=""

    # Run tests with timeout
    if ! test_output=$("${cmd[@]}" 2>&1); then
        local test_exit_code=$?
        log_error "Test suite '$suite' failed with exit code: $test_exit_code"
        echo "$test_output" >> "$TEST_LOG"
        return $test_exit_code
    fi

    echo "$test_output" >> "$TEST_LOG"

    local test_end=$(date +%s)
    local test_duration=$((test_end - test_start))

    log_success "Test suite '$suite' completed successfully in ${test_duration}s"
    return $EXIT_SUCCESS
}

# Clean build artifacts and results
clean_artifacts() {
    log_header "Cleaning Build Artifacts and Results"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would clean build artifacts and results"
        return $EXIT_SUCCESS
    fi

    # Clean build directory
    local build_dir="${TEST_DIR}/build"
    if [[ -d "$build_dir" ]]; then
        log_info "Cleaning build directory: $build_dir"
        rm -rf "$build_dir"
    fi

    # Clean test modules
    for module_file in "${TEST_DIR}"/*.ko; do
        if [[ -f "$module_file" ]]; then
            log_info "Removing test module: $module_file"
            rm -f "$module_file"
        fi
    done

    # Clean results directory (unless keep results is set)
    if [[ "$KEEP_RESULTS" != "true" && -d "$RESULTS_DIR" ]]; then
        log_info "Cleaning results directory: $RESULTS_DIR"
        rm -rf "$RESULTS_DIR"
    fi

    # Clean object files and temporary build artifacts
    find "$TEST_DIR" -name "*.o" -delete 2>/dev/null || true
    find "$TEST_DIR" -name "*.mod.c" -delete 2>/dev/null || true
    find "$TEST_DIR" -name ".tmp_versions" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$TEST_DIR" -name "*.symvers" -delete 2>/dev/null || true
    find "$TEST_DIR" -name "*.order" -delete 2>/dev/null || true

    log_success "Clean completed"
    return $EXIT_SUCCESS
}

# Generate summary report
generate_summary() {
    if [[ ! -d "$RESULTS_DIR" || "$TEST_TYPE" == "clean" ]]; then
        return $EXIT_SUCCESS
    fi

    log_header "Generating Test Summary"

    local summary_file="${RESULTS_DIR}/summary.txt"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local git_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    local git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

    cat > "$summary_file" << EOF
Apple SMB Extensions Test Summary
=================================

Test Run Timestamp: $timestamp
Git Commit: $git_commit
Git Branch: $git_branch
Test Type: $TEST_TYPE
CI Mode: $CI_MODE
Verbose Mode: $VERBOSE

Configuration:
- Config File: $CONFIG_FILE
- Results Directory: $RESULTS_DIR
- Log File: $TEST_LOG

Quality Gates:
- Min Coverage: 95%
- Min Performance Improvement: 14x
- Max Security Vulnerabilities: 0

Results:
EOF

    # Find and analyze test result files
    local json_reports=("${RESULTS_DIR}"/test_report_*.json)
    if [[ ${#json_reports[@]} -gt 0 && -f "${json_reports[0]}" ]]; then
        local latest_report="${json_reports[-1]}" # Get most recent report

        if command -v jq >/dev/null 2>&1; then
            jq -r '{
                "Total Tests": .total_tests,
                "Passed Tests": .passed_tests,
                "Failed Tests": .failed_tests,
                "Skipped Tests": .skipped_tests,
                "Coverage": "\(.coverage_percentage)%",
                "Security Issues": .security_vulnerabilities,
                "Total Duration": "\(.total_duration)s"
            } | to_entries[] | "  \(.key): \(.value)"' "$latest_report" >> "$summary_file"
        else
            echo "  (Install jq for detailed summary)" >> "$summary_file"
        fi
    else
        echo "  No test reports found" >> "$summary_file"
    fi

    # Performance summary
    cat >> "$summary_file" << EOF

Performance Metrics:
EOF

    local perf_reports=("${RESULTS_DIR}"/test_report_*.json)
    if [[ ${#perf_reports[@]} -gt 0 && -f "${perf_reports[-1]}" ]]; then
        local latest_report="${perf_reports[-1]}"
        if command -v jq >/dev/null 2>&1; then
            jq -r '.performance_summary | to_entries[] | "  \(.key): \(.value.improvement_ratio) improvement"' "$latest_report" >> "$summary_file"
        fi
    fi

    cat >> "$summary_file" << EOF

Files Generated:
EOF

    # List generated files
    find "$RESULTS_DIR" -type f -name "*.json" -o -name "*.xml" -o -name "*.html" | sort | while read -r file; do
        local file_size=$(stat -c%s "$file" 2>/dev/null || echo "unknown")
        echo "  - $file (${file_size} bytes)" >> "$summary_file"
    done

    log_success "Summary generated: $summary_file"
    return $EXIT_SUCCESS
}

# Main execution function
main() {
    local start_time=$(date +%s)
    EXIT_CODE=$EXIT_SUCCESS

    log_header "Apple SMB Extensions Test Framework"
    log_info "Started at $(date)"
    log_info "Test type: $TEST_TYPE"

    # Parse command line arguments
    parse_args "$@"

    # Validate environment
    validate_environment || exit $?

    # Setup environment
    setup_environment

    # Execute requested command
    case "$TEST_TYPE" in
        "build")
            build_test_modules || exit $?
            ;;
        "clean")
            clean_artifacts || exit $?
            ;;
        "unit"|"integration"|"performance"|"security"|"all")
            build_test_modules || exit $?
            run_test_suite "$TEST_TYPE" || exit $?
            ;;
        *)
            log_error "Unknown test type: $TEST_TYPE"
            exit $EXIT_CONFIG_ERROR
            ;;
    esac

    # Generate summary
    generate_summary

    # Final status
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))

    log_header "Test Execution Complete"
    log_info "Total duration: ${total_duration}s"
    log_info "Exit code: $EXIT_CODE"

    if [[ $EXIT_CODE -eq $EXIT_SUCCESS ]]; then
        log_success "All operations completed successfully"
    else
        log_error "Some operations failed"
    fi

    exit $EXIT_CODE
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi