#!/bin/bash

# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_arm64_setup.sh - Test script to verify ARM64 cross-compilation setup
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"

    print_info "Testing: $test_name"

    if eval "$test_command" >/dev/null 2>&1; then
        print_success "✓ $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        print_error "✗ $test_name"
        ((TESTS_FAILED++))
        return 1
    fi
}

print_info "KSMBD ARM64 Cross-Compilation Setup Test"
print_info "=========================================="
echo

# Test 1: Check macOS ARM64 environment
run_test "macOS ARM64 system" "[[ \"\$(uname)\" == \"Darwin\" && \"\$(uname -m)\" == \"arm64\" ]]"

# Test 2: Check Homebrew
run_test "Homebrew installed" "command -v brew"

# Test 3: Check cross-compilers
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    run_test "aarch64-linux-gnu-gcc available" "true"
    CROSS_COMPILER="aarch64-linux-gnu-gcc"
elif command -v aarch64-elf-gcc >/dev/null 2>&1; then
    run_test "aarch64-elf-gcc available (recommended: aarch64-linux-gnu-gcc)" "true"
    CROSS_COMPILER="aarch64-elf-gcc"
else
    run_test "No ARM64 cross-compiler found" "false"
    CROSS_COMPILER=""
fi

# Test 4: Check required tools
run_test "curl available" "command -v curl"
run_test "tar available" "command -v tar"
run_test "make available" "command -v make"

# Test 5: Check script files exist and are executable
run_test "setup_arm64_build.sh exists" "[[ -f \"setup_arm64_build.sh\" ]]"
run_test "setup_arm64_build.sh executable" "[[ -x \"setup_arm64_build.sh\" ]]"
run_test "build_arm64.sh exists" "[[ -f \"build_arm64.sh\" ]]"
run_test "build_arm64.sh executable" "[[ -x \"build_arm64.sh\" ]]"
run_test "Makefile.arm64 exists" "[[ -f \"Makefile.arm64\" ]]"
run_test "smb2pdu.c source file exists" "[[ -f \"smb2pdu.c\" ]]"

# Test 6: Check script syntax
run_test "setup_arm64_build.sh syntax valid" "bash -n setup_arm64_build.sh"
run_test "build_arm64.sh syntax valid" "bash -n build_arm64.sh"

# Test 7: Check if build directory exists
run_test "build-arm64 directory status" "[[ ! -d \"build-arm64\" ]] || echo \"build-arm64 exists\""

# Test 8: Test cross-compiler if available
if [ -n "$CROSS_COMPILER" ]; then
    run_test "Cross-compiler version check" "$CROSS_COMPILER --version"
    run_test "Cross-compiler target check" "$CROSS_COMPILER -dumpmachine | grep -q aarch64"
fi

echo
print_info "=== Test Results ==="
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"
echo "Total tests:  $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    print_success "All tests passed! Setup is ready."
    echo
    print_info "Next steps:"
    echo "1. Run: ./setup_arm64_build.sh"
    echo "2. Then: ./build_arm64.sh"
    exit 0
else
    print_error "Some tests failed. Please address the issues above."
    echo
    print_info "Common fixes:"
    echo "- Install missing tools: brew install curl tar make"
    echo "- Install cross-compiler: brew install aarch64-linux-gnu-binutils"
    echo "- Make scripts executable: chmod +x *.sh"
    exit 1
fi