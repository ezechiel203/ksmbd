#!/bin/bash
# lib/test_framework.sh -- Compatibility shim
#
# This file exists for backward compatibility with test files that source
# test_framework.sh directly. It forwards to framework.sh which is the
# authoritative implementation.
#
# New code should source lib/framework.sh directly.

_SHIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the real framework
# shellcheck disable=SC1091
source "${_SHIM_DIR}/framework.sh"

# Source assertion and helper libraries for standalone usage
# shellcheck disable=SC1091
source "${_SHIM_DIR}/assertions.sh"
# shellcheck disable=SC1091
source "${_SHIM_DIR}/smb_helpers.sh"
# shellcheck disable=SC1091
source "${_SHIM_DIR}/vm_control.sh"
# shellcheck disable=SC1091
source "${_SHIM_DIR}/server_health.sh"

# Legacy aliases for backward compatibility
TEST_IDS=()
TEST_FUNCS=()
TEST_DESCS=()
TEST_TIMEOUTS=()
TEST_REQUIRES=()
TEST_TAGS=()
TEST_AFTER=()
RESULT_IDS=()
RESULT_STATUS=()
RESULT_MS=()
RESULT_MSG=()

# Legacy function aliases
run_all() {
    filter_tests
    run_suite
}

print_summary() {
    _print_suite_summary
}
