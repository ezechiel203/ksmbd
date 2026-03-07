#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# run_all_tests.sh -- Top-level test orchestrator for ksmbd
#
# Usage:
#   ./test/run_all_tests.sh [--kunit] [--fuzz-build] [--integration] [--all]
#   ./test/run_all_tests.sh --check
#   ./test/run_all_tests.sh --help
#
# Exit codes:
#   0 - All requested tests passed
#   1 - One or more tests failed
#   2 - Usage error

set -uo pipefail

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Colors (disabled if stdout is not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_GREEN='\033[0;32m'
    C_RED='\033[0;31m'
    C_YELLOW='\033[0;33m'
    C_CYAN='\033[0;36m'
    C_RESET='\033[0m'
else
    C_GREEN='' C_RED='' C_YELLOW='' C_CYAN='' C_RESET=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass()  { printf "${C_GREEN}PASS${C_RESET}: %s\n" "$1"; }
fail()  { printf "${C_RED}FAIL${C_RESET}: %s\n" "$1"; }
skip()  { printf "${C_YELLOW}SKIP${C_RESET}: %s -- %s\n" "$1" "$2"; }
info()  { printf "${C_CYAN}INFO${C_RESET}: %s\n" "$1"; }
section() { printf "\n${C_CYAN}=== %s ===${C_RESET}\n\n" "$1"; }

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

record_pass() { TOTAL_PASS=$((TOTAL_PASS + 1)); pass "$1"; }
record_fail() { TOTAL_FAIL=$((TOTAL_FAIL + 1)); fail "$1"; }
record_skip() { TOTAL_SKIP=$((TOTAL_SKIP + 1)); skip "$1" "$2"; }

default_kdir() {
    local current="/lib/modules/$(uname -r)/build"
    local current_usr="/usr/lib/modules/$(uname -r)/build"
    local latest=""

    if [ -d "$current" ]; then
        printf '%s\n' "$current"
        return 0
    fi

    if [ -d "$current_usr" ]; then
        printf '%s\n' "$current_usr"
        return 0
    fi

    latest=$(
        find /lib/modules /usr/lib/modules -mindepth 2 -maxdepth 2 -type d -name build 2>/dev/null |
        sort -V |
        tail -n 1
    )

    if [ -n "$latest" ]; then
        printf '%s\n' "$latest"
        return 0
    fi

    printf '%s\n' "$current"
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
Usage: ./test/run_all_tests.sh [OPTIONS]

Options:
  --check         Run the test/fuzz registration check only
  --kunit         Run KUnit tests (via kunit.py or modprobe)
  --fuzz-build    Build-verify all fuzz harnesses (kernel + userspace)
  --integration   Run integration tests (requires VM with ksmbd running)
  --all           Run all available test types
  --help          Show this help

Environment variables:
  KDIR            Kernel build directory (default: /lib/modules/$(uname -r)/build)
  LINUX_SRC       Full kernel source tree (for kunit.py; optional)
  VM_NAME         VM name for integration tests (default: VM3)

Examples:
  # Quick CI check (registration only):
  ./test/run_all_tests.sh --check

  # Build-verify everything except integration:
  ./test/run_all_tests.sh --kunit --fuzz-build

  # Full run including integration tests:
  ./test/run_all_tests.sh --all
EOF
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
DO_CHECK=0
DO_KUNIT=0
DO_FUZZ=0
DO_INTEGRATION=0

if [ $# -eq 0 ]; then
    usage
    exit 2
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --check)        DO_CHECK=1; shift ;;
        --kunit)        DO_KUNIT=1; shift ;;
        --fuzz-build)   DO_FUZZ=1; shift ;;
        --integration)  DO_INTEGRATION=1; shift ;;
        --all)          DO_CHECK=1; DO_KUNIT=1; DO_FUZZ=1; DO_INTEGRATION=1; shift ;;
        --help|-h)      usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# --all implies --check; individual modes also run it as a prerequisite
if [ $DO_KUNIT -eq 1 ] || [ $DO_FUZZ -eq 1 ] || [ $DO_INTEGRATION -eq 1 ]; then
    DO_CHECK=1
fi

# ---------------------------------------------------------------------------
# Gate 0: Registration check
# ---------------------------------------------------------------------------
if [ $DO_CHECK -eq 1 ]; then
    section "Test Registration Check"

    if [ -x "$SCRIPT_DIR/check_test_registration.sh" ]; then
        if "$SCRIPT_DIR/check_test_registration.sh"; then
            record_pass "All test/fuzz files registered in Makefiles"
        else
            record_fail "Some test/fuzz files missing from Makefiles"
        fi
    else
        record_skip "check_test_registration.sh" "script not found or not executable"
    fi
fi

# ---------------------------------------------------------------------------
# Gate 1: KUnit tests
# ---------------------------------------------------------------------------
if [ $DO_KUNIT -eq 1 ]; then
    section "KUnit Tests"

    KDIR="${KDIR:-$(default_kdir)}"
    LINUX_SRC="${LINUX_SRC:-}"

    # Strategy 1: Try kunit.py if full kernel source is available
    if [ -n "$LINUX_SRC" ] && [ -f "$LINUX_SRC/tools/testing/kunit/kunit.py" ]; then
        info "Running KUnit via kunit.py (LINUX_SRC=$LINUX_SRC)"

        # Ensure ksmbd is wired into the kernel tree
        if [ ! -d "$LINUX_SRC/fs/ksmbd/test" ]; then
            info "Copying ksmbd into kernel tree at $LINUX_SRC/fs/ksmbd/"
            mkdir -p "$LINUX_SRC/fs/ksmbd/test" "$LINUX_SRC/fs/ksmbd/mgmt"
            cp -a "$REPO_ROOT"/*.c "$REPO_ROOT"/*.h "$REPO_ROOT"/*.asn1 \
                  "$REPO_ROOT"/Kconfig "$REPO_ROOT"/Makefile \
                  "$LINUX_SRC/fs/ksmbd/" 2>/dev/null || true
            cp -a "$REPO_ROOT"/mgmt/* "$LINUX_SRC/fs/ksmbd/mgmt/" 2>/dev/null || true
            cp -a "$REPO_ROOT"/test/*.c "$REPO_ROOT"/test/Makefile \
                  "$LINUX_SRC/fs/ksmbd/test/" 2>/dev/null || true
            cp -a "$REPO_ROOT"/test/kunit.kunitconfig \
                  "$LINUX_SRC/fs/ksmbd/test/" 2>/dev/null || true

            # Wire into fs/ if not already done
            if ! grep -q 'fs/ksmbd/Kconfig' "$LINUX_SRC/fs/Kconfig" 2>/dev/null; then
                echo 'source "fs/ksmbd/Kconfig"' >> "$LINUX_SRC/fs/Kconfig"
            fi
            if ! grep -q 'ksmbd' "$LINUX_SRC/fs/Makefile" 2>/dev/null; then
                echo 'obj-$(CONFIG_SMB_SERVER) += ksmbd/' >> "$LINUX_SRC/fs/Makefile"
            fi
        fi

        cd "$LINUX_SRC"
        if python3 tools/testing/kunit/kunit.py run \
                --kunitconfig=fs/ksmbd/test/kunit.kunitconfig \
                --arch=um \
                --timeout=300 2>&1 | tee /tmp/kunit_output.txt | tail -30; then
            record_pass "KUnit tests via kunit.py"
        else
            record_fail "KUnit tests via kunit.py (see output above)"
        fi
        cd "$REPO_ROOT"

    # Strategy 2: Build as external module (compile-check only)
    elif [ -d "$KDIR" ]; then
        info "Kernel headers found at $KDIR (compile-check only)"
        info "Set LINUX_SRC=/path/to/linux to run tests via kunit.py"

        if make -C "$KDIR" M="$REPO_ROOT" \
                ARCH=x86_64 \
                CONFIG_SMB_SERVER=m \
                CONFIG_SMB_SERVER_SMBDIRECT=n \
                CONFIG_SMB_INSECURE_SERVER=y \
                CONFIG_KSMBD_FRUIT=y \
                CONFIG_SMB_SERVER_QUIC=n \
                CONFIG_KSMBD_KUNIT_TEST=m \
                modules 2>&1 | tail -20; then
            record_pass "KUnit test compilation (external module build)"
        else
            record_fail "KUnit test compilation (external module build)"
        fi

    else
        record_skip "KUnit tests" "no kernel headers found (set KDIR or LINUX_SRC)"
    fi
fi

# ---------------------------------------------------------------------------
# Gate 2: Fuzz build verification
# ---------------------------------------------------------------------------
if [ $DO_FUZZ -eq 1 ]; then
    section "Fuzz Harness Build Verification"

    KDIR="${KDIR:-$(default_kdir)}"

    # 2a: Kernel fuzz harnesses (compile-check)
    if [ -d "$KDIR" ] && [ -f "$REPO_ROOT/test/fuzz/Makefile" ]; then
        info "Building kernel fuzz harnesses (compile-check)..."
        if make -C "$KDIR" M="$REPO_ROOT" \
                ARCH=x86_64 \
                CONFIG_SMB_SERVER=m \
                CONFIG_SMB_SERVER_SMBDIRECT=n \
                CONFIG_SMB_INSECURE_SERVER=y \
                CONFIG_KSMBD_FRUIT=y \
                CONFIG_SMB_SERVER_QUIC=n \
                CONFIG_KSMBD_FUZZ_TEST=m \
                modules 2>&1 | tail -10; then
            record_pass "Kernel fuzz harness compilation"
        else
            record_fail "Kernel fuzz harness compilation"
        fi
    else
        record_skip "Kernel fuzz harnesses" "no kernel headers at $KDIR or test/fuzz/Makefile missing"
    fi

    # 2b: Userspace fuzz harnesses (build + optional smoke test)
    USERSPACE_FUZZ_DIR="$REPO_ROOT/test/fuzz/userspace"
    if [ -f "$USERSPACE_FUZZ_DIR/Makefile" ]; then
        if command -v clang >/dev/null 2>&1; then
            info "Building userspace libFuzzer targets..."
            if make -C "$USERSPACE_FUZZ_DIR" clean 2>/dev/null; true; then
                if make -C "$USERSPACE_FUZZ_DIR" 2>&1; then
                    record_pass "Userspace fuzz target compilation"

                    # Count built targets
                    BUILT=$(find "$USERSPACE_FUZZ_DIR" -maxdepth 1 -name 'fuzz_*' -executable 2>/dev/null | wc -l)
                    info "Built $BUILT userspace fuzz targets"
                else
                    record_fail "Userspace fuzz target compilation"
                fi
            fi
        else
            record_skip "Userspace fuzz targets" "clang not installed"
        fi
    else
        record_skip "Userspace fuzz targets" "test/fuzz/userspace/Makefile not found"
    fi
fi

# ---------------------------------------------------------------------------
# Gate 3: Integration tests
# ---------------------------------------------------------------------------
if [ $DO_INTEGRATION -eq 1 ]; then
    section "Integration Tests"

    VM_NAME="${VM_NAME:-VM3}"
    TORTURE_SCRIPT="$REPO_ROOT/tests/ksmbd-torture/ksmbd-torture.sh"
    VM_EXEC="$REPO_ROOT/vm/vm-exec-instance.sh"

    # Check VM connectivity
    if [ -x "$VM_EXEC" ]; then
        info "Checking VM $VM_NAME connectivity..."
        if "$VM_EXEC" "$VM_NAME" "echo ok" >/dev/null 2>&1; then
            info "VM $VM_NAME is reachable"

            if [ -x "$TORTURE_SCRIPT" ]; then
                info "Running ksmbd-torture suite on $VM_NAME..."
                if "$TORTURE_SCRIPT" --vm "$VM_NAME" --quick --tap 2>&1; then
                    record_pass "Integration tests (ksmbd-torture --quick)"
                else
                    EXIT_CODE=$?
                    case $EXIT_CODE in
                        1) record_fail "Integration tests: some tests failed" ;;
                        2) record_fail "Integration tests: server crash detected" ;;
                        3) record_fail "Integration tests: infrastructure error" ;;
                        *) record_fail "Integration tests: exit code $EXIT_CODE" ;;
                    esac
                fi
            else
                record_skip "ksmbd-torture" "tests/ksmbd-torture/ksmbd-torture.sh not found or not executable"
            fi
        else
            record_skip "Integration tests" "VM $VM_NAME is not reachable (set VM_NAME to change target)"
        fi
    else
        record_skip "Integration tests" "vm/vm-exec-instance.sh not found (no VM infrastructure)"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
section "Summary"

TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))
printf "Total: %d  |  " "$TOTAL"
printf "${C_GREEN}Passed: %d${C_RESET}  |  " "$TOTAL_PASS"
printf "${C_RED}Failed: %d${C_RESET}  |  " "$TOTAL_FAIL"
printf "${C_YELLOW}Skipped: %d${C_RESET}\n" "$TOTAL_SKIP"

if [ $TOTAL_FAIL -gt 0 ]; then
    echo ""
    printf "${C_RED}RESULT: FAIL${C_RESET}\n"
    exit 1
else
    echo ""
    printf "${C_GREEN}RESULT: PASS${C_RESET}\n"
    exit 0
fi
