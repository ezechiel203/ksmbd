#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# CI gate script: verify that all test and fuzz source files are
# registered in their respective Makefiles.
#
# Usage:
#   ./test/check_test_registration.sh
#
# Exit codes:
#   0 - All files registered
#   1 - One or more files missing from Makefiles
#
# Suitable for GitHub Actions, GitLab CI, or any CI system.

set -u

# Resolve the repository root (one level up from test/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TEST_DIR="$REPO_ROOT/test"
FUZZ_DIR="$REPO_ROOT/test/fuzz"
TEST_MAKEFILE="$TEST_DIR/Makefile"
FUZZ_MAKEFILE="$FUZZ_DIR/Makefile"

errors=0
missing_tests=""
missing_fuzz=""

# ---- Check test/ksmbd_test_*.c files ----

if [ ! -f "$TEST_MAKEFILE" ]; then
    echo "ERROR: $TEST_MAKEFILE not found"
    exit 1
fi

test_makefile_content=$(cat "$TEST_MAKEFILE")

for src_file in "$TEST_DIR"/ksmbd_test_*.c; do
    [ -f "$src_file" ] || continue

    basename=$(basename "$src_file")
    obj_name="${basename%.c}.o"

    if ! echo "$test_makefile_content" | grep -qF "$obj_name"; then
        errors=$((errors + 1))
        missing_tests="$missing_tests  $basename -> $obj_name\n"
    fi
done

# ---- Check test/fuzz/*_fuzz.c files ----

if [ ! -f "$FUZZ_MAKEFILE" ]; then
    echo "ERROR: $FUZZ_MAKEFILE not found"
    exit 1
fi

fuzz_makefile_content=$(cat "$FUZZ_MAKEFILE")

for src_file in "$FUZZ_DIR"/*_fuzz.c; do
    [ -f "$src_file" ] || continue

    basename=$(basename "$src_file")
    obj_name="${basename%.c}.o"

    if ! echo "$fuzz_makefile_content" | grep -qF "$obj_name"; then
        errors=$((errors + 1))
        missing_fuzz="$missing_fuzz  $basename -> $obj_name\n"
    fi
done

# ---- Report results ----

if [ $errors -gt 0 ]; then
    echo "FAIL: $errors test/fuzz source file(s) not registered in Makefiles"
    echo ""

    if [ -n "$missing_tests" ]; then
        echo "Unregistered test files (missing from test/Makefile):"
        printf "$missing_tests"
        echo ""
    fi

    if [ -n "$missing_fuzz" ]; then
        echo "Unregistered fuzz files (missing from test/fuzz/Makefile):"
        printf "$missing_fuzz"
        echo ""
    fi

    echo "To fix: add the corresponding .o entries to the Makefile(s)."
    exit 1
else
    echo "OK: All test and fuzz source files are registered in Makefiles"
    exit 0
fi
