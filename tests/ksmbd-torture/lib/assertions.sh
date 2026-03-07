#!/bin/bash
# lib/assertions.sh -- Assertion library for ksmbd-torture
#
# Every assertion:
#   - Returns 0 on success, 1 on failure
#   - Sets ASSERT_MSG with a diagnostic message on failure
#   - Prints the diagnostic to stderr on failure
#   - Can be used directly in test functions: assert_eq "a" "b" "msg" || return 1
#
# Convention: test functions should chain assertions with || return 1
# so the first failure aborts the test.

ASSERT_MSG=""

# ---------------------------------------------------------------------------
# Core Value Assertions
# ---------------------------------------------------------------------------

# assert_status EXPECTED ACTUAL MSG -- Exit code equals expected
assert_status() {
    local expected="$1" actual="$2" msg="${3:-exit code mismatch}"
    if [[ "$actual" -ne "$expected" ]]; then
        ASSERT_MSG="$msg: expected exit code $expected, got $actual"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_eq EXPECTED ACTUAL MSG -- String equality
assert_eq() {
    local expected="$1" actual="$2" msg="${3:-value mismatch}"
    if [[ "$expected" != "$actual" ]]; then
        ASSERT_MSG="$msg: expected '$expected', got '$actual'"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_ne UNEXPECTED ACTUAL MSG -- String inequality
assert_ne() {
    local unexpected="$1" actual="$2" msg="${3:-values should differ}"
    if [[ "$unexpected" == "$actual" ]]; then
        ASSERT_MSG="$msg: got unexpected value '$actual'"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_gt ACTUAL THRESHOLD MSG -- Numeric greater than
assert_gt() {
    local actual="$1" threshold="$2" msg="${3:-value not greater than threshold}"
    if [[ "$actual" -le "$threshold" ]]; then
        ASSERT_MSG="$msg: $actual is not > $threshold"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_ge ACTUAL THRESHOLD MSG -- Numeric greater than or equal
assert_ge() {
    local actual="$1" threshold="$2" msg="${3:-value not >= threshold}"
    if [[ "$actual" -lt "$threshold" ]]; then
        ASSERT_MSG="$msg: $actual is not >= $threshold"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_lt ACTUAL THRESHOLD MSG -- Numeric less than
assert_lt() {
    local actual="$1" threshold="$2" msg="${3:-value not less than threshold}"
    if [[ "$actual" -ge "$threshold" ]]; then
        ASSERT_MSG="$msg: $actual is not < $threshold"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_le ACTUAL THRESHOLD MSG -- Numeric less than or equal
assert_le() {
    local actual="$1" threshold="$2" msg="${3:-value not <= threshold}"
    if [[ "$actual" -gt "$threshold" ]]; then
        ASSERT_MSG="$msg: $actual is not <= $threshold"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_not_empty VALUE MSG -- Value is non-empty
assert_not_empty() {
    local value="$1" msg="${2:-value is empty}"
    if [[ -z "$value" ]]; then
        ASSERT_MSG="$msg"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# String Assertions
# ---------------------------------------------------------------------------

# assert_contains HAYSTACK NEEDLE MSG -- Substring match
assert_contains() {
    local haystack="$1" needle="$2" msg="${3:-substring not found}"
    if [[ "$haystack" != *"$needle"* ]]; then
        ASSERT_MSG="$msg: '$needle' not found in output"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_not_contains HAYSTACK NEEDLE MSG -- Substring absence
assert_not_contains() {
    local haystack="$1" needle="$2" msg="${3:-unexpected substring found}"
    if [[ "$haystack" == *"$needle"* ]]; then
        ASSERT_MSG="$msg: '$needle' unexpectedly found in output"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_matches STRING REGEX MSG -- Regex match
assert_matches() {
    local string="$1" regex="$2" msg="${3:-regex mismatch}"
    if [[ ! "$string" =~ $regex ]]; then
        ASSERT_MSG="$msg: '$string' does not match /$regex/"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_not_matches STRING REGEX MSG -- Regex non-match
assert_not_matches() {
    local string="$1" regex="$2" msg="${3:-unexpected regex match}"
    if [[ "$string" =~ $regex ]]; then
        ASSERT_MSG="$msg: '$string' unexpectedly matches /$regex/"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# File Assertions (local filesystem)
# ---------------------------------------------------------------------------

# assert_file_exists PATH MSG -- File exists locally
assert_file_exists() {
    local path="$1" msg="${2:-file does not exist}"
    if [[ ! -e "$path" ]]; then
        ASSERT_MSG="$msg: $path"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_file_absent PATH MSG -- File does not exist locally
assert_file_absent() {
    local path="$1" msg="${2:-file should not exist}"
    if [[ -e "$path" ]]; then
        ASSERT_MSG="$msg: $path exists"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_file_size PATH OP SIZE MSG -- File size comparison
# OP is a test operator: -eq, -gt, -lt, -ge, -le, -ne
assert_file_size() {
    local path="$1" op="$2" expected="$3" msg="${4:-file size check failed}"
    local actual
    actual=$(stat -c%s "$path" 2>/dev/null)
    if [[ -z "$actual" ]]; then
        ASSERT_MSG="$msg: cannot stat $path"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    if ! eval "[[ $actual $op $expected ]]"; then
        ASSERT_MSG="$msg: file size $actual $op $expected failed"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_file_content PATH EXPECTED MSG -- File content matches string
assert_file_content() {
    local path="$1" expected="$2" msg="${3:-file content mismatch}"
    local actual
    actual=$(cat "$path" 2>/dev/null)
    if [[ "$actual" != "$expected" ]]; then
        ASSERT_MSG="$msg: content differs"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Remote File Assertions (via SSH to VM)
# ---------------------------------------------------------------------------

# assert_remote_file_exists PATH MSG -- File exists on VM
assert_remote_file_exists() {
    local path="$1" msg="${2:-remote file does not exist}"
    if ! vm_exec "test -e '$path'" 2>/dev/null; then
        ASSERT_MSG="$msg: $path"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_remote_file_absent PATH MSG -- File does not exist on VM
assert_remote_file_absent() {
    local path="$1" msg="${2:-remote file should not exist}"
    if vm_exec "test -e '$path'" 2>/dev/null; then
        ASSERT_MSG="$msg: $path exists"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_remote_file_size PATH OP SIZE MSG -- Remote file size comparison
assert_remote_file_size() {
    local path="$1" op="$2" expected="$3" msg="${4:-remote file size check failed}"
    local actual
    actual=$(vm_exec "stat -c%s '$path'" 2>/dev/null)
    if [[ -z "$actual" ]]; then
        ASSERT_MSG="$msg: cannot stat remote $path"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    if ! eval "[[ $actual $op $expected ]]"; then
        ASSERT_MSG="$msg: remote file size $actual $op $expected failed"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# SMB Status Assertions
# ---------------------------------------------------------------------------

# assert_smb_status OUTPUT STATUS MSG -- SMB status code in smbclient output
assert_smb_status() {
    local output="$1" expected_status="$2" msg="${3:-SMB status mismatch}"
    if [[ "$output" != *"$expected_status"* ]]; then
        local actual_status
        actual_status=$(echo "$output" | grep -oP 'NT_STATUS_\w+' | head -1)
        ASSERT_MSG="$msg: expected '$expected_status', got '${actual_status:-none}'"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_smb_success OUTPUT MSG -- No NT_STATUS error in output (except NT_STATUS_OK)
assert_smb_success() {
    local output="$1" msg="${2:-SMB operation failed}"
    if echo "$output" | grep -qP 'NT_STATUS_(?!OK)\w+'; then
        local status
        status=$(echo "$output" | grep -oP 'NT_STATUS_(?!OK)\w+' | head -1)
        ASSERT_MSG="$msg: got $status"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_smb_error OUTPUT EXPECTED MSG -- Specific SMB error present
assert_smb_error() {
    local output="$1" expected="$2" msg="${3:-expected SMB error not found}"
    if [[ "$output" != *"$expected"* ]]; then
        ASSERT_MSG="$msg: expected $expected in output"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Server Health Assertions
# ---------------------------------------------------------------------------

# assert_dmesg_clean MARKER MSG -- No BUG/WARN/OOPS since marker
assert_dmesg_clean() {
    local marker="$1" msg="${2:-dmesg errors detected}"
    local errors
    errors=$(vm_exec "dmesg" 2>/dev/null | sed -n "/${marker}/,\$p" | \
        grep -iE 'BUG|WARN|OOPS|RCU|panic|use.after.free' | \
        grep -v "$marker" | head -5)
    if [[ -n "$errors" ]]; then
        ASSERT_MSG="$msg: $errors"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_slab_stable BASELINE THRESHOLD MSG -- Slab growth within threshold
assert_slab_stable() {
    local baseline="$1" threshold="$2" msg="${3:-slab growth exceeds threshold}"
    local current
    current=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd" | \
        awk '{sum+=$2} END {print sum+0}')
    local delta=$(( current - baseline ))
    if [[ $delta -gt $threshold ]]; then
        ASSERT_MSG="$msg: slab grew by $delta objects (threshold=$threshold)"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# assert_no_open_fds BASELINE MSG -- No FD leak since baseline
assert_no_open_fds() {
    local baseline="$1" msg="${2:-FD leak detected}"
    local current
    current=$(vm_exec "ls /proc/\$(pgrep -x ksmbd | head -1)/fd 2>/dev/null | wc -l")
    current="${current:-0}"
    local delta=$(( current - baseline ))
    if [[ $delta -gt 0 ]]; then
        ASSERT_MSG="$msg: FD count grew by $delta (baseline=$baseline, current=$current)"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# smbtorture Result Assertions
# ---------------------------------------------------------------------------

# assert_torture_pass OUTPUT MSG -- smbtorture output indicates success
assert_torture_pass() {
    local output="$1" msg="${2:-smbtorture test failed}"
    if ! echo "$output" | grep -qE '(^success|passed)'; then
        local failures
        failures=$(echo "$output" | grep -iE '(^failure|FAILED|^error)' | head -5)
        ASSERT_MSG="$msg: $failures"
        echo "$ASSERT_MSG" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Skip Helper
# ---------------------------------------------------------------------------

# skip_test REASON -- Exit with code 77 (skip convention)
skip_test() {
    local reason="${1:-no reason given}"
    echo "SKIP: $reason" >&2
    exit 77
}
