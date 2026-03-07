#!/bin/bash
# lib/helpers.sh -- Shared helper functions for ksmbd-torture integration tests
#
# Provides smbclient-based SMB operations, assertion helpers, and utility
# functions used by all test suites in tests/ksmbd-torture/suites/.
#
# This file is sourced by torture_runner.sh and by individual suite files.
# It expects the following environment variables to be set:
#   SMB_HOST, SMB_PORT, SMB_SHARE, SMB_USER, SMB_PASS

# ============================================================================
# Configuration defaults (can be overridden by caller)
# ============================================================================
: "${SMB_HOST:=127.0.0.1}"
: "${SMB_PORT:=445}"
: "${SMB_SHARE:=test}"
: "${SMB_USER:=testuser}"
: "${SMB_PASS:=1234}"
: "${SMBCLIENT:=smbclient}"
: "${SMBCACLS:=smbcacls}"
: "${SMB_PROTO:=SMB3_11}"

SMB_UNC="//${SMB_HOST}/${SMB_SHARE}"
SMB_CREDS="${SMB_USER}%${SMB_PASS}"

# ============================================================================
# Internal state
# ============================================================================
_HELPERS_TMPDIR=""
_TEST_COUNT=0
_TEST_PASS=0
_TEST_FAIL=0
_TEST_SKIP=0
_TEST_RESULTS=()
_CURRENT_TEST=""
_CURRENT_DESC=""

# ============================================================================
# Cleanup management
# ============================================================================
helpers_init() {
    _HELPERS_TMPDIR=$(mktemp -d "/tmp/ksmbd-torture.XXXXXX")
    trap helpers_cleanup EXIT
}

helpers_cleanup() {
    if [[ -n "$_HELPERS_TMPDIR" && -d "$_HELPERS_TMPDIR" ]]; then
        rm -rf "$_HELPERS_TMPDIR"
    fi
}

# ============================================================================
# SMB Client Wrapper
# ============================================================================

# _smbclient_cmd CMD [EXTRA_ARGS...]
# Run an smbclient command against the configured share.
# Returns smbclient output on stdout; exit code reflects smbclient status.
_smbclient_cmd() {
    local cmd="$1"
    shift
    "$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" -U "$SMB_CREDS" \
        --option="client min protocol=$SMB_PROTO" \
        --option="client max protocol=$SMB_PROTO" \
        "$@" -c "$cmd" 2>&1
}

# _smbclient_cmd_raw CMD [EXTRA_ARGS...]
# Same as above but does not force protocol version (uses smbclient defaults).
_smbclient_cmd_raw() {
    local cmd="$1"
    shift
    "$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" -U "$SMB_CREDS" \
        "$@" -c "$cmd" 2>&1
}

# _smbclient_guest CMD [EXTRA_ARGS...]
# Run smbclient as guest (no authentication).
_smbclient_guest() {
    local cmd="$1"
    shift
    "$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" -N \
        --option="client min protocol=$SMB_PROTO" \
        --option="client max protocol=$SMB_PROTO" \
        "$@" -c "$cmd" 2>&1
}

# ============================================================================
# SMB Operations
# ============================================================================

# smb_connect
# Test basic connectivity to the configured share. Returns 0 on success.
smb_connect() {
    local output
    output=$(_smbclient_cmd "ls" 2>&1)
    local rc=$?
    if [[ $rc -eq 0 ]] && echo "$output" | grep -q "blocks"; then
        return 0
    fi
    echo "$output" >&2
    return 1
}

# smb_disconnect
# No-op for smbclient (connection-per-command model). Provided for API symmetry.
smb_disconnect() {
    return 0
}

# smb_connect_proto PROTOCOL
# Test connectivity with a specific protocol version.
# PROTOCOL: NT1, SMB2_02, SMB2_10, SMB3_00, SMB3_02, SMB3_11
smb_connect_proto() {
    local proto="$1"
    local output
    output=$("$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" -U "$SMB_CREDS" \
        --option="client min protocol=$proto" \
        --option="client max protocol=$proto" \
        -c "ls" 2>&1)
    local rc=$?
    if [[ $rc -eq 0 ]] && echo "$output" | grep -q "blocks"; then
        return 0
    fi
    echo "$output" >&2
    return 1
}

# smb_put_file LOCAL_PATH REMOTE_NAME
# Upload a local file to the share.
smb_put_file() {
    local local_path="$1"
    local remote_name="$2"
    _smbclient_cmd "put \"$local_path\" \"$remote_name\""
}

# smb_get_file REMOTE_NAME LOCAL_PATH
# Download a remote file from the share.
smb_get_file() {
    local remote_name="$1"
    local local_path="$2"
    _smbclient_cmd "get \"$remote_name\" \"$local_path\""
}

# smb_delete REMOTE_NAME
# Delete a file on the share.
smb_delete() {
    local remote_name="$1"
    _smbclient_cmd "del \"$remote_name\""
}

# smb_mkdir REMOTE_DIR
# Create a directory on the share.
smb_mkdir() {
    local remote_dir="$1"
    _smbclient_cmd "mkdir \"$remote_dir\""
}

# smb_rmdir REMOTE_DIR
# Remove a directory on the share.
smb_rmdir() {
    local remote_dir="$1"
    _smbclient_cmd "rmdir \"$remote_dir\""
}

# smb_ls [PATTERN]
# List files on the share. Optional pattern (e.g., "subdir/*").
smb_ls() {
    local pattern="${1:-}"
    if [[ -n "$pattern" ]]; then
        _smbclient_cmd "ls \"$pattern\""
    else
        _smbclient_cmd "ls"
    fi
}

# smb_stat REMOTE_NAME
# Get file attributes using allinfo.
smb_stat() {
    local remote_name="$1"
    _smbclient_cmd "allinfo \"$remote_name\""
}

# smb_rename OLD_NAME NEW_NAME
# Rename a file on the share.
smb_rename() {
    local old_name="$1"
    local new_name="$2"
    _smbclient_cmd "rename \"$old_name\" \"$new_name\""
}

# smb_write_text REMOTE_NAME CONTENT
# Write text content to a remote file via a temporary local file.
smb_write_text() {
    local remote_name="$1"
    local content="$2"
    local tmpfile="${_HELPERS_TMPDIR}/smb_write_$$_${RANDOM}"
    printf '%s' "$content" > "$tmpfile"
    smb_put_file "$tmpfile" "$remote_name"
    local rc=$?
    rm -f "$tmpfile"
    return $rc
}

# smb_read_text REMOTE_NAME
# Read text content from a remote file. Outputs content on stdout.
smb_read_text() {
    local remote_name="$1"
    local tmpfile="${_HELPERS_TMPDIR}/smb_read_$$_${RANDOM}"
    smb_get_file "$remote_name" "$tmpfile" >/dev/null 2>&1
    local rc=$?
    if [[ $rc -eq 0 && -f "$tmpfile" ]]; then
        cat "$tmpfile"
    fi
    rm -f "$tmpfile"
    return $rc
}

# smb_file_exists REMOTE_NAME
# Check if a file exists on the share. Returns 0 if found, 1 otherwise.
smb_file_exists() {
    local remote_name="$1"
    local output
    output=$(_smbclient_cmd "ls \"$remote_name\"" 2>&1)
    if echo "$output" | grep -q "NT_STATUS_NO_SUCH_FILE\|NT_STATUS_OBJECT_NAME_NOT_FOUND"; then
        return 1
    fi
    if echo "$output" | grep -qi "$remote_name"; then
        return 0
    fi
    # Try allinfo as fallback
    output=$(_smbclient_cmd "allinfo \"$remote_name\"" 2>&1)
    if echo "$output" | grep -q "NT_STATUS"; then
        return 1
    fi
    return 0
}

# smb_recursive_delete DIR
# Recursively delete contents of a directory, then the directory itself.
smb_recursive_delete() {
    local dir="$1"
    # Delete files first, then subdirectories
    _smbclient_cmd "cd \"$dir\"; prompt; mget *; lcd /dev/null; del *; cd ..; rmdir \"$dir\"" 2>/dev/null
    # Simpler approach: use recurse + deltree if available, or manual
    _smbclient_cmd "deltree \"$dir\"" 2>/dev/null
    return 0
}

# smb_chmod REMOTE_NAME MODE_STRING
# Set file mode (smbclient setmode). MODE_STRING: e.g., "+r", "-a", "+h".
smb_chmod() {
    local remote_name="$1"
    local mode="$2"
    _smbclient_cmd "setmode \"$remote_name\" $mode"
}

# smb_get_acl REMOTE_NAME
# Get ACL information using smbcacls (if available).
smb_get_acl() {
    local remote_name="$1"
    if ! command -v "$SMBCACLS" >/dev/null 2>&1; then
        echo "smbcacls not available"
        return 1
    fi
    "$SMBCACLS" "$SMB_UNC" "$remote_name" -p "$SMB_PORT" -U "$SMB_CREDS" 2>&1
}

# smb_mput_pattern DIR COUNT PREFIX
# Create COUNT files in DIR with PREFIX naming. Returns 0 on success.
smb_mput_pattern() {
    local dir="$1"
    local count="$2"
    local prefix="${3:-testfile}"
    local i cmds=""
    for ((i = 0; i < count; i++)); do
        local tmpfile="${_HELPERS_TMPDIR}/mput_${i}"
        echo "content_${i}_${RANDOM}" > "$tmpfile"
        cmds="${cmds}put \"$tmpfile\" \"${dir}/${prefix}_$(printf '%04d' "$i")\"; "
    done
    _smbclient_cmd "$cmds"
    local rc=$?
    rm -f "${_HELPERS_TMPDIR}"/mput_*
    return $rc
}

# ============================================================================
# Assertion Helpers
# ============================================================================

# assert_status EXPECTED_RC ACTUAL_RC MESSAGE
# Check that the actual return code matches the expected one.
assert_status() {
    local expected="$1"
    local actual="$2"
    local message="$3"
    if [[ "$actual" -eq "$expected" ]]; then
        return 0
    else
        echo "ASSERT FAILED: $message (expected rc=$expected, got rc=$actual)" >&2
        return 1
    fi
}

# assert_success RC MESSAGE
# Shorthand: assert that RC is 0.
assert_success() {
    local rc="$1"
    local message="$2"
    assert_status 0 "$rc" "$message"
}

# assert_failure RC MESSAGE
# Shorthand: assert that RC is non-zero.
assert_failure() {
    local rc="$1"
    local message="$2"
    if [[ "$rc" -ne 0 ]]; then
        return 0
    else
        echo "ASSERT FAILED: $message (expected failure, got rc=0)" >&2
        return 1
    fi
}

# assert_contains OUTPUT SUBSTRING MESSAGE
# Check that OUTPUT contains SUBSTRING.
assert_contains() {
    local output="$1"
    local substring="$2"
    local message="$3"
    if echo "$output" | grep -qF "$substring"; then
        return 0
    else
        echo "ASSERT FAILED: $message (output does not contain '$substring')" >&2
        echo "  Output was: $(echo "$output" | head -5)" >&2
        return 1
    fi
}

# assert_not_contains OUTPUT SUBSTRING MESSAGE
# Check that OUTPUT does NOT contain SUBSTRING.
assert_not_contains() {
    local output="$1"
    local substring="$2"
    local message="$3"
    if echo "$output" | grep -qF "$substring"; then
        echo "ASSERT FAILED: $message (output should not contain '$substring')" >&2
        return 1
    fi
    return 0
}

# assert_matches OUTPUT REGEX MESSAGE
# Check that OUTPUT matches REGEX (extended grep).
assert_matches() {
    local output="$1"
    local regex="$2"
    local message="$3"
    if echo "$output" | grep -qE "$regex"; then
        return 0
    else
        echo "ASSERT FAILED: $message (output does not match /$regex/)" >&2
        return 1
    fi
}

# assert_file_exists REMOTE_NAME MESSAGE
# Check that a file exists on the share.
assert_file_exists() {
    local remote_name="$1"
    local message="$2"
    if smb_file_exists "$remote_name"; then
        return 0
    else
        echo "ASSERT FAILED: $message (file '$remote_name' does not exist)" >&2
        return 1
    fi
}

# assert_file_not_exists REMOTE_NAME MESSAGE
# Check that a file does NOT exist on the share.
assert_file_not_exists() {
    local remote_name="$1"
    local message="$2"
    if smb_file_exists "$remote_name"; then
        echo "ASSERT FAILED: $message (file '$remote_name' exists but should not)" >&2
        return 1
    fi
    return 0
}

# assert_file_contents REMOTE_NAME EXPECTED_CONTENT MESSAGE
# Download a file and check that its content matches exactly.
assert_file_contents() {
    local remote_name="$1"
    local expected="$2"
    local message="$3"
    local actual
    actual=$(smb_read_text "$remote_name")
    if [[ "$actual" == "$expected" ]]; then
        return 0
    else
        echo "ASSERT FAILED: $message" >&2
        echo "  Expected: $(echo "$expected" | head -3)" >&2
        echo "  Actual:   $(echo "$actual" | head -3)" >&2
        return 1
    fi
}

# assert_file_size REMOTE_NAME EXPECTED_SIZE MESSAGE
# Check that a remote file has the expected size in bytes.
assert_file_size() {
    local remote_name="$1"
    local expected_size="$2"
    local message="$3"
    local info
    info=$(smb_stat "$remote_name")
    local actual_size
    actual_size=$(echo "$info" | grep -i "stream:.*size" | head -1 | grep -oP '\d+' | head -1)
    if [[ -z "$actual_size" ]]; then
        # Try alternate parsing (allinfo format varies)
        actual_size=$(echo "$info" | grep -i "end_of_file:" | grep -oP '\d+' | head -1)
    fi
    if [[ "$actual_size" == "$expected_size" ]]; then
        return 0
    else
        echo "ASSERT FAILED: $message (expected size=$expected_size, got size=$actual_size)" >&2
        return 1
    fi
}

# assert_nt_status OUTPUT STATUS MESSAGE
# Check that smbclient output contains a specific NT_STATUS code.
assert_nt_status() {
    local output="$1"
    local status="$2"
    local message="$3"
    if echo "$output" | grep -q "$status"; then
        return 0
    else
        echo "ASSERT FAILED: $message (expected $status in output)" >&2
        echo "  Output was: $(echo "$output" | head -5)" >&2
        return 1
    fi
}

# ============================================================================
# Utility Functions
# ============================================================================

# random_string [LENGTH]
# Generate a random alphanumeric string. Default length: 16.
random_string() {
    local len="${1:-16}"
    head -c 256 /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$len"
}

# random_file SIZE_BYTES [OUTPUT_PATH]
# Generate a file of SIZE_BYTES with random content.
# If OUTPUT_PATH not given, creates in tmpdir and prints path.
random_file() {
    local size="$1"
    local output="${2:-${_HELPERS_TMPDIR}/random_$$_${RANDOM}}"
    dd if=/dev/urandom of="$output" bs=1024 count=$((size / 1024 + 1)) 2>/dev/null
    truncate -s "$size" "$output"
    echo "$output"
}

# pattern_file SIZE_BYTES [OUTPUT_PATH]
# Generate a file of SIZE_BYTES with a repeating pattern (for checksum verification).
pattern_file() {
    local size="$1"
    local output="${2:-${_HELPERS_TMPDIR}/pattern_$$_${RANDOM}}"
    local chunk=4096
    local remaining=$size
    > "$output"
    while [[ $remaining -gt 0 ]]; do
        local write_size=$((remaining > chunk ? chunk : remaining))
        # Repeating known pattern
        printf '%0*d' "$write_size" 0 | head -c "$write_size" >> "$output"
        remaining=$((remaining - write_size))
    done
    truncate -s "$size" "$output"
    echo "$output"
}

# file_checksum FILE_PATH
# Print the SHA256 checksum of a file.
file_checksum() {
    sha256sum "$1" | awk '{print $1}'
}

# wait_for SECONDS
# Sleep for specified seconds (used for timing-sensitive tests).
wait_for() {
    sleep "$1"
}

# smb_server_cleanup DIR_PREFIX
# Clean up test artifacts from the share. Best-effort, errors ignored.
smb_server_cleanup() {
    local prefix="${1:-torture_test}"
    _smbclient_cmd "deltree \"$prefix\"" 2>/dev/null
    _smbclient_cmd "del \"${prefix}*\"" 2>/dev/null
    return 0
}

# ============================================================================
# Test Harness Helpers (used by torture_runner.sh)
# ============================================================================

# begin_test TEST_NAME DESCRIPTION
# Mark the start of a test.
begin_test() {
    _CURRENT_TEST="$1"
    _CURRENT_DESC="$2"
    ((_TEST_COUNT++))
}

# pass_test [MESSAGE]
# Record a passing test.
pass_test() {
    local msg="${1:-$_CURRENT_DESC}"
    ((_TEST_PASS++))
    _TEST_RESULTS+=("PASS|${_CURRENT_TEST}|${msg}")
}

# fail_test [MESSAGE]
# Record a failing test.
fail_test() {
    local msg="${1:-$_CURRENT_DESC}"
    ((_TEST_FAIL++))
    _TEST_RESULTS+=("FAIL|${_CURRENT_TEST}|${msg}")
}

# skip_test [REASON]
# Record a skipped test.
skip_test() {
    local reason="${1:-no reason given}"
    ((_TEST_SKIP++))
    _TEST_RESULTS+=("SKIP|${_CURRENT_TEST}|${reason}")
}

# get_test_summary
# Print summary counts.
get_test_summary() {
    echo "total=$_TEST_COUNT pass=$_TEST_PASS fail=$_TEST_FAIL skip=$_TEST_SKIP"
}

# get_test_results
# Print all results (one per line): STATUS|NAME|MESSAGE
get_test_results() {
    local r
    for r in "${_TEST_RESULTS[@]}"; do
        echo "$r"
    done
}

# reset_test_state
# Reset counters (useful between suite files).
reset_test_state() {
    _TEST_COUNT=0
    _TEST_PASS=0
    _TEST_FAIL=0
    _TEST_SKIP=0
    _TEST_RESULTS=()
}
