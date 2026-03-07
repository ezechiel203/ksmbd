#!/bin/bash
# lib/smb_helpers.sh -- SMB client operation wrappers
#
# Provides smbclient wrappers with retry logic and structured output,
# smbtorture wrappers with result parsing, and data generation utilities.
#
# All functions use the global SMB_* variables set by the framework.

# ---------------------------------------------------------------------------
# Configuration (inherited from framework or environment)
# ---------------------------------------------------------------------------
: "${SMB_HOST:=127.0.0.1}"
: "${SMB_PORT:=13445}"
: "${SMB_SHARE:=test}"
: "${SMB_USER:=testuser}"
: "${SMB_PASS:=testpass}"
: "${SMBCLIENT_BIN:=smbclient}"
: "${SMBTORTURE_BIN:=smbtorture}"

SMB_UNC="//${SMB_HOST}/${SMB_SHARE}"
SMB_CREDS="${SMB_USER}%${SMB_PASS}"
SMB_IPC="//${SMB_HOST}/IPC\$"

# ---------------------------------------------------------------------------
# Core smbclient Wrapper
# ---------------------------------------------------------------------------

# smb_cmd SHARE [OPTIONS...] -- Run smbclient with flexible options
#
# Options:
#   --user USER%PASS      Override credentials
#   --guest               Connect as guest (no auth)
#   --anon                Same as --guest
#   --proto PROTO         Force specific protocol (both min and max)
#   --min-proto PROTO     Set minimum protocol version
#   --max-proto PROTO     Set maximum protocol version
#   --signing VALUE       Set client signing (required/desired/off)
#   --encrypt VALUE       Set client encryption (required/desired/off)
#   --option KEY=VAL      Pass raw smbclient --option
#   -c "COMMAND"          smbclient command string
#   (bare string)         Treated as smbclient command string
#
# Protocol names: SMB2_02, SMB2_10, SMB3_00, SMB3_02, SMB3_11, NT1
smb_cmd() {
    local share="${1:-$SMB_UNC}"
    shift
    local creds="$SMB_CREDS"
    local extra_opts=()
    local cmd=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --user)      creds="$2"; shift 2 ;;
            --guest|--anon)
                         creds=""; extra_opts+=("-N"); shift ;;
            --option)    extra_opts+=("--option=$2"); shift 2 ;;
            --proto)     extra_opts+=("--option=client min protocol=$2" \
                                      "--option=client max protocol=$2"); shift 2 ;;
            --max-proto) extra_opts+=("--option=client max protocol=$2"); shift 2 ;;
            --min-proto) extra_opts+=("--option=client min protocol=$2"); shift 2 ;;
            --signing)   extra_opts+=("--option=client signing=$2"); shift 2 ;;
            --encrypt)   extra_opts+=("--option=client smb encrypt=$2"); shift 2 ;;
            --port)      extra_opts+=("-p" "$2"); shift 2 ;;
            -c)          cmd="$2"; shift 2 ;;
            *)           cmd="$1"; shift ;;
        esac
    done

    if [[ -n "$creds" ]]; then
        "$SMBCLIENT_BIN" "$share" -p "$SMB_PORT" -U "$creds" \
            "${extra_opts[@]}" -c "$cmd" 2>&1
    else
        "$SMBCLIENT_BIN" "$share" -p "$SMB_PORT" \
            "${extra_opts[@]}" -c "$cmd" 2>&1
    fi
}

# smb_cmd_rc -- Same as smb_cmd but captures exit code separately
# Usage: output=$(smb_cmd_rc "//${host}/${share}" -c "ls"); rc=$SMB_LAST_RC
SMB_LAST_RC=0
smb_cmd_rc() {
    local output
    output=$(smb_cmd "$@")
    SMB_LAST_RC=$?
    echo "$output"
}

# ---------------------------------------------------------------------------
# Directory Operations
# ---------------------------------------------------------------------------

# smb_ls [PATH] [SHARE] -- List directory, return file listing
smb_ls() {
    local path="${1:-.}"
    local share="${2:-$SMB_UNC}"
    smb_cmd "$share" -c "ls $path"
}

# smb_mkdir DIRNAME -- Create directory on share
smb_mkdir() {
    local dirname="$1"
    smb_cmd "$SMB_UNC" -c "mkdir \"$dirname\""
}

# smb_rmdir DIRNAME -- Remove directory on share
smb_rmdir() {
    local dirname="$1"
    smb_cmd "$SMB_UNC" -c "rmdir \"$dirname\""
}

# smb_deltree PATH -- Recursive delete
smb_deltree() {
    local path="$1"
    smb_cmd "$SMB_UNC" -c "deltree \"$path\""
}

# ---------------------------------------------------------------------------
# File Operations
# ---------------------------------------------------------------------------

# smb_put LOCAL REMOTE -- Upload file to share
smb_put() {
    local local_path="$1" remote_path="$2"
    smb_cmd "$SMB_UNC" -c "put \"$local_path\" \"$remote_path\""
}

# smb_get REMOTE LOCAL -- Download file from share
smb_get() {
    local remote_path="$1" local_path="$2"
    smb_cmd "$SMB_UNC" -c "get \"$remote_path\" \"$local_path\""
}

# smb_rm PATH -- Delete file on share
smb_rm() {
    local path="$1"
    smb_cmd "$SMB_UNC" -c "del \"$path\""
}

# smb_rename OLD NEW -- Rename file/directory on share
smb_rename() {
    local old="$1" new="$2"
    smb_cmd "$SMB_UNC" -c "rename \"$old\" \"$new\""
}

# smb_stat PATH -- Get file attributes (allinfo)
smb_stat() {
    local path="$1"
    smb_cmd "$SMB_UNC" -c "allinfo \"$path\""
}

# smb_volume -- Get volume information
smb_volume() {
    smb_cmd "$SMB_UNC" -c "volume"
}

# ---------------------------------------------------------------------------
# Convenience: Write/Read Content
# ---------------------------------------------------------------------------

# smb_write_file REMOTE_NAME CONTENT -- Write string content to a file on share
smb_write_file() {
    local remote_name="$1"
    local content="${2:-test content}"
    local tmpf
    tmpf=$(mktemp)
    printf '%s' "$content" > "$tmpf"
    local out
    out=$(smb_cmd "$SMB_UNC" -c "put \"$tmpf\" \"$remote_name\"")
    rm -f "$tmpf"
    echo "$out"
}

# smb_write_binary REMOTE_NAME SIZE_BYTES -- Write random binary data
smb_write_binary() {
    local remote_name="$1" size="${2:-1024}"
    local tmpf
    tmpf=$(mktemp)
    dd if=/dev/urandom of="$tmpf" bs=1 count="$size" 2>/dev/null
    local out
    out=$(smb_cmd "$SMB_UNC" -c "put \"$tmpf\" \"$remote_name\"")
    rm -f "$tmpf"
    echo "$out"
}

# smb_read_file REMOTE_NAME -- Read file content from share, print to stdout
smb_read_file() {
    local remote_name="$1"
    local tmpf
    tmpf=$(mktemp)
    smb_cmd "$SMB_UNC" -c "get \"$remote_name\" \"$tmpf\"" >/dev/null 2>&1
    cat "$tmpf"
    rm -f "$tmpf"
}

# smb_allinfo PATH -- Get allinfo (same as smb_stat, kept for compatibility)
smb_allinfo() {
    smb_stat "$1"
}

# ---------------------------------------------------------------------------
# Protocol-Specific Operations
# ---------------------------------------------------------------------------

# smb_with_proto PROTO CMD -- Run smbclient command forcing specific protocol
smb_with_proto() {
    local proto="$1"; shift
    smb_cmd "$SMB_UNC" --proto "$proto" "$@"
}

# smb_connect_test [SHARE] [EXTRA_OPTS...] -- Test basic connectivity (ls)
# Returns 0 if connection+ls succeeds, 1 otherwise
smb_connect_test() {
    local share="${1:-$SMB_UNC}"
    shift || true
    local output
    output=$(smb_cmd "$share" "$@" -c "ls" 2>&1)
    local rc=$?
    if [[ $rc -eq 0 ]] && echo "$output" | grep -q "blocks"; then
        return 0
    fi
    return 1
}

# smb_connect_test_retry [MAX_RETRIES] [SHARE] -- Test connectivity with retries
smb_connect_test_retry() {
    local max_retries="${1:-3}"
    local share="${2:-$SMB_UNC}"
    local i
    for i in $(seq 1 "$max_retries"); do
        if smb_connect_test "$share"; then
            return 0
        fi
        [[ $i -lt $max_retries ]] && sleep 2
    done
    return 1
}

# ---------------------------------------------------------------------------
# Mode / Attribute Operations
# ---------------------------------------------------------------------------

# smb_setmode PATH MODE -- Set DOS attributes
smb_setmode() {
    local path="$1" mode="$2"
    smb_cmd "$SMB_UNC" -c "setmode \"$path\" $mode"
}

# smb_chmod PATH MODE -- Change POSIX permissions
smb_chmod() {
    local path="$1" mode="$2"
    smb_cmd "$SMB_UNC" -c "chmod $mode \"$path\""
}

# ---------------------------------------------------------------------------
# smbtorture Wrappers
# ---------------------------------------------------------------------------

# torture_run TEST_NAME [EXTRA_ARGS...] -- Run smbtorture test, capture output
torture_run() {
    local test_name="$1"; shift
    "$SMBTORTURE_BIN" "//${SMB_HOST}/${SMB_SHARE}" \
        -p "$SMB_PORT" \
        -U "${SMB_CREDS}" \
        "$test_name" \
        "$@" 2>&1
}

# torture_run_raw ARGS... -- Run smbtorture with raw arguments
torture_run_raw() {
    "$SMBTORTURE_BIN" "//${SMB_HOST}/${SMB_SHARE}" \
        -p "$SMB_PORT" \
        -U "${SMB_CREDS}" \
        "$@" 2>&1
}

# torture_run_expect_fail TEST_NAME [ARGS...] -- Run test, expect failure
# Returns 0 if smbtorture fails (expected), 1 if it succeeds (unexpected)
torture_run_expect_fail() {
    local test_name="$1"; shift
    local output
    output=$(torture_run "$test_name" "$@")
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "Expected failure but got success: $test_name"
        return 1
    fi
    return 0
}

# torture_list SUITE -- List available tests in a smbtorture suite
torture_list() {
    local suite="$1"
    "$SMBTORTURE_BIN" "//${SMB_HOST}/${SMB_SHARE}" \
        --list "$suite" 2>/dev/null | grep -v '^smbtorture\|^Can.t load'
}

# torture_check TEST_NAME [ARGS...] -- Run smbtorture and check for success
# Returns 0 if test passed, 1 if failed. Output on failure only.
torture_check() {
    local test_name="$1"; shift
    local output
    output=$(torture_run "$test_name" "$@")
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        return 0
    fi
    # Check for explicit success line even with non-zero exit
    if echo "$output" | grep -q "^success:"; then
        return 0
    fi
    echo "$output"
    return 1
}

# torture_count_results OUTPUT -- Parse smbtorture output, return "pass:N fail:N skip:N"
torture_count_results() {
    local output="$1"
    local pass fail skip
    pass=$(echo "$output" | grep -c '^\s*success:' 2>/dev/null || echo 0)
    fail=$(echo "$output" | grep -c '^\s*failure:' 2>/dev/null || echo 0)
    skip=$(echo "$output" | grep -c '^\s*skip:' 2>/dev/null || echo 0)
    echo "pass:$pass fail:$fail skip:$skip"
}

# ---------------------------------------------------------------------------
# Data Generation
# ---------------------------------------------------------------------------

# generate_pattern_file PATH SIZE_BYTES -- Generate file with known pattern
generate_pattern_file() {
    local path="$1" size_bytes="$2"
    dd if=/dev/urandom of="$path" bs=1024 count=$((size_bytes / 1024 + 1)) 2>/dev/null
    truncate -s "$size_bytes" "$path" 2>/dev/null
}

# generate_zero_file PATH SIZE_BYTES -- Generate file filled with zeros
generate_zero_file() {
    local path="$1" size_bytes="$2"
    dd if=/dev/zero of="$path" bs=1024 count=$((size_bytes / 1024 + 1)) 2>/dev/null
    truncate -s "$size_bytes" "$path" 2>/dev/null
}

# generate_compressible_file PATH SIZE_BYTES -- Generate highly compressible data
generate_compressible_file() {
    local path="$1" size_bytes="$2"
    # Repeat a short pattern to make it compressible
    python3 -c "
import sys
pattern = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' * 100
with open('$path', 'wb') as f:
    written = 0
    while written < $size_bytes:
        chunk = pattern[:min(len(pattern), $size_bytes - written)]
        f.write(chunk)
        written += len(chunk)
" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Result Parsing Helpers
# ---------------------------------------------------------------------------

# extract_smb_status OUTPUT -- Extract NT_STATUS_* from smbclient output
extract_smb_status() {
    local output="$1"
    echo "$output" | grep -oP 'NT_STATUS_\w+' | head -1
}

# output_has_status OUTPUT STATUS -- Check if output contains specific status
output_has_status() {
    local output="$1" status="$2"
    echo "$output" | grep -qi "$status"
}

# output_has_error OUTPUT -- Check if output contains any NT_STATUS error
output_has_error() {
    local output="$1"
    echo "$output" | grep -qP 'NT_STATUS_(?!OK)\w+'
}

# ---------------------------------------------------------------------------
# Test Directory Management
# ---------------------------------------------------------------------------

# Share root on the VM (where the test share maps to)
: "${SHARE_ROOT:=/srv/smb/test}"

# create_test_dir [PREFIX] -- Create unique test directory on VM share
create_test_dir() {
    local prefix="${1:-torture}"
    local dir
    dir=$(vm_exec "mktemp -d ${SHARE_ROOT}/${prefix}_XXXXXX" 2>/dev/null)
    echo "$dir"
}

# cleanup_test_dir DIR -- Remove test directory on VM
cleanup_test_dir() {
    local dir="$1"
    [[ -n "$dir" ]] && vm_exec "rm -rf '$dir'" 2>/dev/null
}

# create_local_tmpdir -- Create local temporary directory
create_local_tmpdir() {
    mktemp -d "/tmp/ksmbd-torture-XXXXXX"
}
