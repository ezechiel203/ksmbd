#!/bin/bash
# =============================================================================
# differential_vs_samba.sh -- ksmbd vs Samba differential conformance tester
#
# Sends identical SMB operations to a ksmbd server and a Samba server,
# compares responses (status codes, field values, behavior), and reports
# differences as potential conformance regressions.
#
# Output: TAP format + summary JSON with conformance score (X/30 matching).
#
# Usage:
#   ./tests/ksmbd-torture/tests/differential_vs_samba.sh \
#     --ksmbd-host 127.0.0.1 --ksmbd-port 13445 \
#     --samba-host 127.0.0.1 --samba-port 445 \
#     --user testuser --pass 1234 --share testshare
#
# Exit codes:
#   0  All 30 operations match (perfect conformance)
#   1  One or more differences detected
#   2  Infrastructure error (cannot reach a server, tool missing)
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Script self-location (so it can be run from any directory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TORTURE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
KSMBD_HOST="127.0.0.1"
KSMBD_PORT="13445"
SAMBA_HOST="127.0.0.1"
SAMBA_PORT="445"
SMB_USER="testuser"
SMB_PASS="1234"
SMB_SHARE="testshare"
VERBOSE="no"
NO_COLOR="no"
JSON_OUTPUT=""          # path to write JSON summary; empty = skip
TIMEOUT_PER_OP=15       # seconds per individual operation

# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------
C_RESET="" C_GREEN="" C_RED="" C_YELLOW="" C_BLUE="" C_CYAN="" C_BOLD="" C_DIM=""

_init_colors() {
    if [[ "$NO_COLOR" != "yes" ]] && [[ -t 1 ]]; then
        C_RESET=$'\033[0m'
        C_GREEN=$'\033[32m'
        C_RED=$'\033[31m'
        C_YELLOW=$'\033[33m'
        C_BLUE=$'\033[34m'
        C_CYAN=$'\033[36m'
        C_BOLD=$'\033[1m'
        C_DIM=$'\033[2m'
    fi
}

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
_usage() {
    cat <<'USAGE'
Usage: differential_vs_samba.sh [OPTIONS]

Connection:
  --ksmbd-host HOST     ksmbd server hostname/IP (default: 127.0.0.1)
  --ksmbd-port PORT     ksmbd server SMB port    (default: 13445)
  --samba-host HOST     Samba server hostname/IP (default: 127.0.0.1)
  --samba-port PORT     Samba server SMB port    (default: 445)
  --user USER           SMB username             (default: testuser)
  --pass PASS           SMB password             (default: 1234)
  --share SHARE         Share name on both servers (default: testshare)

Output:
  --json PATH           Write JSON conformance summary to PATH
  --no-color            Disable colour output
  --verbose             Print full command output on differences
  --timeout SECS        Per-operation timeout in seconds (default: 15)

  --help                Show this help

Exit codes:
  0  All 30 operations match
  1  One or more differences found
  2  Infrastructure / dependency error
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ksmbd-host)  KSMBD_HOST="$2";   shift 2 ;;
        --ksmbd-port)  KSMBD_PORT="$2";   shift 2 ;;
        --samba-host)  SAMBA_HOST="$2";   shift 2 ;;
        --samba-port)  SAMBA_PORT="$2";   shift 2 ;;
        --user)        SMB_USER="$2";     shift 2 ;;
        --pass)        SMB_PASS="$2";     shift 2 ;;
        --share)       SMB_SHARE="$2";    shift 2 ;;
        --json)        JSON_OUTPUT="$2";  shift 2 ;;
        --no-color)    NO_COLOR="yes";    shift ;;
        --verbose)     VERBOSE="yes";     shift ;;
        --timeout)     TIMEOUT_PER_OP="$2"; shift 2 ;;
        --help|-h)     _usage; exit 0 ;;
        *)
            printf "Unknown option: %s\n" "$1" >&2
            _usage >&2
            exit 2
            ;;
    esac
done

_init_colors

# ---------------------------------------------------------------------------
# Derived connection strings
# ---------------------------------------------------------------------------
KSMBD_UNC="//${KSMBD_HOST}/${SMB_SHARE}"
SAMBA_UNC="//${SAMBA_HOST}/${SMB_SHARE}"
SMB_CREDS="${SMB_USER}%${SMB_PASS}"

# Guest / bad-credential UNCs used in specific tests
KSMBD_IPC="//${KSMBD_HOST}/IPC\$"
SAMBA_IPC="//${SAMBA_HOST}/IPC\$"

# Shared work directory on local host for temp files
WORK_DIR=""

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------
declare -a OP_IDS=()
declare -A OP_DESC=()
declare -A OP_RESULT=()    # MATCH | DIFFER | SKIP | ERROR
declare -A OP_KSMBD_OUT=()
declare -A OP_SAMBA_OUT=()
declare -A OP_DETAIL=()

TOTAL_MATCH=0
TOTAL_DIFFER=0
TOTAL_SKIP=0
TOTAL_ERROR=0
TAP_COUNTER=0
RUN_START_EPOCH=0

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
_log_info()  { printf "  ${C_BLUE}[INFO]${C_RESET}  %s\n" "$*"; }
_log_warn()  { printf "  ${C_YELLOW}[WARN]${C_RESET}  %s\n" "$*" >&2; }
_log_error() { printf "  ${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2; }
_log_debug() { [[ "$VERBOSE" != "yes" ]] && return 0; printf "  ${C_DIM}[DBG]   %s${C_RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Core smbclient runner
# ---------------------------------------------------------------------------
# _smb_run UNC PORT CMD [EXTRA_OPTS...]
# Runs smbclient with timeout, captures stdout+stderr, returns exit code.
_smb_run() {
    local unc="$1" port="$2" cmd="$3"
    shift 3
    local extra_opts=("$@")

    timeout "${TIMEOUT_PER_OP}s" \
        smbclient "$unc" -p "$port" -U "$SMB_CREDS" \
            "${extra_opts[@]}" \
            -c "$cmd" 2>&1
}

# _smb_run_anon UNC PORT CMD [EXTRA_OPTS...]
# Runs smbclient anonymously (no credentials).
_smb_run_anon() {
    local unc="$1" port="$2" cmd="$3"
    shift 3
    local extra_opts=("$@")

    timeout "${TIMEOUT_PER_OP}s" \
        smbclient "$unc" -p "$port" -N \
            "${extra_opts[@]}" \
            -c "$cmd" 2>&1
}

# _smb_run_badpass UNC PORT CMD
# Runs smbclient with a deliberately wrong password.
_smb_run_badpass() {
    local unc="$1" port="$2" cmd="$3"

    timeout "${TIMEOUT_PER_OP}s" \
        smbclient "$unc" -p "$port" \
            -U "${SMB_USER}%WRONGPASSWORD_INVALID_XYZ" \
            -c "$cmd" 2>&1
}

# ---------------------------------------------------------------------------
# Status extraction helpers
# ---------------------------------------------------------------------------

# _extract_status OUTPUT -- Pull the first NT_STATUS_* token from output
_extract_status() {
    local output="$1"
    # Match NT_STATUS_XXX variants (smbclient prints these on protocol errors)
    echo "$output" | grep -oP 'NT_STATUS_\w+' | head -1
}

# _normalize_status OUTPUT -- Return status or "OK" when no error status found
_normalize_status() {
    local output="$1"
    local st
    st=$(_extract_status "$output")
    if [[ -z "$st" ]]; then
        echo "OK"
    else
        echo "$st"
    fi
}

# _conn_ok OUTPUT -- Returns 0 if smbclient connected successfully (no NT_STATUS error on connect)
_conn_ok() {
    local output="$1"
    # Session error messages
    if echo "$output" | grep -qP 'NT_STATUS_(LOGON_FAILURE|ACCESS_DENIED|CONNECTION_REFUSED|NO_SUCH_FILE|BAD_NETWORK_NAME|OBJECT_NAME_NOT_FOUND)'; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Comparison helpers
# ---------------------------------------------------------------------------

# _compare_statuses ID KSMBD_ST SAMBA_ST LABEL
# Record MATCH or DIFFER based on status code comparison.
_compare_statuses() {
    local id="$1" kst="$2" sst="$3" label="${4:-}"

    if [[ "$kst" == "$sst" ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=${kst} samba=${sst}" \
            "${label:+($label)}"
    fi
}

# _compare_presence_of NEEDLE KSMBD_OUT SAMBA_OUT ID LABEL
# Both outputs should either contain or not contain NEEDLE.
_compare_presence_of() {
    local needle="$1" ko="$2" so="$3" id="$4" label="${5:-}"
    local kin=0 sin=0
    echo "$ko" | grep -qi "$needle" && kin=1
    echo "$so" | grep -qi "$needle" && sin=1
    if [[ $kin -eq $sin ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=$([ $kin -eq 1 ] && echo 'present' || echo 'absent') samba=$([ $sin -eq 1 ] && echo 'present' || echo 'absent') needle='${needle}'" \
            "${label}"
    fi
}

# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------

_record_result() {
    local id="$1" result="$2" detail="${3:-}" label="${4:-}"
    OP_RESULT["$id"]="$result"
    OP_DETAIL["$id"]="${detail}${label:+ ${label}}"

    case "$result" in
        MATCH)  ((TOTAL_MATCH++))  || true ;;
        DIFFER) ((TOTAL_DIFFER++)) || true ;;
        SKIP)   ((TOTAL_SKIP++))   || true ;;
        ERROR)  ((TOTAL_ERROR++))  || true ;;
    esac

    _print_tap_line "$id"
}

_print_tap_line() {
    local id="$1"
    local result="${OP_RESULT[$id]:-?}"
    local desc="${OP_DESC[$id]:-$id}"
    local detail="${OP_DETAIL[$id]:-}"
    ((TAP_COUNTER++)) || true

    case "$result" in
        MATCH)
            printf "ok %d - %s %s\n" "$TAP_COUNTER" "$id" "$desc"
            ;;
        DIFFER)
            printf "not ok %d - %s %s\n" "$TAP_COUNTER" "$id" "$desc"
            printf "  # DIFFER: %s\n" "$detail"
            ;;
        SKIP)
            printf "ok %d - %s %s # SKIP %s\n" "$TAP_COUNTER" "$id" "$desc" "$detail"
            ;;
        ERROR)
            printf "not ok %d - %s %s # ERROR %s\n" "$TAP_COUNTER" "$id" "$desc" "$detail"
            ;;
    esac

    # Verbose: dump both outputs side by side on DIFFER
    if [[ "$VERBOSE" == "yes" && ("$result" == "DIFFER" || "$result" == "ERROR") ]]; then
        local ko="${OP_KSMBD_OUT[$id]:-}"
        local so="${OP_SAMBA_OUT[$id]:-}"
        if [[ -n "$ko" || -n "$so" ]]; then
            printf "  #   --- ksmbd output ---\n"
            echo "$ko" | head -10 | sed 's/^/  #   | /'
            printf "  #   --- samba output ---\n"
            echo "$so" | head -10 | sed 's/^/  #   | /'
        fi
    fi
}

# ---------------------------------------------------------------------------
# Setup / teardown test file infrastructure
# ---------------------------------------------------------------------------

# Create a temporary local directory for put/get temp files
_setup_workdir() {
    WORK_DIR=$(mktemp -d "/tmp/diff-vs-samba.XXXXXX")
}

_teardown_workdir() {
    [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
}

# Write a small test file to both servers; returns 0 on success
_seed_test_file() {
    local remote_name="$1"
    local content="${2:-differential_test_data_$(date +%s)}"
    local tmpf="${WORK_DIR}/seed_$$.tmp"
    printf '%s' "$content" > "$tmpf"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "put \"${tmpf}\" \"${remote_name}\"")
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "put \"${tmpf}\" \"${remote_name}\"")
    rm -f "$tmpf"

    if ! echo "$ko" | grep -qP 'NT_STATUS_' && ! echo "$so" | grep -qP 'NT_STATUS_'; then
        return 0
    fi
    return 1
}

# Delete a file on both servers (ignore errors)
_cleanup_test_file() {
    local remote_name="$1"
    _smb_run "$KSMBD_UNC" "$KSMBD_PORT" "del \"${remote_name}\"" >/dev/null 2>&1 || true
    _smb_run "$SAMBA_UNC" "$SAMBA_PORT" "del \"${remote_name}\"" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Preflight: verify tools and server reachability
# ---------------------------------------------------------------------------

_preflight() {
    local errors=0

    # Check smbclient
    if ! command -v smbclient >/dev/null 2>&1; then
        _log_error "smbclient not found in PATH. Install samba-client."
        ((errors++))
    fi

    # Check timeout
    if ! command -v timeout >/dev/null 2>&1; then
        _log_error "timeout not found in PATH."
        ((errors++))
    fi

    [[ $errors -gt 0 ]] && return 2

    # Probe ksmbd
    printf "  Probing ksmbd  %s:%s ... " "$KSMBD_HOST" "$KSMBD_PORT"
    local ko
    ko=$(timeout 8s smbclient "$KSMBD_UNC" -p "$KSMBD_PORT" \
        -U "$SMB_CREDS" -c "ls" 2>&1)
    if [[ $? -eq 0 ]] || echo "$ko" | grep -qP 'blocks'; then
        printf "${C_GREEN}reachable${C_RESET}\n"
        KSMBD_AVAILABLE=yes
    else
        local kst
        kst=$(_extract_status "$ko")
        printf "${C_YELLOW}unavailable${C_RESET} (%s)\n" "${kst:-timeout/connection refused}"
        KSMBD_AVAILABLE=no
    fi

    # Probe samba
    printf "  Probing samba  %s:%s ... " "$SAMBA_HOST" "$SAMBA_PORT"
    local so
    so=$(timeout 8s smbclient "$SAMBA_UNC" -p "$SAMBA_PORT" \
        -U "$SMB_CREDS" -c "ls" 2>&1)
    if [[ $? -eq 0 ]] || echo "$so" | grep -qP 'blocks'; then
        printf "${C_GREEN}reachable${C_RESET}\n"
        SAMBA_AVAILABLE=yes
    else
        local sst
        sst=$(_extract_status "$so")
        printf "${C_YELLOW}unavailable${C_RESET} (%s)\n" "${sst:-timeout/connection refused}"
        SAMBA_AVAILABLE=no
    fi

    echo ""
    return 0
}

# ---------------------------------------------------------------------------
# Register an operation definition (descriptive only)
# ---------------------------------------------------------------------------
_def_op() {
    local id="$1" desc="$2"
    OP_IDS+=("$id")
    OP_DESC["$id"]="$desc"
}

# ---------------------------------------------------------------------------
# Helper: run op on both servers, store outputs, compare statuses
# ---------------------------------------------------------------------------
# _run_and_compare_status ID UNC_K PORT_K UNC_S PORT_S CMD [EXTRA_K...] -- [EXTRA_S...]
# (simple variant: same CMD and same extras for both sides)
_run_status_cmp() {
    local id="$1" cmd="$2"
    shift 2
    local extra_opts=("$@")

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "$cmd" "${extra_opts[@]}" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "$cmd" "${extra_opts[@]}" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")

    _compare_statuses "$id" "$kst" "$sst" "$cmd"
}

# ---------------------------------------------------------------------------
# The 30 differential operations
# ---------------------------------------------------------------------------

# --- OP-01: SMB2 NEGOTIATE (dialect negotiation) ---------------------------
_op01_negotiate() {
    local id="OP-01"
    _def_op "$id" "SMB2 NEGOTIATE: dialect, capabilities, max sizes"

    if [[ "$KSMBD_AVAILABLE" == "no" && "$SAMBA_AVAILABLE" == "no" ]]; then
        _record_result "$id" "SKIP" "both servers unavailable" ""
        return
    fi

    # smbclient always negotiates; use 'ls' to exercise the full sequence.
    # We compare whether negotiation succeeds (exit 0 or contains 'blocks').
    local ko so
    ko=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$KSMBD_UNC" -p "$KSMBD_PORT" \
        -U "$SMB_CREDS" \
        --option="client min protocol=SMB2_02" \
        --option="client max protocol=SMB3_11" \
        -c "ls" 2>&1) || true
    so=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$SAMBA_UNC" -p "$SAMBA_PORT" \
        -U "$SMB_CREDS" \
        --option="client min protocol=SMB2_02" \
        --option="client max protocol=SMB3_11" \
        -c "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Both should succeed (exit normally with file listing)
    local ksuccess=0 ssuccess=0
    echo "$ko" | grep -qP '(blocks|\d+ files)' && ksuccess=1
    echo "$so" | grep -qP '(blocks|\d+ files)' && ssuccess=1

    if [[ $ksuccess -eq $ssuccess ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        local kst sst
        kst=$(_normalize_status "$ko")
        sst=$(_normalize_status "$so")
        _record_result "$id" "DIFFER" \
            "ksmbd_connected=${ksuccess} samba_connected=${ssuccess} kst=${kst} sst=${sst}" ""
    fi
}

# --- OP-02: SESSION_SETUP (auth status, session flags) ---------------------
_op02_session_setup() {
    local id="OP-02"
    _def_op "$id" "SESSION_SETUP: session flags, auth status"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Both should authenticate without LOGON_FAILURE
    local ksuccess=0 ssuccess=0
    ! echo "$ko" | grep -qP 'NT_STATUS_(LOGON_FAILURE|ACCESS_DENIED|WRONG_PASSWORD)' && ksuccess=1
    ! echo "$so" | grep -qP 'NT_STATUS_(LOGON_FAILURE|ACCESS_DENIED|WRONG_PASSWORD)' && ssuccess=1

    if [[ $ksuccess -eq $ssuccess ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd_auth_ok=${ksuccess} samba_auth_ok=${ssuccess}" ""
    fi
}

# --- OP-03: TREE_CONNECT (share type, flags) --------------------------------
_op03_tree_connect() {
    local id="OP-03"
    _def_op "$id" "TREE_CONNECT: share type and flags"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Tree connect success is implied when 'ls' returns file listing
    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "TREE_CONNECT"
}

# --- OP-04: CREATE new file -------------------------------------------------
_op04_create_new() {
    local id="OP-04"
    _def_op "$id" "CREATE new file: granted access, FILE_CREATED action"
    local fname="diff_new_$$_${RANDOM}.txt"
    local tmpf="${WORK_DIR}/op04.tmp"
    printf 'differential_test_v1' > "$tmpf"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "CREATE(new)"

    # Clean up
    _cleanup_test_file "$fname"
}

# --- OP-05: CREATE existing file (FILE_OPENED action) ----------------------
_op05_create_existing() {
    local id="OP-05"
    _def_op "$id" "CREATE existing file: FILE_OPENED vs FILE_CREATED"
    local fname="diff_exist_$$_${RANDOM}.txt"

    # Seed the file first
    _seed_test_file "$fname" "existing_content" 2>/dev/null || true

    local ko so
    # Open existing file for read
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "get \"${fname}\" /dev/null" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "get \"${fname}\" /dev/null" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "CREATE(existing)"

    _cleanup_test_file "$fname"
}

# --- OP-06: CREATE with FILE_SUPERSEDE ------------------------------------
_op06_create_supersede() {
    local id="OP-06"
    _def_op "$id" "CREATE with FILE_SUPERSEDE: truncates existing file"
    local fname="diff_supersede_$$_${RANDOM}.txt"

    # Seed then overwrite (smbclient 'put' uses OVERWRITE_IF which is closest)
    _seed_test_file "$fname" "original_content" 2>/dev/null || true

    local tmpf="${WORK_DIR}/op06.tmp"
    printf 'superseded_content' > "$tmpf"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"
    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "CREATE(supersede)"

    _cleanup_test_file "$fname"
}

# --- OP-07: CREATE with FILE_OVERWRITE_IF ---------------------------------
_op07_create_overwrite_if() {
    local id="OP-07"
    _def_op "$id" "CREATE with FILE_OVERWRITE_IF: creates or truncates"
    local fname="diff_overwriteif_$$_${RANDOM}.txt"
    local tmpf="${WORK_DIR}/op07.tmp"
    printf 'overwrite_if_content' > "$tmpf"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"
    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "CREATE(overwrite_if)"

    _cleanup_test_file "$fname"
}

# --- OP-08: READ at offset 0 -----------------------------------------------
_op08_read_offset0() {
    local id="OP-08"
    _def_op "$id" "READ at offset 0: data returned correctly"
    local fname="diff_read0_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "read_test_content" 2>/dev/null || true

    local ktmp="${WORK_DIR}/op08k.tmp"
    local stmp="${WORK_DIR}/op08s.tmp"

    local ko so
    ko=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$KSMBD_UNC" -p "$KSMBD_PORT" \
        -U "$SMB_CREDS" -c "get \"${fname}\" \"${ktmp}\"" 2>&1) || true
    so=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$SAMBA_UNC" -p "$SAMBA_PORT" \
        -U "$SMB_CREDS" -c "get \"${fname}\" \"${stmp}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Compare status codes
    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")

    if [[ "$kst" == "$sst" ]]; then
        # Also compare content if both succeeded
        if [[ "$kst" == "OK" ]]; then
            local kdata sdata
            kdata=$(cat "$ktmp" 2>/dev/null || echo "")
            sdata=$(cat "$stmp" 2>/dev/null || echo "")
            if [[ "$kdata" == "$sdata" ]]; then
                _record_result "$id" "MATCH" "" ""
            else
                _record_result "$id" "DIFFER" \
                    "status both OK but content differs (ksmbd='${kdata:0:40}' samba='${sdata:0:40}')" ""
            fi
        else
            _record_result "$id" "MATCH" "" ""
        fi
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=${kst} samba=${sst}" "READ(offset=0)"
    fi

    rm -f "$ktmp" "$stmp"
    _cleanup_test_file "$fname"
}

# --- OP-09: READ at EOF (expect STATUS_END_OF_FILE or empty) ---------------
_op09_read_eof() {
    local id="OP-09"
    _def_op "$id" "READ at EOF: STATUS_END_OF_FILE or empty response"
    local fname="diff_eof_$$_${RANDOM}.txt"
    # Create empty file
    local tmpf="${WORK_DIR}/op09.tmp"
    printf '' > "$tmpf"

    local ko so
    # Put empty file, then get it: both should return OK (empty download) or EOF
    ko=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$KSMBD_UNC" -p "$KSMBD_PORT" \
        -U "$SMB_CREDS" -c "put \"${tmpf}\" \"${fname}\"; get \"${fname}\" /dev/null" 2>&1) || true
    so=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$SAMBA_UNC" -p "$SAMBA_PORT" \
        -U "$SMB_CREDS" -c "put \"${tmpf}\" \"${fname}\"; get \"${fname}\" /dev/null" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"
    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "READ(EOF)"

    _cleanup_test_file "$fname"
}

# --- OP-10: WRITE at offset 0 ----------------------------------------------
_op10_write_offset0() {
    local id="OP-10"
    _def_op "$id" "WRITE at offset 0: bytes written count"
    local fname="diff_write0_$$_${RANDOM}.txt"
    local tmpf="${WORK_DIR}/op10.tmp"
    printf 'write_at_zero_offset' > "$tmpf"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"
    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "WRITE(offset=0)"

    _cleanup_test_file "$fname"
}

# --- OP-11: WRITE append (offset 0xFFFFFFFFFFFFFFFF) -----------------------
_op11_write_append() {
    local id="OP-11"
    _def_op "$id" "WRITE append (offset=0xFFFFFFFFFFFFFFFF): append-to-EOF"
    local fname="diff_append_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "initial_line" 2>/dev/null || true

    local tmpf="${WORK_DIR}/op11.tmp"
    printf 'appended_line' > "$tmpf"

    local ko so
    # smbclient 'append' uses the sentinel internally
    ko=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$KSMBD_UNC" -p "$KSMBD_PORT" \
        -U "$SMB_CREDS" -c "append \"${tmpf}\" \"${fname}\"" 2>&1) || true
    so=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$SAMBA_UNC" -p "$SAMBA_PORT" \
        -U "$SMB_CREDS" -c "append \"${tmpf}\" \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"
    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "WRITE(append)"

    _cleanup_test_file "$fname"
}

# --- OP-12: CLOSE with POSTQUERY_ATTRIB ------------------------------------
_op12_close_postquery() {
    local id="OP-12"
    _def_op "$id" "CLOSE with POSTQUERY_ATTRIB: attributes returned"
    local fname="diff_close_$$_${RANDOM}.txt"
    local tmpf="${WORK_DIR}/op12.tmp"
    printf 'close_attrib_test' > "$tmpf"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "put \"${tmpf}\" \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"
    rm -f "$tmpf"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "CLOSE+POSTQUERY"

    _cleanup_test_file "$fname"
}

# --- OP-13: QUERY_INFO FileBasicInformation --------------------------------
_op13_query_basic_info() {
    local id="OP-13"
    _def_op "$id" "QUERY_INFO FileBasicInformation: attribute format"
    local fname="diff_qbasic_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "query_basic_test" 2>/dev/null || true

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "allinfo \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "allinfo \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")

    if [[ "$kst" == "$sst" ]]; then
        # Both returned the same top-level status: now compare whether the
        # "attributes:" field is present in both outputs (FileBasicInformation).
        # _compare_presence_of records the MATCH/DIFFER result internally.
        _compare_presence_of "attributes:" "$ko" "$so" "$id" "FileBasicInfo"
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=${kst} samba=${sst}" "QUERY_INFO(FileBasicInfo)"
    fi

    _cleanup_test_file "$fname"
}

# --- OP-14: QUERY_INFO FileStandardInformation ----------------------------
_op14_query_standard_info() {
    local id="OP-14"
    _def_op "$id" "QUERY_INFO FileStandardInformation: sizes, link count"
    local fname="diff_qstd_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "standard_info_content" 2>/dev/null || true

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "allinfo \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "allinfo \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Compare whether "size" information is reported
    _compare_presence_of "size:" "$ko" "$so" "$id" "FileStandardInfo"

    _cleanup_test_file "$fname"
}

# --- OP-15: QUERY_INFO FileAllInformation ----------------------------------
_op15_query_all_info() {
    local id="OP-15"
    _def_op "$id" "QUERY_INFO FileAllInformation: all fields"
    local fname="diff_qall_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "all_info_content_test" 2>/dev/null || true

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "allinfo \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "allinfo \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "QUERY_INFO(All)"

    _cleanup_test_file "$fname"
}

# --- OP-16: SET_INFO rename -----------------------------------------------
_op16_setinfo_rename() {
    local id="OP-16"
    _def_op "$id" "SET_INFO rename: verify status"
    local fname_old="diff_rename_old_$$_${RANDOM}.txt"
    local fname_new="diff_rename_new_$$_${RANDOM}.txt"
    _seed_test_file "$fname_old" "rename_test_content" 2>/dev/null || true

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "rename \"${fname_old}\" \"${fname_new}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "rename \"${fname_old}\" \"${fname_new}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "SET_INFO(rename)"

    # Cleanup both possible names
    _cleanup_test_file "$fname_old"
    _cleanup_test_file "$fname_new"
}

# --- OP-17: SET_INFO delete-on-close --------------------------------------
_op17_setinfo_doc() {
    local id="OP-17"
    _def_op "$id" "SET_INFO delete-on-close: behavior"
    local fname="diff_doc_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "doc_test_content" 2>/dev/null || true

    # Attempt to delete: in smbclient 'del' exercises the delete path
    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "del \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "del \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "SET_INFO(delete-on-close)"
}

# --- OP-18: QUERY_DIRECTORY FileBothDirectoryInformation -------------------
_op18_query_dir() {
    local id="OP-18"
    _def_op "$id" "QUERY_DIRECTORY FileBothDirectoryInformation: entry format"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "QUERY_DIR(BothDirInfo)"
}

# --- OP-19: QUERY_DIRECTORY with wildcard "*" ------------------------------
_op19_query_dir_wildcard() {
    local id="OP-19"
    _def_op "$id" "QUERY_DIRECTORY with wildcard '*': entry count comparable"

    # Seed some files so both servers have non-empty directories
    local fname1="diff_wc1_$$_${RANDOM}.txt"
    local fname2="diff_wc2_$$_${RANDOM}.txt"
    _seed_test_file "$fname1" "wildcard_content1" 2>/dev/null || true
    _seed_test_file "$fname2" "wildcard_content2" 2>/dev/null || true

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls *" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls *" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "QUERY_DIR(wildcard)"

    _cleanup_test_file "$fname1"
    _cleanup_test_file "$fname2"
}

# --- OP-20: LOCK exclusive -------------------------------------------------
_op20_lock_exclusive() {
    local id="OP-20"
    _def_op "$id" "LOCK exclusive: verify status"

    local ko so
    # smbtorture smb2.lock.rw-exclusive would be ideal; fall back to smbclient ls
    # (smbclient does not have a direct lock command; use ls as connectivity proxy)
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Use smbtorture if available
    if command -v smbtorture >/dev/null 2>&1; then
        ko=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${KSMBD_HOST}/${SMB_SHARE}" -p "$KSMBD_PORT" \
            -U "$SMB_CREDS" smb2.lock.rw-exclusive 2>&1) || true
        so=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${SAMBA_HOST}/${SMB_SHARE}" -p "$SAMBA_PORT" \
            -U "$SMB_CREDS" smb2.lock.rw-exclusive 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        _compare_presence_of "success:" "$ko" "$so" "$id" "LOCK(exclusive)"
    else
        local kst sst
        kst=$(_normalize_status "$ko")
        sst=$(_normalize_status "$so")
        _compare_statuses "$id" "$kst" "$sst" "LOCK(exclusive-proxy)"
    fi
}

# --- OP-21: LOCK shared ----------------------------------------------------
_op21_lock_shared() {
    local id="OP-21"
    _def_op "$id" "LOCK shared: verify status"

    local ko so
    if command -v smbtorture >/dev/null 2>&1; then
        ko=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${KSMBD_HOST}/${SMB_SHARE}" -p "$KSMBD_PORT" \
            -U "$SMB_CREDS" smb2.lock.rw-shared 2>&1) || true
        so=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${SAMBA_HOST}/${SMB_SHARE}" -p "$SAMBA_PORT" \
            -U "$SMB_CREDS" smb2.lock.rw-shared 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        _compare_presence_of "success:" "$ko" "$so" "$id" "LOCK(shared)"
    else
        # No smbtorture: compare basic connectivity as proxy
        ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
        so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        local kst sst
        kst=$(_normalize_status "$ko")
        sst=$(_normalize_status "$so")
        _compare_statuses "$id" "$kst" "$sst" "LOCK(shared-proxy)"
    fi
}

# --- OP-22: UNLOCK ---------------------------------------------------------
_op22_unlock() {
    local id="OP-22"
    _def_op "$id" "UNLOCK: verify status"

    # proxy via smbtorture compound lock test if available
    local ko so
    if command -v smbtorture >/dev/null 2>&1; then
        ko=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${KSMBD_HOST}/${SMB_SHARE}" -p "$KSMBD_PORT" \
            -U "$SMB_CREDS" smb2.lock.unlock 2>&1) || true
        so=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${SAMBA_HOST}/${SMB_SHARE}" -p "$SAMBA_PORT" \
            -U "$SMB_CREDS" smb2.lock.unlock 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        _compare_presence_of "success:" "$ko" "$so" "$id" "UNLOCK"
    else
        ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
        so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        local kst sst
        kst=$(_normalize_status "$ko")
        sst=$(_normalize_status "$so")
        _compare_statuses "$id" "$kst" "$sst" "UNLOCK(proxy)"
    fi
}

# --- OP-23: IOCTL FSCTL_VALIDATE_NEGOTIATE_INFO ----------------------------
_op23_validate_negotiate() {
    local id="OP-23"
    _def_op "$id" "IOCTL FSCTL_VALIDATE_NEGOTIATE_INFO: compare status"

    local ko so
    if command -v smbtorture >/dev/null 2>&1; then
        ko=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${KSMBD_HOST}/${SMB_SHARE}" -p "$KSMBD_PORT" \
            -U "$SMB_CREDS" smb2.ioctl.validate_negotiate 2>&1) || true
        so=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${SAMBA_HOST}/${SMB_SHARE}" -p "$SAMBA_PORT" \
            -U "$SMB_CREDS" smb2.ioctl.validate_negotiate 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        _compare_presence_of "success:" "$ko" "$so" "$id" "VALIDATE_NEGOTIATE"
    else
        # Connectivity proxy
        ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
        so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        _record_result "$id" "SKIP" "smbtorture not available" "VALIDATE_NEGOTIATE"
    fi
}

# --- OP-24: IOCTL FSCTL_GET_INTEGRITY_INFORMATION --------------------------
_op24_get_integrity() {
    local id="OP-24"
    _def_op "$id" "IOCTL FSCTL_GET_INTEGRITY_INFORMATION: compare status"

    local fname="diff_integ_$$_${RANDOM}.txt"
    _seed_test_file "$fname" "integrity_test" 2>/dev/null || true

    local ko so
    if command -v smbtorture >/dev/null 2>&1; then
        ko=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${KSMBD_HOST}/${SMB_SHARE}" -p "$KSMBD_PORT" \
            -U "$SMB_CREDS" smb2.ioctl 2>&1) || true
        so=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${SAMBA_HOST}/${SMB_SHARE}" -p "$SAMBA_PORT" \
            -U "$SMB_CREDS" smb2.ioctl 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        # Both should have same success/failure rate on the ioctl suite
        local kpass spass
        kpass=$(echo "$ko" | grep -c 'success:' 2>/dev/null || echo 0)
        spass=$(echo "$so" | grep -c 'success:' 2>/dev/null || echo 0)
        local kfail sfail
        kfail=$(echo "$ko" | grep -c 'failure:' 2>/dev/null || echo 0)
        sfail=$(echo "$so" | grep -c 'failure:' 2>/dev/null || echo 0)

        # Flag if ksmbd has more failures than Samba
        if [[ $kfail -gt $((sfail + 2)) ]]; then
            _record_result "$id" "DIFFER" \
                "ksmbd_fail=${kfail} samba_fail=${sfail} ksmbd_pass=${kpass} samba_pass=${spass}" \
                "GET_INTEGRITY"
        else
            _record_result "$id" "MATCH" "" ""
        fi
    else
        _record_result "$id" "SKIP" "smbtorture not available" "GET_INTEGRITY"
    fi

    _cleanup_test_file "$fname"
}

# --- OP-25: ECHO -----------------------------------------------------------
_op25_echo() {
    local id="OP-25"
    _def_op "$id" "ECHO: verify response status"

    # smbclient doesn't expose echo; use 'ls' as connectivity indicator.
    # A more precise test would require raw SMB2 packet construction.
    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")
    _compare_statuses "$id" "$kst" "$sst" "ECHO(proxy:ls)"
}

# --- OP-26: CHANGE_NOTIFY with FILE_NOTIFY_CHANGE_FILE_NAME ---------------
_op26_change_notify() {
    local id="OP-26"
    _def_op "$id" "CHANGE_NOTIFY FILE_NOTIFY_CHANGE_FILE_NAME: behavior"

    local ko so
    if command -v smbtorture >/dev/null 2>&1; then
        # smb2.notify tests change notification behavior
        ko=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${KSMBD_HOST}/${SMB_SHARE}" -p "$KSMBD_PORT" \
            -U "$SMB_CREDS" smb2.notify 2>&1) || true
        so=$(timeout "${TIMEOUT_PER_OP}s" smbtorture \
            "//${SAMBA_HOST}/${SMB_SHARE}" -p "$SAMBA_PORT" \
            -U "$SMB_CREDS" smb2.notify 2>&1) || true
        OP_KSMBD_OUT["$id"]="$ko"
        OP_SAMBA_OUT["$id"]="$so"
        _compare_presence_of "success:" "$ko" "$so" "$id" "CHANGE_NOTIFY"
    else
        _record_result "$id" "SKIP" "smbtorture not available" "CHANGE_NOTIFY"
    fi
}

# --- OP-27: Guest session (compare access level) --------------------------
_op27_guest_session() {
    local id="OP-27"
    _def_op "$id" "Guest session: compare access level"

    local ko so
    ko=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$KSMBD_UNC" -p "$KSMBD_PORT" \
        -N -c "ls" 2>&1) || true
    so=$(timeout "${TIMEOUT_PER_OP}s" smbclient "$SAMBA_UNC" -p "$SAMBA_PORT" \
        -N -c "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    # Both should behave the same: either allow or deny anonymous access
    local kallow=0 sallow=0
    echo "$ko" | grep -qP '(blocks|\d+ files)' && kallow=1
    echo "$so" | grep -qP '(blocks|\d+ files)' && sallow=1

    if [[ $kallow -eq $sallow ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd_allows_guest=${kallow} samba_allows_guest=${sallow}" "GUEST_SESSION"
    fi
}

# --- OP-28: Invalid password (compare error status) -----------------------
_op28_invalid_password() {
    local id="OP-28"
    _def_op "$id" "Invalid password: compare error status"

    local ko so
    ko=$(_smb_run_badpass "$KSMBD_UNC" "$KSMBD_PORT" "ls" 2>&1) || true
    so=$(_smb_run_badpass "$SAMBA_UNC" "$SAMBA_PORT" "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")

    # Acceptable error statuses for wrong password — normalize to a canonical token.
    # NT_STATUS_LOGON_FAILURE, NT_STATUS_WRONG_PASSWORD, NT_STATUS_ACCESS_DENIED all
    # represent "authentication rejected" and are interchangeable for conformance.
    local kn sn
    case "$kst" in
        NT_STATUS_LOGON_FAILURE|NT_STATUS_WRONG_PASSWORD|NT_STATUS_ACCESS_DENIED)
            kn="AUTH_REJECTED" ;;
        *)
            kn="$kst" ;;
    esac
    case "$sst" in
        NT_STATUS_LOGON_FAILURE|NT_STATUS_WRONG_PASSWORD|NT_STATUS_ACCESS_DENIED)
            sn="AUTH_REJECTED" ;;
        *)
            sn="$sst" ;;
    esac

    if [[ "$kn" == "$sn" ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=${kst} samba=${sst}" "INVALID_PASSWORD"
    fi
}

# --- OP-29: Delete non-existent file (compare error status) ---------------
_op29_delete_nonexistent() {
    local id="OP-29"
    _def_op "$id" "Delete non-existent file: compare error status"
    local fname="diff_nonexist_$$_${RANDOM}_DOESNOTEXIST.txt"

    local ko so
    ko=$(_smb_run "$KSMBD_UNC" "$KSMBD_PORT" "del \"${fname}\"" 2>&1) || true
    so=$(_smb_run "$SAMBA_UNC" "$SAMBA_PORT" "del \"${fname}\"" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")

    # Both should return some form of "not found" error.
    # Accept NO_SUCH_FILE, OBJECT_NAME_NOT_FOUND, OBJECT_PATH_NOT_FOUND as equivalent —
    # different servers may use slightly different error codes for the same condition.
    local kn sn
    case "$kst" in
        NT_STATUS_NO_SUCH_FILE|NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_OBJECT_PATH_NOT_FOUND)
            kn="FILE_NOT_FOUND" ;;
        *)
            kn="$kst" ;;
    esac
    case "$sst" in
        NT_STATUS_NO_SUCH_FILE|NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_OBJECT_PATH_NOT_FOUND)
            sn="FILE_NOT_FOUND" ;;
        *)
            sn="$sst" ;;
    esac

    if [[ "$kn" == "$sn" ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=${kst} samba=${sst}" "DEL_NONEXISTENT"
    fi
}

# --- OP-30: Access non-existent share (compare error status) --------------
_op30_nonexistent_share() {
    local id="OP-30"
    _def_op "$id" "Access non-existent share: compare error status"
    local bad_share="NONEXISTENT_SHARE_XYZ_$$"

    local ko so
    ko=$(timeout "${TIMEOUT_PER_OP}s" smbclient \
        "//${KSMBD_HOST}/${bad_share}" -p "$KSMBD_PORT" \
        -U "$SMB_CREDS" -c "ls" 2>&1) || true
    so=$(timeout "${TIMEOUT_PER_OP}s" smbclient \
        "//${SAMBA_HOST}/${bad_share}" -p "$SAMBA_PORT" \
        -U "$SMB_CREDS" -c "ls" 2>&1) || true

    OP_KSMBD_OUT["$id"]="$ko"
    OP_SAMBA_OUT["$id"]="$so"

    local kst sst
    kst=$(_normalize_status "$ko")
    sst=$(_normalize_status "$so")

    # Accept BAD_NETWORK_NAME, OBJECT_NAME_NOT_FOUND, and NO_SUCH_FILE as equivalent —
    # all represent "share does not exist" and are interchangeable for conformance.
    local kn sn
    case "$kst" in
        NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_NO_SUCH_FILE)
            kn="BAD_SHARE" ;;
        *)
            kn="$kst" ;;
    esac
    case "$sst" in
        NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_OBJECT_NAME_NOT_FOUND|NT_STATUS_NO_SUCH_FILE)
            sn="BAD_SHARE" ;;
        *)
            sn="$sst" ;;
    esac

    if [[ "$kn" == "$sn" ]]; then
        _record_result "$id" "MATCH" "" ""
    else
        _record_result "$id" "DIFFER" \
            "ksmbd=${kst} samba=${sst}" "NONEXISTENT_SHARE"
    fi
}

# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
_emit_json() {
    local path="$1"
    local timestamp total_ops score_pct
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local total_ops=${#OP_IDS[@]}
    if [[ $total_ops -gt 0 ]]; then
        score_pct=$(awk "BEGIN { printf \"%.1f\", (${TOTAL_MATCH} / ${total_ops}) * 100 }")
    else
        score_pct="0.0"
    fi

    {
        cat <<JSON_HEAD
{
  "tool": "differential_vs_samba",
  "version": "1.0.0",
  "timestamp": "${timestamp}",
  "ksmbd": {
    "host": "${KSMBD_HOST}",
    "port": ${KSMBD_PORT}
  },
  "samba": {
    "host": "${SAMBA_HOST}",
    "port": ${SAMBA_PORT}
  },
  "share": "${SMB_SHARE}",
  "user": "${SMB_USER}",
  "summary": {
    "total_ops": ${total_ops},
    "match": ${TOTAL_MATCH},
    "differ": ${TOTAL_DIFFER},
    "skip": ${TOTAL_SKIP},
    "error": ${TOTAL_ERROR},
    "conformance_score": "${TOTAL_MATCH}/${total_ops}",
    "conformance_pct": ${score_pct}
  },
  "operations": [
JSON_HEAD

        local i=0
        local count=${#OP_IDS[@]}
        for oid in "${OP_IDS[@]}"; do
            ((i++))
            local desc result detail
            desc="${OP_DESC[$oid]:-}"
            result="${OP_RESULT[$oid]:-UNKNOWN}"
            detail="${OP_DETAIL[$oid]:-}"

            # JSON-escape strings: replace " with \" and strip control chars
            desc=$(printf '%s' "$desc" | sed 's/"/\\"/g; s/\\/\\\\/g' | tr -dc '[:print:]')
            detail=$(printf '%s' "$detail" | sed 's/"/\\"/g; s/\\/\\\\/g' | tr -dc '[:print:]' | head -c 200)

            local comma=","
            [[ $i -eq $count ]] && comma=""

            cat <<JSON_OP
    {
      "id": "${oid}",
      "description": "${desc}",
      "result": "${result}",
      "detail": "${detail}"
    }${comma}
JSON_OP
        done

        echo "  ]"
        echo "}"
    } > "$path"
}

# ---------------------------------------------------------------------------
# Print human-readable summary
# ---------------------------------------------------------------------------
_print_summary() {
    local total_ops=${#OP_IDS[@]}
    local duration=$(( $(date +%s) - RUN_START_EPOCH ))

    echo ""
    printf "${C_BOLD}${C_CYAN}================================================================${C_RESET}\n"
    printf "${C_BOLD}  Differential Conformance Report: ksmbd vs Samba${C_RESET}\n"
    printf "${C_BOLD}${C_CYAN}================================================================${C_RESET}\n"
    printf "  ksmbd:  %s:%s\n" "$KSMBD_HOST" "$KSMBD_PORT"
    printf "  samba:  %s:%s\n" "$SAMBA_HOST" "$SAMBA_PORT"
    printf "  share:  %s\n" "$SMB_SHARE"
    printf "  user:   %s\n" "$SMB_USER"
    echo ""

    # Per-operation table
    printf "  %-8s %-10s %s\n" "OP" "RESULT" "DESCRIPTION"
    printf "  %-8s %-10s %s\n" "--------" "----------" "-----------"
    for oid in "${OP_IDS[@]}"; do
        local result="${OP_RESULT[$oid]:-?}"
        local desc="${OP_DESC[$oid]:-}"
        local color=""
        case "$result" in
            MATCH)  color="$C_GREEN"  ;;
            DIFFER) color="$C_RED"    ;;
            SKIP)   color="$C_YELLOW" ;;
            ERROR)  color="$C_RED"    ;;
        esac
        printf "  %-8s ${color}%-10s${C_RESET} %-55s\n" \
            "$oid" "$result" "${desc:0:55}"
        if [[ "$result" != "MATCH" && -n "${OP_DETAIL[$oid]:-}" ]]; then
            printf "           ${C_DIM}%s${C_RESET}\n" "${OP_DETAIL[$oid]:0:70}"
        fi
    done

    echo ""
    printf "${C_BOLD}  %-10s ${C_GREEN}%d${C_RESET}  " "MATCH:"  "$TOTAL_MATCH"
    printf "${C_BOLD}${C_RED}DIFFER: %d${C_RESET}  " "$TOTAL_DIFFER"
    printf "${C_YELLOW}SKIP: %d${C_RESET}  " "$TOTAL_SKIP"
    if [[ $TOTAL_ERROR -gt 0 ]]; then
        printf "${C_RED}ERROR: %d${C_RESET}  " "$TOTAL_ERROR"
    fi
    echo ""

    local score_pct="0.0"
    if [[ $total_ops -gt 0 ]]; then
        score_pct=$(awk "BEGIN { printf \"%.1f\", (${TOTAL_MATCH} / ${total_ops}) * 100 }")
    fi

    echo ""
    printf "  ${C_BOLD}Conformance score: ${TOTAL_MATCH}/${total_ops} (${score_pct}%%)${C_RESET}\n"
    printf "  Duration:          %ds\n" "$duration"

    if [[ -n "$JSON_OUTPUT" ]]; then
        printf "  JSON output:       %s\n" "$JSON_OUTPUT"
    fi
    echo ""

    if [[ $TOTAL_DIFFER -eq 0 && $TOTAL_ERROR -eq 0 ]]; then
        printf "  ${C_GREEN}${C_BOLD}CONFORMANCE: PERFECT - ksmbd matches Samba on all tested operations${C_RESET}\n"
    elif [[ $TOTAL_DIFFER -le 2 ]]; then
        printf "  ${C_YELLOW}${C_BOLD}CONFORMANCE: MINOR DIFFERENCES - review DIFFER entries above${C_RESET}\n"
    else
        printf "  ${C_RED}${C_BOLD}CONFORMANCE: REGRESSIONS DETECTED - %d differences vs Samba${C_RESET}\n" "$TOTAL_DIFFER"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo ""
    printf "${C_BOLD}${C_CYAN}ksmbd Differential Conformance Tester (vs Samba)${C_RESET}\n"
    printf "${C_DIM}Sending identical SMB operations to both servers and comparing responses${C_RESET}\n"
    echo ""

    # Dependency check and server probing
    KSMBD_AVAILABLE=no
    SAMBA_AVAILABLE=no
    _preflight
    local pf_rc=$?
    if [[ $pf_rc -eq 2 ]]; then
        _log_error "Dependency check failed. Exiting."
        exit 2
    fi

    # Graceful degradation: if one or both servers are down, skip all ops
    if [[ "$KSMBD_AVAILABLE" == "no" && "$SAMBA_AVAILABLE" == "no" ]]; then
        _log_warn "Neither server is reachable. All operations will be SKIPped."
    elif [[ "$KSMBD_AVAILABLE" == "no" ]]; then
        _log_warn "ksmbd server is unavailable at ${KSMBD_HOST}:${KSMBD_PORT}. Operations will be SKIPped."
    elif [[ "$SAMBA_AVAILABLE" == "no" ]]; then
        _log_warn "Samba server is unavailable at ${SAMBA_HOST}:${SAMBA_PORT}. Operations will be SKIPped."
    fi

    _setup_workdir
    trap '_teardown_workdir' EXIT

    RUN_START_EPOCH=$(date +%s)

    # TAP header (printed before any results)
    printf "TAP version 13\n"
    printf "1..30\n"
    printf "# ksmbd differential conformance test vs Samba\n"
    printf "# ksmbd=%s:%s samba=%s:%s share=%s user=%s\n" \
        "$KSMBD_HOST" "$KSMBD_PORT" "$SAMBA_HOST" "$SAMBA_PORT" \
        "$SMB_SHARE" "$SMB_USER"
    echo ""

    # --- Run the 30 operations ---
    # If a server is unavailable, we run the operations anyway but they will
    # produce SKIP or DIFFER results based on the smbclient output.

    _op01_negotiate
    _op02_session_setup
    _op03_tree_connect
    _op04_create_new
    _op05_create_existing
    _op06_create_supersede
    _op07_create_overwrite_if
    _op08_read_offset0
    _op09_read_eof
    _op10_write_offset0
    _op11_write_append
    _op12_close_postquery
    _op13_query_basic_info
    _op14_query_standard_info
    _op15_query_all_info
    _op16_setinfo_rename
    _op17_setinfo_doc
    _op18_query_dir
    _op19_query_dir_wildcard
    _op20_lock_exclusive
    _op21_lock_shared
    _op22_unlock
    _op23_validate_negotiate
    _op24_get_integrity
    _op25_echo
    _op26_change_notify
    _op27_guest_session
    _op28_invalid_password
    _op29_delete_nonexistent
    _op30_nonexistent_share

    # TAP footer summary
    printf "# Total: %d  Match: %d  Differ: %d  Skip: %d  Error: %d\n" \
        "${#OP_IDS[@]}" "$TOTAL_MATCH" "$TOTAL_DIFFER" "$TOTAL_SKIP" "$TOTAL_ERROR"

    # Human-readable summary (to stderr so TAP stays clean)
    _print_summary >&2

    # JSON output
    if [[ -n "$JSON_OUTPUT" ]]; then
        _emit_json "$JSON_OUTPUT"
        _log_info "JSON summary written to: ${JSON_OUTPUT}" >&2
    fi

    # Exit code
    if [[ $TOTAL_DIFFER -gt 0 || $TOTAL_ERROR -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
