#!/bin/bash
# ksmbd-torture.sh -- Main entry point for the ksmbd integration test suite
#
# Usage: ./ksmbd-torture.sh [OPTIONS]
#
# Run --help for full option list.
#
# Exit codes:
#   0  All selected tests passed
#   1  One or more tests failed
#   2  Server crash or unrecoverable error detected
#   3  Infrastructure error (VM unreachable, tool missing, config error)

set -uo pipefail

# ---------------------------------------------------------------------------
# Determine script location (works from any CWD)
# ---------------------------------------------------------------------------
TORTURE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TORTURE_DIR

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
# shellcheck disable=SC1091
source "${TORTURE_DIR}/conf/default.conf"

# ---------------------------------------------------------------------------
# CLI Parsing
# ---------------------------------------------------------------------------
FILTER_CATEGORIES=""
FILTER_TESTS=""
FILTER_TAGS=""
EXCLUDE_CATEGORIES=""
QUICK_MODE="no"
BENCHMARK_MODE="no"
JSON_OUTPUT_FILE=""
LOG_FILE=""
CONFIG_FILE=""
LIST_MODE=""

usage() {
    cat <<'EOF'
Usage: ksmbd-torture.sh [OPTIONS]

Test Selection:
  --category CAT[,CAT...]   Run only these categories (T01, T02, B01, ...)
  --test ID[,ID...]          Run only these specific tests (T01.03, T13.17)
  --exclude CAT[,CAT...]     Skip these categories
  --tag TAG[,TAG...]         Run only tests with these tags (slow, quic, smb1)
  --quick                    Run only fast tests (timeout <= 10s, no 'slow' tag)
  --benchmark                Run benchmark categories (B01-B07) instead of tests

Execution:
  --parallel N               Run up to N tests in parallel within a category
  --restart-between          Reload ksmbd module between categories
  --retry N                  Retry failed tests N times before marking FAIL
  --shuffle                  Randomize test order within categories

VM Target:
  --vm NAME                  VM name (VM3, VM4) -- loads conf/vmN.conf
  --config FILE              Load custom config file
  --share NAME               Share name to test against (default: test)
  --user USER%PASS           Credentials (default: testuser%testpass)
  --guest                    Connect as guest (no credentials)
  --port PORT                SMB port (default: 13445)
  --ssh-port PORT            SSH port (default: 13022)

Output:
  --json FILE                Write JSON results to FILE
  --tap                      Output in TAP format (for CI)
  --no-color                 Disable color output
  --verbose                  Print full test output on failure
  --log FILE                 Tee full console output to FILE

Server Control:
  --no-health-check          Skip server health probes between categories
  --no-restart               Never restart server (overrides --restart-between)

Info:
  --list                     List all registered tests and exit
  --list-categories          List all categories and exit
  --help                     Show this help and exit

Exit Codes:
  0  All selected tests passed
  1  One or more tests failed
  2  Server crash or unrecoverable error detected
  3  Infrastructure error (VM unreachable, tool missing, config error)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --category)         FILTER_CATEGORIES="$2"; shift 2 ;;
        --test)             FILTER_TESTS="$2"; shift 2 ;;
        --exclude)          EXCLUDE_CATEGORIES="$2"; shift 2 ;;
        --tag)              FILTER_TAGS="$2"; shift 2 ;;
        --quick)            QUICK_MODE="yes"; shift ;;
        --benchmark)        BENCHMARK_MODE="yes"; shift ;;
        --parallel)         PARALLEL_JOBS="$2"; shift 2 ;;
        --restart-between)  RESTART_BETWEEN="yes"; shift ;;
        --retry)            RETRY_COUNT="$2"; shift 2 ;;
        --shuffle)          SHUFFLE="yes"; shift ;;
        --vm)
            local_vm_conf="${TORTURE_DIR}/conf/$(echo "$2" | tr '[:upper:]' '[:lower:]').conf"
            if [[ -f "$local_vm_conf" ]]; then
                # shellcheck disable=SC1090
                source "$local_vm_conf"
            else
                # Try parsing as VM name for known VMs
                case "$2" in
                    VM3|vm3) VM_NAME="VM3"; VM_SSH_PORT=13022; SMB_PORT=13445 ;;
                    VM4|vm4) VM_NAME="VM4"; VM_SSH_PORT=14022; SMB_PORT=14445 ;;
                    *)
                        # Try HOST:SSHPORT:SMBPORT format
                        if [[ "$2" == *:* ]]; then
                            IFS=: read -r VM_HOST VM_SSH_PORT SMB_PORT <<< "$2"
                            SMB_HOST="$VM_HOST"
                            VM_NAME="custom"
                        else
                            echo "Unknown VM: $2" >&2
                            exit 3
                        fi
                        ;;
                esac
            fi
            shift 2
            ;;
        --config)           CONFIG_FILE="$2"; shift 2 ;;
        --share)            SMB_SHARE="$2"; shift 2 ;;
        --user)
            SMB_CREDS="$2"
            SMB_USER="${2%%\%*}"
            SMB_PASS="${2#*\%}"
            shift 2
            ;;
        --guest)            SMB_USER=""; SMB_PASS=""; SMB_CREDS=""; shift ;;
        --port)             SMB_PORT="$2"; shift 2 ;;
        --ssh-port)         VM_SSH_PORT="$2"; shift 2 ;;
        --json)             JSON_OUTPUT_FILE="$2"; shift 2 ;;
        --tap)              TAP_OUTPUT="yes"; shift ;;
        --no-color)         NO_COLOR="yes"; shift ;;
        --verbose)          VERBOSE="yes"; shift ;;
        --log)              LOG_FILE="$2"; shift 2 ;;
        --no-health-check)  NO_HEALTH_CHECK="yes"; shift ;;
        --no-restart)       NO_RESTART="yes"; shift ;;
        --list)             LIST_MODE="tests"; shift ;;
        --list-categories)  LIST_MODE="categories"; shift ;;
        --help|-h)          usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 3
            ;;
    esac
done

# Load custom config file if specified (after CLI so CLI wins)
if [[ -n "$CONFIG_FILE" ]]; then
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Config file not found: $CONFIG_FILE" >&2
        exit 3
    fi
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

# Re-derive dependent variables
SMB_HOST="${SMB_HOST:-$VM_HOST}"
SMB_CREDS="${SMB_CREDS:-${SMB_USER}%${SMB_PASS}}"

# ---------------------------------------------------------------------------
# Source Libraries
# ---------------------------------------------------------------------------
# shellcheck disable=SC1091
source "${TORTURE_DIR}/lib/vm_control.sh"
# shellcheck disable=SC1091
source "${TORTURE_DIR}/lib/smb_helpers.sh"
# shellcheck disable=SC1091
source "${TORTURE_DIR}/lib/assertions.sh"
# shellcheck disable=SC1091
source "${TORTURE_DIR}/lib/server_health.sh"
# shellcheck disable=SC1091
source "${TORTURE_DIR}/lib/framework.sh"
# shellcheck disable=SC1091
source "${TORTURE_DIR}/lib/reporting.sh"

# Initialize colors
init_colors

# ---------------------------------------------------------------------------
# Set up logging (tee to file if --log specified)
# ---------------------------------------------------------------------------
if [[ -n "$LOG_FILE" ]]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
fi

# ---------------------------------------------------------------------------
# Discover Tests
# ---------------------------------------------------------------------------
discover_tests

# ---------------------------------------------------------------------------
# Handle --list modes (no VM needed)
# ---------------------------------------------------------------------------
if [[ "$LIST_MODE" == "tests" ]]; then
    for id in "${_TEST_IDS[@]}"; do
        printf "%-12s %-45s timeout=%-4s requires=%-15s tags=%s\n" \
            "$id" \
            "${_TEST_DESCRIPTIONS[$id]:-${_TEST_FUNCS[$id]}}" \
            "${_TEST_TIMEOUTS[$id]}s" \
            "${_TEST_REQUIRES[$id]:-none}" \
            "${_TEST_TAGS[$id]:-none}"
    done
    exit 0
fi

if [[ "$LIST_MODE" == "categories" ]]; then
    while IFS= read -r cat; do
        local_count=0
        for id in "${_TEST_IDS[@]}"; do
            [[ "$id" == "${cat}."* ]] && ((local_count++))
        done
        printf "%-10s %3d tests\n" "$cat" "$local_count"
    done < <(get_all_categories)
    exit 0
fi

# ---------------------------------------------------------------------------
# Pre-Flight Checks
# ---------------------------------------------------------------------------

# Check required tools on host
_missing=""
for tool in sshpass ssh smbclient; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        _missing="${_missing:+$_missing, }$tool"
    fi
done
if [[ -n "$_missing" ]]; then
    log_error "Missing required host tools: $_missing"
    exit 3
fi

# Check VM reachability
log_info "Checking VM $VM_NAME reachability (${VM_HOST}:${VM_SSH_PORT})..."
if ! vm_ssh_reachable; then
    log_error "Cannot reach VM $VM_NAME via SSH (${VM_HOST}:${VM_SSH_PORT})"
    exit 3
fi

if ! vm_smb_port_open; then
    log_warn "SMB port not open on VM $VM_NAME, attempting to start ksmbd..."
    vm_start_ksmbd
    if ! vm_smb_port_open; then
        log_error "SMB port still not open after start attempt"
        exit 3
    fi
fi

log_info "VM $VM_NAME is reachable (SSH + SMB)"

# Verify SMB connectivity from host
log_info "Testing SMB connectivity to //${SMB_HOST}/${SMB_SHARE}:${SMB_PORT}..."
if ! smb_connect_test_retry 3; then
    log_error "Cannot connect to SMB share //${SMB_HOST}/${SMB_SHARE} on port ${SMB_PORT}"
    exit 3
fi
log_info "SMB connectivity verified"

# ---------------------------------------------------------------------------
# Filter Tests
# ---------------------------------------------------------------------------
filter_tests

if [[ ${#_FILTERED_IDS[@]} -eq 0 ]]; then
    log_warn "No tests matched the specified filters"
    exit 0
fi

# ---------------------------------------------------------------------------
# Set up results directory
# ---------------------------------------------------------------------------
setup_results_dir

# ---------------------------------------------------------------------------
# Run Suite
# ---------------------------------------------------------------------------
run_suite

# ---------------------------------------------------------------------------
# Generate Reports
# ---------------------------------------------------------------------------
finalize_results

if [[ "$TAP_OUTPUT" != "yes" && -n "${JSON_OUTPUT_FILE:-}" ]]; then
    log_info "JSON results written to: $JSON_OUTPUT_FILE"
fi

# ---------------------------------------------------------------------------
# Exit with appropriate code
# ---------------------------------------------------------------------------
exit "$(get_exit_code)"
