#!/bin/bash
# torture_runner.sh -- Main ksmbd-torture integration test runner
#
# Discovers and runs all test suites in tests/ksmbd-torture/suites/,
# producing TAP, JSON, or CSV output with colorized terminal display.
#
# Usage: ./torture_runner.sh [OPTIONS]
#
# Options:
#   --host HOST           SMB server host (default: 127.0.0.1)
#   --port PORT           SMB server port (default: 445)
#   --share SHARE         Share name (default: test)
#   --user USER           Username (default: testuser)
#   --pass PASS           Password (default: 1234)
#   --filter PATTERN      Run only tests matching glob pattern (e.g., "T04_*")
#   --output-format FMT   Output format: tap, json, csv (default: tap)
#   --parallel N          Run up to N suites concurrently (default: 1)
#   --timeout SECS        Per-test timeout in seconds (default: 60)
#   --no-color            Disable colorized output
#   --verbose             Show full output from each test
#   --list                List all discovered tests and exit
#   --suite FILE          Run only this specific suite file
#   --help                Show this help
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Infrastructure error (server unreachable, tools missing)

set -uo pipefail

# ============================================================================
# Locate ourselves and source helpers
# ============================================================================
RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUITES_DIR="${RUNNER_DIR}/suites"
LIB_DIR="${RUNNER_DIR}/lib"

if [[ ! -f "${LIB_DIR}/helpers.sh" ]]; then
    echo "FATAL: Cannot find ${LIB_DIR}/helpers.sh" >&2
    exit 2
fi
# shellcheck disable=SC1091
source "${LIB_DIR}/helpers.sh"

# ============================================================================
# Default configuration
# ============================================================================
export SMB_HOST="127.0.0.1"
export SMB_PORT="445"
export SMB_SHARE="test"
export SMB_USER="testuser"
export SMB_PASS="1234"

FILTER=""
OUTPUT_FORMAT="tap"
PARALLEL_JOBS=1
TEST_TIMEOUT=60
NO_COLOR="no"
VERBOSE="no"
LIST_MODE="no"
SUITE_FILE=""

# ============================================================================
# Color support
# ============================================================================
_c_reset=""
_c_green=""
_c_red=""
_c_yellow=""
_c_blue=""
_c_bold=""
_c_dim=""

init_colors() {
    if [[ "$NO_COLOR" == "no" ]] && [[ -t 1 ]]; then
        _c_reset=$'\033[0m'
        _c_green=$'\033[32m'
        _c_red=$'\033[31m'
        _c_yellow=$'\033[33m'
        _c_blue=$'\033[34m'
        _c_bold=$'\033[1m'
        _c_dim=$'\033[2m'
    fi
}

# ============================================================================
# CLI Parsing
# ============================================================================
usage() {
    cat <<'USAGE'
Usage: torture_runner.sh [OPTIONS]

Connection:
  --host HOST           SMB server host (default: 127.0.0.1)
  --port PORT           SMB server port (default: 445)
  --share SHARE         Share name (default: test)
  --user USER           Username (default: testuser)
  --pass PASS           Password (default: 1234)

Test Selection:
  --filter PATTERN      Run only tests/suites matching pattern (e.g., "T04*")
  --suite FILE          Run only this specific suite file (path or basename)
  --list                List all discovered tests and exit

Execution:
  --parallel N          Run up to N suites concurrently (default: 1)
  --timeout SECS        Per-test timeout in seconds (default: 60)

Output:
  --output-format FMT   Output format: tap, json, csv (default: tap)
  --no-color            Disable colorized output
  --verbose             Show full test output on failure

Misc:
  --help                Show this help

Exit Codes:
  0  All tests passed
  1  One or more tests failed
  2  Infrastructure error
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           SMB_HOST="$2"; shift 2 ;;
        --port)           SMB_PORT="$2"; shift 2 ;;
        --share)          SMB_SHARE="$2"; shift 2 ;;
        --user)           SMB_USER="$2"; shift 2 ;;
        --pass)           SMB_PASS="$2"; shift 2 ;;
        --filter)         FILTER="$2"; shift 2 ;;
        --output-format)  OUTPUT_FORMAT="$2"; shift 2 ;;
        --parallel)       PARALLEL_JOBS="$2"; shift 2 ;;
        --timeout)        TEST_TIMEOUT="$2"; shift 2 ;;
        --no-color)       NO_COLOR="yes"; shift ;;
        --verbose)        VERBOSE="yes"; shift ;;
        --list)           LIST_MODE="yes"; shift ;;
        --suite)          SUITE_FILE="$2"; shift 2 ;;
        --help|-h)        usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 2
            ;;
    esac
done

# Re-export derived variables
export SMB_UNC="//${SMB_HOST}/${SMB_SHARE}"
export SMB_CREDS="${SMB_USER}%${SMB_PASS}"

init_colors

# ============================================================================
# Suite Discovery
# ============================================================================

# Discover all suite files (T01_*.sh, T02_*.sh, etc.) sorted by name.
discover_suites() {
    local suites=()
    if [[ -n "$SUITE_FILE" ]]; then
        # Single suite mode
        if [[ -f "$SUITE_FILE" ]]; then
            suites+=("$SUITE_FILE")
        elif [[ -f "${SUITES_DIR}/${SUITE_FILE}" ]]; then
            suites+=("${SUITES_DIR}/${SUITE_FILE}")
        elif [[ -f "${SUITES_DIR}/${SUITE_FILE}.sh" ]]; then
            suites+=("${SUITES_DIR}/${SUITE_FILE}.sh")
        else
            echo "Suite not found: $SUITE_FILE" >&2
            exit 2
        fi
    else
        local f
        for f in "${SUITES_DIR}"/T[0-9][0-9]_*.sh; do
            [[ -f "$f" ]] || continue
            if [[ -n "$FILTER" ]]; then
                local basename
                basename=$(basename "$f" .sh)
                # shellcheck disable=SC2254
                case "$basename" in
                    $FILTER) suites+=("$f") ;;
                    *) ;;
                esac
            else
                suites+=("$f")
            fi
        done
    fi
    printf '%s\n' "${suites[@]}"
}

# Extract test function names from a suite file.
# Convention: functions named test_* are test cases.
extract_tests_from_suite() {
    local suite_file="$1"
    grep -oP '^test_\w+(?=\s*\(\))' "$suite_file" 2>/dev/null || true
}

# ============================================================================
# Test Execution
# ============================================================================

# Global result tracking
declare -a ALL_RESULTS=()
GLOBAL_PASS=0
GLOBAL_FAIL=0
GLOBAL_SKIP=0
GLOBAL_TOTAL=0
GLOBAL_START_TIME=0

# run_single_test SUITE_FILE TEST_FUNC
# Execute a single test function with timeout. Captures output and timing.
# Returns: 0=pass, 1=fail, 2=skip, 124=timeout
run_single_test() {
    local suite_file="$1"
    local test_func="$2"
    local output=""
    local rc=0
    local start_ms end_ms elapsed_ms

    start_ms=$(date +%s%3N 2>/dev/null || date +%s)

    # Run the test in a subshell that sources the suite
    output=$(
        timeout "$TEST_TIMEOUT" bash -c "
            source '${LIB_DIR}/helpers.sh'
            helpers_init
            export SMB_HOST='$SMB_HOST'
            export SMB_PORT='$SMB_PORT'
            export SMB_SHARE='$SMB_SHARE'
            export SMB_USER='$SMB_USER'
            export SMB_PASS='$SMB_PASS'
            export SMB_UNC='//$SMB_HOST/$SMB_SHARE'
            export SMB_CREDS='${SMB_USER}%${SMB_PASS}'
            source '$suite_file'
            $test_func
        " 2>&1
    )
    rc=$?

    end_ms=$(date +%s%3N 2>/dev/null || date +%s)
    elapsed_ms=$((end_ms - start_ms))

    echo "${rc}|${elapsed_ms}|${output}"
    return $rc
}

# run_suite SUITE_FILE
# Run all test_* functions in a suite file, recording results.
run_suite() {
    local suite_file="$1"
    local suite_name
    suite_name=$(basename "$suite_file" .sh)
    local tests
    tests=$(extract_tests_from_suite "$suite_file")

    if [[ -z "$tests" ]]; then
        return 0
    fi

    local test_func
    for test_func in $tests; do
        ((GLOBAL_TOTAL++))
        local result_line
        result_line=$(run_single_test "$suite_file" "$test_func" 2>&1)
        local rc=$?

        local elapsed_ms output
        # Parse the rc|elapsed|output from the subshell
        # Since the output can contain |, we parse carefully
        local raw_rc raw_elapsed raw_output
        raw_rc=$(echo "$result_line" | head -1 | cut -d'|' -f1)
        raw_elapsed=$(echo "$result_line" | head -1 | cut -d'|' -f2)
        raw_output=$(echo "$result_line" | head -1 | cut -d'|' -f3-)

        # Use the actual exit code if parsing fails
        : "${raw_rc:=$rc}"
        : "${raw_elapsed:=0}"

        local status desc
        # Extract description from the test function (convention: first line = local desc="...")
        desc=$(grep -A1 "^${test_func}()" "$suite_file" | grep 'local desc=' | sed 's/.*local desc="\(.*\)".*/\1/' | head -1)
        : "${desc:=$test_func}"

        if [[ "$raw_rc" -eq 0 ]]; then
            status="PASS"
            ((GLOBAL_PASS++))
        elif [[ "$raw_rc" -eq 77 ]]; then
            # Convention: exit 77 = skip
            status="SKIP"
            ((GLOBAL_SKIP++))
        elif [[ "$raw_rc" -eq 124 ]]; then
            status="FAIL"
            raw_output="TIMEOUT after ${TEST_TIMEOUT}s"
            ((GLOBAL_FAIL++))
        else
            status="FAIL"
            ((GLOBAL_FAIL++))
        fi

        ALL_RESULTS+=("${status}|${suite_name}|${test_func}|${desc}|${raw_elapsed}|${raw_output}")

        # Terminal output (always printed during execution)
        case "$status" in
            PASS)
                printf "  ${_c_green}ok${_c_reset}  %s - %s ${_c_dim}(%sms)${_c_reset}\n" \
                    "$test_func" "$desc" "$raw_elapsed"
                ;;
            FAIL)
                printf "  ${_c_red}FAIL${_c_reset} %s - %s ${_c_dim}(%sms)${_c_reset}\n" \
                    "$test_func" "$desc" "$raw_elapsed"
                if [[ "$VERBOSE" == "yes" && -n "$raw_output" ]]; then
                    echo "$raw_output" | sed 's/^/       | /'
                fi
                ;;
            SKIP)
                printf "  ${_c_yellow}skip${_c_reset} %s - %s\n" \
                    "$test_func" "$desc"
                ;;
        esac
    done
}

# ============================================================================
# Output Formatters
# ============================================================================

emit_tap() {
    echo "TAP version 13"
    echo "1..${GLOBAL_TOTAL}"
    local i=0
    local r
    for r in "${ALL_RESULTS[@]}"; do
        ((i++))
        local status suite func desc elapsed output
        IFS='|' read -r status suite func desc elapsed output <<< "$r"
        case "$status" in
            PASS) echo "ok $i - ${suite}::${func} - ${desc}" ;;
            FAIL) echo "not ok $i - ${suite}::${func} - ${desc}"
                  if [[ -n "$output" ]]; then
                      echo "  ---"
                      echo "  message: |"
                      echo "$output" | head -20 | sed 's/^/    /'
                      echo "  duration_ms: $elapsed"
                      echo "  ..."
                  fi
                  ;;
            SKIP) echo "ok $i - ${suite}::${func} - ${desc} # SKIP ${output}" ;;
        esac
    done
}

emit_json() {
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local duration=$(($(date +%s) - GLOBAL_START_TIME))

    cat <<JSON_HEAD
{
  "suite": "ksmbd-torture",
  "version": "1.0.0",
  "timestamp": "${timestamp}",
  "host": "${SMB_HOST}",
  "port": ${SMB_PORT},
  "share": "${SMB_SHARE}",
  "duration_seconds": ${duration},
  "summary": {
    "total": ${GLOBAL_TOTAL},
    "pass": ${GLOBAL_PASS},
    "fail": ${GLOBAL_FAIL},
    "skip": ${GLOBAL_SKIP}
  },
  "tests": [
JSON_HEAD

    local i=0
    local count=${#ALL_RESULTS[@]}
    local r
    for r in "${ALL_RESULTS[@]}"; do
        ((i++))
        local status suite func desc elapsed output
        IFS='|' read -r status suite func desc elapsed output <<< "$r"
        # Escape JSON strings
        output=$(echo "$output" | head -5 | tr '\n' ' ' | sed 's/"/\\"/g; s/\\/\\\\/g' | head -c 500)
        desc=$(echo "$desc" | sed 's/"/\\"/g')
        local comma=","
        [[ $i -eq $count ]] && comma=""
        cat <<JSON_TEST
    {
      "id": "${suite}::${func}",
      "suite": "${suite}",
      "name": "${func}",
      "description": "${desc}",
      "status": "${status}",
      "duration_ms": ${elapsed:-0},
      "message": "${output}"
    }${comma}
JSON_TEST
    done

    echo "  ]"
    echo "}"
}

emit_csv() {
    echo "status,suite,test,description,duration_ms,message"
    local r
    for r in "${ALL_RESULTS[@]}"; do
        local status suite func desc elapsed output
        IFS='|' read -r status suite func desc elapsed output <<< "$r"
        # Escape CSV (double quotes)
        desc=$(echo "$desc" | sed 's/"/""/g')
        output=$(echo "$output" | head -1 | sed 's/"/""/g' | head -c 200)
        echo "\"${status}\",\"${suite}\",\"${func}\",\"${desc}\",${elapsed:-0},\"${output}\""
    done
}

# ============================================================================
# Main
# ============================================================================

# Check that smbclient is available
if ! command -v smbclient >/dev/null 2>&1; then
    echo "FATAL: smbclient not found in PATH. Install samba-client package." >&2
    exit 2
fi

# Discover suites
mapfile -t SUITE_FILES < <(discover_suites)

if [[ ${#SUITE_FILES[@]} -eq 0 ]]; then
    echo "No test suites found in ${SUITES_DIR}/" >&2
    exit 2
fi

# List mode
if [[ "$LIST_MODE" == "yes" ]]; then
    for sf in "${SUITE_FILES[@]}"; do
        local_name=$(basename "$sf" .sh)
        echo "${_c_bold}${local_name}${_c_reset}:"
        local tests
        tests=$(extract_tests_from_suite "$sf")
        for t in $tests; do
            local d
            d=$(grep -A1 "^${t}()" "$sf" | grep 'local desc=' | sed 's/.*local desc="\(.*\)".*/\1/' | head -1)
            printf "  %-40s %s\n" "$t" "${d:-(no description)}"
        done
    done
    exit 0
fi

# Pre-flight: verify SMB connectivity
echo "${_c_bold}ksmbd-torture integration test runner${_c_reset}"
echo "  Host:  ${SMB_HOST}:${SMB_PORT}"
echo "  Share: ${SMB_SHARE}"
echo "  User:  ${SMB_USER}"
echo "  Format: ${OUTPUT_FORMAT}"
echo ""

echo -n "Checking SMB connectivity... "
helpers_init
if smb_connect >/dev/null 2>&1; then
    echo "${_c_green}OK${_c_reset}"
else
    echo "${_c_red}FAILED${_c_reset}"
    echo ""
    echo "Cannot connect to //${SMB_HOST}/${SMB_SHARE}:${SMB_PORT}" >&2
    echo "Verify the server is running and credentials are correct." >&2
    exit 2
fi
echo ""

GLOBAL_START_TIME=$(date +%s)

# Run suites (sequential or parallel)
if [[ "$PARALLEL_JOBS" -gt 1 ]]; then
    # Parallel execution: run suites concurrently using background jobs
    _PARALLEL_TMPDIR=$(mktemp -d "/tmp/ksmbd-torture-parallel.XXXXXX")
    _parallel_pids=()
    _parallel_idx=0

    for sf in "${SUITE_FILES[@]}"; do
        suite_name=$(basename "$sf" .sh)
        (
            # Each parallel job runs in its own subshell
            source "${LIB_DIR}/helpers.sh"
            helpers_init
            GLOBAL_TOTAL=0
            GLOBAL_PASS=0
            GLOBAL_FAIL=0
            GLOBAL_SKIP=0
            ALL_RESULTS=()

            run_suite "$sf"

            # Write results to a temp file
            {
                echo "TOTAL=$GLOBAL_TOTAL"
                echo "PASS=$GLOBAL_PASS"
                echo "FAIL=$GLOBAL_FAIL"
                echo "SKIP=$GLOBAL_SKIP"
                for r in "${ALL_RESULTS[@]}"; do
                    echo "RESULT|$r"
                done
            } > "${_PARALLEL_TMPDIR}/${suite_name}.result"
        ) &
        _parallel_pids+=($!)
        ((_parallel_idx++))

        # Throttle to PARALLEL_JOBS
        if [[ ${#_parallel_pids[@]} -ge $PARALLEL_JOBS ]]; then
            wait "${_parallel_pids[0]}" 2>/dev/null
            _parallel_pids=("${_parallel_pids[@]:1}")
        fi
    done

    # Wait for remaining jobs
    for pid in "${_parallel_pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Aggregate results from temp files
    for sf in "${SUITE_FILES[@]}"; do
        suite_name=$(basename "$sf" .sh)
        local_result="${_PARALLEL_TMPDIR}/${suite_name}.result"
        if [[ -f "$local_result" ]]; then
            while IFS= read -r line; do
                case "$line" in
                    TOTAL=*) GLOBAL_TOTAL=$((GLOBAL_TOTAL + ${line#TOTAL=})) ;;
                    PASS=*)  GLOBAL_PASS=$((GLOBAL_PASS + ${line#PASS=})) ;;
                    FAIL=*)  GLOBAL_FAIL=$((GLOBAL_FAIL + ${line#FAIL=})) ;;
                    SKIP=*)  GLOBAL_SKIP=$((GLOBAL_SKIP + ${line#SKIP=})) ;;
                    RESULT\|*) ALL_RESULTS+=("${line#RESULT|}") ;;
                esac
            done < "$local_result"
        fi
    done
    rm -rf "$_PARALLEL_TMPDIR"
else
    # Sequential execution
    for sf in "${SUITE_FILES[@]}"; do
        suite_name=$(basename "$sf" .sh)
        echo "${_c_bold}${_c_blue}=== ${suite_name} ===${_c_reset}"
        run_suite "$sf"
        echo ""
    done
fi

# ============================================================================
# Summary
# ============================================================================
echo "${_c_bold}=== SUMMARY ===${_c_reset}"
echo "  Total:  ${GLOBAL_TOTAL}"
echo "  ${_c_green}Pass:   ${GLOBAL_PASS}${_c_reset}"
if [[ $GLOBAL_FAIL -gt 0 ]]; then
    echo "  ${_c_red}Fail:   ${GLOBAL_FAIL}${_c_reset}"
else
    echo "  Fail:   ${GLOBAL_FAIL}"
fi
if [[ $GLOBAL_SKIP -gt 0 ]]; then
    echo "  ${_c_yellow}Skip:   ${GLOBAL_SKIP}${_c_reset}"
else
    echo "  Skip:   ${GLOBAL_SKIP}"
fi
echo ""

# ============================================================================
# Emit formatted output
# ============================================================================
case "$OUTPUT_FORMAT" in
    tap)
        echo "${_c_dim}--- TAP Output ---${_c_reset}"
        emit_tap
        ;;
    json)
        emit_json
        ;;
    csv)
        emit_csv
        ;;
    *)
        echo "Unknown output format: $OUTPUT_FORMAT" >&2
        ;;
esac

# ============================================================================
# Exit code
# ============================================================================
if [[ $GLOBAL_FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
