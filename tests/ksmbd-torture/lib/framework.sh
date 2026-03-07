#!/bin/bash
# lib/framework.sh -- Test registration, discovery, execution engine
#
# This is the core of ksmbd-torture. It provides:
#   - Test registration via register_test()
#   - Test discovery by sourcing categories/*.sh
#   - Sequential and parallel execution with per-test timeouts
#   - Result recording and aggregation
#   - Integration with reporting.sh for output generation
#
# This file supersedes test_framework.sh and is the authoritative engine.
# Source it from ksmbd-torture.sh after setting global config vars.

# ---------------------------------------------------------------------------
# Configuration Defaults
# ---------------------------------------------------------------------------
: "${SMB_HOST:=127.0.0.1}"
: "${SMB_PORT:=13445}"
: "${SMB_SHARE:=test}"
: "${SMB_USER:=testuser}"
: "${SMB_PASS:=testpass}"
: "${VM_HOST:=127.0.0.1}"
: "${VM_SSH_PORT:=13022}"
: "${VM_USER:=root}"
: "${VM_PASS:=root}"
: "${VM_NAME:=VM3}"
: "${DEFAULT_TIMEOUT:=30}"
: "${VERBOSE:=no}"
: "${NO_COLOR:=no}"
: "${TAP_OUTPUT:=no}"
: "${PARALLEL_JOBS:=1}"
: "${RESTART_BETWEEN:=no}"
: "${NO_RESTART:=no}"
: "${NO_HEALTH_CHECK:=no}"
: "${SHUFFLE:=no}"
: "${RETRY_COUNT:=0}"
: "${QUICK_MODE:=no}"
: "${BENCHMARK_MODE:=no}"

SMB_CREDS="${SMB_USER}%${SMB_PASS}"

# ---------------------------------------------------------------------------
# Internal State: Test Registry
# ---------------------------------------------------------------------------
declare -a _TEST_IDS=()
declare -A _TEST_FUNCS=()
declare -A _TEST_TIMEOUTS=()
declare -A _TEST_REQUIRES=()
declare -A _TEST_TAGS=()
declare -A _TEST_DESCRIPTIONS=()
declare -A _TEST_AFTER=()

# ---------------------------------------------------------------------------
# Internal State: Results
# ---------------------------------------------------------------------------
declare -a _RESULT_IDS=()
declare -A _RESULT_STATUS=()
declare -A _RESULT_DURATION=()
declare -A _RESULT_MESSAGE=()
declare -A _RESULT_OUTPUT=()

# ---------------------------------------------------------------------------
# Internal State: Categories
# ---------------------------------------------------------------------------
declare -a _CATEGORIES_RUN=()
declare -A _CATEGORY_PASS=()
declare -A _CATEGORY_FAIL=()
declare -A _CATEGORY_SKIP=()
declare -A _CATEGORY_CRASH=()
declare -A _CATEGORY_DURATION=()
declare -A _CATEGORY_HEALTH=()

# ---------------------------------------------------------------------------
# Global Counters
# ---------------------------------------------------------------------------
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_CRASH=0
SUITE_START_MS=0
SUITE_DURATION_MS=0

# Health events
declare -a _HEALTH_EVENTS=()

# Filtered test list (populated by filter_tests)
declare -a _FILTERED_IDS=()

# ---------------------------------------------------------------------------
# Color Support
# ---------------------------------------------------------------------------
_C_RESET="" _C_GREEN="" _C_RED="" _C_YELLOW="" _C_BLUE="" _C_CYAN="" _C_BOLD="" _C_DIM=""

init_colors() {
    if [[ "$NO_COLOR" != "yes" ]] && [[ -t 1 ]]; then
        _C_RESET="\033[0m"
        _C_GREEN="\033[32m"
        _C_RED="\033[31m"
        _C_YELLOW="\033[33m"
        _C_BLUE="\033[34m"
        _C_CYAN="\033[36m"
        _C_BOLD="\033[1m"
        _C_DIM="\033[2m"
    fi
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()  {
    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "# [INFO] $*"
    else
        printf "  ${_C_BLUE}[INFO]${_C_RESET} %s\n" "$*"
    fi
}
log_warn()  {
    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "# [WARN] $*"
    else
        printf "  ${_C_YELLOW}[WARN]${_C_RESET} %s\n" "$*" >&2
    fi
}
log_error() {
    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "# [ERROR] $*"
    else
        printf "  ${_C_RED}[ERROR]${_C_RESET} %s\n" "$*" >&2
    fi
}
log_debug() {
    [[ "$VERBOSE" != "yes" ]] && return 0
    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "# [DEBUG] $*"
    else
        printf "  ${_C_DIM}[DEBUG] %s${_C_RESET}\n" "$*"
    fi
}

# ===========================================================================
# TEST REGISTRATION
# ===========================================================================

# register_test ID FUNCTION [OPTIONS...]
#
# Options:
#   --timeout N           Per-test timeout in seconds (default: 30)
#   --requires TOOL,...   Tool dependencies (smbclient, smbtorture, python3)
#   --tags TAG,...        Freeform tags for filtering (slow, destructive, quic)
#   --description "..."  One-line human-readable description
#   --after ID,...        Test IDs that must run first
register_test() {
    local id="$1"
    local func="$2"
    shift 2

    local timeout="$DEFAULT_TIMEOUT"
    local requires=""
    local tags=""
    local description=""
    local after=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --timeout)     timeout="$2"; shift 2 ;;
            --requires)    requires="$2"; shift 2 ;;
            --tags)        tags="$2"; shift 2 ;;
            --description) description="$2"; shift 2 ;;
            --after)       after="$2"; shift 2 ;;
            *)             shift ;;
        esac
    done

    _TEST_IDS+=("$id")
    _TEST_FUNCS["$id"]="$func"
    _TEST_TIMEOUTS["$id"]="$timeout"
    _TEST_REQUIRES["$id"]="$requires"
    _TEST_TAGS["$id"]="$tags"
    _TEST_DESCRIPTIONS["$id"]="${description:-$func}"
    _TEST_AFTER["$id"]="$after"
}

# ===========================================================================
# TEST DISCOVERY
# ===========================================================================

# discover_tests -- Source all categories/*.sh files
discover_tests() {
    local categories_dir="${TORTURE_DIR}/categories"
    if [[ ! -d "$categories_dir" ]]; then
        log_error "Categories directory not found: $categories_dir"
        return 1
    fi

    local count_before=${#_TEST_IDS[@]}
    local file_count=0

    for catfile in "$categories_dir"/*.sh; do
        [[ -f "$catfile" ]] || continue
        ((file_count++))
        # shellcheck disable=SC1090
        source "$catfile"
    done

    local count_after=${#_TEST_IDS[@]}
    local discovered=$(( count_after - count_before ))
    log_info "Discovered $discovered tests from $file_count category files"
}

# get_tests_for_category CAT -- Return test IDs matching a category prefix
get_tests_for_category() {
    local cat_prefix="$1"
    for id in "${_TEST_IDS[@]}"; do
        if [[ "$id" == "${cat_prefix}."* ]]; then
            echo "$id"
        fi
    done
}

# get_all_categories -- Return unique sorted category prefixes
get_all_categories() {
    local -A seen=()
    for id in "${_TEST_IDS[@]}"; do
        local cat="${id%%.*}"
        if [[ -z "${seen[$cat]:-}" ]]; then
            seen["$cat"]=1
            echo "$cat"
        fi
    done
}

# get_test_count -- Return total registered test count
get_test_count() {
    echo "${#_TEST_IDS[@]}"
}

# ===========================================================================
# TEST FILTERING
# ===========================================================================

# filter_tests -- Apply CLI filters, populate _FILTERED_IDS
filter_tests() {
    _FILTERED_IDS=()

    for id in "${_TEST_IDS[@]}"; do
        local cat="${id%%.*}"
        local tags="${_TEST_TAGS[$id]:-}"
        local timeout="${_TEST_TIMEOUTS[$id]:-30}"

        # --category filter
        if [[ -n "${FILTER_CATEGORIES:-}" ]]; then
            local match=0
            IFS=',' read -ra cats <<< "$FILTER_CATEGORIES"
            for fc in "${cats[@]}"; do
                [[ "$cat" == "$fc" ]] && { match=1; break; }
            done
            [[ $match -eq 0 ]] && continue
        fi

        # --exclude filter
        if [[ -n "${EXCLUDE_CATEGORIES:-}" ]]; then
            local excluded=0
            IFS=',' read -ra excats <<< "$EXCLUDE_CATEGORIES"
            for ec in "${excats[@]}"; do
                [[ "$cat" == "$ec" ]] && { excluded=1; break; }
            done
            [[ $excluded -eq 1 ]] && continue
        fi

        # --test filter
        if [[ -n "${FILTER_TESTS:-}" ]]; then
            local match=0
            IFS=',' read -ra ftests <<< "$FILTER_TESTS"
            for ft in "${ftests[@]}"; do
                [[ "$id" == "$ft" ]] && { match=1; break; }
            done
            [[ $match -eq 0 ]] && continue
        fi

        # --tag filter
        if [[ -n "${FILTER_TAGS:-}" ]]; then
            local match=0
            IFS=',' read -ra ftags <<< "$FILTER_TAGS"
            for ft in "${ftags[@]}"; do
                [[ "$tags" == *"$ft"* ]] && { match=1; break; }
            done
            [[ $match -eq 0 ]] && continue
        fi

        # --quick mode: timeout <= 10 and no 'slow' tag
        if [[ "$QUICK_MODE" == "yes" ]]; then
            [[ $timeout -gt 10 || "$tags" == *"slow"* ]] && continue
        fi

        # --benchmark mode: only B* categories
        if [[ "$BENCHMARK_MODE" == "yes" ]]; then
            [[ "$cat" != B* ]] && continue
        fi

        _FILTERED_IDS+=("$id")
    done

    log_info "Filtered to ${#_FILTERED_IDS[@]} tests"
}

# ===========================================================================
# REQUIREMENT CHECKING
# ===========================================================================

_MISSING_REQS=""

check_requirements() {
    local requires="$1"
    _MISSING_REQS=""
    [[ -z "$requires" ]] && return 0

    IFS=',' read -ra tools <<< "$requires"
    for tool in "${tools[@]}"; do
        tool="$(echo "$tool" | tr -d ' ')"
        if ! command -v "$tool" >/dev/null 2>&1; then
            _MISSING_REQS="${_MISSING_REQS:+$_MISSING_REQS, }$tool"
        fi
    done
    [[ -z "$_MISSING_REQS" ]]
}

# ===========================================================================
# SINGLE TEST EXECUTION
# ===========================================================================

# run_single_test ID -- Execute one test, record result
# Returns: 0=PASS, 1=FAIL, 2=SKIP, 3=CRASH
run_single_test() {
    local test_id="$1"
    local func="${_TEST_FUNCS[$test_id]}"
    local timeout="${_TEST_TIMEOUTS[$test_id]:-30}"
    local requires="${_TEST_REQUIRES[$test_id]:-}"
    local desc="${_TEST_DESCRIPTIONS[$test_id]:-$func}"

    # Check tool requirements
    if ! check_requirements "$requires"; then
        record_result "$test_id" "SKIP" 0 "missing tools: $_MISSING_REQS" ""
        print_test_result "$test_id" "SKIP" 0 "$desc"
        return 2
    fi

    # Execute with timeout in a subshell
    local start_ms elapsed_ms exit_code output
    start_ms=$(date +%s%3N)

    output=$(timeout "${timeout}s" bash -c "
        # Source all library functions so they are available in the subshell
        TORTURE_DIR='${TORTURE_DIR}'
        source '${TORTURE_DIR}/lib/vm_control.sh'
        source '${TORTURE_DIR}/lib/smb_helpers.sh'
        source '${TORTURE_DIR}/lib/assertions.sh'
        source '${TORTURE_DIR}/lib/server_health.sh'

        # Export configuration
        export VM_HOST='${VM_HOST}'
        export VM_SSH_PORT='${VM_SSH_PORT}'
        export VM_USER='${VM_USER}'
        export VM_PASS='${VM_PASS}'
        export SMB_HOST='${SMB_HOST}'
        export SMB_PORT='${SMB_PORT}'
        export SMB_SHARE='${SMB_SHARE}'
        export SMB_USER='${SMB_USER}'
        export SMB_PASS='${SMB_PASS}'
        export SMB_CREDS='${SMB_CREDS}'
        export SMB_UNC='//${SMB_HOST}/${SMB_SHARE}'
        export SHARE_NAME='${SMB_SHARE}'
        export SHARE_ROOT='${SHARE_ROOT:-/srv/smb/test}'
        export VERBOSE='${VERBOSE}'

        # Source the category file that defines the function
        for f in '${TORTURE_DIR}'/categories/*.sh; do
            source \"\$f\" 2>/dev/null
        done

        # Call the test function
        $func
    " 2>&1)
    exit_code=$?
    elapsed_ms=$(( $(date +%s%3N) - start_ms ))

    # Classify result
    local status message
    if [[ $exit_code -eq 0 ]]; then
        status="PASS"
        message=""
    elif [[ $exit_code -eq 124 ]]; then
        status="FAIL"
        message="TIMEOUT after ${timeout}s"
    elif [[ $exit_code -eq 77 ]]; then
        status="SKIP"
        message="$(echo "$output" | tail -5)"
    else
        status="FAIL"
        message="$(echo "$output" | tail -20)"
    fi

    record_result "$test_id" "$status" "$elapsed_ms" "$message" "$output"
    print_test_result "$test_id" "$status" "$elapsed_ms" "$desc"

    case "$status" in
        PASS)  return 0 ;;
        FAIL)  return 1 ;;
        SKIP)  return 2 ;;
        CRASH) return 3 ;;
    esac
}

# ===========================================================================
# RESULT RECORDING
# ===========================================================================

record_result() {
    local id="$1" status="$2" duration="$3" message="$4" output="${5:-}"
    _RESULT_IDS+=("$id")
    _RESULT_STATUS["$id"]="$status"
    _RESULT_DURATION["$id"]="$duration"
    _RESULT_MESSAGE["$id"]="$message"
    _RESULT_OUTPUT["$id"]="$output"

    case "$status" in
        PASS)  ((TOTAL_PASS++))  || true ;;
        FAIL)  ((TOTAL_FAIL++))  || true ;;
        SKIP)  ((TOTAL_SKIP++))  || true ;;
        CRASH) ((TOTAL_CRASH++)) || true ;;
    esac
}

record_health_event() {
    local category="$1" description="$2"
    _HEALTH_EVENTS+=("${category}: ${description}")
}

# ===========================================================================
# CATEGORY EXECUTION
# ===========================================================================

run_category() {
    local category="$1"

    # Collect filtered tests for this category
    local filtered_ids=()
    for fid in "${_FILTERED_IDS[@]}"; do
        [[ "$fid" == "${category}."* ]] && filtered_ids+=("$fid")
    done
    [[ ${#filtered_ids[@]} -eq 0 ]] && return 0

    local cat_start_ms
    cat_start_ms=$(date +%s%3N)

    # Print category header
    if [[ "$TAP_OUTPUT" != "yes" ]]; then
        printf "\n${_C_BOLD}${_C_CYAN}  === %s ===${_C_RESET}\n" "$category"
    else
        echo "# === $category ==="
    fi

    # Snapshot health baseline
    local health_baseline=""
    if [[ "$NO_HEALTH_CHECK" != "yes" ]]; then
        health_baseline=$(health_snapshot 2>/dev/null || echo "")
    fi

    # Module restart between categories if requested
    if [[ "$RESTART_BETWEEN" == "yes" && "$NO_RESTART" != "yes" ]]; then
        log_info "Reloading ksmbd module before category $category..."
        vm_reload_ksmbd
    fi

    local cat_pass=0 cat_fail=0 cat_skip=0 cat_crash=0

    # Separate ordered and unordered tests
    local ordered_ids=() unordered_ids=()
    for id in "${filtered_ids[@]}"; do
        if [[ -n "${_TEST_AFTER[$id]:-}" ]]; then
            ordered_ids+=("$id")
        else
            unordered_ids+=("$id")
        fi
    done

    # Shuffle if requested
    if [[ "$SHUFFLE" == "yes" ]] && [[ ${#unordered_ids[@]} -gt 1 ]]; then
        local shuffled=()
        while IFS= read -r line; do
            [[ -n "$line" ]] && shuffled+=("$line")
        done < <(printf '%s\n' "${unordered_ids[@]}" | shuf 2>/dev/null || printf '%s\n' "${unordered_ids[@]}")
        unordered_ids=("${shuffled[@]}")
    fi

    # Execute unordered tests (parallel or sequential)
    if [[ "$PARALLEL_JOBS" -gt 1 ]] && [[ ${#unordered_ids[@]} -gt 1 ]]; then
        _run_parallel "$PARALLEL_JOBS" cat_pass cat_fail cat_skip cat_crash "${unordered_ids[@]}"
    else
        for id in "${unordered_ids[@]}"; do
            _run_with_retry "$id"
            local rc=$?
            case $rc in
                0) ((cat_pass++)) || true ;;
                1) ((cat_fail++)) || true ;;
                2) ((cat_skip++)) || true ;;
                3) ((cat_crash++)) || true ;;
            esac
        done
    fi

    # Execute ordered tests sequentially
    for id in "${ordered_ids[@]}"; do
        _run_with_retry "$id"
        local rc=$?
        case $rc in
            0) ((cat_pass++)) || true ;;
            1) ((cat_fail++)) || true ;;
            2) ((cat_skip++)) || true ;;
            3) ((cat_crash++)) || true ;;
        esac
    done

    # Post-category health check
    local health_status="OK"
    if [[ "$NO_HEALTH_CHECK" != "yes" && -n "$health_baseline" ]]; then
        health_status=$(health_check "$health_baseline" 2>/dev/null || echo "OK")
        if [[ "$health_status" != "OK" ]]; then
            record_health_event "$category" "$health_status"
            log_warn "Health check after $category: $health_status"
        fi
    fi

    # Record category stats
    local cat_duration=$(( $(date +%s%3N) - cat_start_ms ))
    _CATEGORIES_RUN+=("$category")
    _CATEGORY_PASS["$category"]=$cat_pass
    _CATEGORY_FAIL["$category"]=$cat_fail
    _CATEGORY_SKIP["$category"]=$cat_skip
    _CATEGORY_CRASH["$category"]=$cat_crash
    _CATEGORY_DURATION["$category"]=$cat_duration
    _CATEGORY_HEALTH["$category"]="$health_status"

    # Print category summary line
    _print_category_line "$category" "$cat_pass" "$cat_fail" "$cat_skip" \
        "$cat_crash" "$cat_duration" "$health_status"
}

# _run_with_retry ID -- Run test with optional retry on failure
_run_with_retry() {
    local id="$1"
    run_single_test "$id"
    local rc=$?

    if [[ $rc -eq 1 && "${RETRY_COUNT:-0}" -gt 0 ]]; then
        for ((r = 1; r <= RETRY_COUNT; r++)); do
            log_info "Retrying $id (attempt $r/$RETRY_COUNT)..."
            # Remove previous result counters (the record already happened)
            ((TOTAL_FAIL--)) || true

            run_single_test "$id"
            local retry_rc=$?
            if [[ $retry_rc -eq 0 ]]; then
                return 0
            fi
            # On continued failure, the extra TOTAL_FAIL from record_result
            # is correct (we already decremented once)
        done
        return 1
    fi

    return $rc
}

# ===========================================================================
# PARALLEL EXECUTION
# ===========================================================================

_run_parallel() {
    local max_jobs="$1"
    local pass_var="$2" fail_var="$3" skip_var="$4" crash_var="$5"
    shift 5

    local pids=()
    local result_dir
    result_dir=$(mktemp -d "/tmp/ksmbd-torture-parallel-XXXXXX")

    for test_id in "$@"; do
        local tags="${_TEST_TAGS[$test_id]:-}"

        # Never parallelize destructive tests
        if [[ "$tags" == *"destructive"* ]]; then
            for pid in "${pids[@]}"; do
                wait "$pid" 2>/dev/null || true
                _collect_parallel_result "$result_dir" "$pid" \
                    "$pass_var" "$fail_var" "$skip_var" "$crash_var"
            done
            pids=()

            _run_with_retry "$test_id"
            local rc=$?
            case $rc in
                0) eval "(($pass_var++)) || true" ;;
                1) eval "(($fail_var++)) || true" ;;
                2) eval "(($skip_var++)) || true" ;;
                3) eval "(($crash_var++)) || true" ;;
            esac
            continue
        fi

        # Wait if at max jobs
        while (( ${#pids[@]} >= max_jobs )); do
            wait -n 2>/dev/null || wait "${pids[0]}" 2>/dev/null || true
            local new_pids=()
            for p in "${pids[@]}"; do
                if kill -0 "$p" 2>/dev/null; then
                    new_pids+=("$p")
                else
                    _collect_parallel_result "$result_dir" "$p" \
                        "$pass_var" "$fail_var" "$skip_var" "$crash_var"
                fi
            done
            pids=("${new_pids[@]}")
        done

        # Launch in background
        (
            run_single_test "$test_id"
            echo $? > "$result_dir/$$"
        ) &
        pids+=($!)
    done

    # Wait for remaining
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
        _collect_parallel_result "$result_dir" "$pid" \
            "$pass_var" "$fail_var" "$skip_var" "$crash_var"
    done

    rm -rf "$result_dir"
}

_collect_parallel_result() {
    local dir="$1" pid="$2"
    local pass_var="$3" fail_var="$4" skip_var="$5" crash_var="$6"
    if [[ -f "$dir/$pid" ]]; then
        local rc
        rc=$(cat "$dir/$pid")
        case $rc in
            0) eval "(($pass_var++)) || true" ;;
            1) eval "(($fail_var++)) || true" ;;
            2) eval "(($skip_var++)) || true" ;;
            3) eval "(($crash_var++)) || true" ;;
        esac
    fi
}

# ===========================================================================
# SUITE EXECUTION
# ===========================================================================

# run_suite -- Execute the entire filtered test suite
run_suite() {
    SUITE_START_MS=$(date +%s%3N)
    _print_suite_header

    local all_cats
    all_cats=$(get_all_categories)

    for cat in $all_cats; do
        # Check if any filtered tests belong to this category
        local has_tests=0
        for fid in "${_FILTERED_IDS[@]}"; do
            [[ "$fid" == "${cat}."* ]] && { has_tests=1; break; }
        done
        [[ $has_tests -eq 0 ]] && continue
        run_category "$cat"
    done

    SUITE_DURATION_MS=$(( $(date +%s%3N) - SUITE_START_MS ))
    _print_suite_summary
}

# ===========================================================================
# OUTPUT FORMATTING
# ===========================================================================

_TAP_COUNTER=0

print_test_result() {
    local id="$1" status="$2" duration="$3" desc="$4"
    ((_TAP_COUNTER++)) || true

    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        case "$status" in
            PASS)  echo "ok $_TAP_COUNTER - $id $desc (${duration}ms)" ;;
            FAIL)  echo "not ok $_TAP_COUNTER - $id $desc (${duration}ms)" ;;
            SKIP)  echo "ok $_TAP_COUNTER - $id $desc # SKIP" ;;
            CRASH) echo "not ok $_TAP_COUNTER - $id $desc # CRASH" ;;
        esac
        return
    fi

    local color
    case "$status" in
        PASS)  color="$_C_GREEN"  ;;
        FAIL)  color="$_C_RED"    ;;
        SKIP)  color="$_C_YELLOW" ;;
        CRASH) color="$_C_RED"    ;;
    esac

    printf "  ${color}%-6s${_C_RESET} %-10s %-50s ${_C_DIM}(%dms)${_C_RESET}\n" \
        "$status" "$id" "${desc:0:50}" "$duration"

    # Verbose: print output on failure
    if [[ "$VERBOSE" == "yes" && "$status" == "FAIL" ]]; then
        local msg="${_RESULT_MESSAGE[$id]:-}"
        if [[ -n "$msg" ]]; then
            echo "$msg" | head -10 | sed 's/^/         | /'
        fi
    fi
}

_print_category_line() {
    local cat="$1" pass="$2" fail="$3" skip="$4" crash="$5"
    local duration="$6" health="$7"

    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "# $cat: pass=$pass fail=$fail skip=$skip crash=$crash (${duration}ms) health=$health"
        return
    fi

    printf "\n  ${_C_BOLD}--- %s ---${_C_RESET}" "$cat"
    printf " pass=${_C_GREEN}%d${_C_RESET}" "$pass"
    printf " fail=${_C_RED}%d${_C_RESET}" "$fail"
    [[ $skip -gt 0 ]] && printf " skip=${_C_YELLOW}%d${_C_RESET}" "$skip"
    [[ $crash -gt 0 ]] && printf " crash=${_C_RED}%d${_C_RESET}" "$crash"
    printf " ${_C_DIM}(%dms)${_C_RESET}" "$duration"
    local hc="$_C_GREEN"
    [[ "$health" != "OK" ]] && hc="$_C_YELLOW"
    printf " health=${hc}%s${_C_RESET}\n" "$health"
}

_print_suite_header() {
    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "TAP version 14"
        echo "1..${#_FILTERED_IDS[@]}"
        echo "# ksmbd-torture test suite"
        echo "# VM: ${VM_NAME} (${VM_HOST}:${SMB_PORT})"
        echo "# Tests: ${#_FILTERED_IDS[@]}"
        return
    fi

    printf "\n${_C_BOLD}${_C_CYAN}"
    printf "  ================================================================\n"
    printf "  ksmbd-torture -- Integration Test Suite\n"
    printf "  ================================================================${_C_RESET}\n"
    printf "  VM: ${_C_BOLD}%s${_C_RESET} (%s:%s)\n" "$VM_NAME" "$VM_HOST" "$SMB_PORT"
    printf "  Tests: %d" "${#_FILTERED_IDS[@]}"
    [[ "$PARALLEL_JOBS" -gt 1 ]] && printf " (parallel: %d)" "$PARALLEL_JOBS"
    printf "\n"
}

_print_suite_summary() {
    local total=$(( TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP + TOTAL_CRASH ))
    local duration_s=$(( SUITE_DURATION_MS / 1000 ))
    local duration_ms=$(( SUITE_DURATION_MS % 1000 ))

    if [[ "$TAP_OUTPUT" == "yes" ]]; then
        echo "# Total: $total  Pass: $TOTAL_PASS  Fail: $TOTAL_FAIL  Skip: $TOTAL_SKIP  Crash: $TOTAL_CRASH"
        echo "# Duration: ${duration_s}.${duration_ms}s"
        return
    fi

    printf "\n${_C_BOLD}${_C_CYAN}"
    printf "  ================================================================\n"
    printf "  RESULTS\n"
    printf "  ================================================================${_C_RESET}\n\n"

    # Per-category table
    printf "  %-10s %6s %6s %6s %6s %10s %8s\n" \
        "CATEGORY" "PASS" "FAIL" "SKIP" "CRASH" "TIME(ms)" "HEALTH"
    printf "  %-10s %6s %6s %6s %6s %10s %8s\n" \
        "--------" "----" "----" "----" "-----" "--------" "------"

    for cat in "${_CATEGORIES_RUN[@]}"; do
        local p="${_CATEGORY_PASS[$cat]:-0}"
        local f="${_CATEGORY_FAIL[$cat]:-0}"
        local s="${_CATEGORY_SKIP[$cat]:-0}"
        local c="${_CATEGORY_CRASH[$cat]:-0}"
        local d="${_CATEGORY_DURATION[$cat]:-0}"
        local h="${_CATEGORY_HEALTH[$cat]:-OK}"

        local fc="" hc="" r="$_C_RESET"
        [[ $f -gt 0 ]] && fc="$_C_RED"
        [[ "$h" != "OK" ]] && hc="$_C_YELLOW"

        printf "  %-10s ${_C_GREEN}%6d${r} ${fc}%6d${r} ${_C_YELLOW}%6d${r} %6d %10d ${hc}%8s${r}\n" \
            "$cat" "$p" "$f" "$s" "$c" "$d" "$h"
    done

    # Totals
    printf "\n  ${_C_BOLD}%-10s${_C_RESET}" "TOTAL"
    printf " ${_C_GREEN}%6d${_C_RESET}" "$TOTAL_PASS"
    printf " ${_C_RED}%6d${_C_RESET}" "$TOTAL_FAIL"
    printf " ${_C_YELLOW}%6d${_C_RESET}" "$TOTAL_SKIP"
    printf " %6d %10d\n" "$TOTAL_CRASH" "$SUITE_DURATION_MS"
    printf "\n  Duration: ${_C_BOLD}%d.%03ds${_C_RESET}\n" "$duration_s" "$duration_ms"

    # Health events
    if [[ ${#_HEALTH_EVENTS[@]} -gt 0 ]]; then
        printf "\n  ${_C_YELLOW}${_C_BOLD}Health Events:${_C_RESET}\n"
        for evt in "${_HEALTH_EVENTS[@]}"; do
            printf "    ${_C_YELLOW}! %s${_C_RESET}\n" "$evt"
        done
    fi

    # Failed tests detail
    if [[ $TOTAL_FAIL -gt 0 || $TOTAL_CRASH -gt 0 ]]; then
        printf "\n  ${_C_RED}${_C_BOLD}Failed Tests:${_C_RESET}\n"
        for id in "${_RESULT_IDS[@]}"; do
            local st="${_RESULT_STATUS[$id]}"
            [[ "$st" != "FAIL" && "$st" != "CRASH" ]] && continue
            printf "    ${_C_RED}%s${_C_RESET}: %s\n" "$id" "${_RESULT_MESSAGE[$id]:0:80}"
        done
    fi

    # Verdict
    printf "\n  "
    if [[ $TOTAL_CRASH -gt 0 ]]; then
        printf "${_C_RED}${_C_BOLD}SERVER CRASH DETECTED${_C_RESET}\n"
    elif [[ $TOTAL_FAIL -gt 0 ]]; then
        printf "${_C_RED}${_C_BOLD}FAILURES DETECTED${_C_RESET}\n"
    else
        printf "${_C_GREEN}${_C_BOLD}ALL TESTS PASSED${_C_RESET}\n"
    fi
    printf "\n"
}

# ===========================================================================
# EXIT CODE
# ===========================================================================

get_exit_code() {
    if [[ $TOTAL_CRASH -gt 0 ]]; then
        echo 2
    elif [[ $TOTAL_FAIL -gt 0 ]]; then
        echo 1
    else
        echo 0
    fi
}
