#!/bin/bash
# lib/reporting.sh -- TAP output, JSON results, HTML summary generation
#
# Provides structured output for CI pipelines (JSON/TAP) and human-readable
# summaries for interactive use.
#
# JSON output requires NO external dependencies (no jq) -- we emit JSON
# using bash string operations.

# ---------------------------------------------------------------------------
# JSON Output (no jq dependency)
# ---------------------------------------------------------------------------

# json_escape STRING -- Escape a string for JSON embedding
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"       # backslash
    s="${s//\"/\\\"}"       # double quote
    s="${s//$'\n'/\\n}"     # newline
    s="${s//$'\r'/\\r}"     # carriage return
    s="${s//$'\t'/\\t}"     # tab
    # Remove control characters
    s=$(printf '%s' "$s" | tr -d '\000-\011\013\014\016-\037')
    echo -n "$s"
}

# json_string KEY VALUE -- Emit "key": "value"
json_string() {
    printf '"%s": "%s"' "$1" "$(json_escape "$2")"
}

# json_number KEY VALUE -- Emit "key": value (numeric)
json_number() {
    printf '"%s": %s' "$1" "${2:-0}"
}

# json_bool KEY VALUE -- Emit "key": true/false
json_bool() {
    local val="false"
    [[ "$2" == "true" || "$2" == "1" || "$2" == "yes" ]] && val="true"
    printf '"%s": %s' "$1" "$val"
}

# ---------------------------------------------------------------------------
# Full JSON Report Generation
# ---------------------------------------------------------------------------

# generate_json_report OUTPUT_FILE -- Write complete JSON results file
# Uses global state from the framework (RESULT_*, CATEGORY_*, etc.)
generate_json_report() {
    local output_file="$1"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local kernel_version
    kernel_version=$(vm_kernel_version 2>/dev/null || echo "unknown")

    local ksmbd_version
    ksmbd_version=$(vm_ksmbd_version 2>/dev/null || echo "unknown")

    local total=$(( TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP + TOTAL_CRASH ))

    {
        echo "{"
        echo "  $(json_string "suite" "ksmbd-torture"),"
        echo "  $(json_string "version" "1.0.0"),"
        echo "  $(json_string "timestamp" "$timestamp"),"
        echo "  $(json_string "vm" "${VM_NAME:-VM3}"),"
        echo "  $(json_string "server_version" "ksmbd $ksmbd_version"),"
        echo "  $(json_string "kernel_version" "$kernel_version"),"
        echo "  $(json_number "duration_ms" "$SUITE_DURATION_MS"),"

        # Summary
        echo "  \"summary\": {"
        echo "    $(json_number "total" "$total"),"
        echo "    $(json_number "pass" "$TOTAL_PASS"),"
        echo "    $(json_number "fail" "$TOTAL_FAIL"),"
        echo "    $(json_number "skip" "$TOTAL_SKIP"),"
        echo "    $(json_number "crash" "$TOTAL_CRASH")"
        echo "  },"

        # Categories
        echo "  \"categories\": ["
        local cat_idx=0
        for cat in "${_CATEGORIES_RUN[@]}"; do
            [[ $cat_idx -gt 0 ]] && echo "    ,"
            ((cat_idx++))
            echo "    {"
            echo "      $(json_string "id" "$cat"),"
            echo "      $(json_number "duration_ms" "${_CATEGORY_DURATION[$cat]:-0}"),"
            echo "      $(json_number "pass" "${_CATEGORY_PASS[$cat]:-0}"),"
            echo "      $(json_number "fail" "${_CATEGORY_FAIL[$cat]:-0}"),"
            echo "      $(json_number "skip" "${_CATEGORY_SKIP[$cat]:-0}"),"
            echo "      $(json_number "crash" "${_CATEGORY_CRASH[$cat]:-0}"),"
            echo "      $(json_string "health" "${_CATEGORY_HEALTH[$cat]:-OK}"),"

            # Tests in this category
            echo "      \"tests\": ["
            local test_idx=0
            for id in "${_RESULT_IDS[@]}"; do
                local id_cat="${id%%.*}"
                [[ "$id_cat" != "$cat" ]] && continue
                [[ $test_idx -gt 0 ]] && echo "        ,"
                ((test_idx++))

                local func="${_TEST_FUNCS[$id]:-unknown}"
                local status="${_RESULT_STATUS[$id]:-SKIP}"
                local duration="${_RESULT_DURATION[$id]:-0}"
                local message="${_RESULT_MESSAGE[$id]:-}"

                echo "        {"
                echo "          $(json_string "id" "$id"),"
                echo "          $(json_string "name" "$func"),"
                echo "          $(json_string "status" "$status"),"
                echo "          $(json_number "duration_ms" "$duration"),"
                echo "          $(json_string "message" "$message")"
                echo "        }"
            done
            echo "      ]"
            echo "    }"
        done
        echo "  ],"

        # Health events
        echo "  \"health_events\": ["
        local evt_idx=0
        for evt in "${_HEALTH_EVENTS[@]}"; do
            [[ $evt_idx -gt 0 ]] && echo "    ,"
            ((evt_idx++))
            echo "    \"$(json_escape "$evt")\""
        done
        echo "  ]"

        echo "}"
    } > "$output_file"
}

# ---------------------------------------------------------------------------
# TAP Output
# ---------------------------------------------------------------------------

_TAP_TEST_NUM=0

# tap_header TOTAL -- Print TAP version and plan
tap_header() {
    local total="$1"
    echo "TAP version 14"
    echo "1..$total"
}

# tap_ok ID DESC [DURATION_MS] -- Print TAP ok line
tap_ok() {
    local id="$1" desc="$2" duration="${3:-}"
    ((_TAP_TEST_NUM++))
    if [[ -n "$duration" ]]; then
        echo "ok $_TAP_TEST_NUM - $id $desc (${duration}ms)"
    else
        echo "ok $_TAP_TEST_NUM - $id $desc"
    fi
}

# tap_not_ok ID DESC [MESSAGE] -- Print TAP not ok line
tap_not_ok() {
    local id="$1" desc="$2" message="${3:-}"
    ((_TAP_TEST_NUM++))
    echo "not ok $_TAP_TEST_NUM - $id $desc"
    if [[ -n "$message" ]]; then
        # TAP YAML diagnostic block
        echo "  ---"
        echo "  message: |"
        echo "$message" | head -10 | sed 's/^/    /'
        echo "  ..."
    fi
}

# tap_skip ID DESC REASON -- Print TAP skip directive
tap_skip() {
    local id="$1" desc="$2" reason="${3:-}"
    ((_TAP_TEST_NUM++))
    echo "ok $_TAP_TEST_NUM - $id $desc # SKIP ${reason}"
}

# tap_comment TEXT -- Print TAP comment
tap_comment() {
    echo "# $*"
}

# tap_bail_out REASON -- Print TAP bail out (abort)
tap_bail_out() {
    echo "Bail out! $*"
}

# ---------------------------------------------------------------------------
# TAP Report Generation (from framework state)
# ---------------------------------------------------------------------------

# generate_tap_report -- Print TAP output to stdout using framework state
generate_tap_report() {
    local total=${#_RESULT_IDS[@]}
    tap_header "$total"
    tap_comment "ksmbd-torture test suite"
    tap_comment "VM: ${VM_NAME:-VM3} (${VM_HOST}:${SMB_PORT})"

    _TAP_TEST_NUM=0
    for id in "${_RESULT_IDS[@]}"; do
        local status="${_RESULT_STATUS[$id]:-SKIP}"
        local desc="${_TEST_DESCRIPTIONS[$id]:-${_TEST_FUNCS[$id]:-unknown}}"
        local duration="${_RESULT_DURATION[$id]:-0}"
        local message="${_RESULT_MESSAGE[$id]:-}"

        case "$status" in
            PASS)  tap_ok "$id" "$desc" "$duration" ;;
            FAIL)  tap_not_ok "$id" "$desc" "$message" ;;
            SKIP)  tap_skip "$id" "$desc" "$message" ;;
            CRASH) tap_not_ok "$id" "$desc (CRASH)" "$message" ;;
        esac
    done

    tap_comment ""
    tap_comment "Total: $total  Pass: $TOTAL_PASS  Fail: $TOTAL_FAIL  Skip: $TOTAL_SKIP  Crash: $TOTAL_CRASH"
    tap_comment "Duration: $(( SUITE_DURATION_MS / 1000 )).$(( SUITE_DURATION_MS % 1000 ))s"
}

# ---------------------------------------------------------------------------
# Human-Readable Failed Test Report
# ---------------------------------------------------------------------------

# generate_failure_report -- Print details of failed tests
generate_failure_report() {
    if [[ $TOTAL_FAIL -eq 0 && $TOTAL_CRASH -eq 0 ]]; then
        return 0
    fi

    echo ""
    echo "=== FAILED TESTS ==="
    echo ""

    for id in "${_RESULT_IDS[@]}"; do
        local status="${_RESULT_STATUS[$id]:-SKIP}"
        [[ "$status" != "FAIL" && "$status" != "CRASH" ]] && continue

        local desc="${_TEST_DESCRIPTIONS[$id]:-${_TEST_FUNCS[$id]:-unknown}}"
        local message="${_RESULT_MESSAGE[$id]:-}"
        local duration="${_RESULT_DURATION[$id]:-0}"

        echo "--- $id: $desc ---"
        echo "  Status:   $status"
        echo "  Duration: ${duration}ms"
        if [[ -n "$message" ]]; then
            echo "  Output:"
            echo "$message" | head -20 | sed 's/^/    /'
        fi
        echo ""
    done
}

# ---------------------------------------------------------------------------
# Result File Management
# ---------------------------------------------------------------------------

# setup_results_dir -- Create results directory and symlink structure
setup_results_dir() {
    local results_dir="${TORTURE_DIR}/results"
    mkdir -p "$results_dir"

    # Generate timestamped filename
    local ts
    ts=$(date +"%Y-%m-%d_%H%M%S")
    RESULTS_JSON="${results_dir}/${ts}.json"
    RESULTS_LOG="${results_dir}/${ts}.log"
    RESULTS_LATEST="${results_dir}/latest.json"
    RESULTS_LATEST_LOG="${results_dir}/latest.log"
}

# finalize_results -- Write JSON, update latest symlink
finalize_results() {
    if [[ -n "${JSON_OUTPUT_FILE:-}" ]]; then
        generate_json_report "$JSON_OUTPUT_FILE"
    elif [[ -n "${RESULTS_JSON:-}" ]]; then
        generate_json_report "$RESULTS_JSON"
        # Update latest symlink
        ln -sf "$(basename "$RESULTS_JSON")" "${RESULTS_LATEST:-}"
    fi
}
