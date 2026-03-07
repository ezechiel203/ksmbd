#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# collect_coverage.sh -- Collect gcov data and generate lcov/HTML reports
#
# This script supports two modes:
#   1. UML/kunit.py mode: Extracts gcov data from the UML build tree
#      (after kunit.py run). This is the primary workflow.
#   2. Real hardware mode: Reads gcov data from /sys/kernel/debug/gcov/
#      on a running system with ksmbd loaded (requires root).
#
# Usage:
#   ./test/coverage/collect_coverage.sh [OPTIONS]
#
# Options:
#   --output-dir DIR          Output directory (default: test/coverage/output)
#   --linux-src DIR           Kernel source tree (for UML/kunit.py mode)
#   --min-line-coverage N     Fail if line coverage is below N percent
#   --min-func-coverage N     Fail if function coverage is below N percent
#   --min-branch-coverage N   Fail if branch coverage is below N percent
#   --gcov-dir DIR            Override gcov sysfs path (default: auto-detect)
#   --branch-coverage         Enable branch coverage tracking
#   --keep-intermediates      Do not remove intermediate .info files
#   --help                    Show this help message
#
# Exit codes:
#   0 - Success (thresholds met if specified)
#   1 - Error (prerequisites missing, lcov failure, etc.)
#   2 - Coverage threshold not met

set -u

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

OUTPUT_DIR="${SCRIPT_DIR}/output"
LINUX_SRC=""
GCOV_DIR=""
MIN_LINE_COV=""
MIN_FUNC_COV=""
MIN_BRANCH_COV=""
BRANCH_COVERAGE=0
KEEP_INTERMEDIATES=0

# Coverage data files
RAW_INFO="ksmbd_coverage_raw.info"
KSMBD_INFO="ksmbd_coverage.info"
FINAL_INFO="ksmbd_final.info"

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_GREEN='\033[0;32m'
    C_RED='\033[0;31m'
    C_YELLOW='\033[0;33m'
    C_CYAN='\033[0;36m'
    C_BOLD='\033[1m'
    C_RESET='\033[0m'
else
    C_GREEN='' C_RED='' C_YELLOW='' C_CYAN='' C_BOLD='' C_RESET=''
fi

info()  { printf "${C_CYAN}[INFO]${C_RESET} %s\n" "$1"; }
ok()    { printf "${C_GREEN}[OK]${C_RESET}   %s\n" "$1"; }
warn()  { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$1"; }
err()   { printf "${C_RED}[ERR]${C_RESET}  %s\n" "$1" >&2; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'USAGE_EOF'
Usage: ./test/coverage/collect_coverage.sh [OPTIONS]

Options:
  --output-dir DIR          Output directory (default: test/coverage/output)
  --linux-src DIR           Kernel source tree (for UML/kunit.py mode)
  --min-line-coverage N     Fail if line coverage is below N percent
  --min-func-coverage N     Fail if function coverage is below N percent
  --min-branch-coverage N   Fail if branch coverage is below N percent
  --gcov-dir DIR            Override gcov data directory
  --branch-coverage         Enable branch coverage tracking
  --keep-intermediates      Keep intermediate .info files
  --help                    Show this help

Examples:
  # After kunit.py run (UML mode):
  ./test/coverage/collect_coverage.sh --linux-src /path/to/linux

  # On real hardware with ksmbd loaded:
  sudo ./test/coverage/collect_coverage.sh

  # With threshold enforcement:
  ./test/coverage/collect_coverage.sh --linux-src /path/to/linux \
      --min-line-coverage 30 --min-func-coverage 20
USAGE_EOF
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir)
            OUTPUT_DIR="$2"; shift 2 ;;
        --linux-src)
            LINUX_SRC="$2"; shift 2 ;;
        --min-line-coverage)
            MIN_LINE_COV="$2"; shift 2 ;;
        --min-func-coverage)
            MIN_FUNC_COV="$2"; shift 2 ;;
        --min-branch-coverage)
            MIN_BRANCH_COV="$2"; shift 2 ;;
        --gcov-dir)
            GCOV_DIR="$2"; shift 2 ;;
        --branch-coverage)
            BRANCH_COVERAGE=1; shift ;;
        --keep-intermediates)
            KEEP_INTERMEDIATES=1; shift ;;
        --help|-h)
            usage; exit 0 ;;
        *)
            err "Unknown option: $1"
            usage >&2
            exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
check_prerequisites() {
    local missing=0

    if ! command -v lcov >/dev/null 2>&1; then
        err "lcov is not installed."
        err "Install with: sudo apt-get install lcov  (Debian/Ubuntu)"
        err "              sudo pacman -S lcov          (Arch)"
        err "              sudo dnf install lcov         (Fedora)"
        missing=1
    fi

    if ! command -v genhtml >/dev/null 2>&1; then
        err "genhtml is not installed (usually part of the lcov package)."
        missing=1
    fi

    if ! command -v gcov >/dev/null 2>&1; then
        warn "gcov not found in PATH. lcov may fail to process .gcda files."
        warn "Install with: sudo apt-get install gcc  (usually bundled with gcc)"
    fi

    if [ $missing -ne 0 ]; then
        err "Prerequisites not met. Please install the missing tools."
        exit 1
    fi

    ok "Prerequisites satisfied (lcov, genhtml)"
}

# ---------------------------------------------------------------------------
# Detect gcov data source
# ---------------------------------------------------------------------------
detect_gcov_source() {
    # Priority 1: Explicit --gcov-dir
    if [ -n "$GCOV_DIR" ]; then
        if [ ! -d "$GCOV_DIR" ]; then
            err "Specified gcov directory does not exist: $GCOV_DIR"
            exit 1
        fi
        info "Using explicit gcov directory: $GCOV_DIR"
        return 0
    fi

    # Priority 2: UML/kunit.py build tree
    if [ -n "$LINUX_SRC" ]; then
        # kunit.py builds under .kunit/ by default
        local kunit_build_dir="$LINUX_SRC/.kunit"
        if [ -d "$kunit_build_dir" ]; then
            GCOV_DIR="$kunit_build_dir"
            info "Using kunit.py build tree: $GCOV_DIR"
            return 0
        fi

        # Fallback: standard kernel build directory
        if [ -d "$LINUX_SRC" ]; then
            GCOV_DIR="$LINUX_SRC"
            info "Using kernel source tree: $GCOV_DIR"
            return 0
        fi

        err "LINUX_SRC=$LINUX_SRC does not contain a .kunit/ build directory."
        err "Run 'make -f test/coverage/Makefile coverage-run' first."
        exit 1
    fi

    # Priority 3: sysfs gcov (real hardware, requires root)
    local sysfs_gcov="/sys/kernel/debug/gcov"
    if [ -d "$sysfs_gcov" ]; then
        GCOV_DIR="$sysfs_gcov"
        info "Using sysfs gcov: $GCOV_DIR"
        return 0
    fi

    err "No gcov data source found."
    err "Options:"
    err "  1. Set --linux-src /path/to/linux (after kunit.py run)"
    err "  2. Mount debugfs and load ksmbd with gcov kernel (requires root)"
    err "  3. Set --gcov-dir to a directory containing .gcda/.gcno files"
    exit 1
}

# ---------------------------------------------------------------------------
# Reset gcov counters (sysfs mode only)
# ---------------------------------------------------------------------------
reset_gcov_counters() {
    if [ "$GCOV_DIR" = "/sys/kernel/debug/gcov" ]; then
        info "Resetting gcov counters..."
        if command -v lcov >/dev/null 2>&1; then
            lcov --zerocounters --directory "$GCOV_DIR" 2>/dev/null || true
        fi
        # Alternative: echo to reset file
        if [ -f "$GCOV_DIR/reset" ]; then
            echo 1 > "$GCOV_DIR/reset" 2>/dev/null || true
        fi
        ok "Counters reset"
    fi
}

# ---------------------------------------------------------------------------
# Capture coverage data
# ---------------------------------------------------------------------------
capture_coverage() {
    info "Capturing coverage data from $GCOV_DIR..."
    mkdir -p "$OUTPUT_DIR"

    local lcov_opts="--capture"
    lcov_opts="$lcov_opts --directory $GCOV_DIR"
    lcov_opts="$lcov_opts --output-file $OUTPUT_DIR/$RAW_INFO"

    # For UML/kunit.py builds, we need to specify the gcov tool
    # kunit.py UML builds use the host's gcc, so the default gcov works
    if [ -n "$LINUX_SRC" ]; then
        lcov_opts="$lcov_opts --base-directory $LINUX_SRC"
    fi

    if [ $BRANCH_COVERAGE -eq 1 ]; then
        lcov_opts="$lcov_opts --rc lcov_branch_coverage=1"
    fi

    # Ignore errors from files that gcov cannot process (e.g., asm files)
    lcov_opts="$lcov_opts --ignore-errors source,gcov"

    # shellcheck disable=SC2086
    if ! lcov $lcov_opts 2>"$OUTPUT_DIR/lcov_capture.log"; then
        err "lcov capture failed. Check $OUTPUT_DIR/lcov_capture.log"
        exit 1
    fi

    if [ ! -s "$OUTPUT_DIR/$RAW_INFO" ]; then
        err "No coverage data captured. Possible causes:"
        err "  - ksmbd was not built with gcov instrumentation"
        err "  - KUnit tests did not run (check coverage-run output)"
        err "  - gcov data directory is incorrect"
        exit 1
    fi

    ok "Raw coverage data captured ($OUTPUT_DIR/$RAW_INFO)"
}

# ---------------------------------------------------------------------------
# Filter to ksmbd source only
# ---------------------------------------------------------------------------
filter_coverage() {
    info "Filtering coverage data to ksmbd source files..."

    local lcov_opts=""
    if [ $BRANCH_COVERAGE -eq 1 ]; then
        lcov_opts="--rc lcov_branch_coverage=1"
    fi

    # Extract only ksmbd-related files
    # The paths may vary depending on in-tree vs. external build:
    #   In-tree: */fs/ksmbd/*
    #   External: */<repo-root>/*
    # We use multiple patterns to catch both.
    # shellcheck disable=SC2086
    lcov --extract "$OUTPUT_DIR/$RAW_INFO" \
        '*/ksmbd/*.c' \
        '*/ksmbd/mgmt/*.c' \
        $lcov_opts \
        --output-file "$OUTPUT_DIR/$KSMBD_INFO" \
        2>>"$OUTPUT_DIR/lcov_capture.log" || true

    # If the broad filter caught nothing, try the repo path directly
    if [ ! -s "$OUTPUT_DIR/$KSMBD_INFO" ]; then
        warn "No files matched '*/ksmbd/*.c'; trying repo root path..."
        # shellcheck disable=SC2086
        lcov --extract "$OUTPUT_DIR/$RAW_INFO" \
            "${REPO_ROOT}/*.c" \
            "${REPO_ROOT}/mgmt/*.c" \
            $lcov_opts \
            --output-file "$OUTPUT_DIR/$KSMBD_INFO" \
            2>>"$OUTPUT_DIR/lcov_capture.log" || true
    fi

    if [ ! -s "$OUTPUT_DIR/$KSMBD_INFO" ]; then
        warn "Filter found no ksmbd source files. Using full data set."
        cp "$OUTPUT_DIR/$RAW_INFO" "$OUTPUT_DIR/$KSMBD_INFO"
    fi

    # Remove test files from the coverage report -- we want production code only
    # shellcheck disable=SC2086
    lcov --remove "$OUTPUT_DIR/$KSMBD_INFO" \
        '*/test/*' \
        '*/ksmbd_test_*' \
        '*/fuzz/*' \
        '*_fuzz.c' \
        $lcov_opts \
        --output-file "$OUTPUT_DIR/$FINAL_INFO" \
        2>>"$OUTPUT_DIR/lcov_capture.log" || true

    if [ ! -s "$OUTPUT_DIR/$FINAL_INFO" ]; then
        warn "Removal filter emptied the data. Using pre-filter data."
        cp "$OUTPUT_DIR/$KSMBD_INFO" "$OUTPUT_DIR/$FINAL_INFO"
    fi

    ok "Filtered to ksmbd production source ($OUTPUT_DIR/$FINAL_INFO)"
}

# ---------------------------------------------------------------------------
# Generate HTML report
# ---------------------------------------------------------------------------
generate_html() {
    info "Generating HTML report..."

    local html_dir="$OUTPUT_DIR/coverage_html"
    rm -rf "$html_dir"

    local genhtml_opts=""
    genhtml_opts="$genhtml_opts --output-directory $html_dir"
    genhtml_opts="$genhtml_opts --title 'ksmbd Code Coverage'"
    genhtml_opts="$genhtml_opts --legend"
    genhtml_opts="$genhtml_opts --show-details"
    genhtml_opts="$genhtml_opts --sort"
    genhtml_opts="$genhtml_opts --prefix $REPO_ROOT"

    if [ $BRANCH_COVERAGE -eq 1 ]; then
        genhtml_opts="$genhtml_opts --branch-coverage"
        genhtml_opts="$genhtml_opts --rc lcov_branch_coverage=1"
    fi

    # shellcheck disable=SC2086
    if ! genhtml $genhtml_opts "$OUTPUT_DIR/$FINAL_INFO" \
            2>"$OUTPUT_DIR/genhtml.log"; then
        err "genhtml failed. Check $OUTPUT_DIR/genhtml.log"
        exit 1
    fi

    ok "HTML report generated at $html_dir/index.html"
}

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
print_summary() {
    info "Coverage Summary"
    echo "=================================================================="

    if [ ! -f "$OUTPUT_DIR/$FINAL_INFO" ]; then
        err "No coverage info file found."
        return
    fi

    local summary
    local lcov_opts=""
    if [ $BRANCH_COVERAGE -eq 1 ]; then
        lcov_opts="--rc lcov_branch_coverage=1"
    fi

    # shellcheck disable=SC2086
    summary=$(lcov --summary "$OUTPUT_DIR/$FINAL_INFO" $lcov_opts 2>&1)

    # Extract percentages
    local line_pct func_pct branch_pct
    line_pct=$(echo "$summary" | grep -oP 'lines\.*:\s*\K[0-9.]+' || echo "N/A")
    func_pct=$(echo "$summary" | grep -oP 'functions\.*:\s*\K[0-9.]+' || echo "N/A")
    branch_pct=$(echo "$summary" | grep -oP 'branches\.*:\s*\K[0-9.]+' || echo "N/A")

    # Extract counts
    local lines_hit lines_total funcs_hit funcs_total
    lines_hit=$(echo "$summary" | grep -oP 'lines\.*:.*\(\K[0-9]+(?= of)' || echo "?")
    lines_total=$(echo "$summary" | grep -oP 'lines\.*:.*of \K[0-9]+' || echo "?")
    funcs_hit=$(echo "$summary" | grep -oP 'functions\.*:.*\(\K[0-9]+(?= of)' || echo "?")
    funcs_total=$(echo "$summary" | grep -oP 'functions\.*:.*of \K[0-9]+' || echo "?")

    printf "  %-20s %6s%%  (%s of %s)\n" "Line coverage:" "$line_pct" "$lines_hit" "$lines_total"
    printf "  %-20s %6s%%  (%s of %s)\n" "Function coverage:" "$func_pct" "$funcs_hit" "$funcs_total"
    if [ $BRANCH_COVERAGE -eq 1 ]; then
        local branches_hit branches_total
        branches_hit=$(echo "$summary" | grep -oP 'branches\.*:.*\(\K[0-9]+(?= of)' || echo "?")
        branches_total=$(echo "$summary" | grep -oP 'branches\.*:.*of \K[0-9]+' || echo "?")
        printf "  %-20s %6s%%  (%s of %s)\n" "Branch coverage:" "$branch_pct" "$branches_hit" "$branches_total"
    fi
    echo "=================================================================="
    echo ""
    echo "  HTML report: $OUTPUT_DIR/coverage_html/index.html"
    echo "  Raw data:    $OUTPUT_DIR/$FINAL_INFO"
    echo ""
}

# ---------------------------------------------------------------------------
# Check coverage thresholds
# ---------------------------------------------------------------------------
check_thresholds() {
    local failed=0

    if [ ! -f "$OUTPUT_DIR/$FINAL_INFO" ]; then
        return 0
    fi

    local lcov_opts=""
    if [ $BRANCH_COVERAGE -eq 1 ]; then
        lcov_opts="--rc lcov_branch_coverage=1"
    fi

    # shellcheck disable=SC2086
    local summary
    summary=$(lcov --summary "$OUTPUT_DIR/$FINAL_INFO" $lcov_opts 2>&1)

    if [ -n "$MIN_LINE_COV" ]; then
        local line_pct
        line_pct=$(echo "$summary" | grep -oP 'lines\.*:\s*\K[0-9.]+' || echo "0")
        # Compare using bc or awk for floating point
        if awk "BEGIN {exit !($line_pct < $MIN_LINE_COV)}"; then
            err "Line coverage ${line_pct}% is below threshold ${MIN_LINE_COV}%"
            failed=1
        else
            ok "Line coverage ${line_pct}% meets threshold ${MIN_LINE_COV}%"
        fi
    fi

    if [ -n "$MIN_FUNC_COV" ]; then
        local func_pct
        func_pct=$(echo "$summary" | grep -oP 'functions\.*:\s*\K[0-9.]+' || echo "0")
        if awk "BEGIN {exit !($func_pct < $MIN_FUNC_COV)}"; then
            err "Function coverage ${func_pct}% is below threshold ${MIN_FUNC_COV}%"
            failed=1
        else
            ok "Function coverage ${func_pct}% meets threshold ${MIN_FUNC_COV}%"
        fi
    fi

    if [ -n "$MIN_BRANCH_COV" ] && [ $BRANCH_COVERAGE -eq 1 ]; then
        local branch_pct
        branch_pct=$(echo "$summary" | grep -oP 'branches\.*:\s*\K[0-9.]+' || echo "0")
        if awk "BEGIN {exit !($branch_pct < $MIN_BRANCH_COV)}"; then
            err "Branch coverage ${branch_pct}% is below threshold ${MIN_BRANCH_COV}%"
            failed=1
        else
            ok "Branch coverage ${branch_pct}% meets threshold ${MIN_BRANCH_COV}%"
        fi
    fi

    if [ $failed -ne 0 ]; then
        err "Coverage threshold check FAILED"
        exit 2
    fi
}

# ---------------------------------------------------------------------------
# Cleanup intermediates
# ---------------------------------------------------------------------------
cleanup_intermediates() {
    if [ $KEEP_INTERMEDIATES -eq 0 ]; then
        rm -f "$OUTPUT_DIR/$RAW_INFO" "$OUTPUT_DIR/$KSMBD_INFO"
        info "Intermediate files removed (use --keep-intermediates to keep)"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    echo ""
    printf "${C_BOLD}ksmbd Code Coverage Report Generator${C_RESET}\n"
    echo "=================================================================="
    echo ""

    check_prerequisites
    detect_gcov_source
    capture_coverage
    filter_coverage
    generate_html
    print_summary
    check_thresholds
    cleanup_intermediates

    echo ""
    ok "Coverage collection complete."
}

main
