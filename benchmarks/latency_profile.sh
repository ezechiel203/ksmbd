#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Latency profiling for ksmbd hot paths using perf
#
# Profiles specific SMB operations to identify bottlenecks.
# Measures wall-clock time, operation latency, and optionally captures
# perf flamegraph-compatible data and ftrace function timing.
#
# Prerequisites:
#   - perf (linux-tools-$(uname -r))
#   - fio (>= 3.0)
#   - Root privileges (for perf record)
#   - A mounted SMB share (ksmbd)
#
# Usage:
#   sudo ./latency_profile.sh --mount /mnt/ksmbd_test [--duration 30]

set -e
set -u

# ---------------------------------------------------------------------------
# Color definitions
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MOUNT_POINT=""
DURATION=30
OUTPUT_DIR=""
SKIP_PERF=0
FIO_DIR=""
TEMP_DIR=""

# ksmbd kernel functions to trace (if ftrace is available)
KSMBD_FUNCTIONS=(
    "smb2_open"
    "smb2_read"
    "smb2_write"
    "smb2_close"
    "smb2_negotiate"
    "smb2_sess_setup"
    "ksmbd_vfs_read"
    "ksmbd_vfs_write"
    "ksmbd_conn_handler_loop"
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
${BOLD}Usage:${NC} sudo $(basename "$0") --mount PATH [OPTIONS]

${BOLD}Latency profiling for ksmbd hot paths using perf${NC}

Profiles specific SMB operations to identify performance bottlenecks.
Captures perf data, flamegraph-compatible output, and ftrace timing.

${BOLD}Required:${NC}
  --mount PATH          Mount point of the SMB share to profile

${BOLD}Options:${NC}
  --duration SECS       How long to profile each operation (default: 30)
  --output-dir DIR      Directory for perf.data and reports (default: profile_TIMESTAMP/)
  --skip-perf           Just measure wall-clock time without perf recording
  --help                Show this help message

${BOLD}Profiled operations:${NC}
  1. SMB2_READ     - Sequential read of a large file
  2. SMB2_WRITE    - Sequential write of a large file
  3. SMB2_CREATE   - Rapid file open/close cycle (create+close 10K files)
  4. Conn Setup    - Measure negotiate + session setup latency

${BOLD}Output files (per operation):${NC}
  - perf.data            Raw perf recording
  - perf_report.txt      perf report output
  - perf_collapsed.txt   Flamegraph-compatible collapsed stacks
  - ftrace_timing.txt    ksmbd function timing (if ftrace available)

${BOLD}Prerequisites:${NC}
  - Root privileges (for perf record)
  - perf (linux-tools-\$(uname -r))
  - fio (>= 3.0)

${BOLD}Examples:${NC}
  sudo $(basename "$0") --mount /mnt/ksmbd_test
  sudo $(basename "$0") --mount /mnt/ksmbd_test --duration 60 --output-dir /tmp/profiles
  sudo $(basename "$0") --mount /mnt/ksmbd_test --skip-perf
EOF
}

cleanup() {
    local exit_code=$?
    info "Cleaning up..."

    # Stop any ftrace we may have started
    disable_ftrace 2>/dev/null || true

    # Kill background processes
    if [ -n "${PERF_PID:-}" ] && kill -0 "$PERF_PID" 2>/dev/null; then
        kill "$PERF_PID" 2>/dev/null || true
        wait "$PERF_PID" 2>/dev/null || true
    fi

    if [ -n "$FIO_DIR" ] && [ -d "$FIO_DIR" ]; then
        rm -rf "$FIO_DIR" 2>/dev/null || true
    fi

    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi

    if [ $exit_code -ne 0 ]; then
        warn "Latency profiling exited with code $exit_code"
    fi
}

trap cleanup EXIT

PERF_PID=""

check_prerequisites() {
    local missing=0

    # Check root
    if [ "$SKIP_PERF" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
        err "Root privileges required for perf record. Use sudo or --skip-perf."
        missing=1
    fi

    if ! command -v fio >/dev/null 2>&1; then
        err "fio is not installed. Install with: apt-get install fio"
        missing=1
    fi

    if [ "$SKIP_PERF" -eq 0 ]; then
        if ! command -v perf >/dev/null 2>&1; then
            err "perf is not installed. Install with: apt-get install linux-tools-$(uname -r)"
            missing=1
        fi
    fi

    if ! command -v jq >/dev/null 2>&1; then
        warn "jq not found. JSON output will use basic formatting."
    fi

    if [ $missing -ne 0 ]; then
        err "Missing prerequisites. Aborting."
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Parse command-line arguments
# ---------------------------------------------------------------------------
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --mount)
                shift
                MOUNT_POINT="${1:-}"
                if [ -z "$MOUNT_POINT" ]; then
                    err "--mount requires a PATH argument"
                    exit 1
                fi
                ;;
            --duration)
                shift
                DURATION="${1:-}"
                if [ -z "$DURATION" ] || ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
                    err "--duration requires a numeric argument (seconds)"
                    exit 1
                fi
                ;;
            --output-dir)
                shift
                OUTPUT_DIR="${1:-}"
                if [ -z "$OUTPUT_DIR" ]; then
                    err "--output-dir requires a DIR argument"
                    exit 1
                fi
                ;;
            --skip-perf)
                SKIP_PERF=1
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                err "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

validate_args() {
    if [ -z "$MOUNT_POINT" ]; then
        err "Mount point is required. Use --mount PATH"
        echo ""
        usage
        exit 1
    fi

    if [ ! -d "$MOUNT_POINT" ]; then
        err "Mount point does not exist: $MOUNT_POINT"
        exit 1
    fi

    if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        warn "$MOUNT_POINT does not appear to be a mount point. Continuing anyway."
    fi

    FIO_DIR="$MOUNT_POINT/ksmbd_latprof_$$"
    mkdir -p "$FIO_DIR"

    TEMP_DIR=$(mktemp -d "/tmp/ksmbd_latprof_XXXXXX")

    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="profile_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$OUTPUT_DIR"
}

# ---------------------------------------------------------------------------
# ftrace helpers
# ---------------------------------------------------------------------------
FTRACE_AVAILABLE=0
FTRACE_DIR="/sys/kernel/debug/tracing"

check_ftrace() {
    if [ -d "$FTRACE_DIR" ] && [ -w "$FTRACE_DIR/set_ftrace_filter" ]; then
        FTRACE_AVAILABLE=1
        info "ftrace is available for ksmbd function tracing."
    else
        warn "ftrace not available (need debugfs mounted at /sys/kernel/debug)."
        warn "Skipping ksmbd function timing."
    fi
}

enable_ftrace() {
    local operation_name="$1"

    if [ "$FTRACE_AVAILABLE" -ne 1 ]; then
        return
    fi

    # Reset ftrace
    echo 0 > "$FTRACE_DIR/tracing_on" 2>/dev/null || true
    echo > "$FTRACE_DIR/set_ftrace_filter" 2>/dev/null || true
    echo "function_graph" > "$FTRACE_DIR/current_tracer" 2>/dev/null || true

    # Set ksmbd functions
    for func in "${KSMBD_FUNCTIONS[@]}"; do
        echo "$func" >> "$FTRACE_DIR/set_ftrace_filter" 2>/dev/null || true
    done

    # Clear trace buffer
    echo > "$FTRACE_DIR/trace" 2>/dev/null || true

    # Enable tracing
    echo 1 > "$FTRACE_DIR/tracing_on" 2>/dev/null || true
    info "ftrace enabled for ksmbd functions"
}

disable_ftrace() {
    if [ "$FTRACE_AVAILABLE" -ne 1 ]; then
        return
    fi

    echo 0 > "$FTRACE_DIR/tracing_on" 2>/dev/null || true
    echo "nop" > "$FTRACE_DIR/current_tracer" 2>/dev/null || true
    echo > "$FTRACE_DIR/set_ftrace_filter" 2>/dev/null || true
}

save_ftrace() {
    local output_file="$1"

    if [ "$FTRACE_AVAILABLE" -ne 1 ]; then
        echo "ftrace not available" > "$output_file"
        return
    fi

    # Disable tracing first
    echo 0 > "$FTRACE_DIR/tracing_on" 2>/dev/null || true

    # Save trace
    if [ -f "$FTRACE_DIR/trace" ]; then
        cp "$FTRACE_DIR/trace" "$output_file" 2>/dev/null || true
        local lines
        lines=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        info "Saved ftrace output: $lines lines"
    fi

    # Reset
    echo "nop" > "$FTRACE_DIR/current_tracer" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Perf helpers
# ---------------------------------------------------------------------------
start_perf_record() {
    local perf_data="$1"
    local workload_pid="${2:-}"

    if [ "$SKIP_PERF" -eq 1 ]; then
        return
    fi

    local perf_args=(
        perf record
        -g
        --call-graph dwarf
        -o "$perf_data"
        -a
    )

    if [ -n "$workload_pid" ]; then
        perf_args+=(-p "$workload_pid")
    fi

    "${perf_args[@]}" &
    PERF_PID=$!
    info "perf recording started (PID: $PERF_PID)"
}

stop_perf_record() {
    if [ "$SKIP_PERF" -eq 1 ]; then
        return
    fi

    if [ -n "${PERF_PID:-}" ] && kill -0 "$PERF_PID" 2>/dev/null; then
        kill -INT "$PERF_PID" 2>/dev/null || true
        wait "$PERF_PID" 2>/dev/null || true
        PERF_PID=""
        info "perf recording stopped"
    fi
}

generate_perf_report() {
    local perf_data="$1"
    local report_file="$2"
    local collapsed_file="$3"

    if [ "$SKIP_PERF" -eq 1 ]; then
        echo "perf recording skipped (--skip-perf)" > "$report_file"
        echo "perf recording skipped (--skip-perf)" > "$collapsed_file"
        return
    fi

    if [ ! -f "$perf_data" ]; then
        warn "perf.data not found: $perf_data"
        return
    fi

    # Generate perf report
    info "Generating perf report..."
    perf report -i "$perf_data" --stdio --no-children > "$report_file" 2>/dev/null || true
    ok "Report saved: $report_file"

    # Generate collapsed stacks for flamegraph
    info "Generating flamegraph-compatible collapsed stacks..."
    perf script -i "$perf_data" 2>/dev/null | \
        awk '
        /^[^ ]/ { if (stack != "") print stack " " count; stack=""; count=0; comm=$1 }
        /^\s+[0-9a-f]+/ {
            func = $2
            gsub(/\+0x[0-9a-f]+\/0x[0-9a-f]+/, "", func)
            if (stack == "")
                stack = comm ";" func
            else
                stack = stack ";" func
            count = 1
        }
        END { if (stack != "") print stack " " count }
        ' > "$collapsed_file" 2>/dev/null || true

    # Alternatively, if stackcollapse-perf.pl is available
    if command -v stackcollapse-perf.pl >/dev/null 2>&1; then
        perf script -i "$perf_data" 2>/dev/null | \
            stackcollapse-perf.pl > "$collapsed_file" 2>/dev/null || true
    fi

    local stack_count
    stack_count=$(wc -l < "$collapsed_file" 2>/dev/null || echo "0")
    ok "Collapsed stacks saved: $collapsed_file ($stack_count stacks)"
}

# ---------------------------------------------------------------------------
# Profile operations
# ---------------------------------------------------------------------------

# Measure wall-clock time of a command
# Usage: measure_time <command...>
# Returns: elapsed time in seconds (with decimals)
measure_time() {
    local start_ns
    local end_ns

    start_ns=$(date +%s%N)
    "$@"
    local rc=$?
    end_ns=$(date +%s%N)

    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
    awk "BEGIN {printf \"%.3f\", $elapsed_ms / 1000}"
    return $rc
}

# Profile 1: SMB2_READ — Sequential read of a large file
profile_smb2_read() {
    local op_dir="$OUTPUT_DIR/smb2_read"
    mkdir -p "$op_dir"

    info "============================================================"
    info " Profile 1/4: SMB2_READ (Sequential Read)"
    info " Duration: ${DURATION}s"
    info "============================================================"

    # Create test file
    info "Pre-creating test file for read profiling..."
    fio --name=precreate_read \
        --directory="$FIO_DIR" \
        --rw=write \
        --bs=1M \
        --size=1G \
        --numjobs=1 \
        --ioengine=posixaio \
        >/dev/null 2>&1 || true

    # Enable ftrace
    enable_ftrace "smb2_read"

    # Start perf recording (system-wide for ksmbd kernel threads)
    local perf_data="$op_dir/perf.data"
    start_perf_record "$perf_data"

    # Run the workload and measure time
    local fio_json="$TEMP_DIR/fio_read_profile.json"
    info "Running sequential read workload..."
    local wall_time
    wall_time=$(measure_time fio \
        --name=smb2_read_profile \
        --directory="$FIO_DIR" \
        --rw=read \
        --bs=1M \
        --size=1G \
        --numjobs=1 \
        --runtime="$DURATION" \
        --time_based \
        --group_reporting \
        --output-format=json \
        --output="$fio_json" \
        --ioengine=posixaio \
        --percentile_list=50:95:99 \
        2>/dev/null || true)

    # Stop perf
    stop_perf_record

    # Save ftrace
    save_ftrace "$op_dir/ftrace_timing.txt"

    # Generate perf report
    generate_perf_report "$perf_data" "$op_dir/perf_report.txt" "$op_dir/perf_collapsed.txt"

    # Extract metrics
    local bw="N/A"
    local iops="N/A"
    local lat_avg="N/A"
    if [ -f "$fio_json" ] && command -v jq >/dev/null 2>&1; then
        bw=$(jq -r '.jobs[0].read.bw_bytes // 0' "$fio_json" | awk '{printf "%.2f", $1/1048576}')
        iops=$(jq -r '.jobs[0].read.iops // 0' "$fio_json" | awk '{printf "%.0f", $1}')
        lat_avg=$(jq -r '.jobs[0].read.lat_ns.mean // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
    fi

    ok "SMB2_READ profile complete"
    info "  Wall time   : ${wall_time}s"
    info "  Bandwidth   : ${bw} MB/s"
    info "  IOPS        : ${iops}"
    info "  Avg Latency : ${lat_avg} us"
    info "  Output dir  : $op_dir/"
    echo ""

    # Return summary
    echo "SMB2_READ:${wall_time}:${bw}:${iops}:${lat_avg}"
}

# Profile 2: SMB2_WRITE — Sequential write of a large file
profile_smb2_write() {
    local op_dir="$OUTPUT_DIR/smb2_write"
    mkdir -p "$op_dir"

    info "============================================================"
    info " Profile 2/4: SMB2_WRITE (Sequential Write)"
    info " Duration: ${DURATION}s"
    info "============================================================"

    # Enable ftrace
    enable_ftrace "smb2_write"

    # Start perf
    local perf_data="$op_dir/perf.data"
    start_perf_record "$perf_data"

    # Run the workload
    local fio_json="$TEMP_DIR/fio_write_profile.json"
    info "Running sequential write workload..."
    local wall_time
    wall_time=$(measure_time fio \
        --name=smb2_write_profile \
        --directory="$FIO_DIR" \
        --rw=write \
        --bs=1M \
        --size=1G \
        --numjobs=1 \
        --runtime="$DURATION" \
        --time_based \
        --group_reporting \
        --output-format=json \
        --output="$fio_json" \
        --ioengine=posixaio \
        --percentile_list=50:95:99 \
        2>/dev/null || true)

    # Stop perf
    stop_perf_record

    # Save ftrace
    save_ftrace "$op_dir/ftrace_timing.txt"

    # Generate perf report
    generate_perf_report "$perf_data" "$op_dir/perf_report.txt" "$op_dir/perf_collapsed.txt"

    # Extract metrics
    local bw="N/A"
    local iops="N/A"
    local lat_avg="N/A"
    if [ -f "$fio_json" ] && command -v jq >/dev/null 2>&1; then
        bw=$(jq -r '.jobs[0].write.bw_bytes // 0' "$fio_json" | awk '{printf "%.2f", $1/1048576}')
        iops=$(jq -r '.jobs[0].write.iops // 0' "$fio_json" | awk '{printf "%.0f", $1}')
        lat_avg=$(jq -r '.jobs[0].write.lat_ns.mean // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
    fi

    ok "SMB2_WRITE profile complete"
    info "  Wall time   : ${wall_time}s"
    info "  Bandwidth   : ${bw} MB/s"
    info "  IOPS        : ${iops}"
    info "  Avg Latency : ${lat_avg} us"
    info "  Output dir  : $op_dir/"
    echo ""

    echo "SMB2_WRITE:${wall_time}:${bw}:${iops}:${lat_avg}"
}

# Profile 3: SMB2_CREATE — Rapid file open/close cycle
profile_smb2_create() {
    local op_dir="$OUTPUT_DIR/smb2_create"
    mkdir -p "$op_dir"

    local create_dir="$FIO_DIR/create_test"
    mkdir -p "$create_dir"

    local num_files=10000

    info "============================================================"
    info " Profile 3/4: SMB2_CREATE (File Create/Close Cycle)"
    info " Files: $num_files"
    info "============================================================"

    # Enable ftrace
    enable_ftrace "smb2_create"

    # Start perf
    local perf_data="$op_dir/perf.data"
    start_perf_record "$perf_data"

    # Run the workload: create many small files
    local fio_json="$TEMP_DIR/fio_create_profile.json"
    info "Running file create/close workload ($num_files files)..."
    local wall_time
    wall_time=$(measure_time fio \
        --name=smb2_create_profile \
        --directory="$create_dir" \
        --rw=write \
        --bs=4k \
        --filesize=4k \
        --nrfiles="$num_files" \
        --numjobs=1 \
        --group_reporting \
        --output-format=json \
        --output="$fio_json" \
        --ioengine=posixaio \
        --create_on_open=1 \
        --openfiles=1 \
        --file_service_type=sequential \
        --fallocate=none \
        --percentile_list=50:95:99 \
        2>/dev/null || true)

    # Stop perf
    stop_perf_record

    # Save ftrace
    save_ftrace "$op_dir/ftrace_timing.txt"

    # Generate perf report
    generate_perf_report "$perf_data" "$op_dir/perf_report.txt" "$op_dir/perf_collapsed.txt"

    # Calculate files/sec
    local files_per_sec="N/A"
    local lat_avg="N/A"
    if [ -n "$wall_time" ] && [ "$wall_time" != "0" ] && [ "$wall_time" != "0.000" ]; then
        files_per_sec=$(awk "BEGIN {printf \"%.0f\", $num_files / $wall_time}")
    fi

    if [ -f "$fio_json" ] && command -v jq >/dev/null 2>&1; then
        lat_avg=$(jq -r '.jobs[0].write.lat_ns.mean // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
    fi

    ok "SMB2_CREATE profile complete"
    info "  Wall time   : ${wall_time}s"
    info "  Files/sec   : ${files_per_sec}"
    info "  Avg Latency : ${lat_avg} us"
    info "  Output dir  : $op_dir/"
    echo ""

    # Clean up the created files
    rm -rf "$create_dir" 2>/dev/null || true

    echo "SMB2_CREATE:${wall_time}:${files_per_sec}:${num_files}:${lat_avg}"
}

# Profile 4: Connection setup — Negotiate + session setup latency
profile_conn_setup() {
    local op_dir="$OUTPUT_DIR/conn_setup"
    mkdir -p "$op_dir"

    local iterations=100

    info "============================================================"
    info " Profile 4/4: Connection Setup (Negotiate + Session Setup)"
    info " Iterations: $iterations"
    info "============================================================"

    # Enable ftrace
    enable_ftrace "conn_setup"

    # Start perf
    local perf_data="$op_dir/perf.data"
    start_perf_record "$perf_data"

    # Measure connection setup by doing small file operations
    # Each fio invocation goes through negotiate + session setup
    info "Running connection setup measurement ($iterations iterations)..."
    local start_ns
    start_ns=$(date +%s%N)

    local success_count=0
    local total_lat_ms=0

    for i in $(seq 1 "$iterations"); do
        local iter_start
        iter_start=$(date +%s%N)

        # Each fio run creates a new connection
        fio --name="conn_test_${i}" \
            --directory="$FIO_DIR" \
            --rw=write \
            --bs=4k \
            --size=4k \
            --numjobs=1 \
            --ioengine=posixaio \
            --create_on_open=1 \
            --fallocate=none \
            >/dev/null 2>&1 || continue

        local iter_end
        iter_end=$(date +%s%N)
        local iter_ms=$(( (iter_end - iter_start) / 1000000 ))
        total_lat_ms=$((total_lat_ms + iter_ms))
        success_count=$((success_count + 1))

        # Clean up the file
        rm -f "$FIO_DIR/conn_test_${i}"* 2>/dev/null || true

        # Progress indicator every 10 iterations
        if [ $((i % 10)) -eq 0 ]; then
            info "  Progress: $i/$iterations iterations"
        fi
    done

    local end_ns
    end_ns=$(date +%s%N)
    local wall_time_ms=$(( (end_ns - start_ns) / 1000000 ))
    local wall_time
    wall_time=$(awk "BEGIN {printf \"%.3f\", $wall_time_ms / 1000}")

    # Stop perf
    stop_perf_record

    # Save ftrace
    save_ftrace "$op_dir/ftrace_timing.txt"

    # Generate perf report
    generate_perf_report "$perf_data" "$op_dir/perf_report.txt" "$op_dir/perf_collapsed.txt"

    # Calculate averages
    local avg_lat_ms="N/A"
    local conns_per_sec="N/A"
    if [ "$success_count" -gt 0 ]; then
        avg_lat_ms=$(awk "BEGIN {printf \"%.2f\", $total_lat_ms / $success_count}")
        conns_per_sec=$(awk "BEGIN {printf \"%.1f\", $success_count / ($wall_time_ms / 1000)}")
    fi

    ok "Connection setup profile complete"
    info "  Wall time     : ${wall_time}s"
    info "  Successful    : ${success_count}/${iterations}"
    info "  Avg latency   : ${avg_lat_ms} ms"
    info "  Conns/sec     : ${conns_per_sec}"
    info "  Output dir    : $op_dir/"
    echo ""

    echo "CONN_SETUP:${wall_time}:${conns_per_sec}:${success_count}:${avg_lat_ms}"
}

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
print_summary() {
    local -n results_ref=$1

    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}              LATENCY PROFILE SUMMARY                       ${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    printf "${BOLD}%-18s %12s %14s %14s %14s${NC}\n" \
        "Operation" "Wall Time(s)" "Throughput" "Ops/Count" "Avg Lat"
    printf "%-18s %12s %14s %14s %14s\n" \
        "------------------" "------------" "--------------" "--------------" "--------------"

    for entry in "${results_ref[@]}"; do
        IFS=':' read -r op_name wall_time metric2 metric3 metric4 <<< "$entry"

        local throughput_col=""
        local ops_col=""
        local lat_col=""

        case "$op_name" in
            SMB2_READ)
                throughput_col="${metric2} MB/s"
                ops_col="${metric3} IOPS"
                lat_col="${metric4} us"
                ;;
            SMB2_WRITE)
                throughput_col="${metric2} MB/s"
                ops_col="${metric3} IOPS"
                lat_col="${metric4} us"
                ;;
            SMB2_CREATE)
                throughput_col="${metric2} files/s"
                ops_col="${metric3} files"
                lat_col="${metric4} us"
                ;;
            CONN_SETUP)
                throughput_col="${metric2} conn/s"
                ops_col="${metric3} conns"
                lat_col="${metric4} ms"
                ;;
        esac

        printf "%-18s %12s %14s %14s %14s\n" \
            "$op_name" "$wall_time" "$throughput_col" "$ops_col" "$lat_col"
    done

    echo ""
    echo -e "${BOLD}Output directory:${NC} $OUTPUT_DIR/"
    echo ""

    if [ "$SKIP_PERF" -eq 0 ]; then
        info "To generate flamegraphs from collapsed stacks:"
        info "  flamegraph.pl $OUTPUT_DIR/smb2_read/perf_collapsed.txt > flamegraph_read.svg"
        info "  flamegraph.pl $OUTPUT_DIR/smb2_write/perf_collapsed.txt > flamegraph_write.svg"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Write JSON summary
# ---------------------------------------------------------------------------
write_json_summary() {
    local -n results_ref=$1
    local json_file="$OUTPUT_DIR/summary.json"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local kernel_ver
    kernel_ver=$(uname -r 2>/dev/null || echo "unknown")

    {
        echo "{"
        echo "  \"benchmark\": \"ksmbd-latency-profile\","
        echo "  \"version\": \"1.0.0\","
        echo "  \"timestamp\": \"$timestamp\","
        echo "  \"hostname\": \"$hostname_val\","
        echo "  \"kernel\": \"$kernel_ver\","
        echo "  \"mount_point\": \"$MOUNT_POINT\","
        echo "  \"duration_secs\": $DURATION,"
        echo "  \"skip_perf\": $([ "$SKIP_PERF" -eq 1 ] && echo "true" || echo "false"),"
        echo "  \"profiles\": ["

        local count=${#results_ref[@]}
        local idx=0
        for entry in "${results_ref[@]}"; do
            IFS=':' read -r op_name wall_time metric2 metric3 metric4 <<< "$entry"

            idx=$((idx + 1))
            local comma=","
            if [ "$idx" -eq "$count" ]; then
                comma=""
            fi

            echo "    {"
            echo "      \"operation\": \"$op_name\","
            echo "      \"wall_time_secs\": $wall_time,"

            case "$op_name" in
                SMB2_READ|SMB2_WRITE)
                    echo "      \"bandwidth_mbps\": $metric2,"
                    echo "      \"iops\": $metric3,"
                    echo "      \"avg_latency_us\": $metric4"
                    ;;
                SMB2_CREATE)
                    echo "      \"files_per_sec\": $metric2,"
                    echo "      \"total_files\": $metric3,"
                    echo "      \"avg_latency_us\": $metric4"
                    ;;
                CONN_SETUP)
                    echo "      \"conns_per_sec\": $metric2,"
                    echo "      \"successful_conns\": $metric3,"
                    echo "      \"avg_latency_ms\": $metric4"
                    ;;
            esac

            echo "    }$comma"
        done

        echo "  ]"
        echo "}"
    } > "$json_file"

    ok "JSON summary written to: $json_file"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    validate_args
    check_prerequisites
    check_ftrace

    info "============================================================"
    info " ksmbd Latency Profiling"
    info " Mount point  : $MOUNT_POINT"
    info " Duration     : ${DURATION}s per operation"
    info " Output dir   : $OUTPUT_DIR/"
    info " Skip perf    : $([ "$SKIP_PERF" -eq 1 ] && echo "yes" || echo "no")"
    info " ftrace       : $([ "$FTRACE_AVAILABLE" -eq 1 ] && echo "available" || echo "not available")"
    info "============================================================"
    echo ""

    local -a all_results=()

    # Profile 1: SMB2_READ
    local result
    result=$(profile_smb2_read | tail -1)
    all_results+=("$result")

    # Profile 2: SMB2_WRITE
    result=$(profile_smb2_write | tail -1)
    all_results+=("$result")

    # Profile 3: SMB2_CREATE
    result=$(profile_smb2_create | tail -1)
    all_results+=("$result")

    # Profile 4: Connection Setup
    result=$(profile_conn_setup | tail -1)
    all_results+=("$result")

    # Print summary
    print_summary all_results

    # Write JSON
    write_json_summary all_results

    ok "Latency profiling complete. Results in: $OUTPUT_DIR/"
}

main "$@"
