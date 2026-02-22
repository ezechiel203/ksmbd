#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Connection scalability benchmark for ksmbd
#
# Measures aggregate throughput and per-client latency as the number
# of concurrent clients increases. Identifies the "knee" point where
# per-client throughput starts degrading.
#
# Prerequisites:
#   - fio (>= 3.0)
#   - mpstat (from sysstat package, optional for CPU stats)
#   - A mounted SMB share (ksmbd)
#   - Sufficient disk space for test files
#
# Usage:
#   ./scalability_test.sh --mount /mnt/ksmbd_test [--max-clients 256]

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
MAX_CLIENTS=256
OUTPUT_FILE=""
FILE_SIZE="1G"
RUNTIME=30
FIO_DIR=""
TEMP_DIR=""

# Client counts to test (will be filtered by --max-clients)
ALL_CLIENT_COUNTS=(1 2 4 8 16 32 64 128 256)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
${BOLD}Usage:${NC} $(basename "$0") --mount PATH [OPTIONS]

${BOLD}Connection scalability benchmark for ksmbd${NC}

Measures aggregate throughput and per-client latency as the number of
concurrent clients increases. Helps identify the scaling "knee" point.

${BOLD}Required:${NC}
  --mount PATH          Mount point of the SMB share to benchmark

${BOLD}Options:${NC}
  --max-clients N       Maximum number of concurrent clients (default: 256)
  --file-size SIZE      Size of the shared test file (default: 1G)
  --runtime SECS        Duration per test in seconds (default: 30)
  --output FILE         JSON output file (default: scalability_YYYYMMDD_HHMMSS.json)
  --help                Show this help message

${BOLD}Test matrix:${NC}
  1, 2, 4, 8, 16, 32, 64, 128, 256 concurrent clients
  (capped by --max-clients)

${BOLD}Metrics captured:${NC}
  - Aggregate throughput (MB/s)
  - Aggregate IOPS
  - Per-client average latency (us)
  - CPU utilization (if mpstat available)
  - Lock contention stats (if /proc/lock_stat available)

${BOLD}Examples:${NC}
  $(basename "$0") --mount /mnt/ksmbd_test
  $(basename "$0") --mount /mnt/ksmbd_test --max-clients 64 --runtime 60
  $(basename "$0") --mount /mnt/ksmbd_test --file-size 4G --output scale.json
EOF
}

cleanup() {
    local exit_code=$?
    info "Cleaning up..."

    # Kill any lingering mpstat processes we started
    if [ -n "${MPSTAT_PID:-}" ] && kill -0 "$MPSTAT_PID" 2>/dev/null; then
        kill "$MPSTAT_PID" 2>/dev/null || true
        wait "$MPSTAT_PID" 2>/dev/null || true
    fi

    if [ -n "$FIO_DIR" ] && [ -d "$FIO_DIR" ]; then
        rm -rf "$FIO_DIR" 2>/dev/null || true
    fi

    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi

    if [ $exit_code -ne 0 ]; then
        warn "Scalability test exited with code $exit_code"
    fi
}

trap cleanup EXIT

MPSTAT_PID=""

check_prerequisites() {
    local missing=0

    if ! command -v fio >/dev/null 2>&1; then
        err "fio is not installed. Install with: apt-get install fio"
        missing=1
    fi

    if ! command -v mpstat >/dev/null 2>&1; then
        warn "mpstat not found. CPU utilization will not be captured."
        warn "Install with: apt-get install sysstat"
    fi

    if ! command -v jq >/dev/null 2>&1; then
        warn "jq not found. JSON parsing will use basic fallback."
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
            --max-clients)
                shift
                MAX_CLIENTS="${1:-}"
                if [ -z "$MAX_CLIENTS" ] || ! [[ "$MAX_CLIENTS" =~ ^[0-9]+$ ]]; then
                    err "--max-clients requires a numeric argument"
                    exit 1
                fi
                ;;
            --file-size)
                shift
                FILE_SIZE="${1:-}"
                if [ -z "$FILE_SIZE" ]; then
                    err "--file-size requires a SIZE argument"
                    exit 1
                fi
                ;;
            --runtime)
                shift
                RUNTIME="${1:-}"
                if [ -z "$RUNTIME" ] || ! [[ "$RUNTIME" =~ ^[0-9]+$ ]]; then
                    err "--runtime requires a numeric argument (seconds)"
                    exit 1
                fi
                ;;
            --output)
                shift
                OUTPUT_FILE="${1:-}"
                if [ -z "$OUTPUT_FILE" ]; then
                    err "--output requires a FILE argument"
                    exit 1
                fi
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

    FIO_DIR="$MOUNT_POINT/ksmbd_scale_$$"
    mkdir -p "$FIO_DIR"

    TEMP_DIR=$(mktemp -d "/tmp/ksmbd_scale_XXXXXX")

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="scalability_$(date +%Y%m%d_%H%M%S).json"
    fi
}

# Filter client counts based on max-clients
get_client_counts() {
    local counts=()
    for c in "${ALL_CLIENT_COUNTS[@]}"; do
        if [ "$c" -le "$MAX_CLIENTS" ]; then
            counts+=("$c")
        fi
    done
    echo "${counts[@]}"
}

# ---------------------------------------------------------------------------
# Capture CPU utilization using mpstat
# ---------------------------------------------------------------------------
start_cpu_monitor() {
    local output_file="$1"

    if command -v mpstat >/dev/null 2>&1; then
        mpstat 1 > "$output_file" 2>/dev/null &
        MPSTAT_PID=$!
    else
        MPSTAT_PID=""
    fi
}

stop_cpu_monitor() {
    local output_file="$1"

    if [ -n "${MPSTAT_PID:-}" ] && kill -0 "$MPSTAT_PID" 2>/dev/null; then
        kill "$MPSTAT_PID" 2>/dev/null || true
        wait "$MPSTAT_PID" 2>/dev/null || true
        MPSTAT_PID=""
    fi

    # Extract average CPU utilization
    if [ -f "$output_file" ] && command -v awk >/dev/null 2>&1; then
        # mpstat output: get average idle%, compute usage% = 100 - idle%
        local avg_idle
        avg_idle=$(awk '/^Average:/ && /all/ {print $(NF)}' "$output_file" 2>/dev/null || echo "0")
        if [ -n "$avg_idle" ] && [ "$avg_idle" != "0" ]; then
            awk "BEGIN {printf \"%.1f\", 100 - $avg_idle}"
        else
            # Fallback: average the non-header idle column values
            avg_idle=$(awk '!/^$/ && !/^Linux/ && !/^Average/ && /all/ {sum+=$(NF); n++} END {if(n>0) printf "%.1f", sum/n; else print "0"}' "$output_file" 2>/dev/null || echo "0")
            awk "BEGIN {printf \"%.1f\", 100 - $avg_idle}"
        fi
    else
        echo "N/A"
    fi
}

# ---------------------------------------------------------------------------
# Capture lock contention stats
# ---------------------------------------------------------------------------
capture_lock_stats() {
    local output_file="$1"

    if [ -f /proc/lock_stat ]; then
        cp /proc/lock_stat "$output_file" 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# Run fio with N concurrent clients (numjobs)
# ---------------------------------------------------------------------------
run_scale_test() {
    local num_clients="$1"
    local fio_json="$TEMP_DIR/fio_scale_${num_clients}.json"

    info "Testing with ${BOLD}${num_clients}${NC} concurrent client(s)..."

    # Start CPU monitoring
    local cpu_output="$TEMP_DIR/cpu_${num_clients}.txt"
    start_cpu_monitor "$cpu_output"

    # Capture lock stats before
    local lock_before="$TEMP_DIR/lock_before_${num_clients}.txt"
    capture_lock_stats "$lock_before"

    # Run fio
    local fio_rc=0
    fio \
        --name="scale_test_${num_clients}" \
        --directory="$FIO_DIR" \
        --rw=randread \
        --bs=4k \
        --size="$FILE_SIZE" \
        --numjobs="$num_clients" \
        --runtime="$RUNTIME" \
        --time_based \
        --group_reporting \
        --output-format=json \
        --output="$fio_json" \
        --ioengine=posixaio \
        --direct=1 \
        --percentile_list=50:95:99 \
        2>/dev/null || fio_rc=$?

    # If direct I/O failed, retry without it
    if [ $fio_rc -ne 0 ]; then
        warn "Retrying without direct I/O for $num_clients clients..."
        fio \
            --name="scale_test_${num_clients}" \
            --directory="$FIO_DIR" \
            --rw=randread \
            --bs=4k \
            --size="$FILE_SIZE" \
            --numjobs="$num_clients" \
            --runtime="$RUNTIME" \
            --time_based \
            --group_reporting \
            --output-format=json \
            --output="$fio_json" \
            --ioengine=posixaio \
            --direct=0 \
            --percentile_list=50:95:99 \
            2>/dev/null || true
    fi

    # Capture lock stats after
    local lock_after="$TEMP_DIR/lock_after_${num_clients}.txt"
    capture_lock_stats "$lock_after"

    # Stop CPU monitoring and get average usage
    local cpu_pct
    cpu_pct=$(stop_cpu_monitor "$cpu_output")

    # Extract metrics from fio JSON
    local agg_bw="0"
    local agg_iops="0"
    local avg_lat_us="0"
    local lat_p50_us="0"
    local lat_p95_us="0"
    local lat_p99_us="0"

    if [ -f "$fio_json" ] && command -v jq >/dev/null 2>&1; then
        agg_bw=$(jq -r '.jobs[0].read.bw_bytes // 0' "$fio_json" | awk '{printf "%.2f", $1/1048576}')
        agg_iops=$(jq -r '.jobs[0].read.iops // 0' "$fio_json" | awk '{printf "%.0f", $1}')
        avg_lat_us=$(jq -r '.jobs[0].read.lat_ns.mean // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
        lat_p50_us=$(jq -r '.jobs[0].read.clat_ns.percentile."50.000000" // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
        lat_p95_us=$(jq -r '.jobs[0].read.clat_ns.percentile."95.000000" // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
        lat_p99_us=$(jq -r '.jobs[0].read.clat_ns.percentile."99.000000" // 0' "$fio_json" | awk '{printf "%.2f", $1/1000}')
    fi

    # Calculate per-client throughput
    local per_client_bw
    per_client_bw=$(awk "BEGIN {printf \"%.2f\", $agg_bw / $num_clients}")

    # Lock contention delta (count ksmbd-related entries if available)
    local lock_contention="N/A"
    if [ -f "$lock_before" ] && [ -f "$lock_after" ]; then
        local before_count after_count
        before_count=$(wc -l < "$lock_before" 2>/dev/null || echo "0")
        after_count=$(wc -l < "$lock_after" 2>/dev/null || echo "0")
        lock_contention="$((after_count - before_count)) lines delta"
    fi

    # Return results as colon-separated string
    echo "${num_clients}:${agg_bw}:${agg_iops}:${per_client_bw}:${avg_lat_us}:${lat_p50_us}:${lat_p95_us}:${lat_p99_us}:${cpu_pct}:${lock_contention}"
}

# ---------------------------------------------------------------------------
# Identify the "knee" point
# ---------------------------------------------------------------------------
find_knee_point() {
    local -n results_ref=$1

    if [ ${#results_ref[@]} -lt 3 ]; then
        echo "N/A (insufficient data points)"
        return
    fi

    # The knee is where per-client BW starts to decrease significantly
    # We look for the first point where per-client BW drops by more than 15%
    # compared to the previous data point
    local prev_pcbw=""
    local knee_clients="none detected"

    for entry in "${results_ref[@]}"; do
        IFS=':' read -r clients _ _ pcbw _ _ _ _ _ _ <<< "$entry"

        if [ -n "$prev_pcbw" ] && [ "$prev_pcbw" != "0" ] && [ "$prev_pcbw" != "0.00" ]; then
            local drop_pct
            drop_pct=$(awk "BEGIN {
                if ($prev_pcbw > 0)
                    printf \"%.1f\", (($prev_pcbw - $pcbw) / $prev_pcbw) * 100
                else
                    print 0
            }")

            # If per-client BW dropped more than 15%, this is the knee
            local is_knee
            is_knee=$(awk "BEGIN {print ($drop_pct > 15.0) ? 1 : 0}")
            if [ "$is_knee" -eq 1 ]; then
                knee_clients="$clients clients (per-client BW dropped ${drop_pct}%)"
                break
            fi
        fi

        prev_pcbw="$pcbw"
    done

    echo "$knee_clients"
}

# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------
print_results_table() {
    local -n results_ref=$1

    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}              SCALABILITY TEST RESULTS                      ${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    printf "${BOLD}%-10s %12s %12s %14s %14s %12s %12s %12s %10s${NC}\n" \
        "Clients" "BW (MB/s)" "IOPS" "BW/Client" "Lat Avg(us)" "p50(us)" "p95(us)" "p99(us)" "CPU %"
    printf "%-10s %12s %12s %14s %14s %12s %12s %12s %10s\n" \
        "----------" "------------" "------------" "--------------" "--------------" "------------" "------------" "------------" "----------"

    for entry in "${results_ref[@]}"; do
        IFS=':' read -r clients agg_bw agg_iops pcbw avg_lat p50 p95 p99 cpu lock_info <<< "$entry"

        # Color the per-client BW based on scaling efficiency
        local pcbw_colored="$pcbw"

        printf "%-10s %12s %12s %14s %14s %12s %12s %12s %10s\n" \
            "$clients" "$agg_bw" "$agg_iops" "$pcbw" "$avg_lat" "$p50" "$p95" "$p99" "$cpu"
    done

    echo ""

    # Find and report knee point
    local knee
    knee=$(find_knee_point results_ref)
    echo -e "${BOLD}Scaling knee point:${NC} $knee"
    echo ""
}

# ---------------------------------------------------------------------------
# Write JSON results
# ---------------------------------------------------------------------------
write_json_results() {
    local -n results_ref=$1

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local kernel_ver
    kernel_ver=$(uname -r 2>/dev/null || echo "unknown")

    local knee
    knee=$(find_knee_point results_ref)

    {
        echo "{"
        echo "  \"benchmark\": \"ksmbd-scalability\","
        echo "  \"version\": \"1.0.0\","
        echo "  \"timestamp\": \"$timestamp\","
        echo "  \"hostname\": \"$hostname_val\","
        echo "  \"kernel\": \"$kernel_ver\","
        echo "  \"mount_point\": \"$MOUNT_POINT\","
        echo "  \"max_clients\": $MAX_CLIENTS,"
        echo "  \"file_size\": \"$FILE_SIZE\","
        echo "  \"runtime_secs\": $RUNTIME,"
        echo "  \"knee_point\": \"$knee\","
        echo "  \"results\": ["

        local count=${#results_ref[@]}
        local idx=0
        for entry in "${results_ref[@]}"; do
            IFS=':' read -r clients agg_bw agg_iops pcbw avg_lat p50 p95 p99 cpu lock_info <<< "$entry"

            idx=$((idx + 1))
            local comma=","
            if [ "$idx" -eq "$count" ]; then
                comma=""
            fi

            echo "    {"
            echo "      \"clients\": $clients,"
            echo "      \"aggregate_bandwidth_mbps\": $agg_bw,"
            echo "      \"aggregate_iops\": $agg_iops,"
            echo "      \"per_client_bandwidth_mbps\": $pcbw,"
            echo "      \"latency_avg_us\": $avg_lat,"
            echo "      \"latency_p50_us\": $p50,"
            echo "      \"latency_p95_us\": $p95,"
            echo "      \"latency_p99_us\": $p99,"
            echo "      \"cpu_utilization_pct\": \"$cpu\","
            echo "      \"lock_contention\": \"$lock_info\""
            echo "    }$comma"
        done

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    ok "JSON results written to: $OUTPUT_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    validate_args
    check_prerequisites

    local -a client_counts
    read -ra client_counts <<< "$(get_client_counts)"

    info "============================================================"
    info " Scalability Test"
    info " Mount point  : $MOUNT_POINT"
    info " Max clients  : $MAX_CLIENTS"
    info " Client steps : ${client_counts[*]}"
    info " File size    : $FILE_SIZE"
    info " Runtime/test : ${RUNTIME}s"
    info " Output file  : $OUTPUT_FILE"
    info "============================================================"
    echo ""

    # Pre-create test file for random reads
    info "Pre-creating test file ($FILE_SIZE) for random read workload..."
    fio --name=precreate \
        --directory="$FIO_DIR" \
        --rw=write \
        --bs=1M \
        --size="$FILE_SIZE" \
        --numjobs=1 \
        --ioengine=posixaio \
        --direct=1 \
        >/dev/null 2>&1 || \
    fio --name=precreate \
        --directory="$FIO_DIR" \
        --rw=write \
        --bs=1M \
        --size="$FILE_SIZE" \
        --numjobs=1 \
        --ioengine=posixaio \
        --direct=0 \
        >/dev/null 2>&1 || true
    ok "Test file created."
    echo ""

    # Run scaling tests
    local -a all_results=()

    for nc in "${client_counts[@]}"; do
        local result
        result=$(run_scale_test "$nc")
        all_results+=("$result")

        # Brief summary
        IFS=':' read -r _ bw iops pcbw _ _ _ _ cpu _ <<< "$result"
        ok "  Clients=$nc  BW=${bw} MB/s  IOPS=${iops}  BW/client=${pcbw} MB/s  CPU=${cpu}%"
        echo ""
    done

    # Print results
    print_results_table all_results

    # Write JSON
    write_json_results all_results

    ok "Scalability test complete."
}

main "$@"
