#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# fio-based performance benchmark suite for ksmbd
#
# Runs standardized I/O workloads against a mounted SMB share
# and produces structured results for regression detection.
#
# Prerequisites:
#   - fio (>= 3.0)
#   - A mounted SMB share (ksmbd, Samba, or NFS for comparison)
#   - Sufficient disk space for test files
#
# Usage:
#   ./run_benchmarks.sh --mount /mnt/ksmbd_test [--output results.json]

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
OUTPUT_FILE=""
QUICK_MODE=0
SIZE_OVERRIDE=""
FIO_DIR=""
CLEANUP_FILES=()

# Default sizes
SEQ_SIZE="4G"
RAND_SIZE="1G"
LARGE_SIZE="16G"
META_FILESIZE="4k"
META_NRFILES=10000

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

${BOLD}fio-based performance benchmark suite for ksmbd${NC}

Runs standardized I/O workloads against a mounted SMB share and produces
structured results for regression detection.

${BOLD}Required:${NC}
  --mount PATH        Mount point of the SMB share to benchmark

${BOLD}Options:${NC}
  --size SIZE         Override default file sizes (e.g., 256M for quick runs)
  --output FILE       JSON output file (default: results_YYYYMMDD_HHMMSS.json)
  --quick             Use reduced sizes (256MB) for fast CI runs
  --help              Show this help message

${BOLD}Workloads:${NC}
  1. Sequential read     (1MB blocks, ${SEQ_SIZE} file, 1 job)
  2. Sequential write    (1MB blocks, ${SEQ_SIZE} file, 1 job)
  3. Random read 4K      (4K blocks, ${RAND_SIZE} file, 4 jobs)
  4. Random write 4K     (4K blocks, ${RAND_SIZE} file, 4 jobs)
  5. Mixed random 70/30  (4K blocks, ${RAND_SIZE} file, 4 jobs)
  6. Metadata ops        (4K random write, ${META_NRFILES} files of 4K each)
  7. Large sequential    (1MB blocks, ${LARGE_SIZE} file, sustained throughput)

${BOLD}Prerequisites:${NC}
  - fio (>= 3.0)
  - A mounted SMB share (ksmbd, Samba, or NFS)
  - Sufficient disk space for test files

${BOLD}Examples:${NC}
  $(basename "$0") --mount /mnt/ksmbd_test
  $(basename "$0") --mount /mnt/ksmbd_test --quick --output ci_results.json
  $(basename "$0") --mount /mnt/ksmbd_test --size 512M
EOF
}

cleanup() {
    local exit_code=$?
    info "Cleaning up test files..."
    for f in "${CLEANUP_FILES[@]}"; do
        rm -rf "$f" 2>/dev/null || true
    done
    if [ -n "$FIO_DIR" ] && [ -d "$FIO_DIR" ]; then
        rm -rf "$FIO_DIR" 2>/dev/null || true
    fi
    if [ $exit_code -ne 0 ]; then
        warn "Benchmark exited with code $exit_code"
    fi
}

trap cleanup EXIT

check_prerequisites() {
    local missing=0

    if ! command -v fio >/dev/null 2>&1; then
        err "fio is not installed. Install with: apt-get install fio"
        missing=1
    else
        local fio_ver
        fio_ver=$(fio --version | sed 's/fio-//' | cut -d. -f1)
        if [ "$fio_ver" -lt 3 ] 2>/dev/null; then
            err "fio >= 3.0 is required (found: $(fio --version))"
            missing=1
        fi
    fi

    if ! command -v jq >/dev/null 2>&1; then
        warn "jq is not installed. JSON parsing will use basic fallback."
        warn "Install jq for better results: apt-get install jq"
    fi

    if [ $missing -ne 0 ]; then
        err "Missing prerequisites. Aborting."
        exit 1
    fi
}

validate_mount() {
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

    # Create a test directory under the mount point
    FIO_DIR="$MOUNT_POINT/ksmbd_bench_$$"
    mkdir -p "$FIO_DIR"
    CLEANUP_FILES+=("$FIO_DIR")

    # Quick write test to verify we can write
    if ! touch "$FIO_DIR/.write_test" 2>/dev/null; then
        err "Cannot write to mount point: $MOUNT_POINT"
        exit 1
    fi
    rm -f "$FIO_DIR/.write_test"
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
            --size)
                shift
                SIZE_OVERRIDE="${1:-}"
                if [ -z "$SIZE_OVERRIDE" ]; then
                    err "--size requires a SIZE argument"
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
            --quick)
                QUICK_MODE=1
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

apply_size_settings() {
    if [ "$QUICK_MODE" -eq 1 ]; then
        SEQ_SIZE="256M"
        RAND_SIZE="256M"
        LARGE_SIZE="512M"
        META_NRFILES=1000
        info "Quick mode enabled: using reduced sizes"
    fi

    if [ -n "$SIZE_OVERRIDE" ]; then
        SEQ_SIZE="$SIZE_OVERRIDE"
        RAND_SIZE="$SIZE_OVERRIDE"
        LARGE_SIZE="$SIZE_OVERRIDE"
        info "Size override: all file sizes set to $SIZE_OVERRIDE"
    fi

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="results_$(date +%Y%m%d_%H%M%S).json"
    fi
}

# ---------------------------------------------------------------------------
# fio runner and result extraction
# ---------------------------------------------------------------------------

# Extract metrics from fio JSON output.
# Usage: extract_metrics <fio_json_file> <rw_type>
#   rw_type: "read", "write", or "mixed"
extract_metrics() {
    local json_file="$1"
    local rw_type="$2"

    local bw_mbs="0"
    local iops="0"
    local lat_avg_us="0"
    local lat_p50_us="0"
    local lat_p95_us="0"
    local lat_p99_us="0"

    if command -v jq >/dev/null 2>&1; then
        case "$rw_type" in
            read)
                bw_mbs=$(jq -r '.jobs[0].read.bw_bytes // 0' "$json_file" | awk '{printf "%.2f", $1/1048576}')
                iops=$(jq -r '.jobs[0].read.iops // 0' "$json_file" | awk '{printf "%.0f", $1}')
                lat_avg_us=$(jq -r '.jobs[0].read.lat_ns.mean // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p50_us=$(jq -r '.jobs[0].read.clat_ns.percentile."50.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p95_us=$(jq -r '.jobs[0].read.clat_ns.percentile."95.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p99_us=$(jq -r '.jobs[0].read.clat_ns.percentile."99.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                ;;
            write)
                bw_mbs=$(jq -r '.jobs[0].write.bw_bytes // 0' "$json_file" | awk '{printf "%.2f", $1/1048576}')
                iops=$(jq -r '.jobs[0].write.iops // 0' "$json_file" | awk '{printf "%.0f", $1}')
                lat_avg_us=$(jq -r '.jobs[0].write.lat_ns.mean // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p50_us=$(jq -r '.jobs[0].write.clat_ns.percentile."50.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p95_us=$(jq -r '.jobs[0].write.clat_ns.percentile."95.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p99_us=$(jq -r '.jobs[0].write.clat_ns.percentile."99.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                ;;
            mixed)
                # For mixed workloads, report combined read+write bandwidth
                local rbw
                local wbw
                rbw=$(jq -r '.jobs[0].read.bw_bytes // 0' "$json_file")
                wbw=$(jq -r '.jobs[0].write.bw_bytes // 0' "$json_file")
                bw_mbs=$(awk "BEGIN {printf \"%.2f\", ($rbw + $wbw)/1048576}")
                local riops
                local wiops
                riops=$(jq -r '.jobs[0].read.iops // 0' "$json_file")
                wiops=$(jq -r '.jobs[0].write.iops // 0' "$json_file")
                iops=$(awk "BEGIN {printf \"%.0f\", $riops + $wiops}")
                # Use read latency as representative for mixed
                lat_avg_us=$(jq -r '.jobs[0].read.lat_ns.mean // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p50_us=$(jq -r '.jobs[0].read.clat_ns.percentile."50.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p95_us=$(jq -r '.jobs[0].read.clat_ns.percentile."95.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                lat_p99_us=$(jq -r '.jobs[0].read.clat_ns.percentile."99.000000" // 0' "$json_file" | awk '{printf "%.2f", $1/1000}')
                ;;
        esac
    else
        warn "jq not available; skipping detailed metric extraction"
    fi

    # Return as a colon-separated string
    echo "${bw_mbs}:${iops}:${lat_avg_us}:${lat_p50_us}:${lat_p95_us}:${lat_p99_us}"
}

# Run a single fio workload and return extracted metrics.
# Usage: run_fio_workload <name> <rw> <bs> <size> <numjobs> <extra_opts...>
run_fio_workload() {
    local name="$1"
    local rw="$2"
    local bs="$3"
    local size="$4"
    local numjobs="$5"
    shift 5
    local extra_opts=("$@")

    local fio_json="$FIO_DIR/fio_${name}.json"
    local fio_output="$FIO_DIR/fio_${name}_data"
    CLEANUP_FILES+=("$fio_json" "$fio_output")

    info "Running workload: ${BOLD}$name${NC}"
    info "  rw=$rw bs=$bs size=$size numjobs=$numjobs"

    local fio_cmd=(
        fio
        --name="$name"
        --directory="$FIO_DIR"
        --rw="$rw"
        --bs="$bs"
        --size="$size"
        --numjobs="$numjobs"
        --time_based=0
        --group_reporting
        --output-format=json
        --output="$fio_json"
        --ioengine=posixaio
        --direct=1
        --percentile_list=50:95:99
    )

    # Append any extra options
    if [ ${#extra_opts[@]} -gt 0 ]; then
        fio_cmd+=("${extra_opts[@]}")
    fi

    if ! "${fio_cmd[@]}" 2>/dev/null; then
        warn "fio workload '$name' failed; trying without direct I/O"
        # Retry without direct I/O (some mounted filesystems don't support it)
        fio_cmd=("${fio_cmd[@]/--direct=1/--direct=0}")
        if ! "${fio_cmd[@]}" 2>/dev/null; then
            err "fio workload '$name' failed"
            echo "0:0:0:0:0:0"
            return 1
        fi
    fi

    # Determine rw_type for metric extraction
    local rw_type
    case "$rw" in
        read|randread)  rw_type="read" ;;
        write|randwrite) rw_type="write" ;;
        randrw|readwrite) rw_type="mixed" ;;
        *)              rw_type="read" ;;
    esac

    local metrics
    metrics=$(extract_metrics "$fio_json" "$rw_type")
    ok "Completed: $name"
    echo "$metrics"
}

# ---------------------------------------------------------------------------
# Workload definitions
# ---------------------------------------------------------------------------

run_all_workloads() {
    local -a workload_names=()
    local -a workload_metrics=()

    info "============================================================"
    info " Starting ksmbd benchmark suite"
    info " Mount point : $MOUNT_POINT"
    info " Test dir    : $FIO_DIR"
    info " Output file : $OUTPUT_FILE"
    info " Quick mode  : $([ "$QUICK_MODE" -eq 1 ] && echo "yes" || echo "no")"
    info "============================================================"
    echo ""

    # Workload 1: Sequential read
    local metrics
    workload_names+=("Sequential Read")
    info "--- Workload 1/7: Sequential Read ---"
    # Pre-create file for read test
    fio --name=precreate --directory="$FIO_DIR" --rw=write --bs=1M \
        --size="$SEQ_SIZE" --numjobs=1 --ioengine=posixaio --direct=1 \
        >/dev/null 2>&1 || true
    metrics=$(run_fio_workload "seq_read" "read" "1M" "$SEQ_SIZE" 1)
    workload_metrics+=("$metrics")
    echo ""

    # Workload 2: Sequential write
    workload_names+=("Sequential Write")
    info "--- Workload 2/7: Sequential Write ---"
    metrics=$(run_fio_workload "seq_write" "write" "1M" "$SEQ_SIZE" 1)
    workload_metrics+=("$metrics")
    echo ""

    # Workload 3: Random read 4K
    workload_names+=("Random Read 4K")
    info "--- Workload 3/7: Random Read 4K ---"
    # Pre-create file for random read
    fio --name=precreate_rand --directory="$FIO_DIR" --rw=write --bs=1M \
        --size="$RAND_SIZE" --numjobs=1 --ioengine=posixaio --direct=1 \
        >/dev/null 2>&1 || true
    metrics=$(run_fio_workload "rand_read_4k" "randread" "4k" "$RAND_SIZE" 4)
    workload_metrics+=("$metrics")
    echo ""

    # Workload 4: Random write 4K
    workload_names+=("Random Write 4K")
    info "--- Workload 4/7: Random Write 4K ---"
    metrics=$(run_fio_workload "rand_write_4k" "randwrite" "4k" "$RAND_SIZE" 4)
    workload_metrics+=("$metrics")
    echo ""

    # Workload 5: Mixed random 70/30 read/write
    workload_names+=("Mixed Random 70/30")
    info "--- Workload 5/7: Mixed Random 70/30 ---"
    metrics=$(run_fio_workload "mixed_rand_70_30" "randrw" "4k" "$RAND_SIZE" 4 \
        --rwmixread=70)
    workload_metrics+=("$metrics")
    echo ""

    # Workload 6: Metadata operations
    workload_names+=("Metadata Ops")
    info "--- Workload 6/7: Metadata Operations ---"
    local meta_dir="$FIO_DIR/metadata_test"
    mkdir -p "$meta_dir"
    CLEANUP_FILES+=("$meta_dir")
    local meta_json="$FIO_DIR/fio_metadata.json"
    CLEANUP_FILES+=("$meta_json")

    fio --name=metadata_ops \
        --directory="$meta_dir" \
        --rw=randwrite \
        --bs=4k \
        --filesize="$META_FILESIZE" \
        --nrfiles="$META_NRFILES" \
        --numjobs=1 \
        --group_reporting \
        --output-format=json \
        --output="$meta_json" \
        --ioengine=posixaio \
        --openfiles=10 \
        --file_service_type=sequential \
        --create_on_open=1 \
        --fallocate=none \
        --percentile_list=50:95:99 \
        2>/dev/null || true

    local meta_metrics="0:0:0:0:0:0"
    if [ -f "$meta_json" ] && command -v jq >/dev/null 2>&1; then
        local meta_iops
        meta_iops=$(jq -r '.jobs[0].write.iops // 0' "$meta_json" | awk '{printf "%.0f", $1}')
        local meta_bw
        meta_bw=$(jq -r '.jobs[0].write.bw_bytes // 0' "$meta_json" | awk '{printf "%.2f", $1/1048576}')
        local meta_lat_avg
        meta_lat_avg=$(jq -r '.jobs[0].write.lat_ns.mean // 0' "$meta_json" | awk '{printf "%.2f", $1/1000}')
        local meta_lat_p50
        meta_lat_p50=$(jq -r '.jobs[0].write.clat_ns.percentile."50.000000" // 0' "$meta_json" | awk '{printf "%.2f", $1/1000}')
        local meta_lat_p95
        meta_lat_p95=$(jq -r '.jobs[0].write.clat_ns.percentile."95.000000" // 0' "$meta_json" | awk '{printf "%.2f", $1/1000}')
        local meta_lat_p99
        meta_lat_p99=$(jq -r '.jobs[0].write.clat_ns.percentile."99.000000" // 0' "$meta_json" | awk '{printf "%.2f", $1/1000}')
        meta_metrics="${meta_bw}:${meta_iops}:${meta_lat_avg}:${meta_lat_p50}:${meta_lat_p95}:${meta_lat_p99}"
    fi
    workload_metrics+=("$meta_metrics")
    ok "Completed: Metadata Ops"
    echo ""

    # Workload 7: Large sequential read
    workload_names+=("Large Sequential Read")
    info "--- Workload 7/7: Large Sequential Read ---"
    # Pre-create large file
    fio --name=precreate_large --directory="$FIO_DIR" --rw=write --bs=1M \
        --size="$LARGE_SIZE" --numjobs=1 --ioengine=posixaio --direct=1 \
        >/dev/null 2>&1 || true
    metrics=$(run_fio_workload "large_seq_read" "read" "1M" "$LARGE_SIZE" 1)
    workload_metrics+=("$metrics")
    echo ""

    # Print results
    print_results_table workload_names workload_metrics
    write_json_results workload_names workload_metrics
}

# ---------------------------------------------------------------------------
# Output: formatted table
# ---------------------------------------------------------------------------
print_results_table() {
    local -n names_ref=$1
    local -n metrics_ref=$2

    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}                   BENCHMARK RESULTS                        ${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    # Table header
    printf "${BOLD}%-22s %12s %12s %12s %12s %12s %12s${NC}\n" \
        "Workload" "BW (MB/s)" "IOPS" "Lat Avg(us)" "Lat p50(us)" "Lat p95(us)" "Lat p99(us)"
    printf "%-22s %12s %12s %12s %12s %12s %12s\n" \
        "----------------------" "------------" "------------" "------------" "------------" "------------" "------------"

    for i in "${!names_ref[@]}"; do
        local name="${names_ref[$i]}"
        local m="${metrics_ref[$i]}"
        IFS=':' read -r bw iops lat_avg lat_p50 lat_p95 lat_p99 <<< "$m"

        printf "%-22s %12s %12s %12s %12s %12s %12s\n" \
            "$name" "$bw" "$iops" "$lat_avg" "$lat_p50" "$lat_p95" "$lat_p99"
    done

    echo ""
    echo -e "${GREEN}Results saved to: $OUTPUT_FILE${NC}"
}

# ---------------------------------------------------------------------------
# Output: JSON results
# ---------------------------------------------------------------------------
write_json_results() {
    local -n names_ref=$1
    local -n metrics_ref=$2

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local kernel_ver
    kernel_ver=$(uname -r 2>/dev/null || echo "unknown")

    # Build JSON manually for portability (jq might not be available)
    {
        echo "{"
        echo "  \"benchmark\": \"ksmbd-fio-suite\","
        echo "  \"version\": \"1.0.0\","
        echo "  \"timestamp\": \"$timestamp\","
        echo "  \"hostname\": \"$hostname_val\","
        echo "  \"kernel\": \"$kernel_ver\","
        echo "  \"mount_point\": \"$MOUNT_POINT\","
        echo "  \"quick_mode\": $([ "$QUICK_MODE" -eq 1 ] && echo "true" || echo "false"),"
        echo "  \"workloads\": ["

        for i in "${!names_ref[@]}"; do
            local name="${names_ref[$i]}"
            local m="${metrics_ref[$i]}"
            IFS=':' read -r bw iops lat_avg lat_p50 lat_p95 lat_p99 <<< "$m"

            local comma=","
            if [ "$i" -eq $(( ${#names_ref[@]} - 1 )) ]; then
                comma=""
            fi

            echo "    {"
            echo "      \"name\": \"$name\","
            echo "      \"bandwidth_mbps\": $bw,"
            echo "      \"iops\": $iops,"
            echo "      \"latency_avg_us\": $lat_avg,"
            echo "      \"latency_p50_us\": $lat_p50,"
            echo "      \"latency_p95_us\": $lat_p95,"
            echo "      \"latency_p99_us\": $lat_p99"
            echo "    }$comma"
        done

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"

    if [ -z "$MOUNT_POINT" ]; then
        err "Mount point is required."
        echo ""
        usage
        exit 1
    fi

    check_prerequisites
    apply_size_settings
    validate_mount

    run_all_workloads

    ok "Benchmark suite complete."
}

main "$@"
