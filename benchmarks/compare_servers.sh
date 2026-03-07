#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Server comparison benchmark: ksmbd vs Samba vs NFS
#
# Runs identical fio workloads against multiple server mount points
# and produces a side-by-side comparison table with percentage differences.
#
# Prerequisites:
#   - fio (>= 3.0)
#   - jq (for JSON parsing)
#   - Mounted shares for each server to compare
#   - run_benchmarks.sh in the same directory
#
# Usage:
#   ./compare_servers.sh --ksmbd /mnt/ksmbd --samba /mnt/samba --nfs /mnt/nfs
#   ./compare_servers.sh --ksmbd /mnt/ksmbd --samba /mnt/samba  # NFS optional

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
KSMBD_MOUNT=""
SAMBA_MOUNT=""
NFS_MOUNT=""
QUICK_MODE=0
OUTPUT_FILE=""
SCRIPT_DIR=""
TEMP_DIR=""
SIZE_OVERRIDE=""

# Workload names matching run_benchmarks.sh output
WORKLOAD_NAMES=(
    "Sequential Read"
    "Sequential Write"
    "Random Read 4K"
    "Random Write 4K"
    "Mixed Random 70/30"
    "Metadata Ops"
    "Large Sequential Read"
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
${BOLD}Usage:${NC} $(basename "$0") --ksmbd PATH [--samba PATH] [--nfs PATH] [OPTIONS]

${BOLD}Server comparison benchmark: ksmbd vs Samba vs NFS${NC}

Runs identical fio workloads against multiple server mount points and produces
a side-by-side comparison table with percentage differences.

${BOLD}Required:${NC}
  --ksmbd PATH        Mount point for ksmbd share

${BOLD}Optional servers:${NC}
  --samba PATH        Mount point for Samba share
  --nfs PATH          Mount point for NFS share

  At least one of --samba or --nfs must be provided for comparison.

${BOLD}Options:${NC}
  --size SIZE         Override default file sizes (passed to run_benchmarks.sh)
  --output FILE       JSON output file for comparison results
  --quick             Use reduced sizes for fast runs (passed to run_benchmarks.sh)
  --help              Show this help message

${BOLD}Examples:${NC}
  $(basename "$0") --ksmbd /mnt/ksmbd --samba /mnt/samba --nfs /mnt/nfs
  $(basename "$0") --ksmbd /mnt/ksmbd --samba /mnt/samba --quick
  $(basename "$0") --ksmbd /mnt/ksmbd --nfs /mnt/nfs --output compare.json
EOF
}

cleanup() {
    local exit_code=$?
    info "Cleaning up temporary files..."
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
    if [ $exit_code -ne 0 ]; then
        warn "Comparison exited with code $exit_code"
    fi
}

trap cleanup EXIT

check_prerequisites() {
    local missing=0

    if ! command -v fio >/dev/null 2>&1; then
        err "fio is not installed. Install with: apt-get install fio"
        missing=1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        err "jq is required for comparison. Install with: apt-get install jq"
        missing=1
    fi

    # Find run_benchmarks.sh
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ ! -x "$SCRIPT_DIR/run_benchmarks.sh" ]; then
        err "run_benchmarks.sh not found or not executable in $SCRIPT_DIR"
        err "Ensure run_benchmarks.sh exists alongside this script."
        missing=1
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
            --ksmbd)
                shift
                KSMBD_MOUNT="${1:-}"
                if [ -z "$KSMBD_MOUNT" ]; then
                    err "--ksmbd requires a PATH argument"
                    exit 1
                fi
                ;;
            --samba)
                shift
                SAMBA_MOUNT="${1:-}"
                if [ -z "$SAMBA_MOUNT" ]; then
                    err "--samba requires a PATH argument"
                    exit 1
                fi
                ;;
            --nfs)
                shift
                NFS_MOUNT="${1:-}"
                if [ -z "$NFS_MOUNT" ]; then
                    err "--nfs requires a PATH argument"
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

validate_args() {
    if [ -z "$KSMBD_MOUNT" ]; then
        err "--ksmbd mount point is required."
        echo ""
        usage
        exit 1
    fi

    if [ -z "$SAMBA_MOUNT" ] && [ -z "$NFS_MOUNT" ]; then
        err "At least one of --samba or --nfs must be provided for comparison."
        echo ""
        usage
        exit 1
    fi

    # Validate mount points exist
    for label_mount in "ksmbd:$KSMBD_MOUNT" ${SAMBA_MOUNT:+"samba:$SAMBA_MOUNT"} ${NFS_MOUNT:+"nfs:$NFS_MOUNT"}; do
        local label="${label_mount%%:*}"
        local mnt="${label_mount#*:}"
        if [ ! -d "$mnt" ]; then
            err "$label mount point does not exist: $mnt"
            exit 1
        fi
    done

    # Setup temp directory
    TEMP_DIR=$(mktemp -d "/tmp/ksmbd_compare_XXXXXX")

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="comparison_$(date +%Y%m%d_%H%M%S).json"
    fi
}

# ---------------------------------------------------------------------------
# Run benchmarks for a single server
# ---------------------------------------------------------------------------
run_server_benchmark() {
    local server_name="$1"
    local mount_point="$2"
    local result_file="$TEMP_DIR/${server_name}_results.json"

    info "============================================================"
    info " Running benchmarks for: ${BOLD}${server_name}${NC}"
    info " Mount point: $mount_point"
    info "============================================================"
    echo ""

    local bench_args=(
        --mount "$mount_point"
        --output "$result_file"
    )

    if [ "$QUICK_MODE" -eq 1 ]; then
        bench_args+=(--quick)
    fi

    if [ -n "$SIZE_OVERRIDE" ]; then
        bench_args+=(--size "$SIZE_OVERRIDE")
    fi

    if ! "$SCRIPT_DIR/run_benchmarks.sh" "${bench_args[@]}"; then
        warn "Benchmark for $server_name finished with errors"
    fi

    echo ""
    echo "$result_file"
}

# ---------------------------------------------------------------------------
# Extract bandwidth values from a JSON results file
# Returns a space-separated list of BW values, one per workload
# ---------------------------------------------------------------------------
extract_bw_values() {
    local json_file="$1"

    if [ ! -f "$json_file" ]; then
        # Return zeros for all workloads
        for _ in "${WORKLOAD_NAMES[@]}"; do
            printf "0 "
        done
        return
    fi

    local count
    count=$(jq -r '.workloads | length' "$json_file" 2>/dev/null || echo "0")

    for i in $(seq 0 $(( count - 1 ))); do
        local bw
        bw=$(jq -r ".workloads[$i].bandwidth_mbps // 0" "$json_file" 2>/dev/null || echo "0")
        printf "%s " "$bw"
    done
}

# Extract IOPS values from a JSON results file
extract_iops_values() {
    local json_file="$1"

    if [ ! -f "$json_file" ]; then
        for _ in "${WORKLOAD_NAMES[@]}"; do
            printf "0 "
        done
        return
    fi

    local count
    count=$(jq -r '.workloads | length' "$json_file" 2>/dev/null || echo "0")

    for i in $(seq 0 $(( count - 1 ))); do
        local iops
        iops=$(jq -r ".workloads[$i].iops // 0" "$json_file" 2>/dev/null || echo "0")
        printf "%s " "$iops"
    done
}

# Calculate percentage difference: ((new - base) / base) * 100
# Usage: calc_pct_diff <ksmbd_val> <other_val>
calc_pct_diff() {
    local ksmbd_val="$1"
    local other_val="$2"

    if [ "$other_val" = "0" ] || [ "$other_val" = "0.00" ]; then
        echo "N/A"
        return
    fi

    awk "BEGIN {
        diff = (($ksmbd_val - $other_val) / $other_val) * 100;
        if (diff >= 0)
            printf \"+%.1f%%\", diff;
        else
            printf \"%.1f%%\", diff;
    }"
}

# Colorize a percentage string
colorize_pct() {
    local pct_str="$1"

    if [ "$pct_str" = "N/A" ] || [ "$pct_str" = "-" ]; then
        echo -e "${YELLOW}${pct_str}${NC}"
        return
    fi

    # Check if positive or negative
    if [[ "$pct_str" == +* ]]; then
        echo -e "${GREEN}${pct_str}${NC}"
    elif [[ "$pct_str" == -* ]]; then
        echo -e "${RED}${pct_str}${NC}"
    else
        echo -e "${YELLOW}${pct_str}${NC}"
    fi
}

# ---------------------------------------------------------------------------
# Print comparison table
# ---------------------------------------------------------------------------
print_comparison_table() {
    local ksmbd_json="$1"
    local samba_json="${2:-}"
    local nfs_json="${3:-}"

    # Read bandwidth values into arrays
    local -a ksmbd_bw
    read -ra ksmbd_bw <<< "$(extract_bw_values "$ksmbd_json")"

    local -a samba_bw=()
    local -a nfs_bw=()

    local has_samba=0
    local has_nfs=0

    if [ -n "$samba_json" ] && [ -f "$samba_json" ]; then
        read -ra samba_bw <<< "$(extract_bw_values "$samba_json")"
        has_samba=1
    fi

    if [ -n "$nfs_json" ] && [ -f "$nfs_json" ]; then
        read -ra nfs_bw <<< "$(extract_bw_values "$nfs_json")"
        has_nfs=1
    fi

    echo ""
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}            SERVER COMPARISON RESULTS (Bandwidth)           ${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    # Build header dynamically
    local header
    header=$(printf "${BOLD}%-22s %14s" "Workload" "ksmbd (MB/s)")
    if [ $has_samba -eq 1 ]; then
        header+=$(printf " %14s %16s" "Samba (MB/s)" "ksmbd vs Samba")
    fi
    if [ $has_nfs -eq 1 ]; then
        header+=$(printf " %14s %16s" "NFS (MB/s)" "ksmbd vs NFS")
    fi
    header+="${NC}"
    echo -e "$header"

    local separator
    separator=$(printf "%-22s %14s" "----------------------" "--------------")
    if [ $has_samba -eq 1 ]; then
        separator+=$(printf " %14s %16s" "--------------" "----------------")
    fi
    if [ $has_nfs -eq 1 ]; then
        separator+=$(printf " %14s %16s" "--------------" "----------------")
    fi
    echo "$separator"

    # Print rows
    for i in "${!WORKLOAD_NAMES[@]}"; do
        local name="${WORKLOAD_NAMES[$i]}"
        local kbw="${ksmbd_bw[$i]:-0}"
        local row
        row=$(printf "%-22s %14s" "$name" "$kbw")

        if [ $has_samba -eq 1 ]; then
            local sbw="${samba_bw[$i]:-0}"
            local pct
            pct=$(calc_pct_diff "$kbw" "$sbw")
            local cpct
            cpct=$(colorize_pct "$pct")
            row+=$(printf " %14s " "$sbw")
            # Use echo -e for color codes in the pct column
            echo -en "$row"
            printf "%16b" "$cpct"
            row=""
        fi

        if [ $has_nfs -eq 1 ]; then
            local nbw="${nfs_bw[$i]:-0}"
            local pct
            pct=$(calc_pct_diff "$kbw" "$nbw")
            local cpct
            cpct=$(colorize_pct "$pct")
            if [ -n "$row" ]; then
                echo -en "$row"
                row=""
            fi
            printf " %14s " "$nbw"
            printf "%16b" "$cpct"
        fi

        if [ -n "$row" ]; then
            echo -en "$row"
        fi
        echo ""
    done

    echo ""

    # Also print IOPS comparison
    echo -e "${BOLD}============================================================${NC}"
    echo -e "${BOLD}              SERVER COMPARISON RESULTS (IOPS)              ${NC}"
    echo -e "${BOLD}============================================================${NC}"
    echo ""

    local -a ksmbd_iops
    read -ra ksmbd_iops <<< "$(extract_iops_values "$ksmbd_json")"

    local -a samba_iops=()
    local -a nfs_iops=()

    if [ $has_samba -eq 1 ]; then
        read -ra samba_iops <<< "$(extract_iops_values "$samba_json")"
    fi
    if [ $has_nfs -eq 1 ]; then
        read -ra nfs_iops <<< "$(extract_iops_values "$nfs_json")"
    fi

    header=$(printf "${BOLD}%-22s %14s" "Workload" "ksmbd (IOPS)")
    if [ $has_samba -eq 1 ]; then
        header+=$(printf " %14s %16s" "Samba (IOPS)" "ksmbd vs Samba")
    fi
    if [ $has_nfs -eq 1 ]; then
        header+=$(printf " %14s %16s" "NFS (IOPS)" "ksmbd vs NFS")
    fi
    header+="${NC}"
    echo -e "$header"
    echo "$separator"

    for i in "${!WORKLOAD_NAMES[@]}"; do
        local name="${WORKLOAD_NAMES[$i]}"
        local kiops="${ksmbd_iops[$i]:-0}"
        local row
        row=$(printf "%-22s %14s" "$name" "$kiops")

        if [ $has_samba -eq 1 ]; then
            local siops="${samba_iops[$i]:-0}"
            local pct
            pct=$(calc_pct_diff "$kiops" "$siops")
            local cpct
            cpct=$(colorize_pct "$pct")
            row+=$(printf " %14s " "$siops")
            echo -en "$row"
            printf "%16b" "$cpct"
            row=""
        fi

        if [ $has_nfs -eq 1 ]; then
            local niops="${nfs_iops[$i]:-0}"
            local pct
            pct=$(calc_pct_diff "$kiops" "$niops")
            local cpct
            cpct=$(colorize_pct "$pct")
            if [ -n "$row" ]; then
                echo -en "$row"
                row=""
            fi
            printf " %14s " "$niops"
            printf "%16b" "$cpct"
        fi

        if [ -n "$row" ]; then
            echo -en "$row"
        fi
        echo ""
    done

    echo ""
}

# ---------------------------------------------------------------------------
# Write comparison JSON
# ---------------------------------------------------------------------------
write_comparison_json() {
    local ksmbd_json="$1"
    local samba_json="${2:-}"
    local nfs_json="${3:-}"

    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local kernel_ver
    kernel_ver=$(uname -r 2>/dev/null || echo "unknown")

    local -a ksmbd_bw ksmbd_iops
    read -ra ksmbd_bw <<< "$(extract_bw_values "$ksmbd_json")"
    read -ra ksmbd_iops <<< "$(extract_iops_values "$ksmbd_json")"

    local has_samba=0
    local has_nfs=0
    local -a samba_bw samba_iops nfs_bw nfs_iops

    if [ -n "$samba_json" ] && [ -f "$samba_json" ]; then
        read -ra samba_bw <<< "$(extract_bw_values "$samba_json")"
        read -ra samba_iops <<< "$(extract_iops_values "$samba_json")"
        has_samba=1
    fi

    if [ -n "$nfs_json" ] && [ -f "$nfs_json" ]; then
        read -ra nfs_bw <<< "$(extract_bw_values "$nfs_json")"
        read -ra nfs_iops <<< "$(extract_iops_values "$nfs_json")"
        has_nfs=1
    fi

    {
        echo "{"
        echo "  \"benchmark\": \"ksmbd-server-comparison\","
        echo "  \"version\": \"1.0.0\","
        echo "  \"timestamp\": \"$timestamp\","
        echo "  \"hostname\": \"$hostname_val\","
        echo "  \"kernel\": \"$kernel_ver\","
        echo "  \"servers\": {"
        echo "    \"ksmbd\": \"$KSMBD_MOUNT\""
        [ $has_samba -eq 1 ] && echo "    ,\"samba\": \"$SAMBA_MOUNT\""
        [ $has_nfs -eq 1 ] && echo "    ,\"nfs\": \"$NFS_MOUNT\""
        echo "  },"
        echo "  \"quick_mode\": $([ "$QUICK_MODE" -eq 1 ] && echo "true" || echo "false"),"
        echo "  \"comparison\": ["

        for i in "${!WORKLOAD_NAMES[@]}"; do
            local name="${WORKLOAD_NAMES[$i]}"
            local kbw="${ksmbd_bw[$i]:-0}"
            local kiops="${ksmbd_iops[$i]:-0}"

            local comma=","
            if [ "$i" -eq $(( ${#WORKLOAD_NAMES[@]} - 1 )) ]; then
                comma=""
            fi

            echo "    {"
            echo "      \"workload\": \"$name\","
            echo "      \"ksmbd\": { \"bandwidth_mbps\": $kbw, \"iops\": $kiops }"

            if [ $has_samba -eq 1 ]; then
                local sbw="${samba_bw[$i]:-0}"
                local siops="${samba_iops[$i]:-0}"
                local bw_pct
                bw_pct=$(calc_pct_diff "$kbw" "$sbw")
                echo "      ,\"samba\": { \"bandwidth_mbps\": $sbw, \"iops\": $siops }"
                echo "      ,\"ksmbd_vs_samba_bw\": \"$bw_pct\""
            fi

            if [ $has_nfs -eq 1 ]; then
                local nbw="${nfs_bw[$i]:-0}"
                local niops="${nfs_iops[$i]:-0}"
                local bw_pct
                bw_pct=$(calc_pct_diff "$kbw" "$nbw")
                echo "      ,\"nfs\": { \"bandwidth_mbps\": $nbw, \"iops\": $niops }"
                echo "      ,\"ksmbd_vs_nfs_bw\": \"$bw_pct\""
            fi

            echo "    }$comma"
        done

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    ok "Comparison JSON written to: $OUTPUT_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    parse_args "$@"
    validate_args
    check_prerequisites

    info "============================================================"
    info " Server Comparison Benchmark"
    info " ksmbd : $KSMBD_MOUNT"
    [ -n "$SAMBA_MOUNT" ] && info " Samba : $SAMBA_MOUNT"
    [ -n "$NFS_MOUNT" ]   && info " NFS   : $NFS_MOUNT"
    info " Quick : $([ "$QUICK_MODE" -eq 1 ] && echo "yes" || echo "no")"
    info " Output: $OUTPUT_FILE"
    info "============================================================"
    echo ""

    # Run ksmbd benchmarks
    local ksmbd_result
    ksmbd_result=$(run_server_benchmark "ksmbd" "$KSMBD_MOUNT" | tail -1)

    # Run samba benchmarks (if mount provided)
    local samba_result=""
    if [ -n "$SAMBA_MOUNT" ]; then
        samba_result=$(run_server_benchmark "samba" "$SAMBA_MOUNT" | tail -1)
    fi

    # Run NFS benchmarks (if mount provided)
    local nfs_result=""
    if [ -n "$NFS_MOUNT" ]; then
        nfs_result=$(run_server_benchmark "nfs" "$NFS_MOUNT" | tail -1)
    fi

    # Print comparison
    print_comparison_table "$ksmbd_result" "$samba_result" "$nfs_result"

    # Write JSON
    write_comparison_json "$ksmbd_result" "$samba_result" "$nfs_result"

    ok "Server comparison complete."
}

main "$@"
