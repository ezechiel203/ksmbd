#!/bin/bash
# perf_baseline.sh -- Comprehensive performance benchmark suite for ksmbd
#
# Runs standardized performance benchmarks against a ksmbd server and records
# results in JSON format suitable for regression tracking.
#
# Usage:
#   ./perf_baseline.sh [OPTIONS]
#
# Options:
#   --vm VM3|VM4            Target VM (sets ports automatically)
#   --port PORT             SMB port override
#   --ssh-port PORT         SSH port override
#   --host HOST             SMB host override
#   --share NAME            Share name (default: test)
#   --output FILE           JSON output file (default: auto-named)
#   --work-dir DIR          Working directory for temp files
#   --client smbclient|mount.cifs  Client tool preference
#   --iterations N          Repeat each test N times (default: 3)
#   --skip-throughput       Skip sequential throughput tests
#   --skip-iops             Skip random I/O tests
#   --skip-dir              Skip directory enumeration tests
#   --skip-create           Skip file creation rate tests
#   --skip-metadata         Skip metadata operation tests
#   --skip-smallfile        Skip small file transfer tests
#   --skip-connection       Skip connection rate tests
#   --skip-concurrent       Skip concurrent client tests
#   --only BENCH[,BENCH]    Run only specified benchmarks
#   --quick                 Quick mode: fewer iterations, smaller files
#   --help                  Show this help
#
# Exit codes:
#   0  All benchmarks completed successfully
#   1  One or more benchmarks failed
#   2  Infrastructure error (VM unreachable, tool missing)

set -uo pipefail

# ---------------------------------------------------------------------------
# Determine script location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/perf_config.sh"

# ---------------------------------------------------------------------------
# CLI Parsing
# ---------------------------------------------------------------------------
SKIP_THROUGHPUT="no"
SKIP_IOPS="no"
SKIP_DIR="no"
SKIP_CREATE="no"
SKIP_METADATA="no"
SKIP_SMALLFILE="no"
SKIP_CONNECTION="no"
SKIP_CONCURRENT="no"
ONLY_BENCHMARKS=""
QUICK_MODE="no"

usage() {
    sed -n '2,/^$/s/^# //p' "$0"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vm)
            case "$2" in
                VM3|vm3) PERF_VM_SSH_PORT=13022; PERF_SMB_PORT=13445; PERF_VM_NAME="VM3" ;;
                VM4|vm4) PERF_VM_SSH_PORT=14022; PERF_SMB_PORT=14445; PERF_VM_NAME="VM4" ;;
                *) echo "Unknown VM: $2" >&2; exit 2 ;;
            esac
            shift 2 ;;
        --port)             PERF_SMB_PORT="$2"; shift 2 ;;
        --ssh-port)         PERF_VM_SSH_PORT="$2"; shift 2 ;;
        --host)             PERF_SMB_HOST="$2"; PERF_VM_HOST="$2"; shift 2 ;;
        --share)            PERF_SMB_SHARE="$2"; shift 2 ;;
        --output)           PERF_OUTPUT_FILE="$2"; shift 2 ;;
        --work-dir)         PERF_WORK_DIR="$2"; shift 2 ;;
        --client)           PERF_CLIENT_TOOL="$2"; shift 2 ;;
        --iterations)       PERF_ITERATIONS="$2"; shift 2 ;;
        --skip-throughput)  SKIP_THROUGHPUT="yes"; shift ;;
        --skip-iops)        SKIP_IOPS="yes"; shift ;;
        --skip-dir)         SKIP_DIR="yes"; shift ;;
        --skip-create)      SKIP_CREATE="yes"; shift ;;
        --skip-metadata)    SKIP_METADATA="yes"; shift ;;
        --skip-smallfile)   SKIP_SMALLFILE="yes"; shift ;;
        --skip-connection)  SKIP_CONNECTION="yes"; shift ;;
        --skip-concurrent)  SKIP_CONCURRENT="yes"; shift ;;
        --only)             ONLY_BENCHMARKS="$2"; shift 2 ;;
        --quick)            QUICK_MODE="yes"; shift ;;
        --help|-h)          usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

# Quick mode overrides
if [[ "$QUICK_MODE" == "yes" ]]; then
    PERF_ITERATIONS=1
    PERF_WARMUP_RUNS=0
    PERF_SEQ_FILE_SIZES="1048576 10485760"
    PERF_SEQ_FILE_LABELS="1MB 10MB"
    PERF_DIR_COUNTS="100 1000"
    PERF_CREATE_FILE_COUNT=200
    PERF_METADATA_FILE_COUNT=200
    PERF_SMALL_FILE_COUNT=200
    PERF_CONN_ITERATIONS=20
    PERF_CONCURRENT_CLIENTS="1 2 4"
    PERF_CONCURRENT_FILE_SIZE=10485760
    PERF_RAND_DURATION=10
fi

# ---------------------------------------------------------------------------
# Working directory and output setup
# ---------------------------------------------------------------------------
mkdir -p "$PERF_WORK_DIR"
trap 'rm -rf "$PERF_WORK_DIR"' EXIT

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$PERF_OUTPUT_FILE" ]]; then
    PERF_OUTPUT_FILE="${PERF_BASELINES_DIR}/baseline_${TIMESTAMP}.json"
fi
mkdir -p "$(dirname "$PERF_OUTPUT_FILE")"

LOG_FILE="${PERF_WORK_DIR}/perf_baseline.log"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()  { echo "[$(date '+%H:%M:%S')] INFO  $*" | tee -a "$LOG_FILE" >&2; }
log_warn()  { echo "[$(date '+%H:%M:%S')] WARN  $*" | tee -a "$LOG_FILE" >&2; }
log_error() { echo "[$(date '+%H:%M:%S')] ERROR $*" | tee -a "$LOG_FILE" >&2; }
log_bench() { echo "[$(date '+%H:%M:%S')] BENCH $*" | tee -a "$LOG_FILE" >&2; }

# ---------------------------------------------------------------------------
# Results Collection
# ---------------------------------------------------------------------------
declare -a RESULT_NAMES=()
declare -a RESULT_VALUES=()
declare -a RESULT_UNITS=()
declare -a RESULT_CATEGORIES=()
BENCH_PASS=0
BENCH_FAIL=0
BENCH_SKIP=0

record_result() {
    local name="$1" value="$2" unit="$3" category="$4"
    RESULT_NAMES+=("$name")
    RESULT_VALUES+=("$value")
    RESULT_UNITS+=("$unit")
    RESULT_CATEGORIES+=("$category")
    log_bench "$name = $value $unit"
    ((BENCH_PASS++))
}

record_error() {
    local name="$1" reason="$2" category="$3"
    RESULT_NAMES+=("$name")
    RESULT_VALUES+=("ERROR")
    RESULT_UNITS+=("")
    RESULT_CATEGORIES+=("$category")
    log_error "$name: $reason"
    ((BENCH_FAIL++))
}

record_skip() {
    local name="$1" reason="$2"
    log_warn "SKIP: $name -- $reason"
    ((BENCH_SKIP++))
}

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
now_ns() { date +%s%N; }

now_secs() { date +%s.%N; }

elapsed_secs() {
    local start="$1" end="$2"
    awk "BEGIN { printf \"%.6f\", $end - $start }"
}

calc_mbps() {
    local size_bytes="$1" duration_secs="$2"
    awk "BEGIN { d = $duration_secs; if (d <= 0) print 0; else printf \"%.3f\", ($size_bytes / 1048576.0) / d }"
}

calc_ops() {
    local count="$1" duration_secs="$2"
    awk "BEGIN { d = $duration_secs; if (d <= 0) print 0; else printf \"%.3f\", $count / d }"
}

# Compute median of a list of numbers (one per line on stdin)
median_value() {
    sort -n | awk '{a[NR]=$1} END {
        if (NR%2) print a[(NR+1)/2];
        else printf "%.6f\n", (a[NR/2]+a[NR/2+1])/2
    }'
}

# smbclient wrapper
smb_cmd() {
    "$PERF_SMBCLIENT_BIN" "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" \
        -p "$PERF_SMB_PORT" -U "${PERF_SMB_CREDS}" \
        --option="client min protocol=${PERF_SMB_PROTOCOL}" \
        --option="client max protocol=${PERF_SMB_PROTOCOL}" \
        -c "$1" 2>>"$LOG_FILE"
}

# SSH wrapper
vm_exec() { perf_vm_exec "$@"; }

# Check if a benchmark should run
should_run() {
    local bench="$1"
    if [[ -n "$ONLY_BENCHMARKS" ]]; then
        echo ",$ONLY_BENCHMARKS," | grep -q ",$bench,"
        return $?
    fi
    return 0
}

# Create temporary file of given size
create_temp_file() {
    local path="$1" size_bytes="$2"
    dd if=/dev/urandom of="$path" bs=1048576 count=$((size_bytes / 1048576)) 2>/dev/null
    local remainder=$((size_bytes % 1048576))
    if [[ $remainder -gt 0 ]]; then
        dd if=/dev/urandom bs=1 count="$remainder" >> "$path" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight Checks
# ---------------------------------------------------------------------------
preflight() {
    log_info "=== ksmbd Performance Baseline Suite ==="
    log_info "Target: //${PERF_SMB_HOST}/${PERF_SMB_SHARE}:${PERF_SMB_PORT}"
    log_info "VM: ${PERF_VM_NAME} (SSH ${PERF_VM_SSH_PORT})"
    log_info "Timestamp: ${TIMESTAMP}"
    log_info "Iterations: ${PERF_ITERATIONS}"

    # Check required tools
    local missing=""
    for tool in smbclient sshpass awk sort; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing="${missing:+$missing, }$tool"
        fi
    done
    if [[ -n "$missing" ]]; then
        log_error "Missing required tools: $missing"
        exit 2
    fi

    # Check VM SSH
    log_info "Checking VM SSH connectivity..."
    if ! perf_vm_exec_timeout 5 "echo ok" 2>/dev/null | grep -q ok; then
        log_error "Cannot reach VM ${PERF_VM_NAME} via SSH"
        exit 2
    fi

    # Check SMB connectivity
    log_info "Checking SMB connectivity..."
    if ! smb_cmd "ls" >/dev/null 2>&1; then
        log_error "Cannot connect to //${PERF_SMB_HOST}/${PERF_SMB_SHARE}:${PERF_SMB_PORT}"
        exit 2
    fi

    log_info "Pre-flight checks passed"
}

# ---------------------------------------------------------------------------
# Collect System Information
# ---------------------------------------------------------------------------
collect_sysinfo() {
    log_info "Collecting system information..."

    SYSINFO_KERNEL="$(vm_exec 'uname -r' 2>/dev/null || echo 'unknown')"
    SYSINFO_ARCH="$(vm_exec 'uname -m' 2>/dev/null || echo 'unknown')"
    SYSINFO_HOSTNAME="$(vm_exec 'hostname' 2>/dev/null || echo 'unknown')"
    SYSINFO_CPU="$(vm_exec "grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //'" 2>/dev/null || echo 'unknown')"
    SYSINFO_CPU_CORES="$(vm_exec "nproc" 2>/dev/null || echo 'unknown')"
    SYSINFO_MEMORY_KB="$(vm_exec "grep MemTotal /proc/meminfo 2>/dev/null | awk '{print \$2}'" 2>/dev/null || echo 'unknown')"
    SYSINFO_KSMBD_VER="$(vm_exec "modinfo ksmbd 2>/dev/null | grep ^version | awk '{print \$2}'" 2>/dev/null || echo 'unknown')"

    # Git info from host
    SYSINFO_GIT_COMMIT="$(git -C "${SCRIPT_DIR}/../.." rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    SYSINFO_GIT_BRANCH="$(git -C "${SCRIPT_DIR}/../.." rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
    SYSINFO_GIT_DIRTY="$(git -C "${SCRIPT_DIR}/../.." diff --quiet 2>/dev/null && echo 'false' || echo 'true')"

    log_info "  Kernel: ${SYSINFO_KERNEL}"
    log_info "  CPU: ${SYSINFO_CPU} (${SYSINFO_CPU_CORES} cores)"
    log_info "  Memory: ${SYSINFO_MEMORY_KB}KB"
    log_info "  Git: ${SYSINFO_GIT_COMMIT} (${SYSINFO_GIT_BRANCH})"
}

# ---------------------------------------------------------------------------
# Cleanup server-side benchmark artifacts
# ---------------------------------------------------------------------------
cleanup_server() {
    log_info "Cleaning server-side benchmark artifacts..."
    vm_exec "rm -rf ${PERF_SHARE_ROOT}/perf_bench_* 2>/dev/null" 2>/dev/null
    smb_cmd "deltree perf_bench_throughput; deltree perf_bench_iops; deltree perf_bench_dir; deltree perf_bench_create; deltree perf_bench_meta; deltree perf_bench_small; deltree perf_bench_conn; deltree perf_bench_conc" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Benchmark: Sequential Throughput
# ---------------------------------------------------------------------------
bench_sequential_throughput() {
    if [[ "$SKIP_THROUGHPUT" == "yes" ]] || ! should_run "throughput"; then
        record_skip "sequential_throughput" "skipped by user"
        return
    fi

    log_info "--- Sequential Throughput ---"

    local -a sizes
    local -a labels
    read -ra sizes <<< "$PERF_SEQ_FILE_SIZES"
    read -ra labels <<< "$PERF_SEQ_FILE_LABELS"

    local idx=0
    for size_bytes in "${sizes[@]}"; do
        local label="${labels[$idx]:-${size_bytes}B}"
        ((idx++))

        # --- Sequential Write ---
        log_info "  Sequential write: ${label}..."
        local write_results=""
        local tmpfile="${PERF_WORK_DIR}/write_test_${label}"
        create_temp_file "$tmpfile" "$size_bytes"

        # Warmup
        local w
        for w in $(seq 1 "$PERF_WARMUP_RUNS"); do
            smb_cmd "put ${tmpfile} perf_bench_throughput_w_warmup" >/dev/null 2>&1
            smb_cmd "del perf_bench_throughput_w_warmup" >/dev/null 2>&1
        done

        local iter
        for iter in $(seq 1 "$PERF_ITERATIONS"); do
            local start end duration mbps
            start=$(now_secs)
            if smb_cmd "put ${tmpfile} perf_bench_throughput_w_${label}" >/dev/null 2>&1; then
                end=$(now_secs)
                duration=$(elapsed_secs "$start" "$end")
                mbps=$(calc_mbps "$size_bytes" "$duration")
                write_results="${write_results}${mbps}\n"
            else
                log_warn "  Write iteration $iter failed for ${label}"
            fi
            smb_cmd "del perf_bench_throughput_w_${label}" >/dev/null 2>&1
        done
        rm -f "$tmpfile"

        if [[ -n "$write_results" ]]; then
            local median
            median=$(printf '%b' "$write_results" | median_value)
            record_result "seq_write_${label}" "$median" "MB/s" "throughput"
        else
            record_error "seq_write_${label}" "all iterations failed" "throughput"
        fi

        # --- Sequential Read ---
        log_info "  Sequential read: ${label}..."
        local read_results=""

        # Create test file on server for reading
        vm_exec "dd if=/dev/urandom of=${PERF_SHARE_ROOT}/perf_bench_throughput_r_${label} bs=1048576 count=$((size_bytes / 1048576)) 2>/dev/null" 2>/dev/null

        # Warmup
        for w in $(seq 1 "$PERF_WARMUP_RUNS"); do
            smb_cmd "get perf_bench_throughput_r_${label} ${PERF_WORK_DIR}/read_warmup" >/dev/null 2>&1
            rm -f "${PERF_WORK_DIR}/read_warmup"
        done

        for iter in $(seq 1 "$PERF_ITERATIONS"); do
            local start end duration mbps
            local read_tmp="${PERF_WORK_DIR}/read_${label}_${iter}"
            start=$(now_secs)
            if smb_cmd "get perf_bench_throughput_r_${label} ${read_tmp}" >/dev/null 2>&1; then
                end=$(now_secs)
                duration=$(elapsed_secs "$start" "$end")
                local actual_size
                actual_size=$(stat -c%s "$read_tmp" 2>/dev/null || echo "$size_bytes")
                mbps=$(calc_mbps "$actual_size" "$duration")
                read_results="${read_results}${mbps}\n"
            else
                log_warn "  Read iteration $iter failed for ${label}"
            fi
            rm -f "$read_tmp"
        done

        vm_exec "rm -f ${PERF_SHARE_ROOT}/perf_bench_throughput_r_${label}" 2>/dev/null

        if [[ -n "$read_results" ]]; then
            local median
            median=$(printf '%b' "$read_results" | median_value)
            record_result "seq_read_${label}" "$median" "MB/s" "throughput"
        else
            record_error "seq_read_${label}" "all iterations failed" "throughput"
        fi
    done
}

# ---------------------------------------------------------------------------
# Benchmark: Random 4KB Read/Write IOPS
# ---------------------------------------------------------------------------
bench_random_iops() {
    if [[ "$SKIP_IOPS" == "yes" ]] || ! should_run "iops"; then
        record_skip "random_iops" "skipped by user"
        return
    fi

    log_info "--- Random 4KB IOPS ---"

    # Create test file on server
    local pool_size_mb=$((PERF_RAND_FILE_SIZE / 1048576))
    vm_exec "dd if=/dev/urandom of=${PERF_SHARE_ROOT}/perf_bench_iops_pool bs=1M count=${pool_size_mb} 2>/dev/null" 2>/dev/null

    # Check if fio is available on the host and mount.cifs is usable
    if [[ "$PERF_CLIENT_TOOL" == "mount.cifs" ]] && command -v fio >/dev/null 2>&1; then
        local mnt="${PERF_WORK_DIR}/iops_mount"
        mkdir -p "$mnt"

        if sudo mount -t cifs "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" "$mnt" \
            -o "port=${PERF_SMB_PORT},username=${PERF_SMB_USER},password=${PERF_SMB_PASS},vers=3.1.1" 2>/dev/null; then

            # Random read IOPS
            log_info "  Random 4KB read IOPS (fio)..."
            local fio_out
            fio_out=$(fio --name=rand_read --directory="$mnt" \
                --rw=randread --bs="${PERF_RAND_BLOCK_SIZE}" \
                --size="${PERF_RAND_FILE_SIZE}" --numjobs=1 \
                --runtime="${PERF_RAND_DURATION}" --time_based \
                --filename=perf_bench_iops_pool \
                --group_reporting --output-format=json 2>/dev/null)

            local read_iops
            read_iops=$(echo "$fio_out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(int(d.get('jobs', [{}])[0].get('read', {}).get('iops', 0)))
" 2>/dev/null || echo "0")
            if [[ "$read_iops" != "0" ]]; then
                record_result "rand_read_4k_iops" "$read_iops" "IOPS" "iops"
            else
                record_error "rand_read_4k_iops" "fio returned 0" "iops"
            fi

            # Random write IOPS
            log_info "  Random 4KB write IOPS (fio)..."
            fio_out=$(fio --name=rand_write --directory="$mnt" \
                --rw=randwrite --bs="${PERF_RAND_BLOCK_SIZE}" \
                --size="${PERF_RAND_FILE_SIZE}" --numjobs=1 \
                --runtime="${PERF_RAND_DURATION}" --time_based \
                --group_reporting --output-format=json 2>/dev/null)

            local write_iops
            write_iops=$(echo "$fio_out" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(int(d.get('jobs', [{}])[0].get('write', {}).get('iops', 0)))
" 2>/dev/null || echo "0")
            if [[ "$write_iops" != "0" ]]; then
                record_result "rand_write_4k_iops" "$write_iops" "IOPS" "iops"
            else
                record_error "rand_write_4k_iops" "fio returned 0" "iops"
            fi

            sudo umount "$mnt" 2>/dev/null
        else
            log_warn "  mount.cifs failed, falling back to smbclient estimation"
            bench_random_iops_smbclient
        fi
        rmdir "$mnt" 2>/dev/null
    else
        bench_random_iops_smbclient
    fi

    vm_exec "rm -f ${PERF_SHARE_ROOT}/perf_bench_iops_pool" 2>/dev/null
}

# Fallback: estimate IOPS using smbclient get/put of 4KB chunks
bench_random_iops_smbclient() {
    log_info "  Estimating IOPS via smbclient (less accurate)..."

    local tmpf="${PERF_WORK_DIR}/iops_4k"
    dd if=/dev/urandom of="$tmpf" bs=4096 count=1 2>/dev/null

    local count=0
    local deadline=$(($(date +%s) + PERF_RAND_DURATION))
    local start
    start=$(now_secs)

    while [[ $(date +%s) -lt $deadline ]]; do
        smb_cmd "put ${tmpf} perf_bench_iops_w" >/dev/null 2>&1 && ((count++))
    done

    local end
    end=$(now_secs)
    local duration
    duration=$(elapsed_secs "$start" "$end")
    local write_iops
    write_iops=$(calc_ops "$count" "$duration")

    rm -f "$tmpf"
    smb_cmd "del perf_bench_iops_w" >/dev/null 2>&1

    if [[ "$count" -gt 0 ]]; then
        record_result "rand_write_4k_iops" "$write_iops" "IOPS" "iops"
    else
        record_error "rand_write_4k_iops" "zero successful writes" "iops"
    fi

    # Read IOPS
    vm_exec "dd if=/dev/urandom of=${PERF_SHARE_ROOT}/perf_bench_iops_r bs=4096 count=1 2>/dev/null" 2>/dev/null

    count=0
    deadline=$(($(date +%s) + PERF_RAND_DURATION))
    start=$(now_secs)

    while [[ $(date +%s) -lt $deadline ]]; do
        smb_cmd "get perf_bench_iops_r ${PERF_WORK_DIR}/iops_read_tmp" >/dev/null 2>&1 && ((count++))
        rm -f "${PERF_WORK_DIR}/iops_read_tmp"
    done

    end=$(now_secs)
    duration=$(elapsed_secs "$start" "$end")
    local read_iops
    read_iops=$(calc_ops "$count" "$duration")

    vm_exec "rm -f ${PERF_SHARE_ROOT}/perf_bench_iops_r" 2>/dev/null

    if [[ "$count" -gt 0 ]]; then
        record_result "rand_read_4k_iops" "$read_iops" "IOPS" "iops"
    else
        record_error "rand_read_4k_iops" "zero successful reads" "iops"
    fi
}

# ---------------------------------------------------------------------------
# Benchmark: Directory Enumeration
# ---------------------------------------------------------------------------
bench_dir_enumeration() {
    if [[ "$SKIP_DIR" == "yes" ]] || ! should_run "dir"; then
        record_skip "dir_enumeration" "skipped by user"
        return
    fi

    log_info "--- Directory Enumeration ---"

    local -a counts
    read -ra counts <<< "$PERF_DIR_COUNTS"

    for file_count in "${counts[@]}"; do
        log_info "  Enumerating ${file_count} files..."

        # Create files on server via SSH for speed
        vm_exec "mkdir -p ${PERF_SHARE_ROOT}/perf_bench_dir_${file_count} && \
                 cd ${PERF_SHARE_ROOT}/perf_bench_dir_${file_count} && \
                 for i in \$(seq 1 ${file_count}); do touch file_\${i}.txt; done" 2>/dev/null

        local results=""
        local iter
        for iter in $(seq 1 "$PERF_ITERATIONS"); do
            local start end duration ops
            start=$(now_secs)
            smb_cmd "cd perf_bench_dir_${file_count}; ls" > "${PERF_WORK_DIR}/dir_out" 2>&1
            end=$(now_secs)
            duration=$(elapsed_secs "$start" "$end")
            ops=$(calc_ops "$file_count" "$duration")
            results="${results}${ops}\n"
        done

        vm_exec "rm -rf ${PERF_SHARE_ROOT}/perf_bench_dir_${file_count}" 2>/dev/null

        if [[ -n "$results" ]]; then
            local median
            median=$(printf '%b' "$results" | median_value)
            record_result "dir_enum_${file_count}" "$median" "entries/s" "directory"
        else
            record_error "dir_enum_${file_count}" "no results" "directory"
        fi
    done
}

# ---------------------------------------------------------------------------
# Benchmark: File Creation Rate
# ---------------------------------------------------------------------------
bench_file_creation() {
    if [[ "$SKIP_CREATE" == "yes" ]] || ! should_run "create"; then
        record_skip "file_creation" "skipped by user"
        return
    fi

    log_info "--- File Creation Rate (${PERF_CREATE_FILE_COUNT} files) ---"

    local results=""
    local iter
    for iter in $(seq 1 "$PERF_ITERATIONS"); do
        # Build smbclient batch commands
        local batch="${PERF_WORK_DIR}/create_batch_${iter}.txt"
        local template="${PERF_WORK_DIR}/create_template"
        dd if=/dev/urandom of="$template" bs=1024 count=1 2>/dev/null

        echo "mkdir perf_bench_create_${iter}" > "$batch"
        echo "cd perf_bench_create_${iter}" >> "$batch"
        local i
        for i in $(seq 1 "$PERF_CREATE_FILE_COUNT"); do
            echo "put ${template} file_${i}.dat" >> "$batch"
        done

        local start end duration ops
        start=$(now_secs)
        "$PERF_SMBCLIENT_BIN" "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" \
            -p "$PERF_SMB_PORT" -U "${PERF_SMB_CREDS}" \
            --option="client min protocol=${PERF_SMB_PROTOCOL}" \
            --option="client max protocol=${PERF_SMB_PROTOCOL}" \
            < "$batch" >>"$LOG_FILE" 2>&1
        end=$(now_secs)
        duration=$(elapsed_secs "$start" "$end")
        ops=$(calc_ops "$PERF_CREATE_FILE_COUNT" "$duration")
        results="${results}${ops}\n"

        rm -f "$batch" "$template"
        vm_exec "rm -rf ${PERF_SHARE_ROOT}/perf_bench_create_${iter}" 2>/dev/null
    done

    if [[ -n "$results" ]]; then
        local median
        median=$(printf '%b' "$results" | median_value)
        record_result "file_creation_rate" "$median" "files/s" "creation"
    else
        record_error "file_creation_rate" "no results" "creation"
    fi
}

# ---------------------------------------------------------------------------
# Benchmark: Metadata Operations Rate
# ---------------------------------------------------------------------------
bench_metadata_ops() {
    if [[ "$SKIP_METADATA" == "yes" ]] || ! should_run "metadata"; then
        record_skip "metadata_ops" "skipped by user"
        return
    fi

    log_info "--- Metadata Operations (stat ${PERF_METADATA_FILE_COUNT} files) ---"

    # Create files on server
    vm_exec "mkdir -p ${PERF_SHARE_ROOT}/perf_bench_meta && \
             cd ${PERF_SHARE_ROOT}/perf_bench_meta && \
             for i in \$(seq 1 ${PERF_METADATA_FILE_COUNT}); do \
                 dd if=/dev/urandom of=file_\${i}.dat bs=4096 count=1 2>/dev/null; \
             done" 2>/dev/null

    local results=""
    local iter
    for iter in $(seq 1 "$PERF_ITERATIONS"); do
        # Build smbclient batch for allinfo on each file
        local batch="${PERF_WORK_DIR}/meta_batch_${iter}.txt"
        echo "cd perf_bench_meta" > "$batch"
        local i
        for i in $(seq 1 "$PERF_METADATA_FILE_COUNT"); do
            echo "allinfo file_${i}.dat" >> "$batch"
        done

        local start end duration ops
        start=$(now_secs)
        "$PERF_SMBCLIENT_BIN" "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" \
            -p "$PERF_SMB_PORT" -U "${PERF_SMB_CREDS}" \
            --option="client min protocol=${PERF_SMB_PROTOCOL}" \
            --option="client max protocol=${PERF_SMB_PROTOCOL}" \
            < "$batch" > "${PERF_WORK_DIR}/meta_out_${iter}" 2>>"$LOG_FILE"
        end=$(now_secs)
        duration=$(elapsed_secs "$start" "$end")
        ops=$(calc_ops "$PERF_METADATA_FILE_COUNT" "$duration")
        results="${results}${ops}\n"

        rm -f "$batch"
    done

    vm_exec "rm -rf ${PERF_SHARE_ROOT}/perf_bench_meta" 2>/dev/null

    if [[ -n "$results" ]]; then
        local median
        median=$(printf '%b' "$results" | median_value)
        record_result "metadata_stat_rate" "$median" "ops/s" "metadata"
    else
        record_error "metadata_stat_rate" "no results" "metadata"
    fi
}

# ---------------------------------------------------------------------------
# Benchmark: Small File Transfer
# ---------------------------------------------------------------------------
bench_small_file_transfer() {
    if [[ "$SKIP_SMALLFILE" == "yes" ]] || ! should_run "smallfile"; then
        record_skip "small_file_transfer" "skipped by user"
        return
    fi

    log_info "--- Small File Transfer (${PERF_SMALL_FILE_COUNT} x ${PERF_SMALL_FILE_SIZE}B) ---"

    # Create local small files
    local small_dir="${PERF_WORK_DIR}/small_files"
    mkdir -p "$small_dir"
    local i
    for i in $(seq 1 "$PERF_SMALL_FILE_COUNT"); do
        dd if=/dev/urandom of="${small_dir}/sf_${i}.dat" bs="$PERF_SMALL_FILE_SIZE" count=1 2>/dev/null
    done

    # Upload phase
    local results_upload=""
    local iter
    for iter in $(seq 1 "$PERF_ITERATIONS"); do
        local batch="${PERF_WORK_DIR}/sf_upload_${iter}.txt"
        echo "mkdir perf_bench_small_${iter}" > "$batch"
        echo "cd perf_bench_small_${iter}" >> "$batch"
        for i in $(seq 1 "$PERF_SMALL_FILE_COUNT"); do
            echo "put ${small_dir}/sf_${i}.dat sf_${i}.dat" >> "$batch"
        done

        local start end duration ops
        start=$(now_secs)
        "$PERF_SMBCLIENT_BIN" "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" \
            -p "$PERF_SMB_PORT" -U "${PERF_SMB_CREDS}" \
            --option="client min protocol=${PERF_SMB_PROTOCOL}" \
            --option="client max protocol=${PERF_SMB_PROTOCOL}" \
            < "$batch" >>"$LOG_FILE" 2>&1
        end=$(now_secs)
        duration=$(elapsed_secs "$start" "$end")
        ops=$(calc_ops "$PERF_SMALL_FILE_COUNT" "$duration")
        results_upload="${results_upload}${ops}\n"

        rm -f "$batch"
        vm_exec "rm -rf ${PERF_SHARE_ROOT}/perf_bench_small_${iter}" 2>/dev/null
    done

    rm -rf "$small_dir"

    if [[ -n "$results_upload" ]]; then
        local median
        median=$(printf '%b' "$results_upload" | median_value)
        record_result "small_file_upload_rate" "$median" "files/s" "smallfile"
    else
        record_error "small_file_upload_rate" "no results" "smallfile"
    fi

    # Download phase: create files on server, download via smbclient
    vm_exec "mkdir -p ${PERF_SHARE_ROOT}/perf_bench_small_dl && \
             cd ${PERF_SHARE_ROOT}/perf_bench_small_dl && \
             for i in \$(seq 1 ${PERF_SMALL_FILE_COUNT}); do \
                 dd if=/dev/urandom of=sf_\${i}.dat bs=${PERF_SMALL_FILE_SIZE} count=1 2>/dev/null; \
             done" 2>/dev/null

    local results_download=""
    for iter in $(seq 1 "$PERF_ITERATIONS"); do
        local batch="${PERF_WORK_DIR}/sf_download_${iter}.txt"
        local dl_dir="${PERF_WORK_DIR}/sf_dl_${iter}"
        mkdir -p "$dl_dir"
        echo "cd perf_bench_small_dl" > "$batch"
        for i in $(seq 1 "$PERF_SMALL_FILE_COUNT"); do
            echo "get sf_${i}.dat ${dl_dir}/sf_${i}.dat" >> "$batch"
        done

        local start end duration ops
        start=$(now_secs)
        "$PERF_SMBCLIENT_BIN" "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" \
            -p "$PERF_SMB_PORT" -U "${PERF_SMB_CREDS}" \
            --option="client min protocol=${PERF_SMB_PROTOCOL}" \
            --option="client max protocol=${PERF_SMB_PROTOCOL}" \
            < "$batch" >>"$LOG_FILE" 2>&1
        end=$(now_secs)
        duration=$(elapsed_secs "$start" "$end")
        ops=$(calc_ops "$PERF_SMALL_FILE_COUNT" "$duration")
        results_download="${results_download}${ops}\n"

        rm -rf "$batch" "$dl_dir"
    done

    vm_exec "rm -rf ${PERF_SHARE_ROOT}/perf_bench_small_dl" 2>/dev/null

    if [[ -n "$results_download" ]]; then
        local median
        median=$(printf '%b' "$results_download" | median_value)
        record_result "small_file_download_rate" "$median" "files/s" "smallfile"
    else
        record_error "small_file_download_rate" "no results" "smallfile"
    fi
}

# ---------------------------------------------------------------------------
# Benchmark: Connection Establishment Rate
# ---------------------------------------------------------------------------
bench_connection_rate() {
    if [[ "$SKIP_CONNECTION" == "yes" ]] || ! should_run "connection"; then
        record_skip "connection_rate" "skipped by user"
        return
    fi

    log_info "--- Connection Establishment Rate (${PERF_CONN_ITERATIONS} connections) ---"

    local results=""
    local iter
    for iter in $(seq 1 "$PERF_ITERATIONS"); do
        local start end duration rate
        local success=0
        start=$(now_secs)

        local c
        for c in $(seq 1 "$PERF_CONN_ITERATIONS"); do
            if smb_cmd "ls" >/dev/null 2>&1; then
                ((success++))
            fi
        done

        end=$(now_secs)
        duration=$(elapsed_secs "$start" "$end")
        rate=$(calc_ops "$success" "$duration")
        results="${results}${rate}\n"
    done

    if [[ -n "$results" ]]; then
        local median
        median=$(printf '%b' "$results" | median_value)
        record_result "connection_rate" "$median" "conn/s" "connection"
    else
        record_error "connection_rate" "no results" "connection"
    fi
}

# ---------------------------------------------------------------------------
# Benchmark: Concurrent Client Throughput
# ---------------------------------------------------------------------------
bench_concurrent_throughput() {
    if [[ "$SKIP_CONCURRENT" == "yes" ]] || ! should_run "concurrent"; then
        record_skip "concurrent_throughput" "skipped by user"
        return
    fi

    log_info "--- Concurrent Client Throughput ---"

    local file_size_mb=$((PERF_CONCURRENT_FILE_SIZE / 1048576))

    # Create test file on server
    vm_exec "dd if=/dev/urandom of=${PERF_SHARE_ROOT}/perf_bench_conc_file bs=1M count=${file_size_mb} 2>/dev/null" 2>/dev/null

    local -a client_counts
    read -ra client_counts <<< "$PERF_CONCURRENT_CLIENTS"

    for num_clients in "${client_counts[@]}"; do
        log_info "  ${num_clients} concurrent clients..."

        local results_agg=""
        local results_per=""
        local iter
        for iter in $(seq 1 "$PERF_ITERATIONS"); do
            local pids=""
            local tmpdir="${PERF_WORK_DIR}/conc_${num_clients}_${iter}"
            mkdir -p "$tmpdir"

            local start end
            start=$(now_secs)

            local c
            for c in $(seq 1 "$num_clients"); do
                (
                    "$PERF_SMBCLIENT_BIN" "//${PERF_SMB_HOST}/${PERF_SMB_SHARE}" \
                        -p "$PERF_SMB_PORT" -U "${PERF_SMB_CREDS}" \
                        --option="client min protocol=${PERF_SMB_PROTOCOL}" \
                        --option="client max protocol=${PERF_SMB_PROTOCOL}" \
                        -c "get perf_bench_conc_file ${tmpdir}/out_${c}" \
                        >>"$LOG_FILE" 2>&1
                ) &
                pids="$pids $!"
            done

            local all_ok=true
            for pid in $pids; do
                if ! wait "$pid"; then
                    all_ok=false
                fi
            done

            end=$(now_secs)
            local duration
            duration=$(elapsed_secs "$start" "$end")

            if [[ "$all_ok" == "true" ]]; then
                local total_bytes=$((num_clients * PERF_CONCURRENT_FILE_SIZE))
                local agg_mbps per_mbps
                agg_mbps=$(calc_mbps "$total_bytes" "$duration")
                per_mbps=$(calc_mbps "$PERF_CONCURRENT_FILE_SIZE" "$duration")
                results_agg="${results_agg}${agg_mbps}\n"
                results_per="${results_per}${per_mbps}\n"
            else
                log_warn "  Iteration $iter: some clients failed"
            fi

            rm -rf "$tmpdir"
        done

        if [[ -n "$results_agg" ]]; then
            local median_agg median_per
            median_agg=$(printf '%b' "$results_agg" | median_value)
            median_per=$(printf '%b' "$results_per" | median_value)
            record_result "concurrent_${num_clients}c_aggregate" "$median_agg" "MB/s" "concurrent"
            record_result "concurrent_${num_clients}c_perclient" "$median_per" "MB/s" "concurrent"
        else
            record_error "concurrent_${num_clients}c_aggregate" "all iterations failed" "concurrent"
            record_error "concurrent_${num_clients}c_perclient" "all iterations failed" "concurrent"
        fi
    done

    vm_exec "rm -f ${PERF_SHARE_ROOT}/perf_bench_conc_file" 2>/dev/null
}

# ---------------------------------------------------------------------------
# JSON Output Generation
# ---------------------------------------------------------------------------
generate_json() {
    log_info "Generating JSON output..."

    local json_file="$PERF_OUTPUT_FILE"

    {
        cat <<HEADER
{
  "version": 1,
  "timestamp": "${TIMESTAMP}",
  "timestamp_epoch": $(date +%s),
  "system_info": {
    "kernel_version": "${SYSINFO_KERNEL}",
    "arch": "${SYSINFO_ARCH}",
    "hostname": "${SYSINFO_HOSTNAME}",
    "cpu_model": "${SYSINFO_CPU}",
    "cpu_cores": ${SYSINFO_CPU_CORES:-0},
    "memory_kb": ${SYSINFO_MEMORY_KB:-0},
    "ksmbd_version": "${SYSINFO_KSMBD_VER}"
  },
  "git_info": {
    "commit": "${SYSINFO_GIT_COMMIT}",
    "branch": "${SYSINFO_GIT_BRANCH}",
    "dirty": ${SYSINFO_GIT_DIRTY}
  },
  "config": {
    "vm_name": "${PERF_VM_NAME}",
    "smb_host": "${PERF_SMB_HOST}",
    "smb_port": ${PERF_SMB_PORT},
    "smb_share": "${PERF_SMB_SHARE}",
    "protocol": "${PERF_SMB_PROTOCOL}",
    "client_tool": "${PERF_CLIENT_TOOL}",
    "iterations": ${PERF_ITERATIONS},
    "quick_mode": $([ "$QUICK_MODE" = "yes" ] && echo true || echo false)
  },
  "summary": {
    "total_benchmarks": $((BENCH_PASS + BENCH_FAIL)),
    "passed": ${BENCH_PASS},
    "failed": ${BENCH_FAIL},
    "skipped": ${BENCH_SKIP}
  },
  "results": [
HEADER

        local first=true
        local idx
        for idx in "${!RESULT_NAMES[@]}"; do
            local name="${RESULT_NAMES[$idx]}"
            local value="${RESULT_VALUES[$idx]}"
            local unit="${RESULT_UNITS[$idx]}"
            local category="${RESULT_CATEGORIES[$idx]}"

            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi

            if [[ "$value" == "ERROR" ]]; then
                printf '    {"name": "%s", "value": null, "unit": "%s", "category": "%s", "error": true}' \
                    "$name" "$unit" "$category"
            else
                printf '    {"name": "%s", "value": %s, "unit": "%s", "category": "%s", "error": false}' \
                    "$name" "$value" "$unit" "$category"
            fi
        done

        cat <<FOOTER

  ]
}
FOOTER
    } > "$json_file"

    log_info "JSON results written to: $json_file"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    log_info ""
    log_info "=== Performance Baseline Summary ==="
    log_info "  Benchmarks: $((BENCH_PASS + BENCH_FAIL)) run, ${BENCH_PASS} passed, ${BENCH_FAIL} failed, ${BENCH_SKIP} skipped"
    log_info "  Output: ${PERF_OUTPUT_FILE}"
    log_info ""
    log_info "Results:"
    printf "  %-35s %15s %s\n" "METRIC" "VALUE" "UNIT" >&2
    printf "  %-35s %15s %s\n" "-----------------------------------" "---------------" "----" >&2
    local idx
    for idx in "${!RESULT_NAMES[@]}"; do
        local name="${RESULT_NAMES[$idx]}"
        local value="${RESULT_VALUES[$idx]}"
        local unit="${RESULT_UNITS[$idx]}"
        printf "  %-35s %15s %s\n" "$name" "$value" "$unit" >&2
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    preflight
    collect_sysinfo
    cleanup_server

    bench_sequential_throughput
    bench_random_iops
    bench_dir_enumeration
    bench_file_creation
    bench_metadata_ops
    bench_small_file_transfer
    bench_connection_rate
    bench_concurrent_throughput

    cleanup_server
    generate_json
    print_summary

    log_info "=== Baseline complete ==="

    if [[ "$BENCH_FAIL" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
