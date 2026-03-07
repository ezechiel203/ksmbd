#!/bin/bash
# ksmbd-torture: Benchmark helpers
# Used by B01-B05 benchmark categories.

source "$(dirname "${BASH_SOURCE[0]}")/smb_helpers.sh"

: "${BENCH_ITERATIONS:=1000}"
: "${BENCH_FILE_SIZE:=1048576}"  # 1MB default

# Mount share for fio/dd benchmarks
BENCH_MOUNT="/tmp/ksmbd-torture-bench"

bench_mount() {
    sudo mkdir -p "$BENCH_MOUNT"
    sudo mount -t cifs "//${SMB_HOST}/${SMB_SHARE}" "$BENCH_MOUNT" \
        -o "port=${SMB_PORT},username=${SMB_USER},password=${SMB_PASS},vers=3.1.1" 2>/dev/null
}

bench_unmount() {
    sudo umount "$BENCH_MOUNT" 2>/dev/null
    sudo rmdir "$BENCH_MOUNT" 2>/dev/null
}

# Measure time in milliseconds for a block of operations
bench_time_ms() {
    local start end
    start=$(date +%s%N)
    "$@"
    end=$(date +%s%N)
    echo $(( (end - start) / 1000000 ))
}

# Run fio with SMB mount
bench_fio() {
    local rw="$1" bs="$2" size="$3" numjobs="${4:-1}" runtime="${5:-30}"
    local fio_out
    fio_out=$(fio --name=bench --directory="$BENCH_MOUNT" \
        --rw="$rw" --bs="$bs" --size="$size" \
        --numjobs="$numjobs" --runtime="$runtime" --time_based \
        --group_reporting --output-format=json 2>/dev/null)
    echo "$fio_out"
}

# Extract throughput from fio JSON
bench_fio_bw() {
    local fio_json="$1" direction="${2:-read}"
    echo "$fio_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
jobs = d.get('jobs', [{}])
bw = jobs[0].get('$direction', {}).get('bw_bytes', 0)
print(int(bw / 1048576))  # MB/s
" 2>/dev/null
}

# Extract IOPS from fio JSON
bench_fio_iops() {
    local fio_json="$1" direction="${2:-read}"
    echo "$fio_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
jobs = d.get('jobs', [{}])
iops = jobs[0].get('$direction', {}).get('iops', 0)
print(int(iops))
" 2>/dev/null
}

# Extract latency percentiles from fio JSON
bench_fio_lat_p50() {
    local fio_json="$1" direction="${2:-read}"
    echo "$fio_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
jobs = d.get('jobs', [{}])
percentiles = jobs[0].get('$direction', {}).get('clat_ns', {}).get('percentile', {})
print(int(percentiles.get('50.000000', 0) / 1000))  # us
" 2>/dev/null
}

bench_fio_lat_p99() {
    local fio_json="$1" direction="${2:-read}"
    echo "$fio_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
jobs = d.get('jobs', [{}])
percentiles = jobs[0].get('$direction', {}).get('clat_ns', {}).get('percentile', {})
print(int(percentiles.get('99.000000', 0) / 1000))  # us
" 2>/dev/null
}

# Simple throughput measurement using dd
bench_dd_read() {
    local file="$1" bs="${2:-1M}" count="${3:-100}"
    dd if="${BENCH_MOUNT}/$file" of=/dev/null bs="$bs" count="$count" 2>&1 | \
        grep -oP '[\d.]+ [MG]B/s' || echo "0 MB/s"
}

bench_dd_write() {
    local file="$1" bs="${2:-1M}" count="${3:-100}"
    dd if=/dev/zero of="${BENCH_MOUNT}/$file" bs="$bs" count="$count" conv=fdatasync 2>&1 | \
        grep -oP '[\d.]+ [MG]B/s' || echo "0 MB/s"
}

# Latency measurement for individual operations
bench_latency_loop() {
    local iterations="$1"; shift
    local total_us=0
    local min_us=999999999
    local max_us=0
    local i start_ns end_ns elapsed_us

    for i in $(seq 1 "$iterations"); do
        start_ns=$(date +%s%N)
        "$@" >/dev/null 2>&1
        end_ns=$(date +%s%N)
        elapsed_us=$(( (end_ns - start_ns) / 1000 ))
        total_us=$(( total_us + elapsed_us ))
        [[ $elapsed_us -lt $min_us ]] && min_us=$elapsed_us
        [[ $elapsed_us -gt $max_us ]] && max_us=$elapsed_us
    done

    local avg_us=$(( total_us / iterations ))
    echo "avg=${avg_us}us min=${min_us}us max=${max_us}us total=${total_us}us iterations=$iterations"
}

# Report benchmark result
bench_report() {
    local name="$1" metric="$2" value="$3" unit="$4"
    printf "  BENCH  %-40s %10s %s\n" "$name" "$value" "$unit"
}
