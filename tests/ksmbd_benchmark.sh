#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# ksmbd_benchmark.sh - Over-the-wire SMB performance benchmarks for ksmbd
#
# Runs a suite of file I/O and metadata benchmarks against a running
# ksmbd instance via smbclient, producing structured TSV output suitable
# for regression tracking.
#
# Usage:
#   ./tests/ksmbd_benchmark.sh <VM_SSH_PORT> <VM_SMB_PORT> <SHARE_NAME>
#
# Example:
#   ./tests/ksmbd_benchmark.sh 13022 13445 testshare
#
# Prerequisites:
#   - smbclient installed on the host
#   - sshpass installed on the host (for VM access)
#   - ksmbd running in the VM with the specified share
#   - Share configured with user testuser / password 1234
#
# Output:
#   TSV lines to stdout: benchmark_name<TAB>value<TAB>unit<TAB>details
#   Human-readable progress to stderr
#   Optional JSON output to OUTDIR/results.json

set -u

# ---------------------------------------------------------------------------
# Arguments and defaults
# ---------------------------------------------------------------------------
VM_SSH_PORT="${1:?Usage: $0 <VM_SSH_PORT> <VM_SMB_PORT> <SHARE_NAME>}"
VM_SMB_PORT="${2:?Usage: $0 <VM_SSH_PORT> <VM_SMB_PORT> <SHARE_NAME>}"
SHARE_NAME="${3:?Usage: $0 <VM_SSH_PORT> <VM_SMB_PORT> <SHARE_NAME>}"

SMB_USER="${SMB_USER:-testuser}"
SMB_PASS="${SMB_PASS:-1234}"
SMB_HOST="127.0.0.1"

OUTDIR="${OUTDIR:-/tmp/ksmbd-bench-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"

TSV_FILE="$OUTDIR/results.tsv"
JSON_FILE="$OUTDIR/results.json"
LOG_FILE="$OUTDIR/benchmark.log"

# Sizes
SEQ_FILE_SIZE_MB=1024  # 1 GB for sequential I/O
SMALL_FILE_COUNT=1000
DIR_LIST_COUNT=10000
METADATA_COUNT=1000
CONCURRENT_LEVELS="1 2 4 8"

# smbclient command base
SMBCLIENT="smbclient //${SMB_HOST}/${SHARE_NAME} -p ${VM_SMB_PORT} -U ${SMB_USER}%${SMB_PASS} --option='client min protocol=SMB3_11'"

# SSH command for VM access
SSH="sshpass -p root ssh -p ${VM_SSH_PORT} -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@${SMB_HOST}"

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

log() {
    echo "[$(date '+%H:%M:%S')] $*" >&2
    echo "[$(date '+%H:%M:%S')] $*" >> "$LOG_FILE"
}

die() {
    log "FATAL: $*"
    exit 1
}

# Output a TSV result line
# Args: name value unit [details]
result() {
    local name="$1"
    local value="$2"
    local unit="$3"
    local details="${4:-}"
    printf '%s\t%s\t%s\t%s\n' "$name" "$value" "$unit" "$details" | tee -a "$TSV_FILE"
    log "  RESULT: $name = $value $unit $details"
}

# Run smbclient with a command string; output goes to stdout
smb_cmd() {
    eval "$SMBCLIENT" -c "$1" 2>>"$LOG_FILE"
}

# Calculate throughput in MB/s from size_bytes and duration_seconds
# Args: size_bytes duration_secs
calc_mbps() {
    local size_bytes="$1"
    local duration="$2"
    if [ "$duration" = "0" ] || [ -z "$duration" ]; then
        echo "0"
        return
    fi
    # Use awk for floating point
    echo "$size_bytes $duration" | awk '{printf "%.2f", ($1 / 1048576) / $2}'
}

# Calculate operations per second
# Args: count duration_secs
calc_ops() {
    local count="$1"
    local duration="$2"
    if [ "$duration" = "0" ] || [ -z "$duration" ]; then
        echo "0"
        return
    fi
    echo "$count $duration" | awk '{printf "%.2f", $1 / $2}'
}

# Get elapsed time in seconds (with decimals) from two epoch timestamps
elapsed_secs() {
    local start="$1"
    local end="$2"
    echo "$start $end" | awk '{printf "%.3f", $2 - $1}'
}

# Get current time as floating point seconds since epoch
now_secs() {
    date +%s.%N
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

preflight() {
    log "=== ksmbd benchmark suite ==="
    log "VM SSH port: $VM_SSH_PORT"
    log "VM SMB port: $VM_SMB_PORT"
    log "Share: $SHARE_NAME"
    log "Output dir: $OUTDIR"
    log ""

    # Check smbclient is available
    command -v smbclient >/dev/null 2>&1 || die "smbclient not found in PATH"
    command -v sshpass >/dev/null 2>&1 || die "sshpass not found in PATH"
    command -v dd >/dev/null 2>&1 || die "dd not found in PATH"

    # Verify SMB connectivity
    log "Checking SMB connectivity..."
    smb_cmd "'ls'" >/dev/null 2>&1 || die "Cannot connect to //${SMB_HOST}/${SHARE_NAME}:${VM_SMB_PORT}"
    log "SMB connection OK"

    # Write TSV header
    printf 'benchmark\tvalue\tunit\tdetails\n' > "$TSV_FILE"
}

# ---------------------------------------------------------------------------
# Cleanup helper: remove benchmark files from share
# ---------------------------------------------------------------------------

cleanup_share() {
    log "Cleaning up benchmark files on share..."
    smb_cmd "'deltree bench_seq; deltree bench_small; deltree bench_dir; deltree bench_meta; deltree bench_conc; rm bench_seq_file'" >/dev/null 2>&1
    # Also clean via SSH for certainty
    $SSH "rm -rf /srv/smb/${SHARE_NAME}/bench_* 2>/dev/null; rm -f /srv/smb/${SHARE_NAME}/bench_seq_file 2>/dev/null" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Benchmark 1: Sequential write throughput (dd 1G via smbclient put)
# ---------------------------------------------------------------------------

bench_sequential_write() {
    log "--- Benchmark: Sequential Write (${SEQ_FILE_SIZE_MB}MB) ---"

    local tmpfile="$OUTDIR/bench_write_data"
    local size_bytes=$((SEQ_FILE_SIZE_MB * 1048576))

    # Create local test file
    log "Creating ${SEQ_FILE_SIZE_MB}MB test file..."
    dd if=/dev/urandom of="$tmpfile" bs=1M count="$SEQ_FILE_SIZE_MB" \
       conv=fdatasync 2>>"$LOG_FILE"

    # Upload via smbclient
    log "Uploading via smbclient..."
    local start
    start=$(now_secs)
    eval "$SMBCLIENT" -c "'put ${tmpfile} bench_seq_file'" >>"$LOG_FILE" 2>&1
    local rc=$?
    local end
    end=$(now_secs)

    rm -f "$tmpfile"

    if [ $rc -ne 0 ]; then
        log "  FAILED (smbclient returned $rc)"
        result "sequential_write_MBps" "ERROR" "MB/s" "smbclient put failed"
        return
    fi

    local duration
    duration=$(elapsed_secs "$start" "$end")
    local mbps
    mbps=$(calc_mbps "$size_bytes" "$duration")

    result "sequential_write_MBps" "$mbps" "MB/s" "size=${SEQ_FILE_SIZE_MB}MB duration=${duration}s"
}

# ---------------------------------------------------------------------------
# Benchmark 2: Sequential read throughput (get 1G file)
# ---------------------------------------------------------------------------

bench_sequential_read() {
    log "--- Benchmark: Sequential Read (${SEQ_FILE_SIZE_MB}MB) ---"

    local tmpfile="$OUTDIR/bench_read_data"
    local size_bytes=$((SEQ_FILE_SIZE_MB * 1048576))

    log "Downloading via smbclient..."
    local start
    start=$(now_secs)
    eval "$SMBCLIENT" -c "'get bench_seq_file ${tmpfile}'" >>"$LOG_FILE" 2>&1
    local rc=$?
    local end
    end=$(now_secs)

    if [ $rc -ne 0 ]; then
        log "  FAILED (smbclient returned $rc)"
        result "sequential_read_MBps" "ERROR" "MB/s" "smbclient get failed"
        rm -f "$tmpfile"
        return
    fi

    local actual_size
    actual_size=$(stat -c%s "$tmpfile" 2>/dev/null || echo 0)
    rm -f "$tmpfile"

    local duration
    duration=$(elapsed_secs "$start" "$end")
    local mbps
    mbps=$(calc_mbps "$actual_size" "$duration")

    result "sequential_read_MBps" "$mbps" "MB/s" "size=$((actual_size / 1048576))MB duration=${duration}s"
}

# ---------------------------------------------------------------------------
# Benchmark 3: Small file create throughput (1000 files)
# ---------------------------------------------------------------------------

bench_small_file_create() {
    log "--- Benchmark: Small File Create ($SMALL_FILE_COUNT files) ---"

    # Create a batch script for smbclient
    local script="$OUTDIR/bench_create_script.txt"
    echo "mkdir bench_small" > "$script"
    echo "cd bench_small" >> "$script"

    local i
    for i in $(seq 1 "$SMALL_FILE_COUNT"); do
        # Create a small 1-byte file by putting /dev/null (empty) then writing
        echo "put /dev/null file_${i}.txt" >> "$script"
    done

    # Prepare small local files (1KB each) for upload
    local small_dir="$OUTDIR/bench_small_files"
    mkdir -p "$small_dir"
    dd if=/dev/urandom of="$small_dir/template.dat" bs=1024 count=1 2>/dev/null

    # Build smbclient commands: create dir, then put files one by one
    local cmd_script="$OUTDIR/bench_create_cmds.txt"
    echo "mkdir bench_small" > "$cmd_script"
    echo "cd bench_small" >> "$cmd_script"
    for i in $(seq 1 "$SMALL_FILE_COUNT"); do
        echo "put ${small_dir}/template.dat file_${i}.txt" >> "$cmd_script"
    done

    log "Creating $SMALL_FILE_COUNT files..."
    local start
    start=$(now_secs)
    # Use smbclient with input redirection for batch commands
    eval "$SMBCLIENT" < "$cmd_script" >>"$LOG_FILE" 2>&1
    local rc=$?
    local end
    end=$(now_secs)

    rm -rf "$small_dir" "$cmd_script" "$script"

    if [ $rc -ne 0 ]; then
        log "  FAILED (smbclient returned $rc)"
        result "small_file_create_ops" "ERROR" "files/s" "smbclient batch failed"
        return
    fi

    local duration
    duration=$(elapsed_secs "$start" "$end")
    local ops
    ops=$(calc_ops "$SMALL_FILE_COUNT" "$duration")

    result "small_file_create_ops" "$ops" "files/s" "count=$SMALL_FILE_COUNT duration=${duration}s"
}

# ---------------------------------------------------------------------------
# Benchmark 4: Directory listing speed (ls on 10000-entry dir)
# ---------------------------------------------------------------------------

bench_dir_listing() {
    log "--- Benchmark: Directory Listing ($DIR_LIST_COUNT entries) ---"

    # Create files on the server via SSH for speed
    log "Creating $DIR_LIST_COUNT files on server via SSH..."
    $SSH "mkdir -p /srv/smb/${SHARE_NAME}/bench_dir && \
          cd /srv/smb/${SHARE_NAME}/bench_dir && \
          for i in \$(seq 1 $DIR_LIST_COUNT); do touch file_\${i}.txt; done" \
         >>"$LOG_FILE" 2>&1

    if [ $? -ne 0 ]; then
        log "  FAILED (SSH file creation failed)"
        result "dir_listing_ops" "ERROR" "entries/s" "file creation failed"
        return
    fi

    log "Listing directory via smbclient..."
    local start
    start=$(now_secs)
    eval "$SMBCLIENT" -c "'cd bench_dir; ls'" > "$OUTDIR/dir_list_output.txt" 2>>"$LOG_FILE"
    local rc=$?
    local end
    end=$(now_secs)

    if [ $rc -ne 0 ]; then
        log "  FAILED (smbclient ls returned $rc)"
        result "dir_listing_ops" "ERROR" "entries/s" "smbclient ls failed"
        return
    fi

    local listed_count
    listed_count=$(wc -l < "$OUTDIR/dir_list_output.txt")

    local duration
    duration=$(elapsed_secs "$start" "$end")
    local ops
    ops=$(calc_ops "$DIR_LIST_COUNT" "$duration")

    result "dir_listing_ops" "$ops" "entries/s" "count=$DIR_LIST_COUNT listed=$listed_count duration=${duration}s"
}

# ---------------------------------------------------------------------------
# Benchmark 5: Metadata operations (stat 1000 files via allinfo)
# ---------------------------------------------------------------------------

bench_metadata_ops() {
    log "--- Benchmark: Metadata Operations ($METADATA_COUNT files) ---"

    # Create files on the server via SSH
    log "Creating $METADATA_COUNT files on server via SSH..."
    $SSH "mkdir -p /srv/smb/${SHARE_NAME}/bench_meta && \
          cd /srv/smb/${SHARE_NAME}/bench_meta && \
          for i in \$(seq 1 $METADATA_COUNT); do \
              dd if=/dev/urandom of=file_\${i}.dat bs=4096 count=1 2>/dev/null; \
          done" >>"$LOG_FILE" 2>&1

    if [ $? -ne 0 ]; then
        log "  FAILED (SSH file creation failed)"
        result "metadata_stat_ops" "ERROR" "ops/s" "file creation failed"
        return
    fi

    # Build smbclient batch: allinfo on each file
    local cmd_script="$OUTDIR/bench_meta_cmds.txt"
    echo "cd bench_meta" > "$cmd_script"
    local i
    for i in $(seq 1 "$METADATA_COUNT"); do
        echo "allinfo file_${i}.dat" >> "$cmd_script"
    done

    log "Running allinfo on $METADATA_COUNT files..."
    local start
    start=$(now_secs)
    eval "$SMBCLIENT" < "$cmd_script" > "$OUTDIR/meta_output.txt" 2>>"$LOG_FILE"
    local rc=$?
    local end
    end=$(now_secs)

    rm -f "$cmd_script"

    if [ $rc -ne 0 ]; then
        log "  FAILED (smbclient allinfo returned $rc)"
        result "metadata_stat_ops" "ERROR" "ops/s" "smbclient allinfo failed"
        return
    fi

    local duration
    duration=$(elapsed_secs "$start" "$end")
    local ops
    ops=$(calc_ops "$METADATA_COUNT" "$duration")

    result "metadata_stat_ops" "$ops" "ops/s" "count=$METADATA_COUNT duration=${duration}s"
}

# ---------------------------------------------------------------------------
# Benchmark 6: Concurrent client scaling (1/2/4/8 parallel smbclient)
# ---------------------------------------------------------------------------

bench_concurrent_clients() {
    log "--- Benchmark: Concurrent Client Scaling ---"

    # Prepare a 64MB file on the server for read testing
    local file_size_mb=64
    local file_size_bytes=$((file_size_mb * 1048576))

    $SSH "dd if=/dev/urandom of=/srv/smb/${SHARE_NAME}/bench_conc_file bs=1M count=$file_size_mb 2>/dev/null" \
        >>"$LOG_FILE" 2>&1

    if [ $? -ne 0 ]; then
        log "  FAILED (creating concurrent test file)"
        for n in $CONCURRENT_LEVELS; do
            result "concurrent_read_${n}clients_MBps" "ERROR" "MB/s" "setup failed"
        done
        return
    fi

    for num_clients in $CONCURRENT_LEVELS; do
        log "  Testing with $num_clients parallel clients..."

        local pids=""
        local tmpdir="$OUTDIR/conc_${num_clients}"
        mkdir -p "$tmpdir"

        local start
        start=$(now_secs)

        local c
        for c in $(seq 1 "$num_clients"); do
            (
                eval "$SMBCLIENT" -c "'get bench_conc_file ${tmpdir}/out_${c}'" \
                    >>"$LOG_FILE" 2>&1
            ) &
            pids="$pids $!"
        done

        # Wait for all clients
        local all_ok=true
        for pid in $pids; do
            if ! wait "$pid"; then
                all_ok=false
            fi
        done

        local end
        end=$(now_secs)

        local duration
        duration=$(elapsed_secs "$start" "$end")

        if [ "$all_ok" = "false" ]; then
            result "concurrent_read_${num_clients}clients_MBps" "ERROR" "MB/s" "some clients failed"
        else
            # Total data = num_clients * file_size
            local total_bytes=$((num_clients * file_size_bytes))
            local aggregate_mbps
            aggregate_mbps=$(calc_mbps "$total_bytes" "$duration")
            local per_client_mbps
            per_client_mbps=$(calc_mbps "$file_size_bytes" "$duration")

            result "concurrent_read_${num_clients}clients_aggregate_MBps" \
                   "$aggregate_mbps" "MB/s" \
                   "clients=$num_clients file=${file_size_mb}MB duration=${duration}s"
            result "concurrent_read_${num_clients}clients_perclient_MBps" \
                   "$per_client_mbps" "MB/s" \
                   "clients=$num_clients file=${file_size_mb}MB duration=${duration}s"
        fi

        rm -rf "$tmpdir"
    done
}

# ---------------------------------------------------------------------------
# Generate JSON output from TSV
# ---------------------------------------------------------------------------

generate_json() {
    log "Generating JSON output..."

    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"vm_ssh_port\": $VM_SSH_PORT,"
        echo "  \"vm_smb_port\": $VM_SMB_PORT,"
        echo "  \"share\": \"$SHARE_NAME\","
        echo "  \"benchmarks\": ["

        local first=true
        # Skip header line
        tail -n +2 "$TSV_FILE" | while IFS=$'\t' read -r name value unit details; do
            if [ "$first" = "true" ]; then
                first=false
            else
                echo ","
            fi
            # Escape special characters in details
            details=$(echo "$details" | sed 's/"/\\"/g')
            printf '    {"name": "%s", "value": "%s", "unit": "%s", "details": "%s"}' \
                   "$name" "$value" "$unit" "$details"
        done

        echo ""
        echo "  ]"
        echo "}"
    } > "$JSON_FILE"

    log "JSON written to $JSON_FILE"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo "" >&2
    log "=== Benchmark Summary ==="
    log "Results TSV: $TSV_FILE"
    log "Results JSON: $JSON_FILE"
    log "Full log: $LOG_FILE"
    echo "" >&2

    # Print TSV with column alignment
    log "--- Results ---"
    if [ -f "$TSV_FILE" ]; then
        column -t -s $'\t' < "$TSV_FILE" >&2
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    preflight

    # Clean previous benchmark artifacts
    cleanup_share

    # Run benchmarks in order
    bench_sequential_write
    bench_sequential_read
    bench_small_file_create
    bench_dir_listing
    bench_metadata_ops
    bench_concurrent_clients

    # Clean up
    cleanup_share

    # Generate structured output
    generate_json

    # Print summary
    print_summary

    log "=== Benchmark complete ==="
}

main "$@"
