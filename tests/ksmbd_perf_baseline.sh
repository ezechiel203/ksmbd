#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# ksmbd_perf_baseline.sh — SMB2 performance regression detection framework
#
# Runs a suite of throughput, IOPS, and latency benchmarks against a live
# ksmbd VM instance.  Results are stored as JSON.  In comparison mode the
# script loads a baseline JSON, runs all benchmarks again, computes the
# percentage change for each metric, and flags any regression greater than
# 10 % as a FAIL.
#
# Usage:
#   Generate a new baseline:
#     ./tests/ksmbd_perf_baseline.sh --generate \
#         --host 127.0.0.1 --port 13445 --share test \
#         [--ssh-port 13022] [--user testuser] [--pass 1234] \
#         [--output baseline.json]
#
#   Compare against a previous baseline:
#     ./tests/ksmbd_perf_baseline.sh --compare baseline.json \
#         --host 127.0.0.1 --port 13445 --share test \
#         [--ssh-port 13022] [--user testuser] [--pass 1234]
#
# VM access pattern (same as vm/sweep-smb2.sh):
#   SSH:  sshpass -p root ssh -p SSH_PORT -o StrictHostKeyChecking=no root@HOST
#
# Prerequisites:
#   smbclient, sshpass, awk, python3 (for JSON arithmetic), date with %s.%N
#
# Exit code:
#   0  all benchmarks within tolerance (or generate mode completed)
#   1  one or more regressions detected (compare mode)
#   2  usage / environment error
#
# ─────────────────────────────────────────────────────────────────────────────
set -u

# ─────────────────────────────────────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────────────────────────────────────
MODE=""
BASELINE_FILE=""
OUTPUT_FILE=""
SMB_HOST="127.0.0.1"
SMB_PORT="445"
SHARE_NAME="test"
SSH_PORT="22"
SMB_USER="testuser"
SMB_PASS="1234"
REGRESSION_THRESHOLD=10   # percent drop that constitutes a regression

# Benchmark parameters
SEQ_FILE_SIZE_MB=64        # sequential file size (64 MB to keep runtime short)
SMALL_FILE_COUNT=1000      # number of 1KB files for create/read benchmarks
META_FILE_COUNT=1000       # number of files for stat benchmark
DIR_ENTRY_COUNT=1000       # directory listing size

WORKDIR=""

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
Usage:
  $0 --generate [OPTIONS]
  $0 --compare BASELINE.json [OPTIONS]

Options:
  --host HOST         SMB server address  (default: 127.0.0.1)
  --port PORT         SMB TCP port        (default: 445)
  --share SHARE       Share name          (default: test)
  --ssh-port PORT     SSH port for VM     (default: 22)
  --user USER         SMB username        (default: testuser)
  --pass PASS         SMB password        (default: 1234)
  --output FILE       JSON output path    (default: ksmbd_perf_<timestamp>.json)
  --threshold N       Regression % limit  (default: 10)
  --seq-size MB       Sequential file MB  (default: 64)
  --small-count N     Small file count    (default: 1000)
EOF
    exit 2
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --generate)
                MODE="generate"
                shift
                ;;
            --compare)
                MODE="compare"
                BASELINE_FILE="${2:?--compare requires a filename}"
                shift 2
                ;;
            --host)       SMB_HOST="${2:?}";  shift 2 ;;
            --port)       SMB_PORT="${2:?}";  shift 2 ;;
            --share)      SHARE_NAME="${2:?}"; shift 2 ;;
            --ssh-port)   SSH_PORT="${2:?}";  shift 2 ;;
            --user)       SMB_USER="${2:?}";  shift 2 ;;
            --pass)       SMB_PASS="${2:?}";  shift 2 ;;
            --output)     OUTPUT_FILE="${2:?}"; shift 2 ;;
            --threshold)  REGRESSION_THRESHOLD="${2:?}"; shift 2 ;;
            --seq-size)   SEQ_FILE_SIZE_MB="${2:?}"; shift 2 ;;
            --small-count) SMALL_FILE_COUNT="${2:?}"; shift 2 ;;
            -h|--help)    usage ;;
            *)
                echo "Unknown option: $1" >&2
                usage
                ;;
        esac
    done

    if [ -z "$MODE" ]; then
        echo "ERROR: specify --generate or --compare BASELINE.json" >&2
        usage
    fi

    if [ "$MODE" = "compare" ] && [ ! -f "$BASELINE_FILE" ]; then
        echo "ERROR: baseline file not found: $BASELINE_FILE" >&2
        exit 2
    fi

    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="ksmbd_perf_$(date +%Y%m%dT%H%M%S).json"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
log() {
    echo "[$(date '+%H:%M:%S')] $*" >&2
}

die() {
    log "FATAL: $*"
    exit 2
}

# High-resolution timestamp (seconds.nanoseconds)
now_secs() {
    date +%s.%N 2>/dev/null || date +%s
}

# elapsed_secs START END  →  floating-point seconds
elapsed_secs() {
    awk "BEGIN{printf \"%.3f\", $2 - $1}"
}

# calc_mbps SIZE_BYTES DURATION_SECS  →  MB/s string
calc_mbps() {
    local bytes="$1"
    local dur="$2"
    awk "BEGIN{if($dur>0) printf \"%.2f\", ($bytes/1048576)/$dur; else print \"0\"}"
}

# calc_ops COUNT DURATION_SECS  →  ops/s string
calc_ops() {
    local count="$1"
    local dur="$2"
    awk "BEGIN{if($dur>0) printf \"%.2f\", $count/$dur; else print \"0\"}"
}

# smbclient convenience wrapper
smb_run() {
    smbclient "//${SMB_HOST}/${SHARE_NAME}" \
        -p "${SMB_PORT}" \
        -U "${SMB_USER}%${SMB_PASS}" \
        --option='client min protocol=SMB3_11' \
        --option='socket options=TCP_NODELAY' \
        -c "$1" \
        >"${WORKDIR}/smb_last.log" 2>&1
}

# SSH wrapper matching sweep-smb2.sh pattern
vm_ssh() {
    sshpass -p root ssh \
        -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "root@${SMB_HOST}" \
        "$@" \
        >>"${WORKDIR}/ssh.log" 2>&1
}

# Quote a value for JSON (handles numeric strings — leave numbers bare)
json_val() {
    local v="$1"
    # If value looks like a number (possibly with decimal), emit bare
    if echo "$v" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
        printf '%s' "$v"
    else
        printf '"%s"' "$v"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────────────
preflight() {
    command -v smbclient >/dev/null 2>&1 || die "smbclient not found"
    command -v sshpass   >/dev/null 2>&1 || die "sshpass not found"
    command -v awk       >/dev/null 2>&1 || die "awk not found"

    WORKDIR=$(mktemp -d /tmp/ksmbd_perf_XXXXXX)
    log "Working directory: $WORKDIR"

    log "Checking SMB connectivity to //${SMB_HOST}/${SHARE_NAME}:${SMB_PORT}..."
    if ! smb_run 'ls'; then
        cat "${WORKDIR}/smb_last.log" >&2
        die "Cannot connect to SMB share — is ksmbd running?"
    fi
    log "SMB connectivity OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup benchmark artifacts from the share
# ─────────────────────────────────────────────────────────────────────────────
cleanup_share() {
    log "Cleaning up benchmark artifacts..."
    # Use SSH for reliable recursive deletion
    vm_ssh "rm -rf \
        /srv/smb/${SHARE_NAME}/perf_seq_file \
        /srv/smb/${SHARE_NAME}/perf_small \
        /srv/smb/${SHARE_NAME}/perf_read \
        /srv/smb/${SHARE_NAME}/perf_meta \
        /srv/smb/${SHARE_NAME}/perf_dir \
        2>/dev/null; true"
    # Also try via smbclient (catches cases where share root differs)
    smb_run 'deltree perf_small; deltree perf_read; deltree perf_meta; deltree perf_dir; rm perf_seq_file' >/dev/null 2>&1 || true
}

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark 1: Sequential write throughput
#
# Creates a local file of SEQ_FILE_SIZE_MB megabytes (urandom) and uploads
# it via smbclient put, measuring wall-clock time.
# Result: MB/s
# ─────────────────────────────────────────────────────────────────────────────
bench_seq_write() {
    log "--- Benchmark 1: Sequential write (${SEQ_FILE_SIZE_MB} MB) ---"

    local tmpfile="${WORKDIR}/seq_write_src"
    local size_bytes=$(( SEQ_FILE_SIZE_MB * 1048576 ))

    dd if=/dev/urandom of="$tmpfile" bs=1M count="${SEQ_FILE_SIZE_MB}" \
        conv=fsync 2>/dev/null

    local t0 t1 dur mbps
    t0=$(now_secs)
    if smbclient "//${SMB_HOST}/${SHARE_NAME}" \
            -p "${SMB_PORT}" \
            -U "${SMB_USER}%${SMB_PASS}" \
            --option='client min protocol=SMB3_11' \
            -c "put ${tmpfile} perf_seq_file" \
            >"${WORKDIR}/bench1.log" 2>&1; then
        t1=$(now_secs)
        dur=$(elapsed_secs "$t0" "$t1")
        mbps=$(calc_mbps "$size_bytes" "$dur")
        log "  seq_write_mbps=${mbps} (${dur}s)"
    else
        log "  FAILED: $(cat "${WORKDIR}/bench1.log")"
        mbps="0"
    fi

    rm -f "$tmpfile"
    SEQ_WRITE_MBPS="$mbps"
}

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark 2: Sequential read throughput
#
# Downloads the file previously uploaded by bench_seq_write via smbclient get.
# Result: MB/s
# ─────────────────────────────────────────────────────────────────────────────
bench_seq_read() {
    log "--- Benchmark 2: Sequential read (${SEQ_FILE_SIZE_MB} MB) ---"

    local tmpfile="${WORKDIR}/seq_read_dst"
    local size_bytes=$(( SEQ_FILE_SIZE_MB * 1048576 ))

    local t0 t1 dur mbps actual_bytes
    t0=$(now_secs)
    if smbclient "//${SMB_HOST}/${SHARE_NAME}" \
            -p "${SMB_PORT}" \
            -U "${SMB_USER}%${SMB_PASS}" \
            --option='client min protocol=SMB3_11' \
            -c "get perf_seq_file ${tmpfile}" \
            >"${WORKDIR}/bench2.log" 2>&1; then
        t1=$(now_secs)
        dur=$(elapsed_secs "$t0" "$t1")
        actual_bytes=$(stat -c%s "$tmpfile" 2>/dev/null || echo "$size_bytes")
        mbps=$(calc_mbps "$actual_bytes" "$dur")
        log "  seq_read_mbps=${mbps} (${dur}s, ${actual_bytes} bytes)"
    else
        log "  FAILED: $(cat "${WORKDIR}/bench2.log")"
        mbps="0"
    fi

    rm -f "$tmpfile"
    SEQ_READ_MBPS="$mbps"
}

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark 3: Small file create rate
#
# Creates SMALL_FILE_COUNT × 1 KB files in a subdirectory via smbclient
# batch commands.  Measures total wall-clock time from mkdir to last put.
# Result: files/s
# ─────────────────────────────────────────────────────────────────────────────
bench_small_create() {
    log "--- Benchmark 3: Small file create (${SMALL_FILE_COUNT} × 1 KB) ---"

    # Prepare a local 1 KB template
    local template="${WORKDIR}/1k_template"
    dd if=/dev/urandom of="$template" bs=1024 count=1 2>/dev/null

    # Build smbclient batch script
    local cmdfile="${WORKDIR}/bench3_cmds.txt"
    printf 'mkdir perf_small\ncd perf_small\n' > "$cmdfile"
    local i=1
    while [ "$i" -le "$SMALL_FILE_COUNT" ]; do
        printf 'put %s file_%d.dat\n' "$template" "$i" >> "$cmdfile"
        i=$(( i + 1 ))
    done

    local t0 t1 dur ops
    t0=$(now_secs)
    if smbclient "//${SMB_HOST}/${SHARE_NAME}" \
            -p "${SMB_PORT}" \
            -U "${SMB_USER}%${SMB_PASS}" \
            --option='client min protocol=SMB3_11' \
            < "$cmdfile" \
            >"${WORKDIR}/bench3.log" 2>&1; then
        t1=$(now_secs)
        dur=$(elapsed_secs "$t0" "$t1")
        ops=$(calc_ops "$SMALL_FILE_COUNT" "$dur")
        log "  small_file_create_ops=${ops} (${dur}s)"
    else
        log "  FAILED: $(tail -5 "${WORKDIR}/bench3.log")"
        ops="0"
    fi

    rm -f "$template" "$cmdfile"
    SMALL_CREATE_OPS="$ops"
}

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark 4: Small file read rate
#
# Reads back the SMALL_FILE_COUNT files created in bench_seq_create via
# smbclient batch get commands.
# Result: files/s
# ─────────────────────────────────────────────────────────────────────────────
bench_small_read() {
    log "--- Benchmark 4: Small file read (${SMALL_FILE_COUNT} × 1 KB) ---"

    local dstdir="${WORKDIR}/small_read_dst"
    mkdir -p "$dstdir"

    # Build smbclient batch script
    local cmdfile="${WORKDIR}/bench4_cmds.txt"
    printf 'cd perf_small\n' > "$cmdfile"
    local i=1
    while [ "$i" -le "$SMALL_FILE_COUNT" ]; do
        printf 'get file_%d.dat %s/file_%d.dat\n' "$i" "$dstdir" "$i" >> "$cmdfile"
        i=$(( i + 1 ))
    done

    local t0 t1 dur ops
    t0=$(now_secs)
    if smbclient "//${SMB_HOST}/${SHARE_NAME}" \
            -p "${SMB_PORT}" \
            -U "${SMB_USER}%${SMB_PASS}" \
            --option='client min protocol=SMB3_11' \
            < "$cmdfile" \
            >"${WORKDIR}/bench4.log" 2>&1; then
        t1=$(now_secs)
        dur=$(elapsed_secs "$t0" "$t1")
        ops=$(calc_ops "$SMALL_FILE_COUNT" "$dur")
        log "  small_file_read_ops=${ops} (${dur}s)"
    else
        log "  FAILED: $(tail -5 "${WORKDIR}/bench4.log")"
        ops="0"
    fi

    rm -rf "$dstdir" "$cmdfile"
    SMALL_READ_OPS="$ops"
}

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark 5: Metadata operations (stat)
#
# Creates META_FILE_COUNT files on the server via SSH (fast), then runs
# smbclient allinfo on each one to measure metadata query throughput.
# Result: ops/s
# ─────────────────────────────────────────────────────────────────────────────
bench_metadata_stat() {
    log "--- Benchmark 5: Metadata stat (${META_FILE_COUNT} × allinfo) ---"

    # Create files on server via SSH for speed
    vm_ssh "mkdir -p /srv/smb/${SHARE_NAME}/perf_meta && \
        cd /srv/smb/${SHARE_NAME}/perf_meta && \
        for i in \$(seq 1 ${META_FILE_COUNT}); do \
            dd if=/dev/urandom of=meta_\${i}.dat bs=1024 count=1 2>/dev/null; \
        done"

    local cmdfile="${WORKDIR}/bench5_cmds.txt"
    printf 'cd perf_meta\n' > "$cmdfile"
    local i=1
    while [ "$i" -le "$META_FILE_COUNT" ]; do
        printf 'allinfo meta_%d.dat\n' "$i" >> "$cmdfile"
        i=$(( i + 1 ))
    done

    local t0 t1 dur ops
    t0=$(now_secs)
    if smbclient "//${SMB_HOST}/${SHARE_NAME}" \
            -p "${SMB_PORT}" \
            -U "${SMB_USER}%${SMB_PASS}" \
            --option='client min protocol=SMB3_11' \
            < "$cmdfile" \
            >"${WORKDIR}/bench5.log" 2>&1; then
        t1=$(now_secs)
        dur=$(elapsed_secs "$t0" "$t1")
        ops=$(calc_ops "$META_FILE_COUNT" "$dur")
        log "  metadata_stat_ops=${ops} (${dur}s)"
    else
        log "  FAILED: $(tail -5 "${WORKDIR}/bench5.log")"
        ops="0"
    fi

    rm -f "$cmdfile"
    META_STAT_OPS="$ops"
}

# ─────────────────────────────────────────────────────────────────────────────
# Benchmark 6: Directory listing throughput
#
# Creates DIR_ENTRY_COUNT entries on the server via SSH, then runs a single
# smbclient ls to list them all.  Measures round-trip time for the full
# QUERY_DIRECTORY response.
# Result: entries/s (DIR_ENTRY_COUNT / elapsed)
# ─────────────────────────────────────────────────────────────────────────────
bench_dir_listing() {
    log "--- Benchmark 6: Directory listing (${DIR_ENTRY_COUNT} entries) ---"

    # Create files on server via SSH
    vm_ssh "mkdir -p /srv/smb/${SHARE_NAME}/perf_dir && \
        cd /srv/smb/${SHARE_NAME}/perf_dir && \
        for i in \$(seq 1 ${DIR_ENTRY_COUNT}); do touch entry_\${i}.txt; done"

    local t0 t1 dur listed ops
    t0=$(now_secs)
    smbclient "//${SMB_HOST}/${SHARE_NAME}" \
        -p "${SMB_PORT}" \
        -U "${SMB_USER}%${SMB_PASS}" \
        --option='client min protocol=SMB3_11' \
        -c 'cd perf_dir; ls' \
        >"${WORKDIR}/bench6.log" 2>&1
    t1=$(now_secs)

    listed=$(grep -c '\.' "${WORKDIR}/bench6.log" 2>/dev/null || echo 0)
    dur=$(elapsed_secs "$t0" "$t1")
    ops=$(calc_ops "$DIR_ENTRY_COUNT" "$dur")
    log "  dir_listing_ops=${ops} (listed=${listed} ${dur}s)"

    DIR_LIST_OPS="$ops"
}

# ─────────────────────────────────────────────────────────────────────────────
# Collect system metadata (kernel version, git commit)
# ─────────────────────────────────────────────────────────────────────────────
collect_metadata() {
    KERNEL_VER=$(vm_ssh_capture "uname -r" 2>/dev/null || uname -r 2>/dev/null || echo "unknown")
    KSMBD_COMMIT=$(git -C "$(dirname "$0")/.." rev-parse --short HEAD 2>/dev/null || echo "unknown")
    TIMESTAMP=$(date -Iseconds 2>/dev/null || date)
}

# SSH wrapper that captures output
vm_ssh_capture() {
    sshpass -p root ssh \
        -p "${SSH_PORT}" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "root@${SMB_HOST}" \
        "$@" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
# Write JSON result file
# ─────────────────────────────────────────────────────────────────────────────
write_json() {
    local outfile="$1"

    # Escape any double-quotes in string values
    local kv="${KERNEL_VER//\"/\\\"}"
    local kc="${KSMBD_COMMIT//\"/\\\"}"

    cat > "$outfile" <<EOF
{
  "timestamp": "${TIMESTAMP}",
  "kernel_version": "${kv}",
  "ksmbd_commit": "${kc}",
  "config": {
    "host": "${SMB_HOST}",
    "smb_port": ${SMB_PORT},
    "share": "${SHARE_NAME}",
    "seq_file_size_mb": ${SEQ_FILE_SIZE_MB},
    "small_file_count": ${SMALL_FILE_COUNT},
    "meta_file_count": ${META_FILE_COUNT},
    "dir_entry_count": ${DIR_ENTRY_COUNT}
  },
  "benchmarks": {
    "seq_write_mbps":      $(json_val "${SEQ_WRITE_MBPS}"),
    "seq_read_mbps":       $(json_val "${SEQ_READ_MBPS}"),
    "small_create_ops":    $(json_val "${SMALL_CREATE_OPS}"),
    "small_read_ops":      $(json_val "${SMALL_READ_OPS}"),
    "metadata_stat_ops":   $(json_val "${META_STAT_OPS}"),
    "dir_listing_ops":     $(json_val "${DIR_LIST_OPS}")
  }
}
EOF
    log "Results written to: ${outfile}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Run all benchmarks and return results in global variables
# ─────────────────────────────────────────────────────────────────────────────
run_all_benchmarks() {
    SEQ_WRITE_MBPS="0"
    SEQ_READ_MBPS="0"
    SMALL_CREATE_OPS="0"
    SMALL_READ_OPS="0"
    META_STAT_OPS="0"
    DIR_LIST_OPS="0"

    cleanup_share

    bench_seq_write
    bench_seq_read
    bench_small_create
    bench_small_read
    bench_metadata_stat
    bench_dir_listing

    cleanup_share
}

# ─────────────────────────────────────────────────────────────────────────────
# Extract a numeric field from a JSON file using awk (no jq dependency)
#
# Usage: json_get_field JSONFILE FIELD_NAME
# Returns the numeric value of .benchmarks.<FIELD_NAME>
# ─────────────────────────────────────────────────────────────────────────────
json_get_field() {
    local file="$1"
    local field="$2"
    awk -F':' -v field="\"${field}\"" '
        $1 ~ field {
            gsub(/[[:space:],]/, "", $2)
            print $2
            exit
        }
    ' "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# Percentage change: (new - old) / old * 100
# Negative means regression for throughput metrics (lower is worse).
# ─────────────────────────────────────────────────────────────────────────────
pct_change() {
    local old="$1"
    local new="$2"
    awk "BEGIN{
        if($old==0) { print \"N/A\"; exit }
        printf \"%.1f\", (($new - $old) / $old) * 100
    }"
}

# ─────────────────────────────────────────────────────────────────────────────
# Compare mode: load baseline, run benchmarks, compute deltas
# ─────────────────────────────────────────────────────────────────────────────
compare_mode() {
    log "=== ksmbd performance comparison ==="
    log "Baseline: ${BASELINE_FILE}"

    # Extract baseline values
    local b_seq_write   b_seq_read   b_small_create
    local b_small_read  b_meta_stat  b_dir_list
    b_seq_write=$(   json_get_field "$BASELINE_FILE" "seq_write_mbps")
    b_seq_read=$(    json_get_field "$BASELINE_FILE" "seq_read_mbps")
    b_small_create=$(json_get_field "$BASELINE_FILE" "small_create_ops")
    b_small_read=$(  json_get_field "$BASELINE_FILE" "small_read_ops")
    b_meta_stat=$(   json_get_field "$BASELINE_FILE" "metadata_stat_ops")
    b_dir_list=$(    json_get_field "$BASELINE_FILE" "dir_listing_ops")

    log "Baseline values loaded."
    log "  seq_write_mbps=${b_seq_write}  seq_read_mbps=${b_seq_read}"
    log "  small_create_ops=${b_small_create}  small_read_ops=${b_small_read}"
    log "  metadata_stat_ops=${b_meta_stat}  dir_listing_ops=${b_dir_list}"

    collect_metadata
    run_all_benchmarks
    write_json "$OUTPUT_FILE"

    local overall_rc=0
    local THRESHOLD_NEG
    THRESHOLD_NEG=$(awk "BEGIN{print -${REGRESSION_THRESHOLD}}")

    log ""
    log "=== Regression Analysis (threshold: ${REGRESSION_THRESHOLD}%) ==="
    printf '%-28s %12s %12s %8s %8s\n' \
        "Metric" "Baseline" "Current" "Change%" "Status" >&2

    check_metric() {
        local name="$1"
        local baseline="$2"
        local current="$3"

        local pct status
        pct=$(pct_change "$baseline" "$current")

        if [ "$pct" = "N/A" ]; then
            status="SKIP(b=0)"
        else
            # Check if pct < -THRESHOLD
            local is_regression
            is_regression=$(awk "BEGIN{print ($pct < ${THRESHOLD_NEG}) ? 1 : 0}")
            if [ "$is_regression" = "1" ]; then
                status="FAIL"
                overall_rc=1
            else
                status="OK"
            fi
        fi

        printf '%-28s %12s %12s %8s %8s\n' \
            "$name" "$baseline" "$current" "${pct}%" "$status" >&2

        # Also emit to stdout for machine parsing
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$name" "$baseline" "$current" "${pct}%" "$status"
    }

    check_metric "seq_write_mbps"    "$b_seq_write"    "$SEQ_WRITE_MBPS"
    check_metric "seq_read_mbps"     "$b_seq_read"     "$SEQ_READ_MBPS"
    check_metric "small_create_ops"  "$b_small_create" "$SMALL_CREATE_OPS"
    check_metric "small_read_ops"    "$b_small_read"   "$SMALL_READ_OPS"
    check_metric "metadata_stat_ops" "$b_meta_stat"    "$META_STAT_OPS"
    check_metric "dir_listing_ops"   "$b_dir_list"     "$DIR_LIST_OPS"

    echo "" >&2
    if [ "$overall_rc" -eq 0 ]; then
        log "RESULT: PASS — no regressions detected"
    else
        log "RESULT: FAIL — one or more metrics regressed by more than ${REGRESSION_THRESHOLD}%"
    fi
    log "Current results saved to: ${OUTPUT_FILE}"

    return "$overall_rc"
}

# ─────────────────────────────────────────────────────────────────────────────
# Generate mode: run benchmarks and save JSON baseline
# ─────────────────────────────────────────────────────────────────────────────
generate_mode() {
    log "=== ksmbd performance baseline generation ==="
    log "Output: ${OUTPUT_FILE}"

    collect_metadata
    run_all_benchmarks

    log ""
    log "=== Results ==="
    log "  seq_write_mbps:    ${SEQ_WRITE_MBPS}"
    log "  seq_read_mbps:     ${SEQ_READ_MBPS}"
    log "  small_create_ops:  ${SMALL_CREATE_OPS}"
    log "  small_read_ops:    ${SMALL_READ_OPS}"
    log "  metadata_stat_ops: ${META_STAT_OPS}"
    log "  dir_listing_ops:   ${DIR_LIST_OPS}"

    write_json "$OUTPUT_FILE"

    log "Baseline saved to: ${OUTPUT_FILE}"
    log "To compare a future run:"
    log "  $0 --compare ${OUTPUT_FILE} --host ${SMB_HOST} --port ${SMB_PORT} --share ${SHARE_NAME}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup working directory on exit
# ─────────────────────────────────────────────────────────────────────────────
cleanup_workdir() {
    if [ -n "${WORKDIR:-}" ] && [ -d "${WORKDIR:-}" ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup_workdir EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    preflight

    case "$MODE" in
        generate)
            generate_mode
            exit 0
            ;;
        compare)
            compare_mode
            exit $?
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
