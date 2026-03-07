#!/bin/bash
# perf_config.sh -- Configuration for ksmbd performance baseline suite
#
# This file is sourced by perf_baseline.sh, perf_compare.sh, and perf_track.sh.
# Override any variable via environment before running the scripts.
#
# All paths are relative to the tests/ksmbd-perf/ directory unless absolute.

# ---------------------------------------------------------------------------
# VM / SMB Target
# ---------------------------------------------------------------------------
: "${PERF_VM_NAME:=VM3}"
: "${PERF_VM_HOST:=127.0.0.1}"
: "${PERF_VM_SSH_PORT:=13022}"
: "${PERF_VM_USER:=root}"
: "${PERF_VM_PASS:=root}"

: "${PERF_SMB_HOST:=127.0.0.1}"
: "${PERF_SMB_PORT:=13445}"
: "${PERF_SMB_SHARE:=test}"
: "${PERF_SMB_USER:=testuser}"
: "${PERF_SMB_PASS:=testpass}"
: "${PERF_SMB_CREDS:=${PERF_SMB_USER}%${PERF_SMB_PASS}}"

# Share root on the VM filesystem (for SSH-side file creation)
: "${PERF_SHARE_ROOT:=/srv/smb/test}"

# ---------------------------------------------------------------------------
# Client Tool Preferences
# ---------------------------------------------------------------------------
# Preferred client for throughput tests: "smbclient" or "mount.cifs"
# mount.cifs provides more accurate throughput numbers (avoids smbclient overhead)
# but requires root privileges on the host.
: "${PERF_CLIENT_TOOL:=smbclient}"

# smbclient binary path
: "${PERF_SMBCLIENT_BIN:=smbclient}"

# Protocol version to use for benchmarks
: "${PERF_SMB_PROTOCOL:=SMB3_11}"

# ---------------------------------------------------------------------------
# Test Parameters -- Throughput
# ---------------------------------------------------------------------------
# File sizes for sequential read/write tests (space-separated list in bytes)
: "${PERF_SEQ_FILE_SIZES:=1048576 10485760 104857600}"
# Human-readable labels matching the above sizes
: "${PERF_SEQ_FILE_LABELS:=1MB 10MB 100MB}"

# ---------------------------------------------------------------------------
# Test Parameters -- IOPS
# ---------------------------------------------------------------------------
# Block size for random I/O tests
: "${PERF_RAND_BLOCK_SIZE:=4096}"
# Total file size for random I/O pool
: "${PERF_RAND_FILE_SIZE:=67108864}"
# Duration for random I/O tests in seconds
: "${PERF_RAND_DURATION:=30}"

# ---------------------------------------------------------------------------
# Test Parameters -- Directory Enumeration
# ---------------------------------------------------------------------------
# Number of files for directory listing tests (space-separated list)
: "${PERF_DIR_COUNTS:=100 1000 10000}"

# ---------------------------------------------------------------------------
# Test Parameters -- File Creation / Metadata
# ---------------------------------------------------------------------------
# Number of files for creation rate and metadata rate tests
: "${PERF_CREATE_FILE_COUNT:=1000}"
: "${PERF_METADATA_FILE_COUNT:=1000}"

# ---------------------------------------------------------------------------
# Test Parameters -- Small File Transfer
# ---------------------------------------------------------------------------
# Number of small files and their size in bytes
: "${PERF_SMALL_FILE_COUNT:=1000}"
: "${PERF_SMALL_FILE_SIZE:=4096}"

# ---------------------------------------------------------------------------
# Test Parameters -- Connection Rate
# ---------------------------------------------------------------------------
# Number of connection attempts for rate measurement
: "${PERF_CONN_ITERATIONS:=100}"

# ---------------------------------------------------------------------------
# Test Parameters -- Concurrency
# ---------------------------------------------------------------------------
# Client counts for concurrent throughput testing (space-separated)
: "${PERF_CONCURRENT_CLIENTS:=1 2 4 8}"
# File size per client for concurrent test (bytes)
: "${PERF_CONCURRENT_FILE_SIZE:=67108864}"

# ---------------------------------------------------------------------------
# Test Iteration and Warmup
# ---------------------------------------------------------------------------
# Number of times to repeat each throughput test and take the median
: "${PERF_ITERATIONS:=3}"
# Warmup runs before actual measurement (discarded)
: "${PERF_WARMUP_RUNS:=1}"

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------
# Maximum time for a single benchmark test (seconds)
: "${PERF_TEST_TIMEOUT:=300}"
# Maximum total time for the entire suite (seconds)
: "${PERF_SUITE_TIMEOUT:=3600}"

# ---------------------------------------------------------------------------
# Regression Detection Thresholds
# ---------------------------------------------------------------------------
# Default regression threshold: flag if metric drops by more than this percentage
: "${PERF_REGRESSION_THRESHOLD:=10}"
# Default improvement threshold: flag if metric improves by more than this percentage
: "${PERF_IMPROVEMENT_THRESHOLD:=10}"
# Strict mode regression threshold (used with --strict)
: "${PERF_STRICT_THRESHOLD:=0}"
# Lenient mode regression threshold (used with --lenient)
: "${PERF_LENIENT_THRESHOLD:=20}"

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
# Base directory for baseline storage
PERF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PERF_BASELINES_DIR:=${PERF_SCRIPT_DIR}/baselines}"
# Directory for temporary test artifacts
: "${PERF_WORK_DIR:=/tmp/ksmbd-perf-$$}"
# JSON output file (default: auto-named with timestamp)
: "${PERF_OUTPUT_FILE:=}"

# ---------------------------------------------------------------------------
# SSH Helper (matches ksmbd-torture vm_control.sh pattern)
# ---------------------------------------------------------------------------
PERF_SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"

perf_vm_exec() {
    sshpass -p "$PERF_VM_PASS" ssh $PERF_SSH_OPTS \
        -p "$PERF_VM_SSH_PORT" "${PERF_VM_USER}@${PERF_VM_HOST}" "$@" 2>/dev/null
}

perf_vm_exec_timeout() {
    local seconds="$1"; shift
    timeout "${seconds}s" sshpass -p "$PERF_VM_PASS" ssh $PERF_SSH_OPTS \
        -p "$PERF_VM_SSH_PORT" "${PERF_VM_USER}@${PERF_VM_HOST}" "$@" 2>/dev/null
}
