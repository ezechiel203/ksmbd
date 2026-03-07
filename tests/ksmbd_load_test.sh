#!/bin/bash
# KSMBD Load / Stress / Consistency Test Suite
# Tests: concurrent writers, parallel locks, large transfers, sustained throughput, dmesg checks
# Usage: bash ksmbd_load_test.sh [HOST] [PORT] [USER] [PASS] [DURATION_SEC]

HOST="${1:-127.0.0.1}"
SMB_PORT="${2:-445}"
USER="${3:-testuser}"
PASS="${4:-testpass}"
SHARE="test"
DURATION="${5:-60}"

PASS_COUNT=0; FAIL_COUNT=0
FAILED=()
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; NC='\033[0m'
ok()   { ((PASS_COUNT++)); echo -e "${GREEN}PASS${NC}: $1"; }
fail() { ((FAIL_COUNT++)); FAILED+=("$1"); echo -e "${RED}FAIL${NC}: $1${2:+ — $2}"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}"; }

SMB3() { smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3_11 "$@" 2>&1; }
TMPDIR=$(mktemp -d); trap "rm -rf $TMPDIR" EXIT

echo "========================================"
echo " KSMBD Load + Consistency Test"
echo " Target: //$HOST:$SMB_PORT/$SHARE"
echo " Duration: ${DURATION}s per phase"
echo " Date: $(date)"
echo "========================================"

# ─── PHASE 1: Parallel Write/Read Consistency ────────────────────────────────
header "Phase 1: Parallel Write/Read Consistency (8 workers)"

WORKER_ERRORS=0
cleanup_workers() {
    SMB3 -c "$(for i in $(seq 1 8); do echo -n "del load_worker_$i.bin; "; done) quit" > /dev/null 2>&1
}

# Each worker writes unique data, reads it back, verifies
run_worker() {
    local id=$1
    local fname="load_worker_$id.bin"
    local data="worker${id}_$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | base64 -w0)"
    echo "$data" > "$TMPDIR/w${id}_src.txt"

    # Write
    smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3_11 \
        -c "put $TMPDIR/w${id}_src.txt $fname; quit" > /dev/null 2>&1 || { echo "WRITE_FAIL"; return 1; }

    # Read back
    smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3_11 \
        -c "get $fname $TMPDIR/w${id}_got.txt; quit" > /dev/null 2>&1 || { echo "READ_FAIL"; return 1; }

    # Verify
    diff -q "$TMPDIR/w${id}_src.txt" "$TMPDIR/w${id}_got.txt" > /dev/null 2>&1 || { echo "DATA_MISMATCH"; return 1; }
    echo "OK"
}

declare -a WORKER_PIDS WORKER_RESULTS
for i in $(seq 1 8); do
    run_worker $i > "$TMPDIR/worker_${i}_result.txt" 2>&1 &
    WORKER_PIDS+=($!)
done

WORKER_ERRORS=0
for i in $(seq 1 8); do
    wait "${WORKER_PIDS[$((i-1))]}"
    result=$(cat "$TMPDIR/worker_${i}_result.txt")
    [[ "$result" == "OK" ]] || { WORKER_ERRORS=$((WORKER_ERRORS+1)); echo "  Worker $i: $result"; }
done

cleanup_workers
[[ $WORKER_ERRORS -eq 0 ]] && ok "8-worker parallel write/read/verify" || \
    fail "8-worker parallel write/read/verify" "$WORKER_ERRORS workers failed"

# ─── PHASE 2: Sustained Throughput ───────────────────────────────────────────
header "Phase 2: Sustained Throughput (32 MB transfer)"

dd if=/dev/urandom of="$TMPDIR/thruput_src.bin" bs=1M count=32 2>/dev/null
START_T=$(date +%s%N)
out=$(SMB3 -c "put $TMPDIR/thruput_src.bin ksmbd_thruput.bin; quit")
END_T=$(date +%s%N)
[[ "$out" != *"NT_STATUS"* ]] && {
    ELAPSED_MS=$(( (END_T - START_T) / 1000000 ))
    THROUGHPUT_MB=$(python3 -c "print(f'{32000/$ELAPSED_MS*1000:.1f}')" 2>/dev/null || echo "?")
    ok "32 MB upload (${ELAPSED_MS}ms, ~${THROUGHPUT_MB} MB/s)"
} || fail "32 MB upload" "$out"

START_T=$(date +%s%N)
out=$(SMB3 -c "get ksmbd_thruput.bin $TMPDIR/thruput_got.bin; quit")
END_T=$(date +%s%N)
[[ "$out" != *"NT_STATUS"* ]] && {
    ELAPSED_MS=$(( (END_T - START_T) / 1000000 ))
    THROUGHPUT_MB=$(python3 -c "print(f'{32000/$ELAPSED_MS*1000:.1f}')" 2>/dev/null || echo "?")
    ok "32 MB download (${ELAPSED_MS}ms, ~${THROUGHPUT_MB} MB/s)"
} || fail "32 MB download" "$out"

cmp -s "$TMPDIR/thruput_src.bin" "$TMPDIR/thruput_got.bin" && ok "32 MB data integrity" || \
    fail "32 MB data integrity" "files differ"

SMB3 -c "del ksmbd_thruput.bin; quit" > /dev/null 2>&1

# ─── PHASE 3: Lock Contention ─────────────────────────────────────────────────
header "Phase 3: Lock Contention (4 concurrent smbtorture lock clients)"

if command -v smbtorture > /dev/null 2>&1; then
    declare -a LOCK_PIDS
    for i in 1 2 3 4; do
        smbtorture "//$HOST/$SHARE" -U "$USER%$PASS" -p "$SMB_PORT" -m SMB3_11 \
            smb2.lock.valid1 smb2.lock.valid2 smb2.lock.valid3 -d 0 --timeout 30 \
            > "$TMPDIR/lock_$i.out" 2>&1 &
        LOCK_PIDS+=($!)
    done
    LOCK_FAILS=0
    for i in 1 2 3 4; do
        wait "${LOCK_PIDS[$((i-1))]}"
        out=$(cat "$TMPDIR/lock_$i.out")
        [[ "$out" == *"success: valid1"* && "$out" == *"success: valid2"* ]] || \
            { LOCK_FAILS=$((LOCK_FAILS+1)); }
    done
    [[ $LOCK_FAILS -eq 0 ]] && ok "4 concurrent lock test clients (all passed)" || \
        fail "Concurrent lock contention" "$LOCK_FAILS clients failed"
else
    skip_count=$((SKIP_COUNT+1))
    echo -e "${YELLOW}SKIP${NC}: Lock contention — smbtorture not found"
fi

# ─── PHASE 4: Rapid Session Create/Destroy ───────────────────────────────────
header "Phase 4: Rapid Session Create/Destroy (50 sessions)"

SESSION_FAILS=0
for i in $(seq 1 50); do
    out=$(smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3_11 \
        -c "ls; quit" 2>&1)
    [[ "$out" == *"blocks of size"* ]] || SESSION_FAILS=$((SESSION_FAILS+1))
done
[[ $SESSION_FAILS -eq 0 ]] && ok "50 rapid session create/destroy" || \
    fail "Rapid session create/destroy" "$SESSION_FAILS failures"

# ─── PHASE 5: Mixed Operation Storm ──────────────────────────────────────────
header "Phase 5: Mixed Operation Storm (create/write/read/del in parallel, ${DURATION}s)"

storm_worker() {
    local id=$1
    local end=$(($(date +%s) + $2))
    local iters=0 errors=0
    while [[ $(date +%s) -lt $end ]]; do
        local fname="storm_${id}_$iters.tmp"
        local content="data_${id}_${iters}_$(date +%s%N)"
        echo "$content" > "$TMPDIR/storm_src_${id}.txt"

        smbclient -U "$USER%$PASS" "//$HOST/$SHARE" -p "$SMB_PORT" -m SMB3_11 \
            -c "put $TMPDIR/storm_src_${id}.txt $fname; get $fname $TMPDIR/storm_got_${id}.txt; del $fname; quit" \
            > /dev/null 2>&1 || { errors=$((errors+1)); iters=$((iters+1)); continue; }

        diff -q "$TMPDIR/storm_src_${id}.txt" "$TMPDIR/storm_got_${id}.txt" > /dev/null 2>&1 || \
            errors=$((errors+1))
        iters=$((iters+1))
    done
    echo "$iters $errors"
}

STORM_DURATION=${DURATION}
declare -a STORM_PIDS
for i in $(seq 1 6); do
    storm_worker $i $STORM_DURATION > "$TMPDIR/storm_result_$i.txt" 2>&1 &
    STORM_PIDS+=($!)
done

echo "  Running $STORM_DURATION second storm with 6 workers..."
TOTAL_OPS=0; TOTAL_ERRS=0
for i in $(seq 1 6); do
    wait "${STORM_PIDS[$((i-1))]}"
    read iters errors < "$TMPDIR/storm_result_$i.txt"
    TOTAL_OPS=$((TOTAL_OPS + iters))
    TOTAL_ERRS=$((TOTAL_ERRS + errors))
done
ERROR_RATE=0
[[ $TOTAL_OPS -gt 0 ]] && ERROR_RATE=$(python3 -c "print(f'{$TOTAL_ERRS*100/$TOTAL_OPS:.1f}')" 2>/dev/null || echo "?")
echo "  Total operations: $TOTAL_OPS, Errors: $TOTAL_ERRS, Error rate: ${ERROR_RATE}%"
[[ $TOTAL_ERRS -eq 0 ]] && ok "Mixed operation storm: $TOTAL_OPS ops, 0 errors" || \
    [[ $TOTAL_ERRS -lt $((TOTAL_OPS / 20)) ]] && \
        ok "Mixed operation storm: $TOTAL_OPS ops, ${ERROR_RATE}% error rate (acceptable)" || \
        fail "Mixed operation storm: error rate ${ERROR_RATE}% too high"

# ─── PHASE 6: Kernel Health Check ────────────────────────────────────────────
header "Phase 6: Kernel Health Check"

# This requires SSH to the VM — done by caller after running tests on VM itself
# Here we check the local dmesg for any ksmbd crashes if running on VM directly
if [[ -f /proc/modules ]] && grep -q ksmbd /proc/modules; then
    DMESG_WARNINGS=$(dmesg 2>/dev/null | grep ksmbd | grep -iE "BUG|WARN|panic|null pointer|oops|use-after-free|double free" | wc -l)
    [[ $DMESG_WARNINGS -eq 0 ]] && ok "No kernel BUG/WARN/panic in dmesg" || \
        fail "Kernel warnings detected" "$DMESG_WARNINGS warning lines"

    CREDIT_ERRORS=$(dmesg 2>/dev/null | grep ksmbd | grep -i "credit" | grep -i "error\|fail\|underflow\|overflow" | wc -l)
    [[ $CREDIT_ERRORS -eq 0 ]] && ok "No credit accounting errors" || \
        fail "Credit accounting errors" "$CREDIT_ERRORS error lines"
else
    echo -e "${YELLOW}SKIP${NC}: Kernel health check — not running on the VM"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo " Load Test Summary"
echo "========================================"
echo -e " ${GREEN}PASS: $PASS_COUNT${NC}"
echo -e " ${RED}FAIL: $FAIL_COUNT${NC}"
[[ ${#FAILED[@]} -gt 0 ]] && { echo -e "${RED}Failed:${NC}"; for t in "${FAILED[@]}"; do echo "  - $t"; done; }
echo "========================================"
[[ $FAIL_COUNT -eq 0 ]] && exit 0 || exit 1
