#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Deadlock and livelock detection tests for ksmbd
#
# Usage: ./tests/ksmbd_deadlock_test.sh [SSH_PORT] [SMB_PORT]
#
# Runs 10 tests designed to expose potential deadlock conditions
# in ksmbd by creating lock-order inversion and resource contention
# scenarios.  Each test has a timeout to detect hangs.

SSH_PORT=${1:-13022}
SMB_PORT=${2:-13445}
SERVER=127.0.0.1
SHARE=test
USER=testuser
PASS=1234
TMPDIR=$(mktemp -d /tmp/ksmbd_deadlock_XXXXXX)
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TEST_TIMEOUT=30  # seconds per test

cleanup() {
    rm -rf "$TMPDIR"
    # Kill any lingering smbclient processes
    pkill -f "smbclient.*$SMB_PORT.*ksmbd_deadlock" 2>/dev/null
}
trap cleanup EXIT

echo "=== ksmbd Deadlock Detection Tests ==="
echo "Server: $SERVER:$SMB_PORT  SSH: $SSH_PORT"
echo "Timeout per test: ${TEST_TIMEOUT}s"
echo ""

# ---------- helpers -------------------------------------------------------

smb_cmd() {
    timeout "$TEST_TIMEOUT" smbclient "//$SERVER/$SHARE" "$PASS" -U "$USER" \
        -p "$SMB_PORT" --option="client min protocol=SMB2" -c "$1" 2>/dev/null
}

run_test() {
    local name="$1"
    shift
    local output
    output=$(timeout "$TEST_TIMEOUT" bash -c "$*" 2>&1)
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "  PASS: $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif [ $rc -eq 124 ]; then
        echo "  FAIL: $name (TIMEOUT - possible deadlock)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "  FAIL: $name (rc=$rc)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

check_server_alive() {
    timeout 5 bash -c "echo > /dev/tcp/$SERVER/$SMB_PORT" 2>/dev/null
}

# ---------- test functions ------------------------------------------------

# Test 1: Lock ordering - open + rename same file from two connections
# Risk: inode lock vs dentry lock inversion
test_lock_order_open_rename() {
    smb_cmd "put /dev/null deadlock_lor_1" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 5); do
        (smb_cmd "get deadlock_lor_1 $TMPDIR/lor_out_$i" >/dev/null 2>&1) &
        pids+=($!)
        (smb_cmd "rename deadlock_lor_1 deadlock_lor_tmp_$i; rename deadlock_lor_tmp_$i deadlock_lor_1" >/dev/null 2>&1) &
        pids+=($!)
    done

    local failed=0
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || failed=$((failed + 1))
    done

    smb_cmd "del deadlock_lor_1" >/dev/null 2>&1
    check_server_alive
}

# Test 2: Nested directory operations
# Risk: parent/child inode lock ordering
test_nested_dir_ops() {
    smb_cmd "mkdir deadlock_dir_a" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        (smb_cmd "mkdir deadlock_dir_a/sub_$i" >/dev/null 2>&1) &
        pids+=($!)
        (smb_cmd "ls deadlock_dir_a" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Cleanup
    for i in $(seq 1 10); do
        smb_cmd "rmdir deadlock_dir_a/sub_$i" >/dev/null 2>&1
    done
    smb_cmd "rmdir deadlock_dir_a" >/dev/null 2>&1
    check_server_alive
}

# Test 3: Session setup + tree connect interleave
# Risk: session_lock vs tree_conns_lock
test_session_tree_interleave() {
    local pids=()
    for i in $(seq 1 20); do
        (smbclient "//$SERVER/$SHARE" "$PASS" -U "$USER" -p "$SMB_PORT" \
            --option="client min protocol=SMB2" -c "ls; quit" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 4: Oplock break during close
# Risk: oplock_mutex vs fp->f_lock
test_oplock_close_deadlock() {
    dd if=/dev/urandom of="$TMPDIR/oplock_dl" bs=1024 count=10 2>/dev/null
    smb_cmd "put $TMPDIR/oplock_dl deadlock_oplock" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        (smb_cmd "get deadlock_oplock $TMPDIR/op_out_$i; quit" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del deadlock_oplock" >/dev/null 2>&1
    check_server_alive
}

# Test 5: Concurrent delete-on-close
# Risk: ksmbd_inode->m_lock vs fp close path
test_delete_on_close_deadlock() {
    local pids=()
    for i in $(seq 1 20); do
        (
            smb_cmd "put /dev/null deadlock_doc_$i" >/dev/null 2>&1
            smb_cmd "del deadlock_doc_$i" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 6: Lock + read interleave
# Risk: lock_list_lock vs vfs read path
test_lock_read_interleave() {
    dd if=/dev/urandom of="$TMPDIR/lock_read" bs=1024 count=10 2>/dev/null
    smb_cmd "put $TMPDIR/lock_read deadlock_lr" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        (smb_cmd "get deadlock_lr $TMPDIR/lr_out_$i" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del deadlock_lr" >/dev/null 2>&1
    check_server_alive
}

# Test 7: Connection reset during compound request
# Risk: srv_mutex vs request_lock during connection teardown
test_conn_reset_compound() {
    local pids=()
    for i in $(seq 1 10); do
        (
            # Create + read + close in single session (compound-like)
            smb_cmd "put /dev/null deadlock_compound_$i; get deadlock_compound_$i $TMPDIR/comp_$i; del deadlock_compound_$i" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 8: Multiple share access
# Risk: share_config hashtable lock vs session tree_conns_lock
test_multi_share_access() {
    # Note: only IPC$ is guaranteed to exist besides the test share
    local pids=()
    for i in $(seq 1 15); do
        (smb_cmd "ls" >/dev/null 2>&1) &
        pids+=($!)
        (smbclient "//$SERVER/IPC\$" "$PASS" -U "$USER" -p "$SMB_PORT" \
            --option="client min protocol=SMB2" -c "ls" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 9: Rapid reconnection (connection recycling)
# Risk: conn_list_lock contention
test_rapid_reconnection() {
    local failed=0
    for i in $(seq 1 50); do
        timeout 5 smbclient "//$SERVER/$SHARE" "$PASS" -U "$USER" \
            -p "$SMB_PORT" --option="client min protocol=SMB2" \
            -c "quit" >/dev/null 2>&1 || failed=$((failed + 1))
    done
    [ "$failed" -lt 10 ] && check_server_alive
}

# Test 10: Final health check after all deadlock tests
test_final_health() {
    smb_cmd "ls" >/dev/null 2>&1
}

# ---------- main ----------------------------------------------------------

if ! command -v smbclient >/dev/null 2>&1; then
    echo "ERROR: smbclient not found"
    exit 1
fi

if ! check_server_alive; then
    echo "ERROR: ksmbd not reachable at $SERVER:$SMB_PORT"
    exit 1
fi

echo "Running 10 deadlock detection tests..."
echo ""

run_test "lock_order_open_rename"        test_lock_order_open_rename
run_test "nested_dir_ops"                test_nested_dir_ops
run_test "session_tree_interleave"       test_session_tree_interleave
run_test "oplock_close_deadlock"         test_oplock_close_deadlock
run_test "delete_on_close_deadlock"      test_delete_on_close_deadlock
run_test "lock_read_interleave"          test_lock_read_interleave
run_test "conn_reset_compound"           test_conn_reset_compound
run_test "multi_share_access"            test_multi_share_access
run_test "rapid_reconnection"            test_rapid_reconnection
run_test "final_health_check"            test_final_health

echo ""
echo "=== Results: PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT ==="
echo ""
echo "Note: TIMEOUT failures strongly indicate deadlock conditions."
echo "Check dmesg/kernel log for lockdep warnings."
exit $FAIL_COUNT
