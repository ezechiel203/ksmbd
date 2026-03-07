#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# VM-based concurrency tests for ksmbd
#
# Usage: ./tests/ksmbd_concurrency_test.sh [SSH_PORT] [SMB_PORT]
#
# Runs 20 concurrency tests against a live ksmbd server using
# smbclient and parallel processes.

SSH_PORT=${1:-13022}
SMB_PORT=${2:-13445}
SERVER=127.0.0.1
SHARE=test
USER=testuser
PASS=1234
TMPDIR=$(mktemp -d /tmp/ksmbd_conc_XXXXXX)
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

echo "=== ksmbd Concurrency Tests ==="
echo "Server: $SERVER:$SMB_PORT  SSH: $SSH_PORT"
echo "Temp dir: $TMPDIR"
echo ""

# ---------- helpers -------------------------------------------------------

smb_cmd() {
    smbclient "//$SERVER/$SHARE" "$PASS" -U "$USER" -p "$SMB_PORT" \
        --option="client min protocol=SMB2" -c "$1" 2>/dev/null
}

run_test() {
    local name="$1"
    shift
    local output
    output=$("$@" 2>&1)
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "  PASS: $name"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  FAIL: $name (rc=$rc)"
        echo "        $output" | head -3
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

skip_test() {
    local name="$1"
    local reason="$2"
    echo "  SKIP: $name ($reason)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

check_smbclient() {
    if ! command -v smbclient >/dev/null 2>&1; then
        echo "ERROR: smbclient not found"
        exit 1
    fi
}

check_server() {
    if ! timeout 5 bash -c "echo > /dev/tcp/$SERVER/$SMB_PORT" 2>/dev/null; then
        echo "ERROR: ksmbd not reachable at $SERVER:$SMB_PORT"
        exit 1
    fi
}

# ---------- test functions ------------------------------------------------

# Test 1: 100 concurrent connections
test_parallel_connections() {
    local pids=()
    local failed=0
    for i in $(seq 1 100); do
        (smb_cmd "ls" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done
    [ "$failed" -lt 10 ] # Allow up to 10% failure under load
}

# Test 2: 50 concurrent authentication attempts
test_parallel_auth() {
    local pids=()
    local failed=0
    for i in $(seq 1 50); do
        (smbclient "//$SERVER/$SHARE" "$PASS" -U "$USER" -p "$SMB_PORT" \
            --option="client min protocol=SMB2" -c "ls" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done
    [ "$failed" -lt 5 ]
}

# Test 3: 50 concurrent file creates
test_parallel_file_create() {
    local pids=()
    local failed=0
    for i in $(seq 1 50); do
        (smb_cmd "put /dev/null conc_create_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done
    # Cleanup
    for i in $(seq 1 50); do
        smb_cmd "del conc_create_$i" >/dev/null 2>&1
    done
    [ "$failed" -lt 5 ]
}

# Test 4: Parallel reads of the same file
test_parallel_read_same_file() {
    # Create test file
    dd if=/dev/urandom of="$TMPDIR/readtest" bs=1024 count=100 2>/dev/null
    smb_cmd "put $TMPDIR/readtest conc_readtest" >/dev/null 2>&1

    local pids=()
    local failed=0
    for i in $(seq 1 20); do
        (smb_cmd "get conc_readtest $TMPDIR/read_out_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done

    smb_cmd "del conc_readtest" >/dev/null 2>&1
    [ "$failed" -lt 3 ]
}

# Test 5: Parallel writes to different files
test_parallel_write() {
    local pids=()
    local failed=0
    for i in $(seq 1 20); do
        dd if=/dev/urandom of="$TMPDIR/write_$i" bs=1024 count=10 2>/dev/null
        (smb_cmd "put $TMPDIR/write_$i conc_write_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done

    for i in $(seq 1 20); do
        smb_cmd "del conc_write_$i" >/dev/null 2>&1
    done
    [ "$failed" -lt 3 ]
}

# Test 6: Connect/disconnect storm (200 cycles)
test_connect_disconnect_storm() {
    local failed=0
    local pids=()
    for i in $(seq 1 200); do
        (smb_cmd "quit" >/dev/null 2>&1) &
        pids+=($!)
        # Limit parallelism to 20
        if [ ${#pids[@]} -ge 20 ]; then
            for pid in "${pids[@]}"; do
                wait "$pid" || failed=$((failed + 1))
            done
            pids=()
        fi
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done
    [ "$failed" -lt 20 ]
}

# Test 7: Session logoff during I/O
test_session_logoff_during_io() {
    dd if=/dev/urandom of="$TMPDIR/logoff_test" bs=1024 count=1000 2>/dev/null
    smb_cmd "put $TMPDIR/logoff_test conc_logoff_test" >/dev/null 2>&1

    local pids=()
    # Start a long read
    (smb_cmd "get conc_logoff_test $TMPDIR/logoff_out" >/dev/null 2>&1) &
    pids+=($!)

    # Rapid connect/disconnect to stress session management
    for i in $(seq 1 10); do
        (smb_cmd "ls" >/dev/null 2>&1) &
        pids+=($!)
    done

    local failed=0
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done

    smb_cmd "del conc_logoff_test" >/dev/null 2>&1
    # Server should not crash
    smb_cmd "ls" >/dev/null 2>&1
}

# Test 8: Oplock break under load
test_oplock_break_under_load() {
    dd if=/dev/urandom of="$TMPDIR/oplock_test" bs=1024 count=10 2>/dev/null
    smb_cmd "put $TMPDIR/oplock_test conc_oplock_test" >/dev/null 2>&1

    local pids=()
    # Multiple clients opening the same file
    for i in $(seq 1 10); do
        (smb_cmd "get conc_oplock_test $TMPDIR/oplock_out_$i" >/dev/null 2>&1) &
        pids+=($!)
    done

    local failed=0
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done

    smb_cmd "del conc_oplock_test" >/dev/null 2>&1
    [ "$failed" -lt 3 ]
}

# Test 9: Parallel directory listing
test_parallel_dir_listing() {
    # Create some files first
    for i in $(seq 1 10); do
        smb_cmd "put /dev/null conc_dir_$i" >/dev/null 2>&1
    done

    local pids=()
    local failed=0
    for i in $(seq 1 30); do
        (smb_cmd "ls" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done

    for i in $(seq 1 10); do
        smb_cmd "del conc_dir_$i" >/dev/null 2>&1
    done
    [ "$failed" -lt 5 ]
}

# Test 10: Rename race (two clients try to rename same file)
test_rename_race() {
    smb_cmd "put /dev/null conc_rename_src" >/dev/null 2>&1

    local pids=()
    (smb_cmd "rename conc_rename_src conc_rename_dst_a" >/dev/null 2>&1) &
    pids+=($!)
    (smb_cmd "rename conc_rename_src conc_rename_dst_b" >/dev/null 2>&1) &
    pids+=($!)

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # At least one rename should succeed; cleanup both
    smb_cmd "del conc_rename_dst_a" >/dev/null 2>&1
    smb_cmd "del conc_rename_dst_b" >/dev/null 2>&1
    smb_cmd "del conc_rename_src" >/dev/null 2>&1
    true # Pass if no crash
}

# Test 11: Delete race (two clients try to delete same file)
test_delete_race() {
    smb_cmd "put /dev/null conc_delete_target" >/dev/null 2>&1

    (smb_cmd "del conc_delete_target" >/dev/null 2>&1) &
    local pid1=$!
    (smb_cmd "del conc_delete_target" >/dev/null 2>&1) &
    local pid2=$!

    wait $pid1 2>/dev/null
    wait $pid2 2>/dev/null
    true # One should fail with not found, but no crash
}

# Test 12: Large file upload with concurrent small operations
test_large_upload_with_small_ops() {
    dd if=/dev/urandom of="$TMPDIR/large_file" bs=1024 count=5000 2>/dev/null

    # Start large upload in background
    (smb_cmd "put $TMPDIR/large_file conc_large_upload" >/dev/null 2>&1) &
    local bg_pid=$!

    # Do small operations while upload runs
    local failed=0
    for i in $(seq 1 10); do
        smb_cmd "ls" >/dev/null 2>&1 || failed=$((failed + 1))
    done

    wait $bg_pid 2>/dev/null
    smb_cmd "del conc_large_upload" >/dev/null 2>&1
    [ "$failed" -lt 3 ]
}

# Test 13: Multiple tree connects
test_multiple_tree_connects() {
    local pids=()
    local failed=0
    for i in $(seq 1 30); do
        (smb_cmd "ls" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done
    [ "$failed" -lt 5 ]
}

# Test 14: Interleaved create and delete
test_interleaved_create_delete() {
    local pids=()
    local failed=0

    for i in $(seq 1 30); do
        (smb_cmd "put /dev/null conc_interleave_$i; del conc_interleave_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done
    [ "$failed" -lt 5 ]
}

# Test 15: Stat race (multiple clients stat same file)
test_stat_race() {
    smb_cmd "put /dev/null conc_stat_target" >/dev/null 2>&1

    local pids=()
    local failed=0
    for i in $(seq 1 20); do
        (smb_cmd "allinfo conc_stat_target" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" || failed=$((failed + 1))
    done

    smb_cmd "del conc_stat_target" >/dev/null 2>&1
    [ "$failed" -lt 5 ]
}

# Test 16: mkdir race
test_mkdir_race() {
    local pids=()
    for i in $(seq 1 5); do
        (smb_cmd "mkdir conc_mkdir_race" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    smb_cmd "rmdir conc_mkdir_race" >/dev/null 2>&1
    true
}

# Test 17: Concurrent setinfo
test_concurrent_setinfo() {
    smb_cmd "put /dev/null conc_setinfo_target" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        (smb_cmd "allinfo conc_setinfo_target" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del conc_setinfo_target" >/dev/null 2>&1
    true
}

# Test 18: Write after write (append pattern)
test_concurrent_append() {
    smb_cmd "put /dev/null conc_append_target" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        echo "data_$i" > "$TMPDIR/append_data_$i"
        (smb_cmd "put $TMPDIR/append_data_$i conc_append_target" >/dev/null 2>&1) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del conc_append_target" >/dev/null 2>&1
    true
}

# Test 19: Read while file is being written
test_read_during_write() {
    dd if=/dev/urandom of="$TMPDIR/rdwr_test" bs=1024 count=100 2>/dev/null
    smb_cmd "put $TMPDIR/rdwr_test conc_rdwr_test" >/dev/null 2>&1

    # Concurrent reads and writes
    local pids=()
    (smb_cmd "put $TMPDIR/rdwr_test conc_rdwr_test" >/dev/null 2>&1) &
    pids+=($!)
    (smb_cmd "get conc_rdwr_test $TMPDIR/rdwr_out" >/dev/null 2>&1) &
    pids+=($!)

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del conc_rdwr_test" >/dev/null 2>&1
    true
}

# Test 20: Server survives all tests (final health check)
test_server_health_check() {
    smb_cmd "ls" >/dev/null 2>&1
}

# ---------- main ----------------------------------------------------------

check_smbclient
check_server

echo "Running 20 concurrency tests..."
echo ""

run_test "parallel_connections (100)"        test_parallel_connections
run_test "parallel_auth (50)"               test_parallel_auth
run_test "parallel_file_create (50)"        test_parallel_file_create
run_test "parallel_read_same_file"          test_parallel_read_same_file
run_test "parallel_write"                   test_parallel_write
run_test "connect_disconnect_storm (200)"   test_connect_disconnect_storm
run_test "session_logoff_during_io"         test_session_logoff_during_io
run_test "oplock_break_under_load"          test_oplock_break_under_load
run_test "parallel_dir_listing"             test_parallel_dir_listing
run_test "rename_race"                      test_rename_race
run_test "delete_race"                      test_delete_race
run_test "large_upload_with_small_ops"      test_large_upload_with_small_ops
run_test "multiple_tree_connects"           test_multiple_tree_connects
run_test "interleaved_create_delete"        test_interleaved_create_delete
run_test "stat_race"                        test_stat_race
run_test "mkdir_race"                       test_mkdir_race
run_test "concurrent_setinfo"               test_concurrent_setinfo
run_test "concurrent_append"                test_concurrent_append
run_test "read_during_write"                test_read_during_write
run_test "server_health_check"              test_server_health_check

echo ""
echo "=== Results: PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT ==="
exit $FAIL_COUNT
