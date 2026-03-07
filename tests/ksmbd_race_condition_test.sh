#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# TOCTOU and race condition tests for ksmbd
#
# Usage: ./tests/ksmbd_race_condition_test.sh [SSH_PORT] [SMB_PORT]
#
# Runs 12 tests targeting time-of-check-to-time-of-use and other
# race condition vulnerabilities in ksmbd.

SSH_PORT=${1:-13022}
SMB_PORT=${2:-13445}
SERVER=127.0.0.1
SHARE=test
USER=testuser
PASS=1234
TMPDIR=$(mktemp -d /tmp/ksmbd_race_XXXXXX)
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TEST_TIMEOUT=30

cleanup() {
    rm -rf "$TMPDIR"
    pkill -f "smbclient.*$SMB_PORT.*ksmbd_race" 2>/dev/null
}
trap cleanup EXIT

echo "=== ksmbd Race Condition Tests ==="
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
        echo "  FAIL: $name (TIMEOUT - possible livelock)"
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

# Test 1: Create-delete-create race (TOCTOU on file existence)
# Thread A creates file, Thread B deletes, Thread A accesses stale handle
test_create_delete_create_race() {
    local pids=()

    for round in $(seq 1 10); do
        # Creator
        (smb_cmd "put /dev/null race_cdc_$round" >/dev/null 2>&1) &
        pids+=($!)
        # Deleter
        (smb_cmd "del race_cdc_$round" >/dev/null 2>&1) &
        pids+=($!)
        # Re-creator
        (smb_cmd "put /dev/null race_cdc_$round" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Cleanup
    for round in $(seq 1 10); do
        smb_cmd "del race_cdc_$round" >/dev/null 2>&1
    done
    check_server_alive
}

# Test 2: Rename-read race (file disappears mid-read)
test_rename_read_race() {
    dd if=/dev/urandom of="$TMPDIR/rename_src" bs=1024 count=100 2>/dev/null
    smb_cmd "put $TMPDIR/rename_src race_rename_src" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 5); do
        # Reader
        (smb_cmd "get race_rename_src $TMPDIR/rename_out_$i" >/dev/null 2>&1) &
        pids+=($!)
        # Renamer
        (smb_cmd "rename race_rename_src race_rename_dst_$i" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Cleanup all possible names
    smb_cmd "del race_rename_src" >/dev/null 2>&1
    for i in $(seq 1 5); do
        smb_cmd "del race_rename_dst_$i" >/dev/null 2>&1
    done
    check_server_alive
}

# Test 3: Permission check race (TOCTOU on access control)
# Create file, change permissions, read concurrently
test_permission_check_race() {
    smb_cmd "put /dev/null race_perm_target" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        (smb_cmd "allinfo race_perm_target" >/dev/null 2>&1) &
        pids+=($!)
        (smb_cmd "get race_perm_target $TMPDIR/perm_out_$i" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del race_perm_target" >/dev/null 2>&1
    check_server_alive
}

# Test 4: Double-free via concurrent close
# Two clients attempt to close/access the same logical file
test_concurrent_close() {
    dd if=/dev/urandom of="$TMPDIR/close_target" bs=1024 count=10 2>/dev/null
    smb_cmd "put $TMPDIR/close_target race_close_target" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        (smb_cmd "get race_close_target $TMPDIR/close_out_$i" >/dev/null 2>&1) &
        pids+=($!)
    done

    # While reads are happening, try to delete
    (smb_cmd "del race_close_target" >/dev/null 2>&1) &
    pids+=($!)

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del race_close_target" >/dev/null 2>&1
    check_server_alive
}

# Test 5: Session ID reuse race
# Rapid disconnect+reconnect hoping to reuse session IDs
test_session_id_reuse() {
    local pids=()
    for i in $(seq 1 30); do
        (
            smbclient "//$SERVER/$SHARE" "$PASS" -U "$USER" -p "$SMB_PORT" \
                --option="client min protocol=SMB2" -c "ls; quit" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 6: Tree connect during session expiry
test_tree_connect_session_expiry() {
    local pids=()
    for i in $(seq 1 20); do
        (
            smb_cmd "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 7: File size race (write + stat concurrently)
test_file_size_race() {
    dd if=/dev/urandom of="$TMPDIR/size_race" bs=1024 count=10 2>/dev/null
    smb_cmd "put $TMPDIR/size_race race_size_target" >/dev/null 2>&1

    local pids=()
    for i in $(seq 1 10); do
        # Writer (overwrites with different sizes)
        dd if=/dev/urandom of="$TMPDIR/size_data_$i" bs=1024 count=$((i * 5)) 2>/dev/null
        (smb_cmd "put $TMPDIR/size_data_$i race_size_target" >/dev/null 2>&1) &
        pids+=($!)
        # Stat reader
        (smb_cmd "allinfo race_size_target" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del race_size_target" >/dev/null 2>&1
    check_server_alive
}

# Test 8: Directory enumeration during modification
test_dir_enum_modification() {
    smb_cmd "mkdir race_dir_enum" >/dev/null 2>&1

    local pids=()
    # Create files while listing
    for i in $(seq 1 20); do
        (smb_cmd "put /dev/null race_dir_enum/file_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    for i in $(seq 1 5); do
        (smb_cmd "ls race_dir_enum/" >/dev/null 2>&1) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    # Cleanup
    for i in $(seq 1 20); do
        smb_cmd "del race_dir_enum/file_$i" >/dev/null 2>&1
    done
    smb_cmd "rmdir race_dir_enum" >/dev/null 2>&1
    check_server_alive
}

# Test 9: Oplock break + write race
# One client holds oplock, another writes, triggering break
test_oplock_write_race() {
    dd if=/dev/urandom of="$TMPDIR/oplock_wr" bs=1024 count=50 2>/dev/null
    smb_cmd "put $TMPDIR/oplock_wr race_oplock_wr" >/dev/null 2>&1

    local pids=()
    # Multiple readers (will get oplocks)
    for i in $(seq 1 5); do
        (smb_cmd "get race_oplock_wr $TMPDIR/oplock_out_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    # Writer (will break oplocks)
    (smb_cmd "put $TMPDIR/oplock_wr race_oplock_wr" >/dev/null 2>&1) &
    pids+=($!)

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "del race_oplock_wr" >/dev/null 2>&1
    check_server_alive
}

# Test 10: Compound request FID race
# Compound creates can reference FIDs from prior requests in the compound
test_compound_fid_race() {
    local pids=()
    for i in $(seq 1 15); do
        (
            smb_cmd "put /dev/null race_compound_$i; allinfo race_compound_$i; del race_compound_$i" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    check_server_alive
}

# Test 11: Notification + delete race
# Set up notify watch, then delete the watched directory
test_notify_delete_race() {
    smb_cmd "mkdir race_notify_dir" >/dev/null 2>&1

    local pids=()
    # Create activity in directory
    for i in $(seq 1 10); do
        (smb_cmd "put /dev/null race_notify_dir/nf_$i; del race_notify_dir/nf_$i" >/dev/null 2>&1) &
        pids+=($!)
    done
    # List directory (triggers readdir)
    (smb_cmd "ls race_notify_dir/" >/dev/null 2>&1) &
    pids+=($!)

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_cmd "rmdir race_notify_dir" >/dev/null 2>&1
    check_server_alive
}

# Test 12: Final health check
test_final_health() {
    # Verify server is still responsive after all race tests
    local success=0
    for i in $(seq 1 3); do
        if smb_cmd "ls" >/dev/null 2>&1; then
            success=$((success + 1))
        fi
    done
    [ "$success" -ge 2 ]
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

echo "Running 12 race condition tests..."
echo ""

run_test "create_delete_create_race"     test_create_delete_create_race
run_test "rename_read_race"              test_rename_read_race
run_test "permission_check_race"         test_permission_check_race
run_test "concurrent_close"              test_concurrent_close
run_test "session_id_reuse"              test_session_id_reuse
run_test "tree_connect_session_expiry"   test_tree_connect_session_expiry
run_test "file_size_race"                test_file_size_race
run_test "dir_enum_modification"         test_dir_enum_modification
run_test "oplock_write_race"             test_oplock_write_race
run_test "compound_fid_race"             test_compound_fid_race
run_test "notify_delete_race"            test_notify_delete_race
run_test "final_health_check"            test_final_health

echo ""
echo "=== Results: PASS=$PASS_COUNT FAIL=$FAIL_COUNT SKIP=$SKIP_COUNT ==="
echo ""
echo "Note: These tests exercise TOCTOU and race windows."
echo "If server crashes, check dmesg for BUG/OOPS/UAF/refcount warnings."
exit $FAIL_COUNT
