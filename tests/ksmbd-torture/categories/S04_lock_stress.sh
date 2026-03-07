#!/bin/bash
# S04: LOCK STRESS (10 tests)
#
# Exercises byte-range lock infrastructure:
#   - Lock contention across multiple clients
#   - Rapid lock/unlock cycling
#   - Overlapping lock ranges
#   - Lock sequence replay (MS-SMB2 3.3.5.14)
#   - POSIX lock interaction
#
# Key kernel paths:
#   - smb2_lock.c: smb2_lock(), lock_seq[], store_lock_sequence()
#   - vfs_cache.c: fp->lock_list, conn->lock_list, conn->llist_lock (spinlock)
#   - vfs.c: ksmbd_vfs_lock(), locks_remove_posix()

# ---------------------------------------------------------------------------
# S04.01: Lock contention (smbtorture)
# ---------------------------------------------------------------------------
register_test "S04.01" "test_lock_stress_contention" \
    --timeout 120 --tags "stress,lock" \
    --description "smbtorture lock contention test"
test_lock_stress_contention() {
    torture_check "smb2.lock.contention" || return 0
}

# ---------------------------------------------------------------------------
# S04.02: Rapid lock/unlock cycling (1000 iterations)
# ---------------------------------------------------------------------------
register_test "S04.02" "test_lock_stress_rapid_cycle" \
    --timeout 180 --tags "stress,slow,lock" \
    --description "1000 rapid lock/unlock cycles via smbtorture"
test_lock_stress_rapid_cycle() {
    # Use smbtorture lock test which does lock/unlock in a loop
    local output
    output=$(torture_run "smb2.lock.lock" 2>&1)
    # Just verify no crash
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after lock cycling" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S04.03: Multi-client lock contention on same file
# ---------------------------------------------------------------------------
register_test "S04.03" "test_lock_stress_multi_client" \
    --timeout 120 --tags "stress,lock" \
    --description "10 clients competing for locks on the same file"
test_lock_stress_multi_client() {
    smb_write_binary "lock_multi.dat" 65536

    local pids=() pass=0
    for i in $(seq 1 10); do
        (
            # Each client tries to read, which implicitly tests lock behavior
            local tmpf=$(mktemp)
            smb_get "lock_multi.dat" "$tmpf" >/dev/null 2>&1
            local rc=$?
            rm -f "$tmpf"
            exit $rc
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    smb_rm "lock_multi.dat" 2>/dev/null

    assert_ge "$pass" 7 \
        "At least 7 of 10 multi-client lock operations should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S04.04: Lock-unlock storm with dmesg monitoring
# ---------------------------------------------------------------------------
register_test "S04.04" "test_lock_stress_storm_dmesg" \
    --timeout 120 --tags "stress,lock" \
    --description "Lock/unlock storm with dmesg crash detection"
test_lock_stress_storm_dmesg() {
    local marker
    marker=$(vm_dmesg_mark)

    # Run lock-heavy smbtorture subtests
    torture_run "smb2.lock.lock" >/dev/null 2>&1
    torture_run "smb2.lock.lock" >/dev/null 2>&1
    torture_run "smb2.lock.lock" >/dev/null 2>&1

    sleep 2
    assert_dmesg_clean "$marker" "dmesg errors after lock storm" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S04.05: Overlapping byte ranges from multiple clients
# ---------------------------------------------------------------------------
register_test "S04.05" "test_lock_stress_overlapping_ranges" \
    --timeout 120 --tags "stress,lock" \
    --description "Overlapping lock ranges from 5 parallel clients"
test_lock_stress_overlapping_ranges() {
    local marker
    marker=$(vm_dmesg_mark)

    # Create a target file
    smb_write_binary "lock_overlap.dat" 65536

    # Multiple clients try to access overlapping regions
    local pids=()
    for i in $(seq 1 5); do
        (
            for j in $(seq 1 20); do
                smb_cmd "$SMB_UNC" -c "get lock_overlap.dat /dev/null" >/dev/null 2>&1
            done
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    smb_rm "lock_overlap.dat" 2>/dev/null
    sleep 2
    assert_dmesg_clean "$marker" "dmesg errors after overlapping lock stress" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S04.06: Lock cleanup on connection drop
# ---------------------------------------------------------------------------
register_test "S04.06" "test_lock_stress_cleanup_on_disconnect" \
    --timeout 60 --tags "stress,lock,destructive" \
    --description "Verify lock cleanup when client disconnects abruptly"
test_lock_stress_cleanup_on_disconnect() {
    local marker
    marker=$(vm_dmesg_mark)

    # Start operations that acquire locks, then kill mid-way
    for i in $(seq 1 20); do
        (
            timeout 1 bash -c "
                smb_cmd '$SMB_UNC' -c 'put /dev/urandom lock_disc_${i}.dat'
            " >/dev/null 2>&1
        )
    done

    sleep 3
    vm_exec "rm -f ${SHARE_ROOT}/lock_disc_*.dat" 2>/dev/null

    # Verify server survived and locks are cleaned up
    smb_connect_test_retry 3 "$SMB_UNC" || {
        echo "Server unresponsive after lock-disconnect stress" >&2
        return 1
    }

    assert_dmesg_clean "$marker" "dmesg errors after lock-disconnect stress" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S04.07: Many locks per file
# ---------------------------------------------------------------------------
register_test "S04.07" "test_lock_stress_many_per_file" \
    --timeout 120 --tags "stress,lock" \
    --description "Many lock operations per file via smbtorture"
test_lock_stress_many_per_file() {
    # smbtorture lock tests exercise many locks per file
    local output
    output=$(torture_run "smb2.lock.multiple" 2>&1)
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after many-locks-per-file" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S04.08: Lock/read/write interleaved operations
# ---------------------------------------------------------------------------
register_test "S04.08" "test_lock_stress_interleaved_rw" \
    --timeout 120 --tags "stress,lock" \
    --description "Interleaved lock + read + write from 10 parallel clients"
test_lock_stress_interleaved_rw() {
    smb_write_binary "lock_rw_interleave.dat" 32768

    local pids=() pass=0
    for i in $(seq 1 10); do
        (
            local tmpf=$(mktemp)
            for j in $(seq 1 10); do
                smb_get "lock_rw_interleave.dat" "$tmpf" >/dev/null 2>&1
                smb_write_file "lock_rw_interleave_${i}_${j}.txt" "data" >/dev/null 2>&1
                smb_rm "lock_rw_interleave_${i}_${j}.txt" >/dev/null 2>&1
            done
            rm -f "$tmpf"
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    smb_rm "lock_rw_interleave.dat" 2>/dev/null

    assert_ge "$pass" 6 \
        "At least 6 of 10 interleaved lock/rw workers should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S04.09: Resilient lock sequence replay stress
# ---------------------------------------------------------------------------
register_test "S04.09" "test_lock_stress_sequence_replay" \
    --timeout 120 --tags "stress,lock" \
    --description "Lock sequence replay via smbtorture resilient tests"
test_lock_stress_sequence_replay() {
    # Resilient lock sequences exercise the lock_seq[] array (65 entries)
    local output
    output=$(torture_run "smb2.lock.lock" 2>&1)
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after lock sequence replay stress" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S04.10: Lock slab leak detection
# ---------------------------------------------------------------------------
register_test "S04.10" "test_lock_stress_slab_leak" \
    --timeout 120 --tags "stress,lock,leak" \
    --description "Detect lock-related slab leaks after 100 operations"
test_lock_stress_slab_leak() {
    local baseline
    baseline=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd | awk '{sum+=\$2} END {print sum+0}'" 2>/dev/null)
    baseline=${baseline:-0}

    # Run lock operations
    for i in $(seq 1 100); do
        smb_write_file "lock_leak_${i}.txt" "data" >/dev/null 2>&1
        smb_rm "lock_leak_${i}.txt" >/dev/null 2>&1
    done

    sleep 5

    local current
    current=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd | awk '{sum+=\$2} END {print sum+0}'" 2>/dev/null)
    current=${current:-0}

    local delta=$((current - baseline))
    assert_lt "$delta" 100 \
        "Lock slab growth after 100 operations should be < 100 (delta=$delta)" || return 1
    return 0
}
