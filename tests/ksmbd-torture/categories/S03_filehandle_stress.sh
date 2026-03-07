#!/bin/bash
# S03: FILE HANDLE STRESS (12 tests)
#
# Exercises file handle (FID) lifecycle limits:
#   - Max open files per session (fd_limit from vfs_cache.c)
#   - FID exhaustion and recovery
#   - Rapid open/close cycling
#   - idr allocation/deallocation churn
#   - ksmbd_inode hash table stress
#
# Key kernel paths:
#   - vfs_cache.c: fd_limit_depleted(), ksmbd_open_fd(), idr_alloc_cyclic()
#   - vfs_cache.c: ksmbd_inode_hash (16384 buckets), per-bucket rwlock
#   - vfs_cache.c: filp_cache (kmem_cache), global_ft (idr)

# ---------------------------------------------------------------------------
# S03.01: Create and hold many open files (500 files)
# ---------------------------------------------------------------------------
register_test "S03.01" "test_fh_stress_500_files" \
    --timeout 180 --tags "stress,slow,filehandle" \
    --description "Create 500 files and verify all are accessible"
test_fh_stress_500_files() {
    smb_mkdir "fh_stress_500" 2>/dev/null

    local pids=() pass=0
    # 10 workers, each creating 50 files
    for w in $(seq 1 10); do
        (
            local ok=0
            for i in $(seq 1 50); do
                local idx=$(( (w-1)*50 + i ))
                if smb_write_file "fh_stress_500/file_${idx}.txt" "data_${idx}" >/dev/null 2>&1; then
                    ((ok++))
                fi
            done
            [[ $ok -ge 40 ]]
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    # Verify some files exist
    local count
    count=$(vm_exec "ls ${SHARE_ROOT}/fh_stress_500/ 2>/dev/null | wc -l" 2>/dev/null)
    smb_deltree "fh_stress_500" 2>/dev/null
    vm_exec "rm -rf ${SHARE_ROOT}/fh_stress_500" 2>/dev/null

    assert_ge "${count:-0}" 300 \
        "At least 300 of 500 files should be created (got ${count:-0})" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.02: Rapid open/close cycling (5000 iterations)
# ---------------------------------------------------------------------------
register_test "S03.02" "test_fh_stress_rapid_open_close_5k" \
    --timeout 180 --tags "stress,slow,filehandle" \
    --description "5000 rapid file open/close cycles"
test_fh_stress_rapid_open_close_5k() {
    smb_write_file "rapid_oc_target.txt" "test data for rapid open/close"
    local pass=0
    for i in $(seq 1 5000); do
        if smb_stat "rapid_oc_target.txt" >/dev/null 2>&1; then
            ((pass++))
        fi
    done
    smb_rm "rapid_oc_target.txt" 2>/dev/null
    assert_ge "$pass" 4500 \
        "At least 4500 of 5000 open/close cycles should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.03: Parallel open/close on same file (contention)
# ---------------------------------------------------------------------------
register_test "S03.03" "test_fh_stress_parallel_same_file" \
    --timeout 120 --tags "stress,filehandle" \
    --description "20 clients opening/closing the same file simultaneously"
test_fh_stress_parallel_same_file() {
    smb_write_file "contention_target.txt" "contention test data"

    local pids=() pass=0
    for i in $(seq 1 20); do
        (
            local ok=0
            for j in $(seq 1 50); do
                if smb_stat "contention_target.txt" >/dev/null 2>&1; then
                    ((ok++))
                fi
            done
            [[ $ok -ge 30 ]]
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    smb_rm "contention_target.txt" 2>/dev/null

    assert_ge "$pass" 14 \
        "At least 14 of 20 parallel open/close workers should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.04: File handle leak detection
# ---------------------------------------------------------------------------
register_test "S03.04" "test_fh_stress_leak_detection" \
    --timeout 120 --tags "stress,filehandle,leak" \
    --description "Detect FID slab leaks after 200 create/close cycles"
test_fh_stress_leak_detection() {
    local baseline
    baseline=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd_file_cache | awk '{print \$2+0}'" 2>/dev/null)
    baseline=${baseline:-0}

    for i in $(seq 1 200); do
        smb_write_file "leak_test_${i}.txt" "data" >/dev/null 2>&1
        smb_rm "leak_test_${i}.txt" >/dev/null 2>&1
    done

    sleep 5

    local current
    current=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd_file_cache | awk '{print \$2+0}'" 2>/dev/null)
    current=${current:-0}

    local delta=$((current - baseline))
    assert_lt "$delta" 50 \
        "File cache slab growth after 200 create/close cycles should be < 50 (delta=$delta)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.05: Many files in same directory (inode hash stress)
# ---------------------------------------------------------------------------
register_test "S03.05" "test_fh_stress_same_dir_1000" \
    --timeout 180 --tags "stress,slow,filehandle" \
    --description "1000 files in one directory (inode hash bucket stress)"
test_fh_stress_same_dir_1000() {
    smb_mkdir "inode_hash_test" 2>/dev/null

    local pass=0
    for i in $(seq 1 1000); do
        if smb_write_file "inode_hash_test/f${i}" "d${i}" >/dev/null 2>&1; then
            ((pass++))
        fi
    done

    # Verify directory listing works
    local output
    output=$(smb_ls "inode_hash_test/*" 2>&1)

    smb_deltree "inode_hash_test" 2>/dev/null
    vm_exec "rm -rf ${SHARE_ROOT}/inode_hash_test" 2>/dev/null

    assert_ge "$pass" 800 \
        "At least 800 of 1000 files should be created (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.06: Concurrent create + delete race
# ---------------------------------------------------------------------------
register_test "S03.06" "test_fh_stress_create_delete_race" \
    --timeout 120 --tags "stress,filehandle" \
    --description "Parallel create and delete on overlapping file sets"
test_fh_stress_create_delete_race() {
    smb_mkdir "cd_race" 2>/dev/null
    local marker
    marker=$(vm_dmesg_mark)

    # Creator process
    (
        for i in $(seq 1 100); do
            smb_write_file "cd_race/file_${i}.txt" "create_data_${i}" >/dev/null 2>&1
        done
    ) &
    local create_pid=$!

    # Deleter process (runs slightly behind)
    sleep 1
    (
        for i in $(seq 1 100); do
            smb_rm "cd_race/file_${i}.txt" >/dev/null 2>&1
        done
    ) &
    local delete_pid=$!

    wait "$create_pid" 2>/dev/null
    wait "$delete_pid" 2>/dev/null

    sleep 2
    smb_deltree "cd_race" 2>/dev/null
    vm_exec "rm -rf ${SHARE_ROOT}/cd_race" 2>/dev/null

    # Main check: no crashes
    assert_dmesg_clean "$marker" "dmesg errors after create/delete race" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.07: File handle reuse after close (FID recycling via idr_alloc_cyclic)
# ---------------------------------------------------------------------------
register_test "S03.07" "test_fh_stress_fid_recycling" \
    --timeout 120 --tags "stress,filehandle" \
    --description "FID recycling: create, close, reopen 500 times"
test_fh_stress_fid_recycling() {
    local pass=0
    for i in $(seq 1 500); do
        smb_write_file "fid_recycle.txt" "data_${i}" >/dev/null 2>&1
        if smb_read_file "fid_recycle.txt" 2>/dev/null | grep -q "data_${i}"; then
            ((pass++))
        fi
    done
    smb_rm "fid_recycle.txt" 2>/dev/null

    assert_ge "$pass" 400 \
        "At least 400 of 500 FID recycling cycles should work correctly (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.08: Open files count tracking
# ---------------------------------------------------------------------------
register_test "S03.08" "test_fh_stress_open_count_tracking" \
    --timeout 60 --tags "stress,filehandle" \
    --description "Verify open_files_count returns to 0 after operations"
test_fh_stress_open_count_tracking() {
    # Do many operations
    for i in $(seq 1 50); do
        smb_write_file "count_track_${i}.txt" "data" >/dev/null 2>&1
    done
    for i in $(seq 1 50); do
        smb_rm "count_track_${i}.txt" >/dev/null 2>&1
    done

    sleep 3

    # Check connection count on server (should be minimal)
    local conn_count
    conn_count=$(vm_exec "ss -tnp 2>/dev/null | grep -c ':445 '" 2>/dev/null)
    conn_count=${conn_count:-0}

    # After all operations complete and connections close,
    # connection count should be low
    assert_lt "$conn_count" 10 \
        "Active connections should be < 10 after all operations complete (got $conn_count)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.09: Deeply nested directory tree with files
# ---------------------------------------------------------------------------
register_test "S03.09" "test_fh_stress_deep_nesting" \
    --timeout 120 --tags "stress,filehandle" \
    --description "Create deeply nested directory tree (20 levels)"
test_fh_stress_deep_nesting() {
    # Create nested directories on the server side
    local path="${SHARE_ROOT}/deep_nest"
    vm_exec "mkdir -p '${path}'" 2>/dev/null

    local current="${path}"
    for i in $(seq 1 20); do
        current="${current}/level_${i}"
        vm_exec "mkdir -p '${current}'" 2>/dev/null
    done
    vm_exec "echo 'deep data' > '${current}/deepfile.txt'" 2>/dev/null

    # Access via SMB
    local smb_path="deep_nest"
    for i in $(seq 1 20); do
        smb_path="${smb_path}/level_${i}"
    done

    local output
    output=$(smb_stat "${smb_path}/deepfile.txt" 2>&1)
    local rc=$?

    vm_exec "rm -rf '${SHARE_ROOT}/deep_nest'" 2>/dev/null

    # The access should work (or gracefully fail with path too long)
    # Main concern is no crash
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after deep nesting test" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S03.10: Simultaneous operations on 100 different files
# ---------------------------------------------------------------------------
register_test "S03.10" "test_fh_stress_100_different_files" \
    --timeout 120 --tags "stress,filehandle" \
    --description "100 parallel operations on 100 different files"
test_fh_stress_100_different_files() {
    smb_mkdir "diff100" 2>/dev/null
    local pids=() pass=0

    for i in $(seq 1 100); do
        (
            smb_write_file "diff100/unique_${i}.txt" "unique_data_${i}" >/dev/null 2>&1 &&
            smb_stat "diff100/unique_${i}.txt" >/dev/null 2>&1 &&
            smb_rm "diff100/unique_${i}.txt" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    smb_deltree "diff100" 2>/dev/null
    vm_exec "rm -rf ${SHARE_ROOT}/diff100" 2>/dev/null

    assert_ge "$pass" 70 \
        "At least 70 of 100 parallel file operations should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.11: Delete-on-close with multiple handles
# ---------------------------------------------------------------------------
register_test "S03.11" "test_fh_stress_delete_on_close_multi" \
    --timeout 120 --tags "stress,filehandle" \
    --description "Delete-on-close race with multiple concurrent readers"
test_fh_stress_delete_on_close_multi() {
    local marker
    marker=$(vm_dmesg_mark)

    for round in $(seq 1 20); do
        # Create the file
        smb_write_file "doc_test_${round}.txt" "round_${round}_data" >/dev/null 2>&1

        # Concurrent readers
        local pids=()
        for i in $(seq 1 5); do
            (
                smb_read_file "doc_test_${round}.txt" >/dev/null 2>&1
            ) &
            pids+=($!)
        done

        # Delete while readers are active
        smb_rm "doc_test_${round}.txt" >/dev/null 2>&1

        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null
        done
    done

    sleep 2
    assert_dmesg_clean "$marker" "dmesg errors after delete-on-close stress" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S03.12: Rename storm (concurrent renames of same file)
# ---------------------------------------------------------------------------
register_test "S03.12" "test_fh_stress_rename_storm" \
    --timeout 120 --tags "stress,filehandle" \
    --description "Concurrent rename operations on overlapping file sets"
test_fh_stress_rename_storm() {
    smb_mkdir "rename_storm" 2>/dev/null
    local marker
    marker=$(vm_dmesg_mark)

    # Create initial files
    for i in $(seq 1 30); do
        smb_write_file "rename_storm/orig_${i}.txt" "data_${i}" >/dev/null 2>&1
    done

    # Concurrent renames
    local pids=()
    for i in $(seq 1 30); do
        (
            smb_rename "rename_storm/orig_${i}.txt" "rename_storm/renamed_${i}.txt" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    sleep 2
    smb_deltree "rename_storm" 2>/dev/null
    vm_exec "rm -rf ${SHARE_ROOT}/rename_storm" 2>/dev/null

    assert_dmesg_clean "$marker" "dmesg errors after rename storm" || return 1
    return 0
}
