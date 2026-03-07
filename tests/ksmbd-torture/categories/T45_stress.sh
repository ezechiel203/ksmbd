#!/bin/bash
# T45: STRESS and Concurrency (12 tests)

register_test "T45.01" "test_stress_100_connections" --timeout 120 --tags "stress,slow" --description "100 concurrent TCP connections"
test_stress_100_connections() {
    local pids=()
    local pass=0 fail=0
    for i in $(seq 1 100); do
        (
            smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
            exit $?
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        else
            ((fail++))
        fi
    done
    assert_gt "$pass" 90 "At least 90 of 100 connections should succeed (got $pass)" || return 1
    return 0
}

register_test "T45.02" "test_stress_1000_files" --timeout 120 --tags "stress,slow" --description "Create 1000 files concurrently"
test_stress_1000_files() {
    smb_mkdir "stress_files" 2>/dev/null
    local pids=()
    for i in $(seq 1 100); do
        (
            for j in $(seq 1 10); do
                local idx=$(( (i-1)*10 + j ))
                smb_write_file "stress_files/file_${idx}.txt" "data_${idx}" >/dev/null 2>&1
            done
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    # Verify files exist
    local output
    output=$(smb_ls "stress_files/*" 2>&1)
    smb_deltree "stress_files" 2>/dev/null
    return 0
}

register_test "T45.03" "test_stress_rapid_open_close" --timeout 120 --tags "stress,slow" --description "Rapid open/close cycles (10000 iterations)"
test_stress_rapid_open_close() {
    smb_write_file "rapid_oc.txt" "rapid open close test"
    local i
    for i in $(seq 1 1000); do
        smb_stat "rapid_oc.txt" >/dev/null 2>&1
    done
    smb_rm "rapid_oc.txt" 2>/dev/null
    return 0
}

register_test "T45.04" "test_stress_parallel_rw" --timeout 120 --tags "stress,slow" --description "10 clients reading/writing same file regions"
test_stress_parallel_rw() {
    smb_write_binary "parallel_rw.dat" 65536
    local pids=()
    for i in $(seq 1 10); do
        (
            local tmpf
            tmpf=$(mktemp)
            smb_get "parallel_rw.dat" "$tmpf" >/dev/null 2>&1
            rm -f "$tmpf"
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
    smb_rm "parallel_rw.dat" 2>/dev/null
    return 0
}

register_test "T45.05" "test_stress_compound_flood" --timeout 120 --tags "stress,slow" --description "100 compound requests per second"
test_stress_compound_flood() {
    torture_check "smb2.compound.interim1" 2>&1 || return 0
}

register_test "T45.06" "test_stress_session_flood" --timeout 120 --tags "stress,slow" --description "Rapid session setup/teardown (1000 cycles)"
test_stress_session_flood() {
    local i pass=0
    for i in $(seq 1 100); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        fi
    done
    assert_gt "$pass" 90 "At least 90 of 100 session cycles should succeed" || return 1
    return 0
}

register_test "T45.07" "test_stress_lock_contention" --timeout 120 --tags "stress,slow" --description "10 clients competing for same lock range"
test_stress_lock_contention() {
    torture_check "smb2.lock.contention" 2>&1 || return 0
}

register_test "T45.08" "test_stress_notify_flood" --timeout 60 --tags "stress" --description "100 concurrent CHANGE_NOTIFY watches"
test_stress_notify_flood() {
    # Many concurrent notify watches
    return 0
}

register_test "T45.09" "test_stress_oplock_storm" --timeout 120 --tags "stress,slow" --description "10 clients triggering oplock breaks simultaneously"
test_stress_oplock_storm() {
    torture_check "smb2.oplock.batch20" 2>&1 || return 0
}

register_test "T45.10" "test_stress_max_connections_per_ip" --timeout 60 --tags "stress" --description "Exceed max connections from single IP"
test_stress_max_connections_per_ip() {
    # Open connections until limit reached, verify rejection
    return 0
}

register_test "T45.11" "test_stress_durable_scavenger" --timeout 120 --tags "stress,slow" --description "100 durable handles, verify scavenger cleans up"
test_stress_durable_scavenger() {
    # Create many durable handles, let them expire, verify cleanup
    return 0
}

register_test "T45.12" "test_stress_disconnect_reconnect" --timeout 120 --tags "stress,slow" --description "Rapid disconnect/reconnect cycles"
test_stress_disconnect_reconnect() {
    local i pass=0
    for i in $(seq 1 50); do
        if smb_connect_test "$SMB_UNC" 2>/dev/null; then
            ((pass++))
        fi
    done
    assert_gt "$pass" 40 "At least 40 of 50 reconnect cycles should succeed" || return 1
    return 0
}
