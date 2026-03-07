#!/bin/bash
# S02: SESSION STRESS (10 tests)
#
# Exercises session lifecycle limits:
#   - Rapid authentication/deauthentication
#   - Multiple sessions per connection
#   - Session table exhaustion (xarray-based)
#   - Concurrent session setup races
#   - Session state machine edge cases
#
# Key kernel paths:
#   - mgmt/user_session.c: ksmbd_session_alloc/destroy, session xarray
#   - connection.c: conn->sessions (xarray), session_lock (rw_semaphore)
#   - auth.c: NTLM authentication path, NTLMSSP state machine

# ---------------------------------------------------------------------------
# S02.01: Rapid session setup/logoff (500 cycles)
# ---------------------------------------------------------------------------
register_test "S02.01" "test_session_stress_rapid_500" \
    --timeout 180 --tags "stress,slow,session" \
    --description "500 rapid session setup and logoff cycles"
test_session_stress_rapid_500() {
    local count=500 pass=0
    for i in $(seq 1 "$count"); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        fi
    done
    local threshold=$((count * 90 / 100))
    assert_ge "$pass" "$threshold" \
        "At least $threshold of $count session cycles should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.02: Parallel session setup (50 simultaneous auth attempts)
# ---------------------------------------------------------------------------
register_test "S02.02" "test_session_stress_parallel_50" \
    --timeout 120 --tags "stress,session" \
    --description "50 simultaneous session setup attempts"
test_session_stress_parallel_50() {
    local pids=() pass=0
    for i in $(seq 1 50); do
        (
            smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done
    assert_ge "$pass" 35 \
        "At least 35 of 50 parallel sessions should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.03: Guest session flood
# ---------------------------------------------------------------------------
register_test "S02.03" "test_session_stress_guest_flood" \
    --timeout 120 --tags "stress,session" \
    --description "100 guest (anonymous) session attempts"
test_session_stress_guest_flood() {
    local pids=() pass=0
    for i in $(seq 1 100); do
        (
            smb_cmd "$SMB_UNC" --guest -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
        [[ $((i % 25)) -eq 0 ]] && sleep 0.5
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done
    # Guest sessions may be rejected by policy; just ensure no crash
    # The main assertion is that the server survives
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after guest session flood" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S02.04: Mixed auth method stress (NTLM + guest interleaved)
# ---------------------------------------------------------------------------
register_test "S02.04" "test_session_stress_mixed_auth" \
    --timeout 120 --tags "stress,session" \
    --description "50 NTLM + 50 guest sessions interleaved"
test_session_stress_mixed_auth() {
    local pids=() pass=0
    for i in $(seq 1 100); do
        if [[ $((i % 2)) -eq 0 ]]; then
            (
                smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
            ) &
        else
            (
                smb_cmd "$SMB_UNC" --guest -c "ls" >/dev/null 2>&1
            ) &
        fi
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done
    # Verify server is still alive
    smb_connect_test_retry 3 "$SMB_UNC" || {
        echo "Server unresponsive after mixed auth stress" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S02.05: Session setup with invalid credentials (brute force simulation)
# ---------------------------------------------------------------------------
register_test "S02.05" "test_session_stress_invalid_creds" \
    --timeout 120 --tags "stress,session" \
    --description "100 session setup attempts with invalid credentials"
test_session_stress_invalid_creds() {
    local marker
    marker=$(vm_dmesg_mark)

    local pids=()
    for i in $(seq 1 100); do
        (
            smb_cmd "$SMB_UNC" --user "baduser${i}%wrongpass${i}" -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
        [[ $((i % 25)) -eq 0 ]] && sleep 0.5
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    sleep 2

    # Server should survive the brute-force and still accept valid clients
    smb_connect_test_retry 3 "$SMB_UNC" || {
        echo "Server unresponsive after invalid credential storm" >&2
        return 1
    }

    # Check for crashes
    assert_dmesg_clean "$marker" "dmesg errors after invalid credential storm" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.06: Session setup under memory pressure
# ---------------------------------------------------------------------------
register_test "S02.06" "test_session_stress_memory_pressure" \
    --timeout 120 --tags "stress,session" \
    --description "Session setup while allocating large files on server"
test_session_stress_memory_pressure() {
    # Create memory pressure on server
    vm_exec "dd if=/dev/zero of=/tmp/mempress bs=1M count=256 2>/dev/null" 2>/dev/null

    local pass=0
    for i in $(seq 1 30); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        fi
    done

    vm_exec "rm -f /tmp/mempress" 2>/dev/null

    assert_ge "$pass" 20 \
        "At least 20 of 30 sessions should succeed under memory pressure (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.07: Sustained session churn (30 seconds)
# ---------------------------------------------------------------------------
register_test "S02.07" "test_session_stress_churn_30s" \
    --timeout 90 --tags "stress,session" \
    --description "Continuous session setup/teardown for 30 seconds"
test_session_stress_churn_30s() {
    local duration=30
    local end_time=$(( $(date +%s) + duration ))
    local total=0 pass=0

    while [[ $(date +%s) -lt $end_time ]]; do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        fi
        ((total++))
    done

    local rate=$((pass * 100 / (total > 0 ? total : 1)))
    assert_ge "$rate" 80 \
        "Session churn success rate should be >= 80% (got ${rate}%, $pass/$total)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.08: Session slab leak detection
# ---------------------------------------------------------------------------
register_test "S02.08" "test_session_stress_slab_leak" \
    --timeout 120 --tags "stress,session,leak" \
    --description "Detect session object slab leaks after 100 cycles"
test_session_stress_slab_leak() {
    local baseline
    baseline=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd | awk '{sum+=\$2} END {print sum+0}'" 2>/dev/null)
    baseline=${baseline:-0}

    for i in $(seq 1 100); do
        smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
    done

    sleep 5

    local current
    current=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd | awk '{sum+=\$2} END {print sum+0}'" 2>/dev/null)
    current=${current:-0}

    local delta=$((current - baseline))
    assert_lt "$delta" 200 \
        "Slab growth after 100 session cycles should be < 200 objects (delta=$delta)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.09: Concurrent session setup + tree connect
# ---------------------------------------------------------------------------
register_test "S02.09" "test_session_stress_session_tree_race" \
    --timeout 120 --tags "stress,session" \
    --description "20 clients racing session setup + tree connect + operations"
test_session_stress_session_tree_race() {
    local pids=() pass=0
    for i in $(seq 1 20); do
        (
            # Each client does full lifecycle: negotiate + session + tree + ops
            smb_write_file "session_race_${i}.txt" "data_${i}" >/dev/null 2>&1
            smb_rm "session_race_${i}.txt" >/dev/null 2>&1
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done
    assert_ge "$pass" 14 \
        "At least 14 of 20 session+tree races should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S02.10: Session logoff under active operations
# ---------------------------------------------------------------------------
register_test "S02.10" "test_session_stress_logoff_active" \
    --timeout 120 --tags "stress,session,destructive" \
    --description "Disconnect during active file operations (50 iterations)"
test_session_stress_logoff_active() {
    local marker
    marker=$(vm_dmesg_mark)

    for i in $(seq 1 50); do
        (
            # Start a long operation and kill it mid-way
            timeout 1 bash -c "smb_cmd '$SMB_UNC' -c 'put /dev/urandom big_upload_${i}.dat'" >/dev/null 2>&1
        )
    done

    sleep 5
    vm_exec "rm -f ${SHARE_ROOT}/big_upload_*.dat" 2>/dev/null

    # Server should survive
    smb_connect_test_retry 5 "$SMB_UNC" || {
        echo "Server unresponsive after logoff-during-active stress" >&2
        return 1
    }

    # No crashes
    assert_dmesg_clean "$marker" "dmesg errors after logoff-during-active stress" || return 1
    return 0
}
