#!/bin/bash
# S01: CONNECTION STRESS (15 tests)
#
# Exercises connection lifecycle limits:
#   - Max simultaneous TCP connections
#   - Rapid connect/disconnect cycling
#   - Half-open connection flooding
#   - Connection exhaustion and recovery
#   - Per-IP connection limits
#
# Key kernel paths exercised:
#   - transport_tcp.c: ksmbd_tcp_accept_loop, max_connections, max_ip_connections
#   - connection.c: ksmbd_conn_alloc/free, conn_hash, KSMBD_SOCKET_BACKLOG (64)
#   - server.c: queue_ksmbd_work, server_conf.max_inflight_req
#
# Constants from source:
#   CONN_HASH_SIZE = 256 (1 << CONN_HASH_BITS=8)
#   KSMBD_SOCKET_BACKLOG = 64
#   SMB2_MAX_CREDITS = 8192

# ---------------------------------------------------------------------------
# S01.01: Saturate connection limit (200 concurrent connections)
# ---------------------------------------------------------------------------
register_test "S01.01" "test_conn_stress_200_concurrent" \
    --timeout 180 --tags "stress,slow,conn" \
    --description "200 concurrent TCP connections with SMB negotiate"
test_conn_stress_200_concurrent() {
    local count=200
    local pids=() pass=0 fail=0
    for i in $(seq 1 "$count"); do
        (
            smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
        # Stagger slightly to avoid pure SYN flood
        [[ $((i % 50)) -eq 0 ]] && sleep 0.2
    done
    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        else
            ((fail++))
        fi
    done
    # At least 80% should succeed; some may be rejected at backlog
    local threshold=$((count * 80 / 100))
    assert_ge "$pass" "$threshold" \
        "At least $threshold of $count connections should succeed (got $pass pass, $fail fail)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.02: Rapid connect/disconnect cycling (500 cycles, sequential)
# ---------------------------------------------------------------------------
register_test "S01.02" "test_conn_stress_rapid_cycle_500" \
    --timeout 180 --tags "stress,slow,conn" \
    --description "500 sequential connect/negotiate/disconnect cycles"
test_conn_stress_rapid_cycle_500() {
    local count=500 pass=0 fail=0
    for i in $(seq 1 "$count"); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        else
            ((fail++))
        fi
    done
    local threshold=$((count * 95 / 100))
    assert_ge "$pass" "$threshold" \
        "At least $threshold of $count cycles should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.03: Half-open connection flood (TCP connect without SMB negotiate)
# ---------------------------------------------------------------------------
register_test "S01.03" "test_conn_stress_halfopen_flood" \
    --timeout 120 --tags "stress,conn,destructive" \
    --description "100 TCP connections opened without sending SMB data"
test_conn_stress_halfopen_flood() {
    local count=100
    local pids=()

    # Open raw TCP connections without sending any SMB data
    for i in $(seq 1 "$count"); do
        (
            # Open TCP connection and hold it for 5 seconds
            exec 3<>/dev/tcp/${SMB_HOST}/${SMB_PORT} 2>/dev/null
            sleep 5
            exec 3>&- 2>/dev/null
        ) &
        pids+=($!)
    done

    # While half-open connections exist, verify server still accepts real clients
    sleep 2
    local real_pass=0
    for i in $(seq 1 10); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((real_pass++))
        fi
    done

    # Clean up background processes
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done

    assert_ge "$real_pass" 5 \
        "Server should still accept real clients during half-open flood (got $real_pass/10)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.04: Connection burst and drain (50 at once, wait, repeat 10 times)
# ---------------------------------------------------------------------------
register_test "S01.04" "test_conn_stress_burst_drain" \
    --timeout 180 --tags "stress,slow,conn" \
    --description "10 bursts of 50 simultaneous connections"
test_conn_stress_burst_drain() {
    local bursts=10 per_burst=50
    local total_pass=0 total_fail=0

    for burst in $(seq 1 "$bursts"); do
        local pids=() pass=0 fail=0
        for i in $(seq 1 "$per_burst"); do
            (
                smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
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
        total_pass=$((total_pass + pass))
        total_fail=$((total_fail + fail))
        # Wait for server to drain connections before next burst
        sleep 2
    done

    local total=$((bursts * per_burst))
    local threshold=$((total * 80 / 100))
    assert_ge "$total_pass" "$threshold" \
        "At least $threshold of $total burst connections should succeed (got $total_pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.05: Connection hash bucket collision stress
# ---------------------------------------------------------------------------
register_test "S01.05" "test_conn_stress_hash_collision" \
    --timeout 120 --tags "stress,conn" \
    --description "Many connections from same IP (hash bucket contention)"
test_conn_stress_hash_collision() {
    # All connections from localhost hit the same hash bucket
    # CONN_HASH_SIZE=256, so all 127.0.0.1 connections go to same bucket
    local count=100
    local pids=() pass=0

    for i in $(seq 1 "$count"); do
        (
            smb_cmd "$SMB_UNC" -c "pwd" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 70 \
        "At least 70 of $count same-bucket connections should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.06: Connection cleanup verification (no slab leak)
# ---------------------------------------------------------------------------
register_test "S01.06" "test_conn_stress_slab_leak" \
    --timeout 120 --tags "stress,conn,leak" \
    --description "50 connections with slab leak detection"
test_conn_stress_slab_leak() {
    # Baseline slab count
    local baseline
    baseline=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd | awk '{sum+=\$2} END {print sum+0}'" 2>/dev/null)
    baseline=${baseline:-0}

    # Run connections
    for i in $(seq 1 50); do
        smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
    done

    # Wait for cleanup
    sleep 5

    local current
    current=$(vm_exec "cat /proc/slabinfo 2>/dev/null | grep ksmbd | awk '{sum+=\$2} END {print sum+0}'" 2>/dev/null)
    current=${current:-0}

    local delta=$((current - baseline))
    # Allow some slack (slab caches may keep objects for reuse)
    assert_lt "$delta" 100 \
        "Slab growth after 50 connections should be < 100 objects (delta=$delta)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.07: Connection timeout behavior (idle connections)
# ---------------------------------------------------------------------------
register_test "S01.07" "test_conn_stress_idle_timeout" \
    --timeout 60 --tags "stress,conn" \
    --description "Hold idle connections and verify server stability"
test_conn_stress_idle_timeout() {
    # Open connections that authenticate but do nothing
    local pids=()
    for i in $(seq 1 20); do
        (
            # Connect, negotiate, but then just hold the connection open
            exec 3<>/dev/tcp/${SMB_HOST}/${SMB_PORT} 2>/dev/null
            # Send a minimal NetBIOS session request to trigger negotiate
            printf '\x00\x00\x00\x00' >&3 2>/dev/null
            sleep 15
            exec 3>&- 2>/dev/null
        ) &
        pids+=($!)
    done

    sleep 3
    # Server should still be responsive
    local pass=0
    for i in $(seq 1 5); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        fi
    done

    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done

    assert_ge "$pass" 3 \
        "Server should remain responsive with idle connections (got $pass/5)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.08: Concurrent protocol negotiation storm
# ---------------------------------------------------------------------------
register_test "S01.08" "test_conn_stress_negotiate_storm" \
    --timeout 120 --tags "stress,conn" \
    --description "50 simultaneous protocol negotiations"
test_conn_stress_negotiate_storm() {
    local pids=() pass=0

    for i in $(seq 1 50); do
        (
            # Force full negotiate by using different protocols
            local protos=("SMB2_02" "SMB2_10" "SMB3_00" "SMB3_02" "SMB3_11")
            local proto="${protos[$((i % 5))]}"
            smb_cmd "$SMB_UNC" --proto "$proto" -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 35 \
        "At least 35 of 50 negotiate storms should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.09: Abrupt TCP RST during negotiate
# ---------------------------------------------------------------------------
register_test "S01.09" "test_conn_stress_rst_during_negotiate" \
    --timeout 60 --tags "stress,conn,destructive" \
    --description "TCP RST during SMB negotiation (50 times)"
test_conn_stress_rst_during_negotiate() {
    local marker
    marker=$(vm_dmesg_mark)

    for i in $(seq 1 50); do
        # Open TCP, start sending, then immediately close
        (
            exec 3<>/dev/tcp/${SMB_HOST}/${SMB_PORT} 2>/dev/null
            # Send garbage to trigger negotiate path, then kill
            printf '\x00\x00\x00\x45\xfeSMB' >&3 2>/dev/null
            exec 3>&- 2>/dev/null
        ) 2>/dev/null
    done

    sleep 3

    # Server should survive without BUG/OOPS
    local errors
    errors=$(vm_dmesg_errors "$marker" 2>/dev/null)
    if echo "$errors" | grep -qiE 'BUG|OOPS|panic'; then
        assert_not_contains "$errors" "BUG" "Server crashed during RST storm" || return 1
    fi

    # Server should still be responsive
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after RST storm" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S01.10: Connection storm with dmesg monitoring
# ---------------------------------------------------------------------------
register_test "S01.10" "test_conn_stress_dmesg_clean" \
    --timeout 120 --tags "stress,conn" \
    --description "100 connections with dmesg error checking"
test_conn_stress_dmesg_clean() {
    local marker
    marker=$(vm_dmesg_mark)

    local pids=()
    for i in $(seq 1 100); do
        (
            smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done

    sleep 3
    assert_dmesg_clean "$marker" "dmesg errors after 100-connection stress" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.11: Sustained connection pressure (connections over 60 seconds)
# ---------------------------------------------------------------------------
register_test "S01.11" "test_conn_stress_sustained_60s" \
    --timeout 120 --tags "stress,slow,conn" \
    --description "Continuous connection churn for 60 seconds"
test_conn_stress_sustained_60s() {
    local duration=60
    local end_time=$(( $(date +%s) + duration ))
    local total=0 pass=0

    while [[ $(date +%s) -lt $end_time ]]; do
        local pids=()
        for i in $(seq 1 10); do
            (
                smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
            ) &
            pids+=($!)
            ((total++))
        done
        for pid in "${pids[@]}"; do
            if wait "$pid" 2>/dev/null; then
                ((pass++))
            fi
        done
    done

    local rate=$((pass * 100 / total))
    assert_ge "$rate" 75 \
        "Success rate over ${duration}s should be >= 75% (got ${rate}%, $pass/$total)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.12: Parallel negotiate + session setup race
# ---------------------------------------------------------------------------
register_test "S01.12" "test_conn_stress_negotiate_session_race" \
    --timeout 120 --tags "stress,conn" \
    --description "30 clients racing negotiate + session setup simultaneously"
test_conn_stress_negotiate_session_race() {
    local pids=() pass=0

    for i in $(seq 1 30); do
        (
            # Each client does negotiate + session setup + tree connect + ls
            smb_cmd "$SMB_UNC" -c "ls; pwd; ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 20 \
        "At least 20 of 30 negotiate-session races should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.13: Backlog overflow (more connections than KSMBD_SOCKET_BACKLOG=64)
# ---------------------------------------------------------------------------
register_test "S01.13" "test_conn_stress_backlog_overflow" \
    --timeout 120 --tags "stress,conn" \
    --description "Exceed socket backlog limit (64) with 100 SYN-only connections"
test_conn_stress_backlog_overflow() {
    # Attempt to overwhelm the listen backlog
    local pids=()
    for i in $(seq 1 100); do
        (
            # Just open TCP connections simultaneously
            exec 3<>/dev/tcp/${SMB_HOST}/${SMB_PORT} 2>/dev/null
            sleep 2
            exec 3>&- 2>/dev/null
        ) &
        pids+=($!)
    done

    # After backlog is full, verify server recovers
    sleep 5
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    sleep 3

    # Server should recover and accept connections
    smb_connect_test_retry 5 "$SMB_UNC" || {
        echo "Server did not recover after backlog overflow" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S01.14: Mixed protocol connection stress
# ---------------------------------------------------------------------------
register_test "S01.14" "test_conn_stress_mixed_protocols" \
    --timeout 120 --tags "stress,conn" \
    --description "50 connections with random SMB protocol versions"
test_conn_stress_mixed_protocols() {
    local protos=("SMB2_02" "SMB2_10" "SMB3_00" "SMB3_02" "SMB3_11")
    local pids=() pass=0

    for i in $(seq 1 50); do
        (
            local proto="${protos[$((RANDOM % 5))]}"
            smb_cmd "$SMB_UNC" --proto "$proto" -c "ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 35 \
        "At least 35 of 50 mixed-protocol connections should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S01.15: Connection exhaustion and recovery
# ---------------------------------------------------------------------------
register_test "S01.15" "test_conn_stress_exhaust_recover" \
    --timeout 180 --tags "stress,slow,conn,destructive" \
    --description "Exhaust connections, then verify graceful recovery"
test_conn_stress_exhaust_recover() {
    # Phase 1: Flood with connections to exhaust resources
    local pids=()
    for i in $(seq 1 300); do
        (
            smb_cmd "$SMB_UNC" -c "ls; ls; ls" >/dev/null 2>&1
            sleep 2
        ) &
        pids+=($!)
    done

    # Let the storm run
    sleep 5

    # Phase 2: While under stress, attempt connection
    local during_pass=0
    for i in $(seq 1 5); do
        if timeout 10 bash -c "smb_cmd '$SMB_UNC' -c 'ls'" >/dev/null 2>&1; then
            ((during_pass++))
        fi
    done

    # Clean up
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done

    # Phase 3: Wait for recovery, then verify
    sleep 10
    local after_pass=0
    for i in $(seq 1 10); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((after_pass++))
        fi
        sleep 1
    done

    assert_ge "$after_pass" 7 \
        "Server should recover after connection exhaustion ($after_pass/10 post-recovery)" || return 1
    return 0
}
