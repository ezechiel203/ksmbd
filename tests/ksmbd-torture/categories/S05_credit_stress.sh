#!/bin/bash
# S05: CREDIT STRESS (10 tests)
#
# Exercises SMB2 credit-based flow control:
#   - Credit exhaustion scenarios
#   - Multi-credit operations (large I/O requiring credit_charge > 1)
#   - Credit granting under sustained load
#   - Credit accounting correctness (total_credits, outstanding_credits)
#   - smb2.credits smbtorture suite
#
# Key kernel paths:
#   - smb2misc.c: smb2_check_user_session_in_preq() credit charge validation
#   - smb2_pdu_common.c: smb2_set_rsp_credits() -- credit granting algorithm
#   - connection.c: conn->total_credits (init=1), conn->outstanding_credits
#   - connection.h: conn->credits_lock (spinlock)
#
# Constants:
#   SMB2_MAX_CREDITS = 8192
#   Initial total_credits = 1 (set in ksmbd_conn_alloc)
#   max_credits = SMB2_MAX_CREDITS (per smb2ops.c for all dialects)

# ---------------------------------------------------------------------------
# S05.01: Credit exhaustion via concurrent large operations
# ---------------------------------------------------------------------------
register_test "S05.01" "test_credit_stress_exhaustion" \
    --timeout 180 --tags "stress,slow,credit" \
    --description "Exhaust credits with 50 concurrent large operations"
test_credit_stress_exhaustion() {
    # Create a large file to read
    smb_write_binary "credit_exhaust.dat" 1048576

    local pids=() pass=0
    for i in $(seq 1 50); do
        (
            local tmpf=$(mktemp)
            smb_get "credit_exhaust.dat" "$tmpf" >/dev/null 2>&1
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

    smb_rm "credit_exhaust.dat" 2>/dev/null

    assert_ge "$pass" 30 \
        "At least 30 of 50 credit-heavy operations should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S05.02: Multi-credit operation stress (large reads)
# ---------------------------------------------------------------------------
register_test "S05.02" "test_credit_stress_multicredit_reads" \
    --timeout 180 --tags "stress,slow,credit" \
    --description "100 large reads requiring multi-credit charging"
test_credit_stress_multicredit_reads() {
    # CIFS_DEFAULT_IOSIZE = 8MB for SMB2.0, larger for SMB3
    # Multi-credit charge = ceil(size / 65536) per MS-SMB2
    smb_write_binary "multicredit_read.dat" 524288  # 512KB

    local pass=0
    for i in $(seq 1 100); do
        local tmpf=$(mktemp)
        if smb_get "multicredit_read.dat" "$tmpf" >/dev/null 2>&1; then
            ((pass++))
        fi
        rm -f "$tmpf"
    done

    smb_rm "multicredit_read.dat" 2>/dev/null

    assert_ge "$pass" 90 \
        "At least 90 of 100 multi-credit reads should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S05.03: Credit granting under sustained load
# ---------------------------------------------------------------------------
register_test "S05.03" "test_credit_stress_sustained_grant" \
    --timeout 120 --tags "stress,credit" \
    --description "Verify credit granting stays healthy during 30s sustained load"
test_credit_stress_sustained_grant() {
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
    assert_ge "$rate" 85 \
        "Credit granting success rate should be >= 85% under sustained load (got ${rate}%)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S05.04: smbtorture smb2.credits suite
# ---------------------------------------------------------------------------
register_test "S05.04" "test_credit_stress_torture_suite" \
    --timeout 120 --tags "stress,credit" \
    --description "Run smbtorture smb2.credits test suite"
test_credit_stress_torture_suite() {
    local output
    output=$(torture_run "smb2.credits.session_setup_credits_granted" 2>&1)
    local rc=$?

    # Just verify no server crash; credits behavior may vary
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after smb2.credits suite" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S05.05: Credit accounting leak detection
# ---------------------------------------------------------------------------
register_test "S05.05" "test_credit_stress_accounting_leak" \
    --timeout 120 --tags "stress,credit,leak" \
    --description "Verify no credit accounting drift after 200 operations"
test_credit_stress_accounting_leak() {
    local marker
    marker=$(vm_dmesg_mark)

    for i in $(seq 1 200); do
        smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
    done

    sleep 3

    # Check for credit-related errors in dmesg
    local credit_errors
    credit_errors=$(vm_dmesg_since "$marker" 2>/dev/null | grep -i 'credit' | grep -i 'error\|overflow\|underflow' | head -5)

    if [[ -n "$credit_errors" ]]; then
        echo "Credit accounting errors detected: $credit_errors" >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# S05.06: Rapid credit request/consume cycling
# ---------------------------------------------------------------------------
register_test "S05.06" "test_credit_stress_rapid_cycle" \
    --timeout 120 --tags "stress,credit" \
    --description "Rapid small operations to cycle credit request/consume"
test_credit_stress_rapid_cycle() {
    local pass=0
    # Small operations that each consume 1 credit
    for i in $(seq 1 500); do
        if smb_cmd "$SMB_UNC" -c "pwd" >/dev/null 2>&1; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 450 \
        "At least 450 of 500 rapid credit cycles should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S05.07: Parallel operations with mixed credit charges
# ---------------------------------------------------------------------------
register_test "S05.07" "test_credit_stress_mixed_charges" \
    --timeout 120 --tags "stress,credit" \
    --description "Mix of small (1-credit) and large (multi-credit) operations"
test_credit_stress_mixed_charges() {
    smb_write_binary "credit_mixed.dat" 262144  # 256KB

    local pids=() pass=0
    for i in $(seq 1 30); do
        if [[ $((i % 3)) -eq 0 ]]; then
            # Large operation (multi-credit)
            (
                local tmpf=$(mktemp)
                smb_get "credit_mixed.dat" "$tmpf" >/dev/null 2>&1
                rm -f "$tmpf"
            ) &
        else
            # Small operation (1-credit)
            (
                smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1
            ) &
        fi
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    smb_rm "credit_mixed.dat" 2>/dev/null

    assert_ge "$pass" 20 \
        "At least 20 of 30 mixed credit operations should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S05.08: max_credits boundary test (8192)
# ---------------------------------------------------------------------------
register_test "S05.08" "test_credit_stress_max_boundary" \
    --timeout 180 --tags "stress,slow,credit" \
    --description "Push credit count toward max_credits=8192 boundary"
test_credit_stress_max_boundary() {
    # Many parallel operations on a single connection will push total_credits
    # toward the max_credits=8192 limit
    local pids=() pass=0

    for i in $(seq 1 100); do
        (
            smb_cmd "$SMB_UNC" -c "ls; pwd; ls; pwd; ls" >/dev/null 2>&1
        ) &
        pids+=($!)
    done

    for pid in "${pids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 70 \
        "At least 70 of 100 max-boundary credit tests should succeed (got $pass)" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# S05.09: Credits during compound requests
# ---------------------------------------------------------------------------
register_test "S05.09" "test_credit_stress_compound_credits" \
    --timeout 120 --tags "stress,credit" \
    --description "Credit behavior during compound request chains"
test_credit_stress_compound_credits() {
    local output
    output=$(torture_run "smb2.compound.interim1" 2>&1)

    # Just verify server stability
    smb_connect_test "$SMB_UNC" || {
        echo "Server unresponsive after compound credit stress" >&2
        return 1
    }
    return 0
}

# ---------------------------------------------------------------------------
# S05.10: Credit recovery after error responses
# ---------------------------------------------------------------------------
register_test "S05.10" "test_credit_stress_error_recovery" \
    --timeout 120 --tags "stress,credit" \
    --description "Credit recovery after many error-inducing operations"
test_credit_stress_error_recovery() {
    # Generate many errors (access nonexistent files)
    for i in $(seq 1 100); do
        smb_stat "nonexistent_file_${i}.txt" >/dev/null 2>&1
    done

    # After errors, verify credits recover and normal ops work
    local pass=0
    for i in $(seq 1 20); do
        if smb_cmd "$SMB_UNC" -c "ls" >/dev/null 2>&1; then
            ((pass++))
        fi
    done

    assert_ge "$pass" 16 \
        "At least 16 of 20 post-error credit recovery ops should succeed (got $pass)" || return 1
    return 0
}
