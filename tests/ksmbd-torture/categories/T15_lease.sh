#!/bin/bash
# T15: LEASE -- Directory and File Leases (18 tests)

register_test "T15.01" "test_lease_read" --timeout 30 \
    --requires "smbtorture" \
    --description "Request R lease"
test_lease_read() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.request" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.02" "test_lease_read_write" --timeout 30 \
    --requires "smbtorture" \
    --description "Request RW lease"
test_lease_read_write() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # upgrade2 starts with R and upgrades to RW
    local output
    output=$(torture_run "smb2.lease.upgrade2" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.03" "test_lease_read_write_handle" --timeout 30 \
    --requires "smbtorture" \
    --description "Request RWH lease"
test_lease_read_write_handle() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # upgrade3 tests full RWH lease request
    local output
    output=$(torture_run "smb2.lease.upgrade3" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.04" "test_lease_break_rw_to_r" --timeout 30 \
    --requires "smbtorture" \
    --description "Second open breaks RW to R"
test_lease_break_rw_to_r() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.break" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.05" "test_lease_break_rwh_to_rw" --timeout 30 \
    --requires "smbtorture" \
    --description "Second open breaks RWH to RW"
test_lease_break_rwh_to_rw() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.breaking1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.06" "test_lease_break_to_none" --timeout 30 \
    --requires "smbtorture" \
    --description "Conflicting access breaks to None"
test_lease_break_to_none() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.breaking2" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.07" "test_lease_ack_valid" --timeout 30 \
    --requires "smbtorture" \
    --description "Acknowledge lease break with correct state"
test_lease_ack_valid() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.breaking3" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.08" "test_lease_ack_wrong_state" --timeout 30 \
    --requires "smbtorture" \
    --description "Acknowledge with wrong lease state"
test_lease_ack_wrong_state() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # breaking4 tests ack with invalid/wrong lease state
    local output
    output=$(torture_run "smb2.lease.breaking4" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.09" "test_lease_key_match" --timeout 30 \
    --requires "smbtorture" \
    --description "Two opens with same lease key share lease"
test_lease_key_match() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.request" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.10" "test_lease_key_different" --timeout 30 \
    --requires "smbtorture" \
    --description "Two opens with different lease keys get independent leases"
test_lease_key_different() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # complex1 tests multiple clients with different lease keys
    local output
    output=$(torture_run "smb2.lease.complex1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.11" "test_lease_upgrade" --timeout 30 \
    --requires "smbtorture" \
    --description "Upgrade R lease to RW"
test_lease_upgrade() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.upgrade" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.12" "test_lease_parent_break" --timeout 30 \
    --requires "smbtorture" \
    --description "Parent directory lease break on child create"
test_lease_parent_break() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # v2_flags_parentkey tests parent lease key tracking
    local output
    output=$(torture_run "smb2.lease.v2_flags_parentkey" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.13" "test_lease_v2_epoch" --timeout 30 \
    --requires "smbtorture" \
    --description "Lease V2 with epoch tracking"
test_lease_v2_epoch() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.v2_epoch1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.14" "test_lease_v2_parent_key" --timeout 30 \
    --requires "smbtorture" \
    --description "Lease V2 with parent lease key"
test_lease_v2_parent_key() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.v2_flags_parentkey" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.15" "test_lease_durable_requirement" --timeout 30 \
    --requires "smbtorture" \
    --description "Durable handle requires lease with Handle caching (RWH)"
test_lease_durable_requirement() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # durable-open.open-lease verifies durable+lease combination
    local output
    output=$(torture_run "smb2.durable-open.open-lease" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.16" "test_lease_break_timeout" --timeout 30 \
    --requires "smbtorture" \
    --description "Lease break not acknowledged in time"
test_lease_break_timeout() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.lease.timeout" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.17" "test_lease_on_directory" --timeout 30 \
    --requires "smbtorture" \
    --description "Request lease on directory"
test_lease_on_directory() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # durable-open.open2-lease tests opening a directory with a lease
    local output
    output=$(torture_run "smb2.durable-open.open2-lease" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T15.18" "test_lease_close_releases" --timeout 30 \
    --requires "smbtorture" \
    --description "Close last handle releases lease"
test_lease_close_releases() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # breaking5 tests that closing the handle releases the lease state
    local output
    output=$(torture_run "smb2.lease.breaking5" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}
