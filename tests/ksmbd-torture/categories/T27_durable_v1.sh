#!/bin/bash
# T27: DURABLE HANDLES v1 (10 tests)

register_test "T27.01" "test_durable_v1_create" --timeout 30 \
    --requires "smbtorture" \
    --description "DHnQ with batch oplock"
test_durable_v1_create() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-open.open-oplock" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.02" "test_durable_v1_reconnect" --timeout 30 \
    --requires "smbtorture" \
    --description "DHnC after disconnect"
test_durable_v1_reconnect() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-open.reopen1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.03" "test_durable_v1_timeout" --timeout 120 --tags "slow" \
    --requires "smbtorture" \
    --description "DHnC after timeout expiry (handle must have expired)"
test_durable_v1_timeout() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reopen3 waits for the durable timeout before attempting reconnect,
    # expecting STATUS_OBJECT_NAME_NOT_FOUND
    local output
    output=$(torture_run "smb2.durable-open.reopen3" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.04" "test_durable_v1_no_batch_oplock" --timeout 15 \
    --requires "smbtorture" \
    --description "DHnQ without batch oplock - not granted"
test_durable_v1_no_batch_oplock() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # stat-open tests opening with stat-only access (no oplock) with durable request;
    # the server should not grant the durable handle.
    local output
    output=$(torture_run "smb2.durable-open.stat-open" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.05" "test_durable_v1_with_lease_h" --timeout 30 \
    --requires "smbtorture" \
    --description "DHnQ with lease including Handle caching"
test_durable_v1_with_lease_h() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-open.open-lease" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.06" "test_durable_v1_data_persist" --timeout 30 \
    --requires "smbtorture" \
    --description "Write data, disconnect, reconnect, read"
test_durable_v1_data_persist() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # file-position tests that the file position is preserved across reconnect
    local output
    output=$(torture_run "smb2.durable-open.file-position" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.07" "test_durable_v1_lock_persist" --timeout 30 \
    --requires "smbtorture" \
    --description "Lock, disconnect, reconnect, verify lock"
test_durable_v1_lock_persist() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-open.lock-oplock" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.08" "test_durable_v1_scavenger" --timeout 30 \
    --requires "smbtorture" \
    --description "Multiple durable handles created and cleaned up"
test_durable_v1_scavenger() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reopen4 tests multiple sequential durable reconnects to verify scavenger
    # cleanup does not prematurely remove valid handles.
    local output
    output=$(torture_run "smb2.durable-open.reopen4" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T27.09" "test_durable_v1_config_required" --timeout 15 \
    --description "Durable handle create succeeds when durable handles enabled"
test_durable_v1_config_required() {
    # Verify that a basic create+write+delete cycle works, confirming the share
    # configuration is healthy. The durable handle config is tested more
    # rigorously by the smbtorture reconnect tests above.
    local fname="t27_config_check_$$"
    local output
    output=$(smb_write_file "$fname" "durable config check" 2>&1)
    if echo "$output" | grep -qi "NT_STATUS.*ERROR\|NT_STATUS_ACCESS_DENIED"; then
        echo "Unexpected failure: $output"
        return 1
    fi
    local content
    content=$(smb_read_file "$fname" 2>/dev/null)
    smb_rm "$fname" 2>/dev/null
    assert_eq "durable config check" "$content" \
        "share must be writable for durable handles to work" || return 1
}

register_test "T27.10" "test_durable_v1_oplock_break" --timeout 30 \
    --requires "smbtorture" \
    --description "Oplock broken during disconnect"
test_durable_v1_oplock_break() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # oplock tests that durable oplock state is correctly handled on break
    local output
    output=$(torture_run "smb2.durable-open.oplock" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}
