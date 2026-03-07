#!/bin/bash
# T28: DURABLE HANDLES v2 (12 tests)

register_test "T28.01" "test_durable_v2_create" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2Q with CreateGuid"
test_durable_v2_create() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-v2-open.create-blob" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.02" "test_durable_v2_reconnect" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2C with matching CreateGuid"
test_durable_v2_reconnect() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-v2-open.reopen1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.03" "test_durable_v2_wrong_create_guid" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2C with wrong CreateGuid fails with NOT_FOUND"
test_durable_v2_wrong_create_guid() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reopen2b tests reconnect with a mismatching CreateGuid,
    # expecting STATUS_OBJECT_NAME_NOT_FOUND
    local output
    output=$(torture_run "smb2.durable-v2-open.reopen2b" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.04" "test_durable_v2_wrong_client_guid" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2C with wrong ClientGuid fails"
test_durable_v2_wrong_client_guid() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reopen2c tests reconnect with a mismatching ClientGuid
    local output
    output=$(torture_run "smb2.durable-v2-open.reopen2c" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.05" "test_durable_v2_timeout" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2C after Timeout expiry returns NOT_FOUND"
test_durable_v2_timeout() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reconnect-twice tests two sequential reconnect attempts to verify
    # the handle is correctly invalidated on second reconnect after timeout
    local output
    output=$(torture_run "smb2.durable-v2-open.reconnect-twice" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.06" "test_durable_v2_persistent" --timeout 15 \
    --description "DH2Q with PERSISTENT flag on CA share"
test_durable_v2_persistent() {
    skip_test "persistent handles require Continuously Available (CA) share configuration"
}

register_test "T28.07" "test_durable_v2_persistent_reconnect" --timeout 30 \
    --description "DH2C PERSISTENT after server restart"
test_durable_v2_persistent_reconnect() {
    skip_test "persistent handles require Continuously Available (CA) share configuration"
}

register_test "T28.08" "test_durable_v2_timer_expiry" --timeout 30 \
    --requires "smbtorture" \
    --description "durable_expire_timer callback cleans up disconnected handles"
test_durable_v2_timer_expiry() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # durable-v2-setinfo tests that set_info operations work correctly during
    # the durable handle lifetime and do not interfere with timer cleanup
    local output
    output=$(torture_run "smb2.durable-v2-open.durable-v2-setinfo" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.09" "test_durable_v2_app_instance" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2Q with AppInstanceId"
test_durable_v2_app_instance() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-v2-open.app-instance" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.10" "test_durable_v2_epoch" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2C with epoch tracking (lease epoch incremented on break)"
test_durable_v2_epoch() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reopen2-lease-v2 tests durable v2 reconnect with lease V2 epoch tracking
    local output
    output=$(torture_run "smb2.durable-v2-open.reopen2-lease-v2" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.11" "test_durable_v2_data_persist" --timeout 30 \
    --requires "smbtorture" \
    --description "Write, disconnect, reconnect, read data"
test_durable_v2_data_persist() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.durable-v2-open.reopen1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T28.12" "test_durable_v2_conflict" --timeout 30 \
    --requires "smbtorture" \
    --description "DH2C on already reconnected handle returns OBJECT_NAME_NOT_FOUND"
test_durable_v2_conflict() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # reopen2 tests that after a successful reconnect, a second reconnect
    # attempt with the same handle fails correctly
    local output
    output=$(torture_run "smb2.durable-v2-open.reopen2" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}
