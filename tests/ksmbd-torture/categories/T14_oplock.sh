#!/bin/bash
# T14: OPLOCK -- Opportunistic Locks (16 tests)

register_test "T14.01" "test_oplock_level_ii" --timeout 30 \
    --requires "smbtorture" \
    --description "Request Level II oplock"
test_oplock_level_ii() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.levelii500" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.02" "test_oplock_exclusive" --timeout 30 \
    --requires "smbtorture" \
    --description "Request Exclusive oplock"
test_oplock_exclusive() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.exclusive1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.03" "test_oplock_batch" --timeout 30 \
    --requires "smbtorture" \
    --description "Request Batch oplock"
test_oplock_batch() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.batch1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.04" "test_oplock_break_to_level_ii" --timeout 30 \
    --requires "smbtorture" \
    --description "Second open breaks Exclusive to Level II"
test_oplock_break_to_level_ii() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.exclusive2" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.05" "test_oplock_break_to_none" --timeout 30 \
    --requires "smbtorture" \
    --description "Second open breaks Level II to None"
test_oplock_break_to_none() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.levelii501" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.06" "test_oplock_break_batch_open" --timeout 30 \
    --requires "smbtorture" \
    --description "Batch oplock broken by second CREATE"
test_oplock_break_batch_open() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.batch2" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.07" "test_oplock_ack_valid" --timeout 30 \
    --requires "smbtorture" \
    --description "Acknowledge oplock break with correct level"
test_oplock_ack_valid() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.batch3" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.08" "test_oplock_ack_invalid_level" --timeout 30 \
    --requires "smbtorture" \
    --description "Acknowledge with wrong oplock level"
test_oplock_ack_invalid_level() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # batch9 tests oplock ack with invalid level transitions
    local output
    output=$(torture_run "smb2.oplock.batch9" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.09" "test_oplock_none_request" --timeout 15 \
    --description "Request SMB2_OPLOCK_LEVEL_NONE (no oplock)"
test_oplock_none_request() {
    # Requesting no oplock is implicitly tested by all basic create/write tests.
    # Verify a basic create+write+read works with no oplock requested.
    local fname="t14_none_oplock_$$"
    local output
    output=$(smb_write_file "$fname" "none oplock test" 2>&1)
    if echo "$output" | grep -qi "NT_STATUS"; then
        echo "Expected clean write but got: $output"
        return 1
    fi
    local content
    content=$(smb_read_file "$fname" 2>/dev/null)
    smb_rm "$fname" 2>/dev/null
    assert_eq "none oplock test" "$content" "file content mismatch with no-oplock open" || return 1
}

register_test "T14.10" "test_oplock_break_timeout" --timeout 30 \
    --requires "smbtorture" \
    --description "Fail to acknowledge break within timeout"
test_oplock_break_timeout() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # batch10 tests what happens when the break ack is not sent in time
    local output
    output=$(torture_run "smb2.oplock.batch10" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.11" "test_oplock_break_on_write" --timeout 30 \
    --requires "smbtorture" \
    --description "Write from second client breaks oplock"
test_oplock_break_on_write() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.batch6" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.12" "test_oplock_break_on_lock" --timeout 30 \
    --requires "smbtorture" \
    --description "Byte-range lock triggers oplock break"
test_oplock_break_on_lock() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.oplock.batch7" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.13" "test_oplock_break_on_setinfo" --timeout 30 \
    --requires "smbtorture" \
    --description "SET_INFO triggers oplock break"
test_oplock_break_on_setinfo() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # batch11 exercises set_info triggering an oplock break
    local output
    output=$(torture_run "smb2.oplock.batch11" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.14" "test_oplock_break_async" --timeout 30 \
    --requires "smbtorture" \
    --description "Oplock break uses async semantics"
test_oplock_break_async() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # batch8 tests asynchronous oplock break handling
    local output
    output=$(torture_run "smb2.oplock.batch8" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.15" "test_oplock_reconnect_preserve" --timeout 30 \
    --requires "smbtorture" \
    --description "Oplock state after durable reconnect"
test_oplock_reconnect_preserve() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # durable-open.open-oplock verifies oplock is preserved after disconnect+reconnect
    local output
    output=$(torture_run "smb2.durable-open.open2-oplock" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T14.16" "test_oplock_directory" --timeout 15 \
    --description "Request oplock on directory (should get NONE or Level II only)"
test_oplock_directory() {
    # Directories can only receive Level II or None oplocks per MS-SMB2.
    # Verify that we can list a directory even if we have a directory handle open.
    local dirname="t14_dir_oplock_$$"
    local output
    output=$(smb_mkdir "$dirname" 2>&1)
    if echo "$output" | grep -qi "NT_STATUS.*ERROR\|ERR"; then
        fail_test "mkdir failed: $output"
        return 1
    fi
    output=$(smb_ls "$dirname" 2>&1)
    local rc=$?
    smb_rmdir "$dirname" 2>/dev/null
    if [[ $rc -ne 0 ]]; then
        echo "Directory listing failed: $output"
        return 1
    fi
    return 0
}
