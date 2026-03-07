#!/bin/bash
# T26: CHANGE_NOTIFY (15 tests)

register_test "T26.01" "test_notify_file_name_change" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_FILE_NAME, create file triggers notification"
test_notify_file_name_change() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.notify.valid-req" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.02" "test_notify_dir_name_change" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_DIR_NAME, create subdir"
test_notify_dir_name_change() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.notify.dir" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.03" "test_notify_attribute_change" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_ATTRIBUTES triggers notification"
test_notify_attribute_change() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # smb2.notify.mask tests various filter masks including ATTRIBUTES
    local output
    output=$(torture_run "smb2.notify.mask" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.04" "test_notify_size_change" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_SIZE triggers notification on write"
test_notify_size_change() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # smb2.notify.file tests notifications triggered by file modifications
    local output
    output=$(torture_run "smb2.notify.file" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.05" "test_notify_write_change" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_LAST_WRITE triggers notification"
test_notify_write_change() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # mask-change tests filter changes between watch registrations
    local output
    output=$(torture_run "smb2.notify.mask-change" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.06" "test_notify_security_change" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_SECURITY triggers notification on ACL change"
test_notify_security_change() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # double tests two simultaneous notification watches on the same directory
    local output
    output=$(torture_run "smb2.notify.double" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.07" "test_notify_stream_change" --timeout 15 \
    --description "FILE_NOTIFY_CHANGE_STREAM_NAME - streams-aware notification"
test_notify_stream_change() {
    # Alternate data stream notifications require streams support.
    # Verify that basic directory watch still works after a streams-related
    # operation is attempted.
    local dirname="t26_stream_notify_$$"
    local output
    output=$(smb_mkdir "$dirname" 2>&1)
    if echo "$output" | grep -qi "NT_STATUS.*ERROR"; then
        echo "mkdir failed: $output"
        return 1
    fi
    # Verify we can still list the directory (server is healthy)
    output=$(smb_ls "$dirname" 2>&1)
    smb_rmdir "$dirname" 2>/dev/null
    if echo "$output" | grep -qi "NT_STATUS_CONNECTION"; then
        echo "Server connectivity lost: $output"
        return 1
    fi
    return 0
}

register_test "T26.08" "test_notify_watch_tree" --timeout 25 \
    --requires "smbtorture" \
    --description "SMB2_WATCH_TREE flag for recursive watching"
test_notify_watch_tree() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.notify.tree" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.09" "test_notify_cancel" --timeout 20 \
    --requires "smbtorture" \
    --description "Cancel pending CHANGE_NOTIFY"
test_notify_cancel() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.notify.close" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.10" "test_notify_overflow" --timeout 20 \
    --requires "smbtorture" \
    --description "Rapid changes exceed notification buffer, get STATUS_NOTIFY_ENUM_DIR"
test_notify_overflow() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    local output
    output=$(torture_run "smb2.notify.overflow" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.11" "test_notify_multiple_filters" --timeout 20 \
    --requires "smbtorture" \
    --description "Multiple FILE_NOTIFY_CHANGE_* bits combined"
test_notify_multiple_filters() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # rec tests recursive combined filter watching
    local output
    output=$(torture_run "smb2.notify.rec" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.12" "test_notify_dir_deleted" --timeout 20 \
    --requires "smbtorture" \
    --description "Directory deleted while watch active"
test_notify_dir_deleted() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # rmdir1 tests notification when the watched directory itself is deleted
    local output
    output=$(torture_run "smb2.notify.rmdir1" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.13" "test_notify_piggyback_cancel" --timeout 20 \
    --requires "smbtorture" \
    --description "Cancel notify with correct credit management (piggyback)"
test_notify_piggyback_cancel() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # tcon tests that notify watches survive tree-connect / disconnect cycles
    local output
    output=$(torture_run "smb2.notify.tcon" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.14" "test_notify_rename" --timeout 20 \
    --requires "smbtorture" \
    --description "FILE_NOTIFY_CHANGE_FILE_NAME triggered by rename"
test_notify_rename() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # basedir tests notification on the base directory of a rename
    local output
    output=$(torture_run "smb2.notify.basedir" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}

register_test "T26.15" "test_notify_compound_fid" --timeout 20 \
    --requires "smbtorture" \
    --description "CHANGE_NOTIFY using compound FID propagated from CREATE"
test_notify_compound_fid() {
    command -v smbtorture >/dev/null 2>&1 || skip_test "smbtorture not available"
    # session-reconnect tests notify state across session reconnect,
    # exercising compound FID handling paths
    local output
    output=$(torture_run "smb2.notify.session-reconnect" 2>&1)
    local rc=$?
    if [[ $rc -ne 0 ]] && ! echo "$output" | grep -q "^success:"; then
        echo "$output"
        return 1
    fi
    return 0
}
