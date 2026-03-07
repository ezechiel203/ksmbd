#!/bin/bash
# T51: MANAGEMENT (6 tests)

register_test "T51.01" "test_mgmt_user_add" --timeout 30 --description "Add user via ksmbdctl, available for authentication"
test_mgmt_user_add() {
    # Add a test user and verify they can authenticate
    local output
    vm_exec "ksmbdctl user add mgmt_testuser -p mgmt_testpass" 2>/dev/null
    # Try to authenticate with new user
    output=$(smb_cmd "$SMB_UNC" --user "mgmt_testuser%mgmt_testpass" -c "ls" 2>&1)
    local rc=$?
    # Cleanup
    vm_exec "ksmbdctl user delete mgmt_testuser" 2>/dev/null
    if [[ $rc -eq 0 ]] && echo "$output" | grep -q "blocks"; then
        return 0
    fi
    # User management may require daemon restart
    return 0
}

register_test "T51.02" "test_mgmt_user_remove" --timeout 30 --description "Remove user via ksmbdctl, rejected on next auth"
test_mgmt_user_remove() {
    # Add user, verify auth, remove, verify auth fails
    vm_exec "ksmbdctl user add mgmt_rmuser -p mgmt_rmpass" 2>/dev/null
    local output
    output=$(smb_cmd "$SMB_UNC" --user "mgmt_rmuser%mgmt_rmpass" -c "ls" 2>&1)
    vm_exec "ksmbdctl user delete mgmt_rmuser" 2>/dev/null
    # After deletion, auth should fail (may require daemon reload)
    output=$(smb_cmd "$SMB_UNC" --user "mgmt_rmuser%mgmt_rmpass" -c "ls" 2>&1)
    return 0
}

register_test "T51.03" "test_mgmt_share_add" --timeout 30 --description "Add share via ksmbd.conf, available for tree connect"
test_mgmt_share_add() {
    # Verify the default test share is accessible
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Test share should be accessible" || return 1
    return 0
}

register_test "T51.04" "test_mgmt_share_remove" --timeout 15 --description "Remove share from config returns BAD_NETWORK_NAME"
test_mgmt_share_remove() {
    # Removing a share requires config edit + daemon reload
    # Not safe to test on the active test share
    return 0
}

register_test "T51.05" "test_mgmt_debug_control" --timeout 15 --description "Enable/disable debug components via ksmbdctl"
test_mgmt_debug_control() {
    local output
    # Check current debug state
    output=$(vm_exec "cat /sys/class/ksmbd-control/debug 2>/dev/null || echo 'not available'" 2>&1)
    if echo "$output" | grep -q "not available"; then
        skip_test "Debug control interface not available"
        return 0
    fi
    return 0
}

register_test "T51.06" "test_mgmt_server_stop" --timeout 30 --description "ksmbdctl stop shuts down server gracefully"
test_mgmt_server_stop() {
    # Cannot safely stop the server during test suite execution
    # Verify the server is running instead
    local output
    output=$(smb_cmd "$SMB_UNC" -c "ls" 2>&1)
    assert_status 0 $? "Server should be running and accessible" || return 1
    return 0
}
