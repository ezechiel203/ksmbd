#!/bin/bash
# T03_tree_connect.sh -- Tree connect (share) tests
#
# Tests connecting to valid and invalid shares, disconnection, multiple
# concurrent tree connects, and reconnection after disconnect.

# ============================================================================
# Test 1: Connect to valid share
# ============================================================================
test_tree_connect_valid() {
    local desc="Connect to valid share and list contents"
    local output
    output=$(_smbclient_cmd "ls")
    local rc=$?
    assert_status 0 "$rc" "$desc" || return 1
    assert_contains "$output" "blocks" "Listing should contain 'blocks available'" || return 1
}

# ============================================================================
# Test 2: Reject invalid share name
# ============================================================================
test_tree_connect_invalid_share() {
    local desc="Reject connection to nonexistent share"
    local output
    output=$("$SMBCLIENT" "//${SMB_HOST}/NONEXISTENT_SHARE_$(random_string 8)" \
        -p "$SMB_PORT" -U "$SMB_CREDS" \
        --option="client min protocol=$SMB_PROTO" \
        --option="client max protocol=$SMB_PROTO" \
        -c "ls" 2>&1)
    local rc=$?
    assert_failure "$rc" "Connection to nonexistent share should fail" || return 1
    # Expect BAD_NETWORK_NAME or similar
    if echo "$output" | grep -qE "NT_STATUS_BAD_NETWORK_NAME|NT_STATUS_BAD_NETWORK_PATH|BAD_NETWORK"; then
        return 0
    fi
    # Some versions just say "tree connect failed"
    if echo "$output" | grep -qi "tree connect failed\|Access denied\|not found"; then
        return 0
    fi
    echo "Expected bad network name error, got: $(echo "$output" | head -3)" >&2
    return 1
}

# ============================================================================
# Test 3: Tree disconnect and reconnect
# ============================================================================
test_tree_disconnect_reconnect() {
    local desc="Disconnect from share and reconnect"
    # First connection
    local output
    output=$(_smbclient_cmd "ls")
    local rc=$?
    assert_status 0 "$rc" "Initial connection should succeed" || return 1

    # Reconnect (smbclient disconnects tree on exit, so this is a new tree connect)
    output=$(_smbclient_cmd "ls")
    rc=$?
    assert_status 0 "$rc" "Reconnection should succeed" || return 1
    assert_contains "$output" "blocks" "Listing after reconnect should work" || return 1
}

# ============================================================================
# Test 4: Multiple tree connects in sequence
# ============================================================================
test_tree_connect_multiple() {
    local desc="Multiple rapid tree connects succeed"
    local i
    for i in 1 2 3 4 5; do
        local output
        output=$(_smbclient_cmd "ls")
        local rc=$?
        assert_status 0 "$rc" "Connection $i should succeed" || return 1
    done
}

# ============================================================================
# Test 5: Connect to IPC$ share
# ============================================================================
test_tree_connect_ipc() {
    local desc="Connect to IPC$ pipe share"
    local output
    output=$("$SMBCLIENT" "//${SMB_HOST}/IPC\$" -p "$SMB_PORT" -U "$SMB_CREDS" \
        --option="client min protocol=$SMB_PROTO" \
        --option="client max protocol=$SMB_PROTO" \
        -c "ls" 2>&1)
    local rc=$?
    # IPC$ is a special pipe share. ls may or may not work, but connection
    # should not crash. rc=0 or certain expected errors are fine.
    if [[ $rc -eq 0 ]]; then
        return 0
    fi
    # IPC$ might reject ls but still connect
    if echo "$output" | grep -qE "NT_STATUS_ACCESS_DENIED|NT_STATUS_NO_SUCH_FILE|NT_STATUS_INVALID_INFO_CLASS"; then
        # These are valid responses for ls on IPC$
        return 0
    fi
    # Connection-level errors are failures
    if echo "$output" | grep -qE "Connection.*reset\|Connection.*refused\|DEAD"; then
        echo "IPC$ connection caused server error: $(echo "$output" | head -3)" >&2
        return 1
    fi
    # Any other error is acceptable (IPC$ has limited operations)
    return 0
}
