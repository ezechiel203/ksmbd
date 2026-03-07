#!/bin/bash
# T02_session.sh -- Session management tests
#
# Tests NTLM session setup, guest access, session lifecycle (logoff),
# re-authentication, and session binding behavior.

# ============================================================================
# Test 1: NTLM session setup with valid credentials
# ============================================================================
test_session_ntlm_auth() {
    local desc="NTLM session setup with valid credentials"
    local output
    output=$(_smbclient_cmd "ls")
    local rc=$?
    assert_status 0 "$rc" "$desc" || return 1
    assert_contains "$output" "blocks" "Should list share contents after auth" || return 1
}

# ============================================================================
# Test 2: Guest session (no credentials)
# ============================================================================
test_session_guest() {
    local desc="Guest session connects without credentials"
    local output
    output=$(_smbclient_guest "ls")
    local rc=$?
    # Guest might succeed or fail depending on server config; either is valid.
    # The key test is that the server does not crash and responds properly.
    if [[ $rc -eq 0 ]]; then
        # Guest succeeded -- verify we get a directory listing
        assert_contains "$output" "blocks" "Guest listing should contain blocks" || return 1
    else
        # Guest denied -- server should return a proper error, not crash
        assert_not_contains "$output" "Connection reset" \
            "Server should not reset connection on guest attempt" || return 1
    fi
}

# ============================================================================
# Test 3: Session with invalid password is rejected
# ============================================================================
test_session_invalid_password() {
    local desc="Invalid password is rejected"
    local output
    output=$("$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" \
        -U "${SMB_USER}%WRONGPASSWORD" \
        --option="client min protocol=$SMB_PROTO" \
        --option="client max protocol=$SMB_PROTO" \
        -c "ls" 2>&1)
    local rc=$?
    assert_failure "$rc" "Invalid password should be rejected" || return 1
    # Should get LOGON_FAILURE or similar, not a crash
    if echo "$output" | grep -q "NT_STATUS_LOGON_FAILURE"; then
        return 0
    fi
    # Some smbclient versions say "session setup failed"
    if echo "$output" | grep -qi "session setup failed\|LOGON_FAILURE\|Access denied"; then
        return 0
    fi
    echo "Expected authentication failure message, got: $(echo "$output" | head -3)" >&2
    return 1
}

# ============================================================================
# Test 4: Session logout (clean disconnect)
# ============================================================================
test_session_logout() {
    local desc="Session logout disconnects cleanly"
    # smbclient does implicit logout on exit. Run a command and exit cleanly.
    local output
    output=$(_smbclient_cmd "ls; exit")
    local rc=$?
    assert_status 0 "$rc" "$desc" || return 1
    # Verify we can reconnect immediately after (session was freed)
    output=$(_smbclient_cmd "ls")
    rc=$?
    assert_status 0 "$rc" "Should reconnect after logout" || return 1
}

# ============================================================================
# Test 5: Re-authentication on existing connection
# ============================================================================
test_session_reauth() {
    local desc="Re-authentication works on sequential connections"
    # Connect twice in rapid succession to test session reuse/re-auth paths
    local output1 output2
    output1=$(_smbclient_cmd "ls")
    local rc1=$?
    assert_status 0 "$rc1" "First connection should succeed" || return 1

    output2=$(_smbclient_cmd "ls")
    local rc2=$?
    assert_status 0 "$rc2" "Second connection (re-auth) should succeed" || return 1

    assert_contains "$output1" "blocks" "First listing should have content" || return 1
    assert_contains "$output2" "blocks" "Second listing should have content" || return 1
}
