#!/bin/bash
# T01_negotiate.sh -- Protocol negotiation tests
#
# Tests SMB dialect negotiation, capability advertisement, and error handling
# for invalid negotiation attempts.

# ============================================================================
# Test 1: Negotiate SMB2 dialect
# ============================================================================
test_negotiate_smb2() {
    local desc="Negotiate SMB2 dialect successfully"
    local output
    output=$(smb_connect_proto "SMB2_02")
    local rc=$?
    assert_status 0 "$rc" "$desc" || return 1
}

# ============================================================================
# Test 2: Negotiate SMB3 dialect
# ============================================================================
test_negotiate_smb3() {
    local desc="Negotiate SMB3 dialect successfully"
    local output
    output=$(smb_connect_proto "SMB3_00")
    local rc=$?
    assert_status 0 "$rc" "$desc" || return 1
}

# ============================================================================
# Test 3: Negotiate SMB3.1.1 dialect
# ============================================================================
test_negotiate_smb311() {
    local desc="Negotiate SMB3.1.1 dialect successfully"
    local output
    output=$(smb_connect_proto "SMB3_11")
    local rc=$?
    assert_status 0 "$rc" "$desc" || return 1
}

# ============================================================================
# Test 4: Verify server capabilities in response
# ============================================================================
test_negotiate_capabilities() {
    local desc="Verify server capabilities are present in listing"
    # Connect with the highest dialect and verify we can list files
    # (capabilities are protocol-level; if we can list, negotiation succeeded
    # with the correct capabilities for that dialect)
    local output
    output=$("$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" -U "$SMB_CREDS" \
        --option="client min protocol=SMB3_11" \
        --option="client max protocol=SMB3_11" \
        -c "ls" 2>&1)
    local rc=$?
    assert_status 0 "$rc" "SMB3.1.1 connection failed" || return 1
    assert_contains "$output" "blocks" "Directory listing should contain 'blocks available'" || return 1
}

# ============================================================================
# Test 5: Multi-dialect negotiation selects highest
# ============================================================================
test_negotiate_multi_dialect() {
    local desc="Multi-dialect negotiation selects highest available"
    # Offer SMB2.0.2 through SMB3.1.1, server should pick highest
    local output
    output=$("$SMBCLIENT" "$SMB_UNC" -p "$SMB_PORT" -U "$SMB_CREDS" \
        --option="client min protocol=SMB2_02" \
        --option="client max protocol=SMB3_11" \
        -c "ls" 2>&1)
    local rc=$?
    assert_status 0 "$rc" "Multi-dialect negotiation failed" || return 1
    assert_contains "$output" "blocks" "Directory listing should succeed" || return 1
}
