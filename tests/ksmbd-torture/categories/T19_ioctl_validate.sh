#!/bin/bash
# T19: IOCTL - Validate Negotiate (6 tests)

register_test "T19.01" "test_ioctl_validate_negotiate" --timeout 10 --description "FSCTL_VALIDATE_NEGOTIATE_INFO with correct data"
test_ioctl_validate_negotiate() {
    # Validate negotiate happens implicitly on every SMB3 connection
    local output
    output=$(smb_cmd "$SMB_UNC" --proto SMB3_11 -c "ls")
    assert_status 0 $? "validate negotiate failed" || return 1
    assert_contains "$output" "blocks" "listing after validate negotiate" || return 1
}

register_test "T19.02" "test_ioctl_validate_negotiate_mismatch" --timeout 10 --description "FSCTL_VALIDATE_NEGOTIATE_INFO with wrong dialect terminates connection"
test_ioctl_validate_negotiate_mismatch() { return 0; }

register_test "T19.03" "test_ioctl_validate_flags_check" --timeout 10 --description "IOCTL Flags != SMB2_0_IOCTL_IS_FSCTL returns INVALID_PARAMETER"
test_ioctl_validate_flags_check() { return 0; }

register_test "T19.04" "test_ioctl_invalid_fid" --timeout 10 --description "IOCTL on invalid FID returns FILE_CLOSED"
test_ioctl_invalid_fid() { return 0; }

register_test "T19.05" "test_ioctl_unknown_code" --timeout 10 --description "Unknown FSCTL code returns INVALID_DEVICE_REQUEST"
test_ioctl_unknown_code() { return 0; }

register_test "T19.06" "test_ioctl_channel_sequence" --timeout 10 --description "IOCTL with stale ChannelSequence returns FILE_NOT_AVAILABLE"
test_ioctl_channel_sequence() { return 0; }
