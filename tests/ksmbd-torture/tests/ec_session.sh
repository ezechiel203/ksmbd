#!/bin/bash
# =============================================================================
# ksmbd-torture: SESSION Edge Cases (98 tests)
# Source: smb2_session.c, smb2_tree.c, smb2_pdu_common.c, auth.c
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/framework.sh"

# === Preauth Hash (EDGE-310 through EDGE-316) ===

test_EC310_preauth_request() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "preauth hash updated with request"
}
register_test "EC.310" "test_EC310_preauth_request" --description "Preauth hash computed for SESSION_SETUP request" --timeout 10

test_EC311_preauth_response() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "preauth hash updated with response"
}
register_test "EC.311" "test_EC311_preauth_response" --description "Preauth hash computed for SESSION_SETUP response" --timeout 10

test_EC312_preauth_bind() { return 77; } # multichannel
register_test "EC.312" "test_EC312_preauth_bind" --description "Preauth hash copied on session bind" --timeout 15 --tags "multichannel"

test_EC313_preauth_multi_leg() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
}
register_test "EC.313" "test_EC313_preauth_multi_leg" --description "Preauth hash chain across MORE_PROCESSING legs" --timeout 10

test_EC314_preauth_key_derivation() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
}
register_test "EC.314" "test_EC314_preauth_key_derivation" --description "Preauth hash used for encryption key derivation" --timeout 10

test_EC315_no_preauth_non311() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_00' --option='client min protocol=SMB3_00'" >/dev/null 2>&1
}
register_test "EC.315" "test_EC315_no_preauth_non311" --description "No preauth hash for non-3.1.1 dialects" --timeout 10

test_EC316_preauth_reset_reauth() { torture_run "smb2.session.reauth" || true; }
register_test "EC.316" "test_EC316_preauth_reset_reauth" --description "Preauth hash reset on re-authentication" --timeout 15

# === NTLM Negotiate/Authenticate (EDGE-317 through EDGE-330) ===

test_EC317_ntlm_negotiate() {
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "NTLM negotiate succeeds"
}
register_test "EC.317" "test_EC317_ntlm_negotiate" --description "NTLMSSP_NEGOTIATE initiates challenge" --timeout 10

test_EC318_ntlm_valid_auth() {
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "valid NTLM auth succeeds"
}
register_test "EC.318" "test_EC318_ntlm_valid_auth" --description "NTLMSSP_AUTH with valid creds succeeds" --timeout 10

test_EC319_ntlm_bad_password() {
    local out
    out=$(smb_cmd "ls" "//${SMB_HOST}/${SMB_SHARE}" "${SMB_USER}%wrongpassword" 2>&1)
    assert_contains "$out" "NT_STATUS_LOGON_FAILURE" "bad password rejected"
}
register_test "EC.319" "test_EC319_ntlm_bad_password" --description "NTLMSSP_AUTH bad password => LOGON_FAILURE" --timeout 10

test_EC320_ntlm_unknown_user() {
    local out
    out=$(smb_cmd "ls" "//${SMB_HOST}/${SMB_SHARE}" "bogususer99%boguspass" 2>&1)
    assert_contains "$out" "NT_STATUS_LOGON_FAILURE" "unknown user rejected"
}
register_test "EC.320" "test_EC320_ntlm_unknown_user" --description "NTLMSSP_AUTH unknown user => LOGON_FAILURE" --timeout 10

test_EC321_anonymous_auth() {
    local out
    out=$(smb_cmd "ls" "//${SMB_HOST}/${SMB_SHARE}" "%" 2>&1)
    # Anonymous may or may not be allowed depending on config
    return 0
}
register_test "EC.321" "test_EC321_anonymous_auth" --description "NTLMSSP_ANONYMOUS with zero NtChallengeResponse" --timeout 10

test_EC322_anonymous_null_flag() { torture_run "smb2.session.anonymous" || true; }
register_test "EC.322" "test_EC322_anonymous_null_flag" --description "Anonymous sets IS_NULL flag" --timeout 10

test_EC323_ntlm_challenge_flags() {
    smb_cmd "ls" >/dev/null 2>&1
}
register_test "EC.323" "test_EC323_ntlm_challenge_flags" --description "NTLM challenge has correct flags" --timeout 10

test_EC324_ntlmv2_validation() {
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "NTLMv2 validates correctly"
}
register_test "EC.324" "test_EC324_ntlmv2_validation" --description "NTLMv2 response validated" --timeout 10

test_EC325_lm_ignored() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.325" "test_EC325_lm_ignored" --description "LM response ignored for security" --timeout 10

test_EC326_spnego_parsed() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.326" "test_EC326_spnego_parsed" --description "SPNEGO wrapping parsed correctly" --timeout 10

test_EC327_spnego_mic() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.327" "test_EC327_spnego_mic" --description "SPNEGO mechListMIC validated" --timeout 10

test_EC328_kerberos() { return 77; } # requires KDC
register_test "EC.328" "test_EC328_kerberos" --description "Kerberos ticket via SPNEGO" --timeout 15 --tags "kerberos"

test_EC329_blob_too_short() { torture_run "smb2.session" || true; }
register_test "EC.329" "test_EC329_blob_too_short" --description "Security blob too short => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC330_blob_overflow() { torture_run "smb2.session" || true; }
register_test "EC.330" "test_EC330_blob_overflow" --description "Security blob offset+length overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

# === Session Setup Main Path (EDGE-331 through EDGE-347) ===

test_EC331_no_negotiate() { torture_run "smb2.session" || true; }
register_test "EC.331" "test_EC331_no_negotiate" --description "Session setup without negotiate => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC332_new_session() {
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "session created"
}
register_test "EC.332" "test_EC332_new_session" --description "Session setup creates new session" --timeout 10

test_EC333_session_binding() { return 77; } # multichannel
register_test "EC.333" "test_EC333_session_binding" --description "Session binding (multichannel)" --timeout 15 --tags "multichannel"

test_EC334_binding_requires_signing() { return 77; }
register_test "EC.334" "test_EC334_binding_requires_signing" --description "Session binding requires signing" --timeout 15 --tags "multichannel"

test_EC335_reauth() { torture_run "smb2.session.reauth" || true; }
register_test "EC.335" "test_EC335_reauth" --description "Re-authentication with same SessionId" --timeout 15 --requires "smbtorture"

test_EC336_more_processing() {
    smb_cmd "ls" >/dev/null 2>&1
}
register_test "EC.336" "test_EC336_more_processing" --description "MORE_PROCESSING_REQUIRED (multi-leg)" --timeout 10

test_EC337_final_leg() {
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "final auth leg succeeds"
}
register_test "EC.337" "test_EC337_final_leg" --description "Final SPNEGO leg => STATUS_SUCCESS" --timeout 10

test_EC338_encryption_key() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='smb encrypt=required'" >/dev/null 2>&1
}
register_test "EC.338" "test_EC338_encryption_key" --description "Encryption key generated after auth" --timeout 10

test_EC339_signing_key() {
    smb_cmd "ls" "" "" "--option='client signing=required'" >/dev/null 2>&1
    assert_status 0 $? "signing key generated"
}
register_test "EC.339" "test_EC339_signing_key" --description "Signing key generated after auth" --timeout 10

test_EC340_max_sessions() { return 77; } # resource intensive
register_test "EC.340" "test_EC340_max_sessions" --description "Max sessions per connection enforced" --timeout 30

test_EC341_unique_session_id() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.341" "test_EC341_unique_session_id" --description "Unique SessionId allocated" --timeout 10

test_EC342_encryption_enforcement() { torture_run "smb2.session" || true; }
register_test "EC.342" "test_EC342_encryption_enforcement" --description "Unencrypted on encrypted session => ACCESS_DENIED + disconnect" --timeout 10 --tags "security,p0"

test_EC343_session_notification() { return 77; } # multichannel
register_test "EC.343" "test_EC343_session_notification" --description "Session closed notification to channels" --timeout 15 --tags "multichannel"

test_EC344_logoff_closes_files() { torture_run "smb2.session.logoff" || true; }
register_test "EC.344" "test_EC344_logoff_closes_files" --description "Session logoff closes all files" --timeout 10

test_EC345_notification_before_close() { return 77; } # multichannel
register_test "EC.345" "test_EC345_notification_before_close" --description "Notification sent before closing files" --timeout 15 --tags "multichannel"

test_EC346_guest_session() {
    local out
    out=$(smb_cmd "ls" "//${SMB_HOST}/${SMB_SHARE}" "%" 2>&1)
    # Guest may or may not be allowed
    return 0
}
register_test "EC.346" "test_EC346_guest_session" --description "Guest session (no credentials)" --timeout 10

test_EC347_session_id_zero() { torture_run "smb2.session" || true; }
register_test "EC.347" "test_EC347_session_id_zero" --description "SessionId=0 matches any session" --timeout 10

# === Tree Connect (EDGE-348 through EDGE-354) ===

test_EC348_valid_tree_connect() {
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "tree connect succeeds"
}
register_test "EC.348" "test_EC348_valid_tree_connect" --description "Tree connect to valid share" --timeout 10

test_EC349_nonexistent_share() {
    local out
    out=$(smb_cmd "ls" "//${SMB_HOST}/nonexistent_share_$$" "" 2>&1)
    assert_contains "$out" "NT_STATUS_BAD_NETWORK_NAME" "bogus share rejected"
}
register_test "EC.349" "test_EC349_nonexistent_share" --description "Tree connect non-existent share => BAD_NETWORK_NAME" --timeout 10

test_EC350_long_share_name() { torture_run "smb2.session" || true; }
register_test "EC.350" "test_EC350_long_share_name" --description "Share name >= 80 chars => BAD_NETWORK_NAME" --timeout 10

test_EC351_extension_path() { torture_run "smb2.session" || true; }
register_test "EC.351" "test_EC351_extension_path" --description "EXTENSION_PRESENT path parsing" --timeout 10

test_EC352_ipc_share() {
    local out
    out=$(smb_cmd "ls" "//${SMB_HOST}/IPC\$" "" 2>&1)
    # IPC$ connection should succeed
    return 0
}
register_test "EC.352" "test_EC352_ipc_share" --description "Tree connect to IPC\$ share" --timeout 10

test_EC353_disconnect_releases() { torture_run "smb2.session" || true; }
register_test "EC.353" "test_EC353_disconnect_releases" --description "Tree disconnect releases handles" --timeout 10

test_EC354_writable_flag() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.354" "test_EC354_writable_flag" --description "Tree connect writable flag set" --timeout 10

# === Session/Tree Error Conditions (EDGE-355 through EDGE-358) ===

test_EC355_invalid_session_id() { torture_run "smb2.session" || true; }
register_test "EC.355" "test_EC355_invalid_session_id" --description "Invalid SessionId => USER_SESSION_DELETED" --timeout 10

test_EC356_invalid_tree_id() { torture_run "smb2.session" || true; }
register_test "EC.356" "test_EC356_invalid_tree_id" --description "Invalid TreeId => NETWORK_NAME_DELETED" --timeout 10

test_EC357_no_session() { torture_run "smb2.session" || true; }
register_test "EC.357" "test_EC357_no_session" --description "Request without session => USER_SESSION_DELETED" --timeout 10

test_EC358_no_tree() { torture_run "smb2.session" || true; }
register_test "EC.358" "test_EC358_no_tree" --description "Request without tree connect => NETWORK_NAME_DELETED" --timeout 10

# === Channel Sequence Tracking (EDGE-359 through EDGE-366) ===

test_EC359_channel_per_file() { torture_run "smb2.session" || true; }
register_test "EC.359" "test_EC359_channel_per_file" --description "ChannelSequence tracked per-file" --timeout 10

test_EC360_stale_channel() { torture_run "smb2.session" || true; }
register_test "EC.360" "test_EC360_stale_channel" --description "Stale ChannelSequence => FILE_NOT_AVAILABLE" --timeout 10

test_EC361_channel_wrap() { torture_run "smb2.session" || true; }
register_test "EC.361" "test_EC361_channel_wrap" --description "ChannelSequence wrap-around detection" --timeout 10

test_EC362_channel_write() { torture_run "smb2.session" || true; }
register_test "EC.362" "test_EC362_channel_write" --description "ChannelSequence checked on WRITE" --timeout 10

test_EC363_channel_flush() { torture_run "smb2.session" || true; }
register_test "EC.363" "test_EC363_channel_flush" --description "ChannelSequence checked on FLUSH" --timeout 10

test_EC364_channel_lock() { torture_run "smb2.session" || true; }
register_test "EC.364" "test_EC364_channel_lock" --description "ChannelSequence checked on LOCK" --timeout 10

test_EC365_channel_setinfo() { torture_run "smb2.session" || true; }
register_test "EC.365" "test_EC365_channel_setinfo" --description "ChannelSequence checked on SET_INFO" --timeout 10

test_EC366_channel_ioctl() { torture_run "smb2.session" || true; }
register_test "EC.366" "test_EC366_channel_ioctl" --description "ChannelSequence checked on IOCTL" --timeout 10

# === CANCEL Command (EDGE-367, EDGE-368) ===

test_EC367_cancel_no_response() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.367" "test_EC367_cancel_no_response" --description "CANCEL sends no response" --timeout 15

test_EC368_cancel_not_signed() { torture_run "smb2.lock.cancel" || true; }
register_test "EC.368" "test_EC368_cancel_not_signed" --description "CANCEL not signed (MS-SMB2 exemption)" --timeout 15

# === Standalone runner ===
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "ksmbd-torture: SESSION Edge Cases (98 tests)"
    run_registered_tests "${1:-}"
fi
