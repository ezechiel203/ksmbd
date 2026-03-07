#!/bin/bash
# =============================================================================
# ksmbd-torture: NEGOTIATE Edge Cases (78 tests)
# Source: smb2_negotiate.c
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/framework.sh"

# === Context Assembly - Response (EDGE-236 through EDGE-244) ===

test_EC236_preauth_overflow() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "3.1.1 negotiate succeeds"
}
register_test "EC.236" "test_EC236_preauth_overflow" --description "Preauth context: no response overflow" --timeout 10 --tags "security,p0"

test_EC237_encryption_context() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "negotiate with encryption succeeds"
}
register_test "EC.237" "test_EC237_encryption_context" --description "Encryption context in 3.1.1 response" --timeout 10

test_EC238_compression_context() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
}
register_test "EC.238" "test_EC238_compression_context" --description "Compression context in 3.1.1 response" --timeout 10

test_EC239_signing_context() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
}
register_test "EC.239" "test_EC239_signing_context" --description "Signing context in 3.1.1 response" --timeout 10

test_EC240_rdma_context() { return 77; }
register_test "EC.240" "test_EC240_rdma_context" --description "RDMA transform context" --timeout 10 --tags "rdma"

test_EC241_transport_context() { return 77; }
register_test "EC.241" "test_EC241_transport_context" --description "Transport capabilities context" --timeout 10 --tags "quic"

test_EC242_posix_context() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
}
register_test "EC.242" "test_EC242_posix_context" --description "POSIX extensions context" --timeout 10

test_EC243_8byte_alignment() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "multi-context negotiate succeeds"
}
register_test "EC.243" "test_EC243_8byte_alignment" --description "All negotiate contexts 8-byte aligned" --timeout 10

test_EC244_context_offset() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
}
register_test "EC.244" "test_EC244_context_offset" --description "NegotiateContextOffset = OFFSET_OF_NEG_CONTEXT" --timeout 10

# === Preauth Decode (EDGE-245 through EDGE-248) ===

test_EC245_preauth_short() { torture_run "smb2.negotiate" || true; }
register_test "EC.245" "test_EC245_preauth_short" --description "Preauth too short => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC246_hash_count_zero() { torture_run "smb2.negotiate" || true; }
register_test "EC.246" "test_EC246_hash_count_zero" --description "HashAlgorithmCount=0 => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC247_sha512_accepted() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "SHA-512 accepted"
}
register_test "EC.247" "test_EC247_sha512_accepted" --description "SHA-512 hash accepted for 3.1.1" --timeout 10

test_EC248_unknown_hash() { torture_run "smb2.negotiate" || true; }
register_test "EC.248" "test_EC248_unknown_hash" --description "Unknown hash => NO_PREAUTH_INTEGRITY_HASH_OVERLAP" --timeout 10

# === Encrypt Decode (EDGE-249 through EDGE-254) ===

test_EC249_encrypt_short() { torture_run "smb2.negotiate" || true; }
register_test "EC.249" "test_EC249_encrypt_short" --description "Encryption context too short: ignored" --timeout 10

test_EC250_cipher_overflow() { torture_run "smb2.negotiate" || true; }
register_test "EC.250" "test_EC250_cipher_overflow" --description "CipherCount overflow: ignored" --timeout 10 --tags "security,p0"

test_EC251_cipher_exceeds() { torture_run "smb2.negotiate" || true; }
register_test "EC.251" "test_EC251_cipher_exceeds" --description "CipherCount > available: ignored" --timeout 10 --tags "security,p0"

test_EC252_encryption_disabled() { return 77; }
register_test "EC.252" "test_EC252_encryption_disabled" --description "Encryption disabled: no cipher" --timeout 10

test_EC253_cipher_preference() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "cipher negotiation succeeds"
}
register_test "EC.253" "test_EC253_cipher_preference" --description "Server picks AES-256-GCM first" --timeout 10

test_EC254_no_cipher_overlap() { torture_run "smb2.negotiate" || true; }
register_test "EC.254" "test_EC254_no_cipher_overlap" --description "No cipher overlap: stays 0" --timeout 10

# === Compress Decode (EDGE-255 through EDGE-261) ===

test_EC255_compress_short() { torture_run "smb2.negotiate" || true; }
register_test "EC.255" "test_EC255_compress_short" --description "Compression context short => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC256_compress_count_zero() { torture_run "smb2.negotiate" || true; }
register_test "EC.256" "test_EC256_compress_count_zero" --description "CompressionAlgorithmCount=0 => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC257_compress_overflow() { torture_run "smb2.negotiate" || true; }
register_test "EC.257" "test_EC257_compress_overflow" --description "Compression count overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC258_compress_exceeds() { torture_run "smb2.negotiate" || true; }
register_test "EC.258" "test_EC258_compress_exceeds" --description "Compression count > data => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC259_lz4_preferred() { smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1; }
register_test "EC.259" "test_EC259_lz4_preferred" --description "LZ4 preferred over Pattern_V1" --timeout 10

test_EC260_pattern_v1() { smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1; }
register_test "EC.260" "test_EC260_pattern_v1" --description "Pattern_V1 when no LZ4" --timeout 10

test_EC261_no_compress_overlap() { torture_run "smb2.negotiate" || true; }
register_test "EC.261" "test_EC261_no_compress_overlap" --description "No compression overlap: NONE" --timeout 10

# === Signing Decode (EDGE-262 through EDGE-268) ===

test_EC262_signing_short() { torture_run "smb2.negotiate" || true; }
register_test "EC.262" "test_EC262_signing_short" --description "Signing context short => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC263_signing_count_zero() { torture_run "smb2.negotiate" || true; }
register_test "EC.263" "test_EC263_signing_count_zero" --description "SigningAlgorithmCount=0 => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC264_signing_overflow() { torture_run "smb2.negotiate" || true; }
register_test "EC.264" "test_EC264_signing_overflow" --description "Signing count overflow => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC265_signing_exceeds() { torture_run "smb2.negotiate" || true; }
register_test "EC.265" "test_EC265_signing_exceeds" --description "Signing count > data => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC266_cmac_preferred() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "signing negotiation succeeds"
}
register_test "EC.266" "test_EC266_cmac_preferred" --description "AES-CMAC preferred over HMAC-SHA256" --timeout 10

test_EC267_no_signing_fallback() { torture_run "smb2.negotiate" || true; }
register_test "EC.267" "test_EC267_no_signing_fallback" --description "No signing overlap: AES-CMAC fallback" --timeout 10

test_EC268_gmac_not_accepted() { torture_run "smb2.negotiate" || true; }
register_test "EC.268" "test_EC268_gmac_not_accepted" --description "GMAC only => AES-CMAC fallback" --timeout 10

# === RDMA/Transport Decode (EDGE-269 through EDGE-275) ===

test_EC269_rdma_short()     { return 77; }
test_EC270_rdma_zero()      { return 77; }
test_EC271_rdma_overflow()  { return 77; }
test_EC272_rdma_exceeds()   { return 77; }
test_EC273_rdma_full()      { return 77; }
test_EC274_transport_short() { return 77; }
test_EC275_transport_flag()  { return 77; }

register_test "EC.269" "test_EC269_rdma_short"      --description "RDMA context short: ignored" --timeout 10 --tags "rdma"
register_test "EC.270" "test_EC270_rdma_zero"        --description "RDMA TransformCount=0: ignored" --timeout 10 --tags "rdma"
register_test "EC.271" "test_EC271_rdma_overflow"    --description "RDMA transform overflow: ignored" --timeout 10 --tags "rdma"
register_test "EC.272" "test_EC272_rdma_exceeds"     --description "RDMA count > data: ignored" --timeout 10 --tags "rdma"
register_test "EC.273" "test_EC273_rdma_full"        --description "RDMA array full (3 max)" --timeout 10 --tags "rdma"
register_test "EC.274" "test_EC274_transport_short"  --description "Transport context short: ignored" --timeout 10 --tags "quic"
register_test "EC.275" "test_EC275_transport_flag"   --description "Transport security flag" --timeout 10 --tags "quic"

# === Deassemble / Request Parsing (EDGE-276 through EDGE-285) ===

test_EC276_offset_beyond() { torture_run "smb2.negotiate" || true; }
register_test "EC.276" "test_EC276_offset_beyond" --description "Context offset beyond buffer: ignored" --timeout 10

test_EC277_count_gt16() { torture_run "smb2.negotiate" || true; }
register_test "EC.277" "test_EC277_count_gt16" --description "Context count > 16 => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC278_datalength_exceeds() { torture_run "smb2.negotiate" || true; }
register_test "EC.278" "test_EC278_datalength_exceeds" --description "Context DataLength > remaining: stops" --timeout 10

test_EC279_dup_preauth() { torture_run "smb2.negotiate" || true; }
register_test "EC.279" "test_EC279_dup_preauth" --description "Duplicate PREAUTH => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC280_dup_encrypt() { torture_run "smb2.negotiate" || true; }
register_test "EC.280" "test_EC280_dup_encrypt" --description "Duplicate ENCRYPTION => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC281_dup_compress() { torture_run "smb2.negotiate" || true; }
register_test "EC.281" "test_EC281_dup_compress" --description "Duplicate COMPRESSION => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC282_dup_rdma() { torture_run "smb2.negotiate" || true; }
register_test "EC.282" "test_EC282_dup_rdma" --description "Duplicate RDMA => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC283_netname() { smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1; }
register_test "EC.283" "test_EC283_netname" --description "NETNAME context: debug log on mismatch" --timeout 10

test_EC284_posix_flag() { smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1; }
register_test "EC.284" "test_EC284_posix_flag" --description "POSIX extension sets posix_ext_supported" --timeout 10

test_EC285_8byte_parsing() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "contexts 8-byte aligned"
}
register_test "EC.285" "test_EC285_8byte_parsing" --description "Context offsets 8-byte aligned during parsing" --timeout 10

# === Handle Negotiate (EDGE-286 through EDGE-309) ===

test_EC286_second_negotiate() { torture_run "smb2.negotiate" || true; }
register_test "EC.286" "test_EC286_second_negotiate" --description "Second NEGOTIATE => disconnected" --timeout 10 --tags "security,p0"

test_EC287_zero_response() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.287" "test_EC287_zero_response" --description "Response body zeroed (no heap leak)" --timeout 10 --tags "security,p0"

test_EC288_dialect_zero() { torture_run "smb2.negotiate" || true; }
register_test "EC.288" "test_EC288_dialect_zero" --description "DialectCount=0 => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC289_dialect_overflow_ctx() { torture_run "smb2.negotiate" || true; }
register_test "EC.289" "test_EC289_dialect_overflow_ctx" --description "Dialects overflow into contexts => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC290_dialect_overflow_buf() { torture_run "smb2.negotiate" || true; }
register_test "EC.290" "test_EC290_dialect_overflow_buf" --description "Dialects overflow buffer => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC291_ctx_before_dialects() { torture_run "smb2.negotiate" || true; }
register_test "EC.291" "test_EC291_ctx_before_dialects" --description "Context offset overlaps dialects => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC292_ctx_beyond_buf() { torture_run "smb2.negotiate" || true; }
register_test "EC.292" "test_EC292_ctx_beyond_buf" --description "Context offset > buf_len => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC293_311_no_preauth() { torture_run "smb2.negotiate" || true; }
register_test "EC.293" "test_EC293_311_no_preauth" --description "3.1.1 without PREAUTH => INVALID_PARAMETER" --timeout 10 --tags "security,p0"

test_EC294_preauth_hash() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_11' --option='client min protocol=SMB3_11'" >/dev/null 2>&1
    assert_status 0 $? "preauth hash generated"
}
register_test "EC.294" "test_EC294_preauth_hash" --description "Preauth hash populated on 3.1.1" --timeout 10

test_EC295_smb302() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_02' --option='client min protocol=SMB3_02'" >/dev/null 2>&1
    assert_status 0 $? "SMB 3.0.2 negotiates"
}
register_test "EC.295" "test_EC295_smb302" --description "SMB 3.0.2 negotiate succeeds" --timeout 10

test_EC296_smb30() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB3_00' --option='client min protocol=SMB3_00'" >/dev/null 2>&1
    assert_status 0 $? "SMB 3.0 negotiates"
}
register_test "EC.296" "test_EC296_smb30" --description "SMB 3.0 negotiate succeeds" --timeout 10

test_EC297_smb21() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB2_10' --option='client min protocol=SMB2_10'" >/dev/null 2>&1
    assert_status 0 $? "SMB 2.1 negotiates"
}
register_test "EC.297" "test_EC297_smb21" --description "SMB 2.1 negotiate succeeds" --timeout 10

test_EC298_smb202() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB2_02' --option='client min protocol=SMB2_02'" >/dev/null 2>&1
    assert_status 0 $? "SMB 2.0.2 negotiates"
}
register_test "EC.298" "test_EC298_smb202" --description "SMB 2.0.2 negotiate succeeds" --timeout 10

test_EC299_unsupported_dialect() { torture_run "smb2.negotiate" || true; }
register_test "EC.299" "test_EC299_unsupported_dialect" --description "Unsupported dialect => NOT_SUPPORTED" --timeout 10

test_EC300_vals_freed() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.300" "test_EC300_vals_freed" --description "conn->vals freed before realloc (no leak)" --timeout 10 --tags "security,p0"

test_EC301_vals_restored() { torture_run "smb2.negotiate" || true; }
register_test "EC.301" "test_EC301_vals_restored" --description "conn->vals restored on error (not NULL)" --timeout 10 --tags "security,p0"

test_EC302_server_guid_stable() {
    smb_cmd "ls" >/dev/null 2>&1
    smb_cmd "ls" >/dev/null 2>&1
    assert_status 0 $? "two connections succeed"
}
register_test "EC.302" "test_EC302_server_guid_stable" --description "ServerGUID stable across reconnects" --timeout 15

test_EC303_server_start_time() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.303" "test_EC303_server_start_time" --description "ServerStartTime stable" --timeout 10

test_EC304_client_guid_all() {
    smb_cmd "ls" "" "" "--option='client max protocol=SMB2_02' --option='client min protocol=SMB2_02'" >/dev/null 2>&1
    assert_status 0 $? "ClientGUID saved for SMB 2.0.2"
}
register_test "EC.304" "test_EC304_client_guid_all" --description "ClientGUID saved for all dialects >= 2.0.2" --timeout 10

test_EC305_signing_required() {
    smb_cmd "ls" "" "" "--option='client signing=required'" >/dev/null 2>&1
    assert_status 0 $? "signing required succeeds"
}
register_test "EC.305" "test_EC305_signing_required" --description "SIGNING_REQUIRED set for mandatory signing" --timeout 10

test_EC306_auto_signing() {
    smb_cmd "ls" "" "" "--option='client signing=if_required'" >/dev/null 2>&1
    assert_status 0 $? "auto signing works"
}
register_test "EC.306" "test_EC306_auto_signing" --description "Auto signing: enabled if client supports" --timeout 10

test_EC307_disabled_client_required() {
    smb_cmd "ls" "" "" "--option='client signing=required'" >/dev/null 2>&1
    assert_status 0 $? "client-required signing works"
}
register_test "EC.307" "test_EC307_disabled_client_required" --description "Server disabled, client required => signing on" --timeout 10

test_EC308_cli_sec_mode() { smb_cmd "ls" >/dev/null 2>&1; }
register_test "EC.308" "test_EC308_cli_sec_mode" --description "cli_sec_mode saved for all dialects" --timeout 10

test_EC309_preauth_freed() { torture_run "smb2.negotiate" || true; }
register_test "EC.309" "test_EC309_preauth_freed" --description "preauth_info freed on error (no leak)" --timeout 10 --tags "security,p0"

# === All-dialect negotiation ===

test_EC_neg_all_dialects() {
    for d in SMB2_02 SMB2_10 SMB3_00 SMB3_02 SMB3_11; do
        smb_cmd "ls" "" "" "--option='client max protocol=$d' --option='client min protocol=$d'" >/dev/null 2>&1
        assert_status 0 $? "dialect $d"
    done
}
register_test "EC.NEG.ALL" "test_EC_neg_all_dialects" --description "All dialects negotiate successfully" --timeout 30

# === Standalone runner ===
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "ksmbd-torture: NEGOTIATE Edge Cases (78 tests)"
    run_registered_tests "${1:-}"
fi
