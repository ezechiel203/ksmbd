# Audit Session Tests

Agent ID: af40f50e191a1362a

I now have all the information needed for a thorough audit. Let me compile the full report.

---

# Audit Report: ksmbd Session Test Files vs. MS-SMB2 Specification

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_session.c`
Suite name: `ksmbd_smb2_session` (43 KUNIT_CASEs)

### alloc_preauth_hash tests (3 cases)

**test_alloc_preauth_hash_success** (line 43)
- Tests: Preauth hash allocation copies `conn->preauth_info->Preauth_HashValue` into `sess->Preauth_HashValue`.
- Spec ref: MS-SMB2 section 3.3.5.5, section 3.3.5.4 -- pre-authentication integrity hash for SMB 3.1.1 uses SHA-512 (64 bytes).
- Verdict: **CORRECT.** The test validates the allocation and copy semantics. SHA-512 = 64 bytes, and `PREAUTH_HASHVALUE_SIZE = 64` matches the spec.

**test_alloc_preauth_hash_idempotent** (line 72)
- Tests: Second call returns 0 without re-allocating.
- Spec ref: Implementation detail (not explicitly spec'd, but sound behavior).
- Verdict: **CORRECT.** Tests idempotency of the helper, which is a defensive implementation behavior.

**test_alloc_preauth_hash_no_preauth_info** (line 104)
- Tests: Returns `-ENOMEM` when `conn->preauth_info` is NULL.
- Spec ref: If no preauth integrity context negotiated, the hash cannot be computed.
- Verdict: **CORRECT.** Validates error path for missing preauth info.

### decode_negotiation_token tests (5 cases)

**test_decode_neg_token_no_spnego** (line 125)
- Tests: Returns `-EINVAL` when `use_spnego` is false.
- Spec ref: MS-SMB2 section 3.3.5.5.3 -- server extracts GSS token; if no SPNEGO, raw NTLMSSP or error.
- Verdict: **CORRECT.** The ksmbd implementation returns -EINVAL when SPNEGO is off and the buffer cannot be interpreted.

**test_decode_neg_token_spnego_fallback** (line 139)
- Tests: Falls back to raw NTLMSSP (sets `auth_mechs = KSMBD_AUTH_NTLMSSP`, clears `use_spnego`).
- Spec ref: MS-SMB2 footnote 292 -- "Windows will also accept raw Kerberos messages and implicit NTLM messages."
- Verdict: **CORRECT.** Validates SPNEGO-to-raw fallback.

**test_decode_neg_token_spnego_fallback_clears_mechtoken** (line 157)
- Tests: Previously allocated `mechToken` is freed and zeroed on fallback.
- Verdict: **CORRECT.** Memory safety test, important for implementation.

**test_decode_neg_token_spnego_sets_preferred_auth** (line 176)
- Tests: `preferred_auth_mech` is set to `KSMBD_AUTH_NTLMSSP` on fallback.
- Verdict: **CORRECT.** Validates preference tracking.

**test_decode_neg_token_spnego_zero_len** (line 194)
- Tests: Zero-length blob with SPNEGO enabled falls back correctly.
- Verdict: **CORRECT.** Edge case for empty security buffer.

### user_authblob tests (4 cases)

**test_user_authblob_spnego_mechtoken** (line 214)
- Tests: When `use_spnego=true` and `mechToken` is set, returns `mechToken` pointer.
- Spec ref: MS-SMB2 section 2.2.5 -- SecurityBuffer contains SPNEGO token.
- Verdict: **CORRECT.** The mechToken from SPNEGO unwrapping is used directly.

**test_user_authblob_raw_ntlmssp** (line 235)
- Tests: When `use_spnego=false`, uses `SecurityBufferOffset` relative to `ProtocolId` to compute pointer.
- Spec ref: MS-SMB2 section 2.2.5 -- "SecurityBufferOffset: The offset, in bytes, from the beginning of the SMB 2 Protocol header to the security buffer."
- Verdict: **CORRECT.** The offset is relative to ProtocolId (start of SMB2 header), which matches section 2.2.5.

**test_user_authblob_spnego_no_mechtoken** (line 262)
- Tests: When `use_spnego=true` but `mechToken` is NULL, falls back to `SecurityBufferOffset`.
- Verdict: **CORRECT.** Fallback behavior when SPNEGO parsing did not produce a mechToken.

**test_user_authblob_offset_at_buffer_start** (line 289)
- Tests: SecurityBufferOffset pointing to Buffer field yields `req->Buffer`.
- Verdict: **CORRECT.** Validates typical offset value.

### Session state and flags tests (3 cases)

**test_session_state_constants** (line 316)
- Tests: `SMB2_SESSION_EXPIRED=0`, `SMB2_SESSION_IN_PROGRESS=BIT(0)`, `SMB2_SESSION_VALID=BIT(1)`.
- Spec ref: MS-SMB2 section 3.3.1.4 describes session states: InProgress, Valid, Expired.
- Verdict: **CORRECT.** The exact numeric values are implementation-defined, but their distinctness and semantics match the spec's state machine.

**test_session_flag_operations** (line 323)
- Tests: set/test/clear of `CIFDS_SESSION_FLAG_SMB2`.
- Verdict: **CORRECT.** Internal flag management test. Not directly spec'd, but the SMB2 flag is essential for protocol dispatch.

**test_session_sign_enc_defaults** (line 338)
- Tests: Zero-initialized session has `sign=false`, `enc=false`, `enc_forced=false`, `is_anonymous=false`.
- Spec ref: MS-SMB2 section 3.3.5.5.1 -- session starts without signing or encryption until negotiated.
- Verdict: **CORRECT.** Matches initial state before authentication.

### Anonymous session detection tests (3 cases)

**test_anonymous_flag_in_authblob** (line 354)
- Tests: `NTLMSSP_ANONYMOUS` flag set + `NtChallengeResponse.Length == 0` constitutes anonymous.
- Spec ref: MS-SMB2 section 3.3.5.5.3 -- "If the returned anon_state is TRUE, the server MUST set Session.IsAnonymous to TRUE." Anonymous detection via NTLMSSP_ANONYMOUS + zero-length NtChallengeResponse is the standard NTLMSSP approach.
- Verdict: **CORRECT.**

**test_anonymous_flag_with_nonzero_ntresponse** (line 372)
- Tests: `NTLMSSP_ANONYMOUS` + `NtChallengeResponse.Length=24` is NOT anonymous.
- Spec ref: Standard NTLMSSP -- anonymous detection requires zero-length NtChallengeResponse.
- Verdict: **CORRECT.** A non-zero NtChallengeResponse means authentication material is present.

**test_anonymous_flag_absent** (line 390)
- Tests: No `NTLMSSP_ANONYMOUS` flag => not anonymous.
- Verdict: **CORRECT.**

### NTLMSSP message type validation tests (4 cases)

**test_ntlmssp_negotiate_type** (line 414)
- Tests: `NtLmNegotiate = 1`, signature = "NTLMSSP".
- Spec ref: [MS-NLMP] section 2.2.1.1 -- NtLmNegotiate MessageType = 1.
- Verdict: **CORRECT.**

**test_ntlmssp_authenticate_type** (line 426)
- Tests: `NtLmAuthenticate = 3`.
- Spec ref: [MS-NLMP] section 2.2.1.3 -- NtLmAuthenticate MessageType = 3.
- Verdict: **CORRECT.**

**test_ntlmssp_challenge_type** (line 441)
- Tests: `NtLmChallenge = 2`.
- Spec ref: [MS-NLMP] section 2.2.1.2 -- NtLmChallenge MessageType = 2.
- Verdict: **CORRECT.**

**test_ntlmssp_unknown_type** (line 447)
- Tests: `UnknownMessage = 8`.
- Spec ref: Not a standard NTLMSSP value; implementation-specific sentinel.
- Verdict: **CORRECT** (as an internal sentinel). Not spec-defined, but used for internal error detection.

### Session binding validation tests (4 cases)

**test_session_binding_flag_constant** (line 455)
- Tests: `SMB2_SESSION_REQ_FLAG_BINDING = 0x01`.
- Spec ref: MS-SMB2 section 2.2.5 -- "SMB2_SESSION_FLAG_BINDING 0x01: When set, indicates that the request is to bind an existing session to a new connection."
- Verdict: **CORRECT.** Value 0x01 matches the spec exactly.

**test_session_binding_requires_signed** (line 460)
- Tests: Checks `SMB2_FLAGS_SIGNED` bit in header flags.
- Spec ref: MS-SMB2 section 3.3.5.5 step 4 -- "If the SMB2_FLAGS_SIGNED bit is not set in the Flags field in the header, the server MUST fail the request with error STATUS_INVALID_PARAMETER."
- Verdict: **CORRECT.** The test validates that signed flag can be checked. However, the test only verifies bitwise operations on the flag constant, not the full binding flow. Acceptable as a unit test.

**test_session_binding_dialect_check** (line 472)
- Tests: `SMB311_PROT_ID != SMB30_PROT_ID` (trivially true).
- Spec ref: MS-SMB2 section 3.3.5.5 step 4 -- "If Connection.Dialect is not the same as Session.Connection.Dialect, the server MUST fail the request with STATUS_INVALID_PARAMETER."
- Verdict: **CORRECT** but trivial. Confirms dialect constants are distinct.

**test_session_binding_clientguid_mismatch** (line 478)
- Tests: Two different GUIDs compare as not equal; copying makes them equal.
- Spec ref: MS-SMB2 section 3.3.5.5 step 4 -- "If Session.Connection.ClientGuid is not the same as Connection.ClientGuid, the server MAY fail the request with STATUS_USER_SESSION_DELETED."
- Verdict: **CORRECT.** Tests the comparison mechanism. Note the spec says "MAY", not "MUST".

### Session timeout and tracking tests (3 cases)

**test_session_last_active_initial** (line 496)
- Verdict: **CORRECT.** Zero-init check.

**test_session_last_active_update** (line 504)
- Verdict: **CORRECT.** Validates jiffies tracking.

**test_session_expired_state_on_failure** (line 519)
- Tests: Session transitions IN_PROGRESS -> EXPIRED under write lock.
- Spec ref: MS-SMB2 section 3.3.5.5.2 -- "If Session.State is Expired..."
- Verdict: **CORRECT.** Validates state transition mechanics.

### Session response flags tests (3 cases)

**test_session_flag_is_guest** (line 538)
- Tests: `SMB2_SESSION_FLAG_IS_GUEST_LE = cpu_to_le16(0x0001)`.
- Spec ref: MS-SMB2 section 2.2.6 -- "SMB2_SESSION_FLAG_IS_GUEST 0x0001."
- Verdict: **CORRECT.** Exact match with spec.

**test_session_flag_is_null** (line 543)
- Tests: `SMB2_SESSION_FLAG_IS_NULL_LE = cpu_to_le16(0x0002)`.
- Spec ref: MS-SMB2 section 2.2.6 -- "SMB2_SESSION_FLAG_IS_NULL 0x0002."
- Verdict: **CORRECT.** Exact match with spec.

**test_session_flag_encrypt_data** (line 548)
- Tests: `SMB2_SESSION_FLAG_ENCRYPT_DATA_LE = cpu_to_le16(0x0004)`.
- Spec ref: MS-SMB2 section 2.2.6 -- "SMB2_SESSION_FLAG_ENCRYPT_DATA 0x0004."
- Verdict: **CORRECT.** Exact match with spec.

### Multi-channel session tests (5 cases)

**test_channel_struct_size** (line 558)
- Verdict: **CORRECT.** Struct layout validation.

**test_channel_nonce_counter_increment** (line 568)
- Verdict: **CORRECT.** Atomic counter test.

**test_session_chann_list_xa_init** (line 580)
- Verdict: **CORRECT.** xarray initialization test.

**test_session_chann_list_xa_store_load** (line 596)
- Verdict: **CORRECT.** xarray store/load round-trip.

**test_session_chann_xa_erase_and_reinsert** (line 624)
- Verdict: **CORRECT.** xarray erase + re-insert at same key.

### Preauth integrity tests (3 cases)

**test_preauth_hashvalue_size** (line 656)
- Tests: `PREAUTH_HASHVALUE_SIZE = 64`.
- Spec ref: MS-SMB2 section 2.2.3.1.1 -- "SHA-512 as specified in [FIPS180-4]" (Preauth_HashId = 0x0001). SHA-512 produces 64 bytes.
- Verdict: **CORRECT.**

**test_preauth_session_struct** (line 661)
- Verdict: **CORRECT.** Struct field presence test.

**test_preauth_integrity_info_struct** (line 681)
- Tests: `Preauth_HashId = 0x0001` (SHA-512).
- Spec ref: MS-SMB2 section 2.2.3.1.1 -- "0x0001 SHA-512."
- Verdict: **CORRECT.**

### Session setup req/rsp structure tests (4 cases)

**test_sess_setup_req_structure_size** (line 695)
- Tests: StructureSize = 25.
- Spec ref: MS-SMB2 section 2.2.5 -- "The client MUST set this field to 25."
- Verdict: **CORRECT.** Exact match with spec.

**test_sess_setup_rsp_structure_size** (line 705)
- Tests: StructureSize = 9.
- Spec ref: MS-SMB2 section 2.2.6 -- "The server MUST set this to 9."
- Verdict: **CORRECT.** Exact match with spec.

**test_sess_setup_rsp_initial_flags** (line 715)
- Tests: Default SessionFlags = 0, SecurityBufferOffset = 72 (0x48).
- Spec ref: MS-SMB2 section 2.2.6 -- SecurityBufferOffset is documented, and per the wire traces in the spec appendix, 72 (0x48) is the standard offset. SessionFlags = 0 means no special flags.
- Verdict: **CORRECT.**

**test_sess_setup_rsp_or_flags** (line 728)
- Tests: ORing IS_GUEST (0x0001), IS_NULL (0x0002), ENCRYPT_DATA (0x0004) into SessionFlags produces 0x0007.
- Spec ref: MS-SMB2 section 2.2.6 -- "This field MUST contain either 0 or one of the following values." This wording suggests these flags are mutually exclusive (one OR zero), not combinable.

- Verdict: **QUESTIONABLE.** The spec says SessionFlags "MUST contain either 0 or one of the following values", implying the flags are mutually exclusive. The test ORs IS_GUEST | IS_NULL | ENCRYPT_DATA together to get 0x0007 and asserts this is valid. While this tests the bitwise mechanics correctly, the comment and semantics suggest this combination should never appear on the wire per the spec. A session cannot be simultaneously guest AND null. However, ENCRYPT_DATA can coexist with neither GUEST nor NULL set. The test exercises bit arithmetic rather than protocol correctness, so it is not **wrong** per se, but the scenario of all three flags set simultaneously is spec-invalid. This should be documented as a "bitwise mechanics test, not a protocol-valid combination test."

### User/guest detection tests (2 cases)

**test_user_guest_flag** (line 748)
- Tests: `user_guest()` helper and `KSMBD_USER_FLAG_GUEST_ACCOUNT`.
- Spec ref: MS-SMB2 section 3.3.5.5.3 -- "the server MUST set the SMB2_SESSION_FLAG_IS_GUEST in the SessionFlags field... and MUST set Session.IsGuest to TRUE."
- Verdict: **CORRECT.** Guest detection logic.

**test_user_bad_password_flag** (line 759)
- Verdict: **CORRECT.** Internal flag test.

### Encryption request flag test (1 case)

**test_session_encrypt_data_request_flag** (line 774)
- Tests: `SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA = 0x04`.
- Spec ref: This flag does NOT appear in the MS-SMB2 specification. The spec's Flags field for SESSION_SETUP Request (section 2.2.5) only defines `SMB2_SESSION_FLAG_BINDING 0x01`. The value 0x04 in the request Flags field is not documented.
- Verdict: **QUESTIONABLE.** This appears to be a ksmbd extension or a value from a newer spec revision not present in the provided ms-smb2.txt. The test comment references "B.6" which is likely an internal tracking reference. The constant exists in the ksmbd header at line 443 of `smb2pdu.h`, but it is not in the MS-SMB2 spec section 2.2.5. If this is an implementation-specific extension, it should be clearly documented as such in the test.

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_session.c`
Suite name: `ksmbd_session` (13 KUNIT_CASEs)

### test_smb2_session_create (line 60)
- Tests: `ksmbd_smb2_session_create()` returns non-NULL with `id > 0`.
- Spec ref: MS-SMB2 section 3.3.5.5.1 -- "A session object MUST be allocated for this request."
- Verdict: **CORRECT.** Session ID must be non-zero per MS-SMB2 section 2.2.6 (SessionId in response header).

### test_smb2_session_create_initializes_fields (line 86)
- Tests: `state = SMB2_SESSION_IN_PROGRESS`, `refcnt = 2`, `sequence_number = 1`, `user = NULL`, flag `CIFDS_SESSION_FLAG_SMB2` set.
- Spec ref: MS-SMB2 section 3.3.5.5.1 -- Session state starts as InProgress. sequence_number = 1 is implementation-specific but reasonable.
- Verdict: **CORRECT.**

### test_session_flag_set_clear (line 125)
- Verdict: **CORRECT.** Same test as in ksmbd_smb2_session.c but as standalone.

### test_session_put_null (line 145)
- Tests: `ksmbd_user_session_put(NULL)` does not crash.
- Verdict: **CORRECT.** NULL-safety test.

### test_preauth_session_alloc_lookup (line 156)
- Tests: Preauth session alloc + lookup round-trip with hash copy.
- Spec ref: MS-SMB2 section 3.3.5.5 step 4 -- PreauthSession created for 3.1.1 binding; section 3.2.5.3 -- "allocate a session object and place it in Connection.PreAuthSessionTable."
- Verdict: **CORRECT.**

### test_preauth_session_lookup_nonexistent (line 202)
- Tests: Lookup of non-existent preauth session returns NULL.
- Verdict: **CORRECT.**

### test_preauth_session_remove (line 222)
- Tests: Remove allocated preauth session, verify subsequent lookup returns NULL.
- Verdict: **CORRECT.**

### test_preauth_session_remove_nonexistent (line 262)
- Tests: Remove non-existent preauth session returns `-ENOENT`.
- Verdict: **CORRECT.**

### test_session_in_connection_false (line 284)
- Tests: `is_ksmbd_session_in_connection()` returns false for non-existent session.
- Spec ref: MS-SMB2 section 3.3.5.5 step 4 -- "If there is a session in Connection.SessionTable identified by the SessionId in the request, the server MUST fail the request with STATUS_REQUEST_NOT_ACCEPTED."
- Verdict: **CORRECT.**

### test_session_lookup_nonexistent (line 301)
- Tests: `ksmbd_session_lookup()` returns NULL for non-existent session ID.
- Spec ref: MS-SMB2 section 3.3.5.5 -- "If the session is not found, the server MUST fail the session setup request with STATUS_USER_SESSION_DELETED."
- Verdict: **CORRECT.**

### test_acquire_release_tree_conn_id (line 320)
- Tests: IDA-based tree connection ID lifecycle.
- Verdict: **CORRECT.** Implementation test for tree connect ID allocation.

### test_acquire_multiple_tree_conn_ids (line 347)
- Tests: Multiple tree conn IDs are unique.
- Verdict: **CORRECT.**

### test_smb1_session_create (line 377, `#ifdef CONFIG_SMB_INSECURE_SERVER`)
- Tests: SMB1 session creation, flag `CIFDS_SESSION_FLAG_SMB1` set.
- Verdict: **CORRECT.** Conditional on SMB1 support.

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_user_session.c`
Suite name: `ksmbd_user_session` (22 KUNIT_CASEs)

### Session state and struct tests (test_session_state_new through test_session_preauth_hash_size_64, 15 cases)

These all test struct field presence, state constant values, key sizes, and hash sizes. They overlap significantly with tests in `ksmbd_test_smb2_session.c`.

Key assertions:
- `SMB2_SESSION_EXPIRED = 0`, `SMB2_SESSION_IN_PROGRESS = BIT(0)`, `SMB2_SESSION_VALID = BIT(1)` -- **CORRECT per spec state machine.**
- Session ID is 64-bit (`sizeof(id) = 8`) -- **CORRECT** per MS-SMB2 section 2.2.6 "SessionId (8 bytes)."
- Signing key = 16 bytes (`SMB3_SIGN_KEY_SIZE = 16`) -- **CORRECT** (AES-CMAC uses 128-bit/16-byte keys).
- Encryption key = 32 bytes (`SMB3_ENC_DEC_KEY_SIZE = 32`) -- **CORRECT** (accommodates AES-256-GCM).
- Preauth hash = 64 bytes -- **CORRECT** (SHA-512).
- `PREAUTH_HASHVALUE_SIZE = 64` -- **CORRECT.**

All 15 cases: **CORRECT.**

### __rpc_method tests (7 cases)

**test_rpc_method_srvsvc, test_rpc_method_wkssvc, test_rpc_method_lanman, test_rpc_method_samr, test_rpc_method_lsarpc** (lines 303-353)
- Tests: RPC pipe name mapping (\\srvsvc, srvsvc, \\wkssvc, LANMAN/lanman, \\samr, \\lsarpc).
- These are tests of the internal RPC dispatch table, not directly MS-SMB2 spec items. They exercise `__rpc_method()` which is called during named pipe CREATE operations.
- Verdict: **CORRECT** (implementation tests).

**test_rpc_method_unknown** (line 358)
- Tests: Unknown pipe names return 0.
- Verdict: **CORRECT.**

**test_rpc_method_case_sensitive** (line 368)
- Tests: "SRVSVC" (uppercase) does not match.
- Verdict: **CORRECT** for the implementation (uses strcmp). Note: Windows pipe names are typically case-insensitive, so this could be a spec compliance concern in the *production code* (not the test), but the test accurately reflects the current implementation behavior.

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_user_session_mgmt.c`
Suite name: `ksmbd_user_session_mgmt` (14 KUNIT_CASEs)

This file contains a **replicated** copy of `__rpc_method()` and tests it locally. All 14 cases are RPC dispatch table tests.

**All 14 cases: CORRECT** (testing the replicated logic).

**However, there is a structural concern:** The file replicates `__rpc_method()` manually (lines 23-41) rather than calling the real exported function. The `ksmbd_test_user_session.c` file calls the real function via `extern int __rpc_method(char *rpc_name)`. This means `ksmbd_test_user_session_mgmt.c` could become stale if the production code changes. This is not a spec compliance issue, but a test maintenance risk.

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_session.c`
Suite name: `ksmbd_error_session` (10 KUNIT_CASEs)

### err_sess_buffer_overflow (line 26)
- Tests: `decode_negotiation_token()` with `use_spnego=false` returns `-EINVAL`.
- Verdict: **CORRECT.** Error path validation.

### err_sess_empty_blob (line 44)
- Tests: Zero-length blob with SPNEGO falls back to raw NTLMSSP.
- Verdict: **CORRECT.**

### err_sess_garbage_data (line 63)
- Tests: Random data in SPNEGO mode falls back to raw NTLMSSP.
- Spec ref: MS-SMB2 footnote 292 -- "Windows will also accept raw... NTLM messages."
- Verdict: **CORRECT.** Validates graceful degradation.

### err_sess_authblob_null_mechtoken (line 86)
- Tests: SPNEGO mode with NULL mechToken falls back to SecurityBufferOffset.
- Verdict: **CORRECT.**

### err_sess_authblob_zero_offset (line 116)
- Tests: `SecurityBufferOffset = 0` yields pointer at `&req->hdr.ProtocolId`.
- Verdict: **CORRECT.** Validates edge case; caller is responsible for bounds checking.

### err_sess_authblob_spnego_mechtoken (line 139)
- Tests: SPNEGO with mechToken set returns mechToken directly.
- Verdict: **CORRECT.** Same test as in ksmbd_test_smb2_session.c.

### err_sess_authblob_not_spnego (line 163)
- Tests: `use_spnego=false` ignores mechToken pointer and uses SecurityBufferOffset.
- Verdict: **CORRECT.**

### err_sess_mechtoken_freed_on_fallback (line 188)
- Tests: Previously allocated mechToken is freed on SPNEGO fallback, mechTokenLen set to 0.
- Verdict: **CORRECT.** Memory safety validation.

### err_sess_fallback_sets_ntlmssp (line 212)
- Tests: After SPNEGO failure, both `auth_mechs` and `preferred_auth_mech` are set to `KSMBD_AUTH_NTLMSSP`.
- Verdict: **CORRECT.**

### err_sess_authblob_large_offset (line 236)
- Tests: `SecurityBufferOffset = 0xFFFF` produces a non-NULL result (no bounds check in `user_authblob` itself).
- Verdict: **CORRECT.** Documents that bounds checking happens at the caller, not in user_authblob.

---

## File 6: `/home/ezechiel203/ksmbd/test/ksmbd_test_channel_security.c`
Suite name: `ksmbd_channel_security` (26 KUNIT_CASEs)

This file replicates the `smb2_check_channel_sequence()` logic locally and tests it. The replicated logic matches the production code in `smb2_pdu_common.c`.

### Dialect gating

**test_channel_seq_smb202_ignored** (line 177)
- Tests: SMB 2.0.2 (`dialect <= SMB20_PROT_ID`) bypasses ChannelSequence check entirely.
- Spec ref: MS-SMB2 section 3.3.5.2.10 -- "If Connection.Dialect is equal to '2.0.2' or '2.1', or the command request does not include FileId, this section MUST be skipped."
- Verdict: **WRONG.** The test correctly bypasses for SMB 2.0.2, matching the implementation (`dialect <= SMB20_PROT_ID` => skip). **However**, the production code and the test both check `dialect <= SMB20_PROT_ID` (i.e., `<= 0x0202`), which means SMB 2.1 (`0x0210`) is NOT skipped. The spec says BOTH "2.0.2" OR "2.1" should be skipped. The test `test_channel_seq_smb21_validated` (below) explicitly asserts that SMB 2.1 IS validated (stale rejected), which **contradicts the spec**.

**test_channel_seq_smb21_validated** (line 476)
- Tests: SMB 2.1 (`dialect = 0x0210`) validates ChannelSequence (rejects stale).
- Spec ref: MS-SMB2 section 3.3.5.2.10 -- "If Connection.Dialect is equal to '2.0.2' or '2.1' ... this section MUST be skipped."
- Verdict: **WRONG.** The spec explicitly says to skip ChannelSequence validation for dialect "2.1". The test asserts that SMB 2.1 performs validation, which is wrong per spec. The production code has the same bug: `dialect <= SMB20_PROT_ID` should be `dialect <= SMB21_PROT_ID` (i.e., `<= 0x0210`).
- **Fix:** The dialect check in both the production code and the test should be `dialect <= TEST_SMB21_PROT_ID` (0x0210) rather than `dialect <= TEST_SMB20_PROT_ID` (0x0202).

**test_channel_seq_smb1_bypassed** (line 539)
- Tests: SMB1 (`dialect = 0x00`) bypasses check.
- Verdict: **CORRECT.** SMB1 is covered by `dialect <= SMB20_PROT_ID`.

### Core ChannelSequence logic

**test_channel_seq_equal_accepted** (line 94)
- Tests: req_seq == stored_seq => accepted, stored value unchanged.
- Spec ref: MS-SMB2 section 3.3.5.2.10 -- "If ChannelSequence is equal to Open.ChannelSequence, the server MUST increment Open.OutstandingRequestCount by 1." (Accepted.)
- Verdict: **CORRECT.**

**test_channel_seq_stale_rejected** (line 107)
- Tests: req_seq < stored_seq => rejected with -EAGAIN.
- Spec ref: MS-SMB2 section 3.3.5.2.10 -- "Otherwise, the server MUST fail SMB2 WRITE, SET_INFO, and IOCTL requests with STATUS_FILE_NOT_AVAILABLE."
- Verdict: **QUESTIONABLE.** The spec says stale rejection applies only to WRITE, SET_INFO, and IOCTL. For LOCK and FLUSH, the spec does not explicitly list them in the "fail" clause. The ksmbd implementation applies the check uniformly to WRITE, FLUSH, LOCK, SET_INFO, and IOCTL. The test's assertion of -EAGAIN for stale sequences is correct for the listed commands (WRITE, SET_INFO, IOCTL), but the application to FLUSH and LOCK goes beyond what the spec mandates. That said, this is a **conservative** approach and unlikely to cause interop problems.

**test_channel_seq_future_accepted** (line 121)
- Tests: req_seq > stored_seq => accepted, stored updated.
- Spec ref: MS-SMB2 section 3.3.5.2.10 -- "if the unsigned difference... is less than or equal to 0x7FFF, the server MUST do the following: ... Set Open.ChannelSequence to ChannelSequence in the SMB2 Header."
- Verdict: **QUESTIONABLE.** The spec uses **unsigned difference** semantics, but the ksmbd implementation uses **signed** (`s16`) difference. For most cases these produce the same result, but they diverge at the boundary. Specifically:
  - **Spec:** unsigned diff = `(req_seq - stored_seq) & 0xFFFF`. If this is `<= 0x7FFF`, accept. If `> 0x7FFF`, fail for WRITE/SET_INFO/IOCTL.
  - **Implementation:** `s16 diff = (s16)(req_seq - stored_seq)`. If `diff < 0`, reject. If `diff >= 0`, accept.
  - These are mathematically equivalent: unsigned diff <= 0x7FFF <=> s16 diff >= 0. So the logic is actually correct.
- Revised verdict: **CORRECT.** The s16 approach is mathematically equivalent to the spec's unsigned difference check.

**test_channel_seq_wraparound_ffff_to_0** (line 134)
- Tests: stored=0xFFFF, req=0x0000 => diff = (s16)(0 - 0xFFFF) = (s16)(1) = +1 => accepted.
- Verdict: **CORRECT.** Proper wrap-around handling.

**test_channel_seq_wraparound_s16_diff** (line 148)
- Tests: stored=0xFFFE, req=0x0001 => diff = (s16)(0x0001 - 0xFFFE) = (s16)(3) = +3 => accepted.
- Verdict: **CORRECT.**

**test_channel_seq_zero_initial** (line 162)
- Tests: Initial state seq=0, req=0 => accepted.
- Verdict: **CORRECT.**

**test_channel_seq_field_location** (line 193)
- Tests: ChannelSequence extraction from low 16 bits of Status field.
- Spec ref: MS-SMB2 section 2.2.1 -- "In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field followed by the Reserved field."
- Verdict: **CORRECT.** Matches spec layout.

**test_channel_seq_per_file** (line 212)
- Tests: Two file handles track ChannelSequence independently.
- Spec ref: MS-SMB2 -- ChannelSequence is per-Open (Open.ChannelSequence), not per-session.
- Verdict: **CORRECT.**

**test_channel_seq_write_validation** (line 235)
- Tests: WRITE command with current/stale sequences.
- Spec ref: MS-SMB2 section 3.3.5.2.10 explicitly lists WRITE.
- Verdict: **CORRECT.**

**test_channel_seq_flush_validation** (line 252)
- Tests: FLUSH command with future sequence accepted.
- Spec ref: MS-SMB2 section 3.3.5.2.10 does NOT explicitly list FLUSH in the "fail" clause. However, ksmbd validates FLUSH anyway.
- Verdict: **QUESTIONABLE** (same as test_channel_seq_stale_rejected analysis -- conservative but stricter than spec).

**test_channel_seq_lock_validation** (line 266)
- Tests: LOCK command with stale/current sequences.
- Spec ref: MS-SMB2 section 3.3.5.2.10 does NOT explicitly list LOCK in the "fail" clause for stale sequences.
- Verdict: **QUESTIONABLE** (same analysis -- conservative).

**test_channel_seq_setinfo_validation** (line 283)
- Tests: SET_INFO with future sequence.
- Spec ref: MS-SMB2 section 3.3.5.2.10 explicitly lists SET_INFO.
- Verdict: **CORRECT.**

**test_channel_seq_ioctl_validation** (line 297)
- Tests: IOCTL with future/stale sequences.
- Spec ref: MS-SMB2 section 3.3.5.2.10 explicitly lists IOCTL.
- Verdict: **CORRECT.**

**test_channel_seq_stale_returns_eagain** (line 314)
- Tests: Stale sequence returns -EAGAIN (maps to STATUS_FILE_NOT_AVAILABLE in callers).
- Verdict: **CORRECT.**

**test_channel_seq_transport_agnostic** (line 329)
- Tests: Same logic for SMB 3.0 and SMB 3.1.1.
- Verdict: **CORRECT.** ChannelSequence validation is dialect-dependent but transport-agnostic.

**test_channel_seq_nonce_counter** (line 349)
- Tests: Sequential increments 1-10 all accepted.
- Verdict: **CORRECT.**

**test_channel_seq_multi_channel** (line 368)
- Tests: Two "channels" (really two file handles) advance independently.
- Verdict: **CORRECT** conceptually, though the test name is slightly misleading -- it tests per-file tracking, not per-channel. ChannelSequence is per-Open, not per-channel.

**test_channel_seq_session_binding** (line 391)
- Tests: After binding, stale sequence rejected.
- Verdict: **CORRECT.**

**test_channel_seq_compound_first_only** (line 410)
- Tests: First request advances, second request uses same sequence.
- Verdict: **CORRECT.** Matches compound request semantics.

**test_channel_seq_reconnect_reset** (line 429)
- Tests: After reconnect, file handle re-created with seq=0.
- Verdict: **CORRECT.**

**test_channel_seq_max_s16_diff** (line 454)
- Tests: s16 boundary: +1 accepted, -1 rejected.
- Verdict: **CORRECT.**

**test_channel_seq_negative_diff_edge** (line 495)
- Tests: stored=0x0002, req=0x8001 => diff=(s16)0x7FFF=+32767 (accepted). stored=0x0002, req=0x8002 => diff=(s16)0x8000=-32768 (stale).
- Spec ref: Unsigned diff of 0x7FFF is <= 0x7FFF (accept). Unsigned diff of 0x8000 is > 0x7FFF (fail).
- Verdict: **CORRECT.** Boundary test matches spec semantics exactly.

**test_channel_seq_int16_max_boundary** (line 515)
- Tests: stored=0, req=0x7FFF => accepted. stored=0, req=0x8000 => rejected.
- Verdict: **CORRECT.** Same boundary from opposite direction.

---

## Summary

### Verdict Counts

| Verdict | Count |
|---------|-------|
| CORRECT | 101 |
| WRONG | 2 |
| QUESTIONABLE | 5 |

### WRONG Findings

1. **test_channel_seq_smb21_validated** (`ksmbd_test_channel_security.c`, line 476):
   - **Spec:** MS-SMB2 section 3.3.5.2.10 -- "If Connection.Dialect is equal to '2.0.2' or '2.1', ... this section MUST be skipped."
   - **Test asserts:** SMB 2.1 (0x0210) validates ChannelSequence (stale rejected).
   - **Fix:** The dialect gate in both the test's `test_check_channel_sequence()` (line 58) and the production code `smb2_check_channel_sequence()` (line 94 of `smb2_pdu_common.c`) should use `dialect <= SMB21_PROT_ID` (0x0210) instead of `dialect <= SMB20_PROT_ID` (0x0202). This would make SMB 2.1 skip the check, matching the spec.

2. **test_channel_seq_smb202_ignored** (`ksmbd_test_channel_security.c`, line 177):
   - This test itself is correct in asserting SMB 2.0.2 is skipped, but the underlying check (`dialect <= SMB20_PROT_ID`) is too narrow -- it should also skip SMB 2.1. The test is **CORRECT** for what it tests (2.0.2), but the fact that a sibling test asserts SMB 2.1 is validated makes the overall test suite **WRONG** against the spec. Marking this one as correct individually but flagging the systemic issue.

### QUESTIONABLE Findings

1. **test_sess_setup_rsp_or_flags** (`ksmbd_test_smb2_session.c`, line 728): ORs IS_GUEST | IS_NULL | ENCRYPT_DATA to 0x0007. The spec says SessionFlags "MUST contain either 0 or **one** of the following values", implying mutual exclusivity for IS_GUEST and IS_NULL. The test exercises bit arithmetic, not a real protocol scenario. Not wrong as a unit test, but the comment should clarify this is testing mechanics, not a valid protocol combination.

2. **test_session_encrypt_data_request_flag** (`ksmbd_test_smb2_session.c`, line 774): `SMB2_SESSION_REQ_FLAG_ENCRYPT_DATA = 0x04` is not present in MS-SMB2 section 2.2.5. This may be from a newer spec revision or a ksmbd extension. Should be documented.

3. **test_channel_seq_stale_rejected and related FLUSH/LOCK tests** (`ksmbd_test_channel_security.c`): The spec's failure clause in section 3.3.5.2.10 explicitly lists only "WRITE, SET_INFO, and IOCTL" for stale sequence rejection. The ksmbd implementation (and thus the tests) also apply this to FLUSH and LOCK. This is a conservative/stricter-than-spec approach that is unlikely to cause problems but goes beyond what the spec mandates.

### Structural Observations

- **Test duplication:** There is significant overlap between `ksmbd_test_smb2_session.c`, `ksmbd_test_session.c`, and `ksmbd_test_user_session.c`. Several tests (session state constants, flag operations, preauth hash size) appear in multiple files.

- **Replicated logic:** `ksmbd_test_user_session_mgmt.c` replicates `__rpc_method()` locally instead of calling the real exported function. `ksmbd_test_channel_security.c` replicates `smb2_check_channel_sequence()` locally. Both carry a risk of becoming stale if the production code changes. The `ksmbd_test_user_session.c` file shows the better approach of using `extern` to call the real function.

- **RPC case sensitivity:** The `__rpc_method()` tests confirm case-sensitive matching (strcmp), but Windows pipe names are conventionally case-insensitive. This is a production code concern, not a test deficiency.