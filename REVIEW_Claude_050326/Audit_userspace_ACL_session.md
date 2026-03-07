# Audit Userspace Acl Session

Agent ID: a8e5ec6a52b0faea2

Now I have enough information for the full audit. Let me compile the comprehensive report.

---

## COMPREHENSIVE AUDIT REPORT: ksmbd-tools Userspace Test Files

### File 1: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_smbacl.c`

**17 test cases audited.**

#### SID Structure Constants

| Item | Test Value | Spec Value | Verdict |
|------|-----------|------------|---------|
| `SID_MAX_SUB_AUTHORITIES` | 15 | MS-DTYP 2.4.2: SubAuthorityCount is UCHAR with max value 15 | **CORRECT** |
| `NUM_AUTHS` | 6 | MS-DTYP 2.4.2: IdentifierAuthority is 6 bytes | **CORRECT** |
| SID Revision | 1 | MS-DTYP 2.4.2: Revision must be 1 (SID_REVISION) | **CORRECT** |

#### Test-by-test audit:

1. **test_copy_sid_basic** -- Copies SID {rev=1, num_subauth=2, authority[5]=5, sub_auth=[21,42]}. The SID S-1-5-21-42 is a valid structure. **CORRECT.**

2. **test_copy_sid_max_subauth** -- Uses `SID_MAX_SUB_AUTHORITIES - 1` = 14 sub-authorities. Per MS-DTYP 2.4.2, SubAuthorityCount can range 0..15. Using 14 is within bounds. **CORRECT.**

3. **test_copy_sid_overflow_guard** -- Tests `num_subauth = SID_MAX_SUB_AUTHORITIES + 1` = 16. Expects copy to be rejected (dst unchanged). This matches `smb_copy_sid()` which checks `src->num_subauth > SID_MAX_SUB_AUTHORITIES`. **CORRECT.**

4. **test_compare_sids_equal** -- Two identical SIDs compare equal (return 0). **CORRECT.**

5. **test_compare_sids_null_left** -- NULL left operand returns 1. This is a defensive check, not spec-mandated. **CORRECT** (valid defensive behavior).

6. **test_compare_sids_null_right** -- NULL right operand returns 1. **CORRECT.**

7. **test_compare_sids_revision_greater** -- rev=2 > rev=1 returns 1. **CORRECT** per the implementation's comparison ordering.

8. **test_compare_sids_revision_less** -- rev=1 < rev=2 returns -1. **CORRECT.**

9. **test_compare_sids_authority_diff** -- authority[5]=5 vs authority[5]=22, expects -1 since 5 < 22. **CORRECT.**

10. **test_compare_sids_subauth_diff** -- sub_auth[0]=100 vs sub_auth[0]=50, expects 1 since 100 > 50. **CORRECT.**

11. **test_compare_sids_different_count** -- SID with num_subauth=2 vs num_subauth=1, same first subauth. Expects 0. **QUESTIONABLE.** Per MS-DTYP 2.4.2, SIDs with different numbers of sub-authorities are structurally different SIDs. For example, S-1-5-21 and S-1-5-21-1000 are different SIDs. The `smb_compare_sids()` implementation compares only up to `min(num_subauth)` and returns 0 if those match, which means S-1-5-21-1000 would compare equal to S-1-5-21-1000-500. The test correctly documents this implementation behavior, but the implementation itself is semantically questionable for SID equality. However, the test accurately reflects the actual code behavior, and this comparison function is used specifically for prefix-matching in the ksmbd codebase (comparing a SID against a domain SID prefix). **The test is CORRECT for the implementation**, though the comment could be clearer.

12. **test_write_read_sid_roundtrip** -- Write and read back SID {rev=1, num_subauth=3, auth=5, sub=[21,1000,2000]}. Verifies NDR serialization round-trip. **CORRECT.**

13. **test_read_sid_zero_subauth** -- Expects `smb_read_sid()` to reject num_subauth=0 with -EINVAL. Per the source code: `if (!sid->num_subauth || sid->num_subauth >= SID_MAX_SUB_AUTHORITIES) return -EINVAL`. **QUESTIONABLE.** MS-DTYP 2.4.2 allows SubAuthorityCount to be 0 (e.g., S-1-5 is a valid SID with 0 sub-authorities -- the NT Authority SID). The implementation rejects it, and the test reflects that. The test correctly documents the implementation, but the implementation is stricter than the spec.

14. **test_read_sid_max_subauth_exceeded** -- Writes num_subauth=15 (=SID_MAX_SUB_AUTHORITIES), expects -EINVAL. The source uses `>=` check: `num_subauth >= SID_MAX_SUB_AUTHORITIES` (i.e., rejects >= 15). **QUESTIONABLE.** MS-DTYP 2.4.2 says the max is 15. The implementation rejects 15 itself, only allowing 1-14. This means the implementation cannot represent SIDs with exactly 15 sub-authorities. However, the sub_auth array has `SID_MAX_SUB_AUTHORITIES` (15) elements, so 15 would fit in the struct. The `>=` check is overly restrictive vs. the spec which allows 15. **The test correctly documents the implementation behavior, but the implementation disagrees with the spec.**

15. **test_write_sid_overflow** -- 4-byte buffer, expects -ENOMEM on write. **CORRECT** (buffer overflow protection test).

16. **test_init_domain_sid** -- Verifies `smb_init_domain_sid()` produces SID with rev=1, num_subauth=4, authority[5]=5, sub_auth[0]=21, sub_auth[1..3] from global_conf.gen_subauth[0..2]. This produces S-1-5-21-X-Y-Z. Per MS-DTYP, domain SIDs follow the pattern S-1-5-21-{machine-specific}. **CORRECT.**

17. **test_build_sec_desc** -- Verifies build_sec_desc returns 0 with secdesclen > 0 for uid=1000. **CORRECT** (functional test).

#### Well-known SIDs:

18. **test_set_domain_name_unix_users** -- Tests SID {rev=1, num_subauth=1, authority[5]=22, sub_auth[0]=1} = S-1-22-1. Expects domain "Unix User" and type SMB_SID_TYPE_USER(=1). Per Samba/POSIX mapping convention, S-1-22-1-{uid} maps Unix users and S-1-22-2-{gid} maps Unix groups. These are non-Microsoft SIDs defined by Samba. **CORRECT** (matches the Samba convention and the ksmbd implementation at smbacl.c:21-23).

19. **test_set_domain_name_unix_groups** -- Tests SID S-1-22-2. Expects domain "Unix Group" and type SMB_SID_TYPE_GROUP(=2). **CORRECT** (matches smbacl.c:25-27).

---

### File 2: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_session_tree.c`

**~40+ test cases audited.** This file tests the userspace management layer (session/tree connect management). The tests are not directly protocol-level (they test the daemon's internal management structures), but they exercise IPC handling paths per MS-SMB2 3.3.5.5 (Session Setup) and 3.3.5.7 (Tree Connect).

Key findings:

1. **Session capacity management** (tests 1-8): Tests session counting, capacity exhaustion, and boundary conditions. These are implementation-level tests, not directly spec-constrained. All tests accurately reflect the session manager's behavior. **CORRECT.**

2. **Tree connect/disconnect** (tests 9-17): Tests basic tree connect lifecycle, multiple trees per session, large session IDs (0xFFFFFFFFFFFFFFFF), zero session ID. Per MS-SMB2 2.2.9, TreeId is 4 bytes and SessionId is 8 bytes, so the large values tested are within spec bounds. **CORRECT.**

3. **Tree disconnect edge cases** (tests 18-22): Tests disconnecting nonexistent trees, double disconnects, middle tree removal. These test implementation robustness. **CORRECT.**

4. **Multiple sessions** (tests 23-24): Different users on different sessions, same user on multiple sessions. Per MS-SMB2 3.3.5.5, a server can have multiple sessions. **CORRECT.**

5. **Session capacity reclaim** (tests 25-27): Tests that capacity is reclaimed when sessions are destroyed. **CORRECT** (implementation-level).

6. **Tree connection flags** (tests 28-31): Tests KSMBD_TREE_CONN_FLAG_WRITABLE, READ_ONLY, GUEST_ACCOUNT, ADMIN_ACCOUNT, UPDATE. These flags are ksmbd-specific IPC flags, not directly from MS-SMB2. **CORRECT.**

7. **tcm_handle_tree_connect** (tests 33-44): Tests the full tree connect path including share lookup, user lookup, guest account handling, password validation, session exhaustion, restrict_anon, and unterminated string rejection. The `KSMBD_USER_FLAG_BAD_PASSWORD` with `map_to_guest=NEVER` correctly rejects per ksmbd's mapping logic. **CORRECT.**

8. **Input validation** (tests 40-42): Tests unterminated share name, account name, and peer_addr strings. These are security hardening tests. **CORRECT.**

**Overall: All tests CORRECT for the management layer they test.**

---

### File 3: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_spnego.c`

**~55 test cases audited.**

#### OID Constants Verification:

| OID | Test Value | Spec/Standard Value | Verdict |
|-----|-----------|---------------------|---------|
| SPNEGO | {1,3,6,1,5,5,2} (len=7) | RFC 4178 / RFC 2478: 1.3.6.1.5.5.2 (iso.org.dod.internet.security.mechanisms.ssspnego) | **CORRECT** |
| KRB5 | {1,2,840,113554,1,2,2} (len=7) | RFC 4121 / RFC 1964: 1.2.840.113554.1.2.2 | **CORRECT** |
| MSKRB5 | {1,2,840,48018,1,2,2} (len=7) | Microsoft Kerberos OID (MS-KILE): 1.2.840.48018.1.2.2 | **CORRECT** |
| NTLMSSP | {1,3,6,1,4,1,311,2,2,10} (len=10) | MS-NLMP: 1.3.6.1.4.1.311.2.2.10 (iso.org.dod.internet.private.enterprises.microsoft.security.ntlmssp.10) | **CORRECT** |
| KRB5U2U | {1,2,840,113554,1,2,2,3} (len=8) | RFC 4178 User-to-User: 1.2.840.113554.1.2.2.3 | **CORRECT** |

#### ASN.1 DER encoding in OID tests:

1. **test_oid_decode_krb5** -- DER bytes `{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}`:
   - 0x2A = 40*1 + 2 = 42 (first two arcs 1.2) **CORRECT**
   - 0x86 0x48 = 840: (0x86 & 0x7F) << 7 | 0x48 = 6<<7 | 72 = 840 **CORRECT**
   - 0x86 0xF7 0x12 = 113554: (6<<14) | (0x77<<7) | 0x12 = 98304 + 15232 + 18 = 113554 **CORRECT**
   - 0x01, 0x02, 0x02 = 1, 2, 2 **CORRECT**

2. **test_oid_decode_spnego** -- DER bytes `{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}`:
   - 0x2B = 40*1 + 3 = 43 (arcs 1.3) **CORRECT**
   - 0x06 = 6, 0x01 = 1, 0x05 = 5, 0x05 = 5, 0x02 = 2 **CORRECT**

#### SPNEGO Token Structure Tests:

3. **test_encode_negTokenTarg_krb5** -- Verifies outer tag is `CTX CON [1]` (0xA1). Per RFC 4178 / RFC 2478, negTokenResp (negTokenTarg in older spec) uses context tag [1]. **CORRECT.**

4. **test_encode_negTokenTarg_roundtrip_structure** -- Full structural walk-through:
   - Layer 1: CTX CON [1] (negTokenTarg wrapper) **CORRECT per RFC 4178 1.1/2.2.2**
   - Layer 2: SEQUENCE **CORRECT**
   - Layer 3a: CTX CON [0] / ENUMERATED (negResult=0, accept-completed) **CORRECT per RFC 4178 4.2.2**
   - Layer 3b: CTX CON [1] / OID (supportedMech) **CORRECT**
   - Layer 3c: CTX CON [2] / OCTET STRING (responseToken) **CORRECT**

5. **test_decode_negTokenInit_valid_krb5** -- Builds a valid SPNEGO negTokenInit:
   - APPLICATION [0] CON (GSSAPI wrapper) **CORRECT per RFC 2743**
   - OID 1.3.6.1.5.5.2 (SPNEGO) **CORRECT**
   - CTX [0] CON (negTokenInit) **CORRECT per RFC 4178 4.2.1**
   - SEQUENCE / CTX [0] / SEQUENCE (mechTypes) **CORRECT**
   - CTX [2] / OCTET STRING (mechToken) **CORRECT**
   - APPLICATION [0] CON / OID KRB5 / {01 00} (AP_REQ id) **CORRECT per RFC 1964 1.1.1**

6. **test_compare_oid_**** (6 tests) -- All compare logic tests are consistent with the implementation. **CORRECT.**

7. **test_is_supported_mech_**** (5 tests) -- Tests that KRB5 and MSKRB5 are supported; NTLMSSP and SPNEGO are not (NTLMSSP is handled separately in ksmbd; SPNEGO is a wrapping mechanism, not a security mechanism). **CORRECT.**

8. **test_decode_asn1_hdr_**** (8 tests) -- Various ASN.1 header decode/mismatch tests. All expected tag/class values match X.680/X.690 (ASN.1 BER/DER). **CORRECT.**

9. **test_parse_service_**** (9 tests) -- Kerberos service principal name parsing. Tests null input, name-only, name+host, name+host+realm, non-FQDN rejection, empty service, multiple slashes. **CORRECT** (these are Kerberos-convention tests, not SMB spec tests).

10. **test_sigaction_**** (10 tests) -- Signal handler logic tests. Not spec-related, but functionally correct. **CORRECT.**

11. **test_mountd_**** (6 tests) -- mountd argument parsing and config defaults. **CORRECT.**

12. **test_spnego_mech_enum_values** -- MSKRB5=0, KRB5=1, MAX=2. **CORRECT** per the local enum ordering.

---

### File 4: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_ipc_handlers.c`

**8 test cases audited.**

1. **test_login_valid_user** -- Adds user "validuser" with base64 password "cGFzcw==" (decodes to "pass"). Sends login request, expects `KSMBD_USER_FLAG_OK`. The base64 encoding is correct: base64("pass") = "cGFzcw==". **CORRECT.**

2. **test_login_unknown_user** -- Login for "unknownuser" expects either `KSMBD_USER_FLAG_BAD_USER` or error return. **CORRECT.**

3. **test_session_capacity** -- Fresh state with sessions_cap=1024, capacity check returns 0. **CORRECT.**

4. **test_tree_connect_lifecycle** -- Basic tree connect/disconnect cycle. **CORRECT.**

5. **test_share_config_payload_size** -- Creates share "payloadtest" at "/tmp/payloadtest", verifies payload size > 0. **CORRECT.**

6. **test_shm_open_close_connection** -- Open and close share connection. **CORRECT.**

7. **test_share_lookup_nonexistent** -- Lookup "nonexistent_share" returns NULL. **CORRECT.**

8. **test_multiple_sessions** -- Two sessions with same user, different session IDs. **CORRECT.**

---

### File 5: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_ipc_request_validation.c`

**4 test cases audited.**

1. **test_login_rejects_unterminated_account** -- Fills `req.account` entirely with 'A' (no NUL terminator). Expects -EINVAL and `KSMBD_USER_FLAG_INVALID`. This is a security hardening test. **CORRECT.**

2. **test_login_ext_rejects_unterminated_account** -- Same for extended login request. Expects -EINVAL and ngroups=0. **CORRECT.**

3. **test_logout_rejects_unterminated_account** -- Unterminated account in logout. **CORRECT.**

4. **test_tree_connect_rejects_unterminated_strings** -- All three strings (account, share, peer_addr) unterminated. Expects -EINVAL and `KSMBD_TREE_CONN_STATUS_ERROR`. Also verifies sessions_cap is not decremented. **CORRECT.**

---

### File 6: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_worker_ipc.c`

**~60+ test cases audited.** This file tests IPC message allocation, boundary conditions, event type constants, struct sizes, and worker pool lifecycle.

#### IPC Constants:

| Constant | Test Value | Verdict |
|----------|-----------|---------|
| `KSMBD_IPC_MAX_MESSAGE_SIZE` | 4096 | **CORRECT** (per ksmbd_server.h) |
| `KSMBD_IPC_SO_RCVBUF_SIZE` | 1*1024*1024 (1MB) | **CORRECT** |
| `KSMBD_GENL_NAME` | "SMBD_GENL" | **CORRECT** |
| `KSMBD_GENL_VERSION` | 0x01 | **CORRECT** |
| `KSMBD_REQ_MAX_ACCOUNT_NAME_SZ` | 256 | **CORRECT** |
| `KSMBD_REQ_MAX_HASH_SZ` | 18 | **CORRECT** |
| `KSMBD_REQ_MAX_SHARE_NAME` | 64 | **CORRECT** |

#### Event Type Constants:

| Event | Test Value | Verdict |
|-------|-----------|---------|
| `KSMBD_EVENT_UNSPEC` | 0 | **CORRECT** |
| `KSMBD_EVENT_HEARTBEAT_REQUEST` | 1 | **CORRECT** |
| `KSMBD_EVENT_STARTING_UP` | 2 | **CORRECT** |
| `KSMBD_EVENT_SHUTTING_DOWN` | 3 | **CORRECT** |
| `KSMBD_EVENT_LOGIN_REQUEST` | 4 | **CORRECT** |
| `KSMBD_EVENT_LOGIN_RESPONSE` | 5 | **CORRECT** |
| `KSMBD_EVENT_SHARE_CONFIG_REQUEST` | 6 | **CORRECT** |
| `KSMBD_EVENT_SHARE_CONFIG_RESPONSE` | 7 | **CORRECT** |
| `KSMBD_EVENT_TREE_CONNECT_REQUEST` | 8 | **CORRECT** |
| `KSMBD_EVENT_TREE_CONNECT_RESPONSE` | 9 | **CORRECT** |
| `KSMBD_EVENT_TREE_DISCONNECT_REQUEST` | 10 | **CORRECT** |
| `KSMBD_EVENT_LOGOUT_REQUEST` | 11 | **CORRECT** |
| `KSMBD_EVENT_RPC_REQUEST` | 12 | **CORRECT** |
| `KSMBD_EVENT_RPC_RESPONSE` | 13 | **CORRECT** |
| `KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST` | 14 | **CORRECT** |
| `KSMBD_EVENT_SPNEGO_AUTHEN_RESPONSE` | 15 | **CORRECT** |
| `KSMBD_EVENT_LOGIN_REQUEST_EXT` | 16 | **CORRECT** |
| `KSMBD_EVENT_LOGIN_RESPONSE_EXT` | 17 | **CORRECT** |

The request/response pairing test (`RESPONSE == REQUEST + 1`) is verified for all pairs. **CORRECT.**

#### User Flag Constants:

| Flag | Test Value | Verdict |
|------|-----------|---------|
| `KSMBD_USER_FLAG_INVALID` | 0 | **CORRECT** |
| `KSMBD_USER_FLAG_OK` | BIT(0) = 1 | **CORRECT** |
| `KSMBD_USER_FLAG_BAD_PASSWORD` | BIT(1) = 2 | **CORRECT** |
| `KSMBD_USER_FLAG_BAD_UID` | BIT(2) = 4 | **CORRECT** |
| `KSMBD_USER_FLAG_BAD_USER` | BIT(3) = 8 | **CORRECT** |
| `KSMBD_USER_FLAG_GUEST_ACCOUNT` | BIT(4) = 16 | **CORRECT** |
| `KSMBD_USER_FLAG_DELAY_SESSION` | BIT(5) = 32 | **CORRECT** |
| `KSMBD_USER_FLAG_EXTENSION` | BIT(6) = 64 | **CORRECT** |

#### Tree Connect Status Constants:

All 10 status values (0-9) verified. **CORRECT.**

#### RPC Status Constants:

| Constant | Test Value | Windows Error Code | Verdict |
|----------|-----------|-------------------|---------|
| `KSMBD_RPC_OK` | 0 | ERROR_SUCCESS | **CORRECT** |
| `KSMBD_RPC_EBAD_FUNC` | 0x00000001 | ERROR_INVALID_FUNCTION | **CORRECT** |
| `KSMBD_RPC_EACCESS_DENIED` | 0x00000005 | ERROR_ACCESS_DENIED | **CORRECT** |
| `KSMBD_RPC_EBAD_FID` | 0x00000006 | ERROR_INVALID_HANDLE | **CORRECT** |
| `KSMBD_RPC_ENOMEM` | 0x00000008 | ERROR_NOT_ENOUGH_MEMORY | **CORRECT** |
| `KSMBD_RPC_EBAD_DATA` | 0x0000000D | ERROR_INVALID_DATA | **CORRECT** |
| `KSMBD_RPC_ENOTIMPLEMENTED` | 0x00000040 | ERROR_CALL_NOT_IMPLEMENTED | **CORRECT** |
| `KSMBD_RPC_EINVALID_PARAMETER` | 0x00000057 | ERROR_INVALID_PARAMETER | **CORRECT** |
| `KSMBD_RPC_EMORE_DATA` | 0x000000EA | ERROR_MORE_DATA | **CORRECT** |
| `KSMBD_RPC_EINVALID_LEVEL` | 0x0000007C | ERROR_INVALID_LEVEL | **CORRECT** |
| `KSMBD_RPC_SOME_NOT_MAPPED` | 0x00000107 | ERROR_SOME_NOT_MAPPED | **CORRECT** |

All Win32 error codes match the Microsoft documentation values.

#### Worker Pool Tests (wp_init/wp_destroy):

All lifecycle tests (normal, edge cases, idempotent destroy) test implementation behavior, not protocol spec. **CORRECT.**

---

### File 7: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_asn1_codec.c`

**28 test cases audited.**

#### ASN.1 Tag/Class Constants:

| Constant | Test Value | X.690 / X.680 Spec Value | Verdict |
|----------|-----------|-------------------------|---------|
| `ASN1_UNI` | 0 | Universal class = 0b00 = 0 | **CORRECT** |
| `ASN1_APL` | 1 | Application class = 0b01 = 1 | **CORRECT** |
| `ASN1_CTX` | 2 | Context-specific class = 0b10 = 2 | **CORRECT** |
| `ASN1_PRV` | 3 | Private class = 0b11 = 3 | **CORRECT** |
| `ASN1_PRI` | 0 | Primitive = 0 | **CORRECT** |
| `ASN1_CON` | 1 | Constructed = 1 | **CORRECT** |
| `ASN1_SEQ` | 16 | SEQUENCE = tag 16 | **CORRECT** |
| `ASN1_OTS` | 4 | OCTET STRING = tag 4 | **CORRECT** |
| `ASN1_NUL` | 5 | NULL = tag 5 | **CORRECT** |
| `ASN1_OJI` | 6 | OBJECT IDENTIFIER = tag 6 | **CORRECT** |
| `ASN1_ENUM` | 10 | ENUMERATED = tag 10 | **CORRECT** |
| `ASN1_SET` | 17 | SET = tag 17 | **CORRECT** |
| `ASN1_BOL` | 1 | BOOLEAN = tag 1 | **CORRECT** |
| `ASN1_INT` | 2 | INTEGER = tag 2 | **CORRECT** |
| `ASN1_BTS` | 3 | BIT STRING = tag 3 | **CORRECT** |

#### Encoding/Decoding Tests:

1. **test_header_decode_short_form** -- SEQUENCE (0x30) with length 3. 0x30 = 0b00110000 = Universal(0) | Constructed(1) | tag=16. **CORRECT per X.690 8.1.**

2. **test_header_decode_long_form** -- OCTET STRING (0x04) with length 200 (0x81 0xC8). Long-form length: 0x81 means 1 subsequent length byte, 0xC8=200. **CORRECT per X.690 8.1.3.4.**

3. **test_header_decode_zero_length** -- NULL (0x05 0x00). Tag 5, length 0. **CORRECT per X.690 8.8.**

4. **test_header_decode_context_class** -- 0xA0 = 0b10100000 = Context(2) | Constructed(1) | tag=0. **CORRECT.**

5. **test_header_decode_empty_buffer** -- Empty buffer returns 0 (failure). **CORRECT.**

6. **test_header_decode_truncated** -- Only tag byte, no length. Returns 0. **CORRECT.**

7. **test_header_decode_length_exceeds_buffer** -- Length=10, buffer=4 bytes. Rejects. **CORRECT per X.690 8.1.3.**

8. **test_oid_decode_krb5** -- Verified above. **CORRECT.**

9. **test_oid_decode_spnego** -- Verified above. **CORRECT.**

10. **test_oid_encode_spnego** -- Encodes SPNEGO OID and verifies DER output `{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}`. This matches `40*1 + 3 = 43 = 0x2B`, then `6, 1, 5, 5, 2`. **CORRECT per X.690 8.19.**

11. **test_oid_encode_decode_roundtrip_krb5** -- Encode then decode KRB5 OID. **CORRECT.**

12. **test_oid_encode_decode_roundtrip_ntlmssp** -- Encode then decode NTLMSSP OID. **CORRECT.**

13. **test_oid_encode_decode_roundtrip_mskrb5** -- Encode then decode MSKRB5 OID. **CORRECT.**

14. **test_header_len_small_payload** -- payload=10, depth=1: total=10+1+1=12 (1 tag + 1 length). **CORRECT** for short-form (payload < 128).

15. **test_header_len_medium_payload** -- payload=200, depth=1: total=200+2+1=203 (1 tag + 2 length bytes for 128<=payload<256). **CORRECT.**

16. **test_header_len_large_payload** -- payload=300, depth=1: total=300+3+1=304 (1 tag + 3 length bytes for 256<=payload). **CORRECT.**

17. **test_header_len_depth_zero** -- depth=0, returns just the payload. **CORRECT.**

18. **test_header_len_depth_two** -- Two nesting levels. inner = 10+2 = 12, outer = 12+2 = 14. **CORRECT.**

19. **test_header_encode_small** -- SEQUENCE with total=12: tag=0x30, payload=10, short-form length=10. **CORRECT.**

20. **test_header_encode_medium** -- OCTET STRING with total=203: tag=0x04, length=0x81 0xC8 (200). **CORRECT.**

21. **test_header_encode_too_small** -- Total=1, expects -EINVAL (need at least 2 bytes for tag+length). **CORRECT.**

22. **test_header_encode_decode_roundtrip** -- Encode CTX CON [3] with total=15, decode back. **CORRECT.**

23. **test_full_tlv_roundtrip** -- Complete OCTET STRING TLV encode+decode. **CORRECT.**

---

### File 8: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_md4_kat.c`

**6 test cases audited.**

RFC 1320 Appendix A.5 test vectors:

| # | Input | Expected Hash (hex) | Test Value | Verdict |
|---|-------|-------------------|-----------|---------|
| 1 | "" (empty) | 31d6cfe0d16ae931b73c59d7e0c089c0 | `{0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0}` | **CORRECT** |
| 2 | "a" | bde52cb31de33e46245e05fbdbd6fb24 | `{0xbd,0xe5,0x2c,0xb3,0x1d,0xe3,0x3e,0x46,0x24,0x5e,0x05,0xfb,0xdb,0xd6,0xfb,0x24}` | **CORRECT** |
| 3 | "abc" | a448017aaf21d8525fc10ae87aa6729d | `{0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d}` | **CORRECT** |
| 4 | "message digest" | d9130a8164549fe818874806e1c7014b | `{0xd9,0x13,0x0a,0x81,0x64,0x54,0x9f,0xe8,0x18,0x87,0x48,0x06,0xe1,0xc7,0x01,0x4b}` | **CORRECT** |
| 5 | "abcdefghijklmnopqrstuvwxyz" | d79e1c308aa5bbcdeea8ed63df412da9 | `{0xd7,0x9e,0x1c,0x30,0x8a,0xa5,0xbb,0xcd,0xee,0xa8,0xed,0x63,0xdf,0x41,0x2d,0xa9}` | **CORRECT** |

All five hash values exactly match RFC 1320 Appendix A.5.

6. **test_md4_incremental** -- Verifies that MD4("abc") computed as one-shot equals MD4("a" + "bc") computed incrementally. This tests the update-accumulation property. **CORRECT** (fundamental property of Merkle-Damgard hash functions).

**Note:** RFC 1320 defines 7 test vectors. The test file only implements 5 of them (vectors 1-5). It is missing:
- Vector 6: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" -> 043f8582f241db351ce627e153e7f0e4
- Vector 7: "12345678901234567890123456789012345678901234567890123456789012345678901234567890" -> e33b4ddc9c38f2199c3e7b164fcc0536

This is not a bug, but it represents **incomplete coverage** of the RFC 1320 test suite.

---

## SUMMARY

### Totals

- **Total test cases audited**: ~190+
- **CORRECT**: ~186
- **QUESTIONABLE**: 3
- **WRONG**: 0

### QUESTIONABLE Findings

1. **test_smbacl.c: test_compare_sids_different_count** (line 196-210) -- The `smb_compare_sids()` function treats SIDs with different numbers of sub-authorities as equal if their common prefix matches. Per MS-DTYP 2.4.2, S-1-5-21 and S-1-5-21-1000 are distinct SIDs. However, the test correctly documents the implementation behavior. The implementation uses this for domain-SID prefix matching, where this behavior is intentional. **Rating: QUESTIONABLE** -- the test is correct for the implementation, but the implementation's equality semantics differ from strict SID equality per MS-DTYP.

2. **test_smbacl.c: test_read_sid_zero_subauth** (line 244-264) -- The implementation rejects `num_subauth == 0` via the check `if (!sid->num_subauth || ...)`. Per MS-DTYP 2.4.2, SubAuthorityCount can be 0 (e.g., S-1-5 is the NT Authority SID with 0 sub-authorities). The test correctly reflects the implementation, but the implementation is more restrictive than the spec. **Rating: QUESTIONABLE** -- implementation restriction, not a test bug.

3. **test_smbacl.c: test_read_sid_max_subauth_exceeded** (line 266-284) -- The implementation rejects `num_subauth >= SID_MAX_SUB_AUTHORITIES` (i.e., >= 15), but the spec allows exactly 15 sub-authorities. The struct has room for 15 (`sub_auth[SID_MAX_SUB_AUTHORITIES]`). The test is correct for the implementation, but the implementation's boundary is off-by-one from the spec. **Rating: QUESTIONABLE** -- the `>=` should arguably be `>` per the spec.

### Missing Coverage

- **test_md4_kat.c**: Missing RFC 1320 test vectors 6 and 7 (alphanumeric and repeated digits). Not a bug, but incomplete coverage.
- **test_smbacl.c**: No tests for well-known SIDs like S-1-1-0 (Everyone/World), S-1-5-32 (BUILTIN), S-1-5-18 (LOCAL SYSTEM), or S-1-5-7 (ANONYMOUS LOGON) per MS-DTYP 2.4.2.1.
- **test_asn1_codec.c**: No test for indefinite-length encoding (X.690 8.1.3.6), though this is BER-only and ksmbd uses DER.

Sources:
- [RFC 1320 - The MD4 Message-Digest Algorithm](https://www.rfc-editor.org/rfc/rfc1320)