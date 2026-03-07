# Userspace Acl Session Audit

Agent ID: a9011710aee736c7b

Now I have a complete picture. Let me compile the full audit report.

---

Here is the comprehensive audit of the four test files against the MS-SMB2 protocol specification (`/home/ezechiel203/ksmbd/ms-smb2.txt`).

## Summary

| Test File | Total Tests | CORRECT | WRONG | QUESTIONABLE |
|-----------|-------------|---------|-------|--------------|
| test_smbacl.c | 18 | 16 | 0 | 2 |
| test_session_tree.c | 52 | 52 | 0 | 0 |
| test_spnego.c | 55 | 55 | 0 | 0 |
| test_worker_ipc.c | 76 | 76 | 0 | 0 |
| **TOTAL** | **201** | **199** | **0** | **2** |

**WRONG: 0**
**QUESTIONABLE: 2**

---

## Detailed Findings

### File 1: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_smbacl.c` (18 tests)

These tests exercise the userspace SID manipulation functions (`smb_copy_sid`, `smb_compare_sids`, `smb_write_sid`, `smb_read_sid`, `smb_init_domain_sid`, `build_sec_desc`, `set_domain_name`) in `/home/ezechiel203/ksmbd/ksmbd-tools/mountd/smbacl.c`.

**QUESTIONABLE-1: `test_read_sid_zero_subauth` (line 244)**

The test asserts that `smb_read_sid` returns `-EINVAL` when `num_subauth == 0`. The implementation at `smbacl.c:41` checks `if (!sid->num_subauth || sid->num_subauth >= SID_MAX_SUB_AUTHORITIES)` and rejects `num_subauth == 0`.

However, per [MS-DTYP] section 2.4.2 (which MS-SMB2 references for SID definitions), `SubAuthorityCount` is defined as a UCHAR with valid values from 0 to 15. A SID with 0 sub-authorities is valid -- for example, S-1-0 (NULL Authority SID without a RID). The test correctly reflects the *implementation's* behavior but the implementation itself is overly restrictive compared to the Windows SID specification. The test expectation is correct for the ksmbd-tools implementation but deviates from the protocol specification which permits `SubAuthorityCount == 0`.

**QUESTIONABLE-2: `test_compare_sids_different_count` (line 196)**

The test asserts that `smb_compare_sids` returns `0` (equal) for two SIDs where `a.num_subauth == 2` and `b.num_subauth == 1`, but `a.sub_auth[0] == b.sub_auth[0]`. The test comment says "smb_compare_sids compares up to min(num_subauth)."

The implementation at `smbacl.c:132` uses `num_subauth = num_sat < num_saw ? num_sat : num_saw` and only compares that many sub-authorities. Per [MS-DTYP] section 2.4.2, a SID is uniquely identified by `{Revision, IdentifierAuthority, SubAuthorityCount, SubAuthority[]}`. Two SIDs with different `SubAuthorityCount` values are different SIDs (e.g., S-1-5-21 vs S-1-5-21-1234 are distinct). A strict SID equality comparison should return non-zero when `num_subauth` differs. The implementation behaves as a *prefix match* rather than a full equality check. The test correctly documents this implementation behavior, but the behavior itself contradicts the standard SID comparison semantics where SIDs with different sub-authority counts are never equal.

All other 16 tests in this file are **CORRECT**: they test internal API behaviors (copy overflow guard, write overflow, roundtrip serialization, domain SID initialization, security descriptor building, domain name resolution for Unix SID namespaces) that are implementation-specific and not directly constrained by MS-SMB2.

---

### File 2: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_session_tree.c` (52 tests)

These tests exercise the userspace session management layer (`sm_*` functions), tree connection management (`tcm_*`), connection flags, and capacity tracking.

All 52 tests are **CORRECT**. Key observations:

- **Session capacity tests (7 tests)**: These test the `global_conf.sessions_cap` mechanism, which is an implementation-specific server-side resource limit. MS-SMB2 section 3.3.5.5 does not mandate a specific session capacity mechanism but allows servers to reject sessions when resources are exhausted.

- **Tree connect/disconnect tests (18 tests)**: These test the userspace session-to-tree-connection mapping. The behaviors (multiple trees per session, disconnect-middle, reuse after destroy, zero/large IDs) are all internal management details. The spec (MS-SMB2 section 3.3.5.7 and 3.3.5.8) describes the protocol-level tree connect/disconnect handling, while these tests exercise the userspace daemon's session tracking layer which feeds the kernel via netlink IPC. No spec conflicts.

- **tcm_handle_tree_connect full-path tests (12 tests)**: These test share lookup failure (STATUS_BAD_NETWORK_NAME maps to `KSMBD_TREE_CONN_STATUS_NO_SHARE`), user lookup failure, bad password with `map_to_guest=never`, guest denied on non-guest share, guest accepted on guest-ok share, unterminated fields, exhausted sessions, and restrict_anon. All follow the expected server behavior per MS-SMB2 section 3.3.5.7.

- **Concurrent tests (2 tests)** and **lifecycle tests (3 tests)**: Internal robustness tests, not spec-constrained.

- **`test_tree_connect_zero_session_id` (line 381)**: Uses SessionId=0. Per MS-SMB2 section 2.2.1.2, `SessionId` is 0 for NEGOTIATE request/response only. However, this test exercises the *userspace management layer*, not the protocol handler. The management layer accepts any 64-bit value as a session identifier -- the kernel module enforces the protocol constraint. So this is CORRECT as a userspace management test.

---

### File 3: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_spnego.c` (55 tests)

These tests exercise SPNEGO negotiation helpers, ASN.1 encoding/decoding, Kerberos OID matching, service principal name parsing, signal handler logic, and mountd argument parsing.

All 55 tests are **CORRECT**. Key observations:

- **OID comparison tests (6 tests)**: Test the `compare_oid()` logic which does element-by-element comparison. Correctly identifies KRB5 (1.2.840.113554.1.2.2), MSKRB5 (1.2.840.48018.1.2.2), and SPNEGO (1.3.6.1.5.5.2) OIDs. These match the standard OID values per RFC 4178 and MS-KILE.

- **is_supported_mech tests (5 tests)**: Correctly identifies KRB5 and MSKRB5 as supported, rejects NTLMSSP (1.3.6.1.4.1.311.2.2.10) and SPNEGO as not supported for direct mechanism use. This matches the ksmbd SPNEGO implementation which supports only Kerberos mechanisms. NTLMSSP is handled via a separate path (not through the SPNEGO mechanism negotiation), which is consistent with the MS-SMB2 section 3.3.5.5.3 approach.

- **ASN.1 header decode tests (7 tests)**: Correctly verify SEQUENCE (0x30 = UNI|CON|SEQ), APPLICATION (0x60 = APL|CON|0), CONTEXT-SPECIFIC (0xA0 = CTX|CON|0) header parsing. All byte values and tag/class expectations match ASN.1 DER encoding rules (ITU-T X.690).

- **encode_negTokenTarg tests (5 tests)**: Verify that the negTokenTarg response is correctly structured per RFC 4178 section 4.2.2 -- outer CTX[1] CON wrapper, inner SEQUENCE, negResult=0 (accept-completed), supportedMech OID, responseToken containing GSSAPI-wrapped Kerberos AP-REP.

- **decode_negTokenInit tests (4 tests)**: Verify parsing of the GSSAPI/SPNEGO negTokenInit structure per RFC 4178 section 4.2.1 -- APPLICATION[0] wrapping SPNEGO OID, CTX[0] mechTypes, CTX[2] mechToken containing GSSAPI-wrapped Kerberos AP-REQ with the `01 00` AP-REQ identifier.

- **OID constant verification tests (5 tests)**: All OID values match published standards (RFC 4120 for KRB5, MS-KILE for MSKRB5, RFC 4178 for SPNEGO, MS-NLMP for NTLMSSP, RFC 2478 for KRB5 User-to-User).

- **Signal handler, mountd config, and service name parsing tests (18 tests)**: These are purely implementation-specific and do not intersect with MS-SMB2.

---

### File 4: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_worker_ipc.c` (76 tests)

These tests exercise the IPC message allocation (`ipc_msg_alloc`/`ipc_msg_free`), worker pool lifecycle (`wp_init`/`wp_destroy`/`wp_ipc_msg_push`), message payload embedding, and ABI constant verification.

All 76 tests are **CORRECT**. Key observations:

- **IPC message alloc tests (19 tests)**: Test boundary conditions around `KSMBD_IPC_MAX_MESSAGE_SIZE` (4096 bytes). The max payload formula `4096 - sizeof(struct ksmbd_ipc_msg) - 1` is implementation-specific. Overflow tests (SIZE_MAX, half SIZE_MAX) correctly verify that the allocator rejects pathological sizes.

- **Structure size and layout tests (8 tests)**: Verify that `ksmbd_ipc_msg`, `ksmbd_heartbeat`, `ksmbd_login_request/response`, `ksmbd_tree_connect_request/response`, `ksmbd_rpc_command`, etc. have minimum expected sizes. These are kernel-userspace ABI checks.

- **Event type constant tests (3 tests)**: Verify the `KSMBD_EVENT_*` enum values (0-17) and the request/response pairing rule (response = request + 1). These are ABI constants, not protocol-level values.

- **RPC status constants (1 test)**: The RPC error codes (`KSMBD_RPC_EBAD_FUNC=1`, `KSMBD_RPC_EACCESS_DENIED=5`, etc.) map to standard Windows error codes per [MS-ERREF], and the test values are correct.

- **Share/global flag constants (3 tests)**: Verify bit assignments for `KSMBD_SHARE_FLAG_*` and `KSMBD_GLOBAL_FLAG_*`. These are implementation-defined ABI flags that map to features described in MS-SMB2 (e.g., SMB2_LEASES maps to oplock/lease support in section 2.2.13.2.8, SMB2_ENCRYPTION maps to section 3.3.4.1.3). The bit assignments themselves are not protocol-mandated.

- **Worker pool tests (12 tests)**: Test `wp_init`/`wp_destroy` lifecycle, thread count clamping (0->default, >64->default), idempotency, and message push. Purely implementation-specific.

- **Payload embedding tests (10 tests)**: Verify that typed structures can be correctly embedded in the IPC message payload and fields written/read back correctly. These are ABI correctness tests.

- **Share config response tests (2 tests)**: Verify the `KSMBD_SHARE_CONFIG_VETO_LIST` macro and `ksmbd_share_config_path()` inline function. The path computation (`____payload + veto_list_sz + 1` when veto_list_sz > 0, otherwise `____payload`) matches the implementation at `/home/ezechiel203/ksmbd/ksmbd-tools/include/linux/ksmbd_server.h:211-217`.

---

## Overall Assessment

All 201 tests across the four files are **implementation-correct** -- they accurately test the behavior of the ksmbd-tools userspace daemon code. None of the tests make incorrect assertions about MS-SMB2 protocol behavior.

The two QUESTIONABLE findings are cases where the **implementation** deviates from the strict letter of the protocol specification (MS-DTYP for SID handling), and the tests faithfully document that implementation behavior:

1. **Rejecting SIDs with `num_subauth == 0`**: Valid per MS-DTYP but rejected by ksmbd-tools. Low risk since zero-subauth SIDs rarely appear in SMB authentication contexts.

2. **SID prefix-match comparison**: `smb_compare_sids` treats SIDs with different `num_subauth` as equal if their shared prefix matches. This could theoretically cause incorrect ACL matching (e.g., treating S-1-5-21 the same as S-1-5-21-500), but in practice the function is used in contexts where both SIDs have the same structure.