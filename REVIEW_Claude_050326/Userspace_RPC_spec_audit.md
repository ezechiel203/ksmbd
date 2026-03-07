# Userspace Rpc Spec Audit

Agent ID: aebb224210a2939b4

Now I have a comprehensive understanding of all the test files and the implementation. Let me finalize the audit.

---

Here is the complete audit report:

## Audit Summary

### Scope Clarification

The tests being audited cover **userspace DCE/RPC service implementations** in ksmbd-tools. These tests exercise:
- **NDR primitives** (encoding/decoding per MS-RPCE/C706)
- **SRVSVC** (MS-SRVS: Server Service Remote Protocol)
- **WKSSVC** (MS-WKST: Workstation Service Remote Protocol)
- **SAMR** (MS-SAMR: Security Account Manager Remote Protocol)
- **LSARPC** (MS-LSAR: Local Security Authority Remote Protocol)
- **DCE/RPC pipe lifecycle** (MS-RPCE transport)
- **IPC management layer** (ksmbd-specific kernel-userspace plumbing)

The reference spec provided (`/home/ezechiel203/ksmbd/ms-smb2.txt`) is MS-SMB2, which covers the SMB2/SMB3 transport protocol. MS-SMB2 does **not** specify the RPC payload formats, NDR encoding, or RPC service semantics. These are defined in separate Microsoft specifications (MS-RPCE, MS-SRVS, MS-WKST, MS-SAMR, MS-LSAR). MS-SMB2 only specifies how named pipes (IPC$) are transported -- not what goes inside them.

Therefore, **none of these tests can be directly contradicted by MS-SMB2**. I have instead audited them against the applicable specifications (MS-RPCE C706 for NDR/DCE-RPC, and the respective RPC service specs) and implementation correctness.

---

### Test Counts Per File

| File | Test Count |
|------|-----------|
| `test_rpc_ndr.c` | 11 |
| `test_rpc_srvsvc.c` | 36 |
| `test_rpc_wkssvc.c` | 22 |
| `test_rpc_samr.c` | 31 |
| `test_rpc_lsarpc.c` | 32 |
| `test_rpc_pipe.c` | 67 |
| `test_ipc_handlers.c` | 8 |
| **Total** | **207** |

---

### WRONG Findings (Tests Contradicting Spec)

#### WRONG-1: `test_ndr_write_string` (test_rpc_ndr.c, line 198)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_ndr.c`, lines 198-228

**Test asserts**: `max_count == 2` and `actual_count == 2` for `ndr_write_string(dce, "Hi")`

**Spec says**: Per MS-RPCE section 2.2.5.2.1 (Conformant and Varying Strings, based on C706 14.3.4), a conformant varying string encodes `MaximumCount` and `ActualCount` as the number of elements **including the null terminator**. For `"Hi"`, `MaximumCount` should be 3 and `ActualCount` should be 3 (characters H, i, NUL).

**However**: The test is correct **with respect to the implementation**. The `ndr_write_string()` function (rpc.c line 455-487) intentionally uses `strlen(str)` (without +1) for both max_count and actual_count, and converts only `strlen` characters to UTF-16LE (without the NUL terminator). This differs from `ndr_write_vstring()` (which uses `strlen+1` and includes the NUL). The test correctly validates the implementation behavior, but the implementation itself deviates from the NDR spec. Since `ndr_write_string()` is called from specific contexts where the peer expects this encoding, classifying this as **WRONG against spec but correct against implementation intent**.

**Spec reference**: MS-RPCE 2.2.5.2.1, C706 14.3.4

---

#### WRONG-2: `test_ndr_write_string_null` (test_rpc_pipe.c, line 1801)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_pipe.c`, lines 1801-1820

**Test asserts**: For `ndr_write_string(dce, NULL)`, `max_count == 0`, `actual_count == 0`

**Spec says**: Same as WRONG-1. When the input is NULL, `ndr_write_string` treats it as `""` (empty string, strlen=0). Per the NDR spec, an empty string should still include the NUL terminator, so `MaximumCount=1, ActualCount=1`. The implementation writes `max_count=0, actual_count=0` and no bytes.

**Spec reference**: MS-RPCE 2.2.5.2.1

---

### QUESTIONABLE Findings

#### Q-1: `test_dcerpc_write_headers` frag_length check (test_rpc_pipe.c, line 686)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_pipe.c`, lines 657-689

**Test asserts**: `frag_len == 8` after writing two int32 values (8 bytes of NDR data).

**Issue**: Per MS-RPCE 12.6.3.5, `frag_length` in a DCE/RPC response should include the full PDU size (header + body). For a response PDU, this would be `sizeof(dcerpc_header) + sizeof(dcerpc_response_header) + stub_data_length = 16 + 8 + 8 = 32`. The implementation's `dcerpc_write_headers()` writes `frag_length = dce->offset` which is the **offset within the payload buffer after writing headers in-place**, so the interpretation depends on how the buffer is structured. The test asserts the implementation's behavior rather than the spec. This is implementation-specific and could be correct if the buffer layout starts at offset 0 with the headers already occupying bytes 0..23, making `dce->offset = 32` -- but the test asserts `frag_len == 8`. This is **implementation-specific behavior**.

#### Q-2: `test_wkssvc_version_fields` version values (test_rpc_wkssvc.c, line 616)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_wkssvc.c`, lines 616-653

**Test asserts**: `ver_major == 2`, `ver_minor == 1` in the WKSTA_INFO_100 response.

**Issue**: Per MS-WKST 2.2.5.1 (WKSTA_INFO_100), `wki100_ver_major` and `wki100_ver_minor` represent the major and minor version numbers of the operating system running on the computer. The ksmbd-tools implementation returns hardcoded values (2, 1), which is not a real Windows version. This is implementation-specific (ksmbd is not Windows) and does not contradict a protocol compliance requirement, but a Windows client might interpret these differently. The value 2.1 does not correspond to any actual Windows version. This is acceptable for a Linux implementation but **questionable** from an interoperability perspective.

#### Q-3: NDR union encoding as "write value twice" (test_rpc_pipe.c, lines 1234-1308)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_pipe.c`, lines 1234-1308

**Test asserts**: `ndr_write_union_int32()` writes the value twice (discriminant + arm value), both identical.

**Issue**: Per C706 14.3.8 (Non-Encapsulated Unions), the discriminant and the selected arm value are separate. They happen to be identical only when the discriminant equals the arm value (which is the case for level/switch_is patterns). The implementation shortcut of writing the same value twice is correct for the specific usage pattern but would be incorrect for unions where the discriminant differs from the arm value. This is **implementation-specific**.

#### Q-4: `test_rpc_ioctl_payload_too_small` expects EBAD_DATA (test_rpc_pipe.c, line 644)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_pipe.c`, lines 618-651

**Test asserts**: When `payload_sz == 4` (too small for a DCE/RPC header), `rpc_ioctl_request` returns `KSMBD_RPC_EBAD_DATA`.

**Issue**: The DCE/RPC spec (C706 12.5.2) does not prescribe a specific error for malformed PDUs shorter than the header. The implementation's choice of `EBAD_DATA` (which maps to Windows error code `ERROR_BAD_DATA`) is reasonable but spec-ambiguous. Could also be `RPC_S_PROTOCOL_ERROR` or a fault PDU.

#### Q-5: BIND NACK for unsupported transfer syntax (test_rpc_pipe.c, line 962)

**File**: `/home/ezechiel203/ksmbd/ksmbd-tools/tests/test_rpc_pipe.c`, lines 934-969

**Test asserts**: A BIND with a bogus transfer syntax UUID returns `DCERPC_PTYPE_RPC_BINDNACK`.

**Issue**: Per C706 12.5.5.3 (Bind NAK), BIND_NAK is sent when the server rejects the association entirely. However, if only the transfer syntax is unsupported but the abstract syntax is valid, the proper response per spec would be a BIND_ACK with a `provider_reject` result in the `p_result_list` for that context, not a BIND_NAK. A BIND_NAK should only be used for protocol-level rejections (wrong RPC version, authentication failure, etc.). The implementation sending BIND_NACK is **potentially wrong** per C706, but Windows servers sometimes also send BIND_NAK in similar situations, so this is **questionable**.

---

### Final Results

| Metric | Count |
|--------|-------|
| **Total Tests Audited** | **207** |
| **CORRECT** | **202** |
| **WRONG** | **2** |
| **QUESTIONABLE** | **5** |

### WRONG Details

| ID | File | Test | Issue | Spec Reference |
|----|------|------|-------|----------------|
| WRONG-1 | `test_rpc_ndr.c:198` | `test_ndr_write_string` | max_count/actual_count should include NUL terminator (expected 3, got 2 for "Hi") | MS-RPCE 2.2.5.2.1 |
| WRONG-2 | `test_rpc_pipe.c:1801` | `test_ndr_write_string_null` | Empty string should have max_count=1, actual_count=1 (got 0, 0) | MS-RPCE 2.2.5.2.1 |

### QUESTIONABLE Details

| ID | File | Test | Issue |
|----|------|------|-------|
| Q-1 | `test_rpc_pipe.c:657` | `test_dcerpc_write_headers` | frag_length=8 may not match full PDU size per spec |
| Q-2 | `test_rpc_wkssvc.c:616` | `test_wkssvc_version_fields` | Version 2.1 is not a real Windows version (implementation-specific) |
| Q-3 | `test_rpc_pipe.c:1234` | `test_ndr_write_union_int32_roundtrip` | Union "write twice" shortcut only correct for switch_is==arm patterns |
| Q-4 | `test_rpc_pipe.c:618` | `test_rpc_ioctl_payload_too_small` | EBAD_DATA for truncated PDU is reasonable but not specified |
| Q-5 | `test_rpc_pipe.c:934` | `test_rpc_bind_nack_unsupported_syntax` | BIND_NACK should only be for protocol-level rejection per C706 12.5.5.3; unsupported syntax should use BIND_ACK with provider_reject |

### Key Observation

Both WRONG findings stem from the same root cause: `ndr_write_string()` in `rpc.c` (line 455-487) uses `strlen(str)` without adding 1 for the NUL terminator, while the NDR spec (MS-RPCE 2.2.5.2.1) requires conformant varying strings to include the terminator in both MaximumCount and ActualCount. The companion function `ndr_write_vstring()` (line 405-453) correctly includes the terminator. The tests faithfully validate the implementation behavior, so the bug is in the implementation rather than the tests -- but the tests are WRONG relative to the spec because they assert spec-noncompliant values as correct.