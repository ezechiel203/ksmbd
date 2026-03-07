# Remaining Kernel Tests Pt2

Agent ID: a3bdb2984d5fa19e3

The spec says the server MUST disconnect (without sending an error response) when the command code is invalid. The test returns -1 (analogous to STATUS_INVALID_PARAMETER) and doesn't disconnect. However, this is a replicated simplified dispatcher -- not the real ksmbd code path. The test is testing its own simplified model, not the actual server behavior. This is QUESTIONABLE since the test could mislead about the correct server behavior.

---

Here is the complete audit summary:

## Audit Summary

**Files audited**: 6 (with `ksmbd_test_ksmbd_work.c` mapped to `ksmbd_test_work.c`)

**Total tests**: 116

| File | Tests | CORRECT | WRONG | QUESTIONABLE |
|------|-------|---------|-------|--------------|
| `ksmbd_test_work.c` | 13 | 13 | 0 | 0 |
| `ksmbd_test_ida.c` | 12 | 12 | 0 | 0 |
| `ksmbd_test_misc.c` | 33 | 33 | 0 | 0 |
| `ksmbd_test_unicode.c` | 31 | 31 | 0 | 0 |
| `ksmbd_test_ndr.c` | 10 | 10 | 0 | 0 |
| `ksmbd_test_server.c` | 17 | 14 | 0 | 3 |
| **TOTAL** | **116** | **113** | **0** | **3** |

### WRONG: 0

No tests have expectations that directly contradict the MS-SMB2 specification.

### QUESTIONABLE: 3

All three are in `/home/ezechiel203/ksmbd/test/ksmbd_test_server.c`:

---

**Q-1: `test_process_request_invalid_command` (line 250)**

```c
static void test_process_request_invalid_command(struct kunit *test)
{
    int ret;
    ret = test_process_request_dispatch(0xFF, 0x20, true);
    KUNIT_EXPECT_EQ(test, ret, -1);
}
```

**Issue**: The test expects an invalid command (0xFF, which exceeds max_cmds=0x20) to return -1 (analogous to STATUS_INVALID_PARAMETER). However, MS-SMB2 section 3.3.5.2.6 states: "The server MUST disconnect, as specified in section 3.3.7.1, **without sending an error response** if [...] The Command code in the SMB2 header does not match one of the command codes in the SMB2 header as specified in section 2.2.1."

The spec mandates a silent disconnect, not an error response. The test's replicated dispatcher models this as an error return rather than a disconnect action. While the test is testing its own simplified model (not the real server code), the expectation implies an error response would be sent, which the spec explicitly forbids.

**Spec reference**: MS-SMB2 section 3.3.5.2.6 "Handling Incorrectly Formatted Requests"

---

**Q-2: `test_process_request_unimplemented` (line 258)**

```c
static void test_process_request_unimplemented(struct kunit *test)
{
    int ret;
    ret = test_process_request_dispatch(0x05, 0x20, false);
    KUNIT_EXPECT_EQ(test, ret, -2);
}
```

**Issue**: The test expects a valid command code (0x05) with no handler (`has_proc=false`) to return -2 (analogous to STATUS_NOT_IMPLEMENTED). The MS-SMB2 spec does not define a "STATUS_NOT_IMPLEMENTED" response for valid command codes that lack a handler -- all command codes defined in section 2.2.1 MUST be implemented by a compliant server. If a command code is valid but the specific operation is not supported, the response depends on the specific command's processing rules. The concept of "has_proc=false" for a valid command code is implementation-specific and not addressed by the MS-SMB2 spec.

**Spec reference**: MS-SMB2 section 2.2.1 (command code definitions), section 3.3.5 (processing rules)

---

**Q-3: `test_encrypted_session_unencrypted_request_rejected` (line 291)**

```c
static void test_encrypted_session_unencrypted_request_rejected(struct kunit *test)
{
    /* WRITE command (0x0009) should be rejected */
    KUNIT_EXPECT_TRUE(test, test_encryption_check(true, false, 0x0009));
}
```

**Issue**: The test's replicated encryption enforcement model (`test_encryption_check`) exempts only NEGOTIATE (0x0000) and SESSION_SETUP (0x0001) from encryption enforcement when `enc_forced=true`. While this is broadly correct, the actual MS-SMB2 spec (section 3.3.5.2.9) applies Session.EncryptData enforcement only during the "Verifying the Session" step, which is not invoked for NEGOTIATE or SESSION_SETUP. However, the spec also states in section 3.3.5.5 that SESSION_SETUP itself has its own encryption checks (steps 1-2) where it can reject requests with STATUS_ACCESS_DENIED under certain conditions. The test's simplified model does not capture these nuances -- it treats SESSION_SETUP as unconditionally exempt, when the spec says SESSION_SETUP can also be rejected under encryption enforcement (e.g., when `EncryptData` is TRUE, `RejectUnencryptedAccess` is TRUE, and the Connection dialect is not SMB 3.x, per section 3.3.5.5 step 1).

**Spec reference**: MS-SMB2 section 3.3.5.2.9 "Verifying the Session", section 3.3.5.5 "Receiving an SMB2 SESSION_SETUP Request" (steps 1-2)

---

### Detailed classification of all 116 tests:

**`/home/ezechiel203/ksmbd/test/ksmbd_test_work.c`** (13 tests) -- All CORRECT

These tests verify internal data structure management (work struct allocation, IOV pinning, buffer lifecycle). They are implementation-specific with no MS-SMB2 protocol expectations. The compound_fid sentinel value of 0xFFFFFFFFFFFFFFFF is consistent with MS-SMB2 section 2.2.14 which uses this value for FileId in compound requests.

**`/home/ezechiel203/ksmbd/test/ksmbd_test_ida.c`** (12 tests) -- All CORRECT

These tests verify IDA (ID allocation) management. The SMB2 TID range 1-0xFFFFFFFE and SMB1 TID range 1-0xFFFE are implementation choices consistent with the spec (TreeId is 4 bytes per section 2.2.1.2, and 0 is reserved for TREE_CONNECT Request). The SMB2 UID avoiding 0xFFFE is an SMB1 compatibility measure not addressed by MS-SMB2 but not contradicting it either.

**`/home/ezechiel203/ksmbd/test/ksmbd_test_misc.c`** (33 tests) -- All CORRECT

These tests cover pattern matching (wildcards consistent with MS-FSA 2.1.4.4 as referenced by MS-SMB2 section 2.2.33), filename validation (rejecting control chars and special chars per NTFS rules), path conversion, nlink computation (VFS-specific, not MS-SMB2), time conversion (FILETIME epoch offset is mathematically correct: 369 years * 365 + 89 leap days), character validation, stream name parsing ($DATA/$INDEX_ALLOCATION per MS-FSCC), and stream name validation.

**`/home/ezechiel203/ksmbd/test/ksmbd_test_unicode.c`** (31 tests) -- All CORRECT

These tests verify UTF-16LE encoding/decoding, character validation, and NLS conversion functions. The replicated `is_char_allowed` function does not reject `*` (unlike the `misc.c` version), but this is consistent with the `unicode.c` source it replicates. The mapchars tests (UNI_COLON, UNI_QUESTION, UNI_PIPE) verify Samba-compatible character mapping which is implementation-specific.

**`/home/ezechiel203/ksmbd/test/ksmbd_test_ndr.c`** (10 tests) -- All CORRECT

These tests verify NDR encoding/decoding for xattr_dos_attrib and xattr_ntacl structures. NDR is used for Samba-compatible extended attribute storage and is not defined in MS-SMB2. The roundtrip encoding/decoding tests, truncation handling, version validation, and version mismatch detection are all testing internal implementation logic correctly.

**`/home/ezechiel203/ksmbd/test/ksmbd_test_server.c`** (17 tests) -- 14 CORRECT, 3 QUESTIONABLE

Configuration tests (set/get netbios name, server string, work group, null/empty rejection, replacement) and state machine tests (startup, running, configurable states) are implementation-specific. The three QUESTIONABLE tests are detailed above.