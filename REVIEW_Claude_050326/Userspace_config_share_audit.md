# Userspace Config Share Audit

Agent ID: a92b17b8cfc605767

I now have enough context to perform the full audit. Let me compile my analysis.

---

## Audit Summary

### Scope

I audited 6 userspace test files from `ksmbd-tools/tests/` against the MS-SMB2 protocol specification (`ms-smb2.txt`, MS-SMB2 v20260114). These tests are **userspace management tools tests** -- they test configuration parsing, user/share management, utility functions, and control output. They do **not** directly test on-the-wire SMB2 protocol PDU processing.

The vast majority of these tests exercise implementation-specific userspace tooling behavior (config file parsing, string utilities, memory management, internal data structures) that has no direct counterpart in the MS-SMB2 specification. The spec prescribes wire-protocol behavior, not configuration file syntax or management tool internals.

### Test Counts by File

| File | Tests |
|------|-------|
| `test_config_parser.c` | 30 |
| `test_config_parser_extended.c` | 56 |
| `test_share_management.c` | 45 |
| `test_user_management.c` | 30 |
| `test_tools_utils.c` | 36 |
| `test_control.c` | 37 |
| **Total** | **234** |

### Classification Results

- **CORRECT**: 234
- **WRONG**: 0
- **QUESTIONABLE**: 7

---

### Detailed Findings

All 234 tests were classified against the MS-SMB2 specification. None were found to be **WRONG** (directly contradicting the specification). Seven tests were classified as **QUESTIONABLE** because their expectations touch on areas where the MS-SMB2 specification has relevant guidance, but the test expectations are implementation-specific choices rather than spec violations.

---

#### QUESTIONABLE-1: `test_default_values` (test_config_parser.c, line 192)

**Assertion**: `global_conf.server_signing == KSMBD_CONFIG_OPT_AUTO`

**Spec reference**: MS-SMB2 section 3.3.1.5 (line 10392): "The value of RequireMessageSigning MUST be set based on system configuration, which is implementation-specific."

**Analysis**: The spec says `RequireMessageSigning` is a Boolean and its value is implementation-specific. Mapping the config value "auto" to something that can be TRUE or FALSE at runtime is an implementation choice. The test correctly validates the ksmbd-tools default, but whether "auto" is the right default is an implementation decision, not a spec-mandated one. The spec does not prohibit this; it simply says the behavior is implementation-defined. **Not a spec violation**, but the mapping from "auto/disabled/enabled/mandatory" to the spec's Boolean `RequireMessageSigning` is a ksmbd-specific abstraction.

---

#### QUESTIONABLE-2: `test_smb2_max_rw_trans` (test_config_parser_extended.c, line 1023)

**Assertions**: `smb2_max_read == 8M`, `smb2_max_write == 4M`, `smb2_max_trans == 1M`

**Spec reference**: MS-SMB2 section 3.3.5.4 (lines 20220-20231): "MaxTransactSize SHOULD be greater than or equal to 65536", "MaxReadSize SHOULD be greater than or equal to 65536", "MaxWriteSize SHOULD be greater than or equal to 65536."

**Analysis**: The test verifies that the config parser correctly reads user-configured values. The values 8M, 4M, and 1M all exceed the spec's SHOULD minimum of 65536, so no violation occurs. However, the test does not verify the spec's recommendation that these values SHOULD NOT be less than 65536. A test with `smb2 max read = 1024` would be worth having to verify clamping behavior. **Not a spec violation** -- the test values are valid.

---

#### QUESTIONABLE-3: `test_encryption_enabled` (test_config_parser.c, line 274)

**Assertions**: When encryption is set to "enabled", neither the `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION` (mandatory) nor `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION_OFF` flags are set.

**Spec reference**: MS-SMB2 section 3.3.1.7 (lines 17724-17726): The spec describes `IsEncryptionSupported` as a Boolean and `EncryptData` as a per-session/per-share setting. The spec does not define a three-state (enabled/disabled/mandatory) encryption model.

**Analysis**: The ksmbd implementation uses a three-state model (disabled/enabled/mandatory) that is richer than the spec's Boolean `IsEncryptionSupported`. When "enabled", the server supports encryption but does not require it -- this maps to `IsEncryptionSupported=TRUE, EncryptData=FALSE` which is spec-compliant. **Not a spec violation**, but the three-state semantics are implementation-specific.

---

#### QUESTIONABLE-4: `test_share_lookup_case_insensitive` (test_share_management.c, line 244)

**Assertion**: Share lookup is case-insensitive (e.g., "TestShare" == "testshare" == "TESTSHARE").

**Spec reference**: MS-SMB2 section 2.2.10 (Tree Connect Request): "The share name MUST be a Unicode string" but no explicit case-sensitivity requirement is stated for share names.

**Analysis**: The MS-SMB2 spec does not explicitly state whether share name matching should be case-insensitive or case-sensitive. Windows SMB servers perform case-insensitive share matching. This test validates ksmbd's case-insensitive behavior, which matches Windows behavior but is not explicitly mandated by the spec. **Implementation-compatible, not explicitly spec-mandated.**

---

#### QUESTIONABLE-5: `test_usm_handle_logout_delay_session` (test_user_management.c, line 670)

**Assertion**: After 10+ bad password attempts, the `KSMBD_USER_FLAG_DELAY_SESSION` flag is set.

**Spec reference**: The MS-SMB2 spec does not describe login throttling, brute-force protection, or session delay mechanisms. This is entirely an implementation-specific security measure.

**Analysis**: This is a ksmbd-specific security hardening feature with no spec counterpart. The test correctly validates the implementation's behavior. **Not relevant to the spec** -- the spec is silent on brute-force protection.

---

#### QUESTIONABLE-6: `test_connection_tracking` (test_share_management.c, line 310)

**Assertion**: When `max_connections = 2`, a third connection attempt returns `-EINVAL`.

**Spec reference**: The MS-SMB2 spec does not describe per-share connection limits. Section 3.3.5.7 (tree connect processing) does not mention connection count enforcement.

**Analysis**: Per-share connection limiting is an implementation-specific administrative feature. The test correctly validates ksmbd's behavior, but the error code `-EINVAL` is an internal code and does not map to a specific MS-SMB2 status code requirement. On the wire, the server would presumably return `STATUS_REQUEST_NOT_ACCEPTED` or similar, but the test is purely internal. **Implementation-specific, no spec counterpart.**

---

#### QUESTIONABLE-7: `test_config_opt_values` (test_control.c, line 723)

**Assertion**: `KSMBD_CONFIG_OPT_DISABLED == 0`, `KSMBD_CONFIG_OPT_ENABLED == 1`, `KSMBD_CONFIG_OPT_AUTO == 2`, `KSMBD_CONFIG_OPT_MANDATORY == 3`.

**Spec reference**: The MS-SMB2 spec uses Boolean values for signing (`RequireMessageSigning`) and encryption (`IsEncryptionSupported`, `EncryptData`), not four-state enumerations.

**Analysis**: The four-state config options are a ksmbd-specific abstraction layered on top of the spec's simpler Boolean model. The exact numeric values are irrelevant to the spec. **Not a spec violation** -- purely internal constants.

---

### Final Summary

| Metric | Count |
|--------|-------|
| **Total tests** | **234** |
| **CORRECT** | **227** (tests that are entirely internal/utility and not subject to spec validation) |
| **WRONG** | **0** |
| **QUESTIONABLE** | **7** |

**Conclusion**: None of the 234 tests across these 6 files contradict the MS-SMB2 specification. All tests exercise userspace tool internals (config parsing, string manipulation, user/share management data structures, reference counting, sysfs reading) which are implementation-specific and outside the scope of what the MS-SMB2 wire protocol specification prescribes.

The 7 QUESTIONABLE findings are cases where the test expectations touch on areas that have *some* spec relevance (signing defaults, max read/write/trans sizes, encryption models, share name case sensitivity, connection limits, config option encoding), but in each case the ksmbd implementation's behavior is a reasonable and compatible interpretation of the spec's guidance. None represent clear violations.

The tests are well-constructed for their purpose: validating that the ksmbd-tools userspace configuration and management layer functions correctly. They simply do not (and should not) test on-the-wire SMB2 protocol compliance, which is the domain of the kernel module's own tests and integration tests like smbtorture.