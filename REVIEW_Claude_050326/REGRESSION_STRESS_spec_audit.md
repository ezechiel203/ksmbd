# Regression Stress Spec Audit

Agent ID: aa7a51bb541b1283b

The state_machine_smb2.c test redefines constants locally, and they match. Now I have all the information needed for the final audit.

---

Here is the complete audit report:

## Test File Audit Against MS-SMB2 Specification

### Summary

| Metric | Count |
|--------|-------|
| **Total test files audited** | 20 |
| **Total individual tests** | ~252 |
| **CORRECT** | 244 |
| **WRONG** | 3 |
| **QUESTIONABLE** | 5 |

---

### WRONG Findings (3)

#### WRONG-1: `ksmbd_test_regression_full.c` -- `reg_lock_bit_extraction_order` (line 53)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_full.c`

**Problem**: The test comment and variable names contradict the MS-SMB2 spec naming convention. The comment at line 47 says "Fix: index = val & 0xF, sequence = (val >> 4) & 0xF" but MS-SMB2 section 2.2.26 defines:
- **LockSequenceNumber (4 bits)**: The 4 **least significant** bits (i.e., `val & 0xF`)
- **LockSequenceIndex (28 bits)**: The upper 28 bits (i.e., `val >> 4`)

The test code `u8 idx = raw & 0xF` labels the low 4 bits as "idx" (index), but per spec those are the **sequence number**. The `u8 seq = (raw >> 4) & 0xF` labels the upper bits as "seq" (sequence), but per spec those are the **index**.

The production code (`smb2_lock.c:441-442`) correctly names them `seq_num = val & 0xF` and `seq_idx = (val >> 4)`.

**Impact**: The actual bit extraction is correct and the test will pass. However, the test documents the opposite of what the spec says about which field is which, creating confusion for future maintainers.

**Spec reference**: MS-SMB2 section 2.2.26 (SMB2 LOCK Request), lines 7618-7621.

#### WRONG-2: `ksmbd_test_regression_full.c` -- `reg_channel_sequence_s16_wraparound` (line 583)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_full.c`

**Problem**: The comment at line 583 says "Bug: channel sequence comparison used unsigned diff, failing on wrap-around. Fix: uses s16 diff for correct wrap-around detection." This characterization is backwards relative to the spec.

MS-SMB2 section 3.3.5.2.10 says: "if the **unsigned** difference using 16-bit arithmetic between ChannelSequence in the SMB2 header and Open.ChannelSequence is less than or equal to 0x7FFF".

The spec explicitly describes an **unsigned** difference, not a signed one. The production code at `smb2_pdu_common.c:105` uses `diff = (s16)(req_seq - fp->channel_sequence)` which happens to produce mathematically equivalent results (s16 < 0 iff unsigned difference > 0x7FFF), but the test's narrative claiming the old "unsigned diff" was broken and "s16" is the fix is misleading. Both approaches are valid implementations of the same spec requirement; the comment incorrectly calls the unsigned approach a "bug".

**Impact**: The test expectations are technically correct (they verify the s16 arithmetic produces the right accept/reject decisions), but the comments misrepresent the spec.

**Spec reference**: MS-SMB2 section 3.3.5.2.10 (Verifying the Channel Sequence Number), lines 20085-20096.

#### WRONG-3: `ksmbd_test_regression_session.c` -- `reg_channel_sequence_stale_reject` (line 157)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_session.c`

**Problem**: The test at line 176-179 checks that `incoming=0x8000, stored=0` gives `diff = (s16)(0x8000 - 0) = -32768` which is negative, asserting this should be rejected as stale. However, per MS-SMB2 3.3.5.2.10, the unsigned difference is `0x8000` which is NOT less than or equal to `0x7FFF`, so this case should indeed be rejected. The test expectation (reject) is correct.

But the test's comment at line 175 says "Half-range stale boundary: stored=0, incoming=0x8000" which is correct. However, the paired test `reg_channel_sequence_advance` at line 212-216 checks `incoming=0x7FFF, stored=0` and expects acceptance. The unsigned difference `0x7FFF - 0 = 0x7FFF` which is `<= 0x7FFF`, so this is correctly accepted. But the test asserts `diff > 0` (strictly greater), while the spec says "less than or equal to 0x7FFF" which includes the equal case. When `incoming == stored` (diff=0), the spec's first branch handles it (equal case). The `0x7FFF` case has diff > 0 which is correct.

Actually on re-analysis, the boundary tests are correct in their expectations. But the fundamental approach of using s16 differs from the spec's "unsigned difference" language. The spec says the **unsigned** difference `(ChannelSequence - Open.ChannelSequence) mod 2^16 <= 0x7FFF` means advance; `> 0x7FFF` means stale. Using s16: `(s16)(req - stored) >= 0` means advance (equivalent to unsigned diff <= 0x7FFF), `(s16)(req - stored) < 0` means stale (equivalent to unsigned diff > 0x7FFF). The implementations are mathematically equivalent.

**Revised assessment**: The test expectations (reject/accept decisions) are actually correct. The issue is the same as WRONG-2 -- the narrative around using s16 vs unsigned diff is misleading. I'll reclassify this from WRONG to QUESTIONABLE.

**Revised: QUESTIONABLE** (see QUESTIONABLE section below).

---

### QUESTIONABLE Findings (5)

#### Q-1: `ksmbd_test_regression_session.c` -- Channel sequence tests use s16 arithmetic

**Files**: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_session.c` (lines 157-217)

**Issue**: Tests `reg_channel_sequence_stale_reject` and `reg_channel_sequence_advance` verify s16 arithmetic for channel sequence validation. The spec at MS-SMB2 3.3.5.2.10 describes "unsigned difference using 16-bit arithmetic" with threshold 0x7FFF. The s16 approach is mathematically equivalent but uses a different conceptual model. The test expectations (accept/reject decisions) are correct, but a reader comparing the test code to the spec text would find a mismatch in methodology.

**Spec reference**: MS-SMB2 section 3.3.5.2.10.

#### Q-2: `ksmbd_test_timing_durable.c` -- DHv1 default timeout of 16000ms (16 seconds)

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_timing_durable.c` (line 124)

**Issue**: The test asserts DHv1 handles get a default timeout of 16000ms (16 seconds). The MS-SMB2 spec does not define a specific default for DHv1 reconnect timeout -- section 3.3.5.9.7 does not mandate a specific timeout value. The spec only says the durable open scavenger timer controls how long the server keeps durable handles alive (section 3.3.2.2). The 16-second value appears to be an implementation choice matching Windows behavior rather than a spec requirement. This is valid for implementation testing but not a spec-mandated value.

**Spec reference**: MS-SMB2 sections 3.3.5.9.7 and 3.3.2.2.

#### Q-3: `ksmbd_test_timing_durable.c` -- DHv2 zero-timeout default of 60000ms

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_timing_durable.c` (line 107)

**Issue**: The test asserts that when client timeout is zero, the server default is 60000ms (60 seconds). Per MS-SMB2 3.3.5.9.10, footnote <344>: "If the Timeout value in the request is zero and Share.CATimeout is zero, Windows 8 and Windows Server 2012 SMB2 servers set Timeout to 60 seconds." This is documented as Windows behavior, not a protocol requirement. The spec says the value "SHOULD be set to an implementation-specific value." The test is verifying a specific implementation choice, not a spec mandate.

**Spec reference**: MS-SMB2 section 3.3.5.9.10, footnote <344>.

#### Q-4: `ksmbd_test_timing_oplock.c` -- OPLOCK_WAIT_TIME = 35 seconds

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_timing_oplock.c` (line 37)

**Issue**: The test asserts OPLOCK_WAIT_TIME = 35*HZ (35 seconds). Per MS-SMB2 3.3.2.1: "The server MUST wait for an interval of time greater than or equal to the oplock break acknowledgment timer. This timer MUST be smaller than the client Request Expiration time." Footnote <217>: "Windows SMB2 servers set this timer to 35 seconds." The 35-second value is Windows-specific, not a protocol requirement. The spec only requires the timer to be implementation-specific and smaller than the client request expiration.

**Spec reference**: MS-SMB2 section 3.3.2.1, footnote <217>.

#### Q-5: `ksmbd_test_regression_access.c` -- DESIRED_ACCESS_MASK = 0xF21F01FF

**File**: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_access.c` (line 37)

**Issue**: The DESIRED_ACCESS_MASK value 0xF21F01FF is an implementation-defined mask used to filter client-requested access rights. The MS-SMB2 spec does not define a specific "desired access mask" -- the server is expected to validate access against the underlying security descriptor. This mask is a ksmbd implementation detail (matching upstream kernel ksmbd behavior) rather than a spec-defined constant. The inclusion of FILE_SYNCHRONIZE (bit 20) is correct per MS-SMB2 and MEMORY.md notes that gentest requires `--target=win7` because of this.

**Spec reference**: Implementation-specific; no direct MS-SMB2 section defines this mask.

---

### Category-by-Category CORRECT Test Summary

The following test categories were audited and found CORRECT in their spec-facing assertions:

**Regression Lock Tests** (`ksmbd_test_regression_lock.c`, 8 tests): All lock-related tests correctly verify the production functions `smb2_lock_init()`, `smb2_set_flock_flags()`, `store_lock_sequence()`, and `check_lock_sequence()`. The bit extraction (low 4 bits = sequence number, upper 28 bits = index), array bounds (1-64), sentinel (0xFF), and replay detection (return 1) all match MS-SMB2 section 3.3.5.14 and section 2.2.26.

**Regression Negotiate Tests** (`ksmbd_test_regression_negotiate.c`, 9 tests): Dialect constants (SMB20_PROT_ID=0x0202, SMB21_PROT_ID=0x0210, SMB2X_PROT_ID=0x02FF), second negotiate rejection (3.3.5.3.1), duplicate context rejection (3.3.5.4), signing/compression count zero rejection (2.2.3.1.7, 2.2.3.1.3) all correct.

**Regression Compound Tests** (`ksmbd_test_regression_compound.c`, 3 tests): Compound error propagation, FID capture from CREATE and non-CREATE commands all correctly match MS-SMB2 3.3.5.2.7.2.

**Regression Oplock Tests** (`ksmbd_test_regression_oplock.c`, 4 tests): Directory lease R+H grant, lease copy, oplock level mapping all correctly exercise production functions.

**Regression VFS Tests** (`ksmbd_test_regression_vfs.c`, 6 tests): FD limit, inode hash, sanity check tests are internal implementation tests with no direct spec correlation (all CORRECT for their purpose).

**Regression Session Tests** (`ksmbd_test_regression_session.c`, 7 tests): SMB2_SESSION_FLAG_IS_NULL_LE=0x0002 matches spec section 2.2.6. Anonymous auth, encrypted session enforcement, durable reconnect v1 ClientGUID, and IPC pipe channel check skip are all correct. Channel sequence tests are QUESTIONABLE as noted above.

**Regression Access Tests** (`ksmbd_test_regression_access.c`, 8 tests): FILE_DELETE_ON_CLOSE requires DELETE access (correct per 3.3.5.9), odd NameLength rejection (UTF-16LE alignment), path traversal rejection, share name length limit -- all correct.

**Regression Full Tests** (`ksmbd_test_regression_full.c`, 45 tests): All constant verifications match spec where applicable. Two tests have WRONG/QUESTIONABLE naming issues as documented above. All remaining 43 tests CORRECT.

**Config Tests** (`ksmbd_test_config.c`, 10 tests): Internal configuration framework tests. No direct spec correlation. All CORRECT for their purpose.

**State Machine SMB2 Tests** (`ksmbd_test_state_machine_smb2.c`, ~30 tests): Self-contained state machine simulation matching MS-SMB2 3.3.5.1-3.3.5.14 state transitions. Uses locally redefined constants that match the real values. All CORRECT.

**State Machine SMB1 Tests** (`ksmbd_test_state_machine_smb1.c`, ~30 tests): Self-contained SMB1 state machine simulation. Includes SMB1-to-SMB2 upgrade path (wildcard dialect 0x02FF). All CORRECT per MS-SMB and MS-SMB2 3.3.5.4.

**Timing Durable Tests** (`ksmbd_test_timing_durable.c`, 17 tests): DURABLE_HANDLE_MAX_TIMEOUT=300000ms (300 seconds) matches MS-SMB2 3.3.5.9.10. DHv2 timeout clamping to min(request, 300s) matches spec. Two tests (DHv1 default 16s, DHv2 zero-timeout default 60s) are QUESTIONABLE as noted above. Remaining 15 tests CORRECT.

**Timing Oplock Tests** (`ksmbd_test_timing_oplock.c`, 13 tests): OPLOCK_WAIT_TIME=35*HZ is QUESTIONABLE (implementation-specific). Break timeout behavior, state constants, pending break bit protocol, lease/oplock timer equivalence all correctly reflect the implementation. 12 tests CORRECT, 1 QUESTIONABLE.

**Timing Session Tests** (`ksmbd_test_timing_session.c`, 14 tests): SMB2_SESSION_TIMEOUT=10*HZ, session idle detection, deadtime handling, open files preventing timeout, session state-based expiry -- all internal implementation tests. CORRECT.

**Timing Transport Tests** (`ksmbd_test_timing_transport.c`, 16 tests): TCP recv/send timeouts, IPC timeout, deadtime overflow, socket backlog, connection hash sizing -- all internal implementation constants. CORRECT.

**Perf Tests** (4 files, 43 benchmarks total): `ksmbd_test_perf_data_structures.c` (8), `ksmbd_test_perf_crypto.c` (13), `ksmbd_test_perf_pdu.c` (8), `ksmbd_test_perf_compression.c` (14). Performance benchmarks do not make spec compliance assertions. All CORRECT for their purpose (benchmarking).

---

### Final Count

| Classification | Count | Details |
|---|---|---|
| **WRONG** | 2 | Lock bit naming (WRONG-1), Channel sequence comment (WRONG-2) |
| **QUESTIONABLE** | 5 | Channel sequence s16 vs unsigned (Q-1), DHv1 16s default (Q-2), DHv2 60s default (Q-3), Oplock 35s timer (Q-4), DESIRED_ACCESS_MASK value (Q-5) |
| **CORRECT** | 245 | All remaining tests |
| **Total** | 252 | Across 20 test files |

The two WRONG findings are both **documentation/naming errors** in the test code that do not affect the actual correctness of the assertions (the bit patterns and accept/reject decisions are correct). The five QUESTIONABLE findings reflect implementation-specific values that are valid choices but not mandated by the protocol specification.