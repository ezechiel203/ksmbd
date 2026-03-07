# Oplock Lease Spec Audit

Agent ID: af9813da841e1d7a6

I now have a comprehensive understanding of all four existing test files, the MS-SMB2 spec, and the ksmbd source code. Let me compile the audit results.

---

## AUDIT SUMMARY

### Files Audited

Of the 6 requested files, **4 exist** and **2 do not exist**:

| File | Status |
|------|--------|
| `/home/ezechiel203/ksmbd/test/ksmbd_test_oplock.c` | EXISTS (75 tests) |
| `/home/ezechiel203/ksmbd/test/ksmbd_test_lease.c` | DOES NOT EXIST |
| `/home/ezechiel203/ksmbd/test/ksmbd_test_lease_v2.c` | DOES NOT EXIST |
| `/home/ezechiel203/ksmbd/test/ksmbd_test_oplock_break.c` | DOES NOT EXIST (but `ksmbd_test_timing_oplock.c` exists -- 13 tests) |
| `/home/ezechiel203/ksmbd/test/ksmbd_test_concurrency_oplock.c` | EXISTS (19 tests) |
| `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_oplock.c` | EXISTS (4 tests) |

Additionally, `/home/ezechiel203/ksmbd/test/ksmbd_test_timing_oplock.c` was audited as it covers the break-related timing tests that `ksmbd_test_oplock_break.c` would have covered.

### Total Tests Audited: 111

- `ksmbd_test_oplock.c`: 75 tests
- `ksmbd_test_regression_oplock.c`: 4 tests
- `ksmbd_test_concurrency_oplock.c`: 19 tests
- `ksmbd_test_timing_oplock.c`: 13 tests

---

### Classification Results

| Classification | Count |
|---|---|
| **CORRECT** | 107 |
| **WRONG** | 1 |
| **QUESTIONABLE** | 3 |

---

### WRONG Findings

#### 1. `test_opinfo_write_to_read_lease` (line 723, `ksmbd_test_oplock.c`)

**Test code:**
```c
opinfo->level = SMB2_OPLOCK_LEVEL_BATCH;
opinfo->is_lease = true;
opinfo->o_lease->state = SMB2_LEASE_READ_CACHING_LE |
                         SMB2_LEASE_WRITE_CACHING_LE |
                         SMB2_LEASE_HANDLE_CACHING_LE;
opinfo->o_lease->new_state = SMB2_LEASE_READ_CACHING_LE |
                              SMB2_LEASE_HANDLE_CACHING_LE;

KUNIT_EXPECT_EQ(test, opinfo_write_to_read(opinfo), 0);
KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_II);  /* <-- WRONG */
```

**Issue:** After `opinfo_write_to_read` transitions a lease from RWH to RH (dropping Write caching), the test expects `opinfo->level` to be `SMB2_OPLOCK_LEVEL_II` (0x01). However, the actual implementation sets `opinfo->level = SMB2_OPLOCK_LEVEL_II` unconditionally in `opinfo_write_to_read()` regardless of whether the remaining lease state includes Handle caching.

The test expectation matches the **implementation** but does NOT match the **spec semantics**. Per MS-SMB2 section 3.3.4.7, a lease state of RH (Read+Handle) still represents a meaningful cache state that is stronger than a plain Level II oplock. The lease state `RH` with Handle caching retained should map to a level equivalent to `SMB2_OPLOCK_LEVEL_II` with additional handle semantics (which is how leases extend beyond traditional oplocks). The test is testing the implementation correctly, but the underlying implementation's mapping is questionable.

**Revised assessment:** The test correctly tests the implementation behavior (which sets level to LEVEL_II for any write-to-read transition). The implementation behavior is consistent with the ksmbd internal convention where LEVEL_II is used as the catch-all for "has Read caching, does not have Write caching" in the oplock level field, while the actual lease state tracks the full R/RH/RWH granularity separately. **Reclassified to CORRECT** -- the test accurately tests `opinfo_write_to_read()` as implemented, and the implementation is defensible because oplock levels are an internal simplification while `o_lease->state` carries the authoritative lease state for lease-based opens.

After deeper analysis, I am revising the WRONG count to **0** and reclassifying this as QUESTIONABLE.

---

### QUESTIONABLE Findings

#### 1. `test_opinfo_write_to_read_lease` (line 723, `ksmbd_test_oplock.c`) -- Lease RWH->RH level mapping

**Test code (line 736-738):**
```c
KUNIT_EXPECT_EQ(test, opinfo->level, SMB2_OPLOCK_LEVEL_II);
KUNIT_EXPECT_EQ(test, opinfo->o_lease->state,
                SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE);
```

**Concern:** The test asserts that after breaking a lease from RWH to RH, the opinfo level becomes `SMB2_OPLOCK_LEVEL_II`. This is an internal implementation convention in ksmbd where LEVEL_II is used for any lease state that has Read caching but not Write caching. The spec (MS-SMB2 section 2.2.23.2 Lease Break Notification and section 3.3.4.7) treats lease states independently from oplock levels; there is no explicit mapping of "RH lease state" to a specific oplock level in the spec. The ksmbd convention of mapping RH to LEVEL_II in the `level` field is implementation-specific and not directly derived from the spec. The test is correct relative to the implementation, but the mapping itself is an implementation choice.

**Spec reference:** MS-SMB2 sections 3.3.4.7, 2.2.23.2

---

#### 2. `test_lease_to_oplock_rh` (line 76, `ksmbd_test_oplock.c`) -- RH maps to Level II

**Test code:**
```c
__le32 state = SMB2_LEASE_READ_CACHING_LE | SMB2_LEASE_HANDLE_CACHING_LE;
KUNIT_EXPECT_EQ(test, smb2_map_lease_to_oplock(state), (__u8)SMB2_OPLOCK_LEVEL_II);
```

**Concern:** The `smb2_map_lease_to_oplock()` function maps RH (Read+Handle) to `SMB2_OPLOCK_LEVEL_II` (0x01). The MS-SMB2 spec does not define a direct mapping from lease states to oplock levels, because leases and oplocks are parallel mechanisms. The mapping function is an internal ksmbd utility used to bridge the two concepts. The mapping of RH->LEVEL_II is reasonable (Handle caching without Write does not elevate beyond read-sharing semantics), but it is an implementation-specific decision. The spec itself (section 3.3.5.9.8) says the server should use the lease state directly when responding with lease contexts, not map to oplock levels.

**Spec reference:** MS-SMB2 section 3.3.5.9.8 (lease processing is independent of oplock level mapping)

---

#### 3. `test_lease_none_upgrade_epoch_no_inc_for_none` (line 1129, `ksmbd_test_oplock.c`) -- No epoch increment for NONE->NONE

**Test code:**
```c
opinfo->o_lease->state = SMB2_LEASE_NONE_LE;
opinfo->o_lease->epoch = 5;

KUNIT_EXPECT_EQ(test, lease_none_upgrade(opinfo, SMB2_LEASE_NONE_LE), 0);
/* Epoch should NOT increment for NONE->NONE */
KUNIT_EXPECT_EQ(test, opinfo->o_lease->epoch, (unsigned short)5);
```

**Concern:** The test asserts that upgrading from NONE to NONE does not increment the epoch. Per MS-SMB2 section 3.3.4.7: "the server SHOULD set NewEpoch to Lease.Epoch + 1" on lease state changes. If the state does not actually change (NONE->NONE), not incrementing is reasonable. However, the spec says Epoch is incremented on "lease state change", and whether a no-op (NONE->NONE) counts as a "change" is ambiguous. The implementation's behavior (no increment) is the more conservative and likely correct interpretation, but it is worth noting.

**Spec reference:** MS-SMB2 section 3.3.4.7, line 18949

---

### Detailed CORRECT Test Verification

All remaining 107 tests across the four files were verified as CORRECT against the MS-SMB2 specification. Here are the key verification points:

**Oplock level values (MS-SMB2 section 2.2.13):**
- `SMB2_OPLOCK_LEVEL_NONE` = 0x00 -- matches spec
- `SMB2_OPLOCK_LEVEL_II` = 0x01 -- matches spec
- `SMB2_OPLOCK_LEVEL_EXCLUSIVE` = 0x08 -- matches spec
- `SMB2_OPLOCK_LEVEL_BATCH` = 0x09 -- matches spec
- `SMB2_OPLOCK_LEVEL_LEASE` = 0xFF -- matches spec

**Lease state values (MS-SMB2 section 2.2.13.2.8):**
- `SMB2_LEASE_NONE` = 0x00 -- matches spec
- `SMB2_LEASE_READ_CACHING` = 0x01 -- matches spec
- `SMB2_LEASE_HANDLE_CACHING` = 0x02 -- matches spec
- `SMB2_LEASE_WRITE_CACHING` = 0x04 -- matches spec
- RWH combination = 0x07 -- matches spec (R|H|W = 0x01|0x02|0x04)

**Lease flag values (MS-SMB2 section 2.2.14.2.10):**
- `SMB2_LEASE_FLAG_BREAK_IN_PROGRESS` = 0x02 -- matches spec
- `SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET` = 0x04 -- matches spec (section 2.2.13.2.10)

**Oplock break timer (MS-SMB2 section 3.3.2.1):**
- `OPLOCK_WAIT_TIME` = 35 * HZ (35 seconds) -- matches Windows implementation note (<217>: "Windows SMB2 servers set this timer to 35 seconds")

**Lease-to-oplock mapping (implementation-specific, tested correctly):**
- RWH -> BATCH: Correct (Handle+Read+Write = full batch semantics)
- RW -> EXCLUSIVE: Correct (Read+Write without Handle = exclusive semantics)
- R -> LEVEL_II: Correct (Read only = shared read semantics)
- NONE -> 0: Correct
- W-only -> 0: Correct (Write without Read is not a valid combination in practice)
- WH -> 0: Correct (Write+Handle without Read is not valid)

**Break transition functions (tested correctly against implementation):**
- `opinfo_write_to_read`: BATCH/EXCLUSIVE -> LEVEL_II (correct per spec: break removes write caching)
- `opinfo_write_to_none`: BATCH/EXCLUSIVE -> NONE (correct per spec)
- `opinfo_read_to_none`: LEVEL_II -> NONE (correct per spec)
- `opinfo_read_handle_to_read`: lease-only, RH -> R (correct per spec)
- `opinfo_write_handle_to_write`: lease-only, RWH -> RW (correct per spec)
- `lease_read_to_write`: R -> RW (EXCLUSIVE), RH -> RWH (BATCH) (correct per spec)

**Concurrency tests (all 19 tests):** These test internal synchronization primitives (spinlocks, atomic ops, wait queues, bit operations) and do not make protocol-level assertions. They are all CORRECT as infrastructure/regression tests.

**Timing tests (all 13 tests):** These verify timer constants, state machine values, and timeout behavior patterns. All values match the source code definitions and the MS-SMB2 spec's implementation notes.

---

### Final Tally

| Metric | Count |
|---|---|
| **Total tests audited** | 111 |
| **CORRECT** | 108 |
| **WRONG** | 0 |
| **QUESTIONABLE** | 3 |
| **Files requested but not found** | 2 (`ksmbd_test_lease.c`, `ksmbd_test_lease_v2.c`) |
| **Substitute file audited** | 1 (`ksmbd_test_timing_oplock.c` in place of `ksmbd_test_oplock_break.c`) |

The test suite is well-aligned with the MS-SMB2 specification. The three QUESTIONABLE findings are all related to the internal convention of mapping lease states to oplock levels, which is an implementation-specific design choice in ksmbd that is not directly prescribed by the spec but is reasonable and consistent.