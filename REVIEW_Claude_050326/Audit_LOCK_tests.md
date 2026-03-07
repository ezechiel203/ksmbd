# Audit Lock Tests

Agent ID: a314a11d8a6e7d98f

Now I have all the information I need. Let me compile the comprehensive audit report.

---

# Audit Report: ksmbd Lock Test Files vs. MS-SMB2 Specification

## Reference Specification Sections
- **MS-SMB2 Section 2.2.26**: SMB2 LOCK Request (StructureSize = 48)
- **MS-SMB2 Section 2.2.26.1**: SMB2_LOCK_ELEMENT Structure (Flag values)
- **MS-SMB2 Section 2.2.27**: SMB2 LOCK Response (StructureSize = 4)
- **MS-SMB2 Section 3.3.5.14**: Receiving an SMB2 LOCK Request (lock sequence, flag validation)
- **MS-SMB2 Section 3.3.5.14.1**: Processing Unlocks
- **MS-SMB2 Section 3.3.5.14.2**: Processing Locks

## Spec Constants Verified

From the spec (Section 2.2.26.1):
- `SMB2_LOCKFLAG_SHARED_LOCK` = `0x00000001`
- `SMB2_LOCKFLAG_EXCLUSIVE_LOCK` = `0x00000002`
- `SMB2_LOCKFLAG_UNLOCK` = `0x00000004`
- `SMB2_LOCKFLAG_FAIL_IMMEDIATELY` = `0x00000010`

From the production header `/home/ezechiel203/ksmbd/src/include/protocol/smb2pdu.h` (lines 1253-1260):
- `SMB2_LOCKFLAG_SHARED` = `0x0001` -- matches spec
- `SMB2_LOCKFLAG_EXCLUSIVE` = `0x0002` -- matches spec
- `SMB2_LOCKFLAG_UNLOCK` = `0x0004` -- matches spec
- `SMB2_LOCKFLAG_FAIL_IMMEDIATELY` = `0x0010` -- matches spec

From the spec (Section 2.2.26): StructureSize (Request) = 48. Confirmed in `smb2pdu.h` line 1271.
From the spec (Section 2.2.27): StructureSize (Response) = 4. Confirmed in `smb2pdu.h` line 1288.

Lock Sequence Layout (Section 2.2.26):
- `LockSequenceNumber`: 4 least significant bits (bits 0-3)
- `LockSequenceIndex`: upper 28 bits (bits 4-31), valid range 1-64

---

## File 1: `/home/ezechiel203/ksmbd/test/ksmbd_test_smb2_lock.c`

### Suite: `ksmbd_smb2_lock` (41 test cases)

#### smb2_set_flock_flags() Tests

**1. `test_set_flock_shared`** (line 27)
- Tests: `SMB2_LOCKFLAG_SHARED` maps to `F_SETLKW` + `F_RDLCK`
- Spec ref: Section 2.2.26.1 -- shared lock means read-allowing lock. Section 3.3.5.14.2 -- without FAIL_IMMEDIATELY, lock can block (F_SETLKW).
- **Verdict: CORRECT**

**2. `test_set_flock_exclusive`** (line 43)
- Tests: `SMB2_LOCKFLAG_EXCLUSIVE` maps to `F_SETLKW` + `F_WRLCK`
- Spec ref: Section 2.2.26.1 -- exclusive lock prevents read/write/lock by other opens.
- **Verdict: CORRECT**

**3. `test_set_flock_shared_fail_immediately`** (line 59)
- Tests: `SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY` maps to `F_SETLK` + `F_RDLCK`
- Spec ref: Section 2.2.26.1 -- valid combination; FAIL_IMMEDIATELY means non-blocking (F_SETLK).
- **Verdict: CORRECT**

**4. `test_set_flock_exclusive_fail_immediately`** (line 76)
- Tests: `SMB2_LOCKFLAG_EXCLUSIVE | SMB2_LOCKFLAG_FAIL_IMMEDIATELY` maps to `F_SETLK` + `F_WRLCK`
- Spec ref: Section 2.2.26.1 -- valid combination.
- **Verdict: CORRECT**

**5. `test_set_flock_unlock`** (line 93)
- Tests: `SMB2_LOCKFLAG_UNLOCK` maps to `F_SETLK` + `F_UNLCK`
- Spec ref: Section 2.2.26.1 -- valid; unlocking never blocks (F_SETLK is correct).
- **Verdict: CORRECT**

**6. `test_set_flock_invalid_flags`** (line 109)
- Tests: flags `0xFF` returns `-EINVAL`
- Spec ref: Section 3.3.5.14.2 -- "For combinations of Lock Flags other than those that are defined in the Flags field of section 2.2.26.1, the server SHOULD fail the request with STATUS_INVALID_PARAMETER."
- **Verdict: CORRECT**

**7. `test_set_flock_shared_has_sleep`** (line 120)
- Tests: `SMB2_LOCKFLAG_SHARED` sets `FL_SLEEP` flag
- Spec ref: Without FAIL_IMMEDIATELY, the lock may block waiting, requiring FL_SLEEP for POSIX semantics.
- **Verdict: CORRECT**

**8. `test_set_flock_exclusive_has_sleep`** (line 134)
- Tests: `SMB2_LOCKFLAG_EXCLUSIVE` sets `FL_SLEEP` flag
- **Verdict: CORRECT** (same rationale as above)

**9. `test_set_flock_fail_immediately_no_sleep`** (line 148)
- Tests: `SMB2_LOCKFLAG_SHARED | SMB2_LOCKFLAG_FAIL_IMMEDIATELY` does NOT set `FL_SLEEP`
- Spec ref: FAIL_IMMEDIATELY means fail immediately on conflict, no blocking/sleep.
- **Verdict: CORRECT**

#### smb2_lock_init() Tests

**10. `test_lock_init_basic`** (line 165)
- Tests: Lock init stores cmd=F_SETLKW, start=100, end=200, flags=EXCLUSIVE, zero_len=0
- Production code stores unclamped SMB range (start, end are offset/end of SMB range).
- **Verdict: CORRECT**

**11. `test_lock_init_zero_len`** (line 187)
- Tests: When start==end (500==500), zero_len is set to 1
- Per production code (line 389): `if (lock->start == lock->end) lock->zero_len = 1;`
- **Verdict: CORRECT**

**12. `test_lock_init_large_range`** (line 204)
- Tests: offset=0, end=~0ULL -- full 64-bit range, zero_len=0
- **Verdict: CORRECT**

**13. `test_lock_init_multiple`** (line 223)
- Tests: Two locks added to same list, count is 2
- **Verdict: CORRECT**

**14. `test_lock_init_lists_initialized`** (line 252)
- Tests: clist and flist are initialized as empty heads
- Matches production code (lines 391-392): `INIT_LIST_HEAD(&lock->clist); INIT_LIST_HEAD(&lock->flist);`
- **Verdict: CORRECT**

#### check_lock_sequence() / store_lock_sequence() Tests

**15. `test_lock_seq_index_zero_skipped`** (line 273)
- Tests: LockSequenceIndex=0 (reserved) causes skip (return 0, proceed with lock)
- Spec ref: Section 3.3.5.14 -- "LockSequenceIndex is 0... the server MUST continue lock/unlock processing."
- Encoding: `cpu_to_le32(0x00000005)` -> val=5, seq_num=5&0xF=5, seq_idx=5>>4=0. Index=0.
- **Verdict: CORRECT**

**16. `test_lock_seq_replay_detected`** (line 288)
- Tests: After store(index=1, seq=3), check(index=1, seq=3) returns 1 (replay)
- Encoding: `(1 << 4) | 3` = 0x13. seq_num=3, seq_idx=1.
- Spec ref: Section 3.3.5.14 -- "If the sequence numbers are equal, success is returned to the client without further processing."
- **Verdict: CORRECT**

**17. `test_lock_seq_different_seq_num`** (line 306)
- Tests: After store(index=2, seq=5), check(index=2, seq=7) returns 0 (invalidate and proceed)
- Spec ref: Section 3.3.5.14 -- "If the sequence numbers are not equal, the server MUST reset the entry by setting Open.LockSequenceArray[LockSequenceIndex].Valid to FALSE and continue with regular processing."
- **Verdict: CORRECT**

**18. `test_lock_seq_not_resilient_skipped`** (line 323)
- Tests: Non-resilient/non-durable/non-persistent handle always skips validation (returns 0)
- Spec ref: Section 3.3.5.14 -- "if Open.IsResilient or Open.IsDurable or Open.IsPersistent is TRUE... the server SHOULD perform lock sequence verification"
- **Verdict: CORRECT**

**19. `test_lock_seq_index_out_of_range`** (line 340)
- Tests: index=65 (>64, out of range) returns 0 (skip)
- Spec ref: Section 3.3.5.14 -- "If the index exceeds the maximum extent of the Open.LockSequenceArray"
- Section 2.2.26 says LockSequenceIndex range is 0 to 64.
- **Verdict: CORRECT**

**20. `test_lock_seq_index_64_valid`** (line 355)
- Tests: index=64 is the maximum valid index, replay works
- Spec ref: Section 2.2.26 -- "a value from 0 to 64, where 0 is reserved", so 64 is the max valid non-reserved index.
- **Verdict: CORRECT**

**21. `test_lock_seq_durable_handle`** (line 371)
- Tests: Durable handle validates lock sequence
- Spec ref: Section 3.3.5.14 -- "Open.IsDurable... is TRUE"
- **Verdict: CORRECT**

**22. `test_lock_seq_persistent_handle`** (line 387)
- Tests: Persistent handle validates lock sequence
- Spec ref: Section 3.3.5.14 -- "Open.IsPersistent is TRUE"
- **Verdict: CORRECT**

**23. `test_lock_seq_store_skips_non_resilient`** (line 403)
- Tests: store_lock_sequence is a no-op for non-resilient/non-durable/non-persistent handles
- Spec ref: Sections 3.3.5.14.1/3.3.5.14.2 -- lock sequence is only stored "if Open.IsResilient or Open.IsDurable, or Open.IsPersistent is TRUE or Connection.ServerCapabilities includes the SMB2_GLOBAL_CAP_MULTI_CHANNEL bit"
- **Verdict: CORRECT** (Note: the test does not cover the MULTI_CHANNEL case, which is a coverage gap but the test itself is not wrong)

**24. `test_lock_seq_store_skips_index_zero`** (line 421)
- Tests: store at index 0 is a no-op
- Matches production code behavior (line 482): `if (seq_idx == 0 || seq_idx > 64) return;`
- **Verdict: CORRECT**

**25. `test_lock_seq_all_seq_nums`** (line 436)
- Tests: All 16 sequence numbers (0-15) at index 1 work correctly
- Spec ref: Section 2.2.26 -- LockSequenceNumber is 4 bits, so values 0-15.
- **Verdict: CORRECT**

#### smb2_validate_lock_range() Tests

**26. `test_lock_range_normal`** (line 457)
- Tests: offset=0, length=100 is valid
- **Verdict: CORRECT**

**27. `test_lock_range_zero_length`** (line 462)
- Tests: Zero-length lock at any offset is valid
- **Verdict: CORRECT** (SMB2 allows zero-length locks)

**28. `test_lock_range_max_offset_len_one`** (line 468)
- Tests: offset=~0ULL, length=1 wraps to exactly 0, considered valid
- **Verdict: CORRECT** (wraps to 0 is the boundary case)

**29. `test_lock_range_overflow`** (line 474)
- Tests: offset=~0ULL, length=2 overflows, returns -EINVAL
- **Verdict: CORRECT**

**30. `test_lock_range_large_valid`** (line 480)
- Tests: offset=0, length=~0ULL is valid
- **Verdict: CORRECT**

**31. `test_lock_range_half_max`** (line 487)
- Tests: offset=0x8000000000000000, length=0x8000000000000000 wraps to 0, valid
- **Verdict: CORRECT**

**32. `test_lock_range_near_wrap`** (line 494)
- Tests: offset=0xFFFFFFFFFFFFFFFE, length=3 wraps to 1, invalid
- **Verdict: CORRECT**

**33. `test_lock_range_exact_wrap_to_zero`** (line 501)
- Tests: offset=0xFFFFFFFFFFFFFFFE, length=2 wraps to exactly 0, valid
- **Verdict: CORRECT**

#### smb2_validate_lock_flag_mix() Tests

**34. `test_flag_mix_lock_then_lock`** (line 510)
- Tests: SHARED then EXCLUSIVE in same request array is valid (both are locks)
- Spec ref: Section 3.3.5.14 -- "If the flags of the initial SMB2_LOCK_ELEMENT in the Locks array of the request has SMB2_LOCKFLAG_UNLOCK set, the server MUST process the lock array as a series of unlocks. Otherwise, it MUST process the lock array as a series of lock requests." Section 3.3.5.14.2 -- "if SMB2_LOCKFLAG_UNLOCK is set, the server MUST fail the request with STATUS_INVALID_PARAMETER"
- **Verdict: CORRECT**

**35. `test_flag_mix_lock_then_unlock`** (line 517)
- Tests: SHARED then UNLOCK is invalid (mixing locks and unlocks)
- Spec ref: Section 3.3.5.14 -- the first element determines whether the array is locks or unlocks. Section 3.3.5.14.2 says UNLOCK in a lock array -> STATUS_INVALID_PARAMETER.
- **Verdict: CORRECT**

**36. `test_flag_mix_exclusive_then_unlock`** (line 524)
- Tests: EXCLUSIVE then UNLOCK is invalid
- **Verdict: CORRECT** (same rationale)

**37. `test_flag_mix_unlock_then_lock`** (line 531)
- Tests: UNLOCK then SHARED is invalid
- Spec ref: Section 3.3.5.14.1 -- "if either SMB2_LOCKFLAG_SHARED_LOCK or SMB2_LOCKFLAG_EXCLUSIVE_LOCK is set, the server MUST fail the request with STATUS_INVALID_PARAMETER"
- **Verdict: CORRECT**

**38. `test_flag_mix_unlock_then_unlock`** (line 538)
- Tests: UNLOCK then UNLOCK is valid (all unlocks)
- **Verdict: CORRECT**

**39. `test_flag_mix_first_element`** (line 545)
- Tests: With no previous element (prior_lock=0), any flag is valid
- **Verdict: CORRECT** (first element determines mode)

**40. `test_flag_mix_shared_fail_imm_then_unlock`** (line 556)
- Tests: SHARED|FAIL_IMMEDIATELY then UNLOCK is invalid (shared bit set in lock mode, then unlock)
- **Verdict: CORRECT**

#### smb2_validate_lock_flags() Tests

**41. `test_lock_flags_shared_valid`** (line 566)
- **Verdict: CORRECT** (valid per Section 2.2.26.1)

**42. `test_lock_flags_exclusive_valid`** (line 571)
- **Verdict: CORRECT**

**43. `test_lock_flags_unlock_valid`** (line 576)
- **Verdict: CORRECT**

**44. `test_lock_flags_fail_immediately_alone`** (line 581)
- Tests: FAIL_IMMEDIATELY alone (0x10) is valid
- Spec ref: Section 2.2.26.1 lists valid combinations: SHARED, EXCLUSIVE, SHARED|FAIL_IMM, EXCLUSIVE|FAIL_IMM, UNLOCK. FAIL_IMMEDIATELY alone is NOT in the valid combinations list.
- **Verdict: QUESTIONABLE** -- Per the spec (Section 2.2.26.1), FAIL_IMMEDIATELY alone is NOT a valid combination. The five valid combinations are explicitly listed and do not include FAIL_IMMEDIATELY by itself. However, the production code uses a bitmask approach (`SMB2_LOCKFLAG_MASK`) that accepts FAIL_IMMEDIATELY alone, and Section 3.3.5.14.2 says "SHOULD fail" (not MUST) for invalid combinations. The test is consistent with the production code, but the production code's validation is permissive compared to the spec. This is a spec-deviation-by-design, but worth noting.

**45. `test_lock_flags_zero_invalid`** (line 588)
- Tests: flags=0 is invalid
- **Verdict: CORRECT** (0 is not in the valid combinations)

**46. `test_lock_flags_invalid_bits`** (line 593)
- Tests: 0x08 (bit outside the mask) is invalid
- **Verdict: CORRECT**

**47. `test_lock_flags_combined_valid`** (line 599)
- Tests: EXCLUSIVE|FAIL_IMMEDIATELY is valid
- **Verdict: CORRECT** (valid per Section 2.2.26.1)

---

## File 2: `/home/ezechiel203/ksmbd/test/ksmbd_test_error_lock.c`

### Suite: `ksmbd_error_lock` (12 test cases)

**1. `test_err_flock_zero_flags`** (line 25)
- Tests: flags=0 returns -EINVAL
- **Verdict: CORRECT**

**2. `test_err_flock_shared_and_exclusive`** (line 35)
- Tests: SHARED|EXCLUSIVE returns -EINVAL
- Spec ref: Section 2.2.26.1 -- not a valid combination.
- **Verdict: CORRECT**

**3. `test_err_flock_unlock_and_shared`** (line 47)
- Tests: UNLOCK|SHARED returns -EINVAL
- **Verdict: CORRECT** (not a valid combination)

**4. `test_err_flock_unlock_and_fail_immediately`** (line 59)
- Tests: UNLOCK|FAIL_IMMEDIATELY returns -EINVAL
- Spec ref: Section 2.2.26.1 -- not a valid combination (UNLOCK alone is the only UNLOCK combo).
- **Verdict: CORRECT**

**5. `test_err_flock_all_flags`** (line 71)
- Tests: all four flags set returns -EINVAL
- **Verdict: CORRECT**

**6. `test_err_flock_high_bits_only`** (line 83)
- Tests: 0xF0 returns -EINVAL
- **Verdict: CORRECT**

**7. `test_err_lock_seq_zero_value`** (line 96)
- Tests: val=0 -> index=0 (reserved), returns 0 (skip)
- Spec ref: Section 3.3.5.14 -- "LockSequenceIndex is 0... continue lock/unlock processing"
- **Verdict: CORRECT**

**8. `test_err_lock_seq_max_value`** (line 111)
- Tests: val=0xFFFFFFFF -> index=0x0FFFFFFF (way beyond 64), returns 0 (skip)
- Spec ref: Section 3.3.5.14 -- "If the index exceeds the maximum extent of the Open.LockSequenceArray"
- **Verdict: CORRECT**

**9. `test_err_store_seq_index_zero_noop`** (line 126)
- Tests: store at index 0 is no-op
- **Verdict: CORRECT**

**10. `test_err_store_seq_not_durable_noop`** (line 142)
- Tests: store is no-op for non-durable handles
- **Verdict: CORRECT**

**11. `test_err_store_seq_index_65_noop`** (line 158)
- Tests: store at index 65 (out of range) is no-op
- **Verdict: CORRECT**

**12. `test_err_lock_init_max_values`** (line 174)
- Tests: start=~0ULL, end=~0ULL -> zero_len=1 (start==end)
- **Verdict: CORRECT**

---

## File 3: `/home/ezechiel203/ksmbd/test/ksmbd_test_concurrency_lock.c`

### Suite: `ksmbd_concurrency_lock` (5 test cases)

This file tests generic kernel locking primitives (spinlock, rwlock, mutex, trylock), NOT SMB2 lock protocol behavior. It does not test any SMB2-specific flag values, StructureSize, lock sequences, or protocol behavior.

**1. `test_spinlock_parallel_increment`** (line 46)
- Tests: kernel spinlock correctness under parallel access
- **Verdict: CORRECT** (not protocol-related; infrastructure test)

**2. `test_rwlock_readers_writers`** (line 126)
- Tests: kernel rwlock correctness
- **Verdict: CORRECT** (infrastructure test)

**3. `test_mutex_parallel_increment`** (line 188)
- Tests: kernel mutex correctness
- **Verdict: CORRECT** (infrastructure test)

**4. `test_trylock_contention`** (line 245)
- Tests: kernel spin_trylock behavior
- **Verdict: CORRECT** (infrastructure test)

**5. `test_lock_basic_spinlock`** (line 279)
- Tests: basic spinlock init/lock/unlock
- **Verdict: CORRECT** (infrastructure test)

**Note:** These tests do not validate any MS-SMB2 protocol behavior. They are pure kernel-infrastructure concurrency tests. While useful for ensuring the concurrency primitives used by ksmbd are sound, they have no spec assertions to audit.

---

## File 4: `/home/ezechiel203/ksmbd/test/ksmbd_test_concurrency_lock_race.c`

### Suite: `ksmbd_concurrency_lock_race` (16 test cases)

This file uses **simulated** structures (struct test_lock, struct test_file) rather than calling production code. The flag values are re-defined as local constants. Let me verify those constants match the spec.

Local constants (lines 33-36):
- `TEST_LOCKFLAG_SHARED` = `0x0001` -- matches spec
- `TEST_LOCKFLAG_EXCLUSIVE` = `0x0002` -- matches spec
- `TEST_LOCKFLAG_UNLOCK` = `0x0004` -- matches spec
- `TEST_LOCKFLAG_FAIL_IMMEDIATELY` = `0x0010` -- matches spec
- `LOCK_SEQ_INVALID` = `0xFF` -- matches production sentinel
- `LOCK_SEQ_MAX` = `64` -- matches spec (indices 1-64)

**1. `test_same_range_exclusive_race`** (line 267)
- Tests: Two threads racing for exclusive lock on [0,1023]; exactly one wins
- Spec ref: Section 2.2.26.1 -- exclusive lock prevents read/write/lock by other opens. Section 3.3.5.14.2 -- conflicting lock fails.
- **Verdict: CORRECT**

**2. `test_lock_upgrade_race`** (line 370)
- Tests: Two threads hold shared locks, both try exclusive upgrade; both fail
- Spec ref: Section 2.2.26.1 -- shared allows other shared locks; exclusive blocks all. Upgrade = new exclusive on same range while other shared exists -> conflict.
- **Verdict: CORRECT**

**3. `test_lock_sequence_replay_concurrent`** (line 451)
- Tests: Concurrent lock sequence check/store on same bucket
- Uses simulated `check_lock_sequence_replay()` (NOT production code)
- **Verdict: QUESTIONABLE** -- The simulated `check_lock_sequence_replay()` (lines 198-212) does NOT check the `0xFF` sentinel value (LOCK_SEQ_INVALID). It compares `fp->lock_seq[bucket_idx] == seq_num` directly without first checking if the entry is Valid (not 0xFF). This means if the initialized sentinel (0xFF) happens to equal `seq_num`, it would falsely report a replay. However, in this test `seq=42`, which is not 0xFF, so the test itself would pass correctly. But the simulated function's logic diverges from the production code's spec-compliant behavior. The test exercises concurrency properties adequately but the simulation is imprecise compared to the spec.

**4. `test_unlock_during_lock_acquisition`** (line 547)
- Tests: Concurrent lock/unlock maintains invariant (remaining = acquired - released)
- **Verdict: CORRECT**

**5. `test_byte_range_overlap`** (line 657)
- Tests: Overlapping ranges [0,511] and [256,767] conflict for exclusive locks
- The `ranges_overlap()` function (line 110) uses `s1 > e2 || s2 > e1` as the non-overlap check. This uses inclusive-end semantics.
- **Verdict: CORRECT** (matches the corrected overlap logic)

**6. `test_lock_and_read_atomicity`** (line 765)
- Tests: No torn reads during lock transitions
- **Verdict: CORRECT** (infrastructure test, not protocol-specific)

**7. `test_deadlock_detection`** (line 905)
- Tests: Two threads locking ranges in opposite order; at least one fails with try-style locking
- Spec ref: Section 2.2.26.1 + FAIL_IMMEDIATELY semantics -- try-lock avoids deadlocks.
- **Verdict: CORRECT**

**8. `test_lock_list_iteration_safety`** (line 1024)
- Tests: Concurrent list enumeration and modification doesn't corrupt
- **Verdict: CORRECT** (infrastructure test)

**9. `test_shared_vs_exclusive_coexistence`** (line 1142)
- Tests: Multiple shared locks on same range succeed; subsequent exclusive fails
- Spec ref: Section 2.2.26.1 -- shared "allowing other opens to read from or take a shared lock"; exclusive "not allowing other opens to read, write, or lock within the range."
- **Verdict: CORRECT**

**10. `test_lock_count_limit_concurrent`** (line 1235)
- Tests: Lock count enforced under concurrent load (MAX_LOCK_COUNT=64)
- **Verdict: CORRECT** (implementation-specific limit test)

**11. `test_lock_seq_bucket_isolation`** (line 1318)
- Tests: Different threads writing to different lock_seq buckets don't interfere
- Uses simulated `store_lock_sequence()` matching spec behavior
- **Verdict: CORRECT**

**12. `test_shared_lock_scalability`** (line 1390)
- Tests: All shared locks on same range succeed (no conflicts)
- Spec ref: Section 2.2.26.1 -- "Other locks can be requested and taken on this range" for shared.
- **Verdict: CORRECT**

**13. `test_lock_seq_overwrite_race`** (line 1459)
- Tests: Multiple threads writing different sequence numbers to same bucket; final value is valid (not sentinel)
- **Verdict: CORRECT**

**14. `test_zero_length_lock_conflict`** (line 1496)
- Tests: Zero-length exclusive lock at offset 100 conflicts with another zero-length exclusive at same offset, and with a zero-length shared lock
- The simulated `lock_conflicts()` uses `ranges_overlap(100, 100, 100, 100)` which returns true (since !(100>100) && !(100>100)).
- **Verdict: QUESTIONABLE** -- Zero-length locks in SMB2 are somewhat ambiguous. The spec says Offset and Length define the range; a zero-length lock (Length=0) technically covers no bytes. The production code handles this via the `zero_len` flag and special overlap logic. The test's simulated `ranges_overlap()` treats start==end as a point lock that conflicts, which is consistent with the production code's behavior but should be noted as an implementation choice rather than explicit spec requirement.

**15. `test_stress_rapid_lock_unlock`** (line 1575)
- Tests: Stress test of rapid lock/unlock
- **Verdict: CORRECT** (stress test)

**16. `test_boundary_range_locks`** (line 1616)
- Tests: Locks at offset 0, 0xFFFFFFFFFFFFFFFF, and 1 don't conflict with each other
- **Verdict: CORRECT** (non-overlapping ranges at boundaries)

---

## File 5: `/home/ezechiel203/ksmbd/test/ksmbd_test_regression_lock.c`

### Suite: `ksmbd_regression_lock` (8 test cases)

**1. `test_reg001_lock_init_stores_smb_range`** (line 31)
- Tests: smb2_lock_init stores unclamped SMB range (start=100, end=200)
- Comment says "SMB range [100, 200)" but the lock stores start=100, end=200 which is the raw values passed in. The actual POSIX clamping and inclusive-end conversion happens elsewhere.
- **Verdict: CORRECT**

**2. `test_reg002_lock_init_large_offset`** (line 62)
- Tests: Offsets beyond OFFSET_MAX are stored correctly in the ksmbd_lock structure
- Regression for: locks at offsets > OFFSET_MAX that caused false VFS conflicts
- **Verdict: CORRECT**

**3. `test_reg003_lock_init_wrap_around`** (line 91)
- Tests: offset=~0ULL, end=0 (wrapped) is stored correctly
- Comment says "offset=~0, length=1 => end wraps to 0" but the call is `smb2_lock_init(&fl, F_SETLK, SMB2_LOCKFLAG_EXCLUSIVE, ~0ULL, 0ULL, &lock_list)` which passes start=~0ULL, end=0ULL directly. The smb2_lock_init stores these raw values.
- **Verdict: CORRECT** (the comment is slightly misleading -- it says "length=1" but the function receives start/end not offset/length -- but the assertion itself is correct)

**4. `test_reg004_blocking_lock_sleep_flag`** (line 119)
- Tests: SMB2_LOCKFLAG_EXCLUSIVE -> F_SETLKW + FL_SLEEP
- Regression for: blocking lock upgrade handling
- **Verdict: CORRECT**

**5. `test_reg005_lock_seq_bit_extraction`** (line 145)
- Tests: Encoding `(5 << 4) | 0xA` -> index=5, seq_num=0xA; stored value is 0xA at index 5
- Spec ref: Section 2.2.26 -- LockSequenceNumber = 4 least significant bits, LockSequenceIndex = upper 28 bits
- Production code (line 441-442): `seq_num = val & 0xF; seq_idx = (val >> 4) & 0xFFFFFFF;`
- Regression for: bit extraction was previously reversed ((val>>28)&0xF for seq_num)
- **Verdict: CORRECT**

**6. `test_reg006_lock_replay_returns_one`** (line 173)
- Tests: Replay detected returns 1 (not negative error)
- Spec ref: Section 3.3.5.14 -- "success is returned to the client without further processing"
- Regression for: was returning -EAGAIN instead of success
- **Verdict: CORRECT**

**7. `test_reg007_lock_seq_index_boundary`** (line 196)
- Tests: Index 1 (min valid), 64 (max valid), 65 (out of range), 0 (reserved)
- Spec ref: Section 2.2.26 -- "a value from 0 to 64, where 0 is reserved"
- Regression for: array was only 16 elements, now 65
- **Verdict: CORRECT**

**8. `test_reg008_lock_seq_not_stored_until_success`** (line 235)
- Tests: Without calling store_lock_sequence, check returns 0 (entry is 0xFF sentinel, not valid)
- Spec ref: Sections 3.3.5.14.1/3.3.5.14.2 -- sequence is stored only after successful lock/unlock processing
- Regression for: was stored before processing, causing failed-then-retried locks to falsely detect replay
- Also verifies that check_lock_sequence invalidates the entry (sets to 0xFF) when not a replay (production code line 464: `fp->lock_seq[seq_idx] = 0xFF;`)
- **Verdict: CORRECT**

---

## Summary

### Overall Statistics

| File | Total Cases | CORRECT | WRONG | QUESTIONABLE |
|------|-------------|---------|-------|--------------|
| ksmbd_test_smb2_lock.c | 41 | 40 | 0 | 1 |
| ksmbd_test_error_lock.c | 12 | 12 | 0 | 0 |
| ksmbd_test_concurrency_lock.c | 5 | 5 | 0 | 0 |
| ksmbd_test_concurrency_lock_race.c | 16 | 14 | 0 | 2 |
| ksmbd_test_regression_lock.c | 8 | 8 | 0 | 0 |
| **TOTAL** | **82** | **79** | **0** | **3** |

### Detailed Findings

**WRONG: None**

All flag values (SHARED=0x01, EXCLUSIVE=0x02, UNLOCK=0x04, FAIL_IMMEDIATELY=0x10), StructureSize values (Request=48, Response=4), lock sequence bit layout (seq_num = low 4 bits, seq_idx = upper 28 bits, valid range 1-64), flag combination validation, and error codes are consistent with the MS-SMB2 specification.

**QUESTIONABLE: 3 items**

1. **`test_lock_flags_fail_immediately_alone`** in `ksmbd_test_smb2_lock.c` (line 581):
   - The test asserts that `SMB2_LOCKFLAG_FAIL_IMMEDIATELY` (0x10) alone is a valid flag value (returns 0).
   - Per MS-SMB2 Section 2.2.26.1, the five valid combinations are explicitly: SHARED, EXCLUSIVE, SHARED|FAIL_IMM, EXCLUSIVE|FAIL_IMM, and UNLOCK. FAIL_IMMEDIATELY alone is NOT listed.
   - The production code uses a bitmask approach (`SMB2_LOCKFLAG_MASK`) that accepts any combination of the four defined bits, which is more permissive than the spec.
   - The spec says the server "SHOULD" (not MUST) fail invalid combinations (Section 3.3.5.14.2), so this is not a strict violation but is a deviation from the explicitly listed valid combinations.
   - **Fix if desired:** Change the test expectation to `-EINVAL` and update `smb2_validate_lock_flags()` to reject FAIL_IMMEDIATELY alone; or add a comment documenting the intentional deviation.

2. **`test_lock_sequence_replay_concurrent`** in `ksmbd_test_concurrency_lock_race.c` (line 451):
   - The simulated `check_lock_sequence_replay()` function does not check the 0xFF sentinel (Valid=FALSE) before comparing sequence numbers. It compares `fp->lock_seq[bucket_idx] == seq_num` directly. The production code checks `fp->lock_seq[seq_idx] != 0xFF && fp->lock_seq[seq_idx] == seq_num`.
   - In this specific test `seq=42` (not 0xFF), so the test passes correctly, but the simulation is imprecise. If someone changed the test to use `seq=0xFF`, it would give incorrect results.
   - **Fix:** Add `fp->lock_seq[bucket_idx] != LOCK_SEQ_INVALID &&` before the comparison in `check_lock_sequence_replay()`.

3. **`test_zero_length_lock_conflict`** in `ksmbd_test_concurrency_lock_race.c` (line 1496):
   - The test treats zero-length locks (start==end) as point locks that conflict with each other. The MS-SMB2 spec does not explicitly define the semantics of a zero-length lock range (Length=0). The production code uses a `zero_len` flag and special handling, and this test's simulated behavior is consistent with the production code.
   - This is implementation-specific behavior rather than a spec violation, but it should be documented that zero-length lock conflict behavior is an implementation choice.

### Coverage Gaps (not bugs, but notable omissions)

1. **No test for SMB2_GLOBAL_CAP_MULTI_CHANNEL in lock sequence validation.** The spec (Section 3.3.5.14) says lock sequence verification applies when "Connection.ServerCapabilities includes SMB2_GLOBAL_CAP_MULTI_CHANNEL bit" even if the handle is not resilient/durable/persistent. The production code's `check_lock_sequence()` only checks `is_resilient || is_durable || is_persistent`.

2. **No test for UNLOCK + SHARED/EXCLUSIVE in unlock processing path.** Section 3.3.5.14.1 says "if either SMB2_LOCKFLAG_SHARED_LOCK or SMB2_LOCKFLAG_EXCLUSIVE_LOCK is set, the server MUST fail the request with STATUS_INVALID_PARAMETER." The `smb2_validate_lock_flag_mix()` tests cover this at the flag-mix level but do not test the full unlock processing path.

3. **No test for multi-element lock rollback.** Section 3.3.5.14.2 says if a lock in a multi-element array fails with FAIL_IMMEDIATELY, "the server MUST unlock any ranges locked as part of processing the previous entries in the Locks array." No test covers this rollback behavior.