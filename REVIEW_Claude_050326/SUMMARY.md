# KSMBD Test Coverage Spec Compliance Review — Consolidated Summary

**Date:** 2026-03-05
**Audited by:** 36 parallel Claude agents across 2 batches
**Scope:** ~80+ test files, ~2,459 kernel KUnit + ~600 userspace test cases
**Specs referenced:** MS-SMB, MS-SMB2, MS-FSCC, MS-RPCE, MS-SRVSVC, MS-SAMR, MS-LSAD, MS-DTYP, MS-NLMP, RFC 9000/9001, X.690

---

## Executive Summary

| Metric | Kernel | Userspace | Total |
|--------|-------:|----------:|------:|
| Test cases audited | ~2,459 | ~600 | ~3,059 |
| CORRECT | ~2,423 | ~595 | ~3,018 |
| WRONG | 19 | 2 | **21** |
| QUESTIONABLE | 56 | 12 | **68** |
| Correctness rate | 98.5% | 99.2% | **98.7%** |

**Production code bugs found:** 10 (exposed through test audit)
**Non-compilable test files:** 1 (`ksmbd_test_error_query_set.c`)
**Missing test areas:** Leases, Compound/Cancel/Async, Durable handles, Multi-channel

---

## Production Code Bugs (Fix First)

These are spec violations in **production code**, not just test issues:

| # | Severity | File | Bug | Spec |
|---|----------|------|-----|------|
| P-1 | **HIGH** | `smb2pdu.h:1502` | `SMB2_NOTIFY_SESSION_CLOSED = 0x2` should be `0x0` | MS-SMB2 2.2.44.1 |
| P-2 | **HIGH** | `smb2_pdu_common.c` | ChannelSequence skip checks `dialect <= 0x0202`, should be `<= 0x0210` (missing SMB 2.1) | MS-SMB2 3.3.5.2.10 |
| P-3 | **HIGH** | `smb2_tree.c:190` | Share name `>= 80` rejects valid 80-char names; should be `> 80` | MS-SMB2 2.2.9 |
| P-4 | **MEDIUM** | `vfs.c:2959-2964` | FILE_SEQUENTIAL_ONLY wins over FILE_RANDOM_ACCESS when both set; spec says ignore SEQUENTIAL | MS-SMB2 2.2.13 |
| P-5 | **MEDIUM** | `ksmbd_info.c:935` | FileNormalizedNameInformation rejects SMB 3.0; should only reject 2.0.2, 2.1, 3.0.2 | MS-SMB2 3.3.5.20.1 |
| P-6 | **MEDIUM** | `smb2_read_write.c:458` | READ allows FILE_READ_ATTRIBUTES alone; spec requires FILE_READ_DATA | MS-SMB2 3.3.5.12 |
| P-7 | **MEDIUM** | `ksmbd_vss.h` | GMT token length check uses `namlen==31` but spec token is 24 chars | MS-SMB2 3.3.5.15.1 |
| P-8 | **LOW** | `smb1pdu.c:9604` | NT_TRANSACT_CREATE min param_count=57; spec says 53 | MS-SMB 2.2.7.1.1 |
| P-9 | **LOW** | `ksmbd-tools rpc.c:455` | `ndr_write_string()` omits NUL from max_count/actual_count | MS-RPCE 2.2.5.2.1 |
| P-10 | **LOW** | `smbacl.c` | `smb_read_sid()` rejects 15 sub-authorities (`>=` should be `>`) | MS-DTYP 2.4.2 |

---

## All WRONG Test Findings (21)

### Structure/Constant Errors (8)

| ID | Test File | Issue |
|----|-----------|-------|
| W-1 | `ksmbd_test_fsctl_duplicate.c` | Persistent/Volatile field order swapped in DUPLICATE_EXTENTS struct |
| W-2 | `ksmbd_test_fsctl_duplicate.c` | Same for DUPLICATE_EXTENTS_EX |
| W-3 | `ksmbd_test_smb2_dir.c` | `file_id_extd_dir_info` sizeof expects 96, actual is 88 |
| W-4 | `ksmbd_test_smb2_dir.c` | `file_id_extd_both_dir_info` sizeof expects 122, actual is 114 |
| W-5 | `ksmbd_test_smb2_misc_cmds.c` | `SMB2_NOTIFY_SESSION_CLOSED = 0x2` (should be 0x0) |
| W-6 | `ksmbd_test_smb2_misc_cmds.c` | Notification StructureSize=4 (spec says 8 minimum) |
| W-7 | `ksmbd_test_fsctl_object_id.c` | `FILE_OBJECTID_BUFFER` is 48 bytes, should be 64 (missing BirthVolumeId) |
| W-8 | `ksmbd_test_write_through.c` | WRITE response fields named after READ response (wrong field names) |

### Logic Errors vs Spec (8)

| ID | Test File | Issue |
|----|-----------|-------|
| W-9 | `ksmbd_test_smb2_dir.c` | 0x50 in invalid_levels list; it's valid (FILEID_ALL_EXTD_DIRECTORY_INFORMATION) |
| W-10 | `ksmbd_test_smb2_notify.c` | Rejects zero CompletionFilter; spec says creates perpetually pending watch |
| W-11 | `ksmbd_test_channel_security.c` | Asserts SMB 2.1 validates ChannelSequence; spec says MUST be skipped |
| W-12 | `ksmbd_test_resilient.c` | Expects timeout clamping; spec says MUST fail with STATUS_INVALID_PARAMETER |
| W-13 | `ksmbd_test_fsctl_sparse.c` | Rejects SET_SPARSE on directories; Windows/NTFS allows it |
| W-14 | `ksmbd_test_fsctl_validate_negotiate.c` | All 5 tests use SMB 3.1.1 dialect; FSCTL only valid for 3.0/3.0.2 |
| W-15 | `ksmbd_test_credit.c` | Credit charge=0 for zero payload; spec formula always yields minimum 1 |
| W-16 | `ksmbd_test_smb2_read_write.c` | FILE_READ_ATTRIBUTES alone accepted for READ; spec requires FILE_READ_DATA |

### API Drift / Stale Tests (3)

| ID | Test File | Issue |
|----|-----------|-------|
| W-17 | `ksmbd_test_error_query_set.c` | Won't compile: `buffer_check_err()` 3 args (needs 4), `get_file_ea_info()` 2 args (needs 3) |
| W-18 | `ksmbd_test_info_file.c` | FileNormalizedNameInformation mock rejects SMB 3.0 (shouldn't) |
| W-19 | `ksmbd_test_info_file.c` | FileStatLxInformation reuses wrong mock handler |

### Userspace (2)

| ID | Test File | Issue |
|----|-----------|-------|
| W-20 | `ksmbd-tools test_rpc_ndr.c` | `ndr_write_string` max_count/actual_count should include NUL (+1) |
| W-21 | `ksmbd-tools test_rpc_pipe.c` | Empty string should have max_count=1, not 0 |

---

## Major Coverage Gaps

### Missing Test Files (no dedicated tests exist)

| Category | Missing Coverage |
|----------|-----------------|
| **Leases** | No `ksmbd_test_lease.c` / `_v2.c` — lease break, upgrade/downgrade, directory leases, parent keys |
| **Compound** | No `ksmbd_test_compound.c` — FID propagation, error cascading, related/unrelated |
| **Cancel** | No `ksmbd_test_cancel.c` — async ID matching, cancel-before/after-complete |
| **Async** | No `ksmbd_test_async.c` — interim responses, async completion flows |
| **Durable** | No `ksmbd_test_durable.c` / `_v2.c` — reconnect, persistent handles, timer expiry |
| **Multi-channel** | No `ksmbd_test_multichannel.c` — channel binding, interface enumeration |
| **Flush/Close/Echo** | No dedicated test files |
| **ACL construction** | No ACE parsing/construction tests per MS-DTYP 2.4.4 |

### Tautological / Zero-Value Tests

| File | Issue |
|------|-------|
| `ksmbd_test_fsctl_volume.c` (12 tests) | All assertions trivially true (`sizeof(__le32) <= sizeof(__le32)`) |
| `ksmbd_test_fsctl_reparse.c` (1 test) | Only asserts `-EOPNOTSUPP == -EOPNOTSUPP` |
| `ksmbd_test_fsctl_misc.c` (1 test) | Contains `KUNIT_EXPECT_TRUE(test, true)` |
| `ksmbd_test_error_readwrite.c` (11 tests) | All arithmetic/type checks, zero protocol coverage |
| 3 pipe transceive stubs | Empty, no assertions |

### Mock-Only Tests (no production code called)

- `ksmbd_test_info_file.c` / `info_file_set.c` / `info_fs.c` / `info_quota.c` (~55 tests) — test replicated mock handlers, not actual ksmbd code

---

## QUESTIONABLE Findings Summary (68 total by category)

| Category | Count | Examples |
|----------|------:|---------|
| Trivial/tautological tests | 17 | fsctl_volume.c, fsctl_reparse.c, error_readwrite.c |
| Mock-only (no prod coverage) | 48 | info_file, info_file_set, info_fs, info_quota |
| Implementation-specific choices | 15 | resilient timeout cap, compound CASCADE, lock FAIL_IMMEDIATELY |
| Imprecise spec citations | 8 | cancel signing section, lock bit naming, channel seq comment |
| Stricter-than-spec behavior | 5 | ChannelSequence on FLUSH/LOCK, SET_SPARSE on dirs |
| Config/protocol string ambiguity | 2 | "SMB2"/"SMB3" short forms may not match kernel table |

---

## Priority Action Plan

### Priority 1 — Fix Production Bugs (P-1 through P-3)
1. `SMB2_NOTIFY_SESSION_CLOSED`: 0x2 → 0x0 in `smb2pdu.h` (interop-breaking)
2. ChannelSequence: `<= SMB20_PROT_ID` → `<= SMB21_PROT_ID` in `smb2_pdu_common.c`
3. Share name length: `>= 80` → `> 80` in `smb2_tree.c`

### Priority 2 — Fix Production Bugs (P-4 through P-7)
4. fadvise: swap if/else order so FILE_RANDOM_ACCESS wins
5. FileNormalizedNameInformation: fix dialect gate for SMB 3.0
6. READ access: consider restricting to FILE_READ_DATA only
7. VSS GMT token: fix length check from 31 to 24

### Priority 3 — Fix Broken Tests
8. `ksmbd_test_error_query_set.c`: fix argument counts (won't compile)
9. Validate negotiate tests: change dialect from 3.1.1 to 3.0
10. FSCTL duplicate extents: swap Persistent/Volatile order
11. Dir struct sizes: 96→88, 122→114
12. Notify zero CompletionFilter: should not reject

### Priority 4 — Add Missing Coverage
13. Lease test suite (lease break, upgrade/downgrade, directory leases)
14. Compound/Cancel/Async test suites
15. Durable handle reconnect tests
16. Replace tautological tests with real behavioral tests

### Priority 5 — Improve Test Quality
17. Convert mock-only info tests to call production functions
18. Eliminate test file duplication (session constants in 3+ files)
19. Fix all imprecise spec citations in test comments

---

## Per-Area Detailed Reports

| Area | Report Files | Size |
|------|-------------|------|
| Negotiate | `Audit_NEGOTIATE_tests.md` | 24K |
| Session | `Audit_SESSION_tests.md` | 33K |
| Tree Connect | `Audit_TREE_CONNECT_tests.md` | 28K |
| Create | `Audit_CREATE_tests.md` | 26K |
| Read/Write | `Audit_READ_WRITE_tests.md` | 32K |
| Lock | `Audit_LOCK_tests.md` | 29K |
| IOCTL | `Audit_IOCTL_tests.md` | 34K |
| FSCTL Detail | `Audit_FSCTL_detail_tests.md` + `FSCTL_detail_spec_audit.md` | 31K + 12K |
| Query/Set Info | `Audit_QUERY_SET_INFO_tests.md` + `QUERY_SET_INFO_spec_audit.md` | 32K + 14K |
| Dir + Notify | `Audit_DIR_NOTIFY_tests.md` + `DIR_NOTIFY_spec_audit.md` | 25K + 9K |
| Oplock/Lease | `Audit_OPLOCK_LEASE_tests.md` + `OPLOCK_LEASE_spec_audit.md` | 26K + 10K |
| Credit/Compound/Cancel | `Audit_CREDIT_COMPOUND_CANCEL_tests.md` + `CREDIT_COMPOUND_CANCEL_audit.md` | 44K + 8K |
| SMB1 Protocol | `Audit_SMB1_tests.md` + `SMB1_protocol_spec_audit.md` | 40K + 10K |
| Auth/Crypto/Signing | `Audit_AUTH_CRYPTO_SIGNING_tests.md` + `AUTH_CRYPTO_spec_audit.md` | 30K + 18K |
| VFS/ACL/VSS | `Audit_VFS_ACL_VSS_tests.md` + `VFS_ACL_VSS_spec_audit.md` | 34K + 14K |
| Transport/QUIC/RDMA | `Audit_TRANSPORT_QUIC_RDMA_tests.md` + `TRANSPORT_QUIC_spec_audit.md` | 37K + 13K |
| Regression/Stress | `Audit_REGRESSION_STRESS_tests.md` + `REGRESSION_STRESS_spec_audit.md` | 31K + 14K |
| Remaining Kernel | `Remaining_kernel_tests_pt1.md` + `Remaining_kernel_tests_pt2.md` | 13K + 7K |
| Userspace RPC | `Audit_userspace_RPC_tests.md` + `Userspace_RPC_spec_audit.md` | 31K + 10K |
| Userspace ACL/Session | `Audit_userspace_ACL_session.md` + `Userspace_ACL_session_audit.md` | 25K + 11K |
| Userspace Config/Share | `Audit_userspace_config_share.md` + `Userspace_config_share_audit.md` | 26K + 9K |
