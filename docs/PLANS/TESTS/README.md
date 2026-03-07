# ksmbd Test Suite Enhancement Plans

## Overview

These documents constitute a comprehensive gap analysis and test plan for the ksmbd
kernel module test suite. Each document covers a specific subsystem area, enumerating
every untested function, every missing edge case, and every new test file required.

**Current state (2026-03-03):** 84 KUnit test files (~2,017 tests) + 33 fuzz harnesses
**Target state:** ~110 KUnit test files (3,300+ tests) + 33 fuzz harnesses + ksmbd-torture suite (565 integration tests) + stress test suite + 42 VM concurrency/deadlock/race tests

### Test Quality Assessment

**Critical finding:** ~78% of existing KUnit tests use **replicated helper logic** (inline
re-implementations of static production functions) rather than calling actual kernel module
functions. **These tests are effectively useless** — they test a local copy of the code, not
the real production code. If production code changes, the test still passes.

| Test Quality Tier | % of Tests | Description |
|-------------------|-----------|-------------|
| **Integration** (real calls) | ~22% | Tests calling exported production functions (config, crypto, signing, oplock mapping) |
| **Replicated-logic** (useless) | ~78% | Tests re-implementing static function logic locally — DO NOT test real code |

**Root cause:** 136 static functions implement pure testable logic (validation, calculation,
parsing, protocol state machines) but the `static` keyword prevents test modules from calling them.

**Solution:** Use the kernel's `VISIBLE_IF_KUNIT` macro (`<kunit/visibility.h>`) to make these
136 functions non-static when `CONFIG_KUNIT` is enabled, with zero overhead in production.
Then rewrite all 67 replicated test files to call real production functions via
`MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING")`.
See [15_TESTABILITY_REFACTOR.md](15_TESTABILITY_REFACTOR.md) for the complete plan.

**Effective real coverage of production code paths:** ~5-10% currently → **~40-50% after refactor**.

## Documents

### Part I: KUnit Test Plans (Gap Analysis)

| # | File | Area | New Tests | New Files |
|---|------|------|----------:|----------:|
| 01 | [01_AUTH_CRYPTO_SESSION.md](01_AUTH_CRYPTO_SESSION.md) | Authentication, cryptography, session/negotiate lifecycle | ~129 | 6 new + 1 enhanced |
| 02 | [02_SMB2_PROTOCOL.md](02_SMB2_PROTOCOL.md) | All SMB2/3 command handlers (create, read, write, lock, dir, query, ioctl, tree, notify, compound) | ~543 | 13 new + 3 enhanced |
| 03 | [03_VFS_OPLOCK_ACL.md](03_VFS_OPLOCK_ACL.md) | VFS operations, oplock/lease state machine, ACL/security descriptors, notify, DFS, VSS, quota, BranchCache, resilient, app instance | ~300+ | 8 new + 2 enhanced |
| 04 | [04_FSCTL_INFO_CREATECTX.md](04_FSCTL_INFO_CREATECTX.md) | FSCTL dispatch (50+ handlers), info-level dispatch (30+ handlers), create context dispatch, RSVD | ~261 | 10 new + 3 enhanced |
| 05 | [05_TRANSPORT_CONN_COMPRESS.md](05_TRANSPORT_CONN_COMPRESS.md) | Transport (TCP/RDMA/IPC/QUIC), connection lifecycle, compression (LZNT1/LZ77/Huffman), encoding (ASN.1/NDR/Unicode), work queue, server dispatch | ~271 | 8 new + 3 enhanced |
| 06 | [06_SMB1_MGMT_FRUIT_MISC.md](06_SMB1_MGMT_FRUIT_MISC.md) | SMB1 protocol, share/tree/witness management, Fruit/Apple extensions, hooks, features, config, debugfs, IDA, netmisc | ~209 | 7 new + 6 enhanced |
| 07 | [07_FUZZ_HARNESSES.md](07_FUZZ_HARNESSES.md) | All input parsing surfaces: compression, QUIC, session setup, compound requests, SMB1, EA, copychunk, RSVD, IPC, Unicode, wildcards + existing harness improvements | 20 new harnesses | 20 new |
| | **Subtotal (KUnit)** | | **~1,700+** | **~70 new/enhanced** |

### Part II: ksmbd-torture Integration Test Suite

| # | File | Area | Contents |
|---|------|------|----------|
| 08 | [08_KSMBD_TORTURE_DESIGN.md](08_KSMBD_TORTURE_DESIGN.md) | Framework architecture, test runner, VM integration, 56 test categories, benchmarks | 1,849 lines |
| 09 | [09_KSMBD_TORTURE_TESTCASES.md](09_KSMBD_TORTURE_TESTCASES.md) | 543 named test cases (175 P0, 267 P1, 101 P2) + 22 benchmark definitions | 1,192 lines |
| 10 | [10_EDGE_CASE_REGRESSION.md](10_EDGE_CASE_REGRESSION.md) | 501 source-derived edge cases + 40 regression tests for all fixed bugs | 934 lines |
| | **Subtotal (ksmbd-torture)** | | **565 integration tests + 501 edge cases** |

### Part III: Stress Tests & Coverage Analysis

| # | File | Area | Contents |
|---|------|------|----------|
| 11 | [11_STRESS_TESTS.md](11_STRESS_TESTS.md) | Server capacity stress tests, connection storms, credit exhaustion, lock saturation, compression bombs, concurrency, memory pressure, configurable limits validation | 28 stress test categories, 180+ test cases |
| 12 | [12_COVERAGE_GAP_ANALYSIS.md](12_COVERAGE_GAP_ANALYSIS.md) | File-by-file coverage matrix (84 test files vs 67 production files), function-level gap inventory, quality tier assessment, priority remediation plan | Complete production function inventory |
| 13 | [13_PROTOCOL_COMPLIANCE_MATRIX.md](13_PROTOCOL_COMPLIANCE_MATRIX.md) | MS-SMB v54.0 and MS-SMB2 v84.0 section-by-section test coverage mapping, protocol compliance scoring | 130 spec sections mapped |

### Part IV: Concurrency, Error Path & Regression Tests

| # | File | Area | Contents |
|---|------|------|----------|
| 14 | [14_CONCURRENCY_ERRORPATH_REGRESSION.md](14_CONCURRENCY_ERRORPATH_REGRESSION.md) | 55 regression tests for all documented bug fixes, 220 error path tests for untested -E*/STATUS_* returns, 85 concurrency tests (KUnit kthread + VM integration) | 360 new tests across 25 new files + 6 extended + 3 VM scripts |
| | **Subtotal (Part IV)** | | **360 tests (55 regression + 220 error path + 85 concurrency)** |

### Part V: Testability Refactor (PREREQUISITE for all other plans)

| # | File | Area | Contents |
|---|------|------|----------|
| 15 | [15_TESTABILITY_REFACTOR.md](15_TESTABILITY_REFACTOR.md) | Make 136 static functions testable via `VISIBLE_IF_KUNIT` + `EXPORT_SYMBOL_IF_KUNIT`; rewrite 67 replicated test files to call real production code; eliminate all local `test_` helper functions that mirror production logic | 136 function exports, 67 test rewrites, 12 production files changed |
| | **Impact** | | **Coverage jumps from ~5-10% to ~40-50% of production code paths** |

## Key Findings

### Coverage is Low Despite Many Test Files

With 84 test files and ~2,017 test functions, the raw count looks healthy. However:

- **78% of tests replicate static function logic** rather than calling production code
- **Only config.c (95%), auth.c (65%), and oplock.c (50%)** have meaningful real-call coverage
- **smb2_create.c, smb2_lock.c, connection.c, compress.c** have 0% real-call coverage despite having dedicated test files with 40-78 test functions each
- The production codebase has **67 .c files totaling ~72,634 lines**; effective tested paths cover ~5,000 lines

### Critical Untested Areas (Priority 0)

1. **Compression decompression** -- processes untrusted client data, decompression bomb risk
2. **QUIC packet parsing** -- new code, first bytes on UDP wire
3. **Session setup/NTLMSSP** -- pre-auth, unauthenticated attack surface
4. **Compound request chaining** -- proven FID propagation bugs
5. **Copychunk validation** -- cross-file operations, resume key lifecycle
6. **Lock sequence replay** -- 5 bugs already found and fixed
7. **Security descriptor parsing** -- buffer overflow recently fixed
8. **VFS path resolution** -- TOCTOU, path traversal
9. **Connection lifecycle** -- refcount transitions, state machine
10. **All SMB2 command handlers** -- 17,000+ lines of replicated-only testing
11. **Configurable limits** -- 14 new params (tcp/quic timeouts, lock count, buffer size, etc.) have no stress/boundary tests
12. **Server capacity under load** -- no tests for max connections, credit exhaustion, or OOM behavior

### Missing: Concurrency, Error Path & Regression Tests

**Critical finding (2026-03-03):** The test suite has zero dedicated tests in three critical categories:

1. **Regression tests: 0 of 55** -- Every documented bug fix (REG-001 through REG-046 + 9 more)
   has zero automated regression tests. If any fix is reverted, no test will catch it.

2. **Error path tests: ~400 of 1,037** -- Production code has 1,037 error returns, 854 goto
   cleanup paths, and 122 memory allocation failure checks. Current tests exercise <10% of these.
   The top 4 files (smb1pdu.c, ksmbd_fsctl.c, smb2_query_set.c, smb2_create.c) account for
   62% of all error returns and have near-zero error path test coverage.

3. **Concurrency tests: 0** -- KUnit is single-threaded. No tests spawn kthreads to test
   refcount safety, state machine transitions, hash table races, or lock contention under
   parallel access. No VM integration tests exercise real-server concurrency.

See [14_CONCURRENCY_ERRORPATH_REGRESSION.md](14_CONCURRENCY_ERRORPATH_REGRESSION.md) for the
complete implementation plan (360 new tests).

### Missing: Stress & Capacity Tests

No stress tests exist in the current suite. The new configurable limits system (14 params)
needs boundary and saturation testing:

- What happens when `max_connections` is reached? Does the N+1 connection get rejected cleanly?
- What happens when `max_lock_count` locks are held and another is requested?
- What happens when `max_open_files` file descriptors are exhausted?
- What happens when `max_credits` are consumed and no credits remain?
- Can a compression bomb (small input, huge output) cause OOM?
- Does `tcp_recv_timeout` actually disconnect idle clients?
- Does `session_timeout` expire stale sessions correctly?

See [11_STRESS_TESTS.md](11_STRESS_TESTS.md) for the complete stress test plan.

### Implementation Priority

**Phase 1 (P0):** Pure-logic unit tests that need no kernel mocking -- auth helpers,
compression round-trips, MD4 test vectors, Unicode conversion, NDR encoding, ACL
construction, error code mapping, credit arithmetic. (~200 tests)

**Phase 2 (P1):** Tests requiring lightweight mocking of ksmbd structures -- connection
hash, session lifecycle, share config, tree connect, oplock state machine, FSCTL
dispatch, info-level dispatch. (~400 tests)

**Phase 3 (P2):** Tests requiring VFS/work-queue mocking -- SMB2 command handlers,
compound processing, notify, DFS, VSS, QUIC state machine. (~600 tests)

**Phase 4 (P3):** Fuzz harnesses, stress tests, and capacity tests -- all 20 new fuzz
harnesses, concurrency tests, decompression bombs, max-size inputs, configurable limit
saturation. (~500 tests + harnesses + 180 stress tests)

## Methodology

Each plan document follows the same structure:

1. **Current Coverage Summary** -- what exists, function-by-function coverage table
2. **Gap Analysis** -- completely untested files, untested functions, insufficient tests
3. **New Tests Required** -- named test cases with inputs, expected behavior, and rationale
4. **Edge Cases & Security Tests** -- boundary values, overflow, timing, race conditions
5. **Fuzz Targets** -- new fuzz harnesses with entry points and mutation strategies
6. **Implementation Priority** -- P0 through P3 with estimated counts

## Current Test Inventory Summary

| Category | Test Files | Test Functions | Fuzz Harnesses |
|----------|-----------|---------------|----------------|
| Authentication & Security | 5 | ~162 | 2 |
| SMB1 Protocol | 3 | ~64 | 1 |
| SMB2/3 Protocol | 17 | ~651 | 12 |
| File System & VFS | 20+ | ~500+ | 8 |
| Management & Config | 9 | ~133 | 0 |
| Transport & Networking | 4 | ~100 | 2 |
| Utility & Encoding | 12 | ~400+ | 8 |
| **Total** | **84** | **~2,017** | **33** |

## Total Lines of Plan Documentation

~22,000 lines across 15 plan files + this README.
