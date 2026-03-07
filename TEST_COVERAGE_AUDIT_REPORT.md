# KSMBD Test Infrastructure & Coverage Audit Report

**Date**: 2026-03-04
**Branch**: phase1-security-hardening
**Scope**: ksmbd kernel module, ksmbd-tools userspace, test framework

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Production C source files | 67 files, 74,416 lines |
| Production headers | 51 files, 13,855 lines |
| KUnit test files | 155 files, 75,120 lines |
| Fuzz harnesses (kernel) | 48 files, 17,353 lines |
| Fuzz harnesses (userspace) | 5 files, 1,798 lines |
| Syzkaller description | 1 file, 1,516 lines |
| Integration test scripts | 68 smbtorture categories + 10 shell suites |
| ksmbd-tools source | 29 files, 15,525 lines |
| ksmbd-tools tests | 6 files, 1,246 lines |
| Test-to-production ratio | **1.27:1** (test code is 55.9% of codebase) |
| CI/CD workflows | 5 GitHub Actions pipelines |
| Coverage tooling | gcov/lcov pipeline with threshold enforcement |

**Overall Assessment**: ksmbd has an exceptionally comprehensive test infrastructure for a
Linux kernel module. Every production source file has at least one corresponding test file.
The main gaps are in *depth* of coverage (line/branch coverage within files), not in *breadth*
(which files are tested). ksmbd-tools has significantly weaker test coverage.

---

## Part 1: ksmbd Kernel Module

### 1.1 Production Code Inventory (67 files, 74,416 lines)

#### src/core/ (14 files, 9,237 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| auth.c | 1,935 | ksmbd_test_auth.c (1,383 lines) | HIGH |
| server.c | 1,176 | ksmbd_test_server.c (347) | MEDIUM |
| smb2_compress.c | 1,980 | ksmbd_test_compress.c (1,170) | HIGH |
| connection.c | 890 | ksmbd_test_connection.c (711) | HIGH |
| misc.c | 618 | ksmbd_test_misc.c (305) | MEDIUM |
| crypto_ctx.c | 332 | ksmbd_test_crypto_ctx.c (276) | HIGH |
| ksmbd_md4.c | 264 | ksmbd_test_md4.c (483) | HIGH |
| ksmbd_buffer.c | 237 | ksmbd_test_buffer.c (535) | HIGH |
| ksmbd_config.c | 234 | ksmbd_test_config.c (274) | HIGH |
| ksmbd_work.c | 194 | ksmbd_test_work.c (459) | HIGH |
| ksmbd_hooks.c | 218 | ksmbd_test_hooks.c (595) | HIGH |
| ksmbd_debugfs.c | 170 | ksmbd_test_debugfs.c (116) | MEDIUM |
| ksmbd_feature.c | 60 | ksmbd_test_feature.c (271) | HIGH |
| compat.c | 129 | ksmbd_test_compat.c (357) | HIGH |

#### src/protocol/smb1/ (3 files, 10,535 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| smb1pdu.c | 10,079 | ksmbd_test_smb1_cmds.c (550), ksmbd_test_smb1_pdu.c (627), ksmbd_test_smb1_nt_transact.c (509), ksmbd_test_smb1_nt_transact_subcommands.c (799), ksmbd_test_smb1_trans2.c (557), ksmbd_test_state_machine_smb1.c (1,386), ksmbd_test_smb1_upgrade.c (416) | MEDIUM — 4,844 test lines for 10K source, but many of the 40+ handlers are lightly tested |
| smb1misc.c | 354 | ksmbd_test_smb1_parser.c (482) | HIGH |
| smb1ops.c | 102 | ksmbd_test_smb1_ops.c (267) | HIGH |

#### src/protocol/smb2/ (15 files, 17,463 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| smb2_query_set.c | 3,744 | ksmbd_test_smb2_query_set.c (237), ksmbd_test_info_file.c (977), ksmbd_test_info_file_set.c (219), ksmbd_test_info_fs.c (251), ksmbd_test_info_quota.c (78), ksmbd_test_info_security.c (95) | MEDIUM |
| smb2_create.c | 3,130 | ksmbd_test_smb2_create.c (250) | LOW |
| smb2_pdu_common.c | 1,623 | ksmbd_test_pdu_common.c (137) | LOW |
| smb2_dir.c | 1,373 | ksmbd_test_smb2_dir.c (500) | MEDIUM |
| smb2_read_write.c | 1,218 | ksmbd_test_smb2_read_write.c (510) | MEDIUM |
| smb2_negotiate.c | 1,025 | ksmbd_test_smb2_negotiate.c (275), ksmbd_test_negotiate.c (1,098) | HIGH |
| smb2_lock.c | 1,064 | ksmbd_test_smb2_lock.c (286) | MEDIUM |
| smb2_session.c | 1,040 | ksmbd_test_smb2_session.c (925) | HIGH |
| smb2fruit.c | 830 | ksmbd_test_fruit.c (356) | MEDIUM |
| smb2_misc_cmds.c | 668 | ksmbd_test_smb2_misc.c (373) | MEDIUM |
| smb2misc.c | 568 | ksmbd_test_smb2_check_message.c (715), ksmbd_test_smb2_validate.c (625) | HIGH |
| smb2_tree.c | 547 | ksmbd_test_smb2_tree.c (323) | MEDIUM |
| smb2ops.c | 428 | ksmbd_test_smb2_ops.c (454) | HIGH |
| smb2_notify.c | 399 | ksmbd_test_smb2_notify.c (443) | HIGH |
| smb2_ioctl.c | 214 | ksmbd_test_smb2_ioctl.c (455) | HIGH |

#### src/fs/ (17 files, 22,378 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| vfs.c | 4,133 | ksmbd_test_vfs.c (494) | LOW |
| ksmbd_fsctl.c | 3,034 | ksmbd_test_fsctl_dispatch.c (189) + 10 specialized fsctl tests (total ~3,500 lines) | MEDIUM |
| oplock.c | 2,887 | ksmbd_test_oplock.c (217) | LOW |
| smbacl.c | 2,474 | ksmbd_test_acl.c (728), ksmbd_test_sid_mapping.c (730) | MEDIUM |
| ksmbd_info.c | 2,043 | ksmbd_test_info_dispatch.c (184) + info_file/fs/quota/security tests | MEDIUM |
| vfs_cache.c | 1,680 | ksmbd_test_vfs_cache.c (728) | MEDIUM |
| ksmbd_notify.c | 1,489 | ksmbd_test_notify.c (461) | MEDIUM |
| ksmbd_reparse.c | 1,223 | ksmbd_test_reparse.c (265) | LOW |
| ksmbd_fsctl_extra.c | 742 | ksmbd_test_fsctl_extra.c (1,719) | HIGH |
| ksmbd_vss.c | 760 | ksmbd_test_vss.c (327) | MEDIUM |
| ksmbd_branchcache.c | 720 | ksmbd_test_branchcache.c (381) | MEDIUM |
| ksmbd_rsvd.c | 652 | ksmbd_test_rsvd.c (853) | HIGH |
| ksmbd_dfs.c | 520 | ksmbd_test_dfs.c (485), ksmbd_test_dfs_behavior.c (534) | HIGH |
| ksmbd_quota.c | 429 | ksmbd_test_quota.c (322) | HIGH |
| ksmbd_app_instance.c | 317 | ksmbd_test_app_instance.c (362) | HIGH |
| ksmbd_create_ctx.c | 246 | ksmbd_test_create_ctx.c (358), ksmbd_test_create_ctx_tags.c (225) | HIGH |
| ksmbd_resilient.c | 146 | ksmbd_test_resilient.c (250) | HIGH |

#### src/transport/ (4 files, 8,379 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| transport_quic.c | 3,208 | ksmbd_test_quic.c (820), ksmbd_test_quic_binding.c (558) | MEDIUM |
| transport_rdma.c | 2,851 | ksmbd_test_rdma.c (424), ksmbd_test_rdma_credit.c (708), ksmbd_test_rdma_logic.c (447) | MEDIUM |
| transport_tcp.c | 949 | ksmbd_test_transport.c (376), ksmbd_test_tcp_shutdown.c (782) | HIGH |
| transport_ipc.c | 1,371 | ksmbd_test_ipc.c (378) | LOW |

#### src/mgmt/ (6 files, 2,101 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| user_session.c | 745 | ksmbd_test_session.c (427), ksmbd_test_user_session.c (322), ksmbd_test_user_session_mgmt.c (215) | HIGH |
| ksmbd_witness.c | 636 | ksmbd_test_witness.c (768) | HIGH |
| share_config.c | 353 | ksmbd_test_share_config.c (415) | HIGH |
| tree_connect.c | 200 | ksmbd_test_tree_connect.c (249) | HIGH |
| user_config.c | 111 | ksmbd_test_user_config.c (382) | HIGH |
| ksmbd_ida.c | 56 | ksmbd_test_ida.c (310) | HIGH |

#### src/encoding/ (5 files, 1,841 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| unicode.c | 535 | ksmbd_test_unicode.c (377) | HIGH |
| ndr.c | 645 | ksmbd_test_ndr.c (216) | MEDIUM |
| asn1.c | 390 | ksmbd_test_asn1.c (901) | HIGH |
| ksmbd_spnego_negtokeninit.asn1.c | 93 | ksmbd_test_asn1.c | N/A (generated) |
| ksmbd_spnego_negtokentarg.asn1.c | 78 | ksmbd_test_asn1.c | N/A (generated) |

#### src/protocol/common/ (2 files, 1,566 lines)
| File | Lines | Test File(s) | Coverage Depth |
|------|-------|-------------|----------------|
| smb_common.c | 959 | ksmbd_test_smb_common.c (252) | MEDIUM |
| netmisc.c | 607 | ksmbd_test_netmisc.c (265) | MEDIUM |

### 1.2 Cross-Cutting Test Suites

Beyond per-file unit tests, the following cross-cutting test suites provide additional coverage:

| Suite Type | Files | Total Lines | What They Cover |
|------------|-------|-------------|-----------------|
| Regression | 7 files | 4,279 | 55+ documented bug fixes: lock, compound, credit, negotiate, session, access |
| Concurrency | 7 files | 5,143 | Lock races, oplock races, refcount races, hash table concurrency, state machine races |
| Error paths | 12 files | 2,976 | Auth, create, fsctl, negotiate, session, transport, lock, ioctl, vfs, readwrite, tree, query/set errors |
| Performance | 4 files | 3,359 | Crypto, PDU serialization, compression, data structure benchmarks |
| Timing | 4 files | 1,550 | Durable handle timers, oplock break timing, session timeout, transport timeouts |
| State machine | 2 files | 2,854 | Full SMB1 and SMB2 state machine verification against MS-SMB2 spec |
| Stress | 1 file | 1,514 | Credit limits, lock limits, session storms, timeout behavior |
| Signing/Crypto | 3 files | 1,780 | Known-answer vectors, signing verification, crypto pool lifecycle |
| RDMA | 3 files | 1,579 | RDMA credit management, logic, basic protocol |
| Channel security | 1 file | 589 | Per-channel signing and encryption |

### 1.3 Fuzz Coverage

**48 kernel fuzz harnesses** target all parsing entry points:

| Category | Harnesses | Key Targets |
|----------|-----------|-------------|
| PDU/Header parsing | 12 | SMB2 header, transform header, negotiate contexts, create contexts |
| Command requests | 10 | CREATE, READ, WRITE, LOCK, CLOSE, FLUSH, CANCEL, IOCTL, QUERY_DIR |
| Auth/Security | 5 | NTLMSSP, Kerberos, ASN.1, security descriptors, signing |
| FSCTL operations | 3 | Copychunk, reparse points, general FSCTL dispatch |
| Protocol features | 8 | DFS referrals, oplocks, leases, NDR, wildcards, path parsing, EAs, quotas |
| Transport | 3 | QUIC packets, RDMA negotiate, IPC messages |
| Advanced | 4 | Compression, compound requests, durable handles, session setup |
| SMB1 | 1 | SMB1 command dispatch |
| Unicode | 1 | Unicode conversion |
| SMB2 SET_INFO | 1 | SetInfo request |

**5 userspace libFuzzer targets** for standalone fuzzing without kernel boot:
- Security descriptors, NTLMSSP, negotiate contexts, create contexts, compression

**1 syzkaller description** (1,516 lines): Full SMB2 state machine for coverage-guided kernel fuzzing.

### 1.4 Integration Testing

| Layer | Description |
|-------|-------------|
| smbtorture | 68 category scripts covering SMB2.0/2.1/3.0/3.1.1. 150+ test cases. |
| ksmbd-torture | Custom suite: 17 suites (T01-T10 + edge cases + regression + differential) |
| VM testing | QEMU fleet (VM0-4) with automated module deploy + smbtorture execution |
| xfstests | Generic filesystem tests against ksmbd-mounted share |
| Load/Stress | Connection storms, session storms, concurrent file operations |

### 1.5 CI/CD

| Workflow | Trigger | Actions |
|----------|---------|---------|
| kunit.yml | push/PR to master | KUnit via kunit.py (UML), kernel 6.12.16, TAP output |
| kunit-run.yml | push/PR to master | 3-gate: registration check + kernel compile + userspace fuzz build |
| test.yml | push/PR | Source quality: cppcheck, shellcheck, BUG_ON check, formatting |
| build.yml | push/PR | Cross-arch build: x86_64, arm32, arm64, ppc64le, riscv64 |
| c-cpp.yml | push/PR | Legacy CI + xfstests + smbtorture |

### 1.6 Coverage Tooling

Full gcov/lcov pipeline in `test/coverage/`:
- `collect_coverage.sh` (508 lines): `lcov --capture` + `genhtml`, threshold enforcement
- `kunit_gcov.kunitconfig`: UML config with `CONFIG_GCOV_KERNEL=y`
- Supports 3 data sources: kunit.py build dir, explicit gcov dir, `/sys/kernel/debug/gcov/`
- CI-ready: `--min-line-coverage`, `--min-func-coverage`, `--min-branch-coverage` exit codes

---

## Part 2: ksmbd-tools Userspace

### 2.1 Production Code (29 files, 15,525 lines)

| Component | Files | Lines | Purpose |
|-----------|-------|-------|---------|
| mountd/ (daemon) | 9 | 5,976 | Netlink IPC, RPC services (SAMR/LSARPC/SRVSVC/WKSSVC), ACL, worker |
| tools/ (library+CLI) | 11 | 7,147 | Config parser, share/user/session mgmt, CLI dispatch, ASN.1, SPNEGO |
| addshare/ | 2 | 900 | Share administration (ksmbd.conf edit) |
| adduser/ | 3 | 774 | User administration (ksmbdpwd.db, MD4 hashing) |
| control/ | 1 | 580 | Sysfs-based server control |
| **Total** | **29** | **15,525** | |

### 2.2 Test Coverage (6 files, 1,246 lines)

| Test File | Lines | Cases | What It Tests |
|-----------|-------|-------|---------------|
| test_config_parser.c | 751 | 40 | Bool parsing, memparse, config options, encryption flags, multichannel, durable handles, fruit, clamping, protocol versions |
| test_share_config_payload.c | 206 | 8 | Share config payload sizing and serialization |
| test_host_acl.c | 153 | ~12 | CIDR matching (IPv4/IPv6, /24, /32, /0, hostname, invalid) |
| test_ipc_request_validation.c | 136 | 4 | IPC security: unterminated string handling in login/logout/tree_connect |
| test_integration.sh | 240 | ~30 | End-to-end CLI: user/share add/update/delete/list, config validate |
| test_ipc_compat.sh | 200 | ABI | Struct size/offset diff between kernel and userspace headers |

### 2.3 ksmbd-tools Coverage Gaps

**UNTESTED production files** (no corresponding test):

| File | Lines | Risk | Notes |
|------|-------|------|-------|
| mountd/rpc.c | 1,441 | HIGH | Core DCE/RPC NDR framework, pipe dispatch |
| mountd/rpc_samr.c | 1,092 | HIGH | SAMR RPC: user/group enumeration, domain info |
| mountd/rpc_lsarpc.c | 799 | MEDIUM | LSA RPC: policy queries, SID lookups |
| mountd/rpc_srvsvc.c | 515 | MEDIUM | SRVSVC: share enumeration, server info |
| mountd/ipc.c | 574 | HIGH | Netlink socket setup, event dispatch, overflow guards |
| mountd/worker.c | 470 | MEDIUM | Event routing for all KSMBD_EVENT_* types |
| mountd/mountd.c | 484 | LOW | Daemon lifecycle (fork, PID file, signals) |
| mountd/smbacl.c | 358 | MEDIUM | SMB ACL to POSIX mapping |
| mountd/rpc_wkssvc.c | 243 | LOW | Simple workstation info RPC |
| tools/management/session.c | 227 | MEDIUM | Session lifecycle |
| tools/management/tree_conn.c | 242 | MEDIUM | Tree connect handler, sessions cap enforcement |
| tools/management/user.c | 546 | HIGH | Login/logout handlers, IPC validation |
| tools/management/spnego.c | 340 | LOW | Optional Kerberos path |
| tools/management/spnego_krb5.c | 418 | LOW | Optional Kerberos validation |
| tools/asn1.c | 366 | LOW | Optional ASN.1 parser |
| tools/tools.c | 477 | LOW | Logging, path helpers |
| addshare/share_admin.c | 732 | MEDIUM | INI file editing |
| adduser/user_admin.c | 380 | MEDIUM | Password database management |
| adduser/md4_hash.c | 221 | MEDIUM | MD4 implementation (crypto correctness) |
| control/control.c | 580 | MEDIUM | Sysfs writes (shutdown, debug, reload) |
| tools/ksmbdctl.c | 1,010 | LOW | CLI argument parsing |

**Total untested in ksmbd-tools: ~10,515 lines (67.7% of codebase)**

**Critical CI gap**: The GitHub Actions workflow for ksmbd-tools runs `distcheck`/`meson dist`
but does NOT run `meson test`. The unit tests exist but are never executed in CI.

---

## Part 3: Grades

### Grade: ksmbd Kernel Module Test Coverage — **A-**

**Strengths**:
- Every production file has at least one test file (100% breadth)
- 155 KUnit test files with 2,851 registered test cases
- 48 kernel + 5 userspace fuzz harnesses covering all parsing paths
- 12 error-path test files, 7 concurrency test files, 7 regression test files
- State machine verification against MS-SMB2 spec
- Full gcov/lcov coverage pipeline with threshold enforcement
- 5 CI/CD workflows including cross-arch builds
- Test registration gate prevents orphaned tests
- syzkaller description for coverage-guided kernel fuzzing

**Weaknesses** (preventing A+):
- Depth gaps in largest files: smb2_create.c (3,130 lines / 250 test lines = 8:1 ratio)
- vfs.c (4,133 lines) and oplock.c (2,887 lines) have low test-to-source ratios
- smb2_pdu_common.c (1,623 lines / 137 test lines) — compound/encryption paths undertested
- transport_ipc.c (1,371 lines / 378 test lines) — netlink handler coverage thin
- Coverage baselines in README are conservative (transport_tcp: 0-5%, transport_rdma: 0%)
- 10 test files not yet registered in test/Makefile (newer additions pending)
- No measured line/branch coverage numbers available (tooling exists but no baseline report)

### Grade: ksmbd-tools Test Coverage — **D+**

**Strengths**:
- Config parser well-tested (40 test cases for the core parsing logic)
- IPC ABI compatibility test catches kernel/userspace struct drift
- Integration test covers CLI workflows end-to-end
- Meson test infrastructure is properly set up

**Weaknesses**:
- 67.7% of codebase has zero test coverage
- RPC services (3,847 lines across 4 files) completely untested
- IPC/netlink handler (574 lines) untested
- User management handler (546 lines) untested
- MD4 hash implementation (221 lines) untested — crypto code needs known-answer tests
- CI does NOT run `meson test` — tests exist but are never executed automatically
- No fuzz testing for RPC/NDR parsing (attack surface from network)
- No coverage tooling configured

### Grade: Test Framework Infrastructure — **A**

**Strengths**:
- KUnit integration is exemplary: VISIBLE_IF_KUNIT pattern, MODULE_IMPORT_NS, kunitconfig
- Full coverage pipeline (gcov + lcov + genhtml + threshold enforcement)
- Multi-layer testing: unit (KUnit) + fuzz (syzkaller/libFuzzer) + integration (smbtorture)
- Test registration gate in CI prevents orphaned tests
- Cross-arch build verification (5 architectures)
- run_all_tests.sh master orchestrator with mode selection
- VM fleet for real-hardware integration testing
- Userspace fuzz targets build with ASan + UBSan

**Weaknesses** (preventing A+):
- No measured coverage baseline report committed to repo
- ksmbd-tools CI doesn't execute its own tests
- No mutation testing

---

## Part 4: Remediation Plan

### Priority 1: Critical (ksmbd-tools CI + RPC testing)

**1.1 Enable `meson test` in ksmbd-tools CI** — Effort: 1 hour
- Edit `.github/workflows/c-cpp.yml` to add `meson test` step after `meson dist`
- This alone activates 4 C test executables + 2 shell tests in CI

**1.2 Add RPC NDR unit tests** — Effort: 2-3 days
- Target: `mountd/rpc.c` (1,441 lines) — core NDR serialization
- Test BIND, REQUEST, RESPONSE PDU marshaling with known-good payloads
- Test pipe table lookup, syntax negotiation
- Add fuzz target for malformed RPC input

**1.3 Add RPC service tests** — Effort: 3-4 days
- Target: `rpc_samr.c`, `rpc_srvsvc.c`, `rpc_lsarpc.c`, `rpc_wkssvc.c`
- Test each RPC method with mock netlink context
- Focus on error paths (malformed requests, buffer overflows, null parameters)

**1.4 Add MD4 known-answer tests** — Effort: 2 hours
- Target: `adduser/md4_hash.c` (221 lines)
- Use RFC 1320 test vectors
- Critical because incorrect hashing breaks all NTLM authentication

### Priority 2: High (ksmbd depth gaps)

**2.1 Expand smb2_create.c tests** — Effort: 2-3 days
- Current: 250 test lines for 3,130 source lines (8:1 ratio)
- Add: durable handle create/reconnect paths, lease create contexts, maximal access
- Add: FILE_DELETE_ON_CLOSE edge cases, reparse point handling, SUPERSEDE disposition

**2.2 Expand vfs.c tests** — Effort: 2 days
- Current: 494 test lines for 4,133 source lines
- Add: file rename/link/unlink error paths, xattr operations, stream operations
- Add: POSIX lock range edge cases, large file offset handling

**2.3 Expand oplock.c tests** — Effort: 2 days
- Current: 217 test lines for 2,887 source lines
- Add: lease upgrade/downgrade transitions, oplock break acknowledgment
- Add: multi-client oplock contention scenarios (use concurrency test pattern)

**2.4 Expand smb2_pdu_common.c tests** — Effort: 1-2 days
- Current: 137 test lines for 1,623 source lines
- Add: compound request chaining, encryption/decryption wrappers, channel sequence checking

**2.5 Register 10 unregistered test files in test/Makefile** — Effort: 30 minutes
- Run `check_test_registration.sh` to identify exactly which files are missing
- Add their `.o` entries to Makefile

### Priority 3: Medium (ksmbd-tools coverage expansion)

**3.1 Add IPC handler tests** — Effort: 1-2 days
- Target: `mountd/ipc.c` (574 lines), `mountd/worker.c` (470 lines)
- Test netlink message routing, overflow guards, event dispatch

**3.2 Add user management handler tests** — Effort: 1 day
- Target: `tools/management/user.c` (546 lines)
- Test login/logout request handlers, unterminated string security checks

**3.3 Add share administration tests** — Effort: 1 day
- Target: `addshare/share_admin.c` (732 lines)
- Test INI file section add/update/delete, path validation

**3.4 Add user administration tests** — Effort: 1 day
- Target: `adduser/user_admin.c` (380 lines)
- Test password database read/write, hash format validation

**3.5 Add control interface tests** — Effort: 4 hours
- Target: `control/control.c` (580 lines)
- Test sysfs write formatting, error handling for missing sysfs paths

### Priority 4: Low (infrastructure improvements)

**4.1 Generate and commit coverage baseline report** — Effort: 4 hours
- Run full gcov/lcov pipeline against KUnit tests
- Commit HTML report or summary numbers as CI baseline
- Set minimum coverage thresholds for CI gate

**4.2 Add ksmbd-tools coverage tooling** — Effort: 1 day
- Add `--coverage` flags to meson build
- Add lcov collection for `meson test` runs
- Set minimum coverage threshold

**4.3 Add ksmbd-tools fuzz targets** — Effort: 2 days
- Priority targets: RPC NDR parsing, config parser edge cases, ACL parsing
- Use libFuzzer with ASan+UBSan (same pattern as ksmbd kernel userspace fuzz)

**4.4 Run measured coverage and update README baselines** — Effort: 4 hours
- Replace estimated baselines with actual measured numbers
- Identify specific functions with 0% coverage for targeted test writing

---

## Part 5: Summary Table

| Component | Grade | Breadth | Depth | Fuzz | CI | Tooling |
|-----------|-------|---------|-------|------|----|---------|
| ksmbd kernel module | **A-** | 100% files | ~60% lines (est.) | 53 harnesses | 5 workflows | gcov/lcov |
| ksmbd-tools userspace | **D+** | 32% files | ~15% lines (est.) | None | Broken (no test run) | None |
| Test framework | **A** | N/A | N/A | N/A | Excellent | Excellent |

**Total estimated effort for full remediation: ~25-30 developer-days**
- Priority 1 (Critical): ~5 days
- Priority 2 (High): ~10 days
- Priority 3 (Medium): ~5 days
- Priority 4 (Low): ~5 days
