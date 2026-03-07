# 12. Coverage Gap Analysis (2026-03-03)

## Executive Summary

This document provides a file-by-file, function-by-function coverage analysis comparing
the 84 existing KUnit test files and 33 fuzz harnesses against the 67 production source
files (~72,634 lines) in the ksmbd kernel module, and maps test coverage against every
section of the MS-SMB (v54.0) and MS-SMB2 (v84.0) protocol specifications.

### Key Metrics

| Metric | Value |
|--------|-------|
| Production source files | 67 (.c files in src/) |
| Production code lines | ~72,634 |
| KUnit test files | 84 |
| KUnit test functions | ~2,017 |
| Fuzz harnesses | 33 |
| Tests calling real production functions | ~22% |
| Tests using replicated logic | ~78% |
| Estimated real code path coverage | ~5-10% |
| MS-SMB2 spec sections (server-side) | 92 |
| MS-SMB spec sections (server-side) | 38 |
| Spec sections with integration test coverage | ~25% |

---

## Part I: Production File Coverage Matrix

### Quality Tiers

- **A (Integration)**: Tests call exported production functions directly
- **B (Hybrid)**: Mix of real calls and replicated logic
- **C (Replicated)**: All tests replicate static function logic locally
- **D (None)**: No test file exists for this production module

### src/core/ (14 files, ~8,700 lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage | Notes |
|-----------------|-------|-----------|-------|------|---------------|-------|
| auth.c | 1,858 | ksmbd_test_auth.c | 36 | B | ~65% | Crypto/signing real; NTLMSSP replicated |
| connection.c | 879 | ksmbd_test_connection.c, ksmbd_test_conn_hash.c | 50 | C | ~0% | Full mock; state machine replicated |
| server.c | 1,048 | ksmbd_test_server.c | 18 | C | ~0% | Server init/dispatch replicated |
| misc.c | 641 | ksmbd_test_misc.c | 48 | B | ~40% | match_pattern, time conversion real; path validation mixed |
| smb2_compress.c | 1,969 | ksmbd_test_compress.c | 57 | C | ~0% | All static; algorithm replication only |
| ksmbd_work.c | 193 | ksmbd_test_work.c | 14 | C | ~0% | Work struct alloc replicated |
| ksmbd_buffer.c | 237 | ksmbd_test_buffer.c | 17 | A | ~80% | Real buffer pool calls |
| ksmbd_md4.c | 264 | ksmbd_test_md4.c | 16 | A | ~90% | Real MD4 hash function calls |
| crypto_ctx.c | 330 | ksmbd_test_crypto_ctx.c | 13 | A | ~70% | Real crypto context calls |
| ksmbd_config.c | 297 | ksmbd_test_config.c | 19 | A | ~95% | Real config get/set calls |
| ksmbd_hooks.c | 218 | ksmbd_test_hooks.c | 28 | B | ~50% | Hook registration real; dispatch mixed |
| ksmbd_feature.c | 60 | ksmbd_test_feature.c | 11 | A | ~90% | Real feature flag calls |
| ksmbd_debugfs.c | 194 | ksmbd_test_debugfs.c | 8 | C | ~0% | Debugfs mock |
| compat.c | 129 | -- | 0 | D | 0% | No tests |

**Gap Summary (core/):**
- `connection.c`: 879 lines, 25+ exported functions, ZERO real-call coverage
- `server.c`: 1,048 lines, request dispatch pipeline completely untested
- `smb2_compress.c`: 1,969 lines, all compression algorithms only replicated-tested
- `compat.c`: No tests at all

### src/fs/ (14+ files, ~25,000 lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage | Notes |
|-----------------|-------|-----------|-------|------|---------------|-------|
| vfs.c | 4,062 | ksmbd_test_vfs.c | 39 | C | ~8% | 5 real calls out of 71 functions |
| oplock.c | 2,453 | ksmbd_test_oplock.c | 55 | B | ~50% | smb2_map_lease_to_oplock real; state machine replicated |
| vfs_cache.c | 1,460 | ksmbd_test_vfs_cache.c | 41 | C | ~5% | File open/close/lookup replicated |
| ksmbd_fsctl.c | 3,041 | ksmbd_test_fsctl_*.c (11 files) | 179 | C | ~5% | Dispatch table tested; handlers replicated |
| ksmbd_fsctl_extra.c | 730 | (included in fsctl tests) | -- | C | ~5% | Part of fsctl test coverage |
| ksmbd_notify.c | 1,747 | ksmbd_test_notify.c | 32 | C | ~0% | Watch management replicated |
| ksmbd_info.c | 2,043 | ksmbd_test_info_*.c (6 files) | 88 | C | ~5% | Dispatch tested; handlers replicated |
| smbacl.c | 2,193 | ksmbd_test_acl.c | 61 | C | ~5% | SD build/parse replicated |
| ksmbd_reparse.c | 1,223 | ksmbd_test_reparse.c | 19 | C | ~0% | Reparse logic replicated |
| ksmbd_create_ctx.c | 246 | ksmbd_test_create_ctx.c, ksmbd_test_create_ctx_tags.c | 35 | B | ~40% | Tag matching partially real |
| ksmbd_dfs.c | 520 | ksmbd_test_dfs.c | 28 | C | ~0% | DFS path parse replicated |
| ksmbd_vss.c | 760 | ksmbd_test_vss.c | 17 | C | ~0% | VSS logic replicated |
| ksmbd_branchcache.c | 720 | ksmbd_test_branchcache.c | 29 | C | ~0% | Hash computation replicated |
| ksmbd_quota.c | 437 | ksmbd_test_quota.c | 18 | C | ~0% | Quota logic replicated |
| ksmbd_resilient.c | 146 | ksmbd_test_resilient.c | 15 | C | ~0% | Resilient handle replicated |
| ksmbd_app_instance.c | 317 | ksmbd_test_app_instance.c | 25 | C | ~0% | App instance logic replicated |
| ksmbd_rsvd.c | 652 | ksmbd_test_rsvd.c | 24 | C | ~0% | RSVD tunnel replicated |

**Gap Summary (fs/):**
- `vfs.c`: 4,062 lines, 30+ exported functions, only ~8% covered (5 calls)
- `ksmbd_fsctl.c`: 3,041 lines, 50+ FSCTL handlers, all replicated-only
- `smbacl.c`: 2,193 lines, security descriptor build/parse replicated-only
- `ksmbd_notify.c`: 1,747 lines, no real-call coverage

### src/mgmt/ (6 files, ~2,500 lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage |
|-----------------|-------|-----------|-------|------|---------------|
| user_session.c | 718 | ksmbd_test_session.c, ksmbd_test_user_session_mgmt.c | 27 | C | ~0% |
| share_config.c | 353 | ksmbd_test_share_config.c | 21 | C | ~0% |
| tree_connect.c | 186 | ksmbd_test_tree_connect.c | 10 | C | ~0% |
| user_config.c | 111 | ksmbd_test_user_config.c | 11 | C | ~0% |
| ksmbd_witness.c | 636 | ksmbd_test_witness.c | 28 | C | ~0% |
| ksmbd_ida.c | 56 | ksmbd_test_ida.c | 13 | A | ~80% |

**Gap Summary (mgmt/):**
- All management modules (except ida) have 0% real-call coverage
- Session, share, and tree connect lifecycle completely replicated

### src/protocol/smb1/ (3 files, ~10,500 lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage |
|-----------------|-------|-----------|-------|------|---------------|
| smb1pdu.c | 10,079 | ksmbd_test_smb1_cmds.c, ksmbd_test_smb1_parser.c | 53 | C | ~0% |
| smb1ops.c | 102 | ksmbd_test_smb1_ops.c | 11 | C | ~0% |
| smb1misc.c | 354 | (included in smb1 tests) | -- | C | ~0% |

**Gap Summary (smb1/):**
- 10,000+ lines of SMB1 command handlers with ZERO real-call coverage
- 40+ SMB1 commands completely untested at production level

### src/protocol/smb2/ (14 files, ~14,000+ lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage |
|-----------------|-------|-----------|-------|------|---------------|
| smb2_create.c | 2,954 | ksmbd_test_smb2_create.c | 68 | C | ~0% |
| smb2_query_set.c | 3,392 | ksmbd_test_smb2_query_set.c | 68 | C | ~0% |
| smb2_read_write.c | 1,181 | ksmbd_test_smb2_read_write.c | 37 | C | ~0% |
| smb2_lock.c | 1,058 | ksmbd_test_smb2_lock.c | 37 | C | ~0% |
| smb2_dir.c | 1,370 | ksmbd_test_smb2_dir.c | 37 | C | ~0% |
| smb2_ioctl.c | ~1,600 | ksmbd_test_smb2_ioctl.c | 39 | C | ~0% |
| smb2_session.c | 938 | ksmbd_test_smb2_session.c | 13 | C | ~0% |
| smb2_tree.c | 544 | ksmbd_test_smb2_tree.c | 20 | C | ~0% |
| smb2_negotiate.c | 1,013 | ksmbd_test_smb2_negotiate.c, ksmbd_test_negotiate.c | 65 | C | ~0% |
| smb2_notify.c | ~500 | ksmbd_test_smb2_notify.c | 26 | C | ~0% |
| smb2_misc_cmds.c | ~400 | ksmbd_test_smb2_misc.c | 28 | C | ~0% |
| smb2ops.c | 421 | ksmbd_test_smb2_ops.c | 25 | C | ~0% |
| smb2_pdu_common.c | ~600 | ksmbd_test_pdu_common.c | 22 | C | ~0% |
| smb2misc.c | 558 | ksmbd_test_credit.c | 11 | C | ~0% |
| smb2fruit.c | 830 | ksmbd_test_fruit.c | 45 | C | ~5% |

**Gap Summary (smb2/):**
- **14,000+ lines of SMB2 command handlers with ZERO real-call coverage**
- Every single SMB2 command handler (CREATE, READ, WRITE, LOCK, QUERY_DIR,
  QUERY_INFO, SET_INFO, IOCTL, CANCEL, ECHO, FLUSH, CLOSE, NOTIFY) is
  tested only via replicated logic
- This is the single largest coverage gap in the entire project

### src/transport/ (4 files, ~8,200 lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage |
|-----------------|-------|-----------|-------|------|---------------|
| transport_tcp.c | 964 | ksmbd_test_transport.c | 17 | C | ~0% |
| transport_rdma.c | 2,654 | -- | 0 | D | 0% |
| transport_quic.c | 3,208 | ksmbd_test_quic.c | 33 | C | ~0% |
| transport_ipc.c | 1,416 | ksmbd_test_ipc.c | 16 | C | ~0% |

**Gap Summary (transport/):**
- `transport_rdma.c`: 2,654 lines, NO test file at all
- All transport modules have 0% real-call coverage
- QUIC has 33 tests but all replicated (RFC 9000/9001 compliance untested)

### src/encoding/ (3 files, ~1,570 lines)

| Production File | Lines | Test File | Tests | Tier | Real Coverage |
|-----------------|-------|-----------|-------|------|---------------|
| ndr.c | 645 | ksmbd_test_ndr.c | 20 | B | ~30% |
| unicode.c | 535 | ksmbd_test_unicode.c | 43 | B | ~40% |
| asn1.c | 390 | ksmbd_test_asn1.c | 36 | C | ~5% |

**Gap Summary (encoding/):**
- Best coverage in encoding layer but still mostly replicated logic
- ASN.1/SPNEGO parsing (security-critical) has only replicated tests

### Fuzz Harness Coverage

| Fuzz Harness | Production Target | Coverage Quality |
|--------------|-------------------|-----------------|
| smb2_header_fuzz.c | smb2pdu.c header parsing | Good - tests real parser |
| negotiate_context_fuzz.c | smb2_negotiate.c | Good - tests context parsing |
| create_context_fuzz.c | ksmbd_create_ctx.c | Good - tests context dispatch |
| security_descriptor_fuzz.c | smbacl.c | Good - tests SD parsing |
| lock_request_fuzz.c | smb2_lock.c | Good - tests lock request parsing |
| query_set_info_fuzz.c | smb2_query_set.c | Good - tests info dispatch |
| reparse_point_fuzz.c | ksmbd_reparse.c | Good - tests reparse parsing |
| asn1_fuzz.c | asn1.c | Good - tests SPNEGO parsing |
| ndr_fuzz.c | ndr.c | Good - tests NDR codec |
| path_parse_fuzz.c | misc.c | Good - tests path parsing |
| dfs_referral_fuzz.c | ksmbd_dfs.c | Good - tests DFS parsing |
| quota_request_fuzz.c | ksmbd_quota.c | Good - tests quota parsing |
| transform_header_fuzz.c | smb2_transform.c | Good - tests transform header |
| compression_fuzz.c | smb2_compress.c | Good - tests decompression |
| session_setup_fuzz.c | smb2_session.c | Good - tests session setup parsing |
| smb1_command_fuzz.c | smb1pdu.c | Good - tests SMB1 command parsing |
| compound_request_fuzz.c | smb2pdu.c | Good - tests compound chaining |
| copychunk_fuzz.c | ksmbd_fsctl.c | Good - tests copychunk parsing |
| ioctl_fuzz.c | smb2_ioctl.c | Good - tests IOCTL dispatch |
| tree_connect_fuzz.c | smb2_tree.c | Good - tests tree connect parsing |
| unicode_fuzz.c | unicode.c | Good - tests Unicode conversion |
| wildcard_fuzz.c | misc.c | Good - tests wildcard matching |
| read_request_fuzz.c | smb2_read_write.c | Good - tests read request parsing |
| write_request_fuzz.c | smb2_read_write.c | Good - tests write request parsing |
| flush_request_fuzz.c | smb2_read_write.c | Good - tests flush request parsing |
| close_request_fuzz.c | smb2_misc_cmds.c | Good - tests close request parsing |
| cancel_request_fuzz.c | smb2_lock.c | Good - tests cancel request parsing |
| notify_fuzz.c | ksmbd_notify.c | Good - tests notify parsing |
| oplock_break_fuzz.c | oplock.c | Good - tests oplock break parsing |
| ea_parse_fuzz.c | fs/ | Good - tests EA parsing |
| ipc_message_fuzz.c | transport_ipc.c | Good - tests IPC message parsing |
| quic_packet_fuzz.c | transport_quic.c | Good - tests QUIC packet parsing |
| rsvd_fuzz.c | ksmbd_rsvd.c | Good - tests RSVD parsing |

**Fuzz coverage is the strongest testing layer** -- 33 harnesses covering all major
input parsing surfaces. However, fuzz harnesses test parsing/decoding only, not
the behavioral logic after parsing.

---

## Part II: MS-SMB2 Protocol Specification Coverage

### Section 3.3.5 — Server Processing Rules (92 sections)

This maps every MS-SMB2 v84.0 server-side processing section to test coverage.

| Spec Section | Description | KUnit | Fuzz | Torture | Coverage |
|--------------|-------------|-------|------|---------|----------|
| **3.3.5.1** | Accepting an Incoming Connection | ksmbd_test_connection | -- | -- | C (replicated) |
| **3.3.5.2** | Receiving Any Message | ksmbd_test_pdu_common | smb2_header_fuzz | -- | C+Fuzz |
| **3.3.5.2.1.1** | Decrypting the Message | ksmbd_test_auth (partial) | transform_header_fuzz | -- | B |
| **3.3.5.2.1.2** | Decompressing the Message | ksmbd_test_compress | compression_fuzz | -- | C+Fuzz |
| **3.3.5.2.2** | Verifying the Connection State | ksmbd_test_connection | -- | -- | C |
| **3.3.5.2.3** | Verifying the Sequence Number | ksmbd_test_credit | -- | -- | C |
| **3.3.5.2.4** | Verifying the Signature | ksmbd_test_auth | -- | -- | B |
| **3.3.5.2.5** | Verifying Credit Charge and Payload | ksmbd_test_credit | -- | -- | C |
| **3.3.5.2.6** | Handling Incorrectly Formatted Requests | -- | smb2_header_fuzz | -- | Fuzz only |
| **3.3.5.2.7** | Handling Compounded Requests | ksmbd_test_smb2_compound | compound_request_fuzz | -- | C+Fuzz |
| **3.3.5.2.7.1** | Compounded Unrelated Requests | ksmbd_test_smb2_compound | -- | -- | C |
| **3.3.5.2.7.2** | Compounded Related Requests | ksmbd_test_smb2_compound | -- | -- | C |
| **3.3.5.2.8** | Updating Idle Time | -- | -- | -- | **NONE** |
| **3.3.5.2.9** | Verifying the Session | ksmbd_test_smb2_session | session_setup_fuzz | -- | C+Fuzz |
| **3.3.5.2.10** | Verifying Channel Sequence | ksmbd_test_pdu_common | -- | -- | C |
| **3.3.5.2.11** | Verifying the Tree Connect | ksmbd_test_smb2_tree | tree_connect_fuzz | -- | C+Fuzz |
| **3.3.5.2.12** | Receiving SVHDX operation | ksmbd_test_rsvd | rsvd_fuzz | -- | C+Fuzz |
| **3.3.5.3** | Receiving SMB_COM_NEGOTIATE | ksmbd_test_smb1_parser | smb1_command_fuzz | -- | C+Fuzz |
| **3.3.5.3.1** | SMB 2.1/3.x Support | ksmbd_test_negotiate | -- | -- | C |
| **3.3.5.3.2** | SMB 2.0.2 Support | ksmbd_test_negotiate | -- | -- | C |
| **3.3.5.4** | SMB2 NEGOTIATE Request | ksmbd_test_smb2_negotiate | negotiate_context_fuzz | -- | C+Fuzz |
| **3.3.5.5** | SMB2 SESSION_SETUP | ksmbd_test_smb2_session | session_setup_fuzz | -- | C+Fuzz |
| **3.3.5.5.1** | Authenticating New Session | ksmbd_test_auth | -- | -- | B |
| **3.3.5.5.2** | Reauthenticating Existing Session | -- | -- | -- | **NONE** |
| **3.3.5.5.3** | Handling GSS-API Auth | ksmbd_test_asn1 | asn1_fuzz | -- | C+Fuzz |
| **3.3.5.6** | SMB2 LOGOFF | ksmbd_test_smb2_session | -- | -- | C |
| **3.3.5.7** | SMB2 TREE_CONNECT | ksmbd_test_smb2_tree | tree_connect_fuzz | -- | C+Fuzz |
| **3.3.5.8** | SMB2 TREE_DISCONNECT | ksmbd_test_smb2_tree | -- | -- | C |
| **3.3.5.9** | SMB2 CREATE | ksmbd_test_smb2_create | -- | -- | C |
| **3.3.5.9.1** | CREATE_EA_BUFFER context | -- | create_context_fuzz | -- | Fuzz only |
| **3.3.5.9.2** | CREATE_SD_BUFFER context | ksmbd_test_acl | security_descriptor_fuzz | -- | C+Fuzz |
| **3.3.5.9.3** | CREATE_ALLOCATION_SIZE context | ksmbd_test_smb2_create | -- | -- | C |
| **3.3.5.9.4** | CREATE_TIMEWARP_TOKEN context | -- | -- | -- | **NONE** |
| **3.3.5.9.5** | CREATE_QUERY_MAXIMAL_ACCESS | -- | -- | -- | **NONE** |
| **3.3.5.9.6** | DURABLE_HANDLE_REQUEST | ksmbd_test_smb2_create | -- | -- | C |
| **3.3.5.9.7** | DURABLE_HANDLE_RECONNECT | ksmbd_test_smb2_create | -- | -- | C |
| **3.3.5.9.8** | CREATE_REQUEST_LEASE | ksmbd_test_oplock | -- | -- | B |
| **3.3.5.9.9** | CREATE_QUERY_ON_DISK_ID | -- | -- | -- | **NONE** |
| **3.3.5.9.10** | DURABLE_HANDLE_REQUEST_V2 | ksmbd_test_smb2_create | -- | -- | C |
| **3.3.5.9.11** | CREATE_REQUEST_LEASE_V2 | ksmbd_test_oplock | -- | -- | B |
| **3.3.5.9.12** | DURABLE_HANDLE_RECONNECT_V2 | ksmbd_test_smb2_create | -- | -- | C |
| **3.3.5.9.13** | APP_INSTANCE_ID/VERSION | ksmbd_test_app_instance | -- | -- | C |
| **3.3.5.9.14** | SVHDX_OPEN_DEVICE_CONTEXT | ksmbd_test_rsvd | rsvd_fuzz | -- | C+Fuzz |
| **3.3.5.10** | SMB2 CLOSE | ksmbd_test_smb2_misc | close_request_fuzz | -- | C+Fuzz |
| **3.3.5.11** | SMB2 FLUSH | ksmbd_test_smb2_read_write | flush_request_fuzz | -- | C+Fuzz |
| **3.3.5.12** | SMB2 READ | ksmbd_test_smb2_read_write | read_request_fuzz | -- | C+Fuzz |
| **3.3.5.13** | SMB2 WRITE | ksmbd_test_smb2_read_write | write_request_fuzz | -- | C+Fuzz |
| **3.3.5.14** | SMB2 LOCK | ksmbd_test_smb2_lock | lock_request_fuzz | -- | C+Fuzz |
| **3.3.5.14.1** | Processing Unlocks | ksmbd_test_smb2_lock | -- | -- | C |
| **3.3.5.14.2** | Processing Locks | ksmbd_test_smb2_lock | -- | -- | C |
| **3.3.5.15** | SMB2 IOCTL | ksmbd_test_smb2_ioctl | ioctl_fuzz | -- | C+Fuzz |
| **3.3.5.15.1** | Previous Versions Enum | ksmbd_test_vss | -- | -- | C |
| **3.3.5.15.2** | DFS Referral | ksmbd_test_dfs | dfs_referral_fuzz | -- | C+Fuzz |
| **3.3.5.15.3** | Pipe Transaction | ksmbd_test_fsctl_pipe | -- | -- | C |
| **3.3.5.15.4** | Pipe Peek | ksmbd_test_fsctl_pipe | -- | -- | C |
| **3.3.5.15.5** | Source File Key (copychunk) | ksmbd_test_fsctl_copychunk | copychunk_fuzz | -- | C+Fuzz |
| **3.3.5.15.6** | Server-Side Data Copy | ksmbd_test_fsctl_copychunk | copychunk_fuzz | -- | C+Fuzz |
| **3.3.5.15.7** | Content Info Retrieval (BranchCache) | ksmbd_test_branchcache | -- | -- | C |
| **3.3.5.15.8** | Pass-Through FSCTL | ksmbd_test_fsctl_dispatch | -- | -- | C |
| **3.3.5.15.9** | Resiliency Request | ksmbd_test_resilient | -- | -- | C |
| **3.3.5.15.10** | Pipe Wait | ksmbd_test_fsctl_pipe | -- | -- | C |
| **3.3.5.15.11** | Query Network Interface | -- | -- | -- | **NONE** |
| **3.3.5.15.12** | Validate Negotiate Info | ksmbd_test_fsctl_validate_negotiate | -- | -- | C |
| **3.3.5.15.13** | Set Reparse Point | ksmbd_test_reparse | reparse_point_fuzz | -- | C+Fuzz |
| **3.3.5.15.15** | Shared Virtual Disk Sync | ksmbd_test_rsvd | rsvd_fuzz | -- | C+Fuzz |
| **3.3.5.15.16** | Query Shared Virtual Disk | ksmbd_test_rsvd | -- | -- | C |
| **3.3.5.15.17** | Duplicate Extents | ksmbd_test_fsctl_duplicate | -- | -- | C |
| **3.3.5.15.18** | Extended Duplicate Extents | -- | -- | -- | **NONE** |
| **3.3.5.15.19** | Set Read CopyNumber | -- | -- | -- | **NONE** |
| **3.3.5.16** | SMB2 CANCEL | ksmbd_test_smb2_cancel | cancel_request_fuzz | -- | C+Fuzz |
| **3.3.5.17** | SMB2 ECHO | ksmbd_test_smb2_misc | -- | -- | C |
| **3.3.5.18** | SMB2 QUERY_DIRECTORY | ksmbd_test_smb2_dir | -- | -- | C |
| **3.3.5.19** | SMB2 CHANGE_NOTIFY | ksmbd_test_smb2_notify | notify_fuzz | -- | C+Fuzz |
| **3.3.5.20** | SMB2 QUERY_INFO | ksmbd_test_smb2_query_set, ksmbd_test_info_*.c | query_set_info_fuzz | -- | C+Fuzz |
| **3.3.5.20.1** | QUERY_INFO File | ksmbd_test_info_file.c | -- | -- | C |
| **3.3.5.20.2** | QUERY_INFO Filesystem | ksmbd_test_info_fs.c | -- | -- | C |
| **3.3.5.20.3** | QUERY_INFO Security | ksmbd_test_info_security.c | security_descriptor_fuzz | -- | C+Fuzz |
| **3.3.5.20.4** | QUERY_INFO Quota | ksmbd_test_info_quota.c | quota_request_fuzz | -- | C+Fuzz |
| **3.3.5.21** | SMB2 SET_INFO | ksmbd_test_smb2_query_set | -- | -- | C |
| **3.3.5.21.1** | SET_INFO File | ksmbd_test_info_file_set.c | -- | -- | C |
| **3.3.5.21.2** | SET_INFO Filesystem | -- | -- | -- | **NONE** |
| **3.3.5.21.3** | SET_INFO Security | ksmbd_test_acl | -- | -- | C |
| **3.3.5.21.4** | SET_INFO Quota | ksmbd_test_quota | -- | -- | C |
| **3.3.5.22** | OPLOCK_BREAK Ack | ksmbd_test_oplock | oplock_break_fuzz | -- | B+Fuzz |
| **3.3.5.22.1** | Oplock Acknowledgment | ksmbd_test_oplock | -- | -- | B |
| **3.3.5.22.2** | Lease Acknowledgment | ksmbd_test_oplock | -- | -- | B |

### Coverage Summary — MS-SMB2 Spec

| Coverage Level | Count | % |
|----------------|-------|---|
| **A/B (Real integration)** | 7 | 8% |
| **C (Replicated logic)** | 49 | 53% |
| **C+Fuzz (Replicated + fuzz)** | 27 | 29% |
| **NONE (no test coverage)** | 9 | 10% |
| **Total** | 92 | 100% |

### Sections with ZERO Coverage

1. **3.3.5.2.8** — Updating Idle Time (deadtime enforcement)
2. **3.3.5.5.2** — Reauthenticating Existing Session
3. **3.3.5.9.4** — CREATE_TIMEWARP_TOKEN context (VSS snapshot opens)
4. **3.3.5.9.5** — CREATE_QUERY_MAXIMAL_ACCESS
5. **3.3.5.9.9** — CREATE_QUERY_ON_DISK_ID
6. **3.3.5.15.11** — Query Network Interface
7. **3.3.5.15.18** — Extended Duplicate Extents
8. **3.3.5.15.19** — Set Read CopyNumber
9. **3.3.5.21.2** — SET_INFO Filesystem

### MS-SMB2 Timers (Section 3.3.2)

| Timer | Spec Section | Test Coverage |
|-------|-------------|---------------|
| Oplock Break Ack Timer | 3.3.2.1 | ksmbd_test_oplock (replicated) |
| Durable Open Scavenger Timer | 3.3.2.2 | ksmbd_test_smb2_create (replicated) |
| Session Expiration Timer | 3.3.2.3 | **NONE** (new config param, no stress test) |
| Resilient Open Scavenger Timer | 3.3.2.4 | ksmbd_test_resilient (replicated) |
| Lease Break Ack Timer | 3.3.2.5 | ksmbd_test_oplock (replicated) |

### MS-SMB2 Algorithms (Section 3.3.1)

| Algorithm | Spec Section | Test Coverage |
|-----------|-------------|---------------|
| Sequence Number Handling | 3.3.1.1 | ksmbd_test_credit (replicated) |
| Credit Granting | 3.3.1.2 | ksmbd_test_credit (replicated) |
| Change Notifications | 3.3.1.3 | ksmbd_test_notify (replicated) |
| Leasing | 3.3.1.4 | ksmbd_test_oplock (partially real) |

---

## Part III: MS-SMB (v1) Protocol Specification Coverage

### Section 3.3.5 — Server Processing Rules (38 sections)

| Spec Section | Description | Test Coverage |
|--------------|-------------|---------------|
| **3.3.5.1** | Receiving Any Message | ksmbd_test_smb1_parser (C) |
| **3.3.5.1.1** | Scanning Path for Previous Version | **NONE** |
| **3.3.5.1.2** | Granting Oplocks | ksmbd_test_oplock (B) |
| **3.3.5.2** | SMB_COM_NEGOTIATE | ksmbd_test_smb1_cmds (C) |
| **3.3.5.3** | SMB_COM_SESSION_SETUP_ANDX | ksmbd_test_smb1_cmds (C) |
| **3.3.5.4** | SMB_COM_TREE_CONNECT_ANDX | ksmbd_test_smb1_cmds (C) |
| **3.3.5.6** | SMB_COM_OPEN_ANDX | ksmbd_test_smb1_cmds (C) |
| **3.3.5.7** | SMB_COM_READ_ANDX | ksmbd_test_smb1_cmds (C) |
| **3.3.5.8** | SMB_COM_WRITE_ANDX | ksmbd_test_smb1_cmds (C) |
| **3.3.5.9** | SMB_COM_SEARCH | **NONE** |
| **3.3.5.10** | TRANSACTION2 subcommands | ksmbd_test_smb1_cmds (C) |
| **3.3.5.10.1** | Information Levels | **NONE** |
| **3.3.5.10.2** | TRANS2_FIND_FIRST2 | ksmbd_test_smb1_cmds (C) |
| **3.3.5.10.3** | TRANS2_FIND_NEXT2 | **NONE** |
| **3.3.5.10.4** | TRANS2_QUERY_FILE_INFORMATION | ksmbd_test_smb1_cmds (C) |
| **3.3.5.10.5** | TRANS2_QUERY_PATH_INFORMATION | **NONE** |
| **3.3.5.10.6** | TRANS2_SET_FILE_INFORMATION | ksmbd_test_smb1_cmds (C) |
| **3.3.5.10.7** | TRANS2_SET_PATH_INFORMATION | **NONE** |
| **3.3.5.10.9** | TRANS2_SET_FS_INFORMATION | **NONE** |
| **3.3.5.11** | NT_TRANSACT subcommands | ksmbd_test_smb1_cmds (C) |
| **3.3.5.11.1** | NT_TRANSACT_IOCTL | ksmbd_test_smb1_cmds (C) |
| **3.3.5.11.1.1** | FSCTL_SRV_ENUMERATE_SNAPSHOTS | **NONE** |
| **3.3.5.11.1.2** | FSCTL_SRV_REQUEST_RESUME_KEY | **NONE** |
| **3.3.5.11.1.3** | FSCTL_SRV_COPYCHUNK | **NONE** |
| **3.3.5.11.2** | NT_TRANS_QUERY_QUOTA | ksmbd_test_smb1_cmds (C) |
| **3.3.5.11.3** | NT_TRANS_SET_QUOTA | **NONE** |
| **3.3.5.11.4** | NT_TRANSACT_CREATE | ksmbd_test_smb1_cmds (C) |

### Coverage Summary — MS-SMB Spec

| Coverage Level | Count | % |
|----------------|-------|---|
| **B (Partially real)** | 1 | 3% |
| **C (Replicated logic)** | 15 | 39% |
| **NONE** | 12 | 32% |
| **Not applicable** (client-only) | 10 | 26% |
| **Total** | 38 | 100% |

---

## Part IV: Missing Test Categories

### 1. No Stress Tests

There are zero stress tests in the entire suite. No tests for:
- Connection storms (many simultaneous connections)
- Credit exhaustion (consuming all credits)
- Lock saturation (max_lock_count locks)
- File descriptor exhaustion (max_open_files)
- Session exhaustion (max_sessions)
- Memory pressure (large payloads, many concurrent requests)
- Timeout behavior (tcp_recv_timeout, session_timeout)
- Compression bombs (small input expanding to huge output)

See [11_STRESS_TESTS.md](11_STRESS_TESTS.md) for the complete stress test plan.

### 2. No Concurrency Tests

No tests exercise concurrent access patterns:
- Multiple threads/connections accessing same file
- Oplock break during I/O
- Lock contention
- Session binding/unbinding during active I/O
- Tree disconnect during active I/O

### 3. No Error Path Tests

Most tests exercise happy paths. Missing:
- Disk full during WRITE
- Network disconnection during I/O
- IPC timeout during authentication
- Module unload during active connections
- OOM during buffer allocation

### 4. No Regression Tests for Fixed Bugs

The 40 regression tests described in [10_EDGE_CASE_REGRESSION.md](10_EDGE_CASE_REGRESSION.md)
are designed but not implemented. These cover all bugs fixed in sessions 2026-02-28
through 2026-03-02 (lock fl_end off-by-one, compound FID propagation, delete-on-close,
lock sequence replay, etc.).

### 5. No RDMA Tests

`transport_rdma.c` (2,654 lines) has no test file and no fuzz harness. This is the
only production module with zero test presence.

### 6. No ksmbd-tools Tests

The ksmbd-tools userspace daemon has no unit tests. The config parser, IPC message
builder, share management, and user management functions are untested.

---

## Part V: Priority Remediation Plan

### P0 — Must Fix (Security-Critical Gaps)

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| 1 | Stress tests for configurable limits | Denial of service | Medium |
| 2 | Compression bomb detection test | Remote OOM | Low |
| 3 | Session reauthentication (3.3.5.5.2) | Auth bypass | Medium |
| 4 | Connection state machine integration | Use-after-free | High |
| 5 | VFS path traversal integration | Path escape | High |
| 6 | RDMA transport test file | Memory corruption | High |

### P1 — Should Fix (Protocol Compliance)

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| 7 | CREATE_TIMEWARP_TOKEN (3.3.5.9.4) | VSS noncompliance | Medium |
| 8 | CREATE_QUERY_MAXIMAL_ACCESS (3.3.5.9.5) | Access mask noncompliance | Low |
| 9 | Query Network Interface (3.3.5.15.11) | Multichannel noncompliance | Medium |
| 10 | Idle time update (3.3.5.2.8) | Deadtime noncompliance | Low |
| 11 | SET_INFO Filesystem (3.3.5.21.2) | Info level noncompliance | Low |
| 12 | SMB1 TRANS2 info levels (3.3.5.10.1) | SMB1 noncompliance | Low |
| 13 | All 5 SMB2 timer tests | Timer behavior noncompliance | Medium |

### P2 — Nice to Have (Quality)

| # | Gap | Impact | Effort |
|---|-----|--------|--------|
| 14 | Convert replicated tests to integration | Divergence risk | Very High |
| 15 | Concurrency test suite | Race conditions | High |
| 16 | ksmbd-tools unit tests | Config parsing bugs | Medium |
| 17 | Error path coverage | Error handling bugs | Medium |
| 18 | 40 regression tests from 10_EDGE_CASE_REGRESSION.md | Regression prevention | Medium |

---

## Appendix: Test Files Without Corresponding Production Module

These test files test functionality that spans multiple production files:

| Test File | What It Tests |
|-----------|--------------|
| ksmbd_test_smb_common.c | smb_common.c (protocol negotiation) |
| ksmbd_test_netmisc.c | netmisc.c (error code mapping) |
| ksmbd_test_smb2_dispatch.c | smb2pdu.c (command dispatch table) |
| ksmbd_test_smb2_compound.c | smb2pdu.c (compound request chaining) |
| ksmbd_test_create_ctx_tags.c | ksmbd_create_ctx.c (tag-based dispatch) |

## Appendix: Production Files Without Any Test File

| Production File | Lines | Priority |
|-----------------|-------|----------|
| transport_rdma.c | 2,654 | P0 |
| compat.c | 129 | P2 |
