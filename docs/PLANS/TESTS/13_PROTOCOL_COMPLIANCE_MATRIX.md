# 13. Protocol Compliance Matrix

## References
- **[MS-SMB]** v54.0, January 14, 2026 — `protocol/[MS-SMB].pdf`
- **[MS-SMB2]** v84.0, January 14, 2026 — `protocol/[MS-SMB2].pdf`

This matrix maps every protocol-defined operation and structure to:
1. **Implementation status** in ksmbd source code
2. **Test coverage** (KUnit, fuzz, integration)
3. **Gap priority** for remediation

Legend:
- Impl: Y=implemented, P=partial, N=not implemented, NA=not applicable (client-only)
- Test: A=integration, B=hybrid, C=replicated, F=fuzz-only, **X=none**

---

## MS-SMB2 — Message Syntax (Section 2.2)

### Core Structures

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.1 | SMB2 Packet Header | Y | smb2pdu.h, smb2ops.c | C+F | -- |
| 2.2.1.1 | Packet Header - ASYNC | Y | smb2_pdu_common.c | C | -- |
| 2.2.1.2 | Packet Header - SYNC | Y | smb2_pdu_common.c | C | -- |
| 2.2.2 | SMB2 ERROR Response | Y | smb2_pdu_common.c | C | -- |
| 2.2.2.1 | Error Context Response | P | smb2_pdu_common.c | X | P2 |
| 2.2.2.2.1 | Symbolic Link Error Response | Y | smb2_create.c | X | P1 |
| 2.2.2.2.2 | Share Redirect Error Context | N | -- | X | P2 (cluster) |

### NEGOTIATE (2.2.3 / 2.2.4)

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.3 | NEGOTIATE Request | Y | smb2_negotiate.c | C+F | -- |
| 2.2.3.1.1 | PREAUTH_INTEGRITY_CAPABILITIES | Y | smb2_negotiate.c | C+F | -- |
| 2.2.3.1.2 | ENCRYPTION_CAPABILITIES | Y | smb2_negotiate.c | C+F | -- |
| 2.2.3.1.3 | COMPRESSION_CAPABILITIES | Y | smb2_negotiate.c | C+F | -- |
| 2.2.3.1.4 | NETNAME_NEGOTIATE_CONTEXT_ID | Y | smb2_negotiate.c | C | -- |
| 2.2.3.1.5 | TRANSPORT_CAPABILITIES | Y | smb2_negotiate.c | C | -- |
| 2.2.3.1.6 | RDMA_TRANSFORM_CAPABILITIES | Y | smb2_negotiate.c | C | -- |
| 2.2.3.1.7 | SIGNING_CAPABILITIES | Y | smb2_negotiate.c | C | -- |
| 2.2.4 | NEGOTIATE Response | Y | smb2_negotiate.c | C+F | -- |
| 2.2.4.1.1-7 | Response Contexts (all 7) | Y | smb2_negotiate.c | C | -- |

### SESSION (2.2.5 / 2.2.6)

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.5 | SESSION_SETUP Request | Y | smb2_session.c | C+F | -- |
| 2.2.6 | SESSION_SETUP Response | Y | smb2_session.c | C | -- |
| 2.2.7 | LOGOFF Request | Y | smb2_session.c | C | -- |
| 2.2.8 | LOGOFF Response | Y | smb2_session.c | C | -- |

### TREE CONNECT (2.2.9 / 2.2.10)

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.9 | TREE_CONNECT Request | Y | smb2_tree.c | C+F | -- |
| 2.2.9.1 | TREE_CONNECT Request Extension | Y | smb2_tree.c | C | -- |
| 2.2.9.2.1 | REMOTED_IDENTITY Context | P | smb2_tree.c | X | P2 |
| 2.2.10 | TREE_CONNECT Response | Y | smb2_tree.c | C | -- |
| 2.2.11 | TREE_DISCONNECT Request | Y | smb2_tree.c | C | -- |
| 2.2.12 | TREE_DISCONNECT Response | Y | smb2_tree.c | C | -- |

### CREATE (2.2.13 / 2.2.14) — 15 Create Contexts

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.13 | CREATE Request | Y | smb2_create.c | C | -- |
| 2.2.13.1 | Access Mask Encoding | Y | smb2_create.c | C | -- |
| 2.2.13.1.2 | Directory_Access_Mask | Y | smb2_create.c | C | -- |
| 2.2.13.2 | CREATE_CONTEXT Request Values | Y | ksmbd_create_ctx.c | B+F | -- |
| 2.2.13.2.1 | CREATE_EA_BUFFER | Y | smb2_create.c | F | -- |
| 2.2.13.2.2 | CREATE_SD_BUFFER | Y | smb2_create.c, smbacl.c | C+F | -- |
| 2.2.13.2.3 | DURABLE_HANDLE_REQUEST | Y | smb2_create.c | C | -- |
| 2.2.13.2.4 | DURABLE_HANDLE_RECONNECT | Y | smb2_create.c | C | -- |
| 2.2.13.2.5 | QUERY_MAXIMAL_ACCESS | Y | smb2_create.c | **X** | **P1** |
| 2.2.13.2.6 | CREATE_ALLOCATION_SIZE | Y | smb2_create.c | C | -- |
| 2.2.13.2.7 | CREATE_TIMEWARP_TOKEN | P | smb2_create.c | **X** | **P1** |
| 2.2.13.2.8 | CREATE_REQUEST_LEASE | Y | oplock.c | B | -- |
| 2.2.13.2.9 | CREATE_QUERY_ON_DISK_ID | Y | smb2_create.c | **X** | **P1** |
| 2.2.13.2.10 | CREATE_REQUEST_LEASE_V2 | Y | oplock.c | B | -- |
| 2.2.13.2.11 | DURABLE_HANDLE_REQUEST_V2 | Y | smb2_create.c | C | -- |
| 2.2.13.2.12 | DURABLE_HANDLE_RECONNECT_V2 | Y | smb2_create.c | C | -- |
| 2.2.13.2.13 | CREATE_APP_INSTANCE_ID | Y | ksmbd_app_instance.c | C | -- |
| 2.2.13.2.14 | SVHDX_OPEN_DEVICE_CONTEXT | Y | ksmbd_rsvd.c | C+F | -- |
| 2.2.13.2.15 | CREATE_APP_INSTANCE_VERSION | Y | ksmbd_app_instance.c | C | -- |
| 2.2.14 | CREATE Response | Y | smb2_create.c | C | -- |
| 2.2.14.1 | SMB2_FILEID | Y | smb2_create.c | C | -- |
| 2.2.14.2 | Response Context Values | Y | smb2_create.c | C | -- |

### File I/O (2.2.15 - 2.2.22)

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.15 | CLOSE Request | Y | smb2_misc_cmds.c | C+F | -- |
| 2.2.16 | CLOSE Response | Y | smb2_misc_cmds.c | C | -- |
| 2.2.17 | FLUSH Request | Y | smb2_read_write.c | C+F | -- |
| 2.2.18 | FLUSH Response | Y | smb2_read_write.c | C | -- |
| 2.2.19 | READ Request | Y | smb2_read_write.c | C+F | -- |
| 2.2.20 | READ Response | Y | smb2_read_write.c | C | -- |
| 2.2.21 | WRITE Request | Y | smb2_read_write.c | C+F | -- |
| 2.2.22 | WRITE Response | Y | smb2_read_write.c | C | -- |

### Lock (2.2.26 / 2.2.27)

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.26 | LOCK Request | Y | smb2_lock.c | C+F | -- |
| 2.2.27 | LOCK Response | Y | smb2_lock.c | C | -- |

### IOCTL (2.2.31 / 2.2.32) — 19+ FSCTL handlers

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.31 | IOCTL Request | Y | smb2_ioctl.c | C+F | -- |
| 2.2.31.1 | SRV_COPYCHUNK_COPY | Y | ksmbd_fsctl.c | C+F | -- |
| 2.2.31.2 | SRV_SNAPSHOT_ARRAY | Y | ksmbd_vss.c | C | -- |
| 2.2.31.3 | SRV_REQUEST_RESUME_KEY | Y | ksmbd_fsctl.c | C | -- |
| 2.2.31.4 | NETWORK_INTERFACE_INFO | Y | smb2_ioctl.c | **X** | **P1** |
| 2.2.31.5 | VALIDATE_NEGOTIATE_INFO | Y | ksmbd_fsctl.c | C | -- |
| 2.2.32 | IOCTL Response | Y | smb2_ioctl.c | C | -- |
| 2.2.32.1 | SRV_COPYCHUNK_RESPONSE | Y | ksmbd_fsctl.c | C | -- |
| 2.2.32.3 | NETWORK_RESILIENCY | Y | ksmbd_resilient.c | C | -- |

### Query/Set (2.2.37 - 2.2.40)

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.37 | QUERY_INFO Request | Y | smb2_query_set.c | C+F | -- |
| 2.2.38 | QUERY_INFO Response | Y | smb2_query_set.c | C | -- |
| 2.2.39 | SET_INFO Request | Y | smb2_query_set.c | C | -- |
| 2.2.40 | SET_INFO Response | Y | smb2_query_set.c | C | -- |

### Other Commands

| Section | Structure | Impl | Source File | Test | Gap Priority |
|---------|-----------|------|-------------|------|-------------|
| 2.2.28 | ECHO Request | Y | smb2_misc_cmds.c | C | -- |
| 2.2.29 | ECHO Response | Y | smb2_misc_cmds.c | C | -- |
| 2.2.30 | CANCEL Request | Y | smb2_lock.c | C+F | -- |
| 2.2.33 | QUERY_DIRECTORY Request | Y | smb2_dir.c | C | -- |
| 2.2.34 | QUERY_DIRECTORY Response | Y | smb2_dir.c | C | -- |
| 2.2.35 | CHANGE_NOTIFY Request | Y | smb2_notify.c | C+F | -- |
| 2.2.36 | CHANGE_NOTIFY Response | Y | smb2_notify.c | C | -- |
| 2.2.23 | OPLOCK_BREAK Notification | Y | oplock.c | B+F | -- |
| 2.2.24 | OPLOCK_BREAK Acknowledgment | Y | oplock.c | B | -- |
| 2.2.25 | Lease Break | Y | oplock.c | B | -- |
| 2.2.41 | Transform Header | Y | smb2_pdu_common.c | C+F | -- |
| 2.2.42 | Compression Transform | Y | smb2_compress.c | C+F | -- |

---

## MS-SMB2 — Server Processing (Section 3.3.5)

### Request Validation Pipeline

| Section | Processing Rule | Impl | Test | Notes |
|---------|----------------|------|------|-------|
| 3.3.5.1 | Accepting Incoming Connection | Y | C | connection.c, transport_tcp.c |
| 3.3.5.2 | Receiving Any Message | Y | C | server.c __handle_ksmbd_work |
| 3.3.5.2.1.1 | Decrypting the Message | Y | B | auth.c ksmbd_crypt_message |
| 3.3.5.2.1.2 | Decompressing the Message | Y | C+F | smb2_compress.c |
| 3.3.5.2.2 | Verifying Connection State | Y | C | connection.c state checks |
| 3.3.5.2.3 | Verifying Sequence Number | Y | C | smb2misc.c credit check |
| 3.3.5.2.4 | Verifying the Signature | Y | B | auth.c signing functions |
| 3.3.5.2.5 | Verifying Credit Charge | Y | C | smb2misc.c |
| 3.3.5.2.6 | Incorrectly Formatted Requests | Y | F | smb2_header_fuzz |
| 3.3.5.2.7 | Compounded Requests | Y | C+F | smb2_pdu_common.c |
| 3.3.5.2.7.1 | Unrelated Compounds | Y | C | smb2_pdu_common.c |
| 3.3.5.2.7.2 | Related Compounds | Y | C | smb2_pdu_common.c |
| 3.3.5.2.8 | Updating Idle Time | Y | **X** | deadtime in server.c |
| 3.3.5.2.9 | Verifying the Session | Y | C+F | smb2_session.c |
| 3.3.5.2.10 | Verifying Channel Sequence | Y | C | smb2_pdu_common.c |
| 3.3.5.2.11 | Verifying Tree Connect | Y | C+F | smb2_tree.c |
| 3.3.5.2.12 | SVHDX Operation | Y | C+F | ksmbd_rsvd.c |

### Command Handlers

| Section | Handler | Impl | Test | FSCTL Sub-handler |
|---------|---------|------|------|-------------------|
| 3.3.5.3 | SMB_COM_NEGOTIATE | Y | C+F | -- |
| 3.3.5.4 | SMB2 NEGOTIATE | Y | C+F | -- |
| 3.3.5.5 | SMB2 SESSION_SETUP | Y | C+F | -- |
| 3.3.5.5.1 | Auth new session | Y | B | -- |
| 3.3.5.5.2 | Reauth existing | Y | **X** | **P0** |
| 3.3.5.5.3 | GSS-API auth | Y | C+F | -- |
| 3.3.5.6 | SMB2 LOGOFF | Y | C | -- |
| 3.3.5.7 | SMB2 TREE_CONNECT | Y | C+F | -- |
| 3.3.5.8 | SMB2 TREE_DISCONNECT | Y | C | -- |
| 3.3.5.9 | SMB2 CREATE | Y | C | -- |
| 3.3.5.9.1 | EA_BUFFER ctx | Y | F | -- |
| 3.3.5.9.2 | SD_BUFFER ctx | Y | C+F | -- |
| 3.3.5.9.3 | ALLOCATION_SIZE ctx | Y | C | -- |
| 3.3.5.9.4 | TIMEWARP_TOKEN ctx | P | **X** | **P1** (VSS open) |
| 3.3.5.9.5 | QUERY_MAXIMAL_ACCESS ctx | Y | **X** | **P1** |
| 3.3.5.9.6 | DURABLE_HANDLE_REQ | Y | C | -- |
| 3.3.5.9.7 | DURABLE_HANDLE_RECONNECT | Y | C | -- |
| 3.3.5.9.8 | REQUEST_LEASE | Y | B | -- |
| 3.3.5.9.9 | QUERY_ON_DISK_ID ctx | Y | **X** | **P1** |
| 3.3.5.9.10 | DURABLE_V2 REQ | Y | C | -- |
| 3.3.5.9.11 | LEASE_V2 | Y | B | -- |
| 3.3.5.9.12 | DURABLE_V2 RECONNECT | Y | C | -- |
| 3.3.5.9.13 | APP_INSTANCE ctx | Y | C | -- |
| 3.3.5.9.14 | SVHDX ctx | Y | C+F | -- |
| 3.3.5.10 | SMB2 CLOSE | Y | C+F | -- |
| 3.3.5.11 | SMB2 FLUSH | Y | C+F | -- |
| 3.3.5.12 | SMB2 READ | Y | C+F | -- |
| 3.3.5.13 | SMB2 WRITE | Y | C+F | -- |
| 3.3.5.14 | SMB2 LOCK | Y | C+F | -- |
| 3.3.5.14.1 | Processing Unlocks | Y | C | -- |
| 3.3.5.14.2 | Processing Locks | Y | C | -- |
| 3.3.5.15 | SMB2 IOCTL | Y | C+F | -- |
| 3.3.5.15.1 | Enum Previous Versions | Y | C | ksmbd_vss.c |
| 3.3.5.15.2 | DFS Referral | Y | C+F | ksmbd_dfs.c |
| 3.3.5.15.3 | Pipe Transaction | Y | C | ksmbd_fsctl.c |
| 3.3.5.15.4 | Pipe Peek | Y | C | ksmbd_fsctl.c |
| 3.3.5.15.5 | Source File Key | Y | C+F | ksmbd_fsctl.c |
| 3.3.5.15.6 | Server-Side Copy | Y | C+F | ksmbd_fsctl.c |
| 3.3.5.15.7 | Content Info (BranchCache) | Y | C | ksmbd_branchcache.c |
| 3.3.5.15.8 | Pass-Through FSCTL | Y | C | ksmbd_fsctl.c |
| 3.3.5.15.9 | Resiliency Request | Y | C | ksmbd_resilient.c |
| 3.3.5.15.10 | Pipe Wait | Y | C | ksmbd_fsctl.c |
| 3.3.5.15.11 | Query Network Interface | Y | **X** | **P1** |
| 3.3.5.15.12 | Validate Negotiate Info | Y | C | ksmbd_fsctl.c |
| 3.3.5.15.13 | Set Reparse Point | Y | C+F | ksmbd_reparse.c |
| 3.3.5.15.15 | SVHD Sync Tunnel | Y | C+F | ksmbd_rsvd.c |
| 3.3.5.15.16 | Query SVHD Support | Y | C | ksmbd_rsvd.c |
| 3.3.5.15.17 | Duplicate Extents | Y | C | ksmbd_fsctl.c |
| 3.3.5.15.18 | Extended Dup Extents | P | **X** | **P2** |
| 3.3.5.15.19 | Set Read CopyNumber | N | **X** | **P2** (cluster) |
| 3.3.5.16 | SMB2 CANCEL | Y | C+F | -- |
| 3.3.5.17 | SMB2 ECHO | Y | C | -- |
| 3.3.5.18 | SMB2 QUERY_DIRECTORY | Y | C | -- |
| 3.3.5.19 | SMB2 CHANGE_NOTIFY | Y | C+F | -- |
| 3.3.5.20 | SMB2 QUERY_INFO | Y | C+F | -- |
| 3.3.5.20.1 | INFO_FILE | Y | C | ksmbd_info.c |
| 3.3.5.20.2 | INFO_FILESYSTEM | Y | C | ksmbd_info.c |
| 3.3.5.20.3 | INFO_SECURITY | Y | C+F | smbacl.c |
| 3.3.5.20.4 | INFO_QUOTA | Y | C+F | ksmbd_quota.c |
| 3.3.5.21 | SMB2 SET_INFO | Y | C | -- |
| 3.3.5.21.1 | SET_INFO File | Y | C | ksmbd_info.c |
| 3.3.5.21.2 | SET_INFO Filesystem | P | **X** | **P1** |
| 3.3.5.21.3 | SET_INFO Security | Y | C | smbacl.c |
| 3.3.5.21.4 | SET_INFO Quota | Y | C | ksmbd_quota.c |
| 3.3.5.22 | OPLOCK_BREAK Ack | Y | B+F | -- |
| 3.3.5.22.1 | Oplock Ack | Y | B | oplock.c |
| 3.3.5.22.2 | Lease Ack | Y | B | oplock.c |

### Server Timers (3.3.2)

| Section | Timer | Impl | Test | Stress Test |
|---------|-------|------|------|-------------|
| 3.3.2.1 | Oplock Break Ack Timer | Y | C | S11.02 |
| 3.3.2.2 | Durable Open Scavenger | Y | C | S07.05 |
| 3.3.2.3 | Session Expiration | Y | **X** | **S02.02** |
| 3.3.2.4 | Resilient Open Scavenger | Y | C | -- |
| 3.3.2.5 | Lease Break Ack Timer | Y | C | S11.02 |

### Higher-Layer Events (3.3.4)

| Section | Event | Impl | Test |
|---------|-------|------|------|
| 3.3.4.1 | Sending Any Outgoing Message | Y | C |
| 3.3.4.1.1 | Signing the Message | Y | B |
| 3.3.4.1.2 | Granting Credits | Y | C |
| 3.3.4.1.3 | Compounded Responses | Y | C |
| 3.3.4.1.4 | Encrypting the Message | Y | B |
| 3.3.4.1.5 | Compressing the Message | Y | C+F |
| 3.3.4.6 | Oplock Break | Y | B |
| 3.3.4.7 | Lease Break | Y | B |
| 3.3.4.8 | DFS Active | Y | C |
| 3.3.4.12 | Closing a Session | Y | C |

---

## MS-SMB — Server Processing (Section 3.3.5)

| Section | Handler | Impl | Test | Notes |
|---------|---------|------|------|-------|
| 3.3.5.1 | Receiving Any Message | Y | C | smb1pdu.c |
| 3.3.5.1.1 | Scanning for @GMT token | P | **X** | VSS in SMB1 |
| 3.3.5.1.2 | Granting Oplocks | Y | B | oplock.c |
| 3.3.5.2 | SMB_COM_NEGOTIATE | Y | C+F | smb1pdu.c |
| 3.3.5.3 | SMB_COM_SESSION_SETUP_ANDX | Y | C | smb1pdu.c |
| 3.3.5.4 | SMB_COM_TREE_CONNECT_ANDX | Y | C | smb1pdu.c |
| 3.3.5.6 | SMB_COM_OPEN_ANDX | Y | C | smb1pdu.c |
| 3.3.5.7 | SMB_COM_READ_ANDX | Y | C | smb1pdu.c |
| 3.3.5.8 | SMB_COM_WRITE_ANDX | Y | C | smb1pdu.c |
| 3.3.5.9 | SMB_COM_SEARCH | Y | **X** | smb1pdu.c |
| 3.3.5.10 | TRANSACTION2 | Y | C | smb1pdu.c |
| 3.3.5.10.1 | Any Information Level | Y | **X** | Info level dispatch |
| 3.3.5.10.2 | TRANS2_FIND_FIRST2 | Y | C | smb1pdu.c |
| 3.3.5.10.3 | TRANS2_FIND_NEXT2 | Y | **X** | smb1pdu.c |
| 3.3.5.10.4 | TRANS2_QUERY_FILE_INFO | Y | C | smb1pdu.c |
| 3.3.5.10.5 | TRANS2_QUERY_PATH_INFO | Y | **X** | smb1pdu.c |
| 3.3.5.10.6 | TRANS2_SET_FILE_INFO | Y | C | smb1pdu.c |
| 3.3.5.10.7 | TRANS2_SET_PATH_INFO | Y | **X** | smb1pdu.c |
| 3.3.5.10.9 | TRANS2_SET_FS_INFO | P | **X** | smb1pdu.c |
| 3.3.5.11 | NT_TRANSACT | Y | C | smb1pdu.c |
| 3.3.5.11.1 | NT_TRANSACT_IOCTL | Y | C | smb1pdu.c |
| 3.3.5.11.1.1 | ENUMERATE_SNAPSHOTS | Y | **X** | ksmbd_vss.c |
| 3.3.5.11.1.2 | REQUEST_RESUME_KEY | Y | **X** | ksmbd_fsctl.c |
| 3.3.5.11.1.3 | SRV_COPYCHUNK | Y | **X** | ksmbd_fsctl.c |
| 3.3.5.11.2 | NT_TRANS_QUERY_QUOTA | Y | C | ksmbd_quota.c |
| 3.3.5.11.3 | NT_TRANS_SET_QUOTA | Y | **X** | ksmbd_quota.c |
| 3.3.5.11.4 | NT_TRANSACT_CREATE | Y | C | smb1pdu.c |

### MS-SMB Additional Commands (from 2.2.4)

| Command | Opcode | Impl | Test | Notes |
|---------|--------|------|------|-------|
| SMB_COM_OPEN_ANDX | 0x2D | Y | C | smb1pdu.c |
| SMB_COM_READ_ANDX | 0x2E | Y | C | smb1pdu.c |
| SMB_COM_WRITE_ANDX | 0x2F | Y | C | smb1pdu.c |
| SMB_COM_TRANSACTION2 | 0x32 | Y | C | smb1pdu.c |
| SMB_COM_NEGOTIATE | 0x72 | Y | C+F | smb1pdu.c |
| SMB_COM_SESSION_SETUP_ANDX | 0x73 | Y | C | smb1pdu.c |
| SMB_COM_TREE_CONNECT_ANDX | 0x75 | Y | C | smb1pdu.c |
| SMB_COM_NT_TRANSACT | 0xA0 | Y | C | smb1pdu.c |
| SMB_COM_NT_CREATE_ANDX | 0xA2 | Y | C | smb1pdu.c |
| SMB_COM_SEARCH | 0x81 | Y | **X** | smb1pdu.c |
| SMB_COM_CLOSE | 0x04 | Y | C | smb1pdu.c |
| SMB_COM_DELETE | 0x06 | Y | C | smb1pdu.c |
| SMB_COM_RENAME | 0x07 | Y | C | smb1pdu.c |
| SMB_COM_CHECK_DIRECTORY | 0x10 | Y | C | smb1pdu.c |
| SMB_COM_ECHO | 0x2B | Y | C | smb1pdu.c |
| SMB_COM_LOGOFF_ANDX | 0x74 | Y | C | smb1pdu.c |
| SMB_COM_TREE_DISCONNECT | 0x71 | Y | C | smb1pdu.c |
| SMB_COM_FLUSH | 0x05 | Y | C | smb1pdu.c |
| SMB_COM_CREATE_DIRECTORY | 0x00 | Y | C | smb1pdu.c |
| SMB_COM_DELETE_DIRECTORY | 0x01 | Y | C | smb1pdu.c |
| SMB_COM_LOCKING_ANDX | 0x24 | Y | C | smb1pdu.c |
| SMB_COM_NT_CANCEL | 0xA4 | Y | C | smb1pdu.c |
| SMB_COM_NT_RENAME | 0xA5 | Y | C | smb1pdu.c |
| SMB_COM_QUERY_INFORMATION2 | 0x23 | Y | **X** | smb1pdu.c |
| SMB_COM_SET_INFORMATION | 0x09 | Y | **X** | smb1pdu.c |
| SMB_COM_PROCESS_EXIT | 0x11 | Y | **X** | smb1pdu.c |

---

## Summary: Sections with ZERO Test Coverage

### MS-SMB2 (9 sections without any test):

1. **3.3.5.2.8** — Updating Idle Time (deadtime enforcement)
2. **3.3.5.5.2** — Reauthenticating Existing Session (**P0 security**)
3. **3.3.5.9.4** — CREATE_TIMEWARP_TOKEN context (VSS opens)
4. **3.3.5.9.5** — CREATE_QUERY_MAXIMAL_ACCESS context
5. **3.3.5.9.9** — CREATE_QUERY_ON_DISK_ID context
6. **3.3.5.15.11** — Query Network Interface (multichannel)
7. **3.3.5.15.18** — Extended Duplicate Extents
8. **3.3.5.15.19** — Set Read CopyNumber
9. **3.3.5.21.2** — SET_INFO Filesystem

### MS-SMB (12 sections without any test):

1. **3.3.5.1.1** — Scanning Path for @GMT token
2. **3.3.5.9** — SMB_COM_SEARCH
3. **3.3.5.10.1** — Information Level dispatch
4. **3.3.5.10.3** — TRANS2_FIND_NEXT2
5. **3.3.5.10.5** — TRANS2_QUERY_PATH_INFORMATION
6. **3.3.5.10.7** — TRANS2_SET_PATH_INFORMATION
7. **3.3.5.10.9** — TRANS2_SET_FS_INFORMATION
8. **3.3.5.11.1.1** — ENUMERATE_SNAPSHOTS (SMB1)
9. **3.3.5.11.1.2** — REQUEST_RESUME_KEY (SMB1)
10. **3.3.5.11.1.3** — SRV_COPYCHUNK (SMB1)
11. **3.3.5.11.3** — NT_TRANS_SET_QUOTA
12. Additional commands: SEARCH, QUERY_INFORMATION2, SET_INFORMATION, PROCESS_EXIT

### Overall Protocol Compliance Score

| Protocol | Total Sections | Tested (any tier) | Untested | Coverage % |
|----------|---------------|-------------------|----------|-----------|
| MS-SMB2 | 92 | 83 | 9 | 90% (any test) |
| MS-SMB2 | 92 | 7 | 85 | 8% (integration only) |
| MS-SMB | 38 | 26 | 12 | 68% (any test) |
| MS-SMB | 38 | 1 | 37 | 3% (integration only) |

**Key insight:** 90% of MS-SMB2 sections have *some* test coverage, but only 8% have
real integration test coverage. The remaining 82% rely on replicated-logic KUnit tests
that verify algorithm correctness but not actual production behavior.
