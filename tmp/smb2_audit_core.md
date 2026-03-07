# SMB2 Core Commands Audit

**Repository:** `/home/ezechiel203/ksmbd`
**Spec:** MS-SMB2 v20260114 (January 14, 2026), 499 pages
**Source tree:** `src/protocol/smb2/`
**Date:** 2026-03-01

---

## Summary Table

| Command | Status | Key Gaps |
|---------|--------|----------|
| SMB2 NEGOTIATE (0x0000) | Partial | ServerGUID is always zeroed; NOTIFICATIONS cap not gated on client support; SigningAlgorithmCount=0 / CompressionAlgorithmCount=0 not rejected; no signing-algorithm fallback to AES-CMAC when no overlap; compression response must include NONE=0 when no overlap but does not; PERSISTENT_HANDLES not conditioned on client cap bit; ENCRYPTION cap for SMB3.0/3.0.2 not conditioned on client cap bit |
| SMB2 SESSION_SETUP (0x0001) | Partial | SMB2_SESSION_FLAG_IS_NULL never set for anonymous sessions; Session.SupportsNotifications binding validation missing; EncryptData / RejectUnencryptedAccess global enforcement missing at SESSION_SETUP entry; signing not set per spec when client sets SIGNING_REQUIRED in SecurityMode on new (non-reauth) sessions |
| SMB2 TREE_CONNECT (0x0003) | Partial | SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT ignored; SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER ignored; SMB2_SHAREFLAG_ENCRYPT_DATA never set; SMB2_REMOTED_IDENTITY_TREE_CONNECT context ignored |
| SMB2 CREATE (0x0005) | Partial | FILE_OPEN_BY_FILE_ID returns STATUS_NOT_SUPPORTED instead of opening by inode; IsPersistent fast-path for FLUSH skipped; CreateContexts ordering spec (APP_INSTANCE_VERSION before APP_INSTANCE_ID) implemented correctly |
| SMB2 CLOSE (0x0006) | Mostly Compliant | Minor: post-query uses ctime for ChangeTime instead of mtime; CHANGE_NOTIFY cleanup on close not explicitly dispatched in smb2_close |
| SMB2 FLUSH (0x0007) | Partial | GrantedAccess enforcement (FILE_WRITE_DATA / FILE_APPEND_DATA) missing; IsPersistent fast-path not implemented; STATUS_INVALID_HANDLE returned for all errors instead of per-spec codes; directory flush access check missing |
| SMB2 ECHO (0x000D) | Compliant | Credit charging validated in smb2misc.c; response format correct |

---

## Detailed Analysis

### SMB2 NEGOTIATE

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c`
**Spec refs:** §2.2.3, §2.2.4, §2.2.3.1, §2.2.4.1, §3.3.5.4

#### Implemented

- All seven negotiate context types parsed and assembled: PREAUTH_INTEGRITY, ENCRYPTION, COMPRESSION, NETNAME, POSIX_EXTENSIONS, TRANSPORT_CAPABILITIES, RDMA_TRANSFORM, SIGNING_CAPABILITIES.
- Duplicate context detection: PREAUTH_INTEGRITY, ENCRYPTION, COMPRESSION, RDMA_TRANSFORM each rejected with STATUS_INVALID_PARAMETER if seen more than once.
- Cap on negotiate context count (16) prevents DoS from excessive context iteration.
- SMB 3.1.1 MUST contain exactly one PREAUTH_INTEGRITY context: enforced at lines 768-776.
- Second NEGOTIATE on established connection disconnects per §3.3.5.3.1.
- DialectCount=0 rejected with STATUS_INVALID_PARAMETER.
- Dialect selection: greatest common dialect selected (SMB2.0.2 through SMB3.1.1).
- Pre-authentication integrity hash computed over negotiate request and response buffers.
- SecurityMode: SMB2_NEGOTIATE_SIGNING_ENABLED always set; SIGNING_REQUIRED set when `server_conf.signing == MANDATORY`.
- Salt of 32 bytes (SMB311_SALT_SIZE) included in PREAUTH_INTEGRITY response context.
- SystemTime set to current time.
- NETNAME context parsed (logged, no validation needed per spec §3.3.5.4 -- server MUST ignore).
- Buffer zeroed before population to prevent stale heap data leakage (line 663-664).

#### Missing / Partial

**GAP 1: ServerGUID always zeroed (§2.2.4)**
- Spec says: "ServerGuid is set to the global ServerGuid value."
- Current code at line 868: `memset(rsp->ServerGUID, 0, SMB2_CLIENT_GUID_SIZE);` with comment "not used by client for identifying server".
- While not a MUST requirement that the GUID be unique/non-zero for correctness, the spec clearly states the server MUST set it to the global ServerGuid, not all zeros.
- Implementation plan: Generate and persist a random ServerGuid at module load time; populate it here.

**GAP 2: SMB2_GLOBAL_CAP_NOTIFICATIONS not conditioned on client capability (§3.3.5.4)**
- Spec says: "SMB2_GLOBAL_CAP_NOTIFICATIONS if Connection.Dialect is 3.1.1, IsServerToClientNotificationsSupported is TRUE, AND SMB2_GLOBAL_CAP_NOTIFICATIONS is set in the Capabilities field of the request."
- Current code in `smb2ops.c` line 127: the smb311_server_values static struct hardcodes `capabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_NOTIFICATIONS`. The NOTIFICATIONS bit is advertised unconditionally without checking whether the client sent it.
- Spec also says: "If SMB2_GLOBAL_CAP_NOTIFICATIONS is set in the Capabilities field of the response, the server MUST set Connection.SupportsNotifications to TRUE. Otherwise, the server MUST set Connection.SupportsNotifications to FALSE." No `SupportsNotifications` field exists in `struct ksmbd_conn`.
- Implementation plan: Check `conn->cli_cap & SMB2_GLOBAL_CAP_NOTIFICATIONS` before advertising; track `conn->supports_notifications` boolean; validate it during session binding.

**GAP 3: SigningAlgorithmCount=0 not rejected with STATUS_INVALID_PARAMETER (§3.3.5.4)**
- Spec says: "The server MUST fail the negotiate request with STATUS_INVALID_PARAMETER if... SigningAlgorithmCount is equal to zero."
- Current code in `decode_sign_cap_ctxt()` (line 428): reads `sign_algo_cnt` but only checks for multiplication overflow; if count is 0, the loop at line 443 simply does not execute and `signing_negotiated` remains false -- no STATUS_INVALID_PARAMETER returned.
- Implementation plan: Add an explicit check `if (sign_algo_cnt == 0) return;` and propagate STATUS_INVALID_PARAMETER.

**GAP 4: CompressionAlgorithmCount=0 not rejected (§3.3.5.4)**
- Spec says: "The server MUST fail the negotiate request with STATUS_INVALID_PARAMETER if... CompressionAlgorithmCount is equal to zero."
- Current code in `decode_compress_ctxt()` (line 376): reads `algo_cnt` but does not explicitly reject count=0; the loop simply does not execute.
- Implementation plan: Add explicit `if (algo_cnt == 0) { pr_err; return STATUS_INVALID_PARAMETER; }`.

**GAP 5: SigningAlgorithm fallback to AES-CMAC not implemented (§3.3.5.4)**
- Spec says: "If the server does not support any of the signing algorithms provided by the client, Connection.SigningAlgorithmId MUST be set to 1 (AES-CMAC)."
- Current code in `decode_sign_cap_ctxt()`: if no supported algorithm is found `best_priority` remains -1, `conn->signing_negotiated` is set to false, and the fallback to AES-CMAC (value 1) is NOT performed.
- Implementation plan: After the loop, if `best_priority < 0`, set `conn->signing_algorithm = SIGNING_ALG_AES_CMAC` and set `conn->signing_negotiated = true`.

**GAP 6: Compression response when no overlap must include NONE (§3.3.5.4 / §2.2.4.1.3)**
- Spec says: "If Connection.CompressionIds is empty, The server SHOULD set CompressionAlgorithmCount to 1. The server SHOULD set CompressionAlgorithms to NONE (0x0000)."
- Current code in `assemble_neg_contexts()` (line 204): `if (conn->compress_algorithm != SMB3_COMPRESS_NONE)` -- i.e., no COMPRESSION context is included in the response when no algorithm matched. The spec requires a COMPRESSION context even when the value is NONE=0.
- Implementation plan: Always include COMPRESSION context in response when client sent one; set algorithm to SMB3_COMPRESS_NONE (0) when no overlap.

**GAP 7: SMB2_GLOBAL_CAP_ENCRYPTION not conditioned on client capability for SMB3.0/3.0.2 (§3.3.5.4)**
- Spec says: "SMB2_GLOBAL_CAP_ENCRYPTION if Connection.Dialect is 3.0 or 3.0.2, IsEncryptionSupported is TRUE, the server supports AES-128-CCM encryption algorithm AND SMB2_GLOBAL_CAP_ENCRYPTION is set in the Capabilities field of the request."
- Current code in `init_smb3_0_server()` and `init_smb3_02_server()` (smb2ops.c lines 288-291, 323-326): the ENCRYPTION capability is advertised based on `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION` flag OR if the client cap contains it, but the AND condition with client capability is implemented as OR with a global flag. When `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION` is set, ENCRYPTION is advertised even if the client did not set the bit.
- This is a SHOULD/implementation concern for global-forced encryption, but worth noting.

**GAP 8: SMB2_GLOBAL_CAP_PERSISTENT_HANDLES not conditioned on client request capability (§3.3.5.4)**
- Spec says: "SMB2_GLOBAL_CAP_PERSISTENT_HANDLES if... SMB2_GLOBAL_CAP_PERSISTENT_HANDLES is set in the Capabilities field of the request."
- Current code (smb2ops.c lines 331-332, 364-365): PERSISTENT_HANDLES is advertised based solely on `KSMBD_GLOBAL_FLAG_DURABLE_HANDLE` server flag; client capability is not checked.
- Implementation plan: Add `&& (conn->cli_cap & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES)` to the condition.

---

### SMB2 SESSION_SETUP

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c`
**Spec refs:** §2.2.5, §2.2.6, §3.3.5.5, §3.3.5.5.1, §3.3.5.5.2, §3.3.5.5.3

#### Implemented

- New session creation (SessionId=0 path): allocates session, registers in global/connection table.
- Multi-channel session binding: checks dialect >= SMB3.0, MULTICHANNEL flag, BINDING bit in request Flags.
- Binding validation: verifies dialect match, SMB2_FLAGS_SIGNED on binding request (line 584), ClientGUID match (line 589), session state checks (IN_PROGRESS, EXPIRED).
- Binding signature verification post work->sess assignment (lines 668-675).
- Preauth integrity hash updated for each SESSION_SETUP request (SMB 3.1.1).
- NTLM negotiate/authenticate flow: properly handles NtLmNegotiate -> STATUS_MORE_PROCESSING_REQUIRED -> NtLmAuthenticate.
- Kerberos authentication delegated to ksmbd_krb5_authenticate.
- Re-authentication: recognized when sess->state == SMB2_SESSION_VALID; user object updated or retained.
- Guest session: SMB2_SESSION_FLAG_IS_GUEST_LE set when user_guest(sess->user) is true.
- Signing key generation via conn->ops->generate_signingkey.
- Encryption key generation when smb3_encryption_negotiated().
- PreviousSessionId handling: destroys previous session before proceeding.
- Rate limiting via KSMBD_USER_FLAG_DELAY_SESSION: forces reconnect on auth failure.
- Anonymous fallback in NTLM: handled in auth.c comment references.

#### Missing / Partial

**GAP 1: SMB2_SESSION_FLAG_IS_NULL never set (§2.2.6, §3.3.5.5.3)**
- Spec says SessionFlags MUST be 0 or one of: IS_GUEST (0x0001), IS_NULL (0x0002), ENCRYPT_DATA (0x0004).
- IS_NULL means the client was authenticated as an anonymous user.
- Current code: `sess->is_anonymous` field exists in `struct ksmbd_session` (user_session.h line 50) but it is never used to set `rsp->SessionFlags = SMB2_SESSION_FLAG_IS_NULL_LE` in smb2_session.c.
- The NTLM auth path checks `user_guest()` but never `is_anonymous`. Anonymous sessions are not properly signaled to the client.
- Implementation plan: In `ntlm_authenticate()`, detect anonymous/null session (zero-length credentials / ksmbd_anonymous_user) and set `rsp->SessionFlags = SMB2_SESSION_FLAG_IS_NULL_LE`.

**GAP 2: EncryptData / RejectUnencryptedAccess enforcement at SESSION_SETUP entry (§3.3.5.5 steps 1-2)**
- Spec says (step 1): "If the server implements the SMB 3.x dialect family, Connection.Dialect does not belong to the SMB 3.x dialect family, EncryptData is TRUE, and RejectUnencryptedAccess is TRUE, the server MUST fail with STATUS_ACCESS_DENIED."
- Spec says (step 2): "If Connection.Dialect belongs to the SMB 3.x dialect family, EncryptData is TRUE, RejectUnencryptedAccess is TRUE, and Connection.ClientCapabilities does not include SMB2_GLOBAL_CAP_ENCRYPTION, the server MUST fail with STATUS_ACCESS_DENIED."
- Current code in `smb2_sess_setup()` (line 537+): only checks `ksmbd_conn_need_setup(conn)` and `ksmbd_conn_good(conn)`. No check for EncryptData + RejectUnencryptedAccess + client cap at the top of the handler.
- Implementation plan: Add these two checks at the start of smb2_sess_setup(), gated on `server_conf.flags & KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION` as the EncryptData proxy.

**GAP 3: Session.SupportsNotifications binding validation missing (§3.3.5.5 step 4)**
- Spec says: "If Connection.Dialect is 3.1.1 and Session.SupportsNotifications is not equal to the incoming Connection.SupportsNotifications, then the server MUST fail the request with STATUS_INVALID_PARAMETER."
- Current code: No SupportsNotifications field exists in `struct ksmbd_session` or `struct ksmbd_conn`. This check is entirely absent.
- Implementation plan: Add `supports_notifications` to both structs; enforce during binding.

**GAP 4: Signing flag not set when client sets SIGNING_REQUIRED in SecurityMode (§3.3.5.5 / §3.3.5.5.3)**
- Spec says `Session.SigningRequired` is set TRUE when the client sends `SMB2_NEGOTIATE_SIGNING_REQUIRED`.
- Current code (line 361-363): `sess->sign = true` is set when `req->SecurityMode & SMB2_NEGOTIATE_SIGNING_REQUIRED`, but only if the response is not IS_GUEST. This is correct, however `sess->sign` is only set on new sessions; for binding sessions the sign flag is not re-evaluated from the new connection's security mode requirement.

**GAP 5: STATUS_PASSWORD_EXPIRED and credential-expired error propagation (§3.3.5.5.3)**
- Spec lists many specific error codes that SHOULD be returned (STATUS_PASSWORD_EXPIRED, STATUS_ACCOUNT_DISABLED, STATUS_ACCOUNT_LOCKED_OUT, etc.).
- Current code in `smb2_sess_setup()` out_err: maps rc=-EPERM to STATUS_LOGON_FAILURE generically. Fine-grained NTSTATUS codes from authentication are lost; ksmbd.mountd provides them via netlink but the mapping in the kernel is coarse.
- This is a SHOULD gap, not a MUST, but limits interoperability with strict clients.

---

### SMB2 TREE_CONNECT

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_tree.c`
**Spec refs:** §2.2.9, §2.2.10, §3.3.5.7

#### Implemented

- Share type: DISK (0x01) and PIPE (0x02) correctly set; PRINT (0x03) not applicable (no print share support, which is acceptable).
- Share flags: SMB2_SHAREFLAG_MANUAL_CACHING always set; SMB2_SHAREFLAG_DFS set when DFS enabled.
- Share capabilities: SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY set for CA shares; SMB2_SHARE_CAP_DFS set when DFS enabled.
- MaximalAccess: computed based on writable flag; full access for PIPE shares, read-only or RW for DISK.
- EXTENSION_PRESENT (SMB 3.1.1) flag parsed: PathOffset adjusted relative to extension start (lines 138-148).
- Share name length validation: names >= 80 chars rejected with STATUS_BAD_NETWORK_NAME (per spec §2.2.9 share component MUST be <= 80 chars).
- DFS fallback: if tree connect fails but DFS flag is set, retries with DFS root share name.
- Path bounds checking with overflow detection.

#### Missing / Partial

**GAP 1: SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT completely ignored (§2.2.9, §3.3.5.7)**
- Spec says this flag "indicates that the client has previously connected to the specified cluster share using the SMB dialect of the connection". The server should use this to handle cluster reconnects appropriately.
- Current code: The `req->Reserved` field (which carries the Flags in SMB 3.1.1) is only checked for EXTENSION_PRESENT; CLUSTER_RECONNECT bit is never inspected.
- Note: `SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT` is defined in smb2pdu.h (line 498) but never used in tree connect handler.
- Impact: Low for standalone server; relevant only in cluster scenarios.

**GAP 2: SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER completely ignored (§2.2.9)**
- Spec says this flag "indicates that the client can handle synchronous share redirects via a Share Redirect error context response."
- Current code: flag is defined (smb2pdu.h line 499) but never checked.
- Impact: Servers cannot redirect clients to correct cluster node owner.

**GAP 3: SMB2_SHAREFLAG_ENCRYPT_DATA never set (§2.2.10, §3.3.5.7)**
- Spec says this flag indicates "the server requires encryption of remote file access messages on this share."
- Current code in `smb2_tree_connect()` (lines 246-258): ShareFlags is set to `SMB2_SHAREFLAG_MANUAL_CACHING` + optionally `SHI1005_FLAGS_DFS`. There is no share-level encryption flag support; `SMB2_SHAREFLAG_ENCRYPT_DATA` is never set even when the share is configured with encryption.
- `SMB2_SHAREFLAG_ENCRYPT_DATA` (0x00008000) is not defined in smb2pdu.h.
- Implementation plan: Add share config flag for per-share encryption; set response ShareFlags bit.

**GAP 4: SMB2_REMOTED_IDENTITY_TREE_CONNECT context not processed (§2.2.9.2.1)**
- Spec defines this context for identity remoting; server should process if it supports `SMB2_SHAREFLAG_IDENTITY_REMOTING`.
- Current code: The extension present path decodes PathOffset but no context iteration happens.
- Impact: Low for non-cluster deployments; SMB2_SHAREFLAG_IDENTITY_REMOTING not advertised either.

**GAP 5: SMB2_SHARE_CAP_SCALEOUT never set (§2.2.10)**
- Not implemented, but this is only relevant for scale-out cluster shares.

**GAP 6: MaximalAccess computation is coarse (§3.3.5.7)**
- Spec says MaximalAccess should reflect actual access rights the authenticated user has to the share.
- Current code: MaximalAccess is set based purely on whether the tree connection is `KSMBD_TREE_CONN_FLAG_WRITABLE` -- it does not take into account share-specific ACLs, user-specific permissions, or the actual file system permissions.
- This is a structural limitation and a common interoperability concern.

---

### SMB2 CREATE

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c`
**Spec refs:** §2.2.13, §2.2.14, §3.3.5.9

#### Implemented

- All CreateDisposition values handled: SUPERSEDE, OPEN, CREATE, OPEN_IF, OVERWRITE, OVERWRITE_IF.
- FILE_SEQUENTIAL_ONLY + FILE_RANDOM_ACCESS: sequential cleared when both set.
- FILE_CREATE_TREE_CONNECTION and FILE_RESERVE_OPFILTER: rejected with STATUS_NOT_SUPPORTED.
- FILE_DIRECTORY_FILE + FILE_NON_DIRECTORY_FILE mutual exclusion enforced.
- FILE_TEMPORARY + FILE_DIRECTORY_FILE rejected.
- ImpersonationLevel validated (0 through IL_DELEGATE = 3; higher rejected with STATUS_BAD_IMPERSONATION_LEVEL).
- CreateOptions validated against CREATE_OPTIONS_MASK.
- DesiredAccess validated against DESIRED_ACCESS_MASK.
- FileAttributes validated against ATTR_MASK_LE.
- NameLength must be multiple of 2 (UTF-16LE).
- All core CreateContexts handled: EA_BUFFER, QUERY_MAXIMAL_ACCESS, TIMEWARP_REQUEST, ALLOCATION_SIZE, QUERY_ON_DISK_ID, DH2C (durable reconnect v2), DHnC (durable reconnect), DH2Q (durable request v2), DHnQ (durable request), RqLs (request lease), POSIX.
- Durable handle v1: reconnect validates ClientGUID to prevent theft (line 878).
- Durable handle v2: reconnect validates ClientGUID and CreateGuid (lines 828-842).
- DH2Q (persistent handles): SMB2_DHANDLE_FLAG_PERSISTENT conditioned on CA share flag.
- Lease v1 and v2: parsed via parse_lease_state(); lease context returned in response.
- SD_BUFFER create context handled in smb2_create_sd_buffer().
- APP_INSTANCE_ID and APP_INSTANCE_VERSION: dispatched via registered context handler framework.
- Oplock acquisition: smb_grant_oplock() with proper level downgrade for read-only opens.
- FILE_DELETE_ON_CLOSE: checks DELETE access is granted before setting.
- POSIX create context: posix_mode applied when posix_ext_supported.
- Fruit (AAPL) context: fruit capability negotiation.
- Post-open path escape check: `path_is_under()` validates file is within share root.
- Parent DACL deny check for new files.

#### Missing / Partial

**GAP 1: FILE_OPEN_BY_FILE_ID returns STATUS_NOT_SUPPORTED (§3.3.5.9)**
- Spec describes opening by FileId. The request's NameLength is exactly 8 or 16 bytes containing a FileId.
- Current code (line 1197-1199): `if (req->CreateOptions & FILE_OPEN_BY_FILE_ID_LE) { rc = -EOPNOTSUPP; goto err_out2; }` -- returns STATUS_NOT_SUPPORTED.
- A helper `smb2_resolve_open_by_file_id()` exists in the file (line 1052) but is annotated `__maybe_unused` and never called.
- Impact: Applications relying on open-by-FileId will fail; this is a standard Windows feature.
- Implementation plan: Wire up smb2_resolve_open_by_file_id() and remove the early -EOPNOTSUPP return.

**GAP 2: Resilient handle create context (SMB2_CREATE_RESILIENT_HANDLE / "RHnd") not implemented**
- Spec §3.3.5.9.11 defines handling for resilient open requests.
- Current code: no handler for "RHnd" context.
- Impact: Clients using resilient handles (e.g., for CSV) will silently not get resilience.

**GAP 3: SExT (SMB2_CREATE_REQUEST_LEASE_V2 = "RqL2") -- lease v2 parent key**
- Current code: `parse_lease_state()` parses both lease v1 and v2. Lease v2 includes ParentLeaseKey.
- Per spec §3.3.5.9.8: "If Connection.Dialect belongs to the SMB 3.x dialect family, Lease.Version is set to 1." But for v2, the ParentLeaseKey must be returned in the response with SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET.
- Current code in `create_lease_buf()`: needs verification that ParentLeaseKey is properly propagated in the v2 response context.

**GAP 4: SMB2_CREATE_APP_INSTANCE_VERSION must be processed before SMB2_CREATE_APP_INSTANCE_ID**
- Spec §3.3.5.9.10: "If the create request also includes the SMB2_CREATE_APP_INSTANCE_ID create context, the server MUST process the SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 create context only after processing the SMB2_CREATE_APP_INSTANCE_ID create context."
- Current code comment at line 1041: "Process APP_INSTANCE_VERSION before APP_INSTANCE_ID" -- this is correctly handled by the two-pass dispatch mechanism.
- Status: COMPLIANT.

---

### SMB2 CLOSE

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c` (lines 97-232)
**Spec refs:** §2.2.15, §2.2.16, §3.3.5.10

#### Implemented

- SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB: stat queried via vfs_getattr; CreationTime, LastAccessTime, LastWriteTime, ChangeTime, AllocationSize, EndOfFile, Attributes returned.
- If flag not set: all fields zeroed as required by spec.
- IPC pipe close: handled separately via smb2_close_pipe().
- Compound request FID resolution: uses compound_fid when VolatileFileId not valid.
- SESSION_ID validation: checks session ID; proper error on mismatch.
- ksmbd_close_fd() called to release open.

#### Missing / Partial

**GAP 1: ChangeTime uses ctime, not explicit write time (minor)**
- Spec says ChangeTime is "last change time", which maps to inode ctime on Linux. This is correct POSIX semantics but may differ from Windows where ChangeTime is metadata change time.
- Current code (line 205): `time = ksmbd_UnixTimeToNT(stat.ctime); rsp->ChangeTime = cpu_to_le64(time);` -- acceptable.

**GAP 2: CHANGE_NOTIFY cleanup not explicitly dispatched from smb2_close (§3.3.5.10)**
- Spec says: "The Server MUST send an SMB2 CHANGE_NOTIFY Response with STATUS_NOTIFY_CLEANUP status code for all pending CHANGE_NOTIFY requests associated with the FileId that is closed."
- The actual cleanup is presumably handled within `ksmbd_close_fd()` -> `ksmbd_fd_set_delete_on_close()` chain, but it is not verified that `STATUS_NOTIFY_CLEANUP` is dispatched for all pending change notify handles bound to the closed file.
- Implementation plan: Audit `ksmbd_close_fd()` to confirm CHANGE_NOTIFY requests for the FileId are completed with STATUS_NOTIFY_CLEANUP.

**GAP 3: Open.DurableFileId != FileId.Persistent check (§3.3.5.10)**
- Spec says: "If no open is found, or if Open.DurableFileId is not equal to FileId.Persistent, the server MUST fail the request with STATUS_FILE_CLOSED."
- `ksmbd_close_fd()` calls `ksmbd_lookup_fd_fast()` which uses only VolatileFileId. The Persistent ID validation is not performed in the close path (it is done in FLUSH via `ksmbd_lookup_fd_slow()`).
- Implementation plan: Use `ksmbd_lookup_fd_slow()` with both Volatile+Persistent in close path.

---

### SMB2 FLUSH

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c` (lines 958-1005)
**Spec refs:** §2.2.17, §2.2.18, §3.3.5.11

#### Implemented

- File looked up by both VolatileFileId and PersistentFileId via `ksmbd_lookup_fd_slow()`.
- Channel sequence validated before flush.
- `ksmbd_vfs_fsync()` called for the actual flush.
- Fruit extension: full-device sync (`fullsync = true`) when Reserved1=0xFFFF with macOS client.
- Response structure set correctly: StructureSize=4, Reserved=0.

#### Missing / Partial

**GAP 1: GrantedAccess enforcement missing (§3.3.5.11)**
- Spec says:
  - "If the Open is on a file and Open.GrantedAccess includes neither FILE_WRITE_DATA nor FILE_APPEND_DATA, the server MUST fail with STATUS_ACCESS_DENIED."
  - "If the Open is on a directory and Open.GrantedAccess includes neither FILE_ADD_FILE nor FILE_ADD_SUBDIRECTORY, the server MUST fail with STATUS_ACCESS_DENIED."
- Current code: No such access check exists. Any open file handle can be flushed regardless of granted access.
- Implementation plan: After fp lookup, check `fp->daccess & (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE)` for files and the directory equivalent for directories.

**GAP 2: IsPersistent fast-path not implemented (§3.3.5.11)**
- Spec says: "If Open.IsPersistent is TRUE, the server MUST succeed the operation and MUST respond with an SMB2 FLUSH Response."
- Current code: Always calls `ksmbd_vfs_fsync()` even for persistent opens. For persistent handles, the actual flush is unnecessary (the server already manages persistence), and the spec allows a fast-path success response.
- Impact: Minor; persistent handles are rarely used in this implementation.

**GAP 3: Error status code incorrect for failed lookup (§3.3.5.11)**
- Spec says: "If no open is found, or if Open.DurableFileId is not equal to FileId.Persistent, the server MUST fail the request with STATUS_FILE_CLOSED."
- Current code (line 1002): `rsp->hdr.Status = STATUS_INVALID_HANDLE;` -- incorrect NTSTATUS code. Should be STATUS_FILE_CLOSED.
- Implementation plan: Change line 1002 to `rsp->hdr.Status = STATUS_FILE_CLOSED`.

**GAP 4: FLUSH status on access denied not differentiated (§3.3.5.11)**
- Spec lists STATUS_ACCESS_DENIED as a valid return code for FLUSH. Current code has no access check so this code path is unreachable; the fix in GAP 1 also needs the proper error mapping.

**GAP 5: ReplayEligible flag not cleared (§3.3.5.11)**
- Spec says: "If the server implements the SMB 3.x dialect family and Open.IsReplayEligible is TRUE, the server MUST set Open.IsReplayEligible to FALSE."
- Current code: No such flag update in the FLUSH handler.
- Implementation plan: After fp lookup, if `conn->dialect >= SMB30_PROT_ID && fp->is_replay_eligible`, set `fp->is_replay_eligible = false`.

---

### SMB2 ECHO

**Source:** `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c` (lines 241-253)
**Spec refs:** §2.2.28, §2.2.29, §3.3.5.14 (not shown in spec TOC separately; part of normal command dispatch)

#### Implemented

- Response structure: StructureSize=4, Reserved=0 -- correct.
- Credit charging validated in `smb2_validate_credit_charge()` in smb2misc.c before dispatch.
- Compound request handling: response buffer pointer advanced for chained ECHO (line 248).
- `ksmbd_iov_pin_rsp()` used correctly.

#### Missing / Partial

- None identified. The ECHO command implementation is minimal but correct. The spec (§2.2.28/2.2.29) requires only a 4-byte StructureSize request and a 4-byte StructureSize response with no payload, which is what the implementation provides.

---

## Cross-Cutting Gaps

### G-CC-1: No SupportsNotifications tracking across the codebase
- Connection-level and session-level `SupportsNotifications` field is missing.
- Required for SMB 3.1.1 session binding validation (SESSION_SETUP gap 3).
- Required for correct NOTIFICATIONS capability advertisement (NEGOTIATE gap 2).

### G-CC-2: PersistentFileId validation inconsistently applied
- FLUSH: validates via `ksmbd_lookup_fd_slow()` (correct).
- CLOSE: uses only VolatileFileId via `ksmbd_lookup_fd_fast()` (missing Persistent check).
- READ/WRITE/LOCK: should be audited separately.

### G-CC-3: IsReplayEligible / channel sequence not tracked per-open
- The spec requires clearing `Open.IsReplayEligible` on FLUSH and other modifying operations.
- Implementation partially tracks this but not comprehensively.

### G-CC-4: SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB uses fp->create_time from cached inode
- `fp->create_time` is set at open time. If file's birth time changes after open (uncommon but possible), the post-query value could be stale. Re-querying btime from stat would be more correct.

---

## Severity Classification

| ID | Command | Description | Severity | Spec Strength |
|----|---------|-------------|----------|---------------|
| NEG-1 | NEGOTIATE | ServerGUID always zero | Medium | SHOULD |
| NEG-2 | NEGOTIATE | NOTIFICATIONS cap not gated on client | High | MUST |
| NEG-3 | NEGOTIATE | SigningAlgorithmCount=0 not rejected | High | MUST |
| NEG-4 | NEGOTIATE | CompressionAlgorithmCount=0 not rejected | High | MUST |
| NEG-5 | NEGOTIATE | No signing algorithm fallback to AES-CMAC | High | MUST |
| NEG-6 | NEGOTIATE | Compression NONE not sent when no overlap | Medium | SHOULD |
| NEG-7 | NEGOTIATE | ENCRYPTION cap not gated on client cap | Medium | MUST |
| NEG-8 | NEGOTIATE | PERSISTENT_HANDLES not gated on client cap | Medium | MUST |
| SESS-1 | SESSION_SETUP | IS_NULL flag never set for anonymous | High | MUST |
| SESS-2 | SESSION_SETUP | EncryptData enforcement missing at entry | High | MUST |
| SESS-3 | SESSION_SETUP | SupportsNotifications binding check missing | High | MUST (3.1.1) |
| SESS-4 | SESSION_SETUP | Fine-grained NTSTATUS not propagated | Low | SHOULD |
| TREE-1 | TREE_CONNECT | CLUSTER_RECONNECT flag ignored | Low | N/A |
| TREE-2 | TREE_CONNECT | REDIRECT_TO_OWNER flag ignored | Low | N/A |
| TREE-3 | TREE_CONNECT | SHAREFLAG_ENCRYPT_DATA never set | High | MUST (when configured) |
| TREE-4 | TREE_CONNECT | Coarse MaximalAccess computation | Medium | SHOULD |
| CREATE-1 | CREATE | FILE_OPEN_BY_FILE_ID always fails | Medium | MUST |
| CREATE-2 | CREATE | Resilient handle context not handled | Medium | SHOULD |
| CLOSE-1 | CLOSE | Persistent FID not validated in lookup | Medium | MUST |
| CLOSE-2 | CLOSE | CHANGE_NOTIFY cleanup not verified | Medium | MUST |
| FLUSH-1 | FLUSH | GrantedAccess not checked | High | MUST |
| FLUSH-2 | FLUSH | IsPersistent fast-path missing | Low | MUST |
| FLUSH-3 | FLUSH | Wrong NTSTATUS on failed lookup (INVALID_HANDLE vs FILE_CLOSED) | Medium | MUST |
| FLUSH-4 | FLUSH | IsReplayEligible not cleared | Medium | MUST (SMB3.x) |
