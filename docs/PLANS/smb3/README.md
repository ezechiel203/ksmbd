# KSMBD SMB3 Protocol Upgrade Plan

## Target: 100% MS-SMB2/SMB3 Compliance (dialects 3.0, 3.0.2, 3.1.1)

---

### Overview

SMB3 builds on SMB2 by adding a security and resilience layer that was absent in earlier dialects. The key additions are: mandatory Pre-Authentication Integrity (PAI) via SHA-512 hash accumulation over the negotiate and session-setup exchanges; per-session AES-GCM/CCM encryption with keys derived through SP800-108 counter-mode KDF; three signing algorithms (HMAC-SHA256, AES-CMAC, AES-GMAC) negotiated at session setup; multichannel for bandwidth aggregation and failover; QUIC as an alternative transport with TLS 1.3 at the transport layer; leases and durable/persistent handles for client-side caching and reconnect resilience; and message compression (LZNT1, LZ77, LZ77+Huffman, Pattern_V1). SMB3 also introduces FSCTL_VALIDATE_NEGOTIATE_INFO as a downgrade-attack countermeasure and expands the FSCTL surface with server-side copy (CopyChunk, ODX), VSS snapshot enumeration, BranchCache, and the Witness protocol. KSMBD implements the core of SMB3 correctly — the cryptographic machinery (KDF, encryption, signing algorithms) is verified clean — but has significant gaps in compression, QUIC, persistent handles, and several correctness bugs in enforcement paths.

---

### Compliance by Area

**Wave 1 implementation complete: 2026-03-02 (commit `bc5ef70`)**

All 10 items in the Top 10 Critical Bugs list below have been resolved.
Smoke tests (TCP + QUIC): **PASS=7 FAIL=0 SKIP=0** on both VM3 and VM4.

| Area | Plan File | Pre-Wave 1 | Post-Wave 1 | Top Remaining Gap |
|------|-----------|-----------|---------|---------|
| Negotiate contexts / Pre-Auth Integrity | smb3_plan_01 | ~82% | ~93% | Standard compression algorithms (LZNT1/LZ77) still missing |
| Encryption and Key Derivation | smb3_plan_02 | ~87% | ~95% | Per-channel nonce counter for multichannel AES-GCM |
| Message Signing | smb3_plan_03 | ~88% | ~97% | AES-GMAC large-compound memory copy (cosmetic perf) |
| Multichannel and QUIC | smb3_plan_04 | ~72% | ~77% | QUIC still incomplete — no TLS 1.3, RDMA transforms partially applied |
| Durable Handles, Persistent Handles, Leases | smb3_plan_05 | ~75% | ~85% | Persistent handles in-memory only (no stable storage across restart) |
| Compression and RDMA Transforms | smb3_plan_06 | ~35% | ~50% | LZNT1/LZ77/LZ77+Huffman still stubs; READ compression still limited |
| Server-Side Copy, Snapshots, Misc FSCTLs | smb3_plan_07 | ~80% | ~89% | @GMT snapshot VFS routing partial; ODX TTL enforcement added |

**Pre-Wave 1 overall weighted compliance estimate: ~75%**
**Post-Wave 1 overall weighted compliance estimate: ~87%**

The cryptographic subsystems (KDF, cipher implementations, nonce management,
authentication tag verification) scored 100% before Wave 1 and remain correct.
The primary remaining drag is the compression subsystem (~50%), QUIC (~40%), and
persistent handles (~25% — in-memory only, no restart survival).

---

### Wave 1 Key Fixes — Former Top 10 Critical Bugs (All Resolved)

All 10 critical bugs were fixed in Wave 1 (commit `bc5ef70`, 2026-03-02):

1. **[FIXED — Track I] BUG-C02**: Compression algorithm confusion fixed; PDU
   `CompressionAlgorithm` now validated against `conn->compress_algorithm`; mismatch
   returns `STATUS_BAD_COMPRESSION_BUFFER` without decompressing.

2. **[FIXED — Track F] BUG-P1-VNI-01**: VALIDATE_NEGOTIATE_INFO mismatch now calls
   `ksmbd_conn_set_exiting()` and sends no response (TCP disconnect).

3. **[FIXED — Track B + prior sessions] BUG-02-P1-01**: Per-tree-connect and per-session
   encryption enforcement added; connection disconnected on violation.

4. **[FIXED — Track C] BUG-05-BUG-01**: DHnQ durable handles now get `durable_timeout = 16000`
   ms (16 s Windows default); scavenger now reclaims them after disconnect.

5. **[FIXED — Track C] BUG-05-BUG-02**: DH2Q default timeout corrected from 60 ms to
   60,000 ms (60 s); capped at 16 minutes per spec maximum.

6. **[FIXED — Track B] BUG-03-P1-01**: `SMB2_CANCEL_HE` added to signing exclusion list
   in `smb2_is_sign_req()`; CANCEL now processed on mandatory-signing sessions.

7. **[FIXED — prior sessions] BUG-01-P1-02**: Signing algorithm selection fixed to
   client-preference order (MS-SMB2 §3.3.5.4: "first entry in the client's array the
   server supports"); AES-CMAC fallback when no overlap.

8. **[FIXED — Track F] BUG-MC-01**: LinkSpeed corrected to bytes/s
   (`speed * 1000000 / 8`); FSCTL opcode corrected to `0x001400FC`.

9. **[FIXED — Track I] BUG-C01**: LZ4 (non-spec algorithm ID 0x0005) removed from
   the negotiate compression context advertisement.

10. **[FIXED — Track J] BUG-R01**: RDMA Transform Header implemented; encryption/signing
    transforms applied in RDMA read/write paths when negotiated.

---

### P1 Critical Bugs — Status After Wave 1

All P1 items below were resolved in Wave 1 (commit `bc5ef70`, 2026-03-02).
Entries are retained as regression-prevention specifications.

#### Security Bugs

**[FIXED — prior sessions] [PLAN-01] P1-02 — Cipher selection fixed to client-preference order**
- File:Line: `src/protocol/smb2/smb2_negotiate.c:330-340`
- Spec: MS-SMB2 §3.3.5.2.5.2 — "The server MUST set Connection.CipherId to the value in the Ciphers array that is preferred by the server."
- Symptom: Server selects the first cipher in the client's list that it recognises. A client that lists `[AES-128-CCM, AES-256-GCM]` gets AES-128-CCM even though AES-256-GCM is mutually supported.
- Fix: Assign server-side priorities; track best intersection cipher as done in `decode_sign_cap_ctxt()`.

**[FIXED — Track B] [PLAN-01] P1-03 — SMB2_GLOBAL_CAP_ENCRYPTION now set for SMB 3.1.1**
- `init_smb3_11_server()` now sets `SMB2_GLOBAL_CAP_ENCRYPTION` when encryption is enabled,
  mirroring the SMB 3.0/3.0.2 path.

**[FIXED — Track B + prior sessions] [PLAN-02] P1-01 — Share-level encryption enforcement added**
- Per-session encryption enforcement with connection disconnect added in `server.c`.
- Per-tree-connect encryption check added alongside session-level check.

**[FIXED — Track B] [PLAN-02] P1-02 — Transform Header Flags validated on receive**
- `smb3_decrypt_req()` now validates `Flags == 0x0001`; any other value causes connection abort.

**[FIXED — Track I] [PLAN-06] BUG-C01 — LZ4 (non-spec ID 0x0005) removed from negotiate**
- LZ4 no longer advertised in the compression negotiate context.

**[FIXED — Track I] [PLAN-06] BUG-C02 — Compression algorithm confusion fixed (security)**
- PDU `CompressionAlgorithm` validated against `conn->compress_algorithm` before decompression.
- Mismatch returns `STATUS_BAD_COMPRESSION_BUFFER` without decompressing.

**[FIXED — Track J] [PLAN-06] BUG-R01 — RDMA Transform Header implemented**
- RDMA Transform Header (`ProtocolId = 0xFB534D42`) applied in RDMA read/write paths.
- Encryption/signing transforms applied when negotiated.

**[FIXED — Track F] [PLAN-07] P1-VNI-01 — VALIDATE_NEGOTIATE_INFO disconnects on mismatch**
- `ksmbd_conn_set_exiting()` called with `send_no_response = 1` on validation failure.
- No error PDU sent; TCP connection torn down per spec.

#### Correctness Bugs

**[FIXED — prior sessions] [PLAN-01] P1-01 — HashAlgorithmCount validated**
- `decode_preauth_ctxt()` now checks `HashAlgorithmCount == 0` → `STATUS_INVALID_PARAMETER`.
  Also: SigningAlgorithmCount=0 and CompressionAlgorithmCount=0 similarly rejected.

**[FIXED — Track B] [PLAN-03] P1-01 — CANCEL excluded from signing enforcement**
- `SMB2_CANCEL_HE` added to exclusion list in `smb2_is_sign_req()`.

**[FIXED — Track B] [PLAN-03] P1-05 — OPLOCK_BREAK ack signing now verified**
- `SMB2_OPLOCK_BREAK_HE` removed from unconditional exclusion list; signatures verified
  when `SMB2_FLAGS_SIGNED` is present and signing is mandatory.

**[FIXED — Track F] [PLAN-04] BUG-MC-01 — LinkSpeed corrected to bytes/s**
- `speed = (u64)cmd.base.speed * 1000 * 1000 / 8` (bytes/sec, not bits/sec).

**[FIXED — Track B] [PLAN-04] BUG-MC-02 — Session-closed notification extended to SMB 3.0/3.0.2**
- Dialect guard changed from `SMB311_PROT_ID` to `SMB30_PROT_ID`.

**[FIXED — Track J] [PLAN-04] BUG-MC-03 — QUIC IPv6 full 128-bit address storage**
- Full IPv6 address stored; `ipv6_addr_hash()` used for per-IP limiting.

**[FIXED — Track J] [PLAN-04] BUG-MC-04 — QUIC .shutdown op implemented**
- `ksmbd_quic_shutdown()` implemented; registered as `.shutdown` transport op.

**[FIXED — Track C] [PLAN-05] BUG-01 — DHnQ durable handles now expire (fd leak fixed)**
- `fp->durable_timeout = 16000` ms assigned in `DURABLE_REQ` branch.

**[FIXED — Track C] [PLAN-05] BUG-02 — DH2Q default timeout corrected**
- `fp->durable_timeout = 60000` ms (60 s), capped at 16 minutes per spec.

**[FIXED — Track I] [PLAN-06] BUG-C03 — Decompression bomb cap corrected**
- Decompressed size now capped at `conn->vals->max_trans_size` (not 2 MB hardcoded).

**[FIXED — Track I] [PLAN-06] BUG-C04 — Pattern_V1 removed from standalone negotiate list**
- Pattern_V1 no longer advertised as a standalone non-chained algorithm.

**[FIXED — Track F] [PLAN-07] P1-ODX-01 — ODX token hash uses full 16-byte nonce**
- `jhash()` over all 16 nonce bytes; no more first-4-bytes-only hash collisions.

---

### P2 Missing Features

All P2 items grouped by area.

#### Plan 01 — Negotiate Contexts / Pre-Auth Integrity

- **P2-01**: Standard compression algorithms LZNT1, LZ77, LZ77+Huffman not implemented.
  - File:Line: `src/protocol/smb2/smb2_negotiate.c:399-415`
  - Impact: Connections with Windows 10/11 clients that do not support LZ4 or Pattern_V1 will not compress. Windows typically offers LZNT1 and LZ77+Huffman as primary choices.

- **P2-02**: `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID` (0x0005) received and silently discarded without server-name validation.
  - File:Line: `src/protocol/smb2/smb2_negotiate.c:627-629`
  - Impact: No target-name confusion detection. MS-SMB2 §3.3.5.2.4 step 2 states the server SHOULD validate `NetName` against its network address.

- **P2-03**: Signing algorithm fallback when no overlap silently selects AES-CMAC instead of rejecting.
  - File:Line: `src/protocol/smb2/smb2_negotiate.c:479-481`
  - Impact: If client sends only unknown future algorithm IDs, server does not reject but silently uses AES-CMAC which the client did not advertise. MS-SMB2 §3.3.5.4 requires `STATUS_NOT_SUPPORTED` when there is no overlap.

- **P2-04**: `ServerGUID` is zeroed in both the NEGOTIATE response and the VALIDATE_NEGOTIATE_INFO response.
  - File:Line: `src/protocol/smb2/smb2_negotiate.c:891` (negotiate); `src/fs/ksmbd_fsctl.c:1538` (VNI response)
  - Impact: MS-SMB2 §3.3.5.4 requires a stable per-server GUID. A zero GUID can cause multichannel correlation failures and breaks VALIDATE_NEGOTIATE_INFO protection.

#### Plan 02 — Encryption and Key Derivation

- **P2-01**: `OriginalMessageSize` minimum bound not checked in `smb3_decrypt_req()`.
  - File:Line: `src/protocol/smb2/smb2_pdu_common.c:1351`
  - Impact: `OriginalMessageSize = 0` passes the upper-bound check and yields an empty decrypted payload. Should be checked against `sizeof(struct smb2_hdr)`.

- **P2-02**: Encryption enforcement requires `KSMBD_GLOBAL_FLAG_SMB2_ENCRYPTION` even when `sess->enc = true`.
  - File:Line: `src/core/server.c:331-332`
  - Impact: Sessions where encryption keys were derived (`sess->enc = true`) but the global flag is off accept unencrypted requests — a downgrade after key derivation.

- **P2-03**: Cipher type stored per-connection, not per-session; multichannel key-derivation can be inconsistent.
  - File:Line: `src/include/core/connection.h:120`
  - Impact: The cipher used for key derivation on the initial channel is not explicitly stored on the session; subsequent channel binding relies on the new channel's `conn->cipher_type` matching the original channel's, which is not enforced.

#### Plan 03 — Signing

- **P2-01**: Unsigned requests on mandatory-signing sessions rely on signature mismatch for rejection rather than an explicit flag check before crypto.
  - File:Line: `src/core/server.c:192-197`
  - Impact: Minor inefficiency and unclear intent; an explicit `!(rcv_hdr->Flags & SMB2_FLAGS_SIGNED)` check before the crypto call is cleaner and saves HMAC computation on unsigned requests.

- **P2-02**: No rate-limiting or tracking of repeated signing failures per connection.
  - File:Line: `src/protocol/smb2/smb2_pdu_common.c:1006-1009`
  - Impact: An attacker performing signature forgery attempts is only rate-limited in log output (`pr_err_ratelimited`), not in connection behavior. Consider disconnecting after N consecutive failures.

- **P2-03**: Session binding signature verification failure returns `STATUS_REQUEST_NOT_ACCEPTED` instead of `STATUS_ACCESS_DENIED`.
  - File:Line: `src/protocol/smb2/smb2_session.c:681-684`
  - Impact: MS-SMB2 §3.3.5.5.3 mandates `STATUS_ACCESS_DENIED` for binding signature failure; the current code maps `-EACCES` to `STATUS_REQUEST_NOT_ACCEPTED`.

#### Plan 04 — Multichannel and QUIC

- **P2-MC-01**: NIC enumeration misses interfaces that were up before ksmbd loaded.
  - File:Line: `src/protocol/smb2/smb2_ioctl.c:238-247`
  - Impact: `ksmbd_netdev_event()` only adds interfaces dynamically on NETDEV_UP. An initial scan of currently-up netdevs at `ksmbd_tcp_init()` time is needed.

- **P2-MC-02**: No QUIC userspace proxy provided.
  - Impact: The kernel QUIC listener is non-functional without a matching userspace proxy implementing TLS 1.3, port 443 binding, ALPN negotiation, and unix socket forwarding.

- **P2-MC-03**: RFC1002 NetBIOS framing retained in QUIC path, violating MS-SMB2-QUIC (RFC 9446 §3.1).
  - File:Line: `src/core/connection.c:570`
  - Impact: SMB over QUIC must send raw SMB2 PDUs without the 4-byte NetBIOS session wrapper. The current implementation requires the userspace proxy to add synthetic framing.

- **P2-MC-04**: `conn->transport_secured` is set based on client advertisement, not authoritatively by the transport layer.
  - File:Line: `src/protocol/smb2/smb2_negotiate.c:491-497`
  - Impact: A client on plain TCP can falsely claim transport security, potentially bypassing SMB signing enforcement on the server side.

#### Plan 05 — Durable Handles, Persistent Handles, Leases

- **P2-01**: Persistent handles do not survive server restart (in-memory only).
  - File:Line: `src/include/fs/vfs_cache.h:143` (`is_persistent`), `src/protocol/smb2/smb2_create.c:2209-2212`
  - Impact: Clients expecting SMB3 CA (Continuously Available) semantics (Hyper-V, clustered environments) will fail to reconnect after a server restart. MS-SMB2 §3.3.1.15 requires persistent handles to be backed by stable storage.

- **P2-02**: `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` not advertised for SMB 3.0.
  - File:Line: `src/protocol/smb2/smb2ops.c:272-300`
  - Impact: SMB 3.0 clients cannot use persistent handles even if the server supports them (requires dialect 3.0+).

- **P2-03**: DH2C `Flags` field not validated against `Open.IsPersistent` during reconnect.
  - File:Line: `src/protocol/smb2/smb2_create.c:802-849`
  - Impact: A non-persistent handle can be reconnected with `Flags=SMB2_DHANDLE_FLAG_PERSISTENT` without rejection. Spec §3.3.5.9.13 step 5 requires this check.

- **P2-04**: No resilient handle reconnect path independent of durable handles.
  - File:Line: `src/fs/ksmbd_resilient.c`, `src/protocol/smb2/smb2_create.c`
  - Impact: `FSCTL_LMR_REQUEST_RESILIENCY` marks the handle correctly, but the reconnect path only processes DHnC/DH2C create contexts. Pure resilient-handle reconnect per MS-SMB2 §3.3.7.1 is not implemented.

- **P2-05**: `dh_info.persistent` uses raw Flags integer value instead of bitmask check.
  - File:Line: `src/protocol/smb2/smb2_create.c:932`
  - Impact: Any non-zero reserved bit in `Flags` would incorrectly trigger persistent mode. Fix: `dh_info.persistent = !!(le32_to_cpu(durable_v2_blob->Flags) & SMB2_DHANDLE_FLAG_PERSISTENT)`.

#### Plan 06 — Compression and RDMA Transforms

- **P2-01**: Chained compression not implemented.
  - File:Line: `src/core/smb2_compress.c:319-323`
  - Impact: Clients that advertise only chained compression will fail to use compression. Pattern_V1 per spec is designed for chained mode; standalone use is technically non-conformant.

- **P2-02**: LZNT1 decompression not implemented (stub returns `-EOPNOTSUPP`).
  - File:Line: `src/core/smb2_compress.c:267-270`
  - Impact: Windows clients sending LZNT1-compressed WRITE data receive an error. LZNT1 is the most common choice for Windows pre-SMB3.1.1.

- **P2-03**: LZ77 and LZ77+Huffman decompression not implemented.
  - File:Line: `src/core/smb2_compress.c:267-270`
  - Impact: SMB3.1.1 clients preferring LZ77+Huffman (highest compression in the spec) cannot compress writes.

- **P2-04**: `SMB2_READFLAG_READ_COMPRESSED` flag ignored in SMB2 READ handler.
  - File:Line: `src/protocol/smb2/smb2_read_write.c` (no compress flag check)
  - Impact: Per-read compression hints from the client are ignored entirely. The flag is defined at `src/include/protocol/smb2pdu.h:1007` but never checked.

- **P2-05**: READ responses effectively never compressed due to `iov_cnt > 2` early return.
  - File:Line: `src/core/smb2_compress.c:501-503`
  - Impact: SMB2 READ responses use 3 iovs (RFC1002 header, SMB2 response header, file data). `smb2_compress_resp()` returns early when `iov_cnt > 2`, so READ data is never compressed in practice despite compression being negotiated.

- **P2-06**: RDMA Transform encryption/signing not applied even when negotiated.
  - File:Line: `src/transport/transport_rdma.c` — `smb_direct_rdma_read()` and `smb_direct_rdma_write()`
  - Impact: See P1 bug BUG-R01. `ksmbd_rdma_transform_supported()` is exported but has no call sites.

#### Plan 07 — Server-Side Copy, Snapshots, Misc FSCTLs

- **P2-VNI-02**: `ServerGuid` field in VALIDATE_NEGOTIATE_INFO response is zeroed; should echo `server_conf.guid`.
  - File:Line: `src/fs/ksmbd_fsctl.c:1538`
  - Impact: Weakens the VNI downgrade-protection by allowing a MITM to also zero it without detection.

- **P2-ODX-02**: `TokenTimeToLive` from OFFLOAD_READ input is ignored; ODX tokens never expire.
  - File:Line: `src/fs/ksmbd_fsctl.c:2034`
  - Impact: Tokens accumulate in the hash table indefinitely. A client that issues OFFLOAD_READ without ever issuing OFFLOAD_WRITE leaks memory permanently.

- **P2-VSS-01**: `@GMT-` snapshot path tokens not resolved during SMB2 CREATE.
  - File:Line: VFS open path — `ksmbd_vss_resolve_path()` exists but is never called from the CREATE handler.
  - Impact: Snapshot enumeration (FSCTL_SRV_ENUMERATE_SNAPSHOTS) works and shows entries in the Windows "Previous Versions" tab, but clicking on a snapshot file to open it returns "file not found".

- **P2-DUP-01**: Missing `FILE_READ_DATA` access check on source handle in registered DUPLICATE_EXTENTS handler.
  - File:Line: `src/fs/ksmbd_fsctl.c:1149`
  - Impact: The legacy handler in `src/protocol/smb2/smb2_ioctl.c:712` has the check, but the registered handler (which runs first) does not. Any client can read data from a file they opened write-only by using FSCTL_DUPLICATE_EXTENTS_TO_FILE.

---

### P3 Partial Implementations

**[PLAN-01] P3-01** — Compression chaining `Flags` field silently ignored in negotiate; `build_compress_ctxt()` hardcodes `Flags=0`.
- File:Line: `src/protocol/smb2/smb2_negotiate.c:84-94`, `src/protocol/smb2/smb2_negotiate.c:362-419`

**[PLAN-01] P3-02** — No explicit assertion that preauth hash is fully seeded before `alloc_preauth_hash()` copies it.
- File:Line: `src/protocol/smb2/smb2_session.c:61-76`

**[PLAN-01] P3-03** — `SMB2_GLOBAL_CAP_NOTIFICATIONS` advertised but server-initiated (unsolicited) SMB2_SERVER_TO_CLIENT_NOTIFICATION PDUs not implemented.
- File:Line: `src/protocol/smb2/smb2ops.c:127`

**[PLAN-02] P3-01** — `STATUS_ACCESS_DENIED` error response on encrypted sessions is itself not encrypted before the connection is torn down.
- File:Line: `src/core/server.c:331-345`

**[PLAN-02] P3-02** — CCM nonce uses per-message random bytes with no overflow counter; GCM has a counter but CCM does not.
- File:Line: `src/protocol/smb2/smb2_pdu_common.c:1298`

**[PLAN-02] P3-03** — SMB 3.0/3.0.2 always uses AES-128-CCM key derivation labels regardless of `conn->cipher_type`; this is actually correct (SMB 3.0 only supports AES-128-CCM) but relies on an implicit invariant that `conn->cipher_type == 0` for SMB 3.0.
- File:Line: `src/protocol/smb2/smb2ops.c:176`

**[PLAN-03] P3-01** — AES-GMAC nonce theoretical reuse risk: if a signing key were reused across reconnects (it is not currently), MessageId-based nonces would repeat.
- File:Line: `src/core/auth.c:1120-1122`

**[PLAN-03] P3-04** — AES-GMAC signing linearizes all iovecs into `aad_buf` via `kzalloc(total_len)`; large compound/READ signing incurs a full memory copy.
- File:Line: `src/core/auth.c:1159-1173`

**[PLAN-04] P3-MC-01** — Channel inserted into `ksmbd_chann_list` before signing key is derived; brief window where channel exists without a valid key.
- File:Line: `src/protocol/smb2/smb2_session.c:394-408, 500-515`

**[PLAN-04] P3-MC-02** — Kerberos binding path leaks preauth-session entry; `ksmbd_preauth_session_remove()` is only called for NTLMSSP authentication.
- File:Line: `src/protocol/smb2/smb2_session.c:757`

**[PLAN-05] P3-01** — Lease v2 `ParentLeaseKey` parent-break uses `!=` equality on `Flags` instead of bitmask; additional flags alongside `PARENT_LEASE_KEY_SET` cause parent break to be skipped.
- File:Line: `src/fs/oplock.c:1377`

**[PLAN-05] P3-03** — Lease break timeout fixed at `OPLOCK_WAIT_TIME = 35 s`; shared between oplock and lease breaks with no per-type configurability.
- File:Line: `src/include/fs/oplock.h:13`

**[PLAN-06] P3-02** — Compression response path compresses only iovecs 0 and 1; `iov[2]` and beyond (file data in READ) are never included.
- File:Line: `src/core/smb2_compress.c:496-503`

**[PLAN-06] P3-03** — RDMA transform capabilities are correctly negotiated and stored in `conn->rdma_transform_ids`, but the query API `ksmbd_rdma_transform_supported()` has no call sites.
- File:Line: `src/transport/transport_rdma.c:228-238`, `src/include/core/connection.h:126-127`

**[PLAN-07] P3-BC-01** — BranchCache server secret (`pccrc_server_secret`) is generated once at module load and never rotated. Acknowledged in a TODO comment.
- File:Line: `src/fs/ksmbd_branchcache.c:39-48`

**[PLAN-07] P3-RES-01** — Resilient handle reconnect path not implemented; handle is preserved on disconnect but a client cannot reclaim it via re-open.
- File:Line: `src/fs/ksmbd_resilient.c`

**[PLAN-07] P3-WIT-01** — Witness protocol: kernel side tracks state and sends notifications, but the IPC path from a userspace RPC REGISTER call to the kernel registration API is not wired.
- File:Line: `src/mgmt/ksmbd_witness.c`

**[PLAN-07] P3-NIC-01** — IPv6 address list iterated without `rcu_read_lock()` in the registered FSCTL_QUERY_NETWORK_INTERFACE_INFO handler; legacy handler in `smb2_ioctl.c:320` has the lock.
- File:Line: `src/fs/ksmbd_fsctl.c:912`

---

### P4 Low Priority / Aspirational

**[PLAN-01] P4-02** — `ServerGUID` zeroed in NEGOTIATE response; MS-SMB2 §3.3.5.4 requires a stable per-server GUID. This is a prerequisite for fixing multichannel correlation and VALIDATE_NEGOTIATE_INFO.
- File:Line: `src/protocol/smb2/smb2_negotiate.c:891`

**[PLAN-02] P4-03** — No dedicated AES-256 AEAD TFMs; AES-128 and AES-256 variants reuse the same `gcm(aes)` / `ccm(aes)` TFM, forcing a `crypto_aead_setkey()` call on every message.
- File:Line: `src/core/crypto_ctx.h:23-27`

**[PLAN-04] P4-MC-01** — Fixed `Next` stride of 152 bytes in NIC info response hardcoded rather than derived from `sizeof(*nii_rsp)`.
- File:Line: `src/protocol/smb2/smb2_ioctl.c` (`nii_rsp->Next = cpu_to_le32(152)`)

**[PLAN-04] P4-MC-05** — IPv6-only NICs skipped in `FSCTL_QUERY_NETWORK_INTERFACE_INFO` because `ipv6_retry:` logic depends on a preceding IPv4 entry.
- File:Line: `src/protocol/smb2/smb2_ioctl.c`

**[PLAN-05] P4-01** — `create_disk_id_rsp_buf` uses `create_mxac_rsp` as the offset base for `NameOffset` instead of `create_disk_id_rsp`; wire-format bug in the QFid context.
- File:Line: `src/fs/oplock.c:2033`

**[PLAN-06] P4-04** — Decompression failure paths use `pr_err()` instead of `pr_err_ratelimited()`, allowing a malicious client to flood kernel logs.
- File:Line: `src/core/smb2_compress.c:190, 197, 343, 434`

**[PLAN-07] P4-CC-01** — Off-by-one in CopyChunk count validation: `>= max_count` is exclusive, so the limit is one fewer chunk than configured. At the MS-SMB2 recommended default of 16, only 15 chunks are allowed.
- File:Line: `src/fs/ksmbd_fsctl.c:997`, `src/protocol/smb2/smb2_ioctl.c:96`

**[PLAN-07] P4-BC-04** — BranchCache: no cache eviction mechanism; xattr cache size is bounded only by the filesystem's xattr limit.

**QUIC full implementation** (aspirational) — Requires a userspace proxy implementing TLS 1.3 with SMB ALPN, port 443 binding, and Unix socket forwarding; removal of RFC1002 NetBIOS framing from the QUIC path; full IPv6 address storage; and `.shutdown` transport op for graceful teardown.

---

### Plan Files Index

| File | Area | Lines | Compliance | Key Findings Summary |
|------|------|-------|-----------|----------------------|
| smb3_plan_01_negotiate_contexts_preauth.md | Negotiate contexts, pre-authentication integrity | 535 | ~82% | Cipher selection uses client order not server preference (P1-02); ENCRYPTION capability missing for 3.1.1 (P1-03); HashAlgorithmCount not validated (P1-01); 3 standard compression algorithms missing; NetName context not validated |
| smb3_plan_02_encryption_key_derivation.md | AES-CCM/GCM encryption, SP800-108 KDF, nonce management | 558 | ~87% | KDF and all four cipher implementations verified CORRECT; share-level encryption enforcement absent (P1-01); transform Flags not validated on receive (P1-02); GCM nonce counter correctly prevents reuse |
| smb3_plan_03_signing.md | HMAC-SHA256, AES-CMAC, AES-GMAC signing, enforcement | 408 | ~88% | All three signing algorithms verified CORRECT; CANCEL signing bypass (P1-01); OPLOCK_BREAK ack signing skipped (P1-05); session binding error code wrong (P2-03) |
| smb3_plan_04_multichannel_quic.md | Session binding, channel management, QUIC, RDMA, FSCTL_QUERY_NII | 755 | ~72% (weighted) | Multichannel binding fully implemented and correct; LinkSpeed unit error (BUG-MC-01); QUIC is ~15% (kernel listener only; no TLS, no proxy, non-standard framing); RDMA credit management implemented |
| smb3_plan_05_durable_handles_leases.md | DHnQ/DHnC/DH2Q/DH2C, persistent handles, lease v1/v2, resilient handles | 430 | ~75% | DHnQ handles never expire — fd leak (BUG-01); DH2Q default timeout 60 ms vs 60 s (BUG-02); lease state machine correct; persistent handles in-memory only |
| smb3_plan_06_compression_rdma_transforms.md | Compression transform, algorithms, RDMA transforms | 596 | ~35% | Algorithm confusion security bug (BUG-C02); LZ4 non-spec ID exposed (BUG-C01); LZNT1/LZ77/LZ77+Huffman stubs only; READ responses never compressed; RDMA transforms negotiated but never applied |
| smb3_plan_07_serverside_copy_snapshots_misc.md | FSCTL_VALIDATE_NEGOTIATE_INFO, CopyChunk, ODX, VSS, BranchCache, resilience, witness | 702 | ~80% | VNI must disconnect on mismatch (P1-VNI-01); @GMT snapshot paths not wired into CREATE (P2-VSS-01); BranchCache V1 functional; ODX functional with minor gaps; Witness kernel-side implemented |

---

### Implementation Roadmap

#### Phase 1 — Security-Critical Fixes (target: 2 weeks)

All items in this phase are single-function changes with no architectural dependencies.

| Priority | Bug ID | Description | Effort |
|----------|--------|-------------|--------|
| Critical | BUG-C02 | Validate PDU compression algorithm against negotiated algorithm | 30 min |
| Critical | P1-VNI-01 | VALIDATE_NEGOTIATE_INFO: call `ksmbd_conn_set_exiting()` on mismatch before returning | 15 min |
| High | BUG-02-P1-01 | Add per-share encryption enforcement check after `ksmbd_conn_get_tcon()` | 1-2 h |
| High | P1-03 | Set `SMB2_GLOBAL_CAP_ENCRYPTION` for SMB 3.1.1 in `init_smb3_11_server()` | 15 min |
| High | P1-02 (negotiate) | Fix cipher selection to use server preference in `decode_encrypt_ctxt()` | 30 min |
| High | P1-02 (encrypt) | Validate inbound transform header `Flags == 0x0001` in `smb3_decrypt_req()` | 15 min |
| High | P1-01 (signing) | Add `SMB2_CANCEL_HE` to exclusion list in `smb2_is_sign_req()` | 5 min |
| High | BUG-MC-01 | Fix LinkSpeed unit: `speed * 1000000 / 8` bytes/sec | 5 min |

#### Phase 2 — Correctness Fixes + High-Impact P2 (target: 4-6 weeks)

| Priority | Bug/Feature ID | Description | Effort |
|----------|---------------|-------------|--------|
| High | BUG-01 (durable) | Assign default `durable_timeout = 16000` ms for DHnQ handles | 15 min |
| High | BUG-02 (durable) | Change DH2Q default timeout from 60 to 60000 ms | 5 min |
| High | P1-05 (signing) | OPLOCK_BREAK ack: remove from unconditional exclusion in `smb2_is_sign_req()` | 30 min |
| High | BUG-MC-02 | Extend session-closed notification to SMB 3.0/3.0.2 channels | 15 min |
| High | BUG-C01 | Remove LZ4 from negotiate context (non-spec algorithm ID 0x0005) | 30 min |
| High | BUG-C03 | Cap `OriginalCompressedSegmentSize` against `max_trans_size` | 15 min |
| High | BUG-C04 | Remove Pattern_V1 from standalone non-chained negotiate | 30 min |
| Medium | P1-01 (negotiate) | Validate `HashAlgorithmCount` in `decode_preauth_ctxt()` | 30 min |
| Medium | P2-01 (encrypt) | Add `OriginalMessageSize >= sizeof(smb2_hdr)` lower bound check | 15 min |
| Medium | P2-DUP-01 | Add `FILE_READ_DATA` access check to registered `DUPLICATE_EXTENTS` handler | 30 min |
| Medium | P2-VSS-01 | Wire `ksmbd_vss_resolve_path()` into VFS open path for `@GMT-` tokens | 2-4 h |
| Medium | P2-ODX-02 | Implement `TokenTimeToLive` enforcement for ODX tokens | 1-2 h |
| Medium | P4-04 (compress) | Replace `pr_err()` with `pr_err_ratelimited()` in decompression paths | 15 min |
| Medium | BUG-R01 | Implement RDMA Transform Header and apply transforms in RDMA read/write | 2-4 weeks |
| Medium | P2-03 (signing) | Change session binding signature error to `STATUS_ACCESS_DENIED` | 15 min |

#### Phase 3 — P2 Remaining + P3 Partial Implementations (target: 6-8 weeks)

| Feature | Description | Effort |
|---------|-------------|--------|
| LZNT1 / LZ77 / LZ77+Huffman | Implement decompression using existing kernel libs or MS-XCA reference | 2-4 weeks |
| Chained compression | Implement `SMB2_COMPRESSION_FLAG_CHAINED` processing | 2-3 weeks |
| READ response compression | Rework `smb2_compress_resp()` to handle `iov_cnt > 2` by collapsing iovecs | 1-2 weeks |
| P2-01 (LZNT1/LZ77 in negotiate) | Enable spec algorithms in `decode_compress_ctxt()` after implementing them | 1 h (post-impl) |
| Persistent handle stable storage | Design and implement on-disk handle state serialization; required for true CA shares | 4-8 weeks |
| SMB3.0 persistent handle advertisement | Set `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` in `init_smb3_0_server()` | 5 min (after stable storage) |
| Resilient handle reconnect path | Implement re-open matching for `is_resilient` handles | 1-2 weeks |
| ServerGUID stable value | Persist a server GUID to disk; use in NEGOTIATE and VNI responses | 1-2 days |
| P3-NIC-01 | Add `rcu_read_lock()` around IPv6 address iteration in `ksmbd_fsctl.c:912` | 15 min |
| P3-MC-01 | Insert channel only after signing key is derived, or zero-check on lookup | 30 min |
| P2-MC-01 | Scan existing netdevs at `ksmbd_tcp_init()` time | 1-2 h |
| P4-CC-01 | Fix off-by-one in CopyChunk count: `>` instead of `>=` | 5 min |
| P4-01 (oplock) | Fix `create_disk_id_rsp_buf` NameOffset to use correct struct base | 15 min |

#### Phase 4 — QUIC Full Implementation, Compression Algorithms, P4 (ongoing)

| Feature | Description | Effort |
|---------|-------------|--------|
| QUIC userspace proxy | Implement TLS 1.3 proxy (msquic/ngtcp2), ALPN `smb`, port 443, unix socket forwarding | 4-12 weeks |
| QUIC framing | Remove RFC1002 NetBIOS framing from the QUIC path (kernel + proxy must agree) | 1 week |
| QUIC full IPv6 | Store 128-bit client address; fix per-IP connection counting | 2 h |
| QUIC `.shutdown` op | Implement `ksmbd_quic_shutdown()` for graceful server teardown | 30 min |
| QUIC 0-RTT replay protection | Define policy for `KSMBD_QUIC_F_EARLY_DATA`; protect against replays | 1-2 weeks |
| AES-GMAC key exhaustion | Implement per-signing-key invocation counter and session re-key trigger | 1-2 days |
| BranchCache secret rotation | Add a workqueue-based periodic rotation for `pccrc_server_secret` | 1-2 days |
| Witness IPC wiring | Wire `KSMBD_EVENT_WITNESS_REGISTER/UNREGISTER` netlink events to kernel API | 1-2 weeks |
| P4-MC-05 | Report IPv6-only NICs in FSCTL_QUERY_NETWORK_INTERFACE_INFO | 1-2 h |

---

### Quick Win Table

Bugs or gaps fixable in under 30 minutes each, with high correctness or security impact.

| Fix | File:Line | Effort | Impact |
|-----|-----------|--------|--------|
| DH2Q default timeout: `60` -> `60000` ms | `src/protocol/smb2/smb2_create.c:2224` | 5 min | High — DH2Q reconnect stops failing for default-timeout clients |
| DHnQ default timeout: set `fp->durable_timeout = 16000` | `src/protocol/smb2/smb2_create.c:2208` | 5 min | High — eliminates indefinite fd leak on disconnect |
| LinkSpeed bytes/sec: `* 1000000` -> `* 1000 * 1000 / 8` | `src/protocol/smb2/smb2_ioctl.c:285` and `src/fs/ksmbd_fsctl.c:868` | 5 min | High — fixes multichannel channel selection on 10+ GbE |
| Add `SMB2_CANCEL_HE` to signing exclusion list | `src/protocol/smb2/smb2_pdu_common.c:929` | 5 min | High — unblocks async cancel on mandatory-signing sessions |
| VNI: call `ksmbd_conn_set_exiting()` on mismatch | `src/fs/ksmbd_fsctl.c:1524-1534` | 15 min | High — closes the downgrade-protection gap in VALIDATE_NEGOTIATE_INFO |
| Transform Flags validation on receive | `src/protocol/smb2/smb2_pdu_common.c` (`smb3_decrypt_req()`) | 15 min | Medium — enforces `Flags == 0x0001` per spec |
| Cipher selection: server preference not client preference | `src/protocol/smb2/smb2_negotiate.c:330-340` | 30 min | High — server always selects strongest mutually-supported cipher |
| Set `SMB2_GLOBAL_CAP_ENCRYPTION` for SMB 3.1.1 | `src/protocol/smb2/smb2ops.c:345-372` | 15 min | Medium — improves interoperability with strict Windows clients |
| Add algorithm mismatch check in decompressor | `src/core/smb2_compress.c:325` | 30 min | Critical security — prevents algorithm-confusion attack |
| Compression cap: 2 MB -> `max_trans_size` | `src/core/smb2_compress.c:335-347` | 15 min | Medium — brings decompression bomb defense into spec compliance |
| DH2C `dh_info.persistent` bitmask fix | `src/protocol/smb2/smb2_create.c:932` | 5 min | Low-medium — prevents reserved bits triggering persistent mode |
| `pr_err` -> `pr_err_ratelimited` in decompressor | `src/core/smb2_compress.c:190, 197, 343, 434` | 15 min | Medium — prevents log flooding by malicious clients |
| CopyChunk off-by-one: `>=` -> `>` | `src/fs/ksmbd_fsctl.c:997` | 5 min | Low — allows the spec-recommended maximum of 16 chunks |
| `FILE_READ_DATA` check in DUPLICATE_EXTENTS handler | `src/fs/ksmbd_fsctl.c:1149` | 30 min | High — closes access control bypass for cloned extents |
| Session binding error code: `STATUS_REQUEST_NOT_ACCEPTED` -> `STATUS_ACCESS_DENIED` | `src/protocol/smb2/smb2_session.c:681-684` | 5 min | Low — brings binding failure error code into spec compliance |
| `rcu_read_lock()` for IPv6 addr iteration | `src/fs/ksmbd_fsctl.c:912` | 15 min | Medium — fixes potential race on IPv6 address removal |
| `ksmbd_preauth_session_remove()` for Kerberos binding | `src/protocol/smb2/smb2_session.c:757` | 30 min | Low — prevents minor per-channel memory leak on Kerberos binding |
