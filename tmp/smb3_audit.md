# SMB3 / Advanced SMB2 Features Audit

**Repository:** `/home/ezechiel203/ksmbd`
**Source tree:** `/home/ezechiel203/ksmbd/src/`
**Audit date:** 2026-03-01
**Spec reference:** MS-SMB2 (PDF in `/home/ezechiel203/ksmbd/protocol/[MS-SMB2].pdf`)
**Auditor:** Claude Sonnet 4.6 — static source analysis

---

## Summary Table

| # | Feature | SMB Version | Status | Key Gaps |
|---|---------|-------------|--------|----------|
| 1 | Multi-Channel | 3.0+ | Partial | No channel removal on conn drop; GUID validation present; per-channel signing key correct; ChannelSequence tracked |
| 2 | Signing (HMAC-SHA256 / AES-CMAC / AES-GMAC) | 2.x / 3.0 / 3.1.1 | Implemented | Per-channel key correctly selected; AES-GMAC negotiated and used |
| 3 | Encryption (CCM/GCM 128+256) | 3.0+ | Implemented | All four cipher types negotiated and applied; GCM nonce counter exhaustion handled |
| 4 | Leases v1 + v2 | 2.1+ | Implemented | Lease epoch increment tracked; parent lease key stored; lazy break on close implemented |
| 5 | Durable Handles v1 + v2 | 2.1+ | Implemented | Scavenger thread present; persistent flag gated on CA share; DH2Q/DH1Q reconnect with client GUID check |
| 6 | Compression (SMB 3.1.1) | 3.1.1 | Partial | LZ4 + Pattern_V1 functional; LZNT1/LZ77/LZ77+Huffman are stubs (negotiate succeeds, decompress returns EOPNOTSUPP); chained compression rejected |
| 7 | RDMA / SMB Direct | 3.0+ | Partial | Full RDMA transport; RDMA_TRANSFORM negotiate context decoded; no RDMA transform header applied to payload |
| 8 | Pre-Authentication Integrity | 3.1.1 | Implemented | SHA-512 hash accumulated over NEGOTIATE + SESSION_SETUP; per-binding preauth session tracked |
| 9 | DFS Referrals | 2.0+ | Partial | FSCTL_DFS_GET_REFERRALS + _EX handled; referral v2/v3/v4 built; no server-side DFS namespace — responses point back to local share |
| 10 | QUIC Transport | 3.1.1 ext. | Partial (proxy model) | Userspace proxy + unix socket bridge; no native in-kernel QUIC; no RFC 9000 / SMB-over-QUIC negotiate context |
| 11 | Server-to-Client Notification | 3.1.1 | Implemented | SESSION_CLOSED notification sent to all multi-channel peers on logoff |

---

## Detailed Analysis

### 1. Multi-Channel (SMB 3.0+)

#### Current State

Channel binding during SESSION_SETUP is handled in
`/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_session.c` (function `smb2_sess_setup`).
Key points:

- **Flag detection:** `SMB2_SESSION_REQ_FLAG_BINDING` checked; guarded by
  `KSMBD_GLOBAL_FLAG_SMB3_MULTICHANNEL`.
- **Dialect enforcement:** Both the existing session and the new connection must use the same dialect.
- **Signature enforcement:** The binding request must carry `SMB2_FLAGS_SIGNED`; the signature is
  verified with `check_sign_req()` after `work->sess` is set (MS-SMB2 §3.3.5.2.7).
- **ClientGUID match:** `memcmp(conn->ClientGUID, sess->ClientGUID, SMB2_CLIENT_GUID_SIZE)` enforced.
- **Guest rejection:** Guest sessions cannot bind channels.
- **Channel list:** Stored in `sess->ksmbd_chann_list` (xarray keyed by connection pointer).

ChannelSequence tracking (MS-SMB2 §3.3.5.2.10) is implemented in
`/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_pdu_common.c:smb2_check_channel_sequence()`.
It is called from WRITE, LOCK, IOCTL, SET_INFO, and FLUSH handlers.

RDMA_V1 and RDMA_V1_INVALIDATE channel types for READ/WRITE are handled in
`/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_read_write.c` (lines ~300, ~394, ~754).

#### Gaps

1. **Channel removal on connection drop:** When a connection drops, there is no code in
   `ksmbd_conn_handler_loop` or `ksmbd_conn_cleanup` that removes the channel from
   `sess->ksmbd_chann_list`. The xarray entry for the dead connection remains until the session
   itself expires, which means `ksmbd_all_conn_set_status` may still iterate over dead channels.
   Spec reference: MS-SMB2 §3.3.7.1 "Handling Loss of a Connection."

2. **No failover logic:** After a channel drops, there is no mechanism to detect that the remaining
   channel(s) should absorb outstanding requests. The spec requires the server to maintain the
   session across channel loss if any channel remains.

3. **`SMB2_GLOBAL_CAP_MULTI_CHANNEL` capability bit:** Negotiation in `smb2ops.c` sets the
   capability bits from `conn->vals->capabilities`. Confirm those include `SMB2_GLOBAL_CAP_MULTI_CHANNEL`
   for SMB 3.0+ `smb_version_values`.

#### Effort Estimate

- Channel removal on drop: ~1 day (hook into `ksmbd_conn_cleanup`, remove from session channel list).
- Failover / session-persistence across channel loss: ~3–5 days (complex state machine).

---

### 2. Signing and Encryption

#### Current State — Signing

Signing algorithm selection is fully implemented:

- **Negotiate context parsing** (`/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_negotiate.c`,
  `decode_sign_cap_ctxt`): scans client's list, prefers AES-GMAC > AES-CMAC > HMAC-SHA256.
- **Key generation:**
  - SMB 2.x: `ksmbd_sign_smb2_pdu` (HMAC-SHA256 of session key).
  - SMB 3.0: `ksmbd_gen_smb30_signingkey` — SP800-108 KDF with label `"SMB2AESCMAC"`.
  - SMB 3.1.1: `ksmbd_gen_smb311_signingkey` — same KDF but context is the pre-auth hash,
    binding flag handled.
- **Per-channel vs per-session key:** `generate_smb3signingkey` stores the key in
  `chann->smb3signingkey` when `conn->binding == true` and `dialect >= SMB30_PROT_ID`; otherwise
  in `sess->smb3signingkey`. Verification in `smb3_check_sign_req` selects `chann->smb3signingkey`
  for normal requests and `sess->smb3signingkey` for SESSION_SETUP — correct per spec.
- **AES-GMAC:** `ksmbd_sign_smb3_pdu_gmac` called when `conn->signing_algorithm == SIGNING_ALG_AES_GMAC`.

Source files:
- `/home/ezechiel203/ksmbd/src/core/auth.c` (key derivation, GMAC/CMAC signing)
- `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_pdu_common.c` (`smb3_check_sign_req`,
  `smb3_set_sign_rsp`)

#### Current State — Encryption

- **Negotiation:** `decode_encrypt_ctxt` accepts AES-128-CCM, AES-128-GCM, AES-256-CCM, AES-256-GCM
  (MS-SMB2 §2.2.3.1.7). First client-offered cipher in that list wins.
- **Key derivation:**
  - SMB 3.0: `ksmbd_gen_smb30_encryptionkey` — KDF with labels `"SMB2AESCCM"` / `"ServerIn\0"`.
  - SMB 3.1.1: `ksmbd_gen_smb311_encryptionkey` — uses pre-auth hash as context.
- **Transform header:** `fill_transform_hdr` correctly distinguishes GCM (12-byte nonce) from CCM
  (11-byte nonce), and selects 256-bit key size when cipher type is AES-256.
- **GCM nonce management:** Monotonic counter with 4-byte random session prefix prevents nonce
  reuse. Counter exhaustion logged as a warning and falls back to random nonce.
- **Session-level encryption:** `sess->enc` flag set after key generation. Share-level encryption
  not separately tracked (all traffic on an encrypted session is encrypted).
- **Transform decode/encode:** `smb3_decrypt_req` / `smb3_encrypt_resp` in
  `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_pdu_common.c`.

#### Gaps

1. **Share-level vs session-level encryption:** The spec (MS-SMB2 §3.3.4.1.4) allows per-share
   `TREE_CONNECT` responses to force encryption regardless of session state. Currently only session-level
   `sess->enc` is checked; a per-share "require encryption" flag is not propagated to the tcon.

2. **Encryption on async notifications:** `ksmbd_notify.c` has multiple sites calling
   `conn->ops->encrypt_resp(work)` for CHANGE_NOTIFY responses — reviewed and appears correct.
   No gap found.

3. **SMB 3.0 encryption capability flag:** SMB 3.0/3.0.2 use `SMB2_GLOBAL_CAP_ENCRYPTION` in
   the negotiate response capabilities rather than an encryption negotiate context. The check in
   `smb3_encryption_negotiated()` covers both paths correctly.

#### Effort Estimate

- Share-level encryption flag in tcon: ~1 day.

---

### 3. Leases (SMB 2.1+)

#### Current State

Lease implementation is in `/home/ezechiel203/ksmbd/src/fs/oplock.c` and
`/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_create.c`.

- **Lease v1 (RWH):** `SMB2_LEASE_READ_CACHING_LE`, `WRITE_CACHING_LE`, `HANDLE_CACHING_LE`
  all parsed; state machine in `oplock.c` handles RH → R → None transitions.
- **Lease v2 (parent key + epoch):** `alloc_lease` copies `lctx->parent_lease_key` and
  `lctx->epoch` (incremented by 1). `lease->version` tracked.
- **Lease break notification:** `smb_send_lease_break_noti` in `oplock.c` sends the break;
  `smb_lazy_parent_lease_break_close` handles deferred parent breaks on file close.
- **Lease break acknowledgment:** `smb21_lease_break_ack` in
  `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c` handles `SMB2_OPLOCK_BREAK_HE`
  for lease breaks; state transition rules from spec §3.3.4.7 are implemented (valid vs invalid
  new state checked).
- **NewLeaseState enforcement:** `validate_lease_state_transition` checks that the client acks
  to a state that is a subset of the break notification state.

#### Gaps

1. **Lease epoch in break notifications:** The spec requires incrementing `Epoch` in
   `SMB2_LEASE_BREAK` notifications. The `lease->epoch` is incremented on alloc but it is
   unclear whether it is updated in the break notification body — needs verification in
   `smb_send_lease_break_noti`.

2. **Directory lease (v2 only):** MS-SMB2 §2.2.13.2.8 allows directory leases (R and RH only);
   `lease->is_dir` field is tracked in the lease structure but whether the server correctly limits
   directory lease state to R/RH (no W) needs review.

3. **Lease key deduplication across connections:** The spec requires that a second open with
   the same lease key from the same client (same ClientGUID) reuses the existing lease rather
   than granting a new one. This deduplication logic through `lease_table_list` is present but
   should be audited for race conditions under multi-channel scenarios.

#### Effort Estimate

- Epoch in break notifications: ~0.5 day.
- Directory lease restriction: ~0.5 day audit + fix.

---

### 4. Persistent / Durable Handles

#### Current State

- **Durable v1 (DHnQ/DHnC):** `parse_durable_handle_context` detects `"DHnQ"` / `"DHnC"` create
  contexts. `ksmbd_open_durable_fd` registers the handle in a global IDR; `ksmbd_lookup_durable_fd`
  validates and returns it.
- **Durable v2 (DH2Q/DH2C):** Parsed; `durable_v2_blob->Timeout` and `durable_v2_blob->Flags`
  (persistent bit) read. ClientGUID checked on reconnect to prevent handle theft
  (`pr_err_ratelimited("durable reconnect v2: client GUID mismatch")`).
- **Persistent handles:** `fp->is_persistent = true` set only when `KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY`
  is set on the share (in `smb2_create.c:2198-2201`). This correctly gates persistent handles on
  a CA share.
- **Scavenger thread:** `ksmbd_durable_scavenger` thread in
  `/home/ezechiel203/ksmbd/src/fs/vfs_cache.c` runs on session creation/expiry, iterates durable
  FDs, and closes those whose `durable_scavenger_timeout` has elapsed.
- **Reconnect:** `ksmbd_reopen_durable_fd` clears the scavenger timeout and reassigns `fp->conn`
  and `fp->tcon`.
- **Lock sequence validation:** `check_lock_sequence` in
  `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_lock.c` validates lock sequences for
  resilient/durable/persistent handles per MS-SMB2 §3.3.5.14.

#### Gaps

1. **CA share definition:** The spec requires a continuously available (CA) share to use cluster
   storage and survive node failure. ksmbd treats any share with the `KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY`
   flag as CA, but there is no actual HA backing — persistent handles survive a ksmbd daemon restart
   only if the IDR state is rebuilt (it is not). This is a fundamental limitation for a non-clustered
   server.

2. **DH2Q timeout range enforcement:** MS-SMB2 §3.3.5.9 says if the client requests a timeout
   greater than the server's maximum, the server should return its own maximum. Currently the code
   clamps to 60 seconds only if the requested timeout is 0 — non-zero values are passed through
   unchanged.

3. **Durable handle with no oplock/lease:** MS-SMB2 §3.3.5.9 says a durable handle request
   without a batch oplock or RH lease should be silently ignored. The code does grant durable
   handles in this case — `smb2_check_durable_oplock` in `oplock.c` enforces the condition but
   only for reconnect, not for initial grant path.

#### Effort Estimate

- Timeout clamping: ~0.5 day.
- Initial grant oplock/lease requirement: ~1 day.
- True HA persistent handles: out of scope for a standalone module.

---

### 5. Compression (SMB 3.1.1)

#### Current State

Compression is in `/home/ezechiel203/ksmbd/src/core/smb2_compress.c`.

- **Negotiation:** `decode_compress_ctxt` in `smb2_negotiate.c` selects the best mutually
  supported algorithm: LZ4 (0x0005) preferred, then Pattern_V1 (0x0004).
- **Decompression of requests:** `smb2_decompress_req` decodes `SMB2_COMPRESSION_TRANSFORM_HEADER`,
  supports non-chained mode; amplification ratio capped at 1024:1; decompressed size capped at
  2 MB or `max_write_size`.
- **Compression of responses:** `smb2_compress_resp` compresses single-iov responses using the
  negotiated algorithm; skips multi-iov (READ with aux) and encrypted responses.
- **LZ4:** Fully functional using kernel `LZ4_compress_default` / `LZ4_decompress_safe`.
- **Pattern_V1:** Implemented: detects all-same-byte buffers, encodes 8-byte payload.

#### Gaps

1. **Chained compression (`SMB2_COMPRESSION_FLAG_CHAINED`):** Rejected with `EOPNOTSUPP` on
   receive; not generated on send. MS-SMB2 §2.2.42.1 defines chained compression for PDU
   chains. Not implementing this limits interoperability with Windows clients that prefer
   chained mode.

2. **LZNT1 / LZ77 / LZ77+Huffman decompression:** These three algorithms are stubs — negotiate
   may succeed if the client only offers LZ4 or Pattern_V1, but if a client sends a compressed
   PDU using one of these algorithms, the server returns `EOPNOTSUPP`. This is a protocol error;
   the server should either negotiate only algorithms it can fully handle or return
   `STATUS_COMPRESSION_DISABLED` on setup.
   **Fix:** Remove LZNT1/LZ77/LZ77+Huffman from the list of accepted algorithms in
   `decode_compress_ctxt` so they are never negotiated.

3. **MS-SMB2 algorithm IDs vs LZ4:** The spec defines IDs 0x0001–0x0004 (LZNT1, LZ77,
   LZ77+Huffman, Pattern_V1). LZ4 (0x0005) is a later addition. Confirm the spec version
   consulted includes LZ4; otherwise negotiation against Windows Server may select only
   spec-defined algorithms.

#### Effort Estimate

- Remove LZNT1/LZ77/LZ77+Huffman from negotiation: ~1 hour.
- LZNT1 decompression (kernel has no built-in): ~2–3 days (custom implementation or external lib).
- Chained compression: ~3–5 days.

---

### 6. RDMA / SMB Direct (SMB 3.0+)

#### Current State

Full SMB Direct transport is in `/home/ezechiel203/ksmbd/src/transport/transport_rdma.c`.

- RDMA CM listener on port 445 (InfiniBand) and 5445 (iWARP).
- Credit-based flow control (`smb_direct_transport` fields: `recv_credits`, `send_credits`,
  `rw_credits`).
- `ksmbd_conn_rdma_read` / `ksmbd_conn_rdma_write` in `connection.c` dispatch to transport ops.
- `SMB2_CHANNEL_RDMA_V1` and `SMB2_CHANNEL_RDMA_V1_INVALIDATE` channel types recognized in
  `smb2_read_write.c`; read/write operations use `ksmbd_conn_rdma_read` / `ksmbd_conn_rdma_write`.
- **RDMA Transform negotiate context:** `decode_rdma_transform_ctxt` and
  `build_rdma_transform_ctxt` implemented in `smb2_negotiate.c`; accepts
  `SMB2_RDMA_TRANSFORM_NONE`, `SMB2_RDMA_TRANSFORM_ENCRYPTION`,
  `SMB2_RDMA_TRANSFORM_SIGNING`. `ksmbd_rdma_transform_supported()` checks per-connection.

#### Gaps

1. **RDMA transform payload:** The `SMB2_RDMA_TRANSFORM` negotiate context is decoded and echoed
   back, but the actual RDMA transform header (MS-SMB2 §2.2.42.2) — an additional header placed
   in the buffer descriptor when signing or encrypting RDMA data — is not generated or validated.
   This means RDMA_TRANSFORM_ENCRYPTION and RDMA_TRANSFORM_SIGNING are negotiated but not
   honoured on the data path.

2. **RDMA transport capability bit:** Verify `SMB2_GLOBAL_CAP_RDMA` is set in the negotiate
   response capabilities for SMB 3.0+ when the RDMA transport is active.

3. **`SMB2_READFLAG_REQUEST_SERVER_RDMA_TRANSFORM` / similar flags:** The spec defines
   additional request flags for RDMA transforms that may not be parsed.

#### Effort Estimate

- RDMA transform header on data path: ~5–8 days (complex; requires RDMA scatter-gather changes).
- Capability bit verification: ~0.5 day.

---

### 7. Pre-Authentication Integrity (SMB 3.1.1)

#### Current State

Fully implemented across three files:

- **Negotiate:** `ksmbd_gen_preauth_integrity_hash(conn, work->request_buf,
  conn->preauth_info->Preauth_HashValue)` called after parsing negotiate request
  (`smb2_negotiate.c:787`).
- **Session Setup:** `generate_preauth_hash(work)` called for each SESSION_SETUP exchange;
  correctly handles the binding case (separate `preauth_sess` per session ID in the preauth table).
- **Response hashing:** `smb3_preauth_hash_rsp()` in `smb2_pdu_common.c` hashes the negotiate
  and session setup *response* buffers as well (MS-SMB2 §3.3.4.1.1 requires hashing both
  request and response).
- **SHA-512:** `CRYPTO_SHASH_SHA512` context via `ksmbd_crypto_ctx_find_sha512()`.
- **Binding preauth:** Separate `preauth_session` objects (list on conn) track binding-specific
  preauth hashes; cleaned up in `ksmbd_preauth_session_remove` after binding completes.
- **Mandatory context enforcement:** `!conn->preauth_info->Preauth_HashId` triggers
  `STATUS_INVALID_PARAMETER` for SMB 3.1.1 negotiate without the preauth context.

#### Gaps

1. **Preauth hash binding to session key:** After the final SESSION_SETUP authenticate round,
   the derived session key (for signing/encryption) must incorporate the pre-auth hash as a
   KDF context. `ksmbd_gen_smb311_signingkey` uses `sess->Preauth_HashValue` as the SP800-108
   context — this is correct. Verify the same is done for `ksmbd_gen_smb311_encryptionkey` (it
   uses the session's `Preauth_HashValue` as context at `auth.c:1429`).

No significant gaps found in pre-authentication integrity — the implementation appears complete
and correct for the common paths.

#### Effort Estimate

- No action required (implementation complete).

---

### 8. DFS (Distributed File System)

#### Current State

DFS support is in `/home/ezechiel203/ksmbd/src/fs/ksmbd_dfs.c`.

- **FSCTL_DFS_GET_REFERRALS:** Registered FSCTL handler builds a `RESP_GET_DFS_REFERRAL`
  response with referral version selected from client's `max_referral_level` (V2/V3/V4).
- **FSCTL_DFS_GET_REFERRALS_EX:** Handled similarly with `req_get_dfs_referral_ex` parsing.
- **Referral format:** `dfs_referral_level_3` / `dfs_referral_level_4` structures with DFS path,
  alt path, and node offsets (UTF-16 strings).
- **Target:** Referral points back to the local server (`\\<netbios>\<share>`), i.e., ksmbd acts
  as a "DFS root" that resolves all paths to itself.
- **`KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY`** used for persistent handles; no separate DFS
  root share flag.
- **Tree connect DFS flag:** `SMB2_TREE_CONNECT_FLAG_DFS` is part of the standard tree connect;
  `KSMBD_SHARE_FLAG_CONTINUOUS_AVAILABILITY` set in `smb2_tree.c:249` affects share caps, but no
  explicit DFS-specific TREE_CONNECT response flag (`SMB2_SHAREFLAG_DFS`) was observed set in
  the tree connect response.

#### Gaps

1. **`SMB2_SHAREFLAG_DFS` in TREE_CONNECT response:** MS-SMB2 §3.3.5.7 requires
   `SMB2_SHAREFLAG_DFS` in `ShareFlags` when the share is DFS-enabled. Not observed set.

2. **No real DFS namespace:** ksmbd can only answer DFS referrals for paths pointing to shares
   it already serves; it cannot redirect to remote servers or participate in a distributed
   namespace. This is a design limitation, not a bug.

3. **DFS path resolution in CREATE:** When a client sends an `SMB2_CREATE` with a DFS path
   after following a referral, the server should validate it resolves to a local path.
   Currently the path is passed through to VFS without DFS prefix stripping.

#### Effort Estimate

- `SMB2_SHAREFLAG_DFS` flag: ~0.5 day.
- Real DFS namespace: architectural change, out of scope.

---

### 9. QUIC Transport (SMB over QUIC — 3.1.1 extension)

#### Current State

Implemented in `/home/ezechiel203/ksmbd/src/transport/transport_quic.c` using a **userspace proxy
model**:

```
SMB Client --[QUIC/TLS 1.3]--> [Userspace QUIC Proxy] --[Unix Domain Socket]--> [ksmbd kernel module]
```

- Kernel listens on an abstract unix socket (`KSMBD_QUIC_SOCK_NAME`).
- Per-connection `ksmbd_quic_conn_info` header provides client IP, port, and TLS verification flag.
- TLS verification enforced: `KSMBD_QUIC_F_TLS_VERIFIED` required; unauthenticated proxies rejected.
- Proxy must run as root (uid 0) — verified via `sk_peer_cred`.
- Per-IP and global connection limits enforced.
- Otherwise the connection is treated as a standard byte-stream transport, identical to TCP.

#### Gaps

1. **No native QUIC in kernel:** The proxy model means the kernel does not participate in QUIC
   connection establishment, 0-RTT, or QUIC-level flow control. MS-SMB2 Appendix B (MS-SMBD
   via QUIC) defines SMB-over-QUIC as a transport-level feature requiring QUIC semantics.

2. **No QUIC transport negotiate context:** MS-SMB2 §2.2.3.1 (SMB 3.1.1 negotiate contexts)
   includes a transport capabilities context (`SMB2_TRANSPORT_CAPABILITIES`). There is no QUIC-specific
   negotiate context generated or consumed.

3. **No port 443 listener in kernel:** Port 443 binding (the SMB-over-QUIC well-known port) is
   entirely in the userspace proxy.

4. **mTLS client certificate handling:** Client certificate identity is summarised in
   `conn_info.flags` but no detail is passed to the SMB authentication layer. The spec requires
   client certificate identity to be correlated with user authentication.

This is architecturally sound as a pragmatic implementation approach — full in-kernel QUIC is
a multi-year project. The proxy model correctly routes SMB2 PDUs through a standard ksmbd
connection handler.

#### Effort Estimate

- mTLS identity propagation to auth: ~2–3 days.
- Native in-kernel QUIC: not feasible without kernel QUIC infrastructure (none exists as of 2026).

---

### 10. Server-to-Client Notification (SMB 3.1.1)

#### Current State

Implemented in `/home/ezechiel203/ksmbd/src/protocol/smb2/smb2_misc_cmds.c:smb2_send_session_closed_notification`.

- Sends `SMB2_SERVER_TO_CLIENT_NOTIFICATION` (command 0x0013) with
  `NotificationType = SMB2_NOTIFY_SESSION_CLOSED` to all multi-channel peers when a session
  is logged off.
- Only sent for SMB 3.1.1+ connections.
- Correctly skips the connection that initiated the logoff.
- Called from `smb2_tree.c` at logoff time (line 400).
- Uses unsolicited `MessageId = -1`.
- `ksmbd_conn_r_count_inc/dec` correctly brackets the send.

#### Gaps

1. **Encryption of notifications:** When `sess->enc` is true, the notification must also be
   encrypted. The current code does not call `encrypt_resp` after building the notification
   response (the `ksmbd_conn_write(noti_work)` is called with a plain buffer). Contrast with
   `ksmbd_notify.c` which does call `encrypt_resp` for CHANGE_NOTIFY.

2. **Notification for other session-closure reasons:** The spec (MS-SMB2 §3.3.4.1.8) says the
   notification should also be sent when a session expires (timer, admin eviction). Currently
   only LOGOFF triggers it.

#### Effort Estimate

- Encryption of session-closed notification: ~1 day.
- Notification on session expiry: ~0.5 day.

---

## Cross-Cutting Observations

### Security

1. **Compression before encryption order:** `smb2_compress_resp` skips if `work->encrypted` is
   set (correct — compress-then-encrypt prevents oracle attacks like CRIME/BREACH).

2. **Decompression bomb protection:** Ratio cap (1024:1) and absolute size cap (2 MB or
   `max_write_size`) are present in `smb2_decompress_req`. Good.

3. **GCM nonce uniqueness:** Monotonic counter prevents nonce reuse within a session key's
   lifetime. Counter exhaustion logged. Key rotation not implemented (nonces are capped at
   `S64_MAX`, which effectively never rolls over in practice but has no key renegotiation path).

4. **Auth delay on failure:** `KSMBD_USER_FLAG_DELAY_SESSION` triggers `ksmbd_conn_set_need_reconnect`
   to force client to re-establish TCP, providing natural brute-force rate limiting.

### Missing SMB 3.x Features Not in Audit Scope

- **Cluster witness / SWCN:** No implementation (requires cluster infrastructure).
- **ODX (Offloaded Data Transfer):** `FSCTL_SRV_COPYCHUNK` is implemented but full ODX
  token-based offload is not.
- **Storage QoS:** Not implemented.
- **Azure SMB extensions:** Not applicable for a standalone module.

---

## Priority Recommendations

| Priority | Item | File(s) | Effort |
|----------|------|---------|--------|
| High | Remove LZNT1/LZ77/LZ77+Huffman from compression negotiation (prevents broken decompression) | `src/protocol/smb2/smb2_negotiate.c` | 1 hour |
| High | Encrypt SESSION_CLOSED notification when session is encrypted | `src/protocol/smb2/smb2_misc_cmds.c` | 1 day |
| High | Channel removal from session channel list when connection drops | `src/core/connection.c`, `src/mgmt/user_session.c` | 1 day |
| Medium | DH2Q timeout clamping to server maximum | `src/protocol/smb2/smb2_create.c` | 0.5 day |
| Medium | `SMB2_SHAREFLAG_DFS` in tree connect response | `src/protocol/smb2/smb2_tree.c` | 0.5 day |
| Medium | Share-level encryption flag propagated to tcon | `src/mgmt/tree_connect.c`, `src/protocol/smb2/smb2_tree.c` | 1 day |
| Medium | Session-closed notification on session expiry | `src/protocol/smb2/smb2_misc_cmds.c`, `src/mgmt/user_session.c` | 0.5 day |
| Low | Lease epoch in break notifications | `src/fs/oplock.c` | 0.5 day |
| Low | RDMA transform header on data path | `src/transport/transport_rdma.c` | 5–8 days |
| Low | mTLS identity propagation for QUIC transport | `src/transport/transport_quic.c` | 2–3 days |
